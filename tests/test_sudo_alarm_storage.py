"""Redacted sudo evidence joins alarms without becoming an SSH event."""

import json
import sqlite3

import pytest

from yggdrasil_ids.domain import Finding, SSHEvent
from yggdrasil_ids.storage import SCHEMA_VERSION, Repository

NOW = 1_800_000_000.0
FAILURE = "sudo.repeated_auth_failure"
DENIAL = "sudo.permission_denied"


@pytest.fixture
def repository(tmp_path, monkeypatch):
    monkeypatch.setattr("yggdrasil_ids.storage.time.time", lambda: NOW)
    repo = Repository(tmp_path / "data/events.sqlite3")
    repo.initialize()
    return repo


def add_sudo(repo, index=1, *, detector=FAILURE, timestamp=NOW - 10, process_count=3):
    with repo.transaction() as db:
        return repo.add_sudo_alert(
            db,
            event_id=f"{index:064x}",
            detector_id=detector,
            timestamp=timestamp,
            process_count=process_count,
        )


def add_ssh(db, repo, index, timestamp):
    event = SSHEvent(str(index), timestamp, "192.0.2.8", "ssh-user", "failure", "publickey")
    repo.insert_event(db, event)
    finding = Finding(
        "ssh.failed_burst",
        "SSH alarm",
        "medium",
        "SSH rule",
        event.source_ip,
        event.event_id,
        event.timestamp,
        {"event_ids": [event.event_id]},
    )
    return repo.add_finding(db, finding, cooldown=300)


def counts(repo):
    with repo.reader() as db:
        return {
            table: db.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            for table in ("alerts", "sudo_evidence", "discord_outbox", "events", "records")
        }


def test_schema4_migration_preserves_ssh_state_outbox_and_adds_sudo_evidence(repository):
    with repository.transaction() as db:
        ssh_id = add_ssh(db, repository, 1, NOW - 20)
        repository.put_state(db, "cursor", "existing-ssh-cursor")
        # Schema 5 only adds sudo_evidence and its indexes to the v4 tables.
        db.execute("DROP TABLE sudo_evidence")
        db.execute("PRAGMA user_version=4")
    with repository.reader() as db:
        previous_queue = [tuple(row) for row in db.execute("SELECT * FROM discord_outbox")]
        previous_instance = db.execute("SELECT instance FROM discord_outbox_meta").fetchone()[0]
    repository.initialize()
    repository.initialize()
    assert repository.get_state("cursor") == "existing-ssh-cursor"
    assert repository.alert_detail(ssh_id)["count"] == 1
    with repository.reader() as db:
        assert db.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION == 5
        assert db.execute("SELECT COUNT(*) FROM sudo_evidence").fetchone()[0] == 0
        assert [tuple(row) for row in db.execute("SELECT * FROM discord_outbox")] == previous_queue
        assert (
            db.execute("SELECT instance FROM discord_outbox_meta").fetchone()[0]
            == previous_instance
        )
        assert db.execute("PRAGMA foreign_key_check").fetchall() == []


def test_one_sudo_rule_case_has_redacted_evidence_and_one_outbox_entry(repository):
    alert_id = add_sudo(repository)
    detail = repository.alert_detail(alert_id)
    assert detail["detector_id"] == FAILURE
    assert detail["source_ip"] == "local"
    assert detail["severity"] == "medium"
    assert detail["count"] == 1  # The three processes are evidence, not three alarm cases.
    assert detail["score"] is None and detail["model_version"] is None
    assert detail["details"] == {"source": "sudo_rules", "process_count": 3}
    assert len(detail["findings"]) == 1 and not detail["findings_truncated"]
    evidence = detail["findings"][0]
    assert evidence["event_id"] == f"{1:064x}"
    assert evidence["outcome"] == "sudo"
    assert evidence["message"] is None and evidence["username"] is None
    assert evidence["score"] is None and evidence["model_version"] is None
    assert evidence["details"] == detail["details"]
    assert counts(repository) == {
        "alerts": 1,
        "sudo_evidence": 1,
        "discord_outbox": 1,
        "events": 0,
        "records": 0,
    }
    with repository.reader() as db:
        columns = {row[1] for row in db.execute("PRAGMA table_info(sudo_evidence)")}
        assert not {"uid", "pid", "boot_id", "cursor", "username", "message", "command"} & columns
        outbox = dict(db.execute("SELECT * FROM discord_outbox").fetchone())
    assert outbox["detector_id"] == FAILURE and outbox["happened_at"] == NOW - 10
    assert "sudo_rules" not in json.dumps(outbox)  # Outbox retains only delivery fields.


def test_sudo_replay_returns_same_alarm_without_duplicate_delivery(repository):
    first = add_sudo(repository)
    assert add_sudo(repository) == first
    assert counts(repository)["alerts"] == counts(repository)["discord_outbox"] == 1
    assert repository.alert_detail(first)["count"] == 1


def test_distinct_candidates_and_detector_ids_remain_separate_cases(repository):
    ids = [
        add_sudo(repository, 1),
        add_sudo(repository, 2),
        add_sudo(repository, 1, detector=DENIAL, process_count=1),
    ]
    assert len(set(ids)) == 3
    assert counts(repository)["alerts"] == counts(repository)["discord_outbox"] == 3
    assert repository.alert_detail(ids[-1])["title"] == "Afvist sudo-adgang"


@pytest.mark.parametrize("changed", [{"timestamp": NOW - 9}, {"process_count": 4}])
def test_conflicting_replay_identity_is_rejected_without_replacing_evidence(repository, changed):
    alert_id = add_sudo(repository)
    with pytest.raises(ValueError, match="Conflicting"):
        add_sudo(repository, **changed)
    assert counts(repository)["alerts"] == counts(repository)["discord_outbox"] == 1
    assert repository.alert_detail(alert_id)["details"]["process_count"] == 3


@pytest.mark.parametrize(
    "changed",
    [
        {"event_id": "raw-journal-cursor"},
        {"event_id": "G" * 64},
        {"event_id": "a" * 65},
        {"event_id": None},
        {"detector_id": "sudo.isolation_forest"},
        {"detector_id": "ssh.failed_burst"},
        {"detector_id": []},
        {"timestamp": float("nan")},
        {"timestamp": float("inf")},
        {"timestamp": -1},
        {"timestamp": 4_102_444_800},
        {"timestamp": True},
        {"process_count": True},
        {"process_count": 0},
        {"process_count": 50_001},
        {"process_count": 3.0},
    ],
)
def test_untrusted_or_invalid_sudo_values_create_no_alarm_or_queue(repository, changed):
    values = {
        "event_id": "a" * 64,
        "detector_id": FAILURE,
        "timestamp": NOW - 10,
        "process_count": 3,
    }
    values.update(changed)
    with pytest.raises(ValueError, match="Invalid"):
        with repository.transaction() as db:
            repository.add_sudo_alert(db, **values)
    assert counts(repository)["alerts"] == counts(repository)["discord_outbox"] == 0


def test_sudo_alarm_requires_explicit_transaction(repository):
    db = repository.connect()
    try:
        with pytest.raises(ValueError, match="transaction"):
            repository.add_sudo_alert(
                db,
                event_id="a" * 64,
                detector_id=FAILURE,
                timestamp=NOW - 10,
                process_count=3,
            )
    finally:
        db.close()
    assert counts(repository)["alerts"] == 0


def test_evidence_failure_rolls_back_alarm_outbox_and_bridge_state(repository):
    repository.set_state("sudo_bridge_checkpoint", "before")
    with repository.transaction() as db:
        db.execute(
            "CREATE TRIGGER abort_sudo_evidence BEFORE INSERT ON sudo_evidence "
            "BEGIN SELECT RAISE(ABORT, 'simulated sudo evidence failure'); END"
        )
    with pytest.raises(sqlite3.IntegrityError, match="simulated"):
        with repository.transaction() as db:
            repository.put_state(db, "sudo_bridge_checkpoint", "after")
            repository.add_sudo_alert(
                db,
                event_id="a" * 64,
                detector_id=FAILURE,
                timestamp=NOW - 10,
                process_count=3,
            )
    assert repository.get_state("sudo_bridge_checkpoint") == "before"
    assert counts(repository)["alerts"] == counts(repository)["sudo_evidence"] == 0
    assert counts(repository)["discord_outbox"] == 0


def test_retention_recounts_sudo_and_ssh_independently_and_preserves_queue(repository):
    with repository.transaction() as db:
        ssh_old = add_ssh(db, repository, 1, NOW - 200)
        ssh_new = add_ssh(db, repository, 2, NOW - 50)
    assert ssh_old == ssh_new
    sudo_old = add_sudo(repository, 1, timestamp=NOW - 200)
    sudo_new = add_sudo(repository, 2, timestamp=NOW - 50)
    with repository.transaction() as db:
        db.execute("UPDATE alerts SET count=999,first_seen=1,last_seen=2 WHERE id=?", (sudo_new,))
    with repository.reader() as db:
        queue_before = [
            tuple(row) for row in db.execute("SELECT * FROM discord_outbox ORDER BY seq")
        ]
    assert repository.prune(NOW - 100) == {"events": 1, "records": 0, "firewall_events": 0}
    assert repository.alert_detail(sudo_old) is None
    for alert_id in (ssh_new, sudo_new):
        detail = repository.alert_detail(alert_id)
        assert detail["count"] == 1
        assert detail["first_seen"] == detail["last_seen"] == NOW - 50
        assert len(detail["findings"]) == 1
    with repository.reader() as db:
        assert db.execute("SELECT COUNT(*) FROM sudo_evidence").fetchone()[0] == 1
        assert [
            tuple(row) for row in db.execute("SELECT * FROM discord_outbox ORDER BY seq")
        ] == queue_before
        assert db.execute("PRAGMA foreign_key_check").fetchall() == []


def test_navigation_counts_only_current_registered_sudo_cases_with_existing_sections(repository):
    add_sudo(repository)
    add_sudo(repository, 2, timestamp=NOW - 86_401)
    add_sudo(repository, 3, timestamp=NOW + 1)
    with repository.transaction() as db:
        add_ssh(db, repository, 1, NOW - 20)
        for detector in ("ssh.preauth_burst", "network.tcp_port_scan"):
            db.execute(
                "INSERT INTO alerts(detector_id,title,severity,reason,source_ip,"
                "first_seen,last_seen,count,details) VALUES(?,?,'medium','test','local',?,?,1,'{}')",
                (detector, detector, NOW - 30, NOW - 30),
            )
    assert repository.nav_alert_counts() == {
        "ssh": 1,
        "preauth": 1,
        "network": 1,
        "sudo": 1,
        "alerts": 4,
    }


def test_alarm_deletion_cascades_sudo_evidence_but_not_notification_history(repository):
    first = add_sudo(repository)
    with repository.reader() as db:
        previous = dict(db.execute("SELECT * FROM discord_outbox").fetchone())
    with repository.transaction() as db:
        db.execute("DELETE FROM alerts WHERE id=?", (first,))
    assert counts(repository)["sudo_evidence"] == 0
    assert counts(repository)["discord_outbox"] == 1
    add_sudo(repository, 2)
    with repository.reader() as db:
        queue = [dict(row) for row in db.execute("SELECT * FROM discord_outbox ORDER BY seq")]
    assert queue[0] == previous
    assert queue[1]["seq"] > previous["seq"] and queue[1]["ref"] != previous["ref"]
