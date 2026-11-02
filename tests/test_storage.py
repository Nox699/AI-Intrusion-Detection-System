"""Persistence tests focus on atomicity, retained evidence and read boundaries."""

import sqlite3
import stat
from pathlib import Path

import pytest

from yggdrasil_ids.domain import Finding, SSHEvent
from yggdrasil_ids.storage import SCHEMA_VERSION, Repository

NOW = 1_800_000_000.0
BASE = NOW - 1800


@pytest.fixture
def repository(tmp_path, monkeypatch):
    monkeypatch.setattr("yggdrasil_ids.storage.time.time", lambda: NOW)
    repository = Repository(tmp_path / "data/events.sqlite3")
    repository.initialize()
    return repository


def event(index, *, timestamp=None, username="labuser", source="192.0.2.8", outcome="failure"):
    return SSHEvent(
        str(index),
        BASE + index if timestamp is None else timestamp,
        source,
        username,
        outcome,
        "publickey",
        "server",
        "SSH test",
    )


def finding(item, *, detector="ssh.failed_burst", version=None):
    return Finding(
        detector,
        "Test alarm",
        "high",
        "Documented test threshold",
        item.source_ip,
        item.event_id,
        item.timestamp,
        {"event_ids": [item.event_id]},
        0.7 if version else None,
        version,
    )


def insert(repository, *items):
    with repository.transaction() as db:
        for item in items:
            repository.insert_event(db, item)


def test_firewall_charts_bound_port_count_and_preserve_private_sources(repository):
    """Twelve ports become ten categories plus a single Other total."""
    import json

    from yggdrasil_ids.firewall import UFWParser

    parser = UFWParser()
    with repository.transaction() as db:
        for index in range(14):
            port = 45010 if index >= 12 else 45010 + index
            raw = {
                "_TRANSPORT": "kernel",
                "_BOOT_ID": "a" * 32,
                "_HOSTNAME": "test-sensor",
                "__CURSOR": f"chart-{index}",
                "__REALTIME_TIMESTAMP": str(int((NOW - 120 + index) * 1_000_000)),
                "MESSAGE": (
                    "[UFW BLOCK] IN=wlan0 OUT= SRC=192.0.2.33 DST=192.0.2.92 "
                    f"PROTO=TCP SPT=40000 DPT={port} SYN"
                ),
            }
            parsed = parser.parse(raw, namespace="test")
            assert parsed.event is not None
            assert repository.insert_firewall_event(db, parsed.event)

    report = repository.firewall_charts(hours=1)
    assert report["total_packets"] == 14
    assert report["unique_ports"] == 12
    assert len(report["top_ports"]) == 10
    assert report["top_ports"][0] == {"port": 45010, "packets": 3}
    assert report["other_ports_packets"] == 2
    assert sum(row["packets"] for row in report["series"]) == 14
    assert len(report["series"]) <= 12
    assert "192.0.2.33" not in json.dumps(report)

    before = repository.get_state("cursor")
    reader = Repository(repository.path, readonly=True)
    assert reader.firewall_charts(hours=1) == report
    assert repository.get_state("cursor") == before


def test_readonly_repository_cannot_write_even_if_query_only_is_disabled(repository):
    repository.set_state("collector", {"state": "running"})
    reader = Repository(repository.path, readonly=True)
    assert reader.get_state("collector") == {"state": "running"}
    for operation in (
        reader.initialize,
        lambda: reader.set_state("collector", {}),
        lambda: reader.prune(NOW),
    ):
        with pytest.raises(PermissionError):
            operation()
    with reader.reader() as db:
        db.execute("PRAGMA query_only=OFF")
        with pytest.raises(sqlite3.OperationalError, match="readonly"):
            db.execute("DELETE FROM state")
    assert repository.get_state("collector") == {"state": "running"}


def test_closed_database_can_be_read_from_filesystem_read_only_directory(repository):
    insert(repository, event(1))
    repository.set_state("collector", {"state": "stopped"})
    database = repository.path
    directory = database.parent
    directory_mode = stat.S_IMODE(directory.stat().st_mode)
    database_mode = stat.S_IMODE(database.stat().st_mode)
    before = database.read_bytes()
    probe = directory / "write-probe"
    try:
        directory.chmod(0o555)
        database.chmod(0o444)
        try:
            probe.write_text("check actual filesystem permission enforcement")
        except PermissionError:
            pass
        else:
            pytest.skip("Process bypasses Unix mode bits; cannot test a read-only directory")

        reader = Repository(database, readonly=True)
        assert reader.get_state("collector") == {"state": "stopped"}
        assert reader.list_events()["total"] == 1
        assert database.read_bytes() == before
        assert {path.name for path in directory.iterdir()} == {database.name}
    finally:
        directory.chmod(directory_mode)
        database.chmod(database_mode)
        probe.unlink(missing_ok=True)


def test_reading_missing_database_does_not_create_a_fake_empty_database(tmp_path):
    path = tmp_path / "missing.sqlite3"
    with pytest.raises(sqlite3.OperationalError):
        Repository(path, readonly=True).dashboard()
    assert not path.exists()


def test_unsupported_schema_is_rejected_without_overwriting_existing_data(tmp_path):
    path = tmp_path / "future.sqlite3"
    with sqlite3.connect(path) as db:
        db.execute("CREATE TABLE marker(value TEXT)")
        db.execute("INSERT INTO marker VALUES('preserve me')")
        db.execute("PRAGMA user_version=999")
    before = path.read_bytes()
    with pytest.raises(ValueError, match="999"):
        Repository(path).initialize()
    assert path.read_bytes() == before
    with sqlite3.connect(path) as db:
        assert db.execute("SELECT value FROM marker").fetchone() == ("preserve me",)
        assert db.execute("PRAGMA user_version").fetchone()[0] == 999


def test_initialization_is_idempotent_and_preserves_state(repository):
    insert(repository, event(1))
    repository.set_state("cursor", "first")
    repository.initialize()
    assert repository.list_events()["total"] == 1
    assert repository.get_state("cursor") == "first"
    assert repository.status()["database"]["schema_version"] == SCHEMA_VERSION


def test_filters_treat_sql_metacharacters_as_literal_values(repository):
    unusual_user = "' OR 1=1 --"
    insert(repository, event(1, username=unusual_user), event(2))
    assert repository.list_events(user=unusual_user)["total"] == 1
    assert repository.list_events(user=unusual_user)["items"][0]["username"] == unusual_user
    assert repository.list_events(source="192.0.2.8' OR 1=1 --")["total"] == 0
    assert repository.list_events(outcome="failure' OR 1=1 --")["total"] == 0
    assert repository.list_alerts(detector="x'; DROP TABLE events; --")["total"] == 0
    assert repository.list_events()["total"] == 2


def test_filters_and_pagination_preserve_total_and_stable_order(repository):
    insert(repository, *[event(i, username="labuser" if i % 2 else "admin") for i in range(1, 6)])
    page = repository.list_events(user="labuser", per_page=2)
    assert page["total"] == 3
    assert page["pages"] == 2
    assert [row["event_id"] for row in page["items"]] == ["5", "3"]
    last = repository.list_events(user="labuser", page=999, per_page=2)
    assert last["page"] == 2
    assert [row["event_id"] for row in last["items"]] == ["1"]


@pytest.mark.parametrize(
    "kwargs", [{"hours": True}, {"hours": 0}, {"page": 0}, {"page": True}, {"per_page": 101}]
)
def test_query_bounds_are_enforced(repository, kwargs):
    with pytest.raises(ValueError):
        repository.list_events(**kwargs)


def test_history_uses_same_source_and_exclusive_start_inclusive_end(repository):
    current = event(3, timestamp=BASE + 300)
    insert(
        repository,
        event(0, timestamp=BASE),
        event(1, timestamp=BASE + 1),
        event(2, timestamp=BASE + 200, source="198.51.100.2"),
        current,
        event(4, timestamp=BASE + 301),
    )
    with repository.reader() as db:
        rows = repository.history(db, current, 300)
    assert [row.event_id for row in rows] == ["1", "3"]


def test_cooldown_boundary_groups_findings_but_not_separate_incidents(repository):
    first = event(1, timestamp=BASE)
    boundary = event(2, timestamp=BASE + 300)
    outside = event(3, timestamp=BASE + 601)
    with repository.transaction() as db:
        ids = []
        for item in [first, boundary, outside]:
            repository.insert_event(db, item)
            ids.append(repository.add_finding(db, finding(item), cooldown=300))
    assert ids[0] == ids[1]
    assert ids[2] != ids[1]
    grouped = repository.alert_detail(ids[0])
    assert grouped["count"] == 2
    assert grouped["first_seen"] == first.timestamp
    assert grouped["last_seen"] == boundary.timestamp
    assert {row["event_id"] for row in grouped["findings"]} == {"1", "2"}


def test_different_detectors_sources_and_model_versions_are_not_merged(repository):
    variants = [
        (event(1), "ssh.isolation_forest", "model-one"),
        (event(2), "ssh.isolation_forest", "model-two"),
        (event(3), "ssh.failed_burst", None),
        (event(4, source="198.51.100.2"), "ssh.failed_burst", None),
    ]
    with repository.transaction() as db:
        ids = []
        for item, detector, version in variants:
            repository.insert_event(db, item)
            ids.append(
                repository.add_finding(db, finding(item, detector=detector, version=version), 300)
            )
    assert len(set(ids)) == 4
    assert repository.list_alerts()["total"] == 4


def test_repeated_finding_does_not_duplicate_evidence_or_incident_count(repository):
    item = event(1)
    with repository.transaction() as db:
        repository.insert_event(db, item)
        first_id = repository.add_finding(db, finding(item), 300)
        assert repository.add_finding(db, finding(item), 300) == first_id
    detail = repository.alert_detail(first_id)
    assert detail["count"] == 1
    assert len(detail["findings"]) == 1
    assert detail["findings"][0]["details"] == {"event_ids": ["1"]}
    assert not detail["findings_truncated"]


def test_transaction_rolls_back_event_cursor_and_partial_alarm_on_failure(repository):
    repository.set_state("cursor", "before")
    with pytest.raises(sqlite3.IntegrityError):
        with repository.transaction() as db:
            repository.insert_event(db, event(1))
            repository.put_state(db, "cursor", "after")
            # add_finding inserts/updates an alarm before enforcing the event FK.
            repository.add_finding(db, finding(event(999)), 300)
    assert repository.list_events()["total"] == 0
    assert repository.list_alerts()["total"] == 0
    assert repository.get_state("cursor") == "before"


def test_nonfinite_state_cannot_be_committed_as_invalid_json(repository):
    with pytest.raises(ValueError):
        with repository.transaction() as db:
            repository.insert_event(db, event(1))
            repository.put_state(db, "bad", {"score": float("nan")})
    assert repository.list_events()["total"] == 0
    assert repository.get_state("bad") is None


def test_retention_cascades_and_recounts_retained_incident_evidence(repository):
    old = event(1, timestamp=BASE)
    boundary = event(2, timestamp=BASE + 200)
    old_only = event(3, timestamp=BASE - 100, source="198.51.100.4")
    with repository.transaction() as db:
        alert_ids = []
        for item in [old, boundary, old_only]:
            repository.insert_event(db, item)
            db.execute(
                "INSERT INTO records VALUES(?,?,?,?,?,?)",
                (item.event_id, item.cursor, item.timestamp, "event", "", "{}"),
            )
            db.execute(
                "INSERT INTO observations(event_id,timestamp,source_ip,features,state) VALUES(?,?,?,?,?)",
                (item.event_id, item.timestamp, item.source_ip, '{"failure_count":1}', "untrained"),
            )
            alert_ids.append(repository.add_finding(db, finding(item), 300))
    assert alert_ids[0] == alert_ids[1]
    assert repository.prune(BASE + 200) == {"events": 2, "records": 2, "firewall_events": 0}
    assert repository.alert_detail(alert_ids[2]) is None
    retained = repository.alert_detail(alert_ids[0])
    assert retained["count"] == 1
    assert retained["first_seen"] == boundary.timestamp
    assert retained["last_seen"] == boundary.timestamp
    assert [row["event_id"] for row in retained["findings"]] == ["2"]
    observations = repository.list_observations()
    assert observations["total"] == 1
    assert observations["items"][0]["features"] == {"failure_count": 1}
    with repository.reader() as db:
        assert db.execute("PRAGMA foreign_key_check").fetchall() == []


def test_dashboard_counts_selected_period_without_future_or_old_events(repository):
    insert(
        repository,
        event(1, timestamp=NOW - 10, outcome="success"),
        event(2, timestamp=NOW - 20),
        event(3, timestamp=NOW - 4000),
        event(4, timestamp=NOW + 10),
    )
    result = repository.dashboard(hours=1)
    assert result["totals"] == {"success": 1, "failure": 1, "events": 2, "alerts": 0}
    assert sum(row["success"] for row in result["series"]) == 1
    assert sum(row["failure"] for row in result["series"]) == 1
    assert result["top_sources"][0]["count"] == 2


def test_chart_preauth_is_distinct_and_includes_preauth_only_buckets(repository):
    import json

    def record(index, timestamp, *, uid="0", comm="sshd-session", status="ignored"):
        return (
            f"preauth-{index}",
            f"cursor-{index}",
            timestamp,
            status,
            "preauth",
            json.dumps(
                {
                    "_UID": uid,
                    "_COMM": comm,
                    "MESSAGE": (
                        "Connection closed by authenticating user labuser "
                        f"192.0.2.7 port {20000 + index} [preauth]"
                    ),
                }
            ),
        )

    # A real authentication and a preauth disconnect can share one bucket.
    insert(repository, event(1, timestamp=NOW - 20, outcome="success"))
    with repository.transaction() as db:
        db.executemany(
            "INSERT INTO records(id,cursor,timestamp,status,reason,raw_json) VALUES(?,?,?,?,?,?)",
            [
                record(1, NOW - 25),
                record(2, NOW - 35),
                record(3, NOW - 610),  # Another observed, preauth-only bucket.
                record(4, NOW - 15, uid="1000"),  # Not root-owned: ignore.
                record(5, NOW - 16, comm="logger"),  # Not OpenSSH: ignore.
                record(6, NOW - 3700),  # Before the selected period.
                record(7, NOW + 10),  # Future journal timestamp.
            ],
        )
    result = repository.dashboard(hours=1)
    assert result["totals"] == {"success": 1, "failure": 0, "events": 1, "alerts": 0}
    assert result["preauth_count"] == 3
    assert sum(row["success"] for row in result["series"]) == 1
    assert sum(row["failure"] for row in result["series"]) == 0
    assert sum(row["preauth"] for row in result["series"]) == 3
    assert len(result["series"]) == 2
    assert any(
        row["preauth"] == 1 and row["success"] == 0 and row["failure"] == 0
        for row in result["series"]
    )
    assert any(row["preauth"] == 2 and row["success"] == 1 for row in result["series"])


def test_chart_empty_history_uses_no_synthetic_activity(repository):
    result = repository.dashboard(hours=1)
    assert result["series"] == []
    assert result["preauth_count"] == 0


def test_day_chart_uses_half_hour_intervals_but_hour_chart_keeps_five_minutes(repository):
    # The same two observed successes share one 30-minute bucket.
    insert(
        repository,
        event(31, timestamp=NOW - 1600, outcome="success"),
        event(32, timestamp=NOW - 1200, outcome="success"),
    )
    day = repository.dashboard(hours=24)
    short = repository.dashboard(hours=1)
    assert len(day["series"]) == 1
    assert day["series"][0]["success"] == 2
    assert day["series"][0]["preauth"] == 0
    assert len(short["series"]) == 2
    assert sum(item["success"] for item in short["series"]) == 2
    assert all(item["preauth"] == 0 for item in short["series"])
    assert day["totals"]["success"] == 2


def test_backup_is_consistent_readable_and_does_not_include_uncommitted_data(repository, tmp_path):
    insert(repository, event(1))
    repository.set_state("cursor", "committed")
    destination = tmp_path / "backups/snapshot.sqlite3"
    with repository.transaction() as db:
        repository.insert_event(db, event(2))
        repository.put_state(db, "cursor", "pending")
        Repository(repository.path, readonly=True).backup(destination)
    snapshot = Repository(destination, readonly=True)
    assert snapshot.list_events()["total"] == 1
    assert snapshot.get_state("cursor") == "committed"
    assert snapshot.status()["database"]["schema_version"] == SCHEMA_VERSION
    assert repository.list_events()["total"] == 2
    assert repository.get_state("cursor") == "pending"
    assert stat.S_IMODE(destination.stat().st_mode) == 0o600
    with snapshot.reader() as db:
        assert db.execute("PRAGMA integrity_check").fetchone()[0] == "ok"


def test_backup_refuses_existing_destination_and_source_path(repository, tmp_path):
    destination = tmp_path / "existing.sqlite3"
    destination.write_bytes(b"do not replace")
    with pytest.raises(FileExistsError):
        repository.backup(destination)
    assert destination.read_bytes() == b"do not replace"
    with pytest.raises(ValueError):
        repository.backup(repository.path)


def test_backup_does_not_overwrite_a_file_created_between_check_and_open(
    repository, tmp_path, monkeypatch
):
    destination = tmp_path / "backups/snapshot.sqlite3"
    original_mkdir = Path.mkdir

    def concurrent_file_creation(path, *args, **kwargs):
        result = original_mkdir(path, *args, **kwargs)
        if path == destination.parent:
            with sqlite3.connect(destination) as db:
                db.execute("CREATE TABLE marker(value TEXT)")
                db.execute("INSERT INTO marker VALUES('concurrent file')")
        return result

    monkeypatch.setattr(Path, "mkdir", concurrent_file_creation)
    with pytest.raises(FileExistsError):
        repository.backup(destination)
    with sqlite3.connect(destination) as db:
        assert db.execute("SELECT value FROM marker").fetchone() == ("concurrent file",)
