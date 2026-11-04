"""Opt-in UFW journal integration, schema migration and safety boundaries."""

import json
import sqlite3
from pathlib import Path

import pytest

from yggdrasil_ids.config import AppConfig, NetworkConfig
from yggdrasil_ids.domain import Finding, SSHEvent
from yggdrasil_ids.engine import AnalysisEngine
from yggdrasil_ids.storage import SCHEMA_VERSION, Repository

NOW = 1_800_000_000.0
FIXTURES = Path(__file__).parent / "fixtures" / "ufw_journal.jsonl"


def examples():
    return [json.loads(line) for line in FIXTURES.read_text().splitlines()]


@pytest.fixture(autouse=True)
def live_clock(monkeypatch):
    # Exercise production's activation/future-time guards with a fixed clock.
    monkeypatch.setattr("yggdrasil_ids.engine.time.time", lambda: NOW - 1)


def config(tmp_path, *, mode="live", enabled=True):
    return AppConfig(
        database_path=tmp_path / "events.sqlite3",
        model_path=tmp_path / "model.json",
        credentials_path=tmp_path / "secrets.json",
        mode=mode,
        network=NetworkConfig(enabled=enabled),
    )


def count(repo, table):
    with repo.reader() as db:
        return db.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]


def test_schema3_migrates_without_changing_existing_ssh_alert_outbox(tmp_path):
    # Reproduce the actual Sprint 2 schema, not a v4 schema with tables removed.
    database = tmp_path / "events.sqlite3"
    with sqlite3.connect(database) as db:
        db.executescript((FIXTURES.parent / "schema_v3.sql").read_text())
        db.execute("PRAGMA user_version=3")
    repo = Repository(database)
    with repo.transaction() as db:
        db.execute(
            "INSERT INTO alerts(detector_id,title,severity,reason,source_ip,"
            "first_seen,last_seen,count,details) VALUES(?,?,?,?,?,?,?,1,?)",
            (
                "ssh.preauth_burst",
                "Previous alert",
                "medium",
                "kept",
                "192.0.2.77",
                NOW - 10,
                NOW - 9,
                "{}",
            ),
        )
        db.execute(
            "INSERT INTO records(id,cursor,timestamp,status,reason,raw_json) VALUES(?,?,?,?,?,?)",
            ("existing", "ssh-cursor", NOW - 15, "ignored", "old", "{}"),
        )
        repo.put_state(db, "cursor", "ssh-cursor")
        repo.put_state(db, "namespace", "live")
        repo.put_state(db, "mode", "live")
    with repo.reader() as db:
        old_instance = db.execute("SELECT instance FROM discord_outbox_meta").fetchone()[0]
        old_ref = db.execute("SELECT ref FROM discord_outbox").fetchone()[0]
    with sqlite3.connect(repo.path) as db:
        assert db.execute("PRAGMA user_version").fetchone()[0] == 3
        assert (
            db.execute(
                "SELECT COUNT(*) FROM sqlite_master WHERE name='firewall_events'"
            ).fetchone()[0]
            == 0
        )
    repo.initialize()
    repo.initialize()
    with repo.reader() as db:
        assert db.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION == 5
        assert db.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        assert db.execute("SELECT instance FROM discord_outbox_meta").fetchone()[0] == old_instance
        assert db.execute("SELECT ref FROM discord_outbox").fetchone()[0] == old_ref
        assert db.execute("SELECT COUNT(*) FROM alerts").fetchone()[0] == 1
        assert db.execute("SELECT COUNT(*) FROM records").fetchone()[0] == 1
        assert db.execute("SELECT COUNT(*) FROM firewall_events").fetchone()[0] == 0
    assert repo.get_state("cursor") == "ssh-cursor"


def test_mixed_ssh_and_ufw_are_isolated_and_duplicate_idempotent(tmp_path):
    engine = AnalysisEngine(config(tmp_path), namespace="test")
    udp, igmp, tcp, ipv6 = examples()
    assert engine.process(udp)["status"] == "event"
    assert engine.process(udp)["status"] == "duplicate"
    assert engine.process(igmp)["status"] == "event"
    assert engine.process(tcp)["status"] == "event"
    assert engine.process(ipv6)["status"] == "event"
    assert count(engine.repository, "firewall_events") == 4
    assert count(engine.repository, "events") == 0
    assert count(engine.repository, "records") == 0
    assert count(engine.repository, "observations") == 0
    assert count(engine.repository, "alerts") == 0
    assert count(engine.repository, "discord_outbox") == 0
    assert engine.repository.get_state("counters", {}) == {}
    assert engine.repository.get_state("firewall_counters") == {
        "events": 4,
        "duplicates": 1,
        "malformed": 0,
    }
    with engine.repository.reader() as db:
        udp_row = db.execute(
            "SELECT packet_length,transport_length,source_port,destination_port,"
            "tcp_flags FROM firewall_events WHERE cursor='synthetic-0'"
        ).fetchone()
        assert tuple(udp_row) == (491, 471, 36309, 55817, "[]")
        igmp_row = db.execute(
            "SELECT protocol_number,source_port,destination_port FROM firewall_events "
            "WHERE cursor='synthetic-1'"
        ).fetchone()
        assert tuple(igmp_row) == (2, None, None)
        values = [str(row) for row in db.execute("SELECT * FROM firewall_events")]
        assert "MAC=" not in " ".join(values)
    assert engine.repository.get_state("cursor") == "synthetic-3"


def test_non_ufw_kernel_records_are_not_kept_as_raw_ssh_logs(tmp_path):
    engine = AnalysisEngine(config(tmp_path), namespace="test")
    non_ufw = {
        "_TRANSPORT": "kernel",
        "__CURSOR": "kernel-other",
        "MESSAGE": "Unrelated kernel message",
    }
    assert engine.process(non_ufw)["status"] == "ignored"
    assert count(engine.repository, "records") == 0
    assert count(engine.repository, "firewall_events") == 0
    assert engine.repository.get_state("cursor") == "kernel-other"


def test_live_first_activation_skips_old_kernel_records(tmp_path, monkeypatch):
    monkeypatch.setattr("yggdrasil_ids.engine.time.time", lambda: NOW + 30)
    engine = AnalysisEngine(config(tmp_path, mode="live"), namespace="live")
    old = examples()[2]
    assert engine.process(old)["status"] == "historical"
    assert count(engine.repository, "firewall_events") == 0
    new = dict(old)
    new["__CURSOR"] = "later"
    new["__REALTIME_TIMESTAMP"] = str(int((NOW + 31) * 1_000_000))
    assert engine.process(new)["status"] == "event"
    assert count(engine.repository, "firewall_events") == 1
    assert engine.repository.get_state("cursor") == "later"
    restarted = AnalysisEngine(config(tmp_path, mode="live"), namespace="live")
    assert restarted.repository.get_state("firewall_started_at") == NOW + 30


def test_failure_rolls_back_network_event_and_shared_cursor(tmp_path, monkeypatch):
    engine = AnalysisEngine(config(tmp_path), namespace="test")
    engine.repository.set_state("cursor", "original-ssh")
    original = engine.repository.insert_firewall_event

    def fail(*args):
        raise sqlite3.OperationalError("simulated disk error")

    monkeypatch.setattr(engine.repository, "insert_firewall_event", fail)
    with pytest.raises(sqlite3.OperationalError, match="simulated"):
        engine.process(examples()[2])
    assert engine.repository.get_state("cursor") == "original-ssh"
    assert count(engine.repository, "firewall_events") == 0
    monkeypatch.setattr(engine.repository, "insert_firewall_event", original)
    assert engine.process(examples()[2])["status"] == "event"
    assert engine.repository.get_state("cursor") == "synthetic-2"


def test_network_history_retention_and_backup_are_independent(tmp_path):
    engine = AnalysisEngine(config(tmp_path), namespace="test")
    first = examples()[2]
    second = dict(first)
    second["__CURSOR"] = "synthetic-followup"
    second["__REALTIME_TIMESTAMP"] = str(int((NOW + 10) * 1_000_000))
    assert engine.process(first)["status"] == "event"
    assert engine.process(second)["status"] == "event"
    with engine.repository.reader() as db:
        last = engine.firewall_parser.parse(second, namespace="test").event
        assert last is not None
        history = engine.repository.firewall_history(db, last, 60)
        assert len(history) == 2
        assert all(item.tcp_flags == ("SYN",) for item in history)
        with pytest.raises(ValueError, match="for stor"):
            engine.repository.firewall_history(db, last, 60, limit=1)
    backup = tmp_path / "backup.sqlite3"
    engine.repository.backup(backup)
    assert count(Repository(backup, readonly=True), "firewall_events") == 2
    result = engine.repository.prune(NOW + 5)
    assert result["firewall_events"] == 1
    assert count(engine.repository, "firewall_events") == 1


def test_network_config_default_does_not_touch_kernel_source(tmp_path):
    disabled = AnalysisEngine(config(tmp_path, enabled=False), namespace="test")
    assert disabled.config.network.enabled is False
    assert count(disabled.repository, "firewall_events") == 0


def scan_record(
    index, *, port=None, source="192.0.2.50", target="192.0.2.92", interface="wlan0", timestamp=None
):
    at = NOW + index if timestamp is None else timestamp
    return {
        "_TRANSPORT": "kernel",
        "_HOSTNAME": "test-sensor",
        "_BOOT_ID": "a" * 32,
        "__CURSOR": f"port-scan-{index}-{port}-{target}-{interface}",
        "__REALTIME_TIMESTAMP": str(int(at * 1_000_000)),
        "MESSAGE": (
            f"[UFW BLOCK] IN={interface} OUT= SRC={source} DST={target} "
            f"LEN=60 PROTO=TCP SPT=40000 DPT={port if port is not None else 1000 + index} SYN"
        ),
    }


def test_network_scan_creates_one_incident_and_discord_outbox_message(tmp_path):
    engine = AnalysisEngine(config(tmp_path), namespace="test")
    for index in range(5):
        assert engine.process(scan_record(index))["findings"] == 0
    sixth = engine.process(scan_record(5))
    assert sixth["status"] == "event"
    assert sixth["findings"] == 1
    assert count(engine.repository, "events") == 0
    assert count(engine.repository, "observations") == 0
    assert count(engine.repository, "alerts") == 1
    assert count(engine.repository, "network_evidence") == 1
    assert count(engine.repository, "discord_outbox") == 1
    with engine.repository.reader() as db:
        alert = db.execute("SELECT * FROM alerts").fetchone()
        alert_id = alert["id"]
        assert alert["detector_id"] == "network.tcp_port_scan"
        assert alert["severity"] == "medium"
        assert alert["count"] == 1
    detail = engine.repository.alert_detail(alert_id)
    assert len(detail["findings"]) == 1
    assert detail["findings"][0]["outcome"] == "firewall"
    assert len(detail["details"]["destination_ports"]) == 6
    # A seventh port updates the same incident, but does not create a
    # second Discord notification. Repeated source-port probes do not count.
    assert engine.process(scan_record(6))["findings"] == 1
    repeated = scan_record(7, port=1006)
    assert engine.process(repeated)["findings"] == 0
    assert count(engine.repository, "alerts") == 1
    assert count(engine.repository, "network_evidence") == 2
    assert count(engine.repository, "discord_outbox") == 1
    assert engine.repository.alert_detail(alert_id)["count"] == 2
    assert engine.process(scan_record(6))["status"] == "duplicate"
    assert count(engine.repository, "network_evidence") == 2
    assert count(engine.repository, "discord_outbox") == 1


def test_ssh_and_network_alerts_have_independent_grouping_and_outbox(tmp_path):
    """SSH cooldown never suppresses a separate scan notification."""
    engine = AnalysisEngine(config(tmp_path), namespace="test")
    for index in range(6):
        engine.process(scan_record(index))
    assert count(engine.repository, "discord_outbox") == 1

    def ssh_finding(index):
        item = SSHEvent(
            f"ssh-finding-{index}",
            NOW + index,
            "192.0.2.50",
            "labuser",
            "failure",
            "publickey",
            "test-sensor",
            "Synthetic SSH event",
        )
        finding = Finding(
            "ssh.failed_burst",
            "Test SSH alarm",
            "medium",
            "Synthetic SSH burst for grouping test",
            item.source_ip,
            item.event_id,
            item.timestamp,
            {"event_ids": [item.event_id]},
            None,
            None,
        )
        with engine.repository.transaction() as db:
            engine.repository.insert_event(db, item)
            return engine.repository.add_finding(db, finding, cooldown=300)

    # The SSH alarm uses the SAME source and time period as the portscan,
    # but must create its own incident and Discord outbox entry.
    first_ssh = ssh_finding(7)
    assert count(engine.repository, "alerts") == 2
    assert count(engine.repository, "discord_outbox") == 2

    # Later findings inside the respective 300-second cooldowns update
    # their own incident, but must not produce additional notifications.
    assert engine.process(scan_record(8))["findings"] == 1
    assert ssh_finding(9) == first_ssh
    assert count(engine.repository, "alerts") == 2
    assert count(engine.repository, "discord_outbox") == 2

    with engine.repository.reader() as db:
        categories = {
            row["detector_id"]: row["n"]
            for row in db.execute(
                "SELECT detector_id, COUNT(*) AS n FROM discord_outbox GROUP BY detector_id"
            )
        }
    assert categories == {"network.tcp_port_scan": 1, "ssh.failed_burst": 1}


def test_different_destinations_and_interfaces_have_separate_incidents(tmp_path):
    engine = AnalysisEngine(config(tmp_path), namespace="test")
    for index in range(6):
        assert engine.process(scan_record(index))["findings"] == (1 if index == 5 else 0)
    for index in range(6, 12):
        assert engine.process(scan_record(index, target="192.0.2.93"))["findings"] == (
            1 if index == 11 else 0
        )
    for index in range(12, 18):
        assert engine.process(scan_record(index, interface="tailscale0"))["findings"] == (
            1 if index == 17 else 0
        )
    assert count(engine.repository, "alerts") == 3
    assert count(engine.repository, "discord_outbox") == 3


def test_firewall_errors_leave_ssh_and_discord_state_unchanged(tmp_path, monkeypatch):
    engine = AnalysisEngine(config(tmp_path), namespace="test")
    for index in range(5):
        engine.process(scan_record(index))
    original_cursor = engine.repository.get_state("cursor")
    prior_counters = engine.repository.get_state("firewall_counters")
    original = engine.repository.add_network_alert

    def fail(*_args, **_kwargs):
        raise sqlite3.OperationalError("simulated full disk")

    monkeypatch.setattr(engine.repository, "add_network_alert", fail)
    with pytest.raises(sqlite3.OperationalError, match="full disk"):
        engine.process(scan_record(5))
    assert engine.repository.get_state("cursor") == original_cursor
    assert engine.repository.get_state("firewall_counters") == prior_counters
    assert count(engine.repository, "firewall_events") == 5
    assert count(engine.repository, "alerts") == 0
    assert count(engine.repository, "discord_outbox") == 0
    monkeypatch.setattr(engine.repository, "add_network_alert", original)
    assert engine.process(scan_record(5))["findings"] == 1


def test_replay_and_retention_do_not_regenerate_old_scan_notifications(tmp_path):
    engine = AnalysisEngine(config(tmp_path), namespace="test")
    for index in range(6):
        engine.process(scan_record(index))
    assert count(engine.repository, "discord_outbox") == 1
    assert count(engine.repository, "network_evidence") == 1
    restarted = AnalysisEngine(config(tmp_path), namespace="test")
    assert restarted.process(scan_record(5))["status"] == "duplicate"
    assert count(restarted.repository, "discord_outbox") == 1
    assert restarted.repository.prune(NOW + 6)["firewall_events"] == 6
    assert count(restarted.repository, "network_evidence") == 0
    assert count(restarted.repository, "alerts") == 0
    # Delivery outbox identity is retained even after incident history pruning.
    assert count(restarted.repository, "discord_outbox") == 1


def test_udp_multicast_and_repeat_port_never_trigger_scan(tmp_path):
    engine = AnalysisEngine(config(tmp_path), namespace="test")
    for entry in examples()[:2]:
        assert engine.process(entry)["findings"] == 0
    for index in range(12):
        assert engine.process(scan_record(index, port=22))["findings"] == 0
    assert count(engine.repository, "firewall_events") == 14
    assert count(engine.repository, "alerts") == 0
