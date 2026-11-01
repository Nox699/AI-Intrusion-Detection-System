"""Isolated regression tests for read-only Sprint 3 scan observations."""
import importlib.util
import json
import sqlite3
from pathlib import Path

PATH = Path(__file__).resolve().parents[1] / "deploy/sprint3_network_observe.py"
spec = importlib.util.spec_from_file_location("network_observation", PATH)
obs = importlib.util.module_from_spec(spec)
spec.loader.exec_module(obs)


def test_rolling_distinct_port_limit():
    assert obs.peak_distinct([(100, 45010), (110, 45010), (159, 45011)]) == 2
    assert obs.peak_distinct([(100, 45010), (160, 45011)]) == 1
    assert obs.peak_distinct([(100, 45010), (101, 45011), (102, 45012)]) == 3


def test_aggregate_report_does_not_disclose_ips_or_modify_db(tmp_path):
    db_path = tmp_path / "events.sqlite3"
    with sqlite3.connect(db_path) as db:
        db.execute("PRAGMA user_version=4")
        db.executescript(
            "CREATE TABLE firewall_events("
            "timestamp REAL,action TEXT,direction TEXT,in_interface TEXT,"
            "out_interface TEXT,namespace TEXT,host TEXT,boot_id TEXT,"
            "source_ip TEXT,destination_ip TEXT,protocol_number INTEGER,"
            "destination_port INTEGER,tcp_flags TEXT,event_id TEXT);"
            "CREATE TABLE alerts(detector_id TEXT,last_seen REAL);"
            "CREATE TABLE network_evidence(detector_id TEXT,timestamp REAL);"
            "CREATE TABLE discord_outbox(detector_id TEXT,happened_at REAL);"
            "CREATE TABLE state(key TEXT,value TEXT);"
        )
        for i in range(7):
            db.execute(
                "INSERT INTO firewall_events VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    1000 + i,
                    "BLOCK",
                    "incoming",
                    "wlan0",
                    "",
                    "live",
                    "Yggdrasil",
                    "boot",
                    "192.0.2.101",
                    "192.0.2.102",
                    6,
                    45010 + i,
                    json.dumps(["SYN"]),
                    str(i),
                ),
            )
        db.execute("INSERT INTO alerts VALUES('network.tcp_port_scan',1005)")
        db.execute("INSERT INTO network_evidence VALUES('network.tcp_port_scan',1005)")
        db.execute("INSERT INTO discord_outbox VALUES('network.tcp_port_scan',1005)")
        db.execute(
            "INSERT INTO state VALUES('collector',?)",
            (json.dumps({"state": "running", "heartbeat_at": 1009}),),
        )
        db.execute("INSERT INTO state VALUES('firewall_started_at','999')")
    report = obs.observe(db_path, 1010, minutes=10)
    assert report["firewall_records_in_window"] == 7
    assert report["max_distinct_selected_ports_in_60s_one_group"] == 7
    assert report["scan_alerts_in_window"] == 1
    assert report["network_evidence_in_window"] == 1
    assert report["scan_outbox_in_window"] == 1
    assert report["collector_state"] == "running"
    assert "192.0.2." not in json.dumps(report)
    with sqlite3.connect(db_path) as db:
        assert db.execute("SELECT COUNT(*) FROM firewall_events").fetchone()[0] == 7
