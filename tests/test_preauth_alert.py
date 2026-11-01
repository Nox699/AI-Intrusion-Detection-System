"""End-to-end preauth alert tests, with no SSH auth or ML pollution."""

from yggdrasil_ids.config import AppConfig, RulesConfig
from yggdrasil_ids.engine import AnalysisEngine
from yggdrasil_ids.preauth import parse_preauth
from yggdrasil_ids.storage import Repository


def record(index, timestamp, message):
    return {
        "__CURSOR": f"test-{index}",
        "__REALTIME_TIMESTAMP": str(int(timestamp * 1000000)),
        "_COMM": "sshd-session",
        "_UID": "0",
        "_PID": "123",
        "MESSAGE": message,
    }


def test_parser_checks_producer_and_ip():
    good = record(
        1, 1800000000,
        "Connection closed by authenticating user vidar 192.0.2.7 port 12345 [preauth]",
    )
    assert parse_preauth(good).source_ip == "192.0.2.7"
    assert parse_preauth({**good, "_UID": "1000"}) is None
    assert parse_preauth({**good, "_COMM": "logger"}) is None
    assert parse_preauth({**good, "MESSAGE": "Connection closed by authenticating user vidar bad-ip port 12345 [preauth]"}) is None


def test_burst_needs_threshold_and_never_scores_as_login(tmp_path, monkeypatch):
    monkeypatch.setattr("yggdrasil_ids.engine.time.time", lambda: 1800000000)
    cfg = AppConfig(
        database_path=tmp_path / "events.sqlite3",
        model_path=tmp_path / "model.json",
        credentials_path=tmp_path / "creds.json",
        mode="demo",
        rules=RulesConfig(preauth_threshold=5),
    )
    engine = AnalysisEngine(cfg, "test")
    for index in range(5):
        item = record(
            index, 1800000000 - 20 + index,
            f"Connection closed by authenticating user vidar 192.0.2.7 port {12345+index} [preauth]",
        )
        result = engine.process(item)
        assert result["findings"] == (1 if index == 4 else 0)
    assert engine.repository.dashboard()["totals"]["alerts"] == 1
    assert engine.repository.dashboard()["totals"]["events"] == 0
    assert engine.repository.list_alerts()["items"][0]["detector_id"] == "ssh.preauth_burst"
    assert len(engine.repository.alert_detail(1)["findings"]) == 1
    assert engine.process(item)["status"] == "duplicate"
    with engine.repository.reader() as db:
        assert db.execute("SELECT COUNT(*) FROM observations").fetchone()[0] == 0
        assert db.execute("SELECT COUNT(*) FROM preauth_disconnects").fetchone()[0] == 5


def test_migration_preserves_existing_events(tmp_path):
    import sqlite3

    path = tmp_path / "old.sqlite3"
    repo = Repository(path)
    repo.initialize()
    with repo.connect() as db:
        db.execute("DROP TABLE preauth_evidence")
        db.execute("DROP TABLE preauth_disconnects")
        db.execute("PRAGMA user_version=1")
    repo.initialize()
    with repo.reader() as db:
        assert db.execute("PRAGMA user_version").fetchone()[0] == 2
        assert db.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    repo.initialize()
