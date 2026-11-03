"""Anonymous revision snapshots and exact initial-page acknowledgement context."""

import json
import re

import pytest

from yggdrasil_ids.nav_alerts import snapshot
from yggdrasil_ids.storage import Repository

NOW = 1_800_000_000.0


def add(repo, detector, stamp=NOW - 10, count=1):
    with repo.transaction() as db:
        return db.execute(
            "INSERT INTO alerts(detector_id,title,severity,reason,source_ip,first_seen,last_seen,count,details) "
            "VALUES(?,'private alarm','medium','private reason','private source',?,?,?,'{}')",
            (detector, stamp, stamp, count),
        ).lastrowid


def test_snapshot_contains_only_recent_cases_and_revisions_without_private_content(tmp_path):
    repo = Repository(tmp_path / "events.sqlite3")
    repo.initialize()
    add(repo, "sudo.repeated_auth_failure")
    add(repo, "ssh.preauth_burst")
    add(repo, "network.tcp_port_scan", NOW - 90000)
    before = repo.path.read_bytes()
    result = snapshot(Repository(repo.path, readonly=True), now=NOW)
    assert result["counts"] == {"ssh": 0, "preauth": 1, "network": 0, "sudo": 1, "alerts": 2}
    assert result["cases"] == [
        {"id": 1, "section": "sudo", "count": 1, "last_seen": NOW - 10},
        {"id": 2, "section": "preauth", "count": 1, "last_seen": NOW - 10},
    ]
    assert "private" not in json.dumps(result)
    assert repo.path.read_bytes() == before
    with repo.transaction() as db:
        db.execute("UPDATE alerts SET count=2,last_seen=? WHERE id=1", (NOW - 1,))
    assert snapshot(repo, now=NOW)["cases"][0]["count"] == 2


def test_overflow_or_missing_source_identity_is_not_presented_as_zero(tmp_path, monkeypatch):
    repo = Repository(tmp_path / "events.sqlite3")
    repo.initialize()
    add(repo, "ssh.failed_burst")
    monkeypatch.setattr("yggdrasil_ids.nav_alerts.MAX_CASES", 0)
    with pytest.raises(ValueError, match="bounded"):
        snapshot(repo, now=NOW)
    with repo.transaction() as db:
        db.execute("DELETE FROM discord_outbox_meta")
    with pytest.raises(ValueError, match="identity"):
        snapshot(repo, now=NOW)


def extract_view(response):
    raw = re.search(
        r'<script id="nav-alert-view" type="application/json">(.*?)</script>',
        response.get_data(as_text=True),
        re.S,
    ).group(1)
    return json.loads(raw)


def test_page_scope_and_detail_metadata_are_authenticated_readonly(tmp_path):
    import time

    from werkzeug.security import generate_password_hash

    from yggdrasil_ids.config import AppConfig
    from yggdrasil_ids.web import create_app

    credentials = tmp_path / "credentials.json"
    credentials.write_text(
        json.dumps(
            {
                "secret_key": "test-key-that-exceeds-thirty-two-characters",
                "password_hash": generate_password_hash("test", method="pbkdf2:sha256:1000"),
            }
        )
    )
    cfg = AppConfig(database_path=tmp_path / "events.sqlite3", credentials_path=credentials)
    repo = Repository(cfg.database_path)
    repo.initialize()
    alarm_id = add(repo, "sudo.repeated_auth_failure", time.time() - 10)
    app = create_app(cfg)
    app.config["TESTING"] = True
    client = app.test_client()
    assert client.get("/api/nav-alerts").status_code == 401
    with client.session_transaction() as session:
        session["authenticated"] = True
        session["authenticated_at"] = time.time()
    before = repo.path.read_bytes()
    assert extract_view(client.get("/sudo"))["scope"] == "sudo"
    detail = extract_view(client.get(f"/alerts/{alarm_id}"))
    assert detail["scope"] == "detail" and detail["alert_id"] == alarm_id
    assert extract_view(client.get("/alerts"))["scope"] == "alerts"
    assert extract_view(client.get("/events?hours=invalid"))["scope"] == ""
    assert client.get("/api/nav-alerts").get_json()["cases"][0]["id"] == alarm_id
    assert repo.path.read_bytes() == before
