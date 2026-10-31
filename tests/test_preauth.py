"""Visibility regression tests for already recorded preauth disconnects."""

import json
import sqlite3
import time

from werkzeug.security import generate_password_hash

from yggdrasil_ids.config import AppConfig
from yggdrasil_ids.storage import Repository
from yggdrasil_ids.web import create_app


def add_record(repo, index, message, uid="0", comm="sshd-session", status="ignored", timestamp=None):
    stamp = time.time() - 30 if timestamp is None else timestamp
    record = json.dumps({"_UID": uid, "_COMM": comm, "MESSAGE": message})
    with repo.transaction() as db:
        db.execute(
            "INSERT INTO records(id,cursor,timestamp,status,reason,raw_json) VALUES(?,?,?,?,?,?)",
            (f"test-{index}", f"cursor-{index}", stamp, status, "", record),
        )


def test_existing_schema_and_authentication_counts_are_unchanged(tmp_path):
    repo = Repository(tmp_path / "events.sqlite3")
    repo.initialize()
    closed = "Connection closed by authenticating user vidar 192.0.2.1 port 41000 [preauth]"
    reset = "Connection reset by authenticating user vidar 192.0.2.1 port 41001 [preauth]"
    add_record(repo, 1, closed)
    add_record(repo, 2, reset)
    reader = Repository(repo.path, readonly=True)
    assert reader.list_preauth()["total"] == 2
    assert [row["connection_type"] for row in reader.list_preauth()["items"]] == [
        "Nulstillet", "Lukket"
    ]
    data = reader.dashboard()
    assert data["preauth_count"] == 2
    assert data["totals"] == {"success": 0, "failure": 0, "events": 0, "alerts": 0}
    with reader.reader() as db:
        assert db.execute("PRAGMA user_version").fetchone()[0] == 1
        assert db.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 0
        assert db.execute("SELECT COUNT(*) FROM observations").fetchone()[0] == 0


def test_untrusted_and_non_preauth_records_are_excluded(tmp_path):
    repo = Repository(tmp_path / "events.sqlite3")
    repo.initialize()
    text = "Connection closed by authenticating user vidar 192.0.2.1 port 41000 [preauth]"
    add_record(repo, 1, text, uid="1000")
    add_record(repo, 2, text, comm="logger")
    add_record(repo, 3, text, status="malformed")
    add_record(repo, 4, "Failed publickey for vidar from 192.0.2.1 port 41000 ssh2")
    add_record(repo, 5, "Connection closed after login")
    add_record(repo, 6, text)
    assert repo.list_preauth()["total"] == 1


def test_time_range_and_pagination(tmp_path):
    repo = Repository(tmp_path / "events.sqlite3")
    repo.initialize()
    text = "Connection reset by authenticating user vidar 192.0.2.1 port 41000 [preauth]"
    now = time.time()
    for index in range(28):
        add_record(repo, index, text, timestamp=now - 100 - index)
    add_record(repo, 99, text, timestamp=now - 8000)
    first = repo.list_preauth(hours=1, per_page=10)
    second = repo.list_preauth(hours=1, page=2, per_page=10)
    assert first["total"] == 28
    assert first["pages"] == 3
    assert len(first["items"]) == len(second["items"]) == 10
    assert first["items"][0]["timestamp"] > second["items"][0]["timestamp"]
    assert repo.list_preauth(hours=1, page=999, per_page=10)["page"] == 3


def test_web_requires_login_and_escapes_journal_messages(tmp_path):
    credentials = tmp_path / "credentials.json"
    credentials.write_text(json.dumps({
        "password_hash": generate_password_hash("test-password"),
        "secret_key": "x" * 64,
    }))
    cfg = AppConfig(
        database_path=tmp_path / "events.sqlite3",
        model_path=tmp_path / "model.json",
        credentials_path=credentials,
        mode="live",
    )
    repo = Repository(cfg.database_path)
    repo.initialize()
    attack = "<script>alert(1)</script>"
    add_record(
        repo,
        1,
        f"Connection closed by authenticating user {attack} 192.0.2.1 port 41000 [preauth]",
    )
    app = create_app(cfg)
    app.config["TESTING"] = True
    client = app.test_client()
    assert client.get("/preauth").status_code == 302

    import re

    login_page = client.get("/login")
    csrf = re.search(rb'name="csrf_token" value="([^"]+)"', login_page.data).group(1).decode()
    assert client.post(
        "/login", data={"csrf_token": csrf, "password": "test-password"}
    ).status_code == 302
    rendered = client.get("/preauth")
    assert rendered.status_code == 200
    html = rendered.get_data(as_text=True)
    assert "&lt;script&gt;" in html
    assert "<script>alert(1)</script>" not in html
    assert client.get("/api/overview").json["data"]["preauth_count"] == 1
    assert client.get("/api/overview").json["data"]["totals"]["events"] == 0
