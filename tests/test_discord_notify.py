"""Isolation tests of the private notifier and transactional outbox."""

import io
import json
import sqlite3
import time
import urllib.error

import pytest

from yggdrasil_ids.notify import (
    DeliveryError,
    DiscordNotifier,
    RetryLater,
    deliver,
)
from yggdrasil_ids.storage import Repository


def add_alert(repo):
    with repo.transaction() as db:
        db.execute(
            "INSERT INTO alerts(detector_id,title,severity,reason,source_ip,"
            "first_seen,last_seen,count,details) VALUES(?,?,?,?,?,?,?,1,?)",
            (
                "ssh.preauth_burst",
                "Test",
                "medium",
                "test",
                "192.0.2.1",
                time.time(),
                time.time(),
                "{}",
            ),
        )


def test_bootstrap_skips_history_and_notifies_new(tmp_path):
    repo = Repository(tmp_path / "events.sqlite3")
    repo.initialize()
    add_alert(repo)
    sent = []
    notify = DiscordNotifier(
        repo.path,
        tmp_path / "notify/db.sqlite3",
        webhook_file=tmp_path / "secret",
        sender=lambda w, m: sent.append(m) or "12345",
    )
    notify.webhook_file.write_text("https://discord.com/api/webhooks/" + "1" * 18 + "/" + "a" * 60)
    notify.webhook_file.chmod(0o600)
    assert notify.bootstrap()["last_seq"] == 1
    assert notify.poll() == 1
    assert not sent
    add_alert(repo)
    assert notify.poll() == 2
    assert len(sent) == 1
    assert "192.0.2.1" not in sent[0]
    assert notify.poll() == 2
    assert len(sent) == 1


def test_deleting_alarm_does_not_drop_outbox_and_numbers_do_not_repeat(tmp_path):
    repo = Repository(tmp_path / "events.sqlite3")
    repo.initialize()
    add_alert(repo)
    with repo.transaction() as db:
        db.execute("DELETE FROM alerts")
    add_alert(repo)
    with repo.reader() as db:
        rows = db.execute("SELECT seq,ref FROM discord_outbox ORDER BY seq").fetchall()
        assert len(rows) == 2
        assert rows[0]["seq"] != rows[1]["seq"]
        assert rows[0]["ref"] != rows[1]["ref"]


def test_database_restore_refused(tmp_path):
    repo = Repository(tmp_path / "events.sqlite3")
    repo.initialize()
    n = DiscordNotifier(repo.path, tmp_path / "private/state.sqlite3")
    n.bootstrap()
    with repo.transaction() as db:
        db.execute("UPDATE discord_outbox_meta SET instance='another' WHERE id=1")
    with pytest.raises(DeliveryError):
        n.poll()


def test_send_error_retains_cursor(tmp_path):
    repo = Repository(tmp_path / "events.sqlite3")
    repo.initialize()
    n = DiscordNotifier(
        repo.path,
        tmp_path / "private/state.sqlite3",
        webhook_file=tmp_path / "secret",
        sender=lambda url, msg: (_ for _ in ()).throw(RuntimeError("network")),
    )
    n.webhook_file.write_text("https://discord.com/api/webhooks/" + "1" * 18 + "/" + "a" * 60)
    n.webhook_file.chmod(0o600)
    n.bootstrap()
    add_alert(repo)
    with pytest.raises(RuntimeError):
        n.poll()
    with sqlite3.connect(n.path) as db:
        assert db.execute("SELECT last_seq FROM meta").fetchone()[0] == 0


def test_failed_delivery_does_not_skip_pending_after_restart(tmp_path):
    repo = Repository(tmp_path / "events.sqlite3")
    repo.initialize()
    path = tmp_path / "private/state.sqlite3"
    secret = tmp_path / "secret"
    secret.write_text("https://discord.com/api/webhooks/" + "1" * 18 + "/" + "a" * 60)
    secret.chmod(0o600)
    first = DiscordNotifier(
        repo.path,
        path,
        webhook_file=secret,
        sender=lambda _url, _message: (_ for _ in ()).throw(RetryLater(300)),
    )
    first.bootstrap()
    add_alert(repo)
    with pytest.raises(RetryLater):
        first.poll()
    with sqlite3.connect(path) as db:
        assert db.execute("SELECT last_seq FROM meta").fetchone()[0] == 0
        not_before = db.execute("SELECT not_before FROM meta").fetchone()[0]
        assert not_before > time.time() + 250
    delivered = []
    restarted = DiscordNotifier(
        repo.path, path, webhook_file=secret,
        sender=lambda _url, msg: delivered.append(msg) or "234567890",
    )
    restarted.bootstrap()
    with pytest.raises(RetryLater):
        restarted.poll()
    assert delivered == []
    with sqlite3.connect(path) as db:
        db.execute("UPDATE meta SET not_before=0")
    assert restarted.poll() == 1
    assert len(delivered) == 1


def test_lock_refuses_second_process(tmp_path):
    from yggdrasil_ids.notify import exclusive_notifier as lock

    path = tmp_path / "private/state.sqlite3"
    with lock(path):
        with pytest.raises(DeliveryError, match="allerede"):
            with lock(path):
                pass
    with lock(path):
        pass


def test_429_wait_uses_longer_server_delay(monkeypatch):
    class Opener:
        def open(self, req, timeout):
            raise urllib.error.HTTPError(
                req.full_url,
                429,
                "rate",
                {"Retry-After": "601.25"},
                io.BytesIO(b'{"retry_after": 900.75, "global": true}'),
            )

    monkeypatch.setattr("yggdrasil_ids.notify.urllib.request.build_opener", lambda *args: Opener())
    with pytest.raises(RetryLater) as exc:
        deliver("https://discord.com/api/webhooks/" + "1" * 18 + "/" + "a" * 60, "test")
    assert exc.value.delay == 900.75


def test_realistic_discord_reply_over_1024_bytes(monkeypatch):
    class Reply:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self, amount):
            assert amount >= 2000
            return json.dumps({"id": "12345", "embeds": [{"description": "x" * 1800}]}).encode()

    class Opener:
        def open(self, req, timeout):
            return Reply()

    monkeypatch.setattr("yggdrasil_ids.notify.urllib.request.build_opener", lambda *args: Opener())
    assert (
        deliver("https://discord.com/api/webhooks/" + "1" * 18 + "/" + "a" * 60, "test") == "12345"
    )


def test_malformed_discord_reply_is_manual_review(monkeypatch):
    class Reply:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self, amount):
            return b'{"id":'

    class Opener:
        def open(self, req, timeout):
            return Reply()

    monkeypatch.setattr("yggdrasil_ids.notify.urllib.request.build_opener", lambda *args: Opener())
    with pytest.raises(DeliveryError):
        deliver("https://discord.com/api/webhooks/" + "1" * 18 + "/" + "a" * 60, "test")
