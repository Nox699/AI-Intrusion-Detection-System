"""Isolation tests of the private notifier and transactional outbox."""
import sqlite3
import time

import pytest

from yggdrasil_ids.notify import DiscordNotifier, DeliveryError
from yggdrasil_ids.storage import Repository


def add_alert(repo):
    with repo.transaction() as db:
        db.execute(
            "INSERT INTO alerts(detector_id,title,severity,reason,source_ip,"
            "first_seen,last_seen,count,details) VALUES(?,?,?,?,?,?,?,1,?)",
            ("ssh.preauth_burst", "Test", "medium", "test", "192.0.2.1",
             time.time(), time.time(), "{}"),
        )


def test_bootstrap_skips_history_and_notifies_new(tmp_path):
    repo = Repository(tmp_path / "events.sqlite3")
    repo.initialize()
    add_alert(repo)
    sent = []
    notify = DiscordNotifier(repo.path, tmp_path / "notify/db.sqlite3",
                             webhook_file=tmp_path / "secret",
                             sender=lambda w, m: sent.append(m) or "12345")
    notify.webhook_file.write_text(
        "https://discord.com/api/webhooks/" + "1"*18 + "/" + "a"*60
    )
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
        repo.path, tmp_path / "private/state.sqlite3",
        webhook_file=tmp_path / "secret",
        sender=lambda url, msg: (_ for _ in ()).throw(RuntimeError("network")),
    )
    n.webhook_file.write_text("https://discord.com/api/webhooks/" + "1"*18 + "/" + "a"*60)
    n.webhook_file.chmod(0o600)
    n.bootstrap()
    add_alert(repo)
    with pytest.raises(RuntimeError):
        n.poll()
    with sqlite3.connect(n.path) as db:
        assert db.execute("SELECT last_seq FROM meta").fetchone()[0] == 0
