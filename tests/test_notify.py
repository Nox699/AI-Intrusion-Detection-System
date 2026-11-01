"""The notifier is isolated from the collector and uses a private cursor."""

import json
import stat
import threading
import time

import pytest

from yggdrasil_ids.notify import DiscordNotifier, PermanentNotifyError, load_webhook
from yggdrasil_ids.storage import Repository


@pytest.fixture
def setup(tmp_path):
    repo = Repository(tmp_path / "events.sqlite3")
    repo.initialize()
    url = tmp_path / "webhook.url"
    url.write_text("https://discord.com/api/webhooks/" + "1" * 18 + "/" + "a" * 60)
    url.chmod(0o600)
    state = tmp_path / "private" / "state.json"
    sent = []
    notify = DiscordNotifier(repo.path, url, state, sender=lambda _url, message: sent.append(message))
    return repo, notify, sent


def alert(repo, title="SSH burst", severity="medium"):
    with repo.transaction() as db:
        db.execute(
            "INSERT INTO alerts(detector_id,title,severity,reason,source_ip,"
            "first_seen,last_seen,count,details) VALUES(?,?,?,?,?,?,?,1,?)",
            ("ssh.preauth_burst", title, severity, "private reason",
             "192.0.2.1", time.time(), time.time(), "{}"),
        )


def test_first_start_skips_existing_alerts_and_sends_only_new(setup):
    repo, notify, sent = setup
    alert(repo, "older")
    state = notify.run_once()
    assert state["last_id"] == 1 and sent == []
    alert(repo)
    notify.run_once()
    assert len(sent) == 1
    assert "SSH burst" in sent[0]
    assert "192.0.2.1" not in sent[0]
    notify.run_once()
    assert len(sent) == 1
    assert stat.S_IMODE(notify.state_file.stat().st_mode) == 0o600


def test_failed_delivery_keeps_cursor_for_retry(setup):
    repo, notify, sent = setup
    notify.run_once()
    alert(repo)
    def fails(_url, _message):
        raise RuntimeError("test")
    notify.sender = fails
    with pytest.raises(RuntimeError):
        notify.run_once()
    assert notify._state()["last_id"] == 0
    notify.sender = lambda _url, message: sent.append(message)
    notify.run_once()
    assert len(sent) == 1


def test_severity_filter_discards_low_and_preserves_high(setup):
    repo, notify, sent = setup
    notify.run_once()
    alert(repo, "low", "low")
    alert(repo, "high", "high")
    notify.run_once()
    assert len(sent) == 1 and "high" in sent[0]
    assert notify._state()["last_id"] == 2


def test_webhook_validation_keeps_secrets_private(tmp_path):
    path = tmp_path / "url"
    url = "https://discord.com/api/webhooks/" + "1" * 18 + "/" + "a" * 60
    path.write_text(url)
    path.chmod(0o600)
    assert load_webhook(path) == url
    path.write_text(url.replace("discord.com", "example.org"))
    with pytest.raises(PermanentNotifyError):
        load_webhook(path)
    path.write_text(url)
    path.chmod(0o644)
    with pytest.raises(PermanentNotifyError):
        load_webhook(path)


def test_never_share_user_content_or_mentions(setup):
    repo, notify, sent = setup
    notify.run_once()
    alert(repo, "@everyone hello <@123456>", "medium")
    notify.run_once()
    assert "@everyone" not in sent[0]
    assert "<@123456>" not in sent[0]
    assert "@\u200beveryone" in sent[0]


def test_bad_state_is_not_silently_reset(setup):
    _repo, notify, _sent = setup
    notify.state_file.parent.mkdir()
    notify.state_file.write_text("corrupt")
    notify.state_file.chmod(0o600)
    with pytest.raises(ValueError):
        notify.run_once()
