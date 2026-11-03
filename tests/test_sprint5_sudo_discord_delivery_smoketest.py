"""A real Discord lab message must require explicit opt-in and private credentials."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

SCRIPT = (
    Path(__file__).resolve().parents[1] / "deploy" / "sprint5_sudo_discord_delivery_smoketest.py"
)


@pytest.fixture(scope="module")
def smoke():
    spec = importlib.util.spec_from_file_location("sprint5_sudo_discord_delivery_smoketest", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_default_offline_mode_has_one_fake_delivery_without_network(smoke, monkeypatch):
    def forbid_real_send(*_args, **_kwargs):
        pytest.fail("No real Discord transport allowed during default mode")

    monkeypatch.setattr(smoke, "deliver", forbid_real_send)
    result = smoke.run()
    assert result["mode"] == "offline_fake_sender"
    assert result["notifier_acknowledged"] == 1
    assert result["notifier_pending"] == 0
    assert result["real_discord_send_attempted"] is False
    assert result["real_discord_acknowledged"] is False
    assert result["test_message_clearly_labeled"] is True
    assert result["production_database_modified"] is False
    assert result["production_notifier_state_modified"] is False
    assert result["ubuntu_gateway_contacted"] is False
    assert result["temporary_databases_deleted"] is True


@pytest.mark.parametrize(
    "flags",
    [["--send-real"], ["--confirm-lab-message"]],
)
def test_incomplete_opt_in_refused_before_accessing_secret(smoke, capsys, flags):
    with pytest.raises(SystemExit) as raised:
        smoke.main(flags)
    assert raised.value.code == 2
    assert "webhooks/" not in capsys.readouterr().err


def test_real_mode_requires_notifier_user(smoke, monkeypatch):
    monkeypatch.setattr(smoke.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(
        smoke.pwd,
        "getpwuid",
        lambda _uid: SimpleNamespace(pw_name="labadmin"),
    )
    with pytest.raises(PermissionError, match="notifier"):
        smoke.run(real=True)


def test_real_mode_uses_only_systemd_credential_and_does_not_leak_it(smoke, tmp_path, monkeypatch):
    url = "https://discord.com/api/webhooks/" + "2" * 18 + "/" + "VERYPRIVATE" * 6
    private_dir = tmp_path / "credential"
    private_dir.mkdir(mode=0o700)
    credential_file = private_dir / "discord-webhook.url"
    credential_file.write_text(url)
    credential_file.chmod(0o600)
    monkeypatch.setenv("CREDENTIALS_DIRECTORY", str(private_dir))
    monkeypatch.setattr(smoke.os, "geteuid", lambda: 999)
    monkeypatch.setattr(
        smoke.pwd,
        "getpwuid",
        lambda _uid: SimpleNamespace(pw_name="yggdrasil-notifier"),
    )
    sent = []

    def fake_deliver(webhook, message):
        assert webhook == url
        assert "SUDO LABTEST" in message
        assert "Gentagne sudo-autentificeringsfejl" in message
        sent.append(message)
        return "98765432101234"

    monkeypatch.setattr(smoke, "deliver", fake_deliver)
    result = smoke.run(real=True)
    assert len(sent) == 1
    assert result["mode"] == "real_discord"
    assert result["real_discord_acknowledged"] is True
    assert result["temporary_databases_deleted"] is True
    assert result["production_database_modified"] is False
    serialized = json.dumps(result)
    assert "VERYPRIVATE" not in serialized
    assert url not in serialized


def test_webhook_missing_fails_closed_with_no_notifier_state(smoke, monkeypatch):
    monkeypatch.setattr(smoke.os, "geteuid", lambda: 999)
    monkeypatch.setattr(
        smoke.pwd,
        "getpwuid",
        lambda _uid: SimpleNamespace(pw_name="yggdrasil-notifier"),
    )
    monkeypatch.delenv("CREDENTIALS_DIRECTORY", raising=False)
    with pytest.raises(ValueError, match="credentials"):
        smoke.run(real=True)


def test_real_mode_rejects_injected_sender(smoke):
    with pytest.raises(ValueError):
        smoke.run(real=True, sender=lambda *_: "fake")


def test_one_time_cli_returns_offline_sanitized_report(smoke, capsys):
    assert smoke.main([]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["mode"] == "offline_fake_sender"
    assert data["notifier_acknowledged"] == 1
    assert "token" not in data
