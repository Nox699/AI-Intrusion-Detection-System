"""No-webhook Discord-format preview with the real sudo rule detector."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from yggdrasil_ids.notify import DiscordNotifier
from yggdrasil_ids.sudo_alerts import notification_event
from yggdrasil_ids.sudo_rules import SudoRuleDetector, SudoRuleMatch, SudoSignal

SCRIPT = Path(__file__).resolve().parents[1] / "deploy" / "sprint5_sudo_discord_preview.py"
BASE = 1_793_500_000
BOOT = "a" * 32


@pytest.fixture(scope="module")
def tool():
    spec = importlib.util.spec_from_file_location("sprint5_sudo_discord_preview", SCRIPT)
    assert spec is not None and spec.loader is not None
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def row(index: int, message: str):
    return {
        "_EXE": "/usr/bin/sudo",
        "_UID": "1000",
        "_PID": str(7000 + index),
        "_BOOT_ID": BOOT,
        "__CURSOR": "private-cursor-" + str(index),
        "__REALTIME_TIMESTAMP": str((BASE + index) * 1_000_000),
        "MESSAGE": message,
    }


def test_true_sudo_candidate_produces_redacted_notifier_event():
    signal = SudoSignal("private-cursor", BASE + 2, BOOT, "1000", 7001, "pam_auth_failure")
    detector = SudoRuleDetector()
    for i in range(2):
        assert detector.evaluate(
            SudoSignal(f"failed-{i}", BASE + i, BOOT, "1000", 7002 + i, "pam_auth_failure")
        ) is None
    finding = detector.evaluate(signal)
    assert finding is not None
    assert finding.count == 3
    event = notification_event(signal, finding)
    assert event["detector_id"] == "sudo.repeated_auth_failure"
    assert "private-cursor" not in json.dumps(event)


def test_three_distinct_realistic_failures_preview_one_message(tool):
    inputs = [
        row(i, "pam_unix(sudo:auth): authentication failure; logname=private-secret")
        for i in (1, 2, 3)
    ]
    result = tool.preview(inputs)
    assert result["journal_rows_seen"] == 3
    assert result["parsed_sudo_rows"] == 3
    assert result["candidate_rule_matches"] == {
        "sudo.repeated_auth_failure": 1,
        "sudo.permission_denied": 0,
    }
    message = result["one_redacted_message_preview"]
    assert "Gentagne sudo-autentificeringsfejl" in message
    assert "ubuntu-gateway (isolated lab)" in message
    assert "Undersøg hændelsen i den autoriserede lokale sudo-journal." in message
    assert "sudo-" in message
    for private in ("private-secret", "7001", "1000", "private-cursor", "labuser"):
        assert private not in message
    assert result["discord_messages_sent"] == 0
    assert result["webhook_read"] is False
    assert result["production_database_modified"] is False
    assert result["notifier_state_modified"] is False


def test_normal_sudo_sessions_never_preview_alert(tool):
    inputs = [
        row(1, "pam_unix(sudo:session): session opened for user root(uid=0) by labuser"),
        row(2, "pam_unix(sudo:session): session closed for user root"),
        row(3, "pam_unix(sudo:session): session opened for user root(uid=0) by labuser"),
    ]
    result = tool.preview(inputs)
    assert result["one_redacted_message_preview"] is None
    assert all(not v for v in result["candidate_rule_matches"].values())
    assert result["discord_messages_sent"] == 0


def test_unknown_detector_rejected_instead_of_notification():
    signal = SudoSignal("test", BASE, BOOT, "1000", 1, "pam_auth_failure")
    candidate = SudoRuleMatch("ssh.failed_burst", "medium", 3, BASE)
    with pytest.raises(ValueError):
        notification_event(signal, candidate)


def test_privacy_and_label_without_discord_transport(tmp_path):
    signal = SudoSignal("very-private-cursor", BASE, BOOT, "1000", 1, "pam_auth_failure")
    candidate = SudoRuleMatch("sudo.repeated_auth_failure", "medium", 3, BASE)
    event = notification_event(signal, candidate)
    assert set(event) == {"detector_id", "severity", "happened_at", "ref"}
    assert "very-private-cursor" not in json.dumps(event)
    sender_called = []

    notify = DiscordNotifier(
        tmp_path / "never-created.sqlite3",
        tmp_path / "never-created-notify.sqlite3",
        sender=lambda w, m: sender_called.append((w, m)),
    )
    message = notify.message(event)
    assert "Gentagne sudo-autentificeringsfejl" in message
    assert "1000" not in message
    assert "very-private-cursor" not in message
    assert sender_called == []
    assert not (tmp_path / "never-created.sqlite3").exists()
    assert not (tmp_path / "never-created-notify.sqlite3").exists()


def test_cli_from_mocked_journal_never_contacts_network(tool, monkeypatch, capsys):
    monkeypatch.setattr(
        tool,
        "read_sudo",
        lambda since: [
            row(i, "pam_unix(sudo:auth): authentication failure; logname=lab-secret")
            for i in (1, 2, 3)
        ],
    )
    assert tool.main([]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["candidate_rule_matches"]["sudo.repeated_auth_failure"] == 1
    assert "lab-secret" not in json.dumps(report)
    assert report["discord_messages_sent"] == 0
