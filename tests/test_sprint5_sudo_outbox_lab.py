"""Sudo positive lab detection -> SQLite alert/outbox -> fake Discord delivery."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

DEPLOY = Path(__file__).resolve().parents[1] / "deploy"
SCRIPT = DEPLOY / "sprint5_sudo_outbox_lab.py"
BASE = 1793500000
BOOT = "b" * 32


@pytest.fixture(scope="module")
def lab():
    sys.path.insert(0, str(DEPLOY))
    try:
        spec = importlib.util.spec_from_file_location("sprint5_sudo_outbox_lab", SCRIPT)
        assert spec is not None and spec.loader is not None
        tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(tool)
        return tool
    finally:
        sys.path.remove(str(DEPLOY))


def sudo_row(index: int, second: int, *, kind: str = "failure"):
    if kind == "failure":
        message = "pam_unix(sudo:auth): authentication failure; logname=private-lab-secret"
    else:
        message = "pam_unix(sudo:session): session opened for user root(uid=0) by private-user"
    return {
        "_EXE": "/usr/bin/sudo",
        "_UID": "1000",
        "_PID": str(2500 + index),
        "_BOOT_ID": BOOT,
        "__CURSOR": f"never-echo-cursor-{index}",
        "__REALTIME_TIMESTAMP": str((BASE + second) * 1_000_000),
        "MESSAGE": message,
    }


def test_two_separate_realistic_fail_bursts_generate_two_fake_discord_deliveries(lab):
    rows = [
        sudo_row(1, 10),
        sudo_row(2, 20),
        sudo_row(3, 30),
        sudo_row(4, 700),
        sudo_row(5, 710),
        sudo_row(6, 720),
    ]
    result = lab.run_lab(rows)
    assert result["journal_rows_seen"] == 6
    assert result["parsed_sudo_rows"] == 6
    assert result["candidate_rule_matches"] == {
        "sudo.permission_denied": 0,
        "sudo.repeated_auth_failure": 2,
    }
    assert result["temporary_alert_rows"] == 2
    assert result["temporary_outbox_rows"] == 2
    assert result["fake_notifier_deliveries"] == 2
    assert result["fake_notifier_pending"] == 0
    assert result["discord_messages_sent"] == 0
    assert result["real_webhook_read"] is False
    assert result["fake_sender_only"] is True
    assert result["production_database_modified"] is False
    assert result["production_notifier_state_modified"] is False
    assert result["temporary_databases_deleted"] is True
    message = result["one_redacted_message_preview"]
    assert "Gentagne sudo-autentificeringsfejl" in message
    assert "ubuntu-gateway (isolated lab)" in message
    assert "Niveau: medium" in message
    for private in ("private-lab-secret", "private-user", "never-echo-cursor", "2503"):
        assert private not in json.dumps(result)


def test_duplicate_replay_does_not_create_duplicate_alarm(lab):
    originals = [sudo_row(1, 10), sudo_row(2, 20), sudo_row(3, 30)]
    result = lab.run_lab([*originals, *originals])
    assert result["candidate_rule_matches"]["sudo.repeated_auth_failure"] == 1
    assert result["temporary_outbox_rows"] == 1
    assert result["fake_notifier_deliveries"] == 1
    assert result["discord_messages_sent"] == 0


def test_only_normal_sessions_create_no_alarm_or_webhook_read(lab):
    result = lab.run_lab([sudo_row(i, i, kind="session") for i in range(1, 4)])
    assert result["parsed_sudo_rows"] == 3
    assert result["temporary_outbox_rows"] == 0
    assert result["fake_notifier_deliveries"] == 0
    assert result["one_redacted_message_preview"] is None
    assert result["discord_messages_sent"] == 0


def test_bounded_input_aborts_instead_of_sending_or_reporting_partial_success(lab, monkeypatch):
    monkeypatch.setattr(lab, "MAX_RECORDS", 1)
    with pytest.raises(ValueError, match="bounded"):
        lab.run_lab([sudo_row(1, 10), sudo_row(2, 20)])


def test_cli_with_mocked_local_journal_only_prints_sanitised_report(lab, monkeypatch, capsys):
    monkeypatch.setattr(
        lab,
        "read_sudo",
        lambda _since: [sudo_row(1, 10), sudo_row(2, 20), sudo_row(3, 30)],
    )
    assert lab.main(["--since", "2026-11-03 00:00:00"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["fake_notifier_deliveries"] == 1
    assert report["discord_messages_sent"] == 0
    assert "private-lab-secret" not in json.dumps(report)
