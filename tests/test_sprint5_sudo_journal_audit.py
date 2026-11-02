"""Tests for the private sudo journal format probe (not a live alert detector)."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "deploy" / "sprint5_sudo_journal_audit.py"


@pytest.fixture(scope="module")
def audit():
    spec = importlib.util.spec_from_file_location("sprint5_sudo_journal_audit", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def records():
    messages = [
        " labadmin : TTY=pts/1 ; PWD=/home/labadmin ; USER=root ; COMMAND=/usr/bin/id",
        "pam_unix(sudo:session): session opened for user root(uid=0) by labadmin(uid=1000)",
        "pam_unix(sudo:session): session closed for user root",
        "pam_unix(sudo:auth): authentication failure; logname=labadmin uid=1000",
        " labadmin : 2 incorrect password attempts ; TTY=pts/1",
        " labadmin is not in the sudoers file. This incident will be reported.",
        "unclassified sudo diagnostic for labadmin in /private/path",
    ]
    return [
        {
            "_COMM": "sudo",
            "_UID": "0",
            "__REALTIME_TIMESTAMP": str(1793577600000000 + i * 1000000),
            "MESSAGE": message,
            "SYSLOG_IDENTIFIER": "sudo",
        }
        for i, message in enumerate(messages)
    ]


def test_sudo_audit_recognizes_messages_without_disclosing_identity(audit, records):
    report = audit.aggregate(records)
    assert report["rows_seen"] == 7
    assert report["trusted_sudo_rows"] == 7
    assert report["invalid_sudo_rows"] == 0
    assert report["categories"] == {
        "command_invoked": 1,
        "pam_auth_failure": 1,
        "incorrect_password": 1,
        "not_in_sudoers": 1,
        "pam_session_opened": 1,
        "pam_session_closed": 1,
        "other_sudo": 1,
    }
    assert report["production_sudo_detection_active"] is False
    assert report["raw_command_lines_exposed"] is False
    dump = json.dumps(report)
    assert "labadmin" not in dump
    assert "/usr/bin/id" not in dump
    assert "/private/path" not in dump


def test_untrusted_sender_cannot_spoof_provenance_via_syslog_identifier(audit, records):
    forged = dict(records[0], _COMM="logger", _UID="1000")
    forged["SYSLOG_IDENTIFIER"] = "sudo"
    assert audit.classify(forged) == "ignored"
    assert audit.classify(dict(records[0], _UID="1000")) == "ignored"
    assert audit.classify(dict(records[0], _UID=True)) == "ignored"
    assert audit.classify(dict(records[0], _UID=0)) == "command_invoked"
    assert audit.aggregate([forged])["trusted_sudo_rows"] == 0


def test_sudo_audit_limits_bad_input_and_record_count(audit, records, monkeypatch):
    assert audit.classify(dict(records[0], MESSAGE=None)) == "invalid"
    assert audit.classify(dict(records[0], MESSAGE="x" * 20000)) == "invalid"
    monkeypatch.setattr(audit, "MAX_JOURNAL_ROWS", 2)
    with pytest.raises(ValueError, match="bounded row limit"):
        audit.aggregate(records)


def test_sudo_audit_empty_is_valid_and_does_not_claim_sensor_active(audit):
    result = audit.aggregate([])
    assert result["trusted_sudo_rows"] == 0
    assert result["production_sudo_detection_active"] is False
    assert not result["active_days_utc"]


def test_sudo_audit_cli_prints_only_aggregated_report(audit, records, monkeypatch, capsys):
    def fake_read(since):
        assert since == "2026-10-22 00:00:00"
        yield from records

    monkeypatch.setattr(audit, "read_journal", fake_read)
    assert audit.main([]) == 0
    output = capsys.readouterr().out
    assert "labadmin" not in output
    assert "/usr/bin/id" not in output
    assert json.loads(output)["categories"]["command_invoked"] == 1


def test_sudo_audit_invalid_start_rejected_without_journal_read(audit, monkeypatch):
    def unexpected_read(_since):
        pytest.fail("Untrusted start date must be rejected before spawning journalctl")

    monkeypatch.setattr(audit, "read_journal", unexpected_read)
    assert audit.main(["--since", "bad"]) == 2
