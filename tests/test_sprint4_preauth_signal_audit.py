"""Preauth audit recognises the real SSH family without mislabelling an attack."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

AUDIT = Path(__file__).resolve().parents[1] / "deploy" / "sprint4_preauth_signal_audit.py"


@pytest.fixture(scope="module")
def audit():
    spec = importlib.util.spec_from_file_location("sprint4_preauth_signal_audit", AUDIT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def journal():
    messages = [
        "Invalid user ids-ml-test-no-user from 192.0.2.50 port 41414",
        "Connection closed by invalid user ids-ml-test-no-user 192.0.2.50 port 41414 [preauth]",
        "Connection closed by authenticating user labuser 192.0.2.55 port 41415 [preauth]",
        "Disconnected from invalid user different 192.0.2.60 port 41417 [preauth]",
        "Accepted publickey for labuser from 192.0.2.55 port 41416 ssh2",
    ]
    return [
        {
            "_UID": "0",
            "_COMM": "sshd-session",
            "_BOOT_ID": "testing-boot",
            "SYSLOG_IDENTIFIER": "sshd",
            "MESSAGE": value,
        }
        for value in messages
    ]


def test_correlates_two_test_log_lines_without_counting_two_attacks(audit, journal):
    summary = audit.aggregate(journal)
    assert summary["journal_rows_seen"] == 5
    assert summary["trusted_root_ssh_rows"] == 5
    assert summary["candidate_message_families"] == {
        "invalid_user_notice": 1,
        "invalid_user_disconnect": 1,
        "authenticating_user_disconnect": 1,
        "invalid_user_disconnected": 1,
    }
    assert summary["candidate_signal_rows_total"] == 4
    assert summary["distinct_candidate_source_port_keys_count_only"] == 3
    assert summary["journal_rows_mentioning_test_username"] == 2
    assert summary["parsed_test_signal_rows"] == 2
    assert summary["test_distinct_source_port_keys_count_only"] == 1
    assert summary["recognized_by_existing_preauth_parser"] == 1
    assert summary["trusted_root_ssh_rows_unclassified_as_candidate_signals"] == 1
    assert summary["new_ml_model_trained"] is False
    assert summary["production_ids_changed"] is False
    output = json.dumps(summary)
    assert "192.0.2." not in output
    assert "ids-ml-test-no-user" not in output
    assert "labuser" not in output
    assert "41414" not in output


def test_source_provenance_requires_privileged_real_sshd(audit, journal):
    record = journal[0]
    assert audit.classify(record) is not None
    assert audit.classify(dict(record, _UID=0)) is not None
    assert audit.classify(dict(record, _COMM="logger")) is None
    assert audit.classify(dict(record, _UID="1000")) is None
    assert audit.classify(dict(record, _UID=True)) is None
    forged = dict(record, _COMM="logger", _UID="1000", SYSLOG_IDENTIFIER="sshd")
    result = audit.aggregate([forged])
    assert result["untrusted_rows"] == 1
    assert result["candidate_signal_rows_total"] == 0


@pytest.mark.parametrize(
    "message",
    [
        "Invalid user x from 999.999.999.999 port 41414",
        "Invalid user x from 192.0.2.1 port 0",
        "Invalid user x from 192.0.2.1 port 70000",
        "Invalid user \u202ey from 192.0.2.1 port 41000",
        "Invalid user x from 192.0.2.1 port 41000 trailing-unexpected",
        "Connection closed by invalid user x 192.0.2.1 port 41000",
        "Invalid user x from 192.0.2.1 port 41000\nspoof",
    ],
)
def test_strict_preauth_parsing_rejects_bad_inputs(audit, journal, message):
    assert audit.classify(dict(journal[0], MESSAGE=message)) is None


def test_bounded_resource_usage(audit, journal, monkeypatch):
    monkeypatch.setattr(audit, "MAX_JOURNAL_ROWS", 2)
    with pytest.raises(ValueError, match="Too many journal"):
        audit.aggregate(journal)


def test_cli_prints_counts_without_ssh_identity(audit, journal, monkeypatch, capsys):
    def fake_journal(since):
        assert since == "2026-11-02 15:00:00"
        yield from journal

    monkeypatch.setattr(audit, "journal_records", fake_journal)
    assert audit.main([]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["parsed_test_signal_rows"] == 2
    assert report["test_distinct_source_port_keys_count_only"] == 1
    assert report["recognized_by_existing_preauth_parser"] == 1


def test_cli_rejects_control_characters_before_running_journalctl(
    audit, monkeypatch, capsys
):
    monkeypatch.setattr(
        audit,
        "journal_records",
        lambda _since: pytest.fail("Malformed date must not launch journalctl"),
    )
    assert audit.main(["--since", "2026-11-02\n--no-pager"]) == 2
    assert "STOP" in capsys.readouterr().err
