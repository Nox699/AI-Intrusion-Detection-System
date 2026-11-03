"""Tests for read-only sudo inventory using journald's executable metadata."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "deploy" / "sprint5_sudo_trusted_exe_audit.py"


@pytest.fixture(scope="module")
def inventory():
    spec = importlib.util.spec_from_file_location("sprint5_sudo_trusted_exe_audit", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def sample_rows():
    messages = [
        " labuser : TTY=pts/1 ; PWD=/private ; USER=root ; COMMAND=/usr/bin/id --secret",
        "pam_unix(sudo:auth): authentication failure; logname=labuser",
        " labuser : 2 incorrect password attempts ; TTY=pts/1",
        " labuser is not in the sudoers file. This incident will be reported.",
        "pam_unix(sudo:session): session opened for user root(uid=0) by labuser",
        "pam_unix(sudo:session): session closed for user root",
        "unclassified sudo diagnostic: private-secret",
    ]
    return [
        {
            "_EXE": "/usr/bin/sudo",
            "_COMM": "sudo" if i != 6 else "other",
            "_UID": "1000" if i != 6 else "0",
            "_TRANSPORT": "syslog",
            "SYSLOG_IDENTIFIER": "sudo",
            "__REALTIME_TIMESTAMP": str(1793577600000000 + i * 1_000_000),
            "MESSAGE": message,
        }
        for i, message in enumerate(messages)
    ]


def test_counts_sudo_executable_even_when_uid_nonroot(inventory):
    report = inventory.aggregate(sample_rows())
    assert report["rows_seen"] == 7
    assert report["trusted_sudo_rows"] == 7
    assert report["trusted_comm_sudo"] == 6
    assert report["trusted_comm_other_or_missing"] == 1
    assert report["trusted_uid_root"] == 1
    assert report["trusted_uid_nonroot_or_missing"] == 6
    assert report["trusted_transport_syslog"] == 7
    assert all(value == 1 for value in report["categories"].values())
    assert report["production_sudo_detection_active"] is False
    assert report["private_identifiers_exposed"] is False
    serialized = json.dumps(report)
    for secret in ("labuser", "--secret", "/private", "private-secret", "1000"):
        assert secret not in serialized


def test_spoofed_syslog_identifier_cannot_establish_executable_provenance(inventory):
    spoofed = dict(
        sample_rows()[0],
        _EXE="/usr/bin/logger",
        SYSLOG_IDENTIFIER="sudo",
        _COMM="sudo",
        _UID="0",
    )
    report = inventory.aggregate([spoofed])
    assert report["rows_seen"] == 1
    assert report["trusted_sudo_rows"] == 0
    assert report["ignored_untrusted_executable"] == 1
    assert inventory.classify(dict(sample_rows()[0], MESSAGE=None)) == "invalid_sudo_message"
    assert inventory.classify(dict(sample_rows()[0], MESSAGE="A" * 20000)) == "invalid_sudo_message"


def test_bound_all_rows(inventory, monkeypatch):
    monkeypatch.setattr(inventory, "MAX_ROWS", 2)
    with pytest.raises(ValueError, match="bounded record limit"):
        inventory.aggregate(sample_rows())


def test_cli_prints_only_aggregates(inventory, monkeypatch, capsys):
    def fake_records(since):
        assert since == "2026-10-22 00:00:00"
        yield from sample_rows()

    monkeypatch.setattr(inventory, "read_journal", fake_records)
    assert inventory.main([]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["categories"]["command_invoked"] == 1
    assert result["trusted_sudo_rows"] == 7


def test_invalid_date_does_not_consult_journal(inventory, monkeypatch):
    def unexpected(_since):
        pytest.fail("Journal should not be consulted after bad date")

    monkeypatch.setattr(inventory, "read_journal", unexpected)
    with pytest.raises(SystemExit) as exc:
        inventory.main(["--since", "2026-99-99 00:00:00"])
    assert exc.value.code == 2


def test_journal_command_restricts_to_sudo_executable_without_uid_condition(inventory, monkeypatch):
    import io

    seen_commands = []

    class FakeProcess:
        stdout = io.StringIO(json.dumps(sample_rows()[0]) + "\n")

        def wait(self, timeout=None):
            return 0

        def poll(self):
            return 0

    def fake_popen(command, **kwargs):
        seen_commands.append(command)
        assert kwargs["stderr"] is inventory.subprocess.DEVNULL
        return FakeProcess()

    monkeypatch.setattr(inventory.subprocess, "Popen", fake_popen)
    records = list(inventory.read_journal("2026-10-22 00:00:00"))
    assert len(records) == 1
    assert len(seen_commands) == 1
    assert "_EXE=/usr/bin/sudo" in seen_commands[0]
    assert "_UID=0" not in seen_commands[0]
    assert "_COMM=sudo" not in seen_commands[0]
    assert "--system" not in seen_commands[0]
