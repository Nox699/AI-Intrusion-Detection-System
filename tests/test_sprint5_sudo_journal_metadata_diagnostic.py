"""Metadata-only diagnostics when strict sudo journal source filters match no rows."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

SCRIPT = (
    Path(__file__).resolve().parents[1] / "deploy" / "sprint5_sudo_journal_metadata_diagnostic.py"
)


@pytest.fixture(scope="module")
def diag():
    spec = importlib.util.spec_from_file_location("sudo_metadata_diagnostic", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def sample_records():
    return [
        {
            "MESSAGE": "private command and username must never be printed",
            "_COMM": "sudo",
            "_UID": "0",
            "_EXE": "/usr/bin/sudo",
            "_TRANSPORT": "syslog",
            "SYSLOG_IDENTIFIER": "sudo",
        },
        {
            "MESSAGE": "different private command",
            "_COMM": "rsyslogd",
            "_UID": "0",
            "_EXE": "/usr/sbin/rsyslogd",
            "_TRANSPORT": "syslog",
            "SYSLOG_IDENTIFIER": "sudo",
        },
        {
            "MESSAGE": "ordinary user forges syslog tag",
            "_COMM": "logger",
            "_UID": "1000",
            "_EXE": "/usr/bin/logger",
            "_TRANSPORT": "journal",
            "SYSLOG_IDENTIFIER": "sudo",
        },
        {
            "MESSAGE": "other private data",
            "_UID": True,
            "SYSLOG_IDENTIFIER": "other",
        },
    ]


def test_query_profiles_are_bounded_and_do_not_filter_uid(diag):
    base = ["journalctl", "--system", "--quiet", "--no-pager", "--output=json"]
    for probe in diag.PROBES:
        args = diag.journal_command("2026-10-22 00:00:00", probe)
        assert args[: len(base)] == base
        assert "--since=2026-10-22 00:00:00" in args
        assert not any(value.startswith("_UID=") for value in args)
    assert "_COMM=sudo" in diag.journal_command("2026-10-22 00:00:00", "comm_sudo")
    assert "SYSLOG_IDENTIFIER=sudo" in diag.journal_command("2026-10-22 00:00:00", "tag_sudo")
    assert "--lines=1" in diag.journal_command("2026-10-22 00:00:00", "recent_system")
    with pytest.raises(ValueError):
        diag.journal_command("2026-10-22 00:00:00", "all_records")


def test_metadata_does_not_expose_message_or_untrusted_source(diag):
    summary = diag.metadata_summary(sample_records())
    assert summary["rows"] == 4
    assert summary["comm_sudo"] == 1
    assert summary["comm_other"] == 2
    assert summary["comm_missing"] == 1
    assert summary["uid_root"] == 2
    assert summary["uid_nonroot_or_invalid"] == 2
    assert summary["exe_usr_bin_sudo"] == 1
    assert summary["tag_sudo"] == 3
    assert summary["matches_original_strict_filter"] == 1
    assert summary["transport_syslog"] == 2
    assert summary["transport_journal"] == 1
    assert "private" not in json.dumps(summary)
    assert "rsyslogd" not in json.dumps(summary)
    assert "1000" not in json.dumps(summary)


def test_aggregate_report_uses_three_probes_and_hides_private_messages(diag, monkeypatch):
    def fake_read(since, probe):
        assert since == "2026-10-22 00:00:00"
        if probe == "recent_system":
            yield {"MESSAGE": "sensitive entry", "_COMM": "systemd"}
        elif probe == "comm_sudo":
            yield sample_records()[0]
        elif probe == "tag_sudo":
            yield from sample_records()[:3]

    monkeypatch.setattr(diag, "read_journal", fake_read)
    report = diag.audit("2026-10-22 00:00:00")
    assert report["recent_system_entry_visible"] is True
    assert report["comm_sudo_query"]["rows"] == 1
    assert report["tag_sudo_query"]["rows"] == 3
    assert report["tag_sudo_query"]["matches_original_strict_filter"] == 1
    assert report["production_sudo_detection_active"] is False
    assert report["only_aggregated_metadata_exposed"] is True
    serialized = json.dumps(report)
    for private in ("sensitive", "private", "command", "username", "logger"):
        assert private not in serialized


def test_bounded_metadata_scan_refuses_excessive_rows(diag, monkeypatch):
    monkeypatch.setattr(diag, "MAX_ROWS_PER_QUERY", 2)
    with pytest.raises(ValueError, match="Too many"):
        diag.metadata_summary(sample_records())


def test_invalid_cli_date_exits_before_reading_journal(diag, monkeypatch):
    def unexpected_audit(_since):
        pytest.fail("Bad date reached journal scan")

    monkeypatch.setattr(diag, "audit", unexpected_audit)
    with pytest.raises(SystemExit) as error:
        diag.main(["--since", "2026-17-22 00:00:00"])
    assert error.value.code == 2
