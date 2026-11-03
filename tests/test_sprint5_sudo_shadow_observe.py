"""Sprint 5 isolated sudo shadow observation: no private data or production writes."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

PATH = Path(__file__).resolve().parents[1] / "deploy" / "sprint5_sudo_shadow_observe.py"


@pytest.fixture(scope="module")
def watcher():
    spec = importlib.util.spec_from_file_location("sprint5_sudo_shadow_observe", PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def record(index, message, *, exe="/usr/bin/sudo", pid=None, uid="1000"):
    return {
        "MESSAGE": message,
        "_EXE": exe,
        "_UID": uid,
        "_PID": str(pid if pid is not None else 2000 + index),
        "_BOOT_ID": "e" * 32,
        "__CURSOR": f"private-sudo-cursor-{index}",
        "__REALTIME_TIMESTAMP": str(1793500000000000 + index * 1_000_000),
    }


def feed(observer, index, message, **kwargs):
    observer.ingest(json.dumps(record(index, message, **kwargs)).encode())


def test_command_is_exact_sudo_scope_without_system_flag(watcher):
    command = watcher.journal_command(1793500000.123456)
    assert command[0] == "journalctl"
    assert "--system" not in command
    assert "--follow" in command
    assert "--no-tail" in command
    assert "_EXE=/usr/bin/sudo" in command
    assert "--output=json" in command
    assert "--output-fields=" + watcher.OUTPUT_FIELDS in command
    assert "--since=@1793500000.123456" in command
    assert "MESSAGE" in watcher.OUTPUT_FIELDS
    assert "_EXE" in watcher.OUTPUT_FIELDS
    assert "__CURSOR" in watcher.OUTPUT_FIELDS
    assert "--after-cursor" not in " ".join(command)


@pytest.mark.parametrize("value", [-1, 0, float("nan"), float("inf"), 4102444800])
def test_invalid_start_timestamp_is_rejected(watcher, value):
    with pytest.raises(ValueError):
        watcher.journal_command(value)


def test_normal_sudo_activity_causes_no_candidate_matches(watcher):
    observer = watcher.AggregateObserver()
    feed(
        observer,
        1,
        " labuser : TTY=pts/0 ; PWD=/private ; USER=root ; COMMAND=/usr/bin/id --token=private",
    )
    feed(observer, 2, "pam_unix(sudo:session): session opened for user root(uid=0) by labuser")
    feed(observer, 3, "pam_unix(sudo:session): session closed for user root")
    result = observer.report(15)
    assert result["journal_rows_seen"] == 3
    assert result["parsed_sudo_rows"] == 3
    assert result["sudo_categories"]["command_invoked"] == 1
    assert result["sudo_categories"]["pam_session_opened"] == 1
    assert result["sudo_categories"]["pam_session_closed"] == 1
    assert all(not v for v in result["candidate_rule_matches"].values())
    assert result["database_writes"] is False
    assert result["discord_alerts_sent"] is False
    assert result["production_sudo_detection_active"] is False
    assert result["raw_user_command_or_journal_data_exposed"] is False
    text = json.dumps(result)
    for secret in ("private", "labuser", "--token", "cursor", "2001", "1000"):
        assert secret not in text


def test_synthetic_failures_and_denials_are_only_shadow_candidates(watcher):
    observer = watcher.AggregateObserver()
    for number in range(1, 4):
        feed(
            observer,
            number,
            "pam_unix(sudo:auth): authentication failure; logname=private",
        )
    feed(observer, 4, "private is not in the sudoers file. This incident will be reported.")
    result = observer.report(15)
    assert result["candidate_rule_matches"]["sudo.repeated_auth_failure"] == 1
    assert result["candidate_rule_matches"]["sudo.permission_denied"] == 1
    assert result["discord_alerts_sent"] is False
    assert result["database_writes"] is False


def test_spoofed_sudo_tag_and_password_prompt_not_an_attack(watcher):
    observer = watcher.AggregateObserver()
    spoof = record(1, "private is not in the sudoers file", exe="/usr/bin/logger")
    spoof["SYSLOG_IDENTIFIER"] = "sudo"
    observer.ingest(json.dumps(spoof).encode())
    feed(observer, 2, "sudo: a password is required")
    observer.ingest(b"garbled JSON")
    result = observer.report(10)
    assert result["parsed_sudo_rows"] == 1
    assert result["sudo_categories"]["other_sudo"] == 1
    assert result["malformed_or_untrusted"] == 2
    assert all(not v for v in result["candidate_rule_matches"].values())


def test_duplicates_do_not_inflate_shadow_candidates(watcher):
    observer = watcher.AggregateObserver()
    first = json.dumps(record(1, "pam_unix(sudo:auth): authentication failure; logname=x")).encode()
    observer.ingest(first)
    observer.ingest(first)
    feed(observer, 2, "pam_unix(sudo:auth): authentication failure")
    report = observer.report(5)
    assert all(not v for v in report["candidate_rule_matches"].values())
    assert report["parsed_sudo_rows"] == 3


def test_root_rejected_and_seconds_checked_before_process_start(watcher, monkeypatch):
    monkeypatch.setattr(watcher.os, "geteuid", lambda: 0)

    def no_process(*args, **kwargs):
        pytest.fail("No system command should be executed")

    monkeypatch.setattr(watcher.subprocess, "Popen", no_process)
    with pytest.raises(PermissionError):
        watcher.observe(10)
    with pytest.raises(ValueError):
        watcher.observe(61)
    with pytest.raises(ValueError):
        watcher.observe(True)


def test_record_size_and_count_are_bounded(watcher, monkeypatch):
    monkeypatch.setattr(watcher, "MAX_RECORD_BYTES", 16)
    observer = watcher.AggregateObserver()
    observer.ingest(b"oversized data line")
    assert observer.report(5)["malformed_or_untrusted"] == 1
    monkeypatch.setattr(watcher, "MAX_RECORDS", 1)
    with pytest.raises(ValueError, match="record limit"):
        observer.ingest(b"something")
