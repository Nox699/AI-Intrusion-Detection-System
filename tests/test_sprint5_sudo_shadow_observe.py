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

def test_opt_in_private_staging_persists_only_normalized_events(watcher, tmp_path):
    from yggdrasil_ids.sudo_storage import SudoStagingStore

    folder = tmp_path / "sudo-stage"
    folder.mkdir(mode=0o700)
    store = SudoStagingStore(folder / "sudo.sqlite3")
    store.initialize()
    observer = watcher.AggregateObserver(store)

    feed(
        observer,
        1,
        " labuser : TTY=pts/0 ; PWD=/private ; USER=root ; COMMAND=/usr/bin/id --token=private",
    )
    first = json.dumps(
        record(2, "pam_unix(sudo:auth): authentication failure; logname=private")
    ).encode()
    observer.ingest(first)
    observer.ingest(first)  # Exact journal cursor replay must be deduplicated on disk.
    feed(observer, 3, "pam_unix(sudo:auth): authentication failure; logname=private")
    feed(observer, 4, "pam_unix(sudo:auth): authentication failure; logname=private")
    feed(observer, 5, "private is not in the sudoers file. This incident will be reported.")

    report = observer.report(15)
    assert report["database_writes"] is True
    assert report["production_database_writes"] is False
    assert report["discord_alerts_sent"] is False
    assert report["private_staging_enabled"] is True
    assert report["journal_rows_seen"] == 6
    assert report["staged_unique_rows"] == 5
    assert report["staged_duplicate_rows"] == 1
    assert report["private_staging_summary"]["persisted_log_rows"] == 5
    assert report["private_staging_summary"]["candidate_rule_matches"] == {
        "sudo.permission_denied": 1,
        "sudo.repeated_auth_failure": 1,
    }
    assert report["candidate_rule_matches"] == report["private_staging_summary"][
        "candidate_rule_matches"
    ]

    rows = (folder / "sudo.sqlite3").read_bytes()
    for private in (b"--token", b"labuser", b"private-journal-cursor", b"logname=private"):
        assert private not in rows
    assert "private" not in json.dumps(report)


def test_temp_stage_is_deleted_after_cli_and_never_runs_journal_reader(
    watcher, monkeypatch, capsys
):
    from yggdrasil_ids.sudo_rules import SudoSignal

    created_files = []

    def offline_observe(seconds, *, store=None):
        assert seconds == 5
        assert store is not None
        created_files.append(store.path)
        assert store.path.exists()
        store.append(
            SudoSignal(
                cursor="offline-test-cursor",
                timestamp=1793500000.0,
                boot_id="b" * 32,
                uid="1000",
                pid=4500,
                kind="command_invoked",
            )
        )
        return watcher.AggregateObserver(store).report(seconds)

    def unexpected_popen(*args, **kwargs):
        pytest.fail("The temporary CLI lifecycle test must not open journald")

    monkeypatch.setattr(watcher, "observe", offline_observe)
    monkeypatch.setattr(watcher.subprocess, "Popen", unexpected_popen)
    assert watcher.main(["--seconds", "5", "--stage-temporary"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["temporary_staging_database_deleted"] is True
    assert result["private_staging_summary"]["persisted_log_rows"] == 1
    assert result["production_database_writes"] is False
    assert result["discord_alerts_sent"] is False
    assert len(created_files) == 1
    assert not created_files[0].exists()
    assert not created_files[0].parent.exists()


def test_default_cli_stays_read_only(watcher, monkeypatch, capsys):
    def offline_observe(seconds, *, store=None):
        assert seconds == 5
        assert store is None
        return watcher.AggregateObserver().report(seconds)

    monkeypatch.setattr(watcher, "observe", offline_observe)
    assert watcher.main(["--seconds", "5"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["database_writes"] is False
    assert result["private_staging_enabled"] is False
    assert result["private_staging_summary"] is None
    assert "temporary_staging_database_deleted" not in result
