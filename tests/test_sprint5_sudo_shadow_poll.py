"""Persistent isolated sudo shadow poll: checkpoint, overlap and fail-closed tests."""

from __future__ import annotations

import importlib.util
import json
import os
import sqlite3
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "deploy" / "sprint5_sudo_shadow_poll.py"
BOOT = "c" * 32
BASE = 1_793_680_000.0


@pytest.fixture(scope="module")
def shadow():
    spec = importlib.util.spec_from_file_location("sprint5_sudo_shadow_poll", SCRIPT)
    assert spec is not None and spec.loader is not None
    tool = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(tool)
    return tool


@pytest.fixture
def database(tmp_path):
    tmp_path.chmod(0o700)
    return tmp_path / "sudo-shadow.sqlite3"


def row(index: int, epoch: float, kind: str = "fail"):
    if kind == "fail":
        message = "pam_unix(sudo:auth): authentication failure; logname=never-export"
    elif kind == "summary":
        message = "labuser : 1 incorrect password attempt ; TTY=pts/0 ; PWD=/home/labuser"
    else:
        message = "pam_unix(sudo:session): session opened for user root(uid=0) by labuser"
    return {
        "_EXE": "/usr/bin/sudo",
        "_UID": "1000",
        "_PID": str(4000 + index),
        "_BOOT_ID": BOOT,
        "__CURSOR": f"private-cursor-{index}-{kind}",
        "__REALTIME_TIMESTAMP": str(round(epoch * 1_000_000)),
        "MESSAGE": message,
    }


def snapshot(rows):
    """Simulate journalctl --since/--until, including its time filtering."""

    def read(since, until):
        return [
            rec for rec in rows if since <= int(rec["__REALTIME_TIMESTAMP"]) / 1_000_000 <= until
        ]

    return read


def checkpoint(database):
    with sqlite3.connect(database) as db:
        return db.execute(
            "SELECT last_completed_until FROM shadow_poll_checkpoint WHERE id=1"
        ).fetchone()[0]


def test_read_only_source_command_queries_all_journals_not_system(shadow):
    cmd = shadow.journal_command(BASE, BASE + 40)
    assert "--all" in cmd
    assert "--system" not in cmd
    assert "--output=json" in cmd
    assert "_EXE=/usr/bin/sudo" in cmd
    assert any(x.startswith("--since=@") for x in cmd)
    assert any(x.startswith("--until=@") for x in cmd)
    with pytest.raises(ValueError, match="invalid"):
        shadow.journal_command(BASE, BASE - 1)


def test_normal_sudo_is_stored_without_candidate_and_resumes(shadow, database, monkeypatch):
    rows = [row(1, BASE + 10, "normal"), row(2, BASE + 20, "normal")]
    monkeypatch.setattr(shadow, "journal_records", snapshot(rows))
    first = shadow.poll_once(database, now=BASE + 50)
    assert first["journal_rows_read"] == 2
    assert first["new_normalized_sudo_rows"] == 2
    assert first["new_candidate_rule_matches"]["sudo.repeated_auth_failure"] == 0
    assert first["discord_alerts_sent"] == 0
    first_completed = checkpoint(database)
    second = shadow.poll_once(database, now=BASE + 100)
    assert second["previous_checkpoint_present"] is True
    assert second["journal_rows_read"] == 2
    assert second["new_normalized_sudo_rows"] == 0
    assert second["overlap_duplicates_skipped"] == 2
    assert checkpoint(database) > first_completed
    assert second["private_staging_summary"]["persisted_log_rows"] == 2
    assert second["production_database_modified"] is False


def test_three_unique_failed_processes_one_candidate_across_restarts(shadow, database, monkeypatch):
    events = [
        row(1, BASE + 20),
        row(1, BASE + 20.1, "summary"),
        row(2, BASE + 40),
        row(2, BASE + 40.1, "summary"),
        row(3, BASE + 70),
        row(3, BASE + 70.1, "summary"),
    ]
    monkeypatch.setattr(shadow, "journal_records", snapshot(events))
    first = shadow.poll_once(database, now=BASE + 52)
    assert first["new_normalized_sudo_rows"] == 4
    assert first["new_candidate_rule_matches"]["sudo.repeated_auth_failure"] == 0
    second = shadow.poll_once(database, now=BASE + 100)
    assert second["new_normalized_sudo_rows"] == 2
    assert second["new_candidate_rule_matches"]["sudo.repeated_auth_failure"] == 1
    assert second["private_staging_summary"]["persisted_log_rows"] == 6
    assert second["private_staging_summary"]["candidate_rule_matches"] == {
        "sudo.permission_denied": 0,
        "sudo.repeated_auth_failure": 1,
    }
    third = shadow.poll_once(database, now=BASE + 125)
    assert third["new_candidate_rule_matches"]["sudo.repeated_auth_failure"] == 0
    assert third["overlap_duplicates_skipped"] == 6
    assert third["discord_alerts_sent"] == 0


def test_completed_empty_poll_advances_checkpoint(shadow, database, monkeypatch):
    monkeypatch.setattr(shadow, "journal_records", lambda _a, _b: [])
    first = shadow.poll_once(database, now=BASE + 50)
    second = shadow.poll_once(database, now=BASE + 180)
    assert first["journal_rows_read"] == second["journal_rows_read"] == 0
    assert checkpoint(database) == BASE + 178


def test_journal_error_does_not_advance_checkpoint(shadow, database, monkeypatch):
    first = [row(1, BASE + 20), row(2, BASE + 30)]
    monkeypatch.setattr(shadow, "journal_records", snapshot(first))
    shadow.poll_once(database, now=BASE + 50)
    baseline = checkpoint(database)

    def interrupted(_since, _until):
        yield row(3, BASE + 70)
        raise RuntimeError("Simulated broken journald reader")

    monkeypatch.setattr(shadow, "journal_records", interrupted)
    with pytest.raises(RuntimeError, match="broken journald"):
        shadow.poll_once(database, now=BASE + 100)
    assert checkpoint(database) == baseline
    with sqlite3.connect(database) as db:
        assert db.execute("SELECT COUNT(*) FROM sudo_signals").fetchone()[0] == 2
    monkeypatch.setattr(shadow, "journal_records", snapshot(first + [row(3, BASE + 70)]))
    completed = shadow.poll_once(database, now=BASE + 110)
    assert completed["new_normalized_sudo_rows"] == 1
    assert completed["private_staging_summary"]["persisted_log_rows"] == 3
    assert completed["private_staging_summary"]["candidate_rule_matches"] == {
        "sudo.permission_denied": 0,
        "sudo.repeated_auth_failure": 1,
    }


def test_bounded_and_malformed_records_fail_closed(shadow, database, monkeypatch):
    invalid = row(1, BASE + 20)
    invalid.pop("_BOOT_ID")
    monkeypatch.setattr(shadow, "journal_records", lambda _a, _b: [invalid])
    with pytest.raises(ValueError, match="metadata"):
        shadow.poll_once(database, now=BASE + 50)
    with sqlite3.connect(database) as db:
        count = db.execute("SELECT COUNT(*) FROM shadow_poll_checkpoint").fetchone()[0]
    assert count == 0
    monkeypatch.setattr(shadow, "MAX_ROWS", 2)
    monkeypatch.setattr(
        shadow, "journal_records", lambda _a, _b: [row(i, BASE + i) for i in (1, 2, 3)]
    )
    with pytest.raises(ValueError, match="bounded"):
        shadow.poll_once(database, now=BASE + 50)


def test_outage_or_backward_clock_rejected_without_checkpoint_change(shadow, database, monkeypatch):
    monkeypatch.setattr(shadow, "journal_records", lambda _a, _b: [])
    shadow.poll_once(database, now=BASE + 50)
    old = checkpoint(database)
    with pytest.raises(RuntimeError, match="Gap or clock"):
        shadow.poll_once(database, now=BASE + 50 + shadow.MAX_OUTAGE_SECONDS + 30)
    with pytest.raises(RuntimeError, match="Gap or clock"):
        shadow.poll_once(database, now=BASE - 10)
    assert checkpoint(database) == old


def test_refuses_root_production_db_and_invalid_path(shadow, tmp_path, monkeypatch):
    target = tmp_path / "sudo-shadow.sqlite3"
    monkeypatch.setattr(shadow.os, "geteuid", lambda: 0)
    with pytest.raises(PermissionError, match="unprivileged"):
        shadow.poll_once(target, now=BASE + 30)
    assert not target.exists()
    monkeypatch.undo()
    with pytest.raises(ValueError, match="separately named"):
        shadow.poll_once(tmp_path / "events.sqlite3", now=BASE + 30)


def test_private_db_has_no_raw_message_command_cursor(shadow, database, monkeypatch):
    data = [row(1, BASE + 20)]
    monkeypatch.setattr(shadow, "journal_records", snapshot(data))
    result = shadow.poll_once(database, now=BASE + 60)
    assert result["new_normalized_sudo_rows"] == 1
    with sqlite3.connect(database) as db:
        item = db.execute("SELECT * FROM sudo_signals").fetchone()
        assert item is not None
        fields = [d[0] for d in db.execute("SELECT * FROM sudo_signals").description]
    assert "message" not in fields and "cursor" not in fields
    assert "uid" in fields and "kind" in fields
    assert "private-cursor" not in json.dumps(result)
    assert "never-export" not in json.dumps(result)
    assert os.stat(database).st_mode & 0o077 == 0
