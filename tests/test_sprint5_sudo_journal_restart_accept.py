"""Unit tests for real-journal sudo restart acceptance without reading real logs."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "deploy" / "sprint5_sudo_journal_restart_accept.py"
NOW = 1_793_501_000.0
BASE = 1_793_500_000.0


@pytest.fixture(scope="module")
def lab():
    spec = importlib.util.spec_from_file_location("sprint5_sudo_journal_restart_accept", SCRIPT)
    assert spec is not None and spec.loader is not None
    obj = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(obj)
    return obj


def records():
    return [
        {
            "_EXE": "/usr/bin/sudo",
            "_UID": "1000",
            "_PID": str(4000 + number),
            "_BOOT_ID": "b" * 32,
            "__CURSOR": f"private-journald-cursor-{number}",
            "__REALTIME_TIMESTAMP": str(int((BASE + second) * 1_000_000)),
            "MESSAGE": "pam_unix(sudo:auth): authentication failure; logname=private",
        }
        for number, second in enumerate((10, 20, 40, 70, 80), 1)
    ]


def test_command_is_fixed_bounded_and_filtered_by_trusted_sudo_exe(lab):
    cmd = lab.command(BASE, BASE + 100)
    assert cmd[0] == "journalctl"
    assert "--system" not in cmd
    assert "--follow" not in cmd
    assert "--since=@1793500000.000000" in cmd
    assert "--until=@1793500100.000000" in cmd
    assert "--output=json" in cmd
    assert "_EXE=/usr/bin/sudo" in cmd
    assert "--output-fields=" + lab.FIELDS in cmd
    assert lab.command(BASE, BASE + 100, timestamps_only=True)[4] == "--all"
    for incorrect in (float("nan"), float("inf"), -1, BASE + 200):
        with pytest.raises(ValueError):
            lab.command(incorrect, BASE + 100)


def test_timestamp_only_does_not_emit_raw_record(lab):
    assert lab.timestamps(records()) == [BASE + n for n in (10, 20, 40, 70, 80)]
    with pytest.raises(ValueError):
        lab.timestamps([{"__REALTIME_TIMESTAMP": "unexpected"}])


def test_replay_real_journal_simulation_deduplicates_and_suppresses_repeat_alarm(lab, monkeypatch):
    monkeypatch.setattr(lab.time, "time", lambda: NOW + 5)
    all_rows = records()
    calls = []

    def fake_journal(since, until, *, timestamps_only=False):
        calls.append((since, until, timestamps_only))
        for row in all_rows:
            at = int(row["__REALTIME_TIMESTAMP"]) / 1_000_000
            if since <= at <= until:
                if timestamps_only:
                    yield {"__REALTIME_TIMESTAMP": row["__REALTIME_TIMESTAMP"]}
                else:
                    yield row

    monkeypatch.setattr(lab, "read_snapshot", fake_journal)
    result = lab.evaluate_restarts(24)
    assert result["result"] == "success"
    assert result["historical_rows_available"] == 5
    assert result["first_pass_new_rows"] == 3
    assert result["second_pass_new_rows"] == 2
    assert result["second_pass_replayed_duplicates"] == 3
    assert result["third_pass_new_rows"] == 0
    assert result["third_pass_replayed_duplicates"] == 5
    assert result["unique_rows_in_private_sqlite"] == 5
    assert result["candidate_rule_matches"]["sudo.repeated_auth_failure"] == 1
    assert result["candidate_rule_matches"]["sudo.permission_denied"] == 0
    assert result["temporary_database_deleted"] is True
    assert result["production_database_modified"] is False
    assert result["discord_alerts_sent"] is False
    assert result["raw_private_data_exposed"] is False
    assert len(calls) == 4
    assert calls[0][2] is True
    assert all(call[1] == NOW for call in calls)
    assert "private-journald-cursor" not in json.dumps(result)
    assert "logname=private" not in json.dumps(result)


def test_insufficient_history_does_not_touch_sqlite(lab, monkeypatch):
    monkeypatch.setattr(lab.time, "time", lambda: NOW + 5)

    def fake_journal(since, until, *, timestamps_only=False):
        assert timestamps_only
        yield {"__REALTIME_TIMESTAMP": str(int(BASE * 1_000_000))}

    monkeypatch.setattr(lab, "read_snapshot", fake_journal)
    result = lab.evaluate_restarts(24)
    assert result["result"] == "insufficient_real_journal_history"
    assert result["historical_rows_available"] == 1


def test_no_real_journal_access_is_attempted_as_root(lab, monkeypatch):
    monkeypatch.setattr(lab.os, "geteuid", lambda: 0)

    def blocked(*args, **kwargs):
        pytest.fail("Should never open real journal as root")

    monkeypatch.setattr(lab, "read_snapshot", blocked)
    with pytest.raises(PermissionError):
        lab.evaluate_restarts(24)
    with pytest.raises(ValueError):
        lab.evaluate_restarts(49)


def test_privacy_preserving_cli_handles_empty_history(lab, monkeypatch, capsys):
    monkeypatch.setattr(
        lab,
        "evaluate_restarts",
        lambda hours: {
            "kind": "sudo_real_journal_restart_accept",
            "result": "insufficient_real_journal_history",
            "historical_rows_available": 0,
            "raw_private_data_exposed": False,
        },
    )
    assert lab.main(["--hours", "24"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["result"] == "insufficient_real_journal_history"
