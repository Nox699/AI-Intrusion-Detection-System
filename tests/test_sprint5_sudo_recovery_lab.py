"""Unit and privacy tests for synthetic sudo restart/replay demonstration."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "deploy" / "sprint5_sudo_recovery_lab.py"


@pytest.fixture(scope="module")
def lab():
    spec = importlib.util.spec_from_file_location("sprint5_sudo_recovery_lab", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_synthetic_restarts_deduplicate_and_rebuild_rule_window(lab):
    result = lab.run_lab()
    assert result["session_one_unique_rows"] == 2
    assert result["session_two_replayed_duplicates"] == 2
    assert result["session_two_new_unique_rows"] == 1
    assert result["session_two_candidate_events"] == 1
    assert result["session_three_replayed_duplicates"] == 3
    assert result["session_three_new_unique_rows"] == 1
    assert result["session_three_new_candidate_events"] == 0
    assert result["candidate_rows_before_retention"] == 1
    assert result["unique_rows_before_retention"] == 4
    assert result["retention_removed_rows"] == 3
    assert result["unique_rows_after_retention"] == 1
    assert result["checkpoint_survived_retention"] is True
    assert result["temporary_database_deleted"] is True
    assert result["real_journald_access"] is False
    assert result["production_database_modified"] is False
    assert result["discord_alerts_sent"] is False
    assert result["recovery_guarantee"] == "best_effort_timestamp_overlap_not_lossless_cursor"
    for private in ("synthetic-journal-id", "5001", "1000", "/tmp/", ".sqlite3"):
        assert private not in json.dumps(result)


def test_synthetic_recovery_lab_refuses_root(lab, monkeypatch):
    monkeypatch.setattr(lab.os, "geteuid", lambda: 0)
    with pytest.raises(PermissionError):
        lab.run_lab()


def test_recovery_cli_only_emits_sanitized_counts(lab, capsys):
    assert lab.main() == 0
    result = json.loads(capsys.readouterr().out)
    assert result["temporary_database_deleted"] is True
    assert result["candidate_rows_before_retention"] == 1
