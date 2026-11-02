"""Historical real SSH-data audit never writes, prints IPs, or claims readiness."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from yggdrasil_ids.lab import generate_lab

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "deploy" / "sprint4_ssh_journal_history.py"


@pytest.fixture(scope="module")
def tool():
    spec = importlib.util.spec_from_file_location("sprint4_ssh_journal_history", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def synthetic_journal(tmp_path):
    paths = generate_lab(tmp_path / "lab", anchor=1_793_480_000, seed=42)
    return [
        json.loads(line)
        for line in paths["train_path"].read_text(encoding="utf-8").splitlines()
    ]


def test_history_audit_aggregates_trusted_authentication_only(tool, synthetic_journal):
    result = tool.summarize(synthetic_journal)
    assert result["kind"] == "historical_ssh_journal_inventory"
    assert result["ssh_auth_events"] == 312
    assert result["ssh_auth_events"] == result["ssh_success"] + result["ssh_failure"]
    assert result["unique_feature_vectors"] > 4
    assert result["distinct_sources_count_only"] >= 1
    assert len(result["daily_ssh_auth_counts_utc"]) >= 1
    assert not result["sufficiently_vetted_training_data"]
    body = json.dumps(result)
    assert "192.0.2." not in body
    assert "198.51.100." not in body
    assert "labuser" not in body
    assert "backup" not in body


def test_journal_audit_deduplicates_ssh_authentication(tool, synthetic_journal):
    records = synthetic_journal[:20]
    original = tool.summarize(records)
    # A duplicate of the first event appears after later records.
    extra = tool.summarize([*records, records[0]])
    assert extra["ssh_auth_events"] == original["ssh_auth_events"]
    assert extra["duplicate_auth_records"] == 1


def test_journal_audit_rejects_out_of_order_records(tool, synthetic_journal):
    records = synthetic_journal[:20]
    with pytest.raises(ValueError, match="chronologically"):
        tool.summarize(list(reversed(records)))


def test_journal_audit_is_bounded(tool, synthetic_journal, monkeypatch):
    monkeypatch.setattr(tool, "MAX_JOURNAL_RECORDS", 2)
    with pytest.raises(ValueError, match="bounded record limit"):
        tool.summarize(synthetic_journal[:3])


def test_history_command_exposes_no_raw_message_fields(tool, monkeypatch, capsys):
    def fake_journal(since):
        assert since == "2026-10-22 00:00:00"
        return iter([])

    monkeypatch.setattr(tool, "journal_stream", fake_journal)
    assert tool.main([]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["ssh_auth_events"] == 0
    assert result["sufficiently_vetted_training_data"] is False
    assert "source_ip" not in result
    assert "username" not in result
