"""End-to-end journal ingestion invariants across detectors and SQLite."""

import json
import sqlite3
from dataclasses import replace

import pytest

from yggdrasil_ids.config import AppConfig, CollectorConfig, RulesConfig
from yggdrasil_ids.engine import AnalysisEngine
from yggdrasil_ids.ml import IsolationForestDetector
from yggdrasil_ids.storage import Repository

NOW = 1_800_000_000.0


@pytest.fixture
def config(tmp_path, monkeypatch):
    monkeypatch.setattr("yggdrasil_ids.engine.time.time", lambda: NOW)
    return AppConfig(
        database_path=tmp_path / "events.sqlite3",
        model_path=tmp_path / "model.json",
        credentials_path=tmp_path / "credentials.json",
        mode="demo",
        rules=RulesConfig(failure_threshold=2),
    )


def record(index, *, timestamp=None, message=None):
    stamp = NOW - 100 + index if timestamp is None else timestamp
    return {
        "__CURSOR": f"cursor-{index}",
        "__REALTIME_TIMESTAMP": str(int(stamp * 1_000_000)),
        "_COMM": "sshd-session",
        "_UID": "0",
        "_PID": str(100 + index),
        "_HOSTNAME": "test-server",
        "MESSAGE": message or "Failed publickey for labuser from 192.0.2.10 port 54321 ssh2",
    }


def table_count(repository, table):
    # Only fixed test identifiers are supplied here.
    with repository.reader() as db:
        return db.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]


def test_duplicate_journal_records_do_not_duplicate_authentication_or_findings(config):
    engine = AnalysisEngine(config, "test")
    first, second = record(1), record(2)
    assert engine.process(first)["status"] == "event"
    assert engine.process(second)["findings"] == 1
    assert engine.process(first)["status"] == "duplicate"
    assert engine.process(second)["status"] == "duplicate"
    assert table_count(engine.repository, "events") == 2
    assert table_count(engine.repository, "findings") == 1
    assert table_count(engine.repository, "observations") == 2
    assert engine.repository.get_state("counters")["duplicates"] == 2
    assert engine.repository.get_state("cursor") == "cursor-2"


def test_pam_record_advances_checkpoint_without_counting_second_login(config):
    engine = AnalysisEngine(config, "test")
    engine.process(
        record(1, message="Accepted publickey for labuser from 192.0.2.10 port 54321 ssh2")
    )
    assert (
        engine.process(
            record(
                2,
                message=(
                    "pam_unix(sshd:session): session opened for user labuser(uid=1000) by labuser(uid=0)"
                ),
            )
        )["status"]
        == "ignored"
    )
    assert table_count(engine.repository, "records") == 2
    assert table_count(engine.repository, "events") == 1
    assert engine.repository.get_state("cursor") == "cursor-2"
    assert engine.repository.get_state("counters")["ignored"] == 1


def test_restart_reconstructs_identical_rolling_window_from_database(config, tmp_path):
    config = replace(config, rules=RulesConfig(failure_threshold=3))
    first = AnalysisEngine(config, "test")
    first.process(record(1))
    first.process(record(2))
    restarted = AnalysisEngine(config, "test")
    assert restarted.process(record(3))["findings"] == 1
    clean_config = replace(config, database_path=tmp_path / "uninterrupted.sqlite3")
    uninterrupted = AnalysisEngine(clean_config, "test")
    for index in (1, 2, 3):
        uninterrupted.process(record(index))
    assert restarted.repository.list_alerts() == uninterrupted.repository.list_alerts()
    assert restarted.repository.list_observations() == uninterrupted.repository.list_observations()
    assert restarted.repository.get_state("counters") == uninterrupted.repository.get_state(
        "counters"
    )


def test_database_failure_rolls_back_record_event_finding_and_cursor(config, monkeypatch):
    engine = AnalysisEngine(config, "test")
    engine.process(record(1))
    before = engine.repository.get_state("counters")
    original = Repository.add_finding

    def fail_after_alarm_write(db, finding, cooldown):
        original(db, finding, cooldown)
        raise sqlite3.OperationalError("simulated database failure")

    with monkeypatch.context() as patch:
        patch.setattr(Repository, "add_finding", staticmethod(fail_after_alarm_write))
        with pytest.raises(sqlite3.OperationalError, match="simulated"):
            engine.process(record(2))
    assert engine.repository.get_state("cursor") == "cursor-1"
    assert engine.repository.get_state("counters") == before
    for table in ("records", "events", "observations"):
        assert table_count(engine.repository, table) == 1
    assert table_count(engine.repository, "findings") == 0
    assert table_count(engine.repository, "alerts") == 0
    assert engine.process(record(2))["findings"] == 1


@pytest.mark.parametrize(
    "model_contents,expected_state", [(None, "untrained"), ("{broken", "error")]
)
def test_missing_or_corrupt_model_leaves_rule_detection_functioning(
    config, model_contents, expected_state
):
    if model_contents is not None:
        config.model_path.write_text(model_contents)
    engine = AnalysisEngine(config, "test")
    assert engine.repository.get_state("model")["state"] == expected_state
    engine.process(record(1))
    assert engine.process(record(2))["findings"] == 1
    assert engine.repository.list_alerts()["items"][0]["detector_id"] == "ssh.failed_burst"


def test_model_window_mismatch_is_reported_without_disabling_rules(config, monkeypatch):
    config.model_path.write_text("placeholder")

    class WrongWindow:
        metadata = {"window_seconds": 60}

    monkeypatch.setattr(IsolationForestDetector, "load", lambda path: WrongWindow())
    engine = AnalysisEngine(config, "test")
    assert engine.model is None
    assert engine.repository.get_state("model")["state"] == "error"
    assert "tidsvindue" in engine.repository.get_state("model")["message"]
    engine.process(record(1))
    assert engine.process(record(2))["findings"] == 1


def test_model_scoring_failure_is_isolated_from_rule_findings(config):
    engine = AnalysisEngine(config, "test")

    class BrokenModel:
        def score(self, values):
            raise ValueError("broken model computation")

    engine.model = BrokenModel()
    engine.process(record(1))
    result = engine.process(record(2))
    assert result["status"] == "event"
    assert result["findings"] == 1
    assert engine.repository.list_alerts()["items"][0]["detector_id"] == "ssh.failed_burst"
    assert engine.repository.get_state("model")["state"] == "error"
    assert engine.repository.get_state("counters")["analysis_errors"] >= 1


def test_removing_model_then_reloading_does_not_keep_hidden_stale_model(config):
    engine = AnalysisEngine(config, "test")
    engine.model = object()
    engine.load_model()
    assert engine.model is None
    assert engine.repository.get_state("model")["state"] == "untrained"


def test_out_of_order_event_is_retained_but_not_retroactively_scored(config):
    engine = AnalysisEngine(config, "test")
    engine.process(record(2))
    result = engine.process(record(1))
    assert result["status"] == "event"
    assert result["findings"] == 0
    assert table_count(engine.repository, "events") == 2
    observations = engine.repository.list_observations()["items"]
    assert {row["state"] for row in observations} == {"untrained", "late"}
    assert engine.repository.get_state("counters")["late"] == 1
    assert engine.repository.get_state("data_quality")
    assert table_count(engine.repository, "findings") == 0


def test_future_event_in_live_mode_does_not_poison_normal_event_watermark(config):
    engine = AnalysisEngine(replace(config, mode="live"), "live")
    assert engine.process(record(1, timestamp=NOW + 3600))["findings"] == 0
    assert engine.repository.get_state("max_seen_timestamp") is None
    engine.process(record(2, timestamp=NOW - 5))
    engine.process(record(3, timestamp=NOW - 4))
    assert engine.repository.get_state("max_seen_timestamp") == NOW - 4
    assert engine.repository.get_state("counters")["late"] == 1
    assert table_count(engine.repository, "findings") == 1


def test_malformed_and_oversized_records_are_counted_without_fake_events(config):
    config = replace(config, collector=CollectorConfig(max_record_bytes=1024))
    engine = AnalysisEngine(config, "test")
    assert engine.process(["not", "an", "object"])["status"] == "malformed"
    assert engine.process(record(1, message="x" * 2000))["status"] == "malformed"
    assert engine.process({**record(2), "__REALTIME_TIMESTAMP": "invalid"})["status"] == "malformed"
    assert engine.repository.get_state("counters")["malformed"] == 3
    assert table_count(engine.repository, "events") == 0
    assert engine.repository.get_state("cursor") == "cursor-2"


def test_escaped_surrogate_in_json_is_a_data_error_not_a_collector_crash(config):
    engine = AnalysisEngine(config, "test")
    malformed = record(
        1, message="Failed publickey for bad\ud800user from 192.0.2.10 port 54321 ssh2"
    )
    assert engine.process(malformed)["status"] == "malformed"
    assert engine.repository.get_state("counters")["malformed"] == 1
    assert engine.process(record(2))["status"] == "event"


def test_demo_live_and_replay_namespaces_cannot_mix_in_existing_database(config):
    engine = AnalysisEngine(config, "replay-one")
    engine.process(record(1))
    with pytest.raises(ValueError, match="Demo"):
        AnalysisEngine(replace(config, mode="live"), "replay-one")
    with pytest.raises(ValueError, match="datagrundlag"):
        AnalysisEngine(config, "replay-two")
    assert engine.repository.get_state("namespace") == "replay-one"
    assert engine.repository.get_state("mode") == "demo"
    assert table_count(engine.repository, "events") == 1


def test_live_engine_refuses_replay_before_opening_file(config, tmp_path):
    engine = AnalysisEngine(replace(config, mode="live"), "live")
    with pytest.raises(ValueError, match="Genafspilning"):
        engine.replay(tmp_path / "missing.jsonl")


def test_replay_recovers_after_bad_oversized_and_deep_json_lines(config, tmp_path):
    engine = AnalysisEngine(config, "test")
    source = tmp_path / "events.jsonl"
    source.write_bytes(
        json.dumps(record(1)).encode()
        + b"\n"
        + b"{broken}\n"
        + b"x" * (config.collector.max_record_bytes * 2)
        + b"\n"
        + b"[" * 1500
        + b"0"
        + b"]" * 1500
        + b"\n"
        + json.dumps(record(2)).encode()
        + b"\n"
    )
    counts = engine.replay(source)
    assert counts["events"] == 2
    assert counts["malformed"] == 3
    assert table_count(engine.repository, "findings") == 1
    assert engine.repository.get_state("collector")["state"] == "replay"


def test_replaying_same_file_again_only_increments_duplicates(config, tmp_path):
    engine = AnalysisEngine(config, "test")
    source = tmp_path / "events.jsonl"
    source.write_text("\n".join(json.dumps(record(i)) for i in (1, 2)) + "\n")
    first = engine.replay(source)
    second = engine.replay(source)
    assert second["records"] == first["records"] == 2
    assert second["events"] == first["events"] == 2
    assert second["duplicates"] == 2
    assert table_count(engine.repository, "findings") == 1
