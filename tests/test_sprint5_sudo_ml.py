"""Sudo process-level ML prototype and independently split synthetic evaluation."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from yggdrasil_ids.sudo_ml import (
    FEATURE_NAMES,
    SudoIsolationForest,
    attempts_from_signals,
    feature_rows,
)
from yggdrasil_ids.sudo_rules import SudoSignal

SCRIPT = Path(__file__).resolve().parents[1] / "deploy" / "sprint5_sudo_ml_lab.py"
BOOT = "b" * 32
BASE = 1_793_680_000


@pytest.fixture(scope="module")
def lab():
    spec = importlib.util.spec_from_file_location("sprint5_sudo_ml_lab", SCRIPT)
    assert spec is not None and spec.loader is not None
    obj = importlib.util.module_from_spec(spec)
    import sys

    sys.modules[spec.name] = obj
    spec.loader.exec_module(obj)
    return obj


@pytest.fixture(scope="module")
def fitted(lab):
    training, _, _ = lab.create_splits()
    rows = [row for s in training for row in lab.features_for_scenario(s)]
    return SudoIsolationForest.train(rows, "Independent synthetic normal-only test training")


def signal(i, t, kind, pid=1001, uid="1000"):
    return SudoSignal(f"private-{i}", float(t), BOOT, uid, pid, kind)


def test_multiple_journal_messages_are_only_one_sudo_process():
    events = [
        signal(1, BASE + 1, "pam_auth_failure"),
        signal(2, BASE + 1.1, "incorrect_password"),
        signal(3, BASE + 1.2, "other_sudo"),
        signal(3, BASE + 1.2, "other_sudo"),
    ]
    attempts = attempts_from_signals(events)
    assert len(attempts) == 1
    assert attempts[0].outcome == "failure"
    assert feature_rows(attempts)[0][:5] == [1, 1, 0, 0, 1]


def test_different_pids_represent_independent_attempts_and_rolling_counts():
    events = [
        signal(1, BASE + 1, "pam_auth_failure", 1001),
        signal(2, BASE + 2, "pam_auth_failure", 1002),
        signal(3, BASE + 3, "pam_auth_failure", 1003),
    ]
    rows = feature_rows(attempts_from_signals(events))
    assert len(rows) == 3
    assert rows[-1][:5] == [3, 3, 0, 0, 1.0]


def test_distinct_uids_have_independent_process_windows():
    events = [
        signal(1, BASE + 1, "pam_auth_failure", 1001, "1000"),
        signal(2, BASE + 2, "command_invoked", 1002, "1001"),
    ]
    rows = feature_rows(attempts_from_signals(events))
    assert rows[0][0] == rows[1][0] == 1
    assert rows[1][:5] == [1, 0, 0, 1, 0]


def test_closing_only_signal_is_not_a_new_attempt():
    assert attempts_from_signals([signal(1, BASE, "pam_session_closed")]) == []


def test_duplicate_cursor_conflict_and_unordered_inputs_refused():
    with pytest.raises(ValueError, match="Conflicting"):
        attempts_from_signals(
            [
                signal(1, BASE, "pam_auth_failure"),
                signal(1, BASE + 1, "incorrect_password"),
            ]
        )
    with pytest.raises(ValueError, match="chronological"):
        attempts_from_signals(
            [
                signal(1, BASE + 2, "pam_auth_failure"),
                signal(2, BASE + 1, "pam_auth_failure"),
            ]
        )


def test_feature_names_have_no_identity_data_and_invalid_vectors_rejected(fitted):
    assert len(FEATURE_NAMES) == 7
    assert "uid" not in " ".join(FEATURE_NAMES)
    assert "command" not in " ".join(FEATURE_NAMES)
    vector = [2.0, 2.0, 0.0, 0.0, 1.0, 0.0, 1.0]
    assert isinstance(fitted.score(vector)["is_anomaly"], bool)
    with pytest.raises(ValueError):
        fitted.score([2, 2, 0, 1, 1, 0, 1])
    with pytest.raises(ValueError):
        fitted.score([2, 2, 0, 0, 1, 0, float("nan")])


def test_training_splits_independent_and_model_is_deterministic(lab, fitted):
    training, validation, test = lab.create_splits()
    assert len(training) == 180
    assert all(not row.suspicious for row in training)
    assert len(validation) == 64
    assert len(test) == 64
    all_seeds = [s.seed for s in [*training, *validation, *test]]
    assert len(all_seeds) == len(set(all_seeds))
    features = lab.features_for_scenario(test[32])
    scores = fitted.score_many(features)
    assert len(scores) == len(features)
    assert all(isinstance(s["score"], float) for s in scores)
    assert all(s["version"].startswith("sudo-if-") for s in scores)


def test_model_json_roundtrip_is_nonexecutable_and_rejects_tampering(fitted, tmp_path):
    path = tmp_path / "sudo-if.json"
    fitted.save(path)
    assert path.stat().st_mode & 0o077 == 0
    loaded = SudoIsolationForest.load(path)
    assert loaded.version == fitted.version
    assert loaded.threshold == fitted.threshold
    with pytest.raises(ValueError, match="private output"):
        fitted.save(path)
    payload = json.loads(path.read_text())
    assert payload["format"] == "sudo-isolation-forest-v1"
    assert payload["features"] == list(FEATURE_NAMES)
    assert "usernames" not in payload
    payload["threshold"] += 0.1
    path.write_text(json.dumps(payload))
    with pytest.raises(ValueError, match="fingerprint"):
        SudoIsolationForest.load(path)


def test_labelled_validation_and_test_report_both_rules_and_if(lab, fitted):
    _, validation, test = lab.create_splits()
    for cases in (validation, test):
        report = lab.evaluate(fitted, cases)
        assert report["scenario_count"] == 64
        assert report["normal_scenarios"] == 32
        assert report["suspicious_scenarios"] == 32
        for name in ("ml", "rules"):
            values = report[name]
            assert sum(values[k] for k in ("tp", "fp", "tn", "fn")) == 64
            assert values["false_positive_rate"] is not None
            assert values["recall"] is not None
        assert len(report["scenarios"]) == 64
    assert lab._manifest_hash(validation) != lab._manifest_hash(test)


def test_private_experiment_no_live_writes_and_only_synthetic(lab, tmp_path):
    output = tmp_path / "sudo-if-experiment"
    report = lab.experiment(output)
    assert report["synthetic_only"] is True
    assert report["real_journald_records_read"] == 0
    assert report["production_database_modified"] is False
    assert report["production_sudo_shadow_modified"] is False
    assert report["production_ml_model_modified"] is False
    assert report["discord_messages_sent"] == 0
    assert report["training"]["normal_process_observations"] >= 80
    assert report["validation"]["scenario_count"] == 64
    assert report["test"]["scenario_count"] == 64
    assert (output / "report.json").is_file()
    assert (output / "sudo-model.json").is_file()
    assert output.stat().st_mode & 0o077 == 0
    with pytest.raises(FileExistsError):
        lab.experiment(output)
