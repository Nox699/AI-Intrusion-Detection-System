"""Preauth ML stays separate from live SSH model; labels stay outside features."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

from yggdrasil_ids.features import FEATURE_NAMES as SSH_FEATURE_NAMES
from yggdrasil_ids.preauth_ml import (
    FEATURE_NAMES,
    PreauthIsolationForest,
    connections_from_records,
    feature_rows,
)

DEPLOY = Path(__file__).resolve().parents[1] / "deploy"


@pytest.fixture(scope="module")
def lab():
    sys.path.insert(0, str(DEPLOY))
    try:
        spec = importlib.util.spec_from_file_location(
            "sprint4_preauth_ml_lab", DEPLOY / "sprint4_preauth_ml_lab.py"
        )
        assert spec and spec.loader
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        return module
    finally:
        sys.path.remove(str(DEPLOY))


@pytest.fixture
def synthetic(tmp_path, lab):
    directory = tmp_path / "private-preauth"
    lab.generate(directory, seed=42, anchor=1_793_500_000)
    return directory


def test_lab_splits_are_deterministic_and_training_labels_benign(tmp_path, lab):
    first = tmp_path / "one"
    second = tmp_path / "two"
    lab.generate(first, seed=42)
    lab.generate(second, seed=42)
    for name in (*lab.FAMILIES, "manifest.json"):
        assert (first / name).read_bytes() == (second / name).read_bytes()
    labels = json.loads((first / "labels.json").read_text())
    assert all(item["expected"] == "normal" for item in labels["split_labels"]["train"])
    seen = set()
    for split in ("train", "validation", "test"):
        events = [json.loads(line) for line in (first / f"{split}.jsonl").read_text().splitlines()]
        assert all(
            {"expected", "scenario", "label", "source_kind"} & set(event) == set()
            for event in events
        )
        cursors = {event["__CURSOR"] for event in events}
        assert not seen.intersection(cursors)
        seen |= cursors


def test_correlates_dual_line_invalid_user_into_one_connection(lab):
    from sprint4_preauth_signal_audit import classify

    raw = [
        {
            "_UID": "0",
            "_COMM": "sshd-session",
            "__CURSOR": "first",
            "__REALTIME_TIMESTAMP": "1793500000000000",
            "_BOOT_ID": "synthetic",
            "MESSAGE": "Invalid user guest from 192.0.2.10 port 40000",
        },
        {
            "_UID": "0",
            "_COMM": "sshd-session",
            "__CURSOR": "second",
            "__REALTIME_TIMESTAMP": "1793500001000000",
            "_BOOT_ID": "synthetic",
            "MESSAGE": "Connection closed by invalid user guest 192.0.2.10 port 40000 [preauth]",
        },
    ]
    conn = connections_from_records(raw, classify)
    assert len(conn) == 1
    assert conn[0].cursor == "first"
    assert conn[0].invalid_user and conn[0].disconnected
    assert feature_rows(conn)[0][:5] == [1.0, 1.0, 1.0, 1.0, 1.0]
    assert "source_ip" not in FEATURE_NAMES and "username" not in FEATURE_NAMES
    assert "unique_usernames_300s" in FEATURE_NAMES  # aggregate count, not an identity


def test_model_schemas_are_independent_and_model_fingerprint_verified(synthetic, lab):
    inputs, labels = lab._load(synthetic)
    assert len(labels["split_labels"]["train"]) > 300
    train = connections_from_records(inputs["train"], lab.classify)
    vectors = feature_rows(train)
    assert len(vectors) == 321
    assert len(FEATURE_NAMES) == 7
    assert tuple(FEATURE_NAMES) != tuple(SSH_FEATURE_NAMES)
    model = PreauthIsolationForest.train(vectors, "SYNTHETIC benign preauth fixtures only")
    path = synthetic / "preauth-model.json"
    model.save(path)
    assert path.stat().st_mode & 0o777 == 0o600
    loaded = PreauthIsolationForest.load(path)
    assert loaded.version == model.version
    assert loaded.score(vectors[0]) == model.score(vectors[0])
    with pytest.raises(FileExistsError):
        model.save(path)
    payload = json.loads(path.read_text())
    payload["features"][0] = "accepted_ssh_login_count"
    path.write_text(json.dumps(payload))
    with pytest.raises(ValueError, match="schema"):
        PreauthIsolationForest.load(path)


def test_lab_evaluation_counts_and_holds_out_attacks(synthetic, lab):
    summary = lab.evaluate(synthetic)
    assert summary["kind"] == "synthetic_preauth_isolation_forest_lab"
    assert summary["training_rows"] == 321
    assert summary["production_ids_changed"] is False
    assert summary["new_live_preauth_ml_active"] is False
    assert summary["test_metrics"]["ml"]["total"] == 49
    report = json.loads((synthetic / "report.json").read_text())
    assert report["model"]["trained_on_any_real_pi_data"] is False
    assert report["model"]["training_data_source"] == "synthetic_benign_only"
    for split in ("validation", "test"):
        for key in ("rules", "ml"):
            counts = report[split][key]
            assert sum(counts[name] for name in ("tp", "fp", "tn", "fn")) == counts["total"]
        assert report[split]["connection_candidates"] == sum(
            item["connections"] for item in report[split]["scenarios"]
        )
    assert "198.51.100." not in json.dumps(summary)
    assert "192.0.2." not in json.dumps(summary)


def test_corrupted_test_data_rejected_before_training(synthetic, lab):
    test = synthetic / "test.jsonl"
    test.write_text(test.read_text() + "{}\n")
    with pytest.raises(ValueError, match="hash"):
        lab.evaluate(synthetic)
    assert not (synthetic / "preauth-lab-model.json").exists()


def test_normal_labels_cannot_be_poisoned_with_attack(synthetic, lab):
    data = json.loads((synthetic / "labels.json").read_text())
    data["split_labels"]["train"][0]["expected"] = "simulated_suspicious"
    (synthetic / "labels.json").write_text(json.dumps(data))
    # Changing sidecar but not pinned manifest invalidates the experiment.
    with pytest.raises(ValueError, match="hash"):
        lab.evaluate(synthetic)


def test_prepared_rows_reject_invalid_attack_probability_feature():
    row = [1.0, 0.0, 1.0, 1.0, 0.0, 0.0, 1.0]
    model = PreauthIsolationForest
    with pytest.raises(ValueError, match="Inconsistent"):
        from yggdrasil_ids.preauth_ml import _clean_rows

        _clean_rows([[1.0, 1.0, 1.0, 1.0, 0.0, 0.0, 1.0]])
    assert model is not None
    assert row[4] == 0.0
