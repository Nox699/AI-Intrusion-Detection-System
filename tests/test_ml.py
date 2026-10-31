"""Model invariants and unsafe/ambiguous artifact rejection.

Synthetic data are only test fixtures. These tests verify software behaviour;
they are not measurements of detection quality on the Raspberry Pi.
"""

import copy
import hashlib
import json
import math
from types import SimpleNamespace

import numpy as np
import pytest

from yggdrasil_ids.features import FEATURE_NAMES
from yggdrasil_ids.ml import IsolationForestDetector, ModelValidationError


@pytest.fixture
def normal_rows():
    result = []
    for index in range(96):
        failed = index % 3
        success = 1 + index % 4
        users = min(failed + success, 1 + index % 2)
        phase = 2 * math.pi * (6 + index % 15) / 24
        result.append(
            [failed, success, users, failed / (failed + success), math.sin(phase), math.cos(phase)]
        )
    return result


@pytest.fixture
def model_config():
    return SimpleNamespace(
        window_seconds=300, min_samples=80, contamination=0.03, n_estimators=32, random_state=42
    )


@pytest.fixture
def trained(normal_rows, model_config):
    return IsolationForestDetector.train(
        normal_rows, model_config, "Synthetic normal lab fixtures; no production claims"
    )


def test_score_semantics_and_metadata_are_explicit(trained, normal_rows):
    result = trained.score(normal_rows[0])
    assert 0 <= result["score"] <= 1
    assert 0 <= result["threshold"] <= 1
    assert result["is_anomaly"] is (result["score"] > result["threshold"])
    assert tuple(result["features"]) == FEATURE_NAMES
    assert result["model_version"] == trained.metadata["version"]
    assert trained.metadata["sample_count"] == 96
    assert trained.metadata["score_direction"] == "higher_is_more_anomalous"
    assert trained.metadata["window_seconds"] == 300


def test_synthetic_extreme_window_has_a_higher_score_than_typical_training(trained, normal_rows):
    extreme = [80, 1, 40, 80 / 81, 0.0, 1.0]
    typical_scores = [trained.score(row)["score"] for row in normal_rows]
    assert trained.score(extreme)["score"] > float(np.median(typical_scores))


def test_model_roundtrip_preserves_scores_threshold_identity_and_provenance(
    tmp_path, trained, normal_rows
):
    path = tmp_path / "models" / "ssh.json"
    trained.save(path)
    assert json.loads(path.read_text())["algorithm"] == "sklearn.ensemble.IsolationForest"
    restored = IsolationForestDetector.load(path)
    assert restored.metadata == trained.metadata
    for row in normal_rows[::11]:
        assert restored.score(row) == trained.score(row)
    assert path.stat().st_mode & 0o777 == 0o640


def test_scoring_does_not_change_training_state_or_caller_input(trained, normal_rows):
    metadata = trained.metadata
    row = copy.deepcopy(normal_rows[0])
    trained.score(row)
    trained.score([80, 1, 40, 80 / 81, 0, 1])
    assert row == normal_rows[0]
    assert trained.metadata == metadata
    metadata["feature_names"].clear()
    assert trained.metadata["feature_names"] == list(FEATURE_NAMES)


def test_insufficient_and_unvaried_training_are_rejected(normal_rows, model_config):
    with pytest.raises(ModelValidationError, match="80"):
        IsolationForestDetector.train(normal_rows[:79], model_config, "lab")
    with pytest.raises(ModelValidationError, match="variation"):
        IsolationForestDetector.train([normal_rows[0]] * 96, model_config, "lab")
    only_clock_changes = [[0, 1, 1, 0, row[4], row[5]] for row in normal_rows]
    with pytest.raises(ModelValidationError, match="variation"):
        IsolationForestDetector.train(only_clock_changes, model_config, "lab")


@pytest.mark.parametrize(
    "position,value",
    [
        (0, -1),
        (0, float("nan")),
        (1, float("inf")),
        (2, 1000),
        (3, 1.5),
        (3, 0.81),
        (4, 2),
        (5, "0"),
        (0, True),
        (0, 1.5),
    ],
)
def test_invalid_features_are_rejected(trained, normal_rows, position, value):
    row = list(normal_rows[0])
    row[position] = value
    with pytest.raises(ModelValidationError):
        trained.score(row)


@pytest.mark.parametrize("row", [[], [1, 2], "123456", {"features": [1]}, None])
def test_malformed_feature_shapes_are_rejected(trained, row):
    with pytest.raises(ModelValidationError):
        trained.score(row)


@pytest.mark.parametrize(
    "key,value",
    [
        ("n_estimators", 100000),
        ("n_estimators", True),
        ("contamination", 0),
        ("contamination", 0.9),
        ("contamination", float("nan")),
        ("random_state", -1),
        ("min_samples", 1),
        ("window_seconds", 0),
    ],
)
def test_unbounded_or_invalid_settings_are_rejected_before_training(
    normal_rows, model_config, key, value
):
    setattr(model_config, key, value)
    with pytest.raises(ModelValidationError):
        IsolationForestDetector.train(normal_rows, model_config, "lab")


def test_training_provenance_is_required(normal_rows, model_config):
    with pytest.raises(ModelValidationError, match="datagrundlaget"):
        IsolationForestDetector.train(normal_rows, model_config, "   ")


@pytest.mark.parametrize(
    "key,value",
    [
        ("sklearn_version", "unknown-version"),
        ("feature_names", ["raw_ip"]),
        ("algorithm", "eval"),
        ("format_version", 2),
        ("format_version", True),
        ("trained_at", "2026-10-28T00:00:00"),
        ("threshold", float("inf")),
        ("fingerprint", "f" * 64),
    ],
)
def test_artifact_mismatch_is_rejected_before_refitting(tmp_path, trained, monkeypatch, key, value):
    path = tmp_path / "model.json"
    trained.save(path)
    payload = json.loads(path.read_text())
    payload[key] = value
    path.write_text(json.dumps(payload))

    def unexpected_fit(*args, **kwargs):
        pytest.fail("Invalid artifact must be rejected before model fitting")

    monkeypatch.setattr("yggdrasil_ids.ml.IsolationForest.fit", unexpected_fit)
    with pytest.raises(ModelValidationError):
        IsolationForestDetector.load(path)


def test_valid_checksum_does_not_bypass_resource_limits(tmp_path, trained):
    path = tmp_path / "model.json"
    trained.save(path)
    payload = json.loads(path.read_text())
    payload["settings"]["n_estimators"] = 500000
    body = {key: value for key, value in payload.items() if key != "fingerprint"}
    payload["fingerprint"] = hashlib.sha256(
        json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    path.write_text(json.dumps(payload))
    with pytest.raises(ModelValidationError, match="n_estimators"):
        IsolationForestDetector.load(path)


def test_duplicate_json_keys_and_invalid_json_are_rejected(tmp_path):
    path = tmp_path / "model.json"
    path.write_text('{"format_version":1,"format_version":1}')
    with pytest.raises(ModelValidationError, match="gentagne"):
        IsolationForestDetector.load(path)
    path.write_text("not JSON or executable Python")
    with pytest.raises(ModelValidationError, match="JSON"):
        IsolationForestDetector.load(path)


def test_oversized_artifact_is_rejected_without_unbounded_read(tmp_path, monkeypatch):
    path = tmp_path / "model.json"
    path.write_bytes(b"x" * 65)
    monkeypatch.setattr("yggdrasil_ids.ml.MAX_ARTIFACT_BYTES", 64)
    with pytest.raises(ModelValidationError, match="størrelsesgrænsen"):
        IsolationForestDetector.load(path)


def test_atomic_save_failure_preserves_existing_model(tmp_path, trained, monkeypatch):
    path = tmp_path / "model.json"
    trained.save(path)
    original = path.read_bytes()

    def replacement_fails(*args, **kwargs):
        raise OSError("simulated replacement failure")

    monkeypatch.setattr("yggdrasil_ids.ml.os.replace", replacement_fails)
    with pytest.raises(OSError, match="simulated"):
        trained.save(path)
    assert path.read_bytes() == original
    assert list(tmp_path.glob(".model-*.tmp")) == []
