"""Original Sprint 5 schema, full-data fitting and frozen original-format models."""

import importlib.util
import json
import sys
from pathlib import Path

import pytest

from yggdrasil_ids.sudo_ml import FEATURE_NAMES, SudoIsolationForest


@pytest.fixture(scope="module")
def baseline():
    root = Path(__file__).resolve().parents[1]
    for name in (
        "sprint5_sudo_ml_lab",
        "sprint5_sudo_ml_v2_lab",
        "sprint5_sudo_mixed_ml_lab",
        "sprint5_sudo_baseline_replay",
    ):
        spec = importlib.util.spec_from_file_location(name, root / "deploy" / f"{name}.py")
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
    return sys.modules["sprint5_sudo_baseline_replay"]


def candidate(t, normal=True, outcome="success", group=1):
    return {
        "timestamp": float(t),
        "group": group,
        "outcome": outcome,
        "normal_candidate": normal,
        "also_had_success": outcome == "success",
    }


def fixture(baseline):
    rows = []
    # Two development days and one separate retrospective day.
    for start, count in (
        (baseline.TEST_START - 2 * 86400 + 36000, 90),
        (baseline.TEST_START - 86400 + 36000, 60),
        (baseline.TEST_START + 36000, 50),
    ):
        rows.extend(candidate(start + i * 10) for i in range(count))
    rows.extend(
        candidate(baseline.CONTROLLED_START + 120 + i * 5, False, "failure", 2) for i in range(3)
    )
    return sorted(rows, key=lambda row: row["timestamp"])


def test_sources_use_all_original_synthetic_rows_and_all_real_rows(baseline):
    rows, _, _ = baseline.prepare(fixture(baseline))
    sources = baseline.sources(rows)
    assert len(rows) == 150
    assert {name: len(matrix) for name, matrix in sources.items()} == {
        "synthetic_full": 681,
        "real_full": 150,
        "mixed_full": 831,
    }
    assert all(len(row) == 7 for matrix in sources.values() for row in matrix)
    assert sources["mixed_full"] == rows + sources["synthetic_full"]


def test_reproduces_original_sprint5_published_synthetic_results(baseline):
    matrix = baseline.sources([[1, 0, 0, 1, 0, 0, 1]] * 80)["synthetic_full"]
    model = SudoIsolationForest.train(
        matrix, "Reproduce unchanged original Sprint5 full synthetic baseline"
    )
    _, validation, historical = baseline.create_splits()
    report = baseline.evaluate(model, validation)
    assert (report["ml"]["tp"], report["ml"]["fp"]) == (15, 5)
    report = baseline.evaluate(model, historical)
    assert (report["ml"]["tp"], report["ml"]["fp"]) == (12, 4)


def test_preparation_uses_nov2_development_and_excludes_nov3_training(baseline):
    source = fixture(baseline)
    normal, replay, training = baseline.prepare(source)
    assert len(normal) == 150 and len(training) == 150
    assert all(row["timestamp"] < baseline.TEST_START - baseline.GAP for row in training)
    assert all(row["timestamp"] >= baseline.TEST_START + baseline.GAP for row in replay)
    assert len(replay) == 53


def test_replay_keeps_unscored_warmup_context(baseline):
    rows = fixture(baseline)
    boundary = baseline.TEST_START + baseline.GAP
    rows += [candidate(boundary - 1), candidate(boundary + 1)]
    rows.sort(key=lambda row: row["timestamp"])
    _, replay, _ = baseline.prepare(rows)
    assert replay[0]["timestamp"] == boundary - 1
    # The second process must see the first, even though the first is unscored.
    seen = []

    class Model:
        def score_many(self, matrix):
            seen.extend(matrix)
            return [{"is_anomaly": False} for _ in matrix]

    result = baseline.real_replay(Model(), replay)
    assert seen[1][0] == 2
    assert result["normal_candidate_positions"] == 51


def test_private_original_format_roundtrip_and_no_source_changes(baseline, tmp_path):
    rows = fixture(baseline)
    path = tmp_path / "export.json"
    path.write_text(
        json.dumps(
            {"format": "sudo-process-candidates-v1", "process_count": len(rows), "processes": rows}
        )
    )
    original = path.read_bytes()
    directory = tmp_path / "baseline"
    report = baseline.run(path, directory)
    assert path.read_bytes() == original
    assert report["subsampled"] is False and report["threshold_calibrated_on_validation"] is False
    assert report["models_activated"] is False and report["production_changes"] is False
    assert report["previously_inspected_replays_are_not_unseen"] is True
    for result in report["results"].values():
        assert result["feature_names"] == list(FEATURE_NAMES)
        model = SudoIsolationForest.load(directory / result["model_file"])
        assert model.threshold == result["threshold"]
        assert (directory / result["model_file"]).stat().st_mode & 0o077 == 0
    assert (directory / "report.json").stat().st_mode & 0o077 == 0
    with pytest.raises(FileExistsError):
        baseline.run(path, directory)
