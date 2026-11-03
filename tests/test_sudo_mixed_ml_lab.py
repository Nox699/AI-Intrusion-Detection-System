"""Chronological isolation and comparable normal-training data sources."""

import importlib.util
import json
import sys
from pathlib import Path

import numpy as np
import pytest
from sklearn.ensemble import IsolationForest


@pytest.fixture(scope="module")
def lab():
    root = Path(__file__).resolve().parents[1]
    for name in ("sprint5_sudo_ml_lab", "sprint5_sudo_ml_v2_lab", "sprint5_sudo_mixed_ml_lab"):
        spec = importlib.util.spec_from_file_location(name, root / "deploy" / f"{name}.py")
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
    return sys.modules["sprint5_sudo_mixed_ml_lab"]


def row(t, outcome="success", normal=True, group=1):
    return {
        "timestamp": float(t),
        "group": group,
        "outcome": outcome,
        "also_had_success": outcome == "success",
        "normal_candidate": normal,
    }


def fixture_rows(lab):
    rows = []
    for start, count in (
        (lab.VALIDATION_START - 86400 + 36000, 120),
        (lab.VALIDATION_START + 36000, 60),
        (lab.TEST_START + 36000, 60),
    ):
        rows.extend(row(start + i * 10) for i in range(count))
    rows.extend(row(lab.CONTROLLED_START + 120 + i * 5, "failure", False, 2) for i in range(3))
    return sorted(rows, key=lambda r: r["timestamp"])


def test_schema_rejects_raw_fields_bad_times_and_failed_normal_candidates(lab, tmp_path):
    path = tmp_path / "export.json"

    def write(rows):
        path.write_text(
            json.dumps(
                {
                    "format": "sudo-process-candidates-v1",
                    "process_count": len(rows),
                    "processes": rows,
                }
            )
        )

    write([row(1000)])
    assert len(lab.load_export(path)[0]) == 1
    for rows in (
        [{**row(1000), "uid": "1000"}],
        [row(float("nan"))],
        [row(1000, "failure", True)],
        [row(2000), row(1000)],
        [{**row(1000), "group": True}],
    ):
        write(rows)
        with pytest.raises(ValueError):
            lab.load_export(path)


def test_split_gaps_remove_overlapping_history_at_both_boundaries(lab):
    a, b, g = lab.VALIDATION_START, lab.TEST_START, lab.GAP
    rows = [
        row(a - g - 1),
        row(a - g),
        row(a + g - 1),
        row(a + g),
        row(b - g - 1),
        row(b - g),
        row(b + g - 1),
        row(b + g),
        row(lab.TEST_END),
    ]
    splits, excluded = lab.split_real(rows)
    assert [r["timestamp"] for r in splits["training"]] == [a - g - 1]
    assert [r["timestamp"] for r in splits["validation"]] == [a + g, b - g - 1]
    assert [r["timestamp"] for r in splits["test"]] == [b + g]
    assert excluded == 5


def test_real_features_are_causal_and_grouped_without_identity_features(lab):
    rows = [row(1000, "failure", False), row(1010, group=2), row(1020)]
    attempts, features = lab.real_bundle(rows)
    assert features[0] == [1, 1, 0, 0, 1]
    assert features[1] == [1, 0, 0, 1, 0]
    assert features[2] == [2, 1, 0, 1, 0.5]
    assert lab.real_bundle(rows[:1])[1][0] == features[0]
    evidence = lab.confirmation_values(attempts, [0.9, 0.99, 0.8])
    assert evidence == [None, None, 0.8]
    assert lab.confirmation_values(
        lab.real_bundle([row(1000), row(1010), row(1020)])[0], [0.9, 0.1, 0.9]
    ) == [None, 0.1, 0.1]


def test_equal_training_budgets_reproducible_mixture_and_no_oversampling(lab):
    real = [[i, 0, 0, i, 0] for i in range(100)]
    synthetic = [[1000 + i, 0, 0, 1000 + i, 0] for i in range(200)]
    sets = lab.training_sets(real, synthetic)
    assert sets == lab.training_sets(real, synthetic)
    assert {len(matrix) for matrix in sets.values()} == {100}
    assert sum(r[0] < 1000 for r in sets["mixed"]) == 50
    assert len({r[0] for r in sets["mixed"]}) == 100
    with pytest.raises(ValueError, match="80"):
        lab.training_sets(real[:79], synthetic)


def test_calibration_cannot_inspect_test_data(lab, monkeypatch):
    def forbidden(*args):
        raise AssertionError("Test access during calibration")

    monkeypatch.setattr(lab, "fresh_test_cases", forbidden)
    monkeypatch.setattr(lab, "evaluate_real", forbidden)
    splits, _ = lab.split_real(fixture_rows(lab))
    _, matrix = lab.real_bundle(splits["training"])
    model = IsolationForest(n_estimators=8, random_state=42).fit(np.asarray(matrix))
    _, validation, _ = lab.create_splits()
    calibrated = lab.calibrate(model, splits["validation"], validation)
    assert calibrated["real_validation"]["provisional_confirmed_false_positive_rate"] <= 0.05
    assert calibrated["synthetic_validation"]["false_positive_rate"] <= 0.05


def test_normal_and_review_metrics_not_reported_as_attack_truth(lab):
    rows = [row(1000), row(1010), row(1020, "failure", False)]
    result = lab.real_metrics(rows, [0.9, 0.9, 0.9], [None, 0.9, 0.9], 0.8)
    assert result["raw_anomaly_positions"] == 2
    assert result["confirmed_flag_positions"] == 1
    assert result["confirmed_flags_on_review_positions"] == 1
    assert "tp" not in result and "recall" not in result


def test_single_anomaly_is_visible_raw_but_requires_another_process_to_confirm(lab):
    from types import SimpleNamespace

    model = SimpleNamespace(score_samples=lambda rows: np.full(len(rows), -0.9))
    case = lab.scenario("normal_quiet", 120001)
    assert lab.synthetic_evidence(model, [case], require_confirmation=False) == [0.9]
    assert lab.synthetic_evidence(model, [case]) == [None]


def test_full_private_comparison_input_unchanged_and_recipes_not_deployable(lab, tmp_path):
    rows = fixture_rows(lab)
    path = tmp_path / "input.json"
    payload = {
        "format": "sudo-process-candidates-v1",
        "process_count": len(rows),
        "processes": rows,
    }
    path.write_text(json.dumps(payload))
    original = path.read_bytes()
    output = tmp_path / "comparison"
    report = lab.run(path, output)
    assert path.read_bytes() == original
    assert report["production_changes"] is False and report["discord_messages_sent"] == 0
    assert report["normal_labels_verified"] is False
    assert set(report["results"]) == set(lab.MODES)
    assert {r["training"]["rows"] for r in report["results"].values()} == {120}
    for result in report["results"].values():
        assert result["real_test"]["provisional_normal_positions"] == 60
        assert result["real_test"]["controlled_three_failure_probe"]["matched_expected_test_window"]
        assert (
            result["real_test"]["controlled_three_failure_probe"][
                "used_for_training_or_calibration"
            ]
            is False
        )
        assert (
            sum(
                result["fresh_synthetic_test"]["ml_with_confirmation"][k]
                for k in ("tp", "fp", "tn", "fn")
            )
            == 900
        )
    recipes = json.loads((output / "research-recipes.json").read_text())
    assert all(value["deployable"] is False for value in recipes.values())
    assert (output / "report.json").stat().st_mode & 0o077 == 0
    assert output.stat().st_mode & 0o077 == 0
    with pytest.raises(FileExistsError):
        lab.run(path, output)
