"""Score tradeoffs preserve frozen models and do not consume final holdouts."""

import importlib.util
import json
import sys
from pathlib import Path

import pytest


@pytest.fixture(scope="module")
def modules():
    root = Path(__file__).resolve().parents[1]
    names = (
        "sprint5_sudo_ml_lab",
        "sprint5_sudo_ml_v2_lab",
        "sprint5_sudo_mixed_ml_lab",
        "sprint5_sudo_score_diagnostics",
    )
    for name in names:
        spec = importlib.util.spec_from_file_location(name, root / "deploy" / f"{name}.py")
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
    return sys.modules[names[-2]], sys.modules[names[-1]]


@pytest.fixture(scope="module")
def frozen_synthetic(modules):
    lab, diagnostic = modules
    training, validation, _ = lab.create_splits()
    pool = [r for case in training for r in lab.scenario_bundle(case)[1]]
    rows = lab.training_sets([[1, 0, 0, 1, 0]] * 181, pool)["synthetic"]
    fingerprint = lab.sha256(rows)
    assert fingerprint == "02af99371e15ca5c0d8db60e0d7187f51963293c902c613cd2975748c121b5d7"
    recipe = {
        "deployable": False,
        "normal_training_rows": rows,
        "sklearn_version": diagnostic.sklearn.__version__,
        "forest_parameters": {
            "n_estimators": 128,
            "random_state": 42,
            "n_jobs": 1,
            "contamination": 0.03,
            "max_samples": 181,
        },
    }
    model, matrix = diagnostic.reconstruct(recipe, fingerprint)
    return model, matrix, recipe, validation


def test_reconstruction_checks_matrix_and_version(modules, frozen_synthetic):
    _, diagnostic = modules
    _, _, recipe, _ = frozen_synthetic
    with pytest.raises(ValueError, match="fingerprint"):
        diagnostic.reconstruct(recipe, "0" * 64)
    with pytest.raises(ValueError, match="version"):
        diagnostic.reconstruct({**recipe, "sklearn_version": "invalid"}, "0" * 64)


def test_181_row_synthetic_false_positive_budget_cliff_is_reproduced(modules, frozen_synthetic):
    lab, diagnostic = modules
    model, _, _, cases = frozen_synthetic
    # Constructed real validation is irrelevant to the synthetic-only cap profile.
    rows = [
        {
            "timestamp": float(1000 + i * 10),
            "group": 1,
            "outcome": "success",
            "also_had_success": True,
            "normal_candidate": True,
        }
        for i in range(40)
    ]
    attempts, matrix = lab.real_bundle(rows)
    raw = -model.score_samples(matrix)
    values = lab.confirmation_values(attempts, raw)
    synthetic = lab.synthetic_evidence(model, cases)
    result = diagnostic.operating_profiles(
        rows, raw, values, cases, synthetic, float(-model.offset_), 0.6293101117393565
    )
    assert result["synthetic_5pct_only"]["synthetic_validation"]["tp"] == 0
    assert result["unconstrained_validation"]["synthetic_validation"]["tp"] == 24
    assert result["unconstrained_validation"]["synthetic_validation"]["fp"] == 2


def test_score_distribution_ignores_missing_confirmation_and_preserves_bounds(modules):
    _, diagnostic = modules
    assert diagnostic.distribution([None, None]) == {"count": 0}
    result = diagnostic.distribution([None, 0.4, 0.6])
    assert result["min"] == 0.4 and result["max"] == 0.6 and result["median"] == 0.5


def test_validation_only_private_diagnostics_leave_original_files_unchanged(
    modules, tmp_path, monkeypatch
):
    lab, diagnostic = modules
    rows = []
    for start, count in (
        (lab.VALIDATION_START - 86400 + 36000, 100),
        (lab.VALIDATION_START + 36000, 50),
        (lab.TEST_START + 36000, 50),
    ):
        rows.extend(
            {
                "timestamp": float(start + i * 10),
                "group": 1,
                "outcome": "success",
                "also_had_success": True,
                "normal_candidate": True,
            }
            for i in range(count)
        )
    dataset = tmp_path / "dataset.json"
    dataset.write_text(
        json.dumps(
            {"format": "sudo-process-candidates-v1", "process_count": len(rows), "processes": rows}
        )
    )
    folder = tmp_path / "original"
    lab.run(dataset, folder)
    files = [dataset, folder / "report.json", folder / "research-recipes.json"]
    originals = [p.read_bytes() for p in files]

    class ForbiddenHoldout:
        def __iter__(self):
            raise AssertionError("Diagnostics must not evaluate the final test")

    original_split = diagnostic.split_real

    def guarded_split(value):
        result, excluded = original_split(value)
        result["test"] = ForbiddenHoldout()
        result["training"] = ForbiddenHoldout()
        return result, excluded

    monkeypatch.setattr(diagnostic, "split_real", guarded_split)
    result = diagnostic.run(dataset, folder / "report.json", tmp_path / "diagnostics")
    assert [p.read_bytes() for p in files] == originals
    assert result["final_test_scored"] is False and result["thresholds_changed"] is False
    assert all(r["original_calibration_reproduced"] for r in result["results"].values())
    assert (tmp_path / "diagnostics" / "diagnostics.json").stat().st_mode & 0o077 == 0
