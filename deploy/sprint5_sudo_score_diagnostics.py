#!/usr/bin/env python3
"""Retrospective validation-only diagnostics of existing private sudo recipes.

Reconstructs the exact forests from saved normal matrices, seed and parameters.
No training-source change, deployment, threshold update or new holdout claim.
Profiles are descriptions of already-used validation data, not recommendations.
"""

from __future__ import annotations

import argparse
import json
import math
import os
from collections import Counter
from pathlib import Path

import numpy as np
import sklearn
from sklearn.ensemble import IsolationForest
from sprint5_sudo_mixed_ml_lab import (
    MODES,
    calibrate,
    confirmation_values,
    create_splits,
    flags,
    load_export,
    real_bundle,
    real_metrics,
    scenario_bundle,
    scenario_metrics,
    sha256,
    split_real,
    synthetic_evidence,
)

from yggdrasil_ids.sudo_ml import FEATURE_NAMES

PROFILES = (
    ("both_5pct", 0.05, 0.05),
    ("synthetic_5pct_only", 1.0, 0.05),
    ("real_5pct_only", 0.05, 1.0),
    ("real_5pct_synthetic_10pct", 0.05, 0.10),
    ("both_10pct", 0.10, 0.10),
    ("both_20pct", 0.20, 0.20),
    ("unconstrained_validation", 1.0, 1.0),
)


def distribution(values):
    clean = np.asarray([value for value in values if value is not None], dtype=float)
    if not len(clean):
        return {"count": 0}
    return {
        "count": len(clean),
        "min": float(clean.min()),
        "median": float(np.median(clean)),
        "p95": float(np.quantile(clean, 0.95)),
        "max": float(clean.max()),
        "distinct_values": len(np.unique(clean)),
    }


def operating_profiles(
    real_rows, real_raw, real_values, cases, synthetic_values, default, selected
):
    thresholds = {float(default), float(selected)}
    for value in [*real_values, *synthetic_values]:
        if value is not None:
            thresholds.update((float(value), float(np.nextafter(value, -np.inf))))

    def result(threshold):
        return {
            "threshold": threshold,
            "real_validation": real_metrics(real_rows, real_raw, real_values, threshold),
            "synthetic_validation": scenario_metrics(cases, flags(synthetic_values, threshold)),
        }

    candidates = [result(threshold) for threshold in sorted(thresholds)]
    profiles = {
        "saved_calibrated": result(float(selected)),
        "forest_default": result(float(default)),
    }
    for name, real_cap, synthetic_cap in PROFILES:
        feasible = [
            item
            for item in candidates
            if item["real_validation"]["provisional_confirmed_false_positive_rate"] <= real_cap
            and item["synthetic_validation"]["false_positive_rate"] <= synthetic_cap
        ]
        best = min(
            feasible,
            key=lambda item: (
                -item["synthetic_validation"]["tp"],
                item["real_validation"]["confirmed_flag_positions"],
                item["synthetic_validation"]["fp"],
                -item["threshold"],
            ),
        )
        profiles[name] = {**best, "real_budget": real_cap, "synthetic_budget": synthetic_cap}
    return profiles


def reconstruct(recipe, expected_matrix_sha):
    if recipe.get("format") != "sudo-mixed-research-recipe-v1":
        raise ValueError("Unexpected recipe format")
    if recipe.get("features") != list(FEATURE_NAMES[:5]):
        raise ValueError("Recipe feature names/order differ from the scoring schema")
    if recipe.get("confirmation_seconds") != 900 or recipe.get("required_consecutive") != 2:
        raise ValueError("Recipe confirmation policy differs from the scoring policy")
    if recipe.get("deployable") is not False:
        raise ValueError("Expected a non-deployable research recipe")
    if recipe.get("sklearn_version") != sklearn.__version__:
        raise ValueError("scikit-learn version differs from the original run")
    matrix = np.asarray(recipe["normal_training_rows"], dtype=float)
    if matrix.ndim != 2 or matrix.shape[1] != 5 or not 80 <= len(matrix) <= 10000:
        raise ValueError("Invalid frozen training matrix")
    if not np.isfinite(matrix).all() or sha256(matrix.tolist()) != expected_matrix_sha:
        raise ValueError("Frozen training matrix fingerprint differs")
    parameters = recipe["forest_parameters"]
    expected = {
        "n_estimators": 128,
        "random_state": 42,
        "n_jobs": 1,
        "contamination": 0.03,
        "max_samples": min(256, len(matrix)),
    }
    if parameters != expected:
        raise ValueError("Unexpected forest parameters; refusing an altered reconstruction")
    return IsolationForest(**parameters).fit(matrix), matrix


def diagnose(dataset, report_path):
    rows, dataset_sha = load_export(dataset)
    saved = json.loads(report_path.read_text())
    if saved.get("kind") != "sudo_real_synthetic_mixed_research":
        raise ValueError("Unexpected original report kind")
    if saved["dataset_sha256"] != dataset_sha:
        raise ValueError("Dataset differs from the original experiment")
    recipes = json.loads((report_path.parent / "research-recipes.json").read_text())
    partitions, _ = split_real(rows)
    # Only the ORIGINAL validation partition is scored. No final-test helper is called.
    validation = partitions["validation"]
    attempts, real_matrix = real_bundle(validation)
    normal_indices = [i for i, row in enumerate(validation) if row["normal_candidate"]]
    if not normal_indices:
        raise ValueError("No normal validation candidates")
    _, cases, _ = create_splits()
    results = {}
    for name in MODES:
        recipe = recipes[name]
        original = saved["results"][name]
        model, training = reconstruct(recipe, original["training"]["training_matrix_sha256"])
        threshold = recipe["threshold"]
        if not math.isfinite(threshold) or threshold != original["calibration"]["threshold"]:
            raise ValueError("Saved threshold differs between report and recipe")
        # Reproduce the original choice to catch stale code or incompatible reconstruction.
        recalculated = calibrate(model, validation, cases)
        if not math.isclose(recalculated["threshold"], threshold, rel_tol=0, abs_tol=1e-12):
            raise ValueError("Original calibration could not be reconstructed")
        real_raw = -model.score_samples(real_matrix)
        real_values = confirmation_values(attempts, real_raw)
        values = synthetic_evidence(model, cases)
        profiles = operating_profiles(
            validation, real_raw, real_values, cases, values, float(-model.offset_), threshold
        )
        used = Counter(
            int(feature)
            for tree in model.estimators_
            for feature in tree.tree_.feature
            if feature >= 0
        )
        synthetic_normal = [
            row for item in cases if not item.suspicious for row in scenario_bundle(item)[1]
        ]
        synthetic_suspicious = [
            row for item in cases if item.suspicious for row in scenario_bundle(item)[1]
        ]
        real_normal = np.asarray([real_matrix[i] for i in normal_indices])
        coverage = {}
        for column, feature in enumerate(FEATURE_NAMES[:5]):
            coverage[feature] = {
                "training_range": [
                    float(training[:, column].min()),
                    float(training[:, column].max()),
                ],
                "real_normal_validation_range": [
                    float(real_normal[:, column].min()),
                    float(real_normal[:, column].max()),
                ],
                "synthetic_suspicious_validation_range": [
                    min(row[column] for row in synthetic_suspicious),
                    max(row[column] for row in synthetic_suspicious),
                ],
                "tree_splits": used[column],
            }
        normal_vectors = {tuple(row) for row in [*real_normal.tolist(), *synthetic_normal]}
        suspicious_vectors = {tuple(row) for row in synthetic_suspicious}
        results[name] = {
            "original_calibration_reproduced": True,
            "original_status": recalculated["status"],
            "selected_threshold": threshold,
            "default_threshold": float(-model.offset_),
            "score_distributions": {
                "real_normal_raw": distribution([real_raw[i] for i in normal_indices]),
                "real_normal_confirmation": distribution([real_values[i] for i in normal_indices]),
                "synthetic_normal_confirmation": distribution(
                    [v for c, v in zip(cases, values) if not c.suspicious]
                ),
                "synthetic_suspicious_confirmation": distribution(
                    [v for c, v in zip(cases, values) if c.suspicious]
                ),
            },
            "identical_normal_and_suspicious_feature_vectors": len(
                normal_vectors & suspicious_vectors
            ),
            "feature_coverage": coverage,
            "profiles": profiles,
        }
    return {
        "kind": "retrospective_sudo_validation_score_diagnostics",
        "dataset_sha256": dataset_sha,
        "results": results,
        "final_test_scored": False,
        "thresholds_changed": False,
        "models_activated": False,
        "original_files_modified": False,
        "interpretation": "Profiles are retrospective validation tradeoffs, not approved new thresholds. The previously inspected test is no longer unseen for future changes.",
    }


def run(dataset, original_report, directory):
    if directory.exists() or directory.is_symlink():
        raise FileExistsError("Choose a fresh diagnostics folder")
    result = diagnose(dataset, original_report)
    directory.mkdir(parents=True, mode=0o700)
    directory.chmod(0o700)
    output = directory / "diagnostics.json"
    with output.open("x") as file:
        json.dump(result, file, indent=2, sort_keys=True, allow_nan=False)
        file.write("\n")
    output.chmod(0o600)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--directory", required=True, type=Path)
    args = parser.parse_args()
    if os.geteuid() == 0:
        parser.exit(2, "STOP: Run as vidar, not root.\n")
    try:
        result = run(args.dataset, args.report, args.directory)
    except (OSError, ValueError, KeyError, TypeError, RuntimeError) as exc:
        parser.exit(1, f"STOP: Private diagnostics failed: {exc}\n")
    for name, detail in result["results"].items():
        print(f"\n=== {name.upper()} ===")
        print("Status:", detail["original_status"])
        print(
            "Selected/default thresholds:",
            detail["selected_threshold"],
            detail["default_threshold"],
        )
        for profile, values in detail["profiles"].items():
            syn = values["synthetic_validation"]
            real = values["real_validation"]
            print(
                f"{profile}: TP={syn['tp']}/{syn['tp'] + syn['fn']} "
                f"synthetic-FP={syn['fp']}/{syn['fp'] + syn['tn']} "
                f"real-flags={real['confirmed_flag_positions']}/{real['provisional_normal_positions']}"
            )
        print("Confirmation-score distributions:")
        for label, values in detail["score_distributions"].items():
            print(label, values)
        print(
            "Unsplit features:",
            [f for f, values in detail["feature_coverage"].items() if values["tree_splits"] == 0],
        )
    print("\nValidation-only diagnostics. Existing thresholds and files unchanged.")
    print("Private diagnostics:", args.directory / "diagnostics.json")


if __name__ == "__main__":
    main()
