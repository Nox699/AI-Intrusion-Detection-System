#!/usr/bin/env python3
"""Restore the original Sprint 5 model/schema/policy; vary normal data source.

Full seven-feature SudoIsolationForest, default threshold, any raw anomaly.
Previously inspected November 2 is development training data. November 3 is
never fitted, but its replay is retrospective, not an untouched final test.
This writes private original-format models for a future frozen-model probe;
it does not install or activate them.
"""

import argparse
import json
import os
import time
from pathlib import Path

import numpy as np
from sprint5_sudo_mixed_ml_lab import (
    CONTROLLED_END,
    CONTROLLED_START,
    GAP,
    TEST_END,
    TEST_START,
    load_export,
    real_bundle,
    sha256,
)
from sprint5_sudo_ml_lab import create_splits, evaluate, features_for_scenario
from sprint5_sudo_ml_v2_lab import custom_case

from yggdrasil_ids.sudo_ml import FEATURE_NAMES, SudoIsolationForest, feature_rows

MODES = ("synthetic_full", "real_full", "mixed_full")


def prepare(rows):
    training = [row for row in rows if row["timestamp"] < TEST_START - GAP]
    # Keep 300 seconds of unscored warm-up context before the replay boundary.
    replay = [row for row in rows if TEST_START + GAP - 300 <= row["timestamp"] < TEST_END]
    attempts, _ = real_bundle(training)
    matrix = feature_rows(attempts)
    normal = [
        values for row, values in zip(training, matrix, strict=True) if row["normal_candidate"]
    ]
    if len(normal) < 80:
        raise ValueError("At least 80 real normal development observations are required")
    if sum(row["normal_candidate"] and row["timestamp"] >= TEST_START + GAP for row in replay) < 40:
        raise ValueError("At least 40 retrospective normal observations are required")
    return normal, replay, training


def sources(real_normal):
    training, _, _ = create_splits()
    synthetic = [values for case in training for values in features_for_scenario(case)]
    return {
        "synthetic_full": synthetic,
        "real_full": real_normal,
        "mixed_full": [*real_normal, *synthetic],
    }


def real_replay(model, rows):
    attempts, _ = real_bundle(rows)
    scored = model.score_many(feature_rows(attempts))
    normal = [
        i
        for i, row in enumerate(rows)
        if row["normal_candidate"] and row["timestamp"] >= TEST_START + GAP
    ]
    raw = sum(scored[i]["is_anomaly"] for i in normal)
    matched = [
        i
        for i, row in enumerate(rows)
        if row["outcome"] == "failure" and CONTROLLED_START <= row["timestamp"] < CONTROLLED_END
    ]
    probe_matches = len(matched) == 3 and len({rows[i]["group"] for i in matched}) == 1
    return {
        "normal_candidate_positions": len(normal),
        "raw_flagged_positions": raw,
        "provisional_flag_rate": raw / len(normal),
        "controlled_probe_matched": probe_matches,
        "controlled_probe_flagged_processes": sum(scored[i]["is_anomaly"] for i in matched)
        if probe_matches
        else None,
        "controlled_probe_detected": any(scored[i]["is_anomaly"] for i in matched)
        if probe_matches
        else None,
        "unit": "process positions, not emitted alarms",
    }


def short_metrics(report):
    return {key: report[key] for key in ("ml", "rules", "normal_scenarios", "suspicious_scenarios")}


def workload_checks(model):
    # Known challenge families, not new unseen tests and never training data.
    cases = [
        custom_case("successful_activity_30", 160000, [("success", i * 2) for i in range(30)]),
        custom_case("successful_activity_60", 160001, [("success", i * 2) for i in range(60)]),
        custom_case("corrected_typo", 160002, [("failure", 0), ("success", 25)]),
    ]
    result = {}
    for case in cases:
        scored = model.score_many(features_for_scenario(case))
        result[case.category] = {
            "positions": len(scored),
            "flagged_positions": sum(row["is_anomaly"] for row in scored),
            "scenario_flagged": any(row["is_anomaly"] for row in scored),
        }
    return result


def run(dataset, directory):
    if directory.exists() or directory.is_symlink():
        raise FileExistsError("Choose a fresh private baseline folder")
    rows, fingerprint = load_export(dataset)
    real_normal, replay, training = prepare(rows)
    matrices = sources(real_normal)
    _, validation, historical = create_splits()
    directory.mkdir(parents=True, mode=0o700)
    directory.chmod(0o700)
    results = {}
    for name in MODES:
        matrix = matrices[name]
        model = SudoIsolationForest.train(
            matrix,
            f"Sprint5 baseline restoration: {name}; normal-only development through Nov2; "
            "default policy, no subsampling, retrospective replay only, not activated.",
        )
        path = directory / f"{name}-model.json"
        model.save(path)
        loaded = SudoIsolationForest.load(path)
        # Exercise the exact original loader and scorer before reporting results.
        if loaded.version != model.version or loaded.score(matrix[0]) != model.score(matrix[0]):
            raise RuntimeError("Original-format model round trip differs")
        values = np.asarray(matrix)
        results[name] = {
            "training_rows": len(matrix),
            "matrix_sha256": sha256(matrix),
            "real_rows": 0 if name == "synthetic_full" else len(real_normal),
            "synthetic_rows": 0 if name == "real_full" else len(matrices["synthetic_full"]),
            "feature_names": list(FEATURE_NAMES),
            "threshold": loaded.threshold,
            "constant_features": [
                name for name, span in zip(FEATURE_NAMES, np.ptp(values, axis=0)) if span == 0
            ],
            "validation_descriptive": short_metrics(evaluate(loaded, validation)),
            "historical_descriptive": short_metrics(evaluate(loaded, historical)),
            "real_replay_descriptive": real_replay(loaded, replay),
            "known_workload_checks": workload_checks(loaded),
            "model_file": path.name,
        }
    report = {
        "kind": "restored_sprint5_full_data_baseline",
        "dataset_sha256": fingerprint,
        "policy": "original seven features, default 3% training offset, any raw anomaly",
        "normal_candidates_verified": False,
        "subsampled": False,
        "threshold_calibrated_on_validation": False,
        "real_training_processes": len(training),
        "real_normal_training_rows": len(real_normal),
        "training_end_exclusive": TEST_START - GAP,
        "models_frozen_at": time.time(),
        "source_export_latest_timestamp": max(row["timestamp"] for row in rows),
        "previously_inspected_replays_are_not_unseen": True,
        "real_time_policy": "exporter's causal process evidence; original synthetic fixture timing retained",
        "source_sizes_differ": True,
        "production_changes": False,
        "models_activated": False,
        "next_requirement": "Freeze model before a new prospective normal and controlled suspicious probe.",
        "results": results,
    }
    path = directory / "report.json"
    with path.open("x") as file:
        json.dump(report, file, indent=2, sort_keys=True, allow_nan=False)
        file.write("\n")
    path.chmod(0o600)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, required=True)
    parser.add_argument("--directory", type=Path, required=True)
    args = parser.parse_args()
    if os.geteuid() == 0:
        parser.exit(2, "STOP: Run as vidar, not root.\n")
    try:
        report = run(args.dataset, args.directory)
    except (OSError, ValueError, RuntimeError, KeyError) as exc:
        parser.exit(1, f"STOP: Baseline restoration failed: {exc}\n")
    print("=== Original Sprint 5: seven features, full data, default threshold ===")
    print("Real normal development rows through November 2:", report["real_normal_training_rows"])
    for name, result in report["results"].items():
        print(f"\n=== {name.upper()} ===")
        print(
            "Training rows:",
            result["training_rows"],
            "real:",
            result["real_rows"],
            "synthetic:",
            result["synthetic_rows"],
        )
        print("Default threshold:", result["threshold"])
        print("Real retrospective replay:", result["real_replay_descriptive"])
        print("Original synthetic validation:", result["validation_descriptive"]["ml"])
        print("Original synthetic historical test:", result["historical_descriptive"]["ml"])
        print("Known normal workloads:", result["known_workload_checks"])
    print("\nDescriptive replay only; no new independent test claim. No model activated.")
    print("Private baseline folder:", args.directory)


if __name__ == "__main__":
    main()
