#!/usr/bin/env python3
"""Compare synthetic/real/mixed normal training on a private sudo export.

An offline experiment with chronological real splits and a frozen two-hit alert
policy. Test data never participates in fitting, sampling or calibration. Real
normal labels remain provisional. No journal, production model or notifier is
accessed; the only real input is the user's existing pseudonymized JSON export.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
from collections import defaultdict, deque
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

import numpy as np
import sklearn
from sklearn.ensemble import IsolationForest
from sprint5_sudo_ml_lab import NORMAL, SUSPICIOUS, create_splits, scenario
from sprint5_sudo_ml_v2_lab import custom_case, original_rule, simple_long_rule

from yggdrasil_ids.sudo_ml import FEATURE_NAMES, SudoAttempt, attempts_from_signals, feature_rows

TZ = ZoneInfo("Europe/Copenhagen")
VALIDATION_START = datetime(2026, 11, 2, tzinfo=TZ).timestamp()
TEST_START = datetime(2026, 11, 3, tzinfo=TZ).timestamp()
TEST_END = datetime(2026, 11, 4, tzinfo=TZ).timestamp()
GAP = 900
FPR_BUDGET = 0.05
MODES = ("synthetic", "real", "mixed")
CONTROLLED_START = datetime(2026, 11, 3, 13, 15, tzinfo=TZ).timestamp()
CONTROLLED_END = datetime(2026, 11, 3, 13, 20, tzinfo=TZ).timestamp()
PROTOCOL = {
    "features": list(FEATURE_NAMES[:5]),
    "feature_window_seconds": 300,
    "clock_features": False,
    "real_splits": {
        "training": "before 2026-11-02 Europe/Copenhagen",
        "validation": "2026-11-02 Europe/Copenhagen",
        "test": "2026-11-03 Europe/Copenhagen",
    },
    "purge_seconds_each_side_of_split": GAP,
    "training": "provisional normal candidates only; same row budget for all models",
    "mixed_ratio": "approximately 50% real / 50% synthetic; no duplicated observations",
    "forest": {
        "n_estimators": 128,
        "random_state": 42,
        "n_jobs": 1,
        "max_samples": "min(256, common training row budget)",
        "contamination": 0.03,
    },
    "confirmation": "two consecutive anomalous processes in the same group within 900s",
    "calibration": "maximize synthetic validation scenario recall under BOTH real-position and synthetic-scenario FPR budgets",
    "validation_fpr_budget": FPR_BUDGET,
    "calibration_tie_break": "fewer real flags, fewer synthetic false positives, higher threshold",
    "fresh_synthetic_seeds": "normal 120000..120499; suspicious 130000/131000/132000/133000 + 0..99",
    "controlled_real_test": "three same-group failures, 2026-11-03 13:15..13:20 local; evaluated only after calibration",
    "labels": "real normal candidates are not verified; real review events are not automatically attacks",
    "metrics": "real confirmed flags per provisional-normal process position; synthetic TP/FP per complete scenario",
    "limitations": "correlated windows and short real history; fresh seeds reuse known synthetic families",
}


def sha256(payload):
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    ).hexdigest()


def load_export(path):
    path = Path(path)
    if path.stat().st_size > 10_000_000:
        raise ValueError("Private export exceeds 10 MB bound")
    payload = json.loads(path.read_text())
    if payload.get("format") != "sudo-process-candidates-v1":
        raise ValueError("Unsupported real export format")
    rows = payload.get("processes")
    if not isinstance(rows, list) or not 1 <= len(rows) <= 10000:
        raise ValueError("Expected 1..10000 process candidates")
    if payload.get("process_count") != len(rows):
        raise ValueError("Inconsistent process count")
    previous = -1
    for row in rows:
        if not isinstance(row, dict) or set(row) != {
            "timestamp",
            "group",
            "outcome",
            "also_had_success",
            "normal_candidate",
        }:
            raise ValueError("Unexpected exported process fields")
        timestamp = row["timestamp"]
        if (
            type(timestamp) not in (float, int)
            or not math.isfinite(timestamp)
            or not 0 <= timestamp < 4_102_444_800
            or timestamp < previous
        ):
            raise ValueError("Invalid or unordered process time")
        previous = timestamp
        if type(row["group"]) is not int or not 1 <= row["group"] <= 2**32 - 1:
            raise ValueError("Invalid pseudonymous group")
        if row["outcome"] not in {"success", "failure", "denied"}:
            raise ValueError("Unknown exported outcome")
        if type(row["normal_candidate"]) is not bool or type(row["also_had_success"]) is not bool:
            raise ValueError("Invalid candidate flags")
        if row["normal_candidate"] and row["outcome"] != "success":
            raise ValueError("Failed/denied process cannot be normal training candidate")
    return rows, sha256(payload)


def split_real(rows):
    splits = {name: [] for name in ("training", "validation", "test")}
    excluded = 0
    for row in rows:
        t = row["timestamp"]
        if t < VALIDATION_START - GAP:
            splits["training"].append(row)
        elif VALIDATION_START + GAP <= t < TEST_START - GAP:
            splits["validation"].append(row)
        elif TEST_START + GAP <= t < TEST_END:
            splits["test"].append(row)
        else:
            excluded += 1
    return splits, excluded


def real_bundle(rows):
    # Identity values are export-local synthetic identifiers and never model features.
    attempts = [
        SudoAttempt(row["timestamp"], "b" * 32, str(row["group"]), i + 1, row["outcome"])
        for i, row in enumerate(rows)
    ]
    values = [row[:5] for row in feature_rows(attempts)]
    return attempts, values


def confirmation_values(attempts, scores):
    if len(attempts) != len(scores):
        raise ValueError("Mismatched score stream")
    windows = defaultdict(lambda: deque(maxlen=2))
    values = []
    for attempt, score in zip(attempts, scores, strict=True):
        window = windows[(attempt.boot_id, attempt.uid)]
        window.append((attempt.timestamp, float(score)))
        values.append(
            min(value for _, value in window)
            if len(window) == 2 and attempt.timestamp - window[0][0] < GAP
            else None
        )
    return values


def scenario_bundle(item):
    attempts = attempts_from_signals(item.signals)
    return attempts, [row[:5] for row in feature_rows(attempts)]


def synthetic_evidence(model, cases, require_confirmation=True):
    bundles = [scenario_bundle(item) for item in cases]
    flat = [row for _, rows in bundles for row in rows]
    scores = -model.score_samples(flat)
    values = []
    offset = 0
    for attempts, rows in bundles:
        part = scores[offset : offset + len(rows)]
        stream = confirmation_values(attempts, part) if require_confirmation else part
        confirmed = [float(value) for value in stream if value is not None]
        values.append(max(confirmed) if confirmed else None)
        offset += len(rows)
    return values


def flags(values, threshold):
    return [value is not None and value > threshold for value in values]


def scenario_metrics(cases, decisions):
    positive = sum(item.suspicious for item in cases)
    negative = len(cases) - positive
    tp = sum(item.suspicious and flag for item, flag in zip(cases, decisions, strict=True))
    fp = sum(not item.suspicious and flag for item, flag in zip(cases, decisions, strict=True))
    return {
        "tp": int(tp),
        "fp": int(fp),
        "tn": int(negative - fp),
        "fn": int(positive - tp),
        "recall": tp / positive if positive else None,
        "false_positive_rate": fp / negative if negative else None,
    }


def real_metrics(rows, raw_scores, evidence, threshold):
    normal = [i for i, row in enumerate(rows) if row["normal_candidate"]]
    confirmed = flags(evidence, threshold)
    raw_count = sum(raw_scores[i] > threshold for i in normal)
    confirmed_count = sum(confirmed[i] for i in normal)
    return {
        "provisional_normal_positions": len(normal),
        "raw_anomaly_positions": int(raw_count),
        "confirmed_flag_positions": int(confirmed_count),
        "provisional_confirmed_false_positive_rate": confirmed_count / len(normal)
        if normal
        else None,
        "confirmed_flags_on_review_positions": sum(
            confirmed[i] for i, row in enumerate(rows) if not row["normal_candidate"]
        ),
        "unit": "process position, not emitted alarms or independent scenarios",
    }


def training_sets(real_rows, synthetic_rows):
    count = min(len(real_rows), len(synthetic_rows))
    if count < 80:
        raise ValueError("Need at least 80 real normal training candidates before November 2")
    rng = np.random.default_rng(42)

    def sample(rows, n):
        indices = sorted(rng.choice(len(rows), size=n, replace=False).tolist())
        return [rows[i] for i in indices]

    return {
        "synthetic": sample(synthetic_rows, count),
        "real": sample(real_rows, count),
        "mixed": sample(real_rows, (count + 1) // 2) + sample(synthetic_rows, count // 2),
    }


def calibrate(model, validation_rows, validation_cases):
    attempts, matrix = real_bundle(validation_rows)
    raw = -model.score_samples(matrix)
    real_values = confirmation_values(attempts, raw)
    synthetic_values = synthetic_evidence(model, validation_cases)
    candidates = {float(-model.offset_)}
    for value in [*real_values, *synthetic_values]:
        if value is not None:
            candidates.update((float(value), float(np.nextafter(value, -np.inf))))
    choices = []
    for threshold in candidates:
        real = real_metrics(validation_rows, raw, real_values, threshold)
        synthetic = scenario_metrics(validation_cases, flags(synthetic_values, threshold))
        if (
            real["provisional_confirmed_false_positive_rate"] <= FPR_BUDGET
            and synthetic["false_positive_rate"] <= FPR_BUDGET
        ):
            choices.append((threshold, real, synthetic))
    if not choices:
        raise RuntimeError("No calibration threshold meets declared validation budgets")
    threshold, real, synthetic = min(
        choices, key=lambda c: (-c[2]["tp"], c[1]["confirmed_flag_positions"], c[2]["fp"], -c[0])
    )
    return {
        "threshold": threshold,
        "real_validation": real,
        "synthetic_validation": synthetic,
        "thresholds_examined": len(candidates),
    }


def fresh_test_cases():
    cases = [scenario(NORMAL[i % len(NORMAL)], 120000 + i) for i in range(500)]
    for index, category in enumerate(SUSPICIOUS):
        cases.extend(scenario(category, 130000 + index * 1000 + i) for i in range(100))
    return cases


def evaluate_synthetic(model, cases, threshold):
    ml = flags(synthetic_evidence(model, cases), threshold)
    rules = [original_rule(item) for item in cases]
    return {
        "raw_ml": scenario_metrics(
            cases, flags(synthetic_evidence(model, cases, require_confirmation=False), threshold)
        ),
        "ml_with_confirmation": scenario_metrics(cases, ml),
        "original_rules": scenario_metrics(cases, rules),
        "rules_or_ml": scenario_metrics(cases, [a or b for a, b in zip(ml, rules, strict=True)]),
        "simple_long_rule": scenario_metrics(cases, [simple_long_rule(item) for item in cases]),
        "ml_only_suspicious_scenarios": sum(
            item.suspicious and a and not b for item, a, b in zip(cases, ml, rules, strict=True)
        ),
    }


def evaluate_real(model, rows, threshold):
    attempts, matrix = real_bundle(rows)
    raw = -model.score_samples(matrix)
    values = confirmation_values(attempts, raw)
    report = real_metrics(rows, raw, values, threshold)
    indices = [
        i
        for i, row in enumerate(rows)
        if row["outcome"] == "failure" and CONTROLLED_START <= row["timestamp"] < CONTROLLED_END
    ]
    matched = len(indices) == 3 and len({rows[i]["group"] for i in indices}) == 1
    confirmed = flags(values, threshold)
    report["controlled_three_failure_probe"] = {
        "matched_expected_test_window": matched,
        "matched_failure_processes": len(indices),
        "pattern_detected": any(confirmed[i] for i in indices) if matched else None,
        "raw_anomaly_processes": int(sum(raw[i] > threshold for i in indices)) if matched else None,
        "confirmed_process_positions": sum(confirmed[i] for i in indices) if matched else None,
        "used_for_training_or_calibration": False,
    }
    return report


def experiment(rows, dataset_sha):
    splits, excluded = split_real(rows)
    counts = {name: sum(row["normal_candidate"] for row in part) for name, part in splits.items()}
    if counts["validation"] < 40 or counts["test"] < 40:
        raise ValueError(
            "Need at least 40 provisional normal positions in each validation/test day"
        )
    _, real_matrix = real_bundle(splits["training"])
    real_normal = [
        vector
        for row, vector in zip(splits["training"], real_matrix, strict=True)
        if row["normal_candidate"]
    ]
    synthetic_training, synthetic_validation, _ = create_splits()
    synthetic_matrix = [row for item in synthetic_training for row in scenario_bundle(item)[1]]
    sets = training_sets(real_normal, synthetic_matrix)
    models = {}
    calibrations = {}
    training_reports = {}
    recipes = {}
    for name in MODES:
        matrix = np.asarray(sets[name], dtype=float)
        model = IsolationForest(
            n_estimators=128,
            random_state=42,
            n_jobs=1,
            contamination=0.03,
            max_samples=min(256, len(matrix)),
        ).fit(matrix)
        models[name] = model
        calibrations[name] = calibrate(model, splits["validation"], synthetic_validation)
        training_reports[name] = {
            "rows": len(matrix),
            "real_rows": len(matrix)
            if name == "real"
            else (len(matrix) + 1) // 2
            if name == "mixed"
            else 0,
            "synthetic_rows": len(matrix)
            if name == "synthetic"
            else len(matrix) // 2
            if name == "mixed"
            else 0,
            "unique_feature_vectors": len(np.unique(matrix, axis=0)),
            "training_matrix_sha256": sha256(matrix.tolist()),
            "constant_features": [
                feature
                for feature, span in zip(FEATURE_NAMES[:5], np.ptp(matrix, axis=0), strict=True)
                if span == 0
            ],
        }
        recipes[name] = {
            "format": "sudo-mixed-research-recipe-v1",
            "deployable": False,
            "normal_training_rows": matrix.tolist(),
            "threshold": calibrations[name]["threshold"],
            "sklearn_version": sklearn.__version__,
            "forest_parameters": {
                "n_estimators": 128,
                "random_state": 42,
                "n_jobs": 1,
                "contamination": 0.03,
                "max_samples": min(256, len(matrix)),
            },
            "features": list(FEATURE_NAMES[:5]),
            "confirmation_seconds": GAP,
            "required_consecutive": 2,
        }
    # Freeze ALL models and thresholds before constructing/scoring final cases.
    selection_sha = sha256(
        {"protocol": PROTOCOL, "training": training_reports, "calibration": calibrations}
    )
    final_cases = fresh_test_cases()
    challenges = [
        custom_case(
            "normal_corrected_double_typo",
            140000,
            [("failure", 0), ("success", 25), ("failure", 420), ("success", 450)],
        ),
        custom_case(
            "normal_successful_automation", 141000, [("success", i * 2) for i in range(30)]
        ),
    ]
    reports = {}
    for name in MODES:
        model = models[name]
        threshold = calibrations[name]["threshold"]
        reports[name] = {
            "training": training_reports[name],
            "calibration": calibrations[name],
            "real_test": evaluate_real(model, splits["test"], threshold),
            "fresh_synthetic_test": evaluate_synthetic(model, final_cases, threshold),
            "known_family_challenges": {
                case.category: flags(synthetic_evidence(model, [case]), threshold)[0]
                for case in challenges
            },
        }
    report = {
        "kind": "sudo_real_synthetic_mixed_research",
        "protocol": PROTOCOL,
        "dataset_sha256": dataset_sha,
        "selection_sha256": selection_sha,
        "real_split_counts": {
            name: {"all_processes": len(part), "normal_candidates": counts[name]}
            for name, part in splits.items()
        },
        "purged_or_outside_test_period": excluded,
        "results": reports,
        "normal_labels_verified": False,
        "source_sample_sizes_are_not_independent": True,
        "production_changes": False,
        "discord_messages_sent": 0,
    }
    return report, recipes


def run(path, directory):
    if directory.exists() or directory.is_symlink():
        raise FileExistsError("Choose a fresh output directory")
    rows, dataset_sha = load_export(path)
    report, recipes = experiment(rows, dataset_sha)
    directory.mkdir(parents=True, mode=0o700)
    directory.chmod(0o700)
    for name, value in (("report.json", report), ("research-recipes.json", recipes)):
        output = directory / name
        with output.open("x", encoding="utf-8") as file:
            json.dump(value, file, indent=2, sort_keys=True, allow_nan=False)
            file.write("\n")
        output.chmod(0o600)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", required=True, type=Path)
    parser.add_argument("--directory", required=True, type=Path)
    args = parser.parse_args()
    if os.geteuid() == 0:
        parser.exit(2, "STOP: Run the research as vidar, not root.\n")
    try:
        report = run(args.dataset, args.directory)
    except (OSError, ValueError, RuntimeError, KeyError, TypeError) as exc:
        parser.exit(1, f"STOP: Mixed-data research failed: {exc}\n")
    print("=== Kronologiske normal-kandidater ===")
    for split, values in report["real_split_counts"].items():
        print(split, values)
    for name, result in report["results"].items():
        print(f"\n=== {name.upper()} TRAINING ===")
        print("Training:", result["training"])
        real = result["real_test"]
        print(
            f"Real normal test: {real['confirmed_flag_positions']}/{real['provisional_normal_positions']} confirmed flags"
        )
        print("Controlled three-failure test:", real["controlled_three_failure_probe"])
        print("Fresh synthetic test:")
        for method, values in result["fresh_synthetic_test"].items():
            print(method, values)
        print("Known benign challenges flagged:", result["known_family_challenges"])
    print("\nNormal labels remain provisional. No operational detection rate is established.")
    print("No model activated. Private report:", args.directory / "report.json")


if __name__ == "__main__":
    main()
