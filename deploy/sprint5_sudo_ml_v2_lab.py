#!/usr/bin/env python3
"""Isolated synthetic sudo IF research: feature ablations and confirmed signals.

Fit on the original normal-only training set, select on development validation,
then evaluate a fresh-seed holdout ONCE. The historical test is descriptive only.
Neither raw sudo logs nor production models, databases, services or webhooks
are accessed. Two-hit confirmation is an alert policy, not an improved raw IF.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import platform
from collections import defaultdict, deque
from pathlib import Path

import numpy as np
import sklearn
from sklearn.ensemble import IsolationForest
from sprint5_sudo_ml_lab import NORMAL, SUSPICIOUS, Scenario, create_splits, scenario

from yggdrasil_ids.sudo_ml import attempts_from_signals, feature_rows
from yggdrasil_ids.sudo_rules import SudoRuleDetector, SudoSignal

VARIANTS = ("original_clock", "counts_300", "counts_300_900", "counts_300_900_gap")
CONFIRMATION_SECONDS = 900
VALIDATION_FPR_BUDGET = 0.05
RANDOM_STATE = 42
PROTOCOL = {
    "training": "original 180 normal scenarios, seeds 10000..10179",
    "validation": "original development validation; old test excluded from selection",
    "features": list(VARIANTS),
    "consecutive_anomalies": [1, 2],
    "confirmation_seconds": CONFIRMATION_SECONDS,
    "threshold_selection": "validation score breakpoints, maximum recall under FPR budget",
    "validation_fpr_budget": VALIDATION_FPR_BUDGET,
    "tie_break": "fewer FP, fewer features, fewer required observations, higher threshold",
    "forest": {"n_estimators": 128, "max_samples": 256, "random_state": RANDOM_STATE},
    "fresh_holdout": {
        "normal_seed_start": 70000,
        "normal_count": 500,
        "suspicious_seed_start": 80000,
        "per_suspicious_type": 100,
    },
    "stress": "50 benign corrected-double-typo and 50 benign successful-automation cases",
    "exploratory_notice": "Feature, sampling and confirmation ideas were explored on development data.",
    "limitations": "New seeds reuse the original synthetic generator, not unseen attack families.",
}


def digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    ).hexdigest()


def features(item: Scenario, variant: str) -> list[list[float]]:
    if variant not in VARIANTS:
        raise ValueError("Unknown feature variant")
    attempts = attempts_from_signals(item.signals)
    if variant == "original_clock":
        return feature_rows(attempts)
    windows = {seconds: defaultdict(deque) for seconds in (300, 900)}
    previous = {}
    result = []
    for attempt in attempts:
        group = (attempt.boot_id, attempt.uid)
        values = []
        periods = (300,) if variant == "counts_300" else (300, 900)
        for seconds in periods:
            window = windows[seconds][group]
            while window and window[0].timestamp <= attempt.timestamp - seconds:
                window.popleft()
            window.append(attempt)
            failed = sum(row.outcome == "failure" for row in window)
            denied = sum(row.outcome == "denied" for row in window)
            succeeded = len(window) - failed - denied
            values.extend([len(window), failed, denied, succeeded, (failed + denied) / len(window)])
        if variant == "counts_300_900_gap":
            gap = attempt.timestamp - previous.get(group, attempt.timestamp - 900)
            values.append(min(gap, 900) / 900)
        previous[group] = attempt.timestamp
        result.append([float(value) for value in values])
    return result


def evidence_score(attempts, scores, required: int) -> float | None:
    """Maximum minimum score of k consecutive same-group processes in 15min.

    This gives exactly the threshold decisions of a causal confirmation policy.
    An intervening normal process breaks a run. No future observation changes a
    previously computed score; a confirmed finding occurs at the last process.
    """
    if required not in (1, 2) or len(attempts) != len(scores):
        raise ValueError("Invalid confirmation input")
    recent = defaultdict(lambda: deque(maxlen=required))
    best = None
    for attempt, score in zip(attempts, scores, strict=True):
        score = float(score)
        if not math.isfinite(score):
            raise ValueError("Non-finite anomaly score")
        window = recent[(attempt.boot_id, attempt.uid)]
        window.append((attempt.timestamp, score))
        if len(window) == required and attempt.timestamp - window[0][0] < CONFIRMATION_SECONDS:
            value = min(row[1] for row in window)
            best = value if best is None else max(best, value)
    return best


def scored_cases(model, cases, variant):
    matrices = [features(item, variant) for item in cases]
    lengths = [len(rows) for rows in matrices]
    flat = [row for rows in matrices for row in rows]
    scores = -model.score_samples(flat)
    bundles = []
    offset = 0
    for item, length in zip(cases, lengths, strict=True):
        bundles.append((attempts_from_signals(item.signals), scores[offset : offset + length]))
        offset += length
    return bundles


def decisions(bundles, threshold, required):
    return [
        value is not None and value > threshold
        for value in (evidence_score(a, s, required) for a, s in bundles)
    ]


def metrics(cases, flags):
    if len(cases) != len(flags):
        raise ValueError("Mismatched evaluation lengths")
    tp = sum(item.suspicious and flag for item, flag in zip(cases, flags, strict=True))
    fp = sum(not item.suspicious and flag for item, flag in zip(cases, flags, strict=True))
    positive = sum(item.suspicious for item in cases)
    negative = len(cases) - positive
    return {
        "tp": int(tp),
        "fp": int(fp),
        "tn": int(negative - fp),
        "fn": int(positive - tp),
        "recall": tp / positive if positive else None,
        "false_positive_rate": fp / negative if negative else None,
    }


def original_rule(item):
    detector = SudoRuleDetector()
    # Evaluate the complete stream, even after a candidate.
    return any([detector.evaluate(row) is not None for row in item.signals])


def simple_long_rule(item):
    """Fair non-ML comparator: two consecutive failures/15min OR sudoers denial."""
    previous = {}
    for attempt in attempts_from_signals(item.signals):
        group = (attempt.boot_id, attempt.uid)
        if attempt.outcome == "denied":
            return True
        prior = previous.get(group)
        if (
            attempt.outcome == "failure"
            and prior is not None
            and prior.outcome == "failure"
            and attempt.timestamp - prior.timestamp < CONFIRMATION_SECONDS
        ):
            return True
        previous[group] = attempt
    return False


def select_candidate(training, validation):
    candidates = []
    fitted = {}
    for variant in VARIANTS:
        rows = [row for item in training for row in features(item, variant)]
        model = IsolationForest(
            n_estimators=128,
            max_samples=256,
            contamination=0.03,
            random_state=RANDOM_STATE,
            n_jobs=1,
        ).fit(rows)
        fitted[variant] = model
        bundles = scored_cases(model, validation, variant)
        for required in (1, 2):
            values = [
                value
                for value in (evidence_score(a, s, required) for a, s in bundles)
                if value is not None
            ]
            thresholds = {float(-model.offset_)}
            for value in values:
                thresholds.update((value, float(np.nextafter(value, -np.inf))))
            options = []
            for threshold in sorted(thresholds):
                result = metrics(validation, decisions(bundles, threshold, required))
                if result["false_positive_rate"] <= VALIDATION_FPR_BUDGET:
                    options.append(
                        {
                            "variant": variant,
                            "required_consecutive": required,
                            "threshold": threshold,
                            "feature_count": len(rows[0]),
                            "validation": result,
                            "thresholds_examined": len(thresholds),
                        }
                    )
            if not options:
                raise RuntimeError("No candidate meets the declared validation budget")
            candidates.append(sorted(options, key=selection_key)[0])
    selected = sorted(candidates, key=selection_key)[0]
    return selected, candidates, fitted


def selection_key(candidate):
    score = candidate["validation"]
    return (
        -score["tp"],
        score["fp"],
        candidate["feature_count"],
        candidate["required_consecutive"],
        -candidate["threshold"],
        candidate["variant"],
    )


def fresh_holdout():
    cases = [scenario(NORMAL[i % len(NORMAL)], 70000 + i) for i in range(500)]
    for index, category in enumerate(SUSPICIOUS):
        cases.extend(scenario(category, 80000 + index * 1000 + i) for i in range(100))
    return cases


def custom_case(category, seed, specs):
    template = scenario("normal_quiet", seed)
    start = template.signals[0].timestamp
    signals = []
    for i, (outcome, offset) in enumerate(specs, 1):
        kind = "pam_auth_failure" if outcome == "failure" else "command_invoked"
        signals.append(
            SudoSignal(
                f"stress-{seed}-{i}",
                start + offset,
                template.signals[0].boot_id,
                "1000",
                20000 + i,
                kind,
            )
        )
    return Scenario(category, False, seed, tuple(signals))


def stress_cases():
    cases = []
    for i in range(50):
        cases.append(
            custom_case(
                "normal_corrected_double_typo",
                90000 + i,
                [("failure", 0), ("success", 25), ("failure", 420), ("success", 450)],
            )
        )
        cases.append(
            custom_case(
                "normal_successful_automation", 91000 + i, [("success", j * 2) for j in range(30)]
            )
        )
    return cases


def evaluate(cases, baseline_model, selected_model, selected):
    baseline = decisions(
        scored_cases(baseline_model, cases, "original_clock"), float(-baseline_model.offset_), 1
    )
    candidate = decisions(
        scored_cases(selected_model, cases, selected["variant"]),
        selected["threshold"],
        selected["required_consecutive"],
    )
    rules = [original_rule(item) for item in cases]
    long_rule = [simple_long_rule(item) for item in cases]
    flags = {
        "original_if": baseline,
        "candidate_if_with_policy": candidate,
        "original_rules": rules,
        "original_hybrid": [a or b for a, b in zip(baseline, rules)],
        "candidate_hybrid": [a or b for a, b in zip(candidate, rules)],
        "simple_long_rule": long_rule,
    }
    return {
        "normal_scenarios": sum(not item.suspicious for item in cases),
        "suspicious_scenarios": sum(item.suspicious for item in cases),
        "metrics": {name: metrics(cases, values) for name, values in flags.items()},
        "scenarios": [
            {
                "type": item.category,
                "seed": item.seed,
                "suspicious_label": item.suspicious,
                **{name: bool(values[i]) for name, values in flags.items()},
            }
            for i, item in enumerate(cases)
        ],
    }


def dataset_hash(cases):
    return digest(
        [
            (
                item.category,
                item.suspicious,
                item.seed,
                [(s.timestamp, s.kind) for s in item.signals],
            )
            for item in cases
        ]
    )


def research():
    training, validation, historical = create_splits()
    selected, candidates, fitted = select_candidate(training, validation)
    # All selection is complete before constructing or scoring either holdout.
    selection_sha = digest({"protocol": PROTOCOL, "selected": selected})
    holdout = fresh_holdout()
    stress = stress_cases()
    splits = [training, validation, historical, holdout, stress]
    seeds = [item.seed for cases in splits for item in cases]
    if len(seeds) != len(set(seeds)):
        raise RuntimeError("Scenario seeds overlap between datasets")
    baseline = fitted["original_clock"]
    candidate = fitted[selected["variant"]]
    report = {
        "kind": "sudo_if_v2_synthetic_research",
        "synthetic_only": True,
        "protocol": PROTOCOL,
        "protocol_sha256": digest(PROTOCOL),
        "selection_sha256": selection_sha,
        "selection": selected,
        "candidate_validation_results": candidates,
        "versions": {
            "python": platform.python_version(),
            "sklearn": sklearn.__version__,
            "numpy": np.__version__,
        },
        "dataset_sha256": {
            name: dataset_hash(cases)
            for name, cases in zip(
                ("training", "validation", "historical", "fresh", "stress"), splits
            )
        },
        "training_normal_only": all(not item.suspicious for item in training),
        "historical_test_is_development_only": True,
        "confirmation_is_separate_alert_policy": True,
        "production_changes": False,
        "real_journal_rows_read": 0,
        "discord_messages_sent": 0,
        "validation": evaluate(validation, baseline, candidate, selected),
        "historical_test_descriptive_only": evaluate(historical, baseline, candidate, selected),
        "fresh_seed_holdout": evaluate(holdout, baseline, candidate, selected),
        "benign_stress_holdout": evaluate(stress, baseline, candidate, selected),
    }
    rows = [row for item in training for row in features(item, selected["variant"])]
    artifact = {
        "format": "sudo-if-v2-research-recipe-v1",
        "deployable": False,
        "protocol_sha256": report["protocol_sha256"],
        "selection": selected,
        "normal_training_rows": rows,
        "forest_parameters": PROTOCOL["forest"],
        "sklearn_version": sklearn.__version__,
    }
    artifact["sha256"] = digest(artifact)
    return report, artifact


def save_research(output: Path):
    if output.exists() or output.is_symlink():
        raise FileExistsError("Choose a fresh experiment directory")
    output.mkdir(parents=True, mode=0o700)
    output.chmod(0o700)
    report, artifact = research()
    for name, payload in (("report.json", report), ("research-recipe.json", artifact)):
        path = output / name
        with path.open("x", encoding="utf-8") as file:
            json.dump(payload, file, indent=2, sort_keys=True, allow_nan=False)
            file.write("\n")
        path.chmod(0o600)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", required=True, type=Path)
    args = parser.parse_args()
    if os.geteuid() == 0:
        parser.exit(2, "STOP: Run this isolated experiment as an unprivileged user.\n")
    try:
        report = save_research(args.directory)
    except (OSError, ValueError, RuntimeError) as exc:
        parser.exit(1, f"STOP: Isolated experiment failed: {type(exc).__name__}\n")
    print("Selected research candidate:", json.dumps(report["selection"], sort_keys=True))
    for split in (
        "validation",
        "historical_test_descriptive_only",
        "fresh_seed_holdout",
        "benign_stress_holdout",
    ):
        print(f"\n=== {split} ===")
        for method, values in report[split]["metrics"].items():
            print(
                f"{method}: TP={values['tp']} FP={values['fp']} TN={values['tn']} FN={values['fn']}"
            )
    print("\nSynthetic research only. Confirmation/calibration are separate from raw IF.")
    print("Research recipe is NOT a production model. No services or dashboards updated.")
    print(f"Private results: {args.directory}")


if __name__ == "__main__":
    main()
