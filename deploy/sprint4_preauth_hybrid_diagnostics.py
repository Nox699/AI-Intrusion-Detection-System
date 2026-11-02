#!/usr/bin/env python3
"""Read-only hybrid-vs-rules analysis of the EXISTING synthetic preauth lab.

Retrospective diagnostics only: does not tune thresholds, change training
data, create models, touch production SQLite or send network requests.
Reads and validates the previously generated input manifest and model.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from sprint4_preauth_ml_lab import _load
from sprint4_preauth_signal_audit import classify
from yggdrasil_ids.preauth_ml import PreauthIsolationForest, connections_from_records, feature_rows

METHODS = ("ml", "rules", "hybrid")
COUNTS = ("tp", "fp", "tn", "fn")


def _metric(expected: list[bool], detected: list[bool]) -> dict[str, Any]:
    if len(expected) != len(detected):
        raise ValueError("Mismatched labels and observations")
    tp = sum(a and b for a, b in zip(expected, detected, strict=True))
    fp = sum(not a and b for a, b in zip(expected, detected, strict=True))
    tn = sum(not a and not b for a, b in zip(expected, detected, strict=True))
    fn = sum(a and not b for a, b in zip(expected, detected, strict=True))
    return {
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "total": len(expected),
        "precision": tp / (tp + fp) if tp + fp else None,
        "recall": tp / (tp + fn) if tp + fn else None,
        "false_positive_rate": fp / (fp + tn) if fp + tn else None,
    }


def analyse(directory: Path) -> dict[str, Any]:
    """Never writes files, never retrains and never adjusts a detector."""
    data, labels = _load(directory)
    report = json.loads((directory / "report.json").read_text(encoding="utf-8"))
    if report.get("kind") != "synthetic_preauth_isolation_forest_lab":
        raise ValueError("Unexpected lab report format")
    model = PreauthIsolationForest.load(directory / "preauth-lab-model.json")
    if model.version != report["model"]["version"]:
        raise ValueError("Model version differs from saved laboratory report")
    if model.threshold != report["model"]["threshold"]:
        raise ValueError("Model threshold differs from saved laboratory report")

    results: dict[str, Any] = {
        "kind": "retrospective_synthetic_preauth_hybrid_diagnostics",
        "model_version": model.version,
        "model_retrained": False,
        "original_threshold_unchanged": True,
        "test_set_is_no_longer_unseen": True,
        "production_ids_changed": False,
        "evaluation_unit": "one_correlated_preauth_connection",
        "interpretation": (
            "Synthetic data and scenario labels only; a surge of disconnects "
            "is not proof of an attack. Combined OR detection is a retrospective "
            "description, not a validated new production detector."
        ),
    }

    for split in ("validation", "test"):
        conns = connections_from_records(data[split], classify)
        vectors = feature_rows(conns)
        by_cursor = {item["cursor"]: item for item in labels["split_labels"][split]}
        expected: list[bool] = []
        detected: dict[str, list[bool]] = {key: [] for key in METHODS}
        groups: dict[str, dict[str, Any]] = {}

        for conn, row in zip(conns, vectors, strict=True):
            intent = by_cursor[conn.cursor]
            suspicious = intent["expected"] == "simulated_suspicious"
            ml_flag = model.score(row)["is_anomaly"]
            connections, invalid, distinct, disconnect = row[:4]
            rule_flag = bool(
                invalid >= 5 or distinct >= 4 or disconnect >= 10 or connections >= 12
            )
            flags = {"ml": ml_flag, "rules": rule_flag, "hybrid": ml_flag or rule_flag}
            expected.append(suspicious)
            for method, flag in flags.items():
                detected[method].append(flag)

            name = intent["scenario"]
            group = groups.setdefault(
                name,
                {
                    "scenario": name,
                    "expected": intent["expected"],
                    "connections": 0,
                    "first_detection_at": {method: None for method in METHODS},
                },
            )
            if group["expected"] != intent["expected"]:
                raise ValueError("Scenario labels disagree within the same scenario")
            group["connections"] += 1
            for method, flag in flags.items():
                if flag and group["first_detection_at"][method] is None:
                    group["first_detection_at"][method] = group["connections"]

        totals = {method: _metric(expected, detected[method]) for method in METHODS}
        # Guard against accidentally changing the old scoring algorithm.
        for method in ("ml", "rules"):
            for key in (*COUNTS, "total"):
                if totals[method][key] != report[split][method][key]:
                    raise ValueError(f"Historical {split} {method} counts changed")
        if len(conns) != report[split]["connection_candidates"]:
            raise ValueError("Historical correlated-connection counts changed")

        suspicious_groups = [
            group for group in groups.values() if group["expected"] == "simulated_suspicious"
        ]
        normal_groups = [group for group in groups.values() if group["expected"] == "normal"]
        scenario_recall = {}
        for method in METHODS:
            detected_groups = sum(
                group["first_detection_at"][method] is not None for group in suspicious_groups
            )
            normal_flagged = sum(
                group["first_detection_at"][method] is not None for group in normal_groups
            )
            scenario_recall[method] = {
                "suspicious_scenarios_detected": detected_groups,
                "suspicious_scenarios_total": len(suspicious_groups),
                "normal_scenarios_flagged": normal_flagged,
                "normal_scenarios_total": len(normal_groups),
            }

        results[split] = {
            "connection_candidates": len(conns),
            "connections_with_disconnected_equal_to_count": sum(
                a[0] == a[3] for a in vectors
            ),
            "metrics": totals,
            "scenario_coverage": scenario_recall,
            "scenarios": list(groups.values()),
        }
    return results


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("lab_directory", type=Path, help="Existing private synthetic lab directory")
    args = parser.parse_args(argv)
    directory = args.lab_directory.expanduser().resolve()
    result = analyse(directory)
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
