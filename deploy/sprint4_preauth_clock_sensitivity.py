#!/usr/bin/env python3
"""Read-only time-of-day sensitivity check for the EXISTING synthetic preauth model.

Counterfactual analysis: rotate only hour_sin/hour_cos by fixed UTC-hour
offsets. Keep all connection features, model, threshold, source histories and
scenario labels unchanged. This is NOT an independent test or production IDS.
Does not train a model, write files, or issue SSH/network requests.
"""

from __future__ import annotations

import argparse
import json
import math
from collections import defaultdict
from pathlib import Path
from typing import Any

from sprint4_preauth_ml_lab import _load
from sprint4_preauth_signal_audit import classify

from yggdrasil_ids.preauth_ml import (
    FEATURE_NAMES,
    PreauthIsolationForest,
    connections_from_records,
    feature_rows,
)

SHIFTS_HOURS = (0, 6, 12, 18)


def shift_clock(row: list[float], hours: int) -> list[float]:
    """Rotate hour-of-day cyclic features without altering behavioral evidence."""
    if len(row) != len(FEATURE_NAMES) or tuple(FEATURE_NAMES[-2:]) != (
        "hour_sin",
        "hour_cos",
    ):
        raise ValueError("Unexpected preauth feature schema")
    if hours not in SHIFTS_HOURS:
        raise ValueError("Unsupported clock shift")
    radians = 2 * math.pi * hours / 24
    sine, cosine = row[-2:]
    return [
        *row[:-2],
        sine * math.cos(radians) + cosine * math.sin(radians),
        cosine * math.cos(radians) - sine * math.sin(radians),
    ]


def counts(expected: list[bool], predictions: list[bool]) -> dict[str, int]:
    if len(expected) != len(predictions):
        raise ValueError("Mismatched synthetic labels")
    return {
        "tp": sum(a and b for a, b in zip(expected, predictions, strict=True)),
        "fp": sum(not a and b for a, b in zip(expected, predictions, strict=True)),
        "tn": sum(not a and not b for a, b in zip(expected, predictions, strict=True)),
        "fn": sum(a and not b for a, b in zip(expected, predictions, strict=True)),
    }


def analyse(directory: Path) -> dict[str, Any]:
    records, labels = _load(directory)
    report = json.loads((directory / "report.json").read_text(encoding="utf-8"))
    if report.get("kind") != "synthetic_preauth_isolation_forest_lab":
        raise ValueError("Unexpected synthetic lab report")
    model = PreauthIsolationForest.load(directory / "preauth-lab-model.json")
    if (
        model.version != report["model"]["version"]
        or model.threshold != report["model"]["threshold"]
    ):
        raise ValueError("Saved model and original lab report disagree")

    result: dict[str, Any] = {
        "kind": "retrospective_synthetic_preauth_clock_sensitivity",
        "model_version": model.version,
        "evaluation_unit": "one_correlated_preauth_connection",
        "shifted_features": ["hour_sin", "hour_cos"],
        "unchanged_features": list(FEATURE_NAMES[:-2]),
        "clock_shifts_hours": list(SHIFTS_HOURS),
        "model_retrained": False,
        "threshold_changed": False,
        "files_written": False,
        "production_ids_changed": False,
        "test_set_is_no_longer_unseen": True,
        "interpretation": (
            "Artificial time-of-day shifts on previously inspected SYNTHETIC "
            "scenarios; sensitivity is not evidence of real-world detection "
            "quality. No source history, labels, threshold or model were changed."
        ),
    }
    for split in ("validation", "test"):
        conn = connections_from_records(records[split], classify)
        rows = feature_rows(conn)
        label_map = {item["cursor"]: item for item in labels["split_labels"][split]}
        intent = [label_map[item.cursor] for item in conn]
        expected = [item["expected"] == "simulated_suspicious" for item in intent]
        baseline = [model.score(row)["is_anomaly"] for row in rows]
        original = counts(expected, baseline)
        for key, value in original.items():
            if value != report[split]["ml"][key]:
                raise ValueError(f"Historical {split} ML {key} does not match")
        if len(conn) != report[split]["connection_candidates"]:
            raise ValueError("Historical connection count changed")

        offsets = {}
        for hours in SHIFTS_HOURS:
            if hours == 0:
                predictions = baseline
            else:
                predictions = [model.score(shift_clock(row, hours))["is_anomaly"] for row in rows]
            first_by_scenario: dict[str, int | None] = {}
            scenario_index: dict[str, int] = defaultdict(int)
            for item, flag in zip(intent, predictions, strict=True):
                scenario = item["scenario"]
                scenario_index[scenario] += 1
                if scenario not in first_by_scenario:
                    first_by_scenario[scenario] = None
                if flag and first_by_scenario[scenario] is None:
                    first_by_scenario[scenario] = scenario_index[scenario]

            offsets[str(hours)] = {
                "ml": counts(expected, predictions),
                "ml_decisions_changed_from_original": sum(
                    current != old for current, old in zip(predictions, baseline, strict=True)
                ),
                "first_detection_by_scenario": first_by_scenario,
            }
        result[split] = {
            "connection_candidates": len(conn),
            "offsets": offsets,
        }
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("lab_directory", type=Path)
    args = parser.parse_args(argv)
    result = analyse(args.lab_directory.expanduser().resolve())
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
