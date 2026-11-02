#!/usr/bin/env python3
"""Verify independent synthetic lab evaluation without revealing per-event logs.

This is a verifier of documented laboratory evidence, not a new detector,
live trainer or production-accuracy benchmark.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import sys
from pathlib import Path

SPLITS = ("train", "validation", "test")
FIELDS = ("tp", "fp", "tn", "fn")
MAX_BYTES = 16 * 1024 * 1024


def load_json(path: Path) -> dict:
    if not path.is_file() or path.stat().st_size > MAX_BYTES:
        raise ValueError("Lab report missing or oversized")
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("Unexpected report structure")
    return data


def checked_hash(path: Path, expected: str) -> None:
    if not path.is_file() or not 0 < path.stat().st_size <= MAX_BYTES:
        raise ValueError("Input artifact missing or oversized")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if len(expected) != 64 or digest != expected:
        raise ValueError("Input artifact SHA-256 does not match lab report")


def metric(numerator: int, denominator: int) -> float | None:
    return numerator / denominator if denominator else None


def check_metrics(actual: dict, records: list[dict], method: str) -> dict:
    for row in records:
        if type(row.get("expected_positive")) is not bool or type(row.get(method)) is not bool:
            raise ValueError("Missing or nonboolean held-out label/prediction")
    counts = {
        "tp": sum(row["expected_positive"] and row[method] for row in records),
        "fp": sum(not row["expected_positive"] and row[method] for row in records),
        "tn": sum(not row["expected_positive"] and not row[method] for row in records),
        "fn": sum(row["expected_positive"] and not row[method] for row in records),
    }
    if any(type(actual.get(key)) is not int or actual[key] != counts[key] for key in FIELDS):
        raise ValueError("Confusion matrix differs from observed held-out labels")
    tp, fp, tn, fn = (counts[key] for key in FIELDS)
    expected = {
        "precision": metric(tp, tp + fp),
        "recall": metric(tp, tp + fn),
        "false_positive_rate": metric(fp, fp + tn),
    }
    if actual.get("total") != len(records):
        raise ValueError("Held-out total does not match observation count")
    if actual.get("expected_positive") != tp + fn or actual.get("predicted_positive") != tp + fp:
        raise ValueError("Prediction/label totals do not match confusion matrix")
    for name, value in expected.items():
        candidate = actual.get(name)
        if value is None and candidate is not None:
            raise ValueError("Undefined metric must remain null")
        if value is not None and (
            type(candidate) not in (int, float) or
            not math.isfinite(candidate) or not math.isclose(candidate, value, abs_tol=1e-10)
        ):
            raise ValueError("Reported evaluation metric does not match confusion matrix")
    return {**counts, **expected, "total": len(records)}


def verify(directory: Path) -> dict:
    report = load_json(directory / "report.json")
    if report.get("kind") != "synthetic_laboratory":
        raise ValueError("Only synthetic laboratory reports may be verified")
    if report.get("observation_unit") != "one_accepted_or_failed_authentication":
        raise ValueError("Unexpected observation unit")
    splits = report["splits"]
    labels_path = directory / "labels.json"
    checked_hash(labels_path, report["labels_sha256"])
    labels = load_json(labels_path)
    label_sets = labels["splits"]
    all_cursors: set[str] = set()
    for split in SPLITS:
        info = splits[split]
        checked_hash(directory / f"{split}.jsonl", info["sha256"])
        if not 0 < info["event_count"] <= 10000:
            raise ValueError("Lab split size must be bounded")
        if not info["first_timestamp"] < info["last_timestamp"]:
            raise ValueError("Lab split has no valid time span")
        items = label_sets[split]
        if not isinstance(items, list) or len(items) != info["event_count"]:
            raise ValueError("Labels and report split size differ")
        cursors = {item["cursor"] for item in items}
        if len(cursors) != len(items) or cursors.intersection(all_cursors):
            raise ValueError("Dataset leakage or duplicate event cursors")
        all_cursors.update(cursors)
        if split == "train" and any(item.get("expected") != "normal" for item in items):
            raise ValueError("Train split contains suspicious test labels")

    window = report["settings"]["ml"]["window_seconds"]
    for earlier, later in (("train", "validation"), ("validation", "test")):
        if splits[later]["first_timestamp"] - splits[earlier]["last_timestamp"] <= 2 * window:
            raise ValueError("Training/validation/test split time leakage")
    model = report["model"]
    if model["sample_count"] != splits["train"]["event_count"]:
        raise ValueError("Model sample count and training split disagree")
    if model["window_seconds"] != window:
        raise ValueError("Model window and lab settings disagree")
    model_artifact = load_json(directory / "lab-model.json")
    if model_artifact.get("fingerprint") != model.get("fingerprint"):
        raise ValueError("Model fingerprint differs from lab evaluation")
    if len(model_artifact.get("training_rows", [])) != model["sample_count"]:
        raise ValueError("Model training-row count disagrees with split")
    if model["sample_count"] < report["settings"]["ml"]["min_samples"]:
        raise ValueError("Model lacks minimum training observations")

    output = {
        "kind": "verified_synthetic_lab_only",
        "production_model_activated": False,
        "training_rows": model["sample_count"],
        "model_version": model["version"],
        "window_seconds": window,
        "splits": {
            key: {"events": splits[key]["event_count"], "sha256": splits[key]["sha256"]}
            for key in SPLITS
        },
        "comparisons": {},
        "warning": (
            "Synthetic scenarios, not production labels or estimates of real-world "
            "detection/false-positive rates."
        ),
    }
    for split in ("validation", "test"):
        result = report[split]
        rows = result["observations"]
        if len(rows) != splits[split]["event_count"]:
            raise ValueError("Held-out observation count does not match split")
        for method, field in (("rules", "rule_alarm"), ("ml", "ml_alarm")):
            output["comparisons"].setdefault(split, {})[method] = check_metrics(
                result[method], rows, field
            )
    return output


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        summary = verify(args.directory)
    except (OSError, ValueError, KeyError, TypeError, IndexError) as exc:
        print(f"Lab verification failed ({type(exc).__name__}); no files modified.", file=sys.stderr)
        return 1
    print(json.dumps(summary, indent=2, sort_keys=True, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
