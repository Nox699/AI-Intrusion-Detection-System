#!/usr/bin/env python3
"""Private experimental training preview: synthetic benign + reviewed Pi benign SSH.

DOES NOT write /var/lib, run systemctl, send alerts, or activate any model.
A successful login is not intrinsically trustworthy: a human must approve
the small real sample with --approve-reviewed-successes before mixing it in.
The final held-out synthetic attack/test split never participates in training.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys
from pathlib import Path

from yggdrasil_ids.config import MLConfig, RulesConfig
from yggdrasil_ids.features import FEATURE_NAMES
from yggdrasil_ids.lab import _evaluate_events, _read_events, prepare_rows
from yggdrasil_ids.ml import IsolationForestDetector, _validate_rows

MAX_JSON_BYTES = 8 * 1024 * 1024
MAX_REAL_EVENTS = 10000
MIN_REAL_EVENTS = 10


def read_json(path: Path) -> dict:
    if not path.is_file() or path.stat().st_size > MAX_JSON_BYTES:
        raise ValueError("Missing or oversized private JSON artifact")
    parsed = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(parsed, dict):
        raise ValueError("Expected JSON object")
    return parsed


def _check_lab(lab: Path) -> tuple[list[list[float]], dict]:
    report = read_json(lab / "report.json")
    labels = read_json(lab / "labels.json")
    if report.get("kind") != "synthetic_laboratory":
        raise ValueError("Expected a synthetic lab, not real attack logs")
    if labels.get("kind") != "synthetic_laboratory":
        raise ValueError("Invalid lab label source")
    label_count = report["splits"]["train"]["event_count"]
    for split in ("train", "validation", "test"):
        path = lab / f"{split}.jsonl"
        if not path.is_file() or path.stat().st_size > MAX_JSON_BYTES:
            raise ValueError("Missing or oversized lab data")
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if digest != report["splits"][split]["sha256"]:
            raise ValueError("Laboratory input hash does not match report")
    digest = hashlib.sha256((lab / "labels.json").read_bytes()).hexdigest()
    if digest != report["labels_sha256"]:
        raise ValueError("Laboratory labels hash mismatch")
    training_labels = labels["splits"]["train"]
    if len(training_labels) != label_count or any(
        item.get("expected") != "normal" for item in training_labels
    ):
        raise ValueError("Attack labels or missing normal labels in training split")
    training_events = _read_events(lab / "train.jsonl")
    if {e.cursor for e in training_events} != {row["cursor"] for row in training_labels}:
        raise ValueError("Training labels do not match journal events")
    if not (
        report["splits"]["validation"]["first_timestamp"]
        > report["splits"]["train"]["last_timestamp"] + 600
        and report["splits"]["test"]["first_timestamp"]
        > report["splits"]["validation"]["last_timestamp"] + 600
    ):
        raise ValueError("Lab temporal holdouts are not separated")
    rows = prepare_rows(lab / "train.jsonl")
    if len(rows) != label_count:
        raise ValueError("Lab prepared-row count mismatch")
    return rows, labels


def _validated_real(path: Path) -> list[list[float]]:
    data = read_json(path)
    if (
        data.get("kind") != "private_real_ssh_normal_candidates"
        or data.get("reviewed_as_normal") is not False
        or data.get("feature_names") != list(FEATURE_NAMES)
        or data.get("window_seconds") != 300
    ):
        raise ValueError("Unexpected unreviewed SSH feature export")
    rows = data.get("rows")
    timestamps = data.get("timestamps")
    if (
        not isinstance(rows, list)
        or not isinstance(timestamps, list)
        or len(rows) != len(timestamps)
        or not MIN_REAL_EVENTS <= len(rows) <= MAX_REAL_EVENTS
    ):
        raise ValueError("Insufficient or malformed real SSH candidate records")
    if data.get("candidate_success_rows") != len(rows):
        raise ValueError("Real SSH feature count mismatch")
    if not all(type(value) in (int, float) and value >= 0 for value in timestamps) or any(
        a > b for a, b in zip(timestamps, timestamps[1:])
    ):
        raise ValueError("Real SSH timestamps not chronological")
    matrix = _validate_rows(rows, MIN_REAL_EVENTS)
    return matrix.tolist()


def build_preview(lab: Path, real_path: Path, output: Path) -> dict:
    if output.exists():
        raise FileExistsError("Private output directory already exists; never overwrite models")
    synthetic_rows, labels = _check_lab(lab)
    real_rows = _validated_real(real_path)
    # Training and tiny real holdout cannot overlap by event. However adjacent
    # 300-second windows can overlap: do not claim this measures a real FPR.
    heldout_count = max(3, len(real_rows) // 3)
    train_real, heldout_real = real_rows[:-heldout_count], real_rows[-heldout_count:]
    if len(train_real) < 5:
        raise ValueError("Too few real candidates for experimental bootstrap")
    config = MLConfig()
    model = IsolationForestDetector.train(
        synthetic_rows + train_real,
        config,
        (
            f"EXPERIMENTAL hybrid bootstrap: {len(synthetic_rows)} synthetic benign "
            f"SSH features plus {len(train_real)} explicitly reviewed real Pi "
            "success-candidate features. No real-world FPR established; shadow only."
        ),
    )
    synthetic_test_events = _read_events(lab / "test.jsonl")
    label_map = {item["cursor"]: item for item in labels["splits"]["test"]}
    evaluation = _evaluate_events(
        synthetic_test_events,
        label_map,
        RulesConfig(
            expected_sources=("192.0.2.10/32", "192.0.2.11/32"),
            expected_users=("labuser", "backup"),
        ),
        model,
        config.window_seconds,
    )
    real_scores = [model.score(row) for row in heldout_real]
    report = {
        "kind": "EXPERIMENTAL_private_hybrid_bootstrap_preview",
        "production_model_activated": False,
        "normality_approved_by_owner_not_independently_verified": True,
        "synthetic_train_rows": len(synthetic_rows),
        "real_candidate_train_rows": len(train_real),
        "real_candidate_heldout_rows": len(heldout_real),
        "synthetic_heldout_test_rows": len(synthetic_test_events),
        "synthetic_heldout_test": {
            "rules": evaluation["rules"],
            "ml": evaluation["ml"],
        },
        "real_heldout_shadow_anomalies": sum(x["is_anomaly"] for x in real_scores),
        "real_heldout_score_min": min(x["score"] for x in real_scores),
        "real_heldout_score_max": max(x["score"] for x in real_scores),
        "model": model.metadata,
        "warning": (
            "Not validated on real attacks; real observations are few and "
            "time-correlated. Treat as an experimental shadow model, NOT an "
            "estimate of deployed intrusion detection accuracy."
        ),
    }
    output.mkdir(mode=0o700, parents=False, exist_ok=False)
    os.chmod(output, stat.S_IRWXU)
    model.save(output / "candidate-model.json")
    destination = output / "preview.json"
    with destination.open("x", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, ensure_ascii=False, allow_nan=False)
    os.chmod(destination, stat.S_IRUSR | stat.S_IWUSR)
    return {
        "kind": report["kind"],
        "candidate_model_file": str(output / "candidate-model.json"),
        "preview_file": str(destination),
        "model_version": model.metadata["version"],
        "synthetic_train_rows": len(synthetic_rows),
        "real_train_rows": len(train_real),
        "real_heldout_rows": len(heldout_real),
        "real_heldout_shadow_anomalies": report["real_heldout_shadow_anomalies"],
        "test_ml_recall_synthetic_only": evaluation["ml"]["recall"],
        "test_ml_false_positive_rate_synthetic_only": evaluation["ml"]["false_positive_rate"],
        "production_model_activated": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lab-directory", required=True, type=Path)
    parser.add_argument("--real-candidates", required=True, type=Path)
    parser.add_argument("--output-directory", required=True, type=Path)
    parser.add_argument(
        "--approve-reviewed-successes",
        action="store_true",
        help="Owner has reviewed and accepts the real success samples as benign.",
    )
    args = parser.parse_args(argv)
    if not args.approve_reviewed_successes:
        print(
            "STOP: Real SSH success events need explicit owner review and approval.",
            file=sys.stderr,
        )
        return 2
    if os.geteuid() == 0:
        print("STOP: Run in your unprivileged home account, not as root.", file=sys.stderr)
        return 2
    try:
        summary = build_preview(
            args.lab_directory.resolve(), args.real_candidates.resolve(), args.output_directory
        )
    except (ValueError, OSError, KeyError, TypeError, IndexError) as exc:
        print(f"STOP: Experimental training preview failed ({type(exc).__name__})", file=sys.stderr)
        return 1
    print(json.dumps(summary, indent=2, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
