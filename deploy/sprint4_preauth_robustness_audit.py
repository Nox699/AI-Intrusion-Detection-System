#!/usr/bin/env python3
"""Read-only synthetic preauth stress suite for an EXISTING trained model.

This is a supplementary adversarial/benign scenario challenge, NOT independent
real-world validation. It does not retrain, tune, write files, touch production
SQLite, initiate SSH connections or transmit any identifiers.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sprint4_preauth_ml_lab import _load
from sprint4_preauth_signal_audit import classify

from yggdrasil_ids.preauth_ml import (
    PreauthIsolationForest,
    connections_from_records,
    feature_rows,
)

HOURS_UTC = (0, 6, 12, 18)
BASE_DAY_UTC = int(datetime(2026, 11, 20, tzinfo=timezone.utc).timestamp())
METHODS = ("ml", "rules", "hybrid")
# Each step: (synthetic username, message family, synthetic source slot)
Step = tuple[str, str, int]


@dataclass(frozen=True)
class Case:
    name: str
    expected: str
    steps: tuple[Step, ...]
    spacing_seconds: int = 15


def cases() -> tuple[Case, ...]:
    """Fixed scenarios selected before looking at this challenge's predictions."""
    return (
        Case(
            "benign_short_legitimate",
            "normal",
            tuple(("operator", "auth_close", 0) for _ in range(3)),
        ),
        Case(
            "benign_typo_recovery",
            "normal",
            (("typo", "invalid_close", 0),)
            + tuple(("operator", "auth_close", 0) for _ in range(4)),
        ),
        Case(
            "benign_connection_retry_storm",
            "normal",
            tuple(("operator", "auth_close", 0) for _ in range(14)),
        ),
        Case(
            "benign_distributed_maintenance",
            "normal",
            tuple(("operator", "auth_close", i % 4) for i in range(16)),
        ),
        Case(
            "benign_repeated_username_typo",
            "normal",
            tuple(("mistyped", "invalid_close", 0) for _ in range(5)),
        ),
        Case(
            "simulated_invalid_user_spray",
            "simulated_suspicious",
            tuple((f"guess{i}", "invalid_close", 0) for i in range(9)),
        ),
        Case(
            "simulated_invalid_user_burst",
            "simulated_suspicious",
            tuple(("unknown", "invalid_close", 0) for _ in range(13)),
        ),
        Case(
            "simulated_preauth_disconnect_surge",
            "simulated_suspicious",
            tuple(("operator", "auth_close", 0) for _ in range(14)),
        ),
        Case(
            "simulated_distributed_invalid",
            "simulated_suspicious",
            tuple((f"guess{i}", "invalid_close", i % 4) for i in range(16)),
        ),
        Case(
            "simulated_low_rate_invalid",
            "simulated_suspicious",
            tuple(("unknown", "invalid_close", 0) for _ in range(8)),
            spacing_seconds=420,
        ),
        Case(
            "simulated_missing_disconnect_lines",
            "simulated_suspicious",
            tuple((f"guess{i}", "invalid_notice_only", 0) for i in range(9)),
        ),
    )


def make_records() -> tuple[list[dict[str, str]], dict[str, tuple[str, int, bool]]]:
    """Make in-memory, documentation-address-only journal records and labels."""
    records: list[dict[str, str]] = []
    labels: dict[str, tuple[str, int, bool]] = {}
    for hour_index, hour in enumerate(HOURS_UTC):
        for case_index, case in enumerate(cases()):
            for index, (username, kind, source_slot) in enumerate(case.steps):
                if kind not in {"auth_close", "invalid_close", "invalid_notice_only"}:
                    raise ValueError("Unsupported synthetic event kind")
                if not 0 <= source_slot <= 3:
                    raise ValueError("Unsupported synthetic source slot")
                address = f"192.0.2.{10 + 5 * case_index + source_slot}"
                port = 40000 + hour_index * 5000 + case_index * 100 + index
                stamp = BASE_DAY_UTC + hour * 3600 + index * case.spacing_seconds
                if kind == "auth_close":
                    messages = (
                        f"Connection closed by authenticating user {username} "
                        f"{address} port {port} [preauth]",
                    )
                else:
                    initial = f"Invalid user {username} from {address} port {port}"
                    if kind == "invalid_notice_only":
                        messages = (initial,)
                    else:
                        messages = (
                            initial,
                            f"Connection closed by invalid user {username} "
                            f"{address} port {port} [preauth]",
                        )

                for part, message in enumerate(messages):
                    cursor = f"fixed-stress-{hour}-{case_index}-{index}-{part}"
                    labels[cursor] = (
                        case.name,
                        hour,
                        case.expected == "simulated_suspicious",
                    )
                    records.append(
                        {
                            "__CURSOR": cursor,
                            "__REALTIME_TIMESTAMP": str(stamp * 1_000_000 + part * 200_000),
                            "_UID": "0",
                            "_COMM": "sshd-session",
                            "_BOOT_ID": "synthetic-fixed-stress-boot",
                            "MESSAGE": message,
                        }
                    )
    records.sort(key=lambda record: (int(record["__REALTIME_TIMESTAMP"]), record["__CURSOR"]))
    return records, labels


def rule_flag(vector: list[float]) -> bool:
    """Exactly the comparator used in sprint4_preauth_hybrid_diagnostics.py."""
    attempts, invalid, distinct, disconnects = vector[:4]
    return bool(invalid >= 5 or distinct >= 4 or disconnects >= 10 or attempts >= 12)


def metrics(items: list[dict[str, Any]], method: str) -> dict[str, Any]:
    tp = sum(item["suspicious"] and item["flags"][method] for item in items)
    fp = sum(not item["suspicious"] and item["flags"][method] for item in items)
    tn = sum(not item["suspicious"] and not item["flags"][method] for item in items)
    fn = sum(item["suspicious"] and not item["flags"][method] for item in items)
    return {
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "precision": tp / (tp + fp) if tp + fp else None,
        "recall": tp / (tp + fn) if tp + fn else None,
        "false_positive_rate": fp / (fp + tn) if fp + tn else None,
    }


def analyse(directory: Path) -> dict[str, Any]:
    """Load pinned lab model, assess NEW synthetic controls, and print aggregate results."""
    _load(directory)  # Revalidate the original manifest before using the model.
    historical = json.loads((directory / "report.json").read_text(encoding="utf-8"))
    if historical.get("kind") != "synthetic_preauth_isolation_forest_lab":
        raise ValueError("Unexpected original preauth lab report")
    model = PreauthIsolationForest.load(directory / "preauth-lab-model.json")
    if (
        model.version != historical["model"]["version"]
        or model.threshold != historical["model"]["threshold"]
    ):
        raise ValueError("Existing model version or threshold changed")

    records, label_by_cursor = make_records()
    connections = connections_from_records(records, classify)
    vectors = feature_rows(connections)
    expected_count = len(HOURS_UTC) * sum(len(case.steps) for case in cases())
    if len(connections) != expected_count:
        raise ValueError("Synthetic SSH connection correlation changed")

    observations = []
    for conn, row in zip(connections, vectors, strict=True):
        name, hour, suspicious = label_by_cursor[conn.cursor]
        ml = bool(model.score(row)["is_anomaly"])
        rules = rule_flag(row)
        observations.append(
            {
                "case": name,
                "hour": hour,
                "suspicious": suspicious,
                "vector": row,
                "flags": {"ml": ml, "rules": rules, "hybrid": ml or rules},
            }
        )

    # The two differently labelled cases have identical observable feature
    # vectors, so NO classifier using this schema can distinguish their intent.
    matched = {}
    for hour in HOURS_UTC:
        benign = [
            item
            for item in observations
            if item["case"] == "benign_connection_retry_storm" and item["hour"] == hour
        ]
        suspicious = [
            item
            for item in observations
            if item["case"] == "simulated_preauth_disconnect_surge" and item["hour"] == hour
        ]
        identical = (
            len(benign) == len(suspicious) == 14
            and all(a["vector"] == b["vector"] for a, b in zip(benign, suspicious, strict=True))
        )
        if not identical:
            raise ValueError("Matched opposite-label control is not feature-identical")
        matched[str(hour)] = True

    per_hour = {}
    for hour in HOURS_UTC:
        items = [item for item in observations if item["hour"] == hour]
        per_hour[str(hour)] = {
            "candidates": len(items),
            **{method: metrics(items, method) for method in METHODS},
        }

    per_case = []
    for case in cases():
        items = [item for item in observations if item["case"] == case.name]
        first_by_hour = {}
        for hour in HOURS_UTC:
            subset = [item for item in items if item["hour"] == hour]
            first_by_hour[str(hour)] = {
                method: next(
                    (i for i, item in enumerate(subset, start=1) if item["flags"][method]),
                    None,
                )
                for method in METHODS
            }
        per_case.append(
            {
                "scenario": case.name,
                "synthetic_intent": case.expected,
                "candidates": len(items),
                "counts": {
                    method: {
                        key: value
                        for key, value in metrics(items, method).items()
                        if key in {"tp", "fp", "tn", "fn"}
                    }
                    for method in METHODS
                },
                "first_detection_by_hour": first_by_hour,
            }
        )

    return {
        "kind": "supplementary_synthetic_preauth_robustness_audit",
        "model_version": model.version,
        "evaluation_unit": "one_correlated_preauth_connection",
        "utc_hours_tested": list(HOURS_UTC),
        "model_retrained": False,
        "model_threshold_unchanged": True,
        "production_ids_changed": False,
        "files_written": False,
        "original_test_set_is_already_inspected": True,
        "synthetic_scenario_labels_are_not_verified_attack_truth": True,
        "interpretation": (
            "Pre-specified supplementary synthetic controls are NOT an independent "
            "real-world evaluation. Some benign scenarios intentionally mimic "
            "suspicious patterns. Incomplete notices are candidate log observations, "
            "not proof of completed connections or attacks."
        ),
        "per_utc_hour": per_hour,
        "cases": per_case,
        "opposite_label_identical_features": {
            "benign": "benign_connection_retry_storm",
            "suspicious": "simulated_preauth_disconnect_surge",
            "feature_vectors_identical_at_each_utc_hour": matched,
            "conclusion": (
                "This feature schema cannot infer intent when legitimate and "
                "suspicious cases are observationally identical."
            ),
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("lab_directory", type=Path)
    args = parser.parse_args(argv)
    result = analyse(args.lab_directory.expanduser().resolve())
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
