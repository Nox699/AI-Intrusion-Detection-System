#!/usr/bin/env python3
"""Reproducible, isolated preauth ML experiment with held-out synthetic scenarios.

No SSH connections or live SQLite access. Records use documentation-only IP
ranges; scenario intent is stored ONLY in a separate labels.json file. A
preauth record is not automatically evidence of an attack.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
from collections import defaultdict, deque
from pathlib import Path
from typing import Any

from sprint4_preauth_signal_audit import classify
from yggdrasil_ids.preauth_ml import (
    CONNECTION_GAP,
    WINDOW,
    PreauthIsolationForest,
    connections_from_records,
    feature_rows,
)

SPLITS = ("train", "validation", "test")
FAMILIES = ("train.jsonl", "validation.jsonl", "test.jsonl", "labels.json")
NORMAL_SOURCES = ("192.0.2.10", "192.0.2.11", "203.0.113.22")
SUSPICIOUS_SOURCE = "198.51.100.44"
SEED = 42
ANCHOR = 1_793_500_000
NORMAL_NAMES = ("labuser", "backup", "operator")
SUSPICIOUS_NAMES = (
    "admin", "guest", "root", "oracle", "postgres", "support",
    "deploy", "test", "ubuntu", "git", "monitor", "service",
)
DISCLAIMER = (
    "Synthetic event-level preauth simulation only; the small real Pi journal "
    "audit had just two candidate connection keys, not enough real normal "
    "samples to train or validate this preauth ML model."
)


def _write(path: Path, content: Any) -> None:
    with path.open("x", encoding="utf-8") as output:
        json.dump(content, output, ensure_ascii=False, indent=2, allow_nan=False)
        output.write("\n")
    os.chmod(path, 0o600)


def generate(directory: Path, seed: int = SEED, anchor: int = ANCHOR) -> dict[str, Any]:
    """Generate training, validation and final test chronologically separated."""
    if type(seed) is not int or not 0 <= seed <= 2**32 - 1:
        raise ValueError("Invalid synthetic lab seed")
    if type(anchor) is not int or not 200000 <= anchor <= 253402000000:
        raise ValueError("Invalid synthetic lab timestamp")
    if directory.exists():
        raise FileExistsError("Synthetic preauth lab directory already exists")
    directory.mkdir(mode=0o700, parents=False)
    rng = random.Random(seed)
    records: dict[str, list[dict[str, str]]] = {split: [] for split in SPLITS}
    labels: dict[str, Any] = {
        "schema": 1,
        "kind": "synthetic_preauth_lab",
        "seed": seed,
        "anchor": anchor,
        "split_labels": {split: [] for split in SPLITS},
        "scenario_labels": [],
    }
    next_port = 42000
    lab_start = anchor - 150000

    def scenario(
        split: str,
        title: str,
        expected: str,
        start: float,
        source: str,
        actions: list[tuple[str, bool]],
    ) -> None:
        nonlocal next_port
        name = f"{split}_{title}"
        for index, (username, invalid) in enumerate(actions):
            stamp = start + index * 15 + rng.randint(0, 2)
            port = next_port
            next_port += 1
            messages = (
                [
                    f"Invalid user {username} from {source} port {port}",
                    f"Connection closed by invalid user {username} "
                    f"{source} port {port} [preauth]",
                ]
                if invalid
                else [
                    f"Connection closed by authenticating user {username} "
                    f"{source} port {port} [preauth]"
                ]
            )
            for part, message in enumerate(messages):
                cursor = f"preauth-lab-{seed}-{name}-{index:02d}-{part}"
                record = {
                    "__CURSOR": cursor,
                    "__REALTIME_TIMESTAMP": str(int((stamp + part * 0.2) * 1_000_000)),
                    "_UID": "0",
                    "_COMM": "sshd-session",
                    "_BOOT_ID": "synthetic-preauth-boot",
                    "MESSAGE": message,
                }
                records[split].append(record)
                labels["split_labels"][split].append(
                    {"cursor": cursor, "scenario": name, "expected": expected}
                )
        labels["scenario_labels"].append(
            {"split": split, "name": name, "expected": expected, "attempts": len(actions)}
        )

    # All 108 training scenarios are labelled benign. Intent never enters the ML vector.
    for index in range(108):
        start = lab_start + index * 850
        source = NORMAL_SOURCES[index % len(NORMAL_SOURCES)]
        count = 1 + index % 5
        actions: list[tuple[str, bool]] = []
        for step in range(count):
            invalid = index % 9 == 0 and step == 0
            if index % 23 == 0 and step == 2:
                invalid = True
            username = f"typo{index % 4}" if invalid else NORMAL_NAMES[index % 3]
            actions.append((username, invalid))
        scenario("train", f"benign_{index:03d}", "normal", start, source, actions)

    def heldout(prefix: str, beginning: int, extra: int) -> None:
        specs = [
            ("short_legitimate", "normal", NORMAL_SOURCES[0],
             [(NORMAL_NAMES[0], False)] * (3 + extra)),
            ("legitimate_typo", "normal", NORMAL_SOURCES[1],
             [("typo", True)] + [(NORMAL_NAMES[1], False)] * 2),
            ("routine_maintenance", "normal", NORMAL_SOURCES[2],
             [(NORMAL_NAMES[2], False)] * (6 + extra)),
            ("new_legitimate_source", "normal", "203.0.113.77",
             [(NORMAL_NAMES[0], False)] * 2),
            ("invalid_user_spray", "simulated_suspicious", SUSPICIOUS_SOURCE,
             [(SUSPICIOUS_NAMES[i], True) for i in range(9 + extra)]),
            ("invalid_user_burst", "simulated_suspicious", SUSPICIOUS_SOURCE,
             [("guest", True)] * (12 + extra)),
            ("preauth_disconnect_surge", "simulated_suspicious", SUSPICIOUS_SOURCE,
             [(NORMAL_NAMES[0], False)] * (14 + extra)),
        ]
        for position, (name, expected, source, actions) in enumerate(specs):
            scenario(prefix, name, expected, beginning + position * 900, source, actions)

    train_end = lab_start + 107 * 850 + 4 * 15 + 2
    validation_start = int(train_end + 1800)
    heldout("validation", validation_start, extra=1)
    test_start = validation_start + 7 * 900 + 1800
    heldout("test", test_start, extra=0)

    for split in SPLITS:
        path = directory / f"{split}.jsonl"
        with path.open("x", encoding="utf-8") as handle:
            for record in records[split]:
                handle.write(json.dumps(record, sort_keys=True) + "\n")
        os.chmod(path, 0o600)
    _write(directory / "labels.json", labels)
    manifest = {
        "schema": 1,
        "kind": "synthetic_preauth_manifest",
        "files": {
            name: hashlib.sha256((directory / name).read_bytes()).hexdigest()
            for name in FAMILIES
        },
        "record_counts": {split: len(records[split]) for split in SPLITS},
        "warning": DISCLAIMER,
    }
    _write(directory / "manifest.json", manifest)
    return manifest


def _load(directory: Path) -> tuple[dict[str, list[dict]], dict]:
    manifest = json.loads((directory / "manifest.json").read_text(encoding="utf-8"))
    if manifest.get("kind") != "synthetic_preauth_manifest" or set(
        manifest.get("files", {})
    ) != set(FAMILIES):
        raise ValueError("Unrecognized synthetic preauth input manifest")
    for name, sha in manifest["files"].items():
        path = directory / name
        if not path.is_file() or path.stat().st_size > 10 * 1024 * 1024:
            raise ValueError("Missing or oversized preauth lab input")
        if hashlib.sha256(path.read_bytes()).hexdigest() != sha:
            raise ValueError("Synthetic preauth lab input hash mismatch")
    labels = json.loads((directory / "labels.json").read_text(encoding="utf-8"))
    if labels.get("kind") != "synthetic_preauth_lab" or set(
        labels.get("split_labels", {})
    ) != set(SPLITS):
        raise ValueError("Unrecognized synthetic label sidecar")
    result = {}
    global_cursors: set[str] = set()
    for split in SPLITS:
        lines = (directory / f"{split}.jsonl").read_text(encoding="utf-8").splitlines()
        records = [json.loads(line) for line in lines]
        cursors = [item.get("__CURSOR") for item in records]
        entries = labels["split_labels"][split]
        expected = [item.get("cursor") for item in entries]
        if cursors != expected or len(set(cursors)) != len(cursors):
            raise ValueError("Journal records and independent labels mismatch")
        if global_cursors & set(cursors):
            raise ValueError("Train/test data must not share journal cursors")
        global_cursors.update(cursors)
        if split == "train" and any(item.get("expected") != "normal" for item in entries):
            raise ValueError("Suspicious labels cannot be in normal training")
        if any(item.get("expected") not in {"normal", "simulated_suspicious"} for item in entries):
            raise ValueError("Unrecognized synthetic scenario intent")
        if any(set(item) != {"cursor", "scenario", "expected"} for item in entries):
            raise ValueError("Invalid synthetic label metadata")
        result[split] = records
    for earlier, later in (("train", "validation"), ("validation", "test")):
        end = int(result[earlier][-1]["__REALTIME_TIMESTAMP"])
        first = int(result[later][0]["__REALTIME_TIMESTAMP"])
        if first - end <= 2 * WINDOW * 1_000_000:
            raise ValueError("Independent held-out split lacks a 600s purge gap")
    return result, labels


def _metrics(expected: list[bool], predicted: list[bool]) -> dict[str, Any]:
    tp = sum(a and p for a, p in zip(expected, predicted, strict=True))
    fp = sum(not a and p for a, p in zip(expected, predicted, strict=True))
    tn = sum(not a and not p for a, p in zip(expected, predicted, strict=True))
    fn = sum(a and not p for a, p in zip(expected, predicted, strict=True))
    return {
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "precision": tp / (tp + fp) if tp + fp else None,
        "recall": tp / (tp + fn) if tp + fn else None,
        "false_positive_rate": fp / (fp + tn) if fp + tn else None,
        "total": len(expected),
    }


def _score_split(records: list[dict], label_entries: list[dict], model: PreauthIsolationForest):
    cursor_to_label = {row["cursor"]: row for row in label_entries}
    connections = connections_from_records(records, classify)
    rows = feature_rows(connections)
    expected = []
    ml_predicted = []
    rule_predicted = []
    scenarios: dict[str, dict[str, list[bool]]] = defaultdict(
        lambda: {"expected": [], "ml": [], "rules": []}
    )
    for conn, vector in zip(connections, rows, strict=True):
        intent = cursor_to_label[conn.cursor]
        suspicious = intent["expected"] == "simulated_suspicious"
        ml = model.score(vector)["is_anomaly"]
        attempts, invalid, users, disconnects = vector[:4]
        rule = bool(invalid >= 5 or users >= 4 or disconnects >= 10 or attempts >= 12)
        expected.append(suspicious)
        ml_predicted.append(ml)
        rule_predicted.append(rule)
        value = scenarios[intent["scenario"]]
        value["expected"].append(suspicious)
        value["ml"].append(ml)
        value["rules"].append(rule)
    return {
        "observation_unit": "one_correlated_preauth_connection",
        "connection_candidates": len(connections),
        "ml": _metrics(expected, ml_predicted),
        "rules": _metrics(expected, rule_predicted),
        "scenarios": [
            {
                "scenario": name,
                "connections": len(values["expected"]),
                "ml": _metrics(values["expected"], values["ml"]),
                "rules": _metrics(values["expected"], values["rules"]),
            }
            for name, values in scenarios.items()
        ],
    }


def evaluate(directory: Path) -> dict[str, Any]:
    inputs, labels = _load(directory)
    train_connections = connections_from_records(inputs["train"], classify)
    normal_rows = feature_rows(train_connections)
    if len(normal_rows) < 80:
        raise ValueError("Synthetic preauth normal training is insufficient")
    model = PreauthIsolationForest.train(
        normal_rows,
        (
            "Isolated SYNTHETIC benign preauth training only. "
            "Independent validation and test journal events and "
            "known simulated attack scenarios are excluded. NOT production."
        ),
    )
    model.save(directory / "preauth-lab-model.json")
    loaded = PreauthIsolationForest.load(directory / "preauth-lab-model.json")
    if loaded.version != model.version:
        raise ValueError("Preauth model did not survive safe artifact reload")
    report = {
        "kind": "synthetic_preauth_isolation_forest_lab",
        "schema": 1,
        "model": {
            "version": model.version,
            "threshold": model.threshold,
            "training_rows": len(normal_rows),
            "feature_names": list(model.payload["features"]),
            "training_data_source": "synthetic_benign_only",
            "trained_on_any_real_pi_data": False,
        },
        "manifest_sha256": hashlib.sha256(
            (directory / "manifest.json").read_bytes()
        ).hexdigest(),
        "validation": _score_split(inputs["validation"], labels["split_labels"]["validation"], loaded),
        "test": _score_split(inputs["test"], labels["split_labels"]["test"], loaded),
        "limits": [
            DISCLAIMER,
            "All scores come from a constructed synthetic scenario distribution.",
            "Multiple observations from the same scenario share a source and 300s window.",
            "The explicit rule comparator uses predefined thresholds, not learned ones.",
            "Model scores represent deviation, not the probability of intrusion.",
            "This experiment does not change the existing live SSH model or service.",
        ],
    }
    _write(directory / "report.json", report)
    return {
        "kind": report["kind"],
        "model_version": model.version,
        "training_rows": len(normal_rows),
        "threshold": model.threshold,
        "validation_metrics": {
            "rules": report["validation"]["rules"],
            "ml": report["validation"]["ml"],
        },
        "test_metrics": {
            "rules": report["test"]["rules"],
            "ml": report["test"]["ml"],
        },
        "private_report": str(directory / "report.json"),
        "private_model": str(directory / "preauth-lab-model.json"),
        "production_ids_changed": False,
        "new_live_preauth_ml_active": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", required=True, type=Path)
    parser.add_argument("--seed", type=int, default=SEED)
    args = parser.parse_args(argv)
    if os.geteuid() == 0:
        parser.error("Run synthetic preauth training as unprivileged vidar, not root")
    directory = args.directory.expanduser().resolve()
    if directory.exists() or not directory.parent.is_dir():
        parser.error("Select a fresh private output folder under an existing directory")
    try:
        generate(directory, seed=args.seed)
        summary = evaluate(directory)
    except (OSError, TypeError, ValueError, KeyError, IndexError) as exc:
        parser.error(f"Preauth lab failed: {type(exc).__name__}: {str(exc)[:150]}")
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
