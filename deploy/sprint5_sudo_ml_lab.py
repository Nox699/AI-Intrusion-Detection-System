#!/usr/bin/env python3
"""Reproducible, isolated sudo ML-vs-rules scenario experiment.

Separate synthetic normal-only training from synthetic labeled validation
and locked final test. Results describe this constructed lab ONLY, not
actual attack detection rates or false-positive rates on Yggdrasil.
Real sudo logs, production database, model, timer and Discord untouched.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from yggdrasil_ids.sudo_ml import (
    SudoIsolationForest,
    attempts_from_signals,
    feature_rows,
)
from yggdrasil_ids.sudo_rules import SudoRuleDetector, SudoSignal

BASE = 1_793_680_000
NORMAL = ("normal_quiet", "normal_maintenance", "normal_typo", "normal_busy", "normal_spaced")
SUSPICIOUS = (
    "sudo_auth_burst",
    "sudoers_denial",
    "mixed_auth_denial",
    "slow_auth_failure",
)
TRAIN_SCENARIOS = 180
VALIDATION_NORMAL = 32
VALIDATION_SUSPICIOUS_PER_TYPE = 8
TEST_NORMAL = 32
TEST_SUSPICIOUS_PER_TYPE = 8


@dataclass(frozen=True)
class Scenario:
    category: str
    suspicious: bool
    seed: int
    signals: tuple[SudoSignal, ...]


def scenario(category: str, seed: int) -> Scenario:
    """Synthetic process groups; no real user identity or real journal read."""
    if category not in NORMAL + SUSPICIOUS:
        raise ValueError("Unknown synthetic sudo scenario")
    rng = random.Random(seed)
    start = BASE + rng.randint(0, 86_000)
    boot = f"{seed:032x}"
    uid = "1000" if seed % 5 else "1001"

    if category == "normal_quiet":
        process_specs = [("success", 0)]
    elif category == "normal_maintenance":
        process_specs = [("success", i * rng.randint(12, 40)) for i in range(rng.randint(2, 8))]
    elif category == "normal_typo":
        process_specs = [("failure", 0), ("success", rng.randint(15, 70))]
    elif category == "normal_busy":
        process_specs = [("success", i * rng.randint(6, 20)) for i in range(rng.randint(5, 12))]
    elif category == "normal_spaced":
        process_specs = [("success", i * rng.randint(360, 700)) for i in range(rng.randint(1, 4))]
    elif category == "sudo_auth_burst":
        process_specs = [("failure", i * rng.randint(8, 24)) for i in range(rng.randint(3, 7))]
    elif category == "sudoers_denial":
        process_specs = [("denied", 0)]
    elif category == "mixed_auth_denial":
        process_specs = [("failure", 0), ("failure", 18), ("denied", 32)]
    else:
        process_specs = [("failure", 0), ("failure", 420)]

    records = []
    for process, (outcome, offset) in enumerate(process_specs, start=1):
        kinds = {
            "success": ("command_invoked", "pam_session_opened", "pam_session_closed"),
            "failure": ("pam_auth_failure", "incorrect_password"),
            "denied": ("not_in_sudoers",),
        }[outcome]
        for i, kind in enumerate(kinds):
            records.append(
                SudoSignal(
                    cursor=f"synthetic-{seed}-{process}-{kind}",
                    timestamp=float(start + offset) + 0.1 * i,
                    boot_id=boot,
                    uid=uid,
                    pid=10_000 + process,
                    kind=kind,
                )
            )
    return Scenario(
        category=category,
        suspicious=category in SUSPICIOUS,
        seed=seed,
        signals=tuple(sorted(records, key=lambda item: (item.timestamp, item.cursor))),
    )


def create_splits() -> tuple[list[Scenario], list[Scenario], list[Scenario]]:
    training = [scenario(NORMAL[i % len(NORMAL)], 10_000 + i) for i in range(TRAIN_SCENARIOS)]
    validation = [scenario(NORMAL[i % len(NORMAL)], 20_000 + i) for i in range(VALIDATION_NORMAL)]
    test = [scenario(NORMAL[i % len(NORMAL)], 40_000 + i) for i in range(TEST_NORMAL)]
    for i, category in enumerate(SUSPICIOUS):
        validation.extend(
            scenario(category, 30_000 + i * 100 + j) for j in range(VALIDATION_SUSPICIOUS_PER_TYPE)
        )
        test.extend(
            scenario(category, 50_000 + i * 100 + j) for j in range(TEST_SUSPICIOUS_PER_TYPE)
        )
    seeds = [item.seed for item in training + validation + test]
    if len(set(seeds)) != len(seeds):
        raise RuntimeError("Synthetic scenario seeds overlap between splits")
    return training, validation, test


def features_for_scenario(item: Scenario) -> list[list[float]]:
    return feature_rows(attempts_from_signals(item.signals))


def _metrics(outcomes: list[tuple[bool, bool]]) -> dict:
    counts: Counter[str] = Counter()
    for is_suspicious, flagged in outcomes:
        counts[
            "tp"
            if is_suspicious and flagged
            else "fn"
            if is_suspicious
            else "fp"
            if flagged
            else "tn"
        ] += 1
    tp, fp, tn, fn = (counts[x] for x in ("tp", "fp", "tn", "fn"))
    return {
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "precision": round(tp / (tp + fp), 4) if tp + fp else None,
        "recall": round(tp / (tp + fn), 4) if tp + fn else None,
        "false_positive_rate": round(fp / (fp + tn), 4) if fp + tn else None,
    }


def evaluate(model: SudoIsolationForest, cases: list[Scenario]) -> dict:
    ml_decisions = []
    rule_decisions = []
    scenarios = []
    for item in cases:
        features = features_for_scenario(item)
        flagged_ml = any(row["is_anomaly"] for row in model.score_many(features))
        detector = SudoRuleDetector()
        flagged_rule = any(
            match is not None for match in (detector.evaluate(signal) for signal in item.signals)
        )
        ml_decisions.append((item.suspicious, flagged_ml))
        rule_decisions.append((item.suspicious, flagged_rule))
        scenarios.append(
            {
                "scenario_type": item.category,
                "seed": item.seed,
                "suspicious_label": item.suspicious,
                "processes": len(features),
                "ml_detected": flagged_ml,
                "rules_detected": flagged_rule,
            }
        )
    return {
        "scenario_count": len(cases),
        "normal_scenarios": sum(not x.suspicious for x in cases),
        "suspicious_scenarios": sum(x.suspicious for x in cases),
        "ml": _metrics(ml_decisions),
        "rules": _metrics(rule_decisions),
        "scenarios": scenarios,
    }


def _manifest_hash(cases: list[Scenario]) -> str:
    data = [(item.category, item.suspicious, item.seed) for item in cases]
    return hashlib.sha256(json.dumps(data, separators=(",", ":")).encode("ascii")).hexdigest()


def experiment(output: Path) -> dict:
    if os.geteuid() == 0:
        raise PermissionError("Sudo ML experiment must run as unprivileged user")
    if output.is_symlink() or output.exists():
        raise FileExistsError("Choose a fresh private sudo ML experiment folder")
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    output.chmod(0o700)
    training, validation, test = create_splits()
    training_rows = [row for item in training for row in features_for_scenario(item)]
    model = SudoIsolationForest.train(
        training_rows,
        "Sudo ML v1: synthetic normal-only, grouped by independent scenario. "
        "No actual Raspberry Pi journal data. Do not infer real-world attack accuracy.",
    )
    model.save(output / "sudo-model.json")
    loaded = SudoIsolationForest.load(output / "sudo-model.json")
    if model.version != loaded.version:
        raise RuntimeError("Saved sudo model identity did not survive reload")
    report = {
        "kind": "isolated_sudo_rule_vs_isolation_forest_synthetic_lab",
        "features": list(model.payload["features"]),
        "model_version": model.version,
        "threshold": model.threshold,
        "training": {
            "normal_scenarios": len(training),
            "normal_process_observations": len(training_rows),
            "scenario_manifest_sha256": _manifest_hash(training),
        },
        "validation": evaluate(loaded, validation),
        "test": evaluate(loaded, test),
        "holdout_manifest_sha256": {
            "validation": _manifest_hash(validation),
            "test": _manifest_hash(test),
        },
        "synthetic_only": True,
        "real_journald_records_read": 0,
        "production_sudo_shadow_modified": False,
        "production_database_modified": False,
        "production_ml_model_modified": False,
        "discord_messages_sent": 0,
        "warning": (
            "Scenario-level results on synthetic, constructed data. "
            "Not a real-world FPR or evidence of attack detection. "
            "Model was not used to generate production alerts."
        ),
    }
    (output / "report.json").write_text(
        json.dumps(report, indent=2, ensure_ascii=False, sort_keys=True),
        encoding="utf-8",
    )
    return report


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--directory", type=Path, required=True)
    args = p.parse_args(argv)
    try:
        report = experiment(args.directory)
    except (OSError, ValueError, RuntimeError, PermissionError):
        p.exit(status=1, message="STOP: Isolated sudo ML lab failed (no production changes)\n")
    summary = {k: v for k, v in report.items() if k not in ("validation", "test")}
    summary["validation"] = {k: v for k, v in report["validation"].items() if k != "scenarios"}
    summary["test"] = {k: v for k, v in report["test"].items() if k != "scenarios"}
    print(json.dumps(summary, indent=2, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
