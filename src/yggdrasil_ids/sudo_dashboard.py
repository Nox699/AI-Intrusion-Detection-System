"""Fail-closed, read-only public sudo dashboard data for an authenticated Flask page.

This web module never opens the worker-owned private sudo SQLite database,
the journal, or a webhook. Only a fixed-schema, bounded, anonymous worker
export is exposed; invalid, unavailable, or stale input is not displayed as
'healthy' or interpreted as zero events.
"""

from __future__ import annotations

import json
import math
import os
import stat
import time
from importlib import resources
from pathlib import Path
from typing import Any

PUBLIC_STATUS = Path("/var/lib/yggdrasil-sudo-public/sudo-status.json")
PUBLIC_ACTIVITY = Path("/var/lib/yggdrasil-sudo-public/sudo-activity.json")
SUMMARY_FORMAT = "sudo-shadow-summary-v1"
ACTIVITY_FORMAT = "sudo-shadow-activity-v1"
ACTIVITY_CATEGORIES = frozenset(
    {"permission_denied", "authentication_failed", "session_opened", "command_logged", "other"}
)
ACTIVITY_ATTENTION = frozenset({"rule_candidate", "review", "normal"})
CATEGORIES = frozenset(
    {
        "command_invoked",
        "pam_auth_failure",
        "incorrect_password",
        "not_in_sudoers",
        "pam_session_opened",
        "pam_session_closed",
        "other_sudo",
    }
)
DETECTORS = frozenset({"sudo.permission_denied", "sudo.repeated_auth_failure"})
EXPECTED = {
    "format",
    "mode",
    "generated_at",
    "checkpoint_at",
    "period_seconds",
    "total_signals",
    "total_candidates",
    "recent_signals",
    "categories",
    "candidate_detectors",
    "source",
    "sends_alerts",
    "shares_production_database",
}
MAX_SIZE = 16_384
MAX_COUNT = 1_000_000_000
MAX_AGE = 300


def _read_json(path: Path, size: int, *, secure: bool) -> Any:
    descriptor = os.open(
        path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    )
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_size > size:
            raise ValueError("Unexpected sudo dashboard input")
        if secure and (stat.S_IMODE(info.st_mode) & 0o137 or info.st_nlink != 1):
            raise ValueError("Unsafe public sudo summary permissions")
        with os.fdopen(os.dup(descriptor), "rb") as handle:
            encoded = handle.read(size + 1)
        if len(encoded) > size:
            raise ValueError("Oversized sudo dashboard input")
    finally:
        os.close(descriptor)
    return json.loads(encoded)


def _number(value: Any) -> int:
    if type(value) is not int or not 0 <= value <= MAX_COUNT:
        raise ValueError("Invalid sudo summary counter")
    return value


def _timestamp(value: Any, now: float) -> float:
    if type(value) not in (int, float) or not math.isfinite(value) or not 1 <= value <= now + 60:
        raise ValueError("Invalid sudo summary timestamp")
    return float(value)


def validate_summary(value: Any, *, now: float) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != EXPECTED:
        raise ValueError("Unknown sudo public summary schema")
    if (
        value["format"] != SUMMARY_FORMAT
        or value["mode"] != "shadow"
        or value["period_seconds"] != 86400
        or value["source"] != "worker_owned_private_sudo_staging"
        or value["sends_alerts"] is not False
        or value["shares_production_database"] is not False
    ):
        raise ValueError("Unsafe sudo public summary provenance")
    exported_at = _timestamp(value["generated_at"], now)
    checkpoint = _timestamp(value["checkpoint_at"], now)
    if checkpoint > exported_at + 60:
        raise ValueError("Sudo summary checkpoint is later than export time")
    total = _number(value["total_signals"])
    candidates = _number(value["total_candidates"])
    recent = _number(value["recent_signals"])
    if recent > total:
        raise ValueError("Sudo recent signals exceed total")
    if candidates > total:
        raise ValueError("Sudo candidates exceed total signals")
    categories = value["categories"]
    detectors = value["candidate_detectors"]
    if not isinstance(categories, dict) or set(categories) != CATEGORIES:
        raise ValueError("Unknown sudo event categories")
    if not isinstance(detectors, dict) or set(detectors) != DETECTORS:
        raise ValueError("Unknown sudo detector categories")
    normalized_categories = {key: _number(categories[key]) for key in sorted(CATEGORIES)}
    normalized_detectors = {key: _number(detectors[key]) for key in sorted(DETECTORS)}
    if (
        sum(normalized_categories.values()) != recent
        or sum(normalized_detectors.values()) > candidates
    ):
        raise ValueError("Inconsistent sudo public summary counts")
    state = "ready" if now - exported_at <= MAX_AGE and now - checkpoint <= MAX_AGE else "stale"
    return {
        "state": state,
        "generated_at": exported_at,
        "checkpoint_at": checkpoint,
        "period_seconds": 86400,
        "total_signals": total,
        "total_candidates": candidates,
        "recent_signals": recent,
        "recent_candidates": sum(normalized_detectors.values()),
        "categories": normalized_categories,
        "candidate_detectors": normalized_detectors,
        "mode": "shadow",
    }


def read_summary(path: Path = PUBLIC_STATUS, *, now: float | None = None) -> dict[str, Any]:
    """Only a sanitized file; never a direct SQLite fallback if it is missing."""
    clock = time.time() if now is None else now
    if not math.isfinite(clock) or clock < 1:
        raise ValueError("Invalid dashboard time")
    try:
        status = validate_summary(_read_json(path, MAX_SIZE, secure=True), now=clock)
    except (OSError, ValueError, TypeError, OverflowError, RecursionError):
        return {
            "state": "unavailable",
            "message": "Ingen gyldig sudo-opsummering tilgængelig fra den isolerede sensor.",
        }
    if status["state"] == "stale":
        status["message"] = "Sudo-opsummeringen eller sensorens checkpoint er forældet."
    return status


def validate_activity(value: Any, *, now: float) -> dict[str, Any]:
    """Validate fixed-schema, bounded, already-anonymized process-level data."""
    keys = {
        "format",
        "mode",
        "generated_at",
        "checkpoint_at",
        "period_seconds",
        "latest_limit",
        "latest",
        "candidate_limit",
        "candidates",
        "source",
        "sends_alerts",
        "shares_production_database",
    }
    if not isinstance(value, dict) or set(value) != keys:
        raise ValueError("Unknown sudo activity schema")
    if (
        value["format"] != ACTIVITY_FORMAT
        or value["mode"] != "shadow"
        or type(value["period_seconds"]) is not int
        or value["period_seconds"] != 86400
        or type(value["latest_limit"]) is not int
        or value["latest_limit"] != 15
        or type(value["candidate_limit"]) is not int
        or value["candidate_limit"] != 8
        or value["source"] != "worker_owned_private_sudo_staging"
        or value["sends_alerts"] is not False
        or value["shares_production_database"] is not False
    ):
        raise ValueError("Invalid sudo activity source or time-window provenance")
    generated = _timestamp(value["generated_at"], now)
    checkpoint = _timestamp(value["checkpoint_at"], now)
    if checkpoint > generated + 60:
        raise ValueError("Sudo activity checkpoint is from the future")
    latest = value["latest"]
    candidates = value["candidates"]
    if (
        not isinstance(latest, list)
        or len(latest) > 15
        or not isinstance(candidates, list)
        or len(candidates) > 8
    ):
        raise ValueError("Unbounded sudo activity list")
    last_ts = float("inf")
    processed = []
    for item in latest:
        if not isinstance(item, dict) or set(item) != {
            "timestamp",
            "category",
            "attention",
            "detector_id",
        }:
            raise ValueError("Unknown sudo activity row")
        stamp = _timestamp(item["timestamp"], now)
        category, attention, detector = (item["category"], item["attention"], item["detector_id"])
        if (
            stamp <= generated - 86400
            or stamp > last_ts
            or category not in ACTIVITY_CATEGORIES
            or attention not in ACTIVITY_ATTENTION
            or (detector is not None and detector not in DETECTORS)
            or (attention == "rule_candidate") != (detector is not None)
            or (
                attention == "review"
                and category not in {"permission_denied", "authentication_failed"}
            )
            or (
                attention == "normal" and category in {"permission_denied", "authentication_failed"}
            )
        ):
            raise ValueError("Invalid sudo activity categorization or ordering")
        last_ts = stamp
        processed.append(
            {
                "timestamp": stamp,
                "category": category,
                "attention": attention,
                "detector_id": detector,
            }
        )
    prior_ts = float("inf")
    validated_candidates = []
    for item in candidates:
        if not isinstance(item, dict) or set(item) != {"timestamp", "detector_id", "process_count"}:
            raise ValueError("Unknown sudo candidate row")
        stamp = _timestamp(item["timestamp"], now)
        detector = item["detector_id"]
        count = _number(item["process_count"])
        if stamp <= generated - 86400 or stamp > prior_ts or detector not in DETECTORS or count < 1:
            raise ValueError("Invalid sudo candidate timestamp or type")
        prior_ts = stamp
        validated_candidates.append(
            {"timestamp": stamp, "detector_id": detector, "process_count": count}
        )
    state = "ready" if now - generated <= MAX_AGE and now - checkpoint <= MAX_AGE else "stale"
    return {
        "state": state,
        "generated_at": generated,
        "checkpoint_at": checkpoint,
        "latest": processed,
        "candidates": validated_candidates,
        "mode": "shadow",
    }


def read_activity(path: Path = PUBLIC_ACTIVITY, *, now: float | None = None) -> dict[str, Any]:
    """No fallback to private SQLite on stale/missing or malformed activity."""
    clock = time.time() if now is None else now
    if not math.isfinite(clock) or clock < 1:
        raise ValueError("Invalid dashboard time")
    try:
        status = validate_activity(_read_json(path, MAX_SIZE, secure=True), now=clock)
    except (OSError, ValueError, TypeError, OverflowError, RecursionError):
        return {
            "state": "unavailable",
            "message": "Ingen gyldig anonymiseret sudo-hændelsesoversigt er tilgængelig.",
        }
    if status["state"] == "stale":
        status["message"] = "Listen er forældet. Kontroller sudo-eksportørens timer."
    return status


def read_experiment() -> dict[str, Any]:
    """Bundled, explicitly labeled synthetic benchmark, never a live model."""
    try:
        path = resources.files("yggdrasil_ids").joinpath("sudo_benchmark.json")
        with path.open("rb") as handle:
            encoded = handle.read(MAX_SIZE + 1)
        if len(encoded) > MAX_SIZE:
            raise ValueError("Benchmark is oversized")
        report = json.loads(encoded)
        if not isinstance(report, dict) or set(report) != {
            "format",
            "synthetic_only",
            "model_version",
            "threshold",
            "training_scenarios",
            "training_process_rows",
            "validation",
            "test",
            "source_run_commit",
        }:
            raise ValueError("Unexpected sudo experiment schema")
        if (
            report["format"] != "sudo-synthetic-benchmark-v1"
            or report["synthetic_only"] is not True
            or not isinstance(report["model_version"], str)
            or not report["model_version"].startswith("sudo-if-")
            or type(report["threshold"]) not in (int, float)
            or not math.isfinite(report["threshold"])
            or not 0 <= report["threshold"] <= 1
            or _number(report["training_scenarios"]) < 80
            or _number(report["training_process_rows"]) < 80
            or not isinstance(report["source_run_commit"], str)
            or len(report["source_run_commit"]) != 40
        ):
            raise ValueError("Unverified sudo experiment metadata")
        for split in ("validation", "test"):
            record = report[split]
            if not isinstance(record, dict) or set(record) != {
                "normal_scenarios",
                "suspicious_scenarios",
                "ml",
                "rules",
            }:
                raise ValueError("Invalid sudo benchmark split")
            normal = _number(record["normal_scenarios"])
            suspicious = _number(record["suspicious_scenarios"])
            for method in ("ml", "rules"):
                figures = record[method]
                if not isinstance(figures, dict) or set(figures) != {"tp", "fp", "tn", "fn"}:
                    raise ValueError("Invalid sudo benchmark metrics")
                metrics = {key: _number(figures[key]) for key in ("tp", "fp", "tn", "fn")}
                if metrics["tp"] + metrics["fn"] != suspicious:
                    raise ValueError("Inconsistent positive sudo scenario labels")
                if metrics["tn"] + metrics["fp"] != normal:
                    raise ValueError("Inconsistent normal sudo scenario labels")
        return report
    except (OSError, ValueError, TypeError, RecursionError):
        return {"synthetic_only": True, "unavailable": True}
