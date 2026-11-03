"""Read only the bounded, anonymous sudo integration export.

The export describes registered rule cases and provisional model scores. It
does not establish delivery to Discord, label an attack, or expose the private
source database or model artifact to the web process.
"""

from __future__ import annotations

import math
import re
import time
from pathlib import Path
from typing import Any

from .sudo_dashboard import _read_json

PUBLIC_INTEGRATION = Path("/var/lib/yggdrasil-sudo-public/sudo-integration.json")
MAX_AGE = 180
MAX_SIZE = 16_384
_VERSION = re.compile(r"sudo-if-[0-9a-f]{16}\Z")
_CATEGORIES = frozenset(
    {"session_opened", "command_logged", "authentication_failed", "permission_denied"}
)


def _time(value: Any, now: float) -> float:
    if type(value) not in (int, float) or not math.isfinite(value) or not 1 <= value <= now + 60:
        raise ValueError("Invalid public timestamp")
    return float(value)


def _count(value: Any, maximum: int = 1_000_000_000) -> int:
    if type(value) is not int or not 0 <= value <= maximum:
        raise ValueError("Invalid public counter")
    return value


def _score(value: Any) -> float:
    if type(value) not in (int, float) or not math.isfinite(value) or not 0 <= value <= 1:
        raise ValueError("Invalid public score")
    return float(value)


def _message(value: Any) -> None:
    # Messages are validated for shape but never reflected into the dashboard.
    if not isinstance(value, str) or len(value) > 256:
        raise ValueError("Invalid public message")


def _ml(value: Any, now: float) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError("Invalid public model status")
    if set(value) == {"state", "message"} and value["state"] == "unavailable":
        _message(value["message"])
        return {"state": "unavailable"}
    keys = {
        "format",
        "mode",
        "generated_at",
        "source_checkpoint",
        "snapshot_cutoff",
        "window_seconds",
        "warmup_seconds",
        "model_version",
        "threshold",
        "provisional",
        "total_scored",
        "anomalous",
        "skipped_ambiguous_processes",
        "latest_limit",
        "latest",
        "sends_alerts",
        "shares_production_database",
    }
    if set(value) != keys or (
        value["format"] != "sudo-ml-shadow-v1"
        or value["mode"] != "shadow"
        or type(value["window_seconds"]) is not int
        or value["window_seconds"] != 900
        or type(value["warmup_seconds"]) is not int
        or value["warmup_seconds"] != 300
        or type(value["latest_limit"]) is not int
        or value["latest_limit"] != 15
        or value["provisional"] is not True
        or value["sends_alerts"] is not False
        or value["shares_production_database"] is not False
        or not isinstance(value["model_version"], str)
        or not _VERSION.fullmatch(value["model_version"])
    ):
        raise ValueError("Invalid public model provenance")
    generated = _time(value["generated_at"], now)
    checkpoint = _time(value["source_checkpoint"], now)
    cutoff = _time(value["snapshot_cutoff"], now)
    if cutoff != checkpoint or checkpoint > generated + 60:
        raise ValueError("Inconsistent public model checkpoint")
    total = _count(value["total_scored"], 3000)
    anomalous = _count(value["anomalous"], total)
    skipped = _count(value["skipped_ambiguous_processes"], 3000)
    threshold = _score(value["threshold"])
    latest = value["latest"]
    if not isinstance(latest, list) or len(latest) != min(total, 15):
        raise ValueError("Invalid public model list bound")
    processed = []
    prior = float("inf")
    for item in latest:
        if not isinstance(item, dict) or set(item) != {
            "timestamp",
            "category",
            "score",
            "is_anomaly",
        }:
            raise ValueError("Invalid public model row")
        stamp = _time(item["timestamp"], now)
        score = _score(item["score"])
        if (
            not cutoff - 900 < stamp <= cutoff
            or stamp > prior
            or item["category"] not in _CATEGORIES
            or type(item["is_anomaly"]) is not bool
            or item["is_anomaly"] != (score > threshold)
        ):
            raise ValueError("Inconsistent public model row")
        prior = stamp
        processed.append({**item, "timestamp": stamp, "score": score})
    shown_anomalies = sum(item["is_anomaly"] for item in processed)
    if not shown_anomalies <= anomalous <= shown_anomalies + total - len(processed):
        raise ValueError("Inconsistent public model count")
    return {
        "state": "ready" if max(now - generated, now - checkpoint) <= MAX_AGE else "stale",
        "generated_at": generated,
        "source_checkpoint": checkpoint,
        "model_version": value["model_version"],
        "threshold": threshold,
        "total_scored": total,
        "anomalous": anomalous,
        "skipped_ambiguous_processes": skipped,
        "latest": processed,
    }


def validate_integration(value: Any, *, now: float) -> dict[str, Any]:
    if (
        not isinstance(value, dict)
        or set(value)
        != {"schema", "generated_at", "source_checkpoint", "activated_at", "rules", "ml"}
        or value["schema"] != "sudo-integration-v1"
    ):
        raise ValueError("Unknown public integration schema")
    generated = _time(value["generated_at"], now)
    activated = _time(value["activated_at"], now)
    rules = value["rules"]
    if not isinstance(rules, dict) or set(rules) != {"state", "imported_total", "message"}:
        raise ValueError("Invalid public rule status")
    if rules["state"] not in {"active", "error"}:
        raise ValueError("Invalid public rule state")
    checkpoint = value["source_checkpoint"]
    if checkpoint is None:
        if rules["state"] != "error":
            raise ValueError("Active rules lack a source checkpoint")
    else:
        checkpoint = _time(checkpoint, now)
    if activated > generated + 60 or (checkpoint is not None and checkpoint > generated + 60):
        raise ValueError("Inconsistent public integration time")
    _message(rules["message"])
    imported = _count(rules["imported_total"])
    state = "ready" if rules["state"] == "active" else "error"
    if now - generated > MAX_AGE or (checkpoint is not None and now - checkpoint > MAX_AGE):
        state = "stale"
    return {
        "state": state,
        "rules_active": state == "ready",
        "generated_at": generated,
        "source_checkpoint": checkpoint,
        "activated_at": activated,
        "imported_total": imported,
        "ml": _ml(value["ml"], now),
    }


def read_integration(
    path: Path = PUBLIC_INTEGRATION, *, now: float | None = None
) -> dict[str, Any]:
    clock = time.time() if now is None else now
    if type(clock) not in (int, float) or not math.isfinite(clock) or clock < 1:
        raise ValueError("Invalid dashboard time")
    try:
        return validate_integration(_read_json(path, MAX_SIZE, secure=True), now=clock)
    except (OSError, ValueError, TypeError, OverflowError, RecursionError):
        return {"state": "unavailable", "rules_active": False, "ml": {"state": "unavailable"}}


def require_current_run(
    path: Path = PUBLIC_INTEGRATION,
    *,
    not_before: float,
    expected_activation: float,
    expected_model: str,
    now: float | None = None,
) -> dict[str, Any]:
    """Prove a completed deployment invocation through its anonymous export.

    A skipped systemd condition can return success without running the worker.
    A previous healthy export is insufficient: both rule and ML results must
    have been generated since this invocation started, for the armed release.
    """
    clock = time.time() if now is None else now
    started = _time(not_before, clock)
    activated = _time(expected_activation, clock)
    if (
        not activated <= started <= clock
        or not isinstance(expected_model, str)
        or not _VERSION.fullmatch(expected_model)
    ):
        raise ValueError("Invalid deployment snapshot expectation")
    status = read_integration(path, now=clock)
    ml = status["ml"]
    if (
        status["state"] != "ready"
        or not status["rules_active"]
        or status["activated_at"] != activated
        or not started <= status["generated_at"] <= clock
        or ml["state"] != "ready"
        or ml["model_version"] != expected_model
        or ml["generated_at"] != status["generated_at"]
    ):
        raise ValueError("Current sudo integration run was not verified")
    return status
