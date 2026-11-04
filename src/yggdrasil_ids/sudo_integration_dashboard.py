"""Bounded, anonymous sudo rule status for the authenticated dashboard.

Web never opens the private sudo database. A current integration export proves
that the worker completed rule forwarding, not that Discord delivery succeeded.
"""

from __future__ import annotations

import math
import time
from pathlib import Path
from typing import Any

from .sudo_dashboard import _read_json

PUBLIC_INTEGRATION = Path("/var/lib/yggdrasil-sudo-public/sudo-integration.json")
MAX_AGE = 180
MAX_SIZE = 16_384


def _time(value: Any, now: float) -> float:
    if type(value) not in (int, float) or not math.isfinite(value) or not 1 <= value <= now:
        raise ValueError("Invalid public timestamp")
    return float(value)


def validate_integration(value: Any, *, now: float) -> dict[str, Any]:
    if (
        not isinstance(value, dict)
        or set(value) != {"schema", "generated_at", "source_checkpoint", "activated_at", "rules"}
        or value["schema"] != "sudo-integration-v2"
    ):
        raise ValueError("Unknown public integration schema")
    generated = _time(value["generated_at"], now)
    rules = value["rules"]
    if (
        not isinstance(rules, dict)
        or set(rules) != {"state", "imported_total", "message"}
        or rules["state"] not in {"active", "error"}
        or not isinstance(rules["message"], str)
        or len(rules["message"]) > 256
    ):
        raise ValueError("Invalid public rule status")
    activated = value["activated_at"]
    checkpoint = value["source_checkpoint"]
    for name, stamp in (("activation", activated), ("checkpoint", checkpoint)):
        if stamp is None:
            if rules["state"] != "error":
                raise ValueError("Active rules lack a source " + name)
        elif _time(stamp, now) > generated:
            raise ValueError("Inconsistent public integration time")
    imported = rules["imported_total"]
    if type(imported) is not int or not 0 <= imported <= 1_000_000_000:
        raise ValueError("Invalid public counter")
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
    }


def read_integration(
    path: Path = PUBLIC_INTEGRATION, *, now: float | None = None
) -> dict[str, Any]:
    clock = time.time() if now is None else now
    if type(clock) not in (int, float) or not math.isfinite(clock) or clock < 1:
        raise ValueError("Invalid dashboard time")
    try:
        data = _read_json(path, MAX_SIZE, secure=True)
        return validate_integration(data, now=time.time() if now is None else clock)
    except (OSError, ValueError, TypeError, OverflowError, RecursionError):
        return {"state": "unavailable", "rules_active": False}


def require_current_run(
    path: Path = PUBLIC_INTEGRATION,
    *,
    not_before: float,
    expected_activation: float,
    now: float | None = None,
) -> dict[str, Any]:
    """Require a completed invocation, not a skipped start or older export."""
    clock = time.time() if now is None else now
    started = _time(not_before, clock)
    activated = _time(expected_activation, clock)
    if not activated <= started <= clock:
        raise ValueError("Invalid deployment snapshot expectation")
    status = read_integration(path, now=clock)
    if (
        status["state"] != "ready"
        or not status["rules_active"]
        or status["activated_at"] != activated
        or not started <= status["generated_at"] <= clock
    ):
        raise ValueError("Current sudo integration run was not verified")
    return status
