"""One production sudo job: collect privately, register rules, publish safe views.

No model is loaded and no network connection is opened. The existing notifier
owns delivery of the production outbox. Only explicit installation can arm the
rule bridge; a scheduled poll never creates or moves its activation boundary.
"""

from __future__ import annotations

import math
import sqlite3
import subprocess
import time
from pathlib import Path
from typing import Any, Iterable

from .config import AppConfig
from .storage import Repository
from .sudo_bridge import ARM_KEY, PROGRESS_KEY, arm_rules, forward_rules
from .sudo_collector import _require_worker, exclusive_state, poll_once, private_directory
from .sudo_export import build_activity, build_summary, publish
from .sudo_rules import SudoRuleConfig


class SudoServiceError(RuntimeError):
    """A scheduled run could not establish a healthy, complete sudo pipeline."""


def _configuration(config: AppConfig) -> tuple[Repository, Path, Path]:
    if config.mode != "live" or config.sudo.enabled is not True:
        raise ValueError("Sudo production collection is not enabled")
    database = Path(config.sudo_database_path)
    public = Path(config.sudo_public_directory)
    if database.parent.resolve() == config.database_path.parent.resolve():
        raise ValueError("Private sudo data must be separate from production alarm data")
    if not config.database_path.is_file():
        raise RuntimeError("Existing production IDS database required")
    return Repository(config.database_path), database, public


def arm(config: AppConfig, *, now: float | None = None) -> float:
    """Explicit initial installation action; repeating it preserves activation."""
    _require_worker()
    repository, _, _ = _configuration(config)
    return arm_rules(repository, now=now)


def _activation(repository: Repository, now: float) -> tuple[float | None, int]:
    with Repository(repository.path, readonly=True).reader() as db:
        activated = repository.state_in(db, ARM_KEY)
        progress = repository.state_in(db, PROGRESS_KEY, {})
    if (
        type(activated) not in (int, float)
        or not math.isfinite(activated)
        or not 1 <= activated <= now
    ):
        activated = None
    total = progress.get("imported_total", 0) if isinstance(progress, dict) else 0
    if type(total) is not int or not 0 <= total <= 1_000_000_000:
        total = 0
    return activated, total


def run_once(
    config: AppConfig,
    *,
    now: float | None = None,
    records: Iterable[dict[str, Any]] | None = None,
) -> dict:
    """Run one bounded poll; publish a final readiness marker after safe views.

    `records` is an internal dependency-injection seam for deterministic unit
    tests. The production CLI always uses the trusted journal reader. Errors
    expose a fixed public message rather than private journal or exception text.
    """
    _require_worker()
    stamp = time.time() if now is None else now
    if (
        type(stamp) not in (int, float)
        or not math.isfinite(stamp)
        or not 3 <= stamp < 4_102_444_800
    ):
        raise ValueError("Invalid sudo pipeline time")
    repository, database, public = _configuration(config)
    try:
        private_directory(database.parent)
        # Only the lock owner may publish success OR failure. A duplicate CLI
        # invocation cannot replace another job's freshly completed marker.
        with exclusive_state(database.parent / "sudo-service.lock"):
            return _run_locked(config, repository, database, public, stamp, records)
    except BlockingIOError:
        raise SudoServiceError("A sudo production poll is already running") from None
    except (OSError, ValueError, sqlite3.Error):
        raise SudoServiceError("Sudo private state could not be locked safely") from None


def _run_locked(config, repository, database, public, stamp, records):
    activated, imported = None, 0
    try:
        activated, imported = _activation(repository, stamp)
        if activated is None:
            raise RuntimeError("Sudo production rules have not been explicitly armed")
        poll_once(
            database,
            now=stamp,
            records=records,
            retention_days=config.retention_days,
            executable=config.collector.executable,
            rule_config=SudoRuleConfig(
                window_seconds=config.sudo.window_seconds,
                failure_process_threshold=config.sudo.failure_process_threshold,
                cooldown_seconds=config.sudo.cooldown_seconds,
            ),
        )
        rules = forward_rules(
            repository,
            database,
            now=stamp,
            retention_seconds=config.retention_days * 86400,
        )
        summary = build_summary(database, now=stamp)
        activity = build_activity(database, now=stamp)
        if not summary["checkpoint_at"] == activity["checkpoint_at"] == rules["source_checkpoint"]:
            raise RuntimeError("Sudo source changed during publication")
        result = {"schema": "sudo-integration-v2", "generated_at": stamp, **rules}
        # The integration file is the final completion marker. A publication
        # failure cannot advertise a new successful pipeline snapshot.
        publish(activity, public / "sudo-activity.json")
        publish(summary, public / "sudo-status.json")
        publish(result, public / "sudo-integration.json")
        return result
    except (OSError, ValueError, RuntimeError, sqlite3.Error, subprocess.SubprocessError):
        try:
            activated, imported = _activation(repository, stamp)
        except (OSError, ValueError, sqlite3.Error):
            pass
        failed = {
            "schema": "sudo-integration-v2",
            "generated_at": stamp,
            "source_checkpoint": None,
            "activated_at": activated,
            "rules": {
                "state": "error",
                "imported_total": imported,
                "message": "Sudo collection or rule integration unavailable; inspect the worker service",
            },
        }
        try:
            publish(failed, public / "sudo-integration.json")
        except (OSError, ValueError):
            # An unsafe/unwritable public directory must not be bypassed. The
            # previous export ages out and the failed service remains visible.
            pass
        raise SudoServiceError("Sudo production poll failed; inspect the worker service") from None
