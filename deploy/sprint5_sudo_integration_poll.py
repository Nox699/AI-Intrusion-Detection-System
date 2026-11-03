#!/usr/bin/env python3
"""One-shot rule integration and independent frozen-ML shadow snapshot.

This is deployment preparation, not an installer. Never starts another
notifier, opens a network connection, migrates a DB or changes a model.
"""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import stat
import tempfile
import time
from pathlib import Path

from yggdrasil_ids.config import load_config
from yggdrasil_ids.storage import Repository
from yggdrasil_ids.sudo_live_bridge import ARM_KEY, PROGRESS_KEY, arm_rules, forward_rules
from yggdrasil_ids.sudo_live_ml import build_ml_snapshot

SOURCE = Path("/var/lib/yggdrasil-sudo-shadow/sudo-shadow.sqlite3")
MODEL = Path("/var/lib/yggdrasil-sudo-integration-private/mixed_full-model.json")
PUBLIC = Path("/var/lib/yggdrasil-sudo-public/sudo-integration.json")
MODEL_VERSION = "sudo-if-15207a3b77b40fe2"
MODEL_SHA256 = "5839076103232763379a2ae401ee1590b39d22cb28e31ea272fe7ced539bf370"


def publish(path: Path, payload: dict) -> None:
    """Replace a single group-readable public snapshot, never an arbitrary link."""
    directory = path.parent.lstat()
    if (
        not stat.S_ISDIR(directory.st_mode)
        or directory.st_uid != os.geteuid()
        or directory.st_gid != os.getegid()
        or stat.S_IMODE(directory.st_mode) != 0o750
    ):
        raise PermissionError("Expected worker-owned public sudo directory")
    if path.is_symlink():
        raise PermissionError("Refusing linked public sudo snapshot")
    if path.exists():
        target = path.lstat()
        if not stat.S_ISREG(target.st_mode) or target.st_uid != os.geteuid():
            raise PermissionError("Invalid public sudo snapshot ownership")
    data = json.dumps(payload, ensure_ascii=False, allow_nan=False, separators=(",", ":"))
    if len(data.encode("utf-8")) > 65_536:
        raise ValueError("Public sudo snapshot exceeds bound")
    fd, temporary = tempfile.mkstemp(prefix=".sudo-integration-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(data + "\n")
            stream.flush()
            os.fchmod(stream.fileno(), 0o640)
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def run_once(
    repository: Repository,
    source: Path,
    model: Path,
    *,
    retention_seconds: int,
    now: float | None = None,
) -> dict:
    stamp = time.time() if now is None else now
    # Refuse to advertise activation until the explicit deployment arm step.
    with Repository(repository.path, readonly=True).reader() as db:
        activated = repository.state_in(db, ARM_KEY)
        progress = repository.state_in(db, PROGRESS_KEY, {})
    if type(activated) not in (int, float) or not 1 <= activated <= stamp:
        raise RuntimeError("Sudo rules have not been explicitly armed")
    try:
        rules = forward_rules(repository, source, now=stamp, retention_seconds=retention_seconds)
    except (OSError, ValueError, RuntimeError, sqlite3.Error):
        rules = {
            "activated_at": activated,
            "source_checkpoint": None,
            "rules": {
                "state": "error",
                "imported_total": progress.get("imported_total", 0),
                "message": "Sudo rule integration unavailable; inspect the local worker service",
            },
        }
    try:
        ml = build_ml_snapshot(source, model, MODEL_VERSION, MODEL_SHA256, now=stamp)
    except (OSError, ValueError, RuntimeError, sqlite3.Error):
        ml = {
            "state": "unavailable",
            "message": "Frozen sudo ML snapshot unavailable; no ML alerts are emitted",
        }
    return {"schema": "sudo-integration-v1", "generated_at": stamp, **rules, "ml": ml}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=Path("/etc/yggdrasil-ids/config.toml"))
    parser.add_argument(
        "--arm", action="store_true", help="Explicitly set activation boundary only"
    )
    args = parser.parse_args()
    if os.geteuid() == 0:
        raise SystemExit("STOP: Run as the unprivileged IDS worker")
    config = load_config(args.config)
    if config.mode != "live":
        raise SystemExit("STOP: Existing live IDS configuration required")
    repository = Repository(config.database_path)
    if args.arm:
        activated = arm_rules(repository)
        print(json.dumps({"armed_at": activated, "historical_candidates_imported": False}))
        return
    payload = run_once(repository, SOURCE, MODEL, retention_seconds=config.retention_days * 86400)
    publish(PUBLIC, payload)
    print(
        json.dumps(
            {
                "rules_state": payload["rules"]["state"],
                "registered_rule_cases": payload["rules"]["imported_total"],
                "ml_state": "shadow" if payload["ml"].get("format") else "unavailable",
                "ml_alerts_emitted": False,
            }
        )
    )
    if payload["rules"]["state"] != "active" or payload["ml"].get("state") == "unavailable":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
