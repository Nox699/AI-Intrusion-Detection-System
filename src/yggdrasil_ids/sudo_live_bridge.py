"""Explicitly armed bridge from private sudo rule candidates to the IDS outbox.

The private sensor remains the rule/cooldown authority. Only its anonymous
candidate identity, detector, timestamp and process count cross this boundary.
ML scores never enter this bridge. Runtime polling cannot migrate or arm a DB.
"""

from __future__ import annotations

import math
import os
import sqlite3
import stat
import time
from pathlib import Path

from .storage import SCHEMA_VERSION, Repository
from .sudo_live_source import source_snapshot_guard

ARM_KEY = "sudo_integration_activation_v1"
PROGRESS_KEY = "sudo_integration_progress_v1"
MAX_CANDIDATES = 10_000
MAX_CHECKPOINT_AGE = 180


def _epoch(value: object) -> float:
    if (
        type(value) not in (int, float)
        or not math.isfinite(value)
        or not 1 <= value < 4_102_444_800
    ):
        raise ValueError("Invalid sudo integration timestamp")
    return float(value)


def _production(db: sqlite3.Connection) -> None:
    if db.execute("PRAGMA user_version").fetchone()[0] != SCHEMA_VERSION:
        raise RuntimeError("Coordinated database migration is required before sudo integration")
    if Repository.state_in(db, "mode") != "live" or Repository.state_in(db, "namespace") != "live":
        raise RuntimeError("Sudo integration requires an existing live IDS database")
    # Never bootstrap or replace the existing notifier stream.
    if db.execute("SELECT COUNT(*) FROM discord_outbox_meta").fetchone()[0] != 1:
        raise RuntimeError("Existing IDS outbox identity is required")


def arm_rules(repository: Repository, *, now: float | None = None) -> float:
    """Record the first activation boundary; repeating this never moves it."""
    stamp = _epoch(time.time() if now is None else now)
    if not repository.path.is_file():
        raise RuntimeError("Existing IDS database is required")
    with repository.transaction() as db:
        _production(db)
        existing = repository.state_in(db, ARM_KEY)
        if existing is not None:
            return _epoch(existing)
        repository.put_state(db, ARM_KEY, stamp)
    return stamp


def _source_candidates(database: Path, activated_at: float, now: float, retention_seconds: int):
    database = Path(database)
    if database.is_symlink() or database.parent.is_symlink():
        raise PermissionError("Private sudo source must not be symlinked")
    folder, file = database.parent.stat(), database.stat()
    if (
        not stat.S_ISDIR(folder.st_mode)
        or not stat.S_ISREG(file.st_mode)
        or folder.st_uid != os.geteuid()
        or file.st_uid != os.geteuid()
        or stat.S_IMODE(folder.st_mode) & 0o077
        or stat.S_IMODE(file.st_mode) & 0o077
    ):
        raise PermissionError("Private sudo source ownership is required")
    with (
        source_snapshot_guard(database),
        sqlite3.connect(database.absolute().as_uri() + "?mode=ro", uri=True, timeout=5) as db,
    ):
        db.execute("PRAGMA query_only=ON")
        db.execute("BEGIN")
        if db.execute("PRAGMA user_version").fetchone()[0] != 2:
            raise RuntimeError("Unsupported sudo source schema")
        row = db.execute(
            "SELECT last_completed_until FROM shadow_poll_checkpoint WHERE id=1"
        ).fetchone()
        if row is None:
            raise RuntimeError("Sudo source has no completed checkpoint")
        checkpoint = _epoch(row[0])
        if not 0 <= now - checkpoint <= MAX_CHECKPOINT_AGE:
            raise RuntimeError("Sudo source checkpoint is stale or in the future")
        # Revisit the bounded retained range: a later poll may add candidates
        # whose event time precedes the last checkpoint. Evidence keys dedup.
        rows = db.execute(
            "SELECT event_id,detector_id,timestamp,process_count FROM sudo_candidates "
            "WHERE timestamp>=? AND timestamp<=? ORDER BY timestamp,event_id,detector_id LIMIT ?",
            (max(activated_at, now - retention_seconds), checkpoint, MAX_CANDIDATES + 1),
        ).fetchall()
        if len(rows) > MAX_CANDIDATES:
            raise RuntimeError("Sudo bridge candidate bound exceeded")
    return checkpoint, rows


def forward_rules(
    repository: Repository,
    source_database: Path,
    *,
    now: float | None = None,
    retention_seconds: int = 30 * 86400,
) -> dict:
    """Atomically add new post-activation rule cases and their outbox entries."""
    stamp = _epoch(time.time() if now is None else now)
    if type(retention_seconds) is not int or not 86400 <= retention_seconds <= 365 * 86400:
        raise ValueError("Invalid sudo bridge retention interval")
    if not repository.path.is_file():
        raise RuntimeError("Existing IDS database is required")
    with repository.reader() as db:
        _production(db)
        activated_at = _epoch(repository.state_in(db, ARM_KEY))
    if activated_at > stamp:
        raise RuntimeError("Sudo activation timestamp is in the future")
    checkpoint, candidates = _source_candidates(
        source_database, activated_at, stamp, retention_seconds
    )
    inserted = 0
    with repository.transaction() as db:
        _production(db)
        if repository.state_in(db, ARM_KEY) != activated_at:
            raise RuntimeError("Sudo activation changed during poll")
        progress = repository.state_in(db, PROGRESS_KEY, {})
        if checkpoint < _epoch(progress.get("source_checkpoint", checkpoint)):
            raise RuntimeError("Sudo source checkpoint moved backwards")
        total = progress.get("imported_total", 0)
        if type(total) is not int or not 0 <= total <= 1_000_000_000:
            raise RuntimeError("Invalid sudo integration progress")
        for event_id, detector_id, timestamp, process_count in candidates:
            before = db.total_changes
            repository.add_sudo_alert(
                db,
                event_id=event_id,
                detector_id=detector_id,
                timestamp=timestamp,
                process_count=process_count,
            )
            inserted += int(db.total_changes > before)
        total += inserted
        repository.put_state(
            db,
            PROGRESS_KEY,
            {"source_checkpoint": checkpoint, "imported_total": total, "updated_at": stamp},
        )
    return {
        "activated_at": activated_at,
        "source_checkpoint": checkpoint,
        "rules": {"state": "active", "imported_total": total, "message": ""},
    }
