"""Publish only a bounded, anonymous production sudo summary for the web reader.

Run as yggdrasil-worker in a separate one-shot systemd unit.
Read private SQLite in query_only mode; atomically publish fixed-schema
aggregated JSON to a worker-owned, group-readable directory. Never expose
UID/PID, journal identity, commands, raw records, or secrets.
"""

from __future__ import annotations

import json
import math
import os
import sqlite3
import stat
import tempfile
import time
from contextlib import closing
from pathlib import Path

from .sudo_source import source_snapshot_guard

PRIVATE = Path("/var/lib/yggdrasil-sudo/sudo.sqlite3")
PUBLIC = Path("/var/lib/yggdrasil-sudo-public/sudo-status.json")
FORMAT = "sudo-status-v1"
CATEGORIES = (
    "command_invoked",
    "pam_auth_failure",
    "incorrect_password",
    "not_in_sudoers",
    "pam_session_opened",
    "pam_session_closed",
    "other_sudo",
)
DETECTORS = ("sudo.permission_denied", "sudo.repeated_auth_failure")
MAX_COUNT = 1_000_000_000


def _private_db(path: Path) -> None:
    if path.is_symlink() or path.parent.is_symlink() or path.name != "sudo.sqlite3":
        raise PermissionError("Expected a dedicated, non-symlink sudo staging DB")
    folder, file = path.parent.stat(), path.stat()
    if (
        folder.st_uid != os.geteuid()
        or stat.S_IMODE(folder.st_mode) & 0o077
        or not stat.S_ISREG(file.st_mode)
        or file.st_nlink != 1
        or file.st_uid != os.geteuid()
        or stat.S_IMODE(file.st_mode) & 0o077
    ):
        raise PermissionError("Refusing sudo DB without private worker ownership")


def _public_dir(folder: Path) -> None:
    if folder.is_symlink():
        raise PermissionError("Public summary folder must not be symlinked")
    info = folder.stat()
    mode = stat.S_IMODE(info.st_mode)
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or info.st_gid != os.getegid()
        or mode & 0o027
        or not mode & 0o050 == 0o050
    ):
        raise PermissionError("Public summary directory must be worker-owned, group-readable")


def _count(value: object) -> int:
    if type(value) is not int or not 0 <= value <= MAX_COUNT:
        raise ValueError("Invalid count in private sudo summary")
    return value


def build_summary(database: Path, *, now: float | None = None) -> dict:
    _private_db(database)
    now = time.time() if now is None else now
    if not math.isfinite(now) or not 1 <= now < 4_102_444_800:
        raise ValueError("Invalid summary time")
    uri = database.absolute().as_uri() + "?mode=ro"
    with source_snapshot_guard(database), closing(sqlite3.connect(uri, uri=True, timeout=5)) as db:
        db.execute("PRAGMA query_only=ON")
        db.execute("BEGIN")
        if db.execute("PRAGMA user_version").fetchone()[0] != 2:
            raise ValueError("Unexpected private sudo database schema")
        checkpoint_row = db.execute(
            "SELECT last_completed_until FROM shadow_poll_checkpoint WHERE id=1"
        ).fetchone()
        if checkpoint_row is None:
            raise ValueError("Production sudo poll has no completed checkpoint")
        checkpoint = float(checkpoint_row[0])
        if not math.isfinite(checkpoint) or not 0 <= now - checkpoint <= 180:
            raise ValueError("Invalid production sudo checkpoint")

        start = now - 86400
        total = _count(
            db.execute(
                "SELECT COUNT(*) FROM sudo_signals WHERE timestamp<=?", (checkpoint,)
            ).fetchone()[0]
        )
        total_matches = _count(
            db.execute(
                "SELECT COUNT(*) FROM sudo_candidates WHERE timestamp<=?", (checkpoint,)
            ).fetchone()[0]
        )
        recent = _count(
            db.execute(
                "SELECT COUNT(*) FROM sudo_signals WHERE timestamp > ? AND timestamp <= ?",
                (start, checkpoint),
            ).fetchone()[0]
        )
        kind_counts = {name: 0 for name in CATEGORIES}
        for kind, value in db.execute(
            "SELECT kind, COUNT(*) FROM sudo_signals "
            "WHERE timestamp > ? AND timestamp <= ? GROUP BY kind",
            (start, checkpoint),
        ):
            if kind not in kind_counts:
                raise ValueError("Unrecognized sudo category in private DB")
            kind_counts[kind] = _count(value)
        if sum(kind_counts.values()) != recent:
            raise ValueError("Sudo signal counts do not reconcile")
        detector_counts = {name: 0 for name in DETECTORS}
        for detector, value in db.execute(
            "SELECT detector_id,COUNT(*) FROM sudo_candidates "
            "WHERE timestamp > ? AND timestamp <= ? GROUP BY detector_id",
            (start, checkpoint),
        ):
            if detector not in detector_counts:
                raise ValueError("Unexpected sudo detector in private DB")
            detector_counts[detector] = _count(value)
    return {
        "format": FORMAT,
        "mode": "live",
        "generated_at": now,
        "checkpoint_at": checkpoint,
        "period_seconds": 86400,
        "total_signals": total,
        "total_candidates": total_matches,
        "recent_signals": recent,
        "categories": kind_counts,
        "candidate_detectors": detector_counts,
        "source": "worker_owned_private_sudo",
        "sends_alerts": False,
        "shares_production_database": False,
    }


ACTIVITY_FORMAT = "sudo-activity-v1"
ACTIVITY_FILE = Path("/var/lib/yggdrasil-sudo-public/sudo-activity.json")
MAX_LATEST = 15
MAX_CANDIDATES = 8


def build_activity(database: Path, *, now: float | None = None) -> dict:
    """One anonymous row per (boot, UID, PID) and recent rule candidates.

    SQL grouping is internal: no PID, UID, boot ID, command, message, cursor,
    source address or raw event identity escapes into the JSON output.
    """
    _private_db(database)
    now = time.time() if now is None else now
    if not math.isfinite(now) or not 1 <= now < 4_102_444_800:
        raise ValueError("Invalid activity export time")
    start = now - 86400
    with (
        source_snapshot_guard(database),
        closing(
            sqlite3.connect(database.absolute().as_uri() + "?mode=ro", uri=True, timeout=5)
        ) as db,
    ):
        db.execute("PRAGMA query_only=ON")
        db.execute("BEGIN")
        if db.execute("PRAGMA user_version").fetchone()[0] != 2:
            raise ValueError("Unexpected private sudo database schema")

        checkpoint_row = db.execute(
            "SELECT last_completed_until FROM shadow_poll_checkpoint WHERE id=1"
        ).fetchone()
        if checkpoint_row is None:
            raise ValueError("Missing completed sudo poll checkpoint")
        checkpoint = float(checkpoint_row[0])
        if not math.isfinite(checkpoint) or not 0 <= now - checkpoint <= 180:
            raise ValueError("Invalid sudo activity checkpoint")

        # LEFT JOIN is used only to mark processes with real stored rule matches.
        processes = db.execute(
            "SELECT MAX(s.timestamp) AS timestamp, "
            "MAX(CASE WHEN s.kind='not_in_sudoers' THEN 1 ELSE 0 END) AS denied, "
            "MAX(CASE WHEN s.kind IN ('pam_auth_failure','incorrect_password') "
            "THEN 1 ELSE 0 END) AS failed, "
            "MAX(CASE WHEN s.kind='command_invoked' THEN 1 ELSE 0 END) AS command, "
            "MAX(CASE WHEN s.kind='pam_session_opened' THEN 1 ELSE 0 END) AS opened, "
            "MAX(CASE WHEN c.detector_id='sudo.permission_denied' THEN 1 ELSE 0 END) "
            "AS denied_match, "
            "MAX(CASE WHEN c.detector_id='sudo.repeated_auth_failure' "
            "THEN 1 ELSE 0 END) AS auth_match "
            "FROM sudo_signals AS s "
            "LEFT JOIN sudo_candidates AS c ON c.event_id=s.event_id "
            "WHERE s.timestamp>? AND s.timestamp<=? "
            "GROUP BY s.boot_id,s.uid,s.pid "
            "ORDER BY timestamp DESC LIMIT ?",
            (start, checkpoint, MAX_LATEST),
        ).fetchall()

        candidates = db.execute(
            "SELECT detector_id,timestamp,process_count FROM sudo_candidates "
            "WHERE timestamp>? AND timestamp<=? "
            "ORDER BY timestamp DESC,detector_id LIMIT ?",
            (start, checkpoint, MAX_CANDIDATES),
        ).fetchall()

    latest = []
    for stamp, denied, failed, command, opened, denied_match, auth_match in processes:
        if denied:
            category = "permission_denied"
        elif failed:
            category = "authentication_failed"
        elif opened:
            category = "session_opened"
        elif command:
            category = "command_logged"
        else:
            category = "other"
        if denied_match:
            detector = "sudo.permission_denied"
        elif auth_match:
            detector = "sudo.repeated_auth_failure"
        else:
            detector = None
        latest.append(
            {
                "timestamp": float(stamp),
                "category": category,
                "attention": (
                    "rule_candidate"
                    if detector is not None
                    else "review"
                    if denied or failed
                    else "normal"
                ),
                "detector_id": detector,
            }
        )

    recent_candidates = []
    for detector, timestamp, count in candidates:
        if detector not in DETECTORS:
            raise ValueError("Unexpected sudo rule candidate ID")
        recent_candidates.append(
            {
                "timestamp": float(timestamp),
                "detector_id": detector,
                "process_count": _count(count),
            }
        )

    return {
        "format": ACTIVITY_FORMAT,
        "mode": "live",
        "generated_at": now,
        "checkpoint_at": checkpoint,
        "period_seconds": 86400,
        "latest_limit": MAX_LATEST,
        "latest": latest,
        "candidate_limit": MAX_CANDIDATES,
        "candidates": recent_candidates,
        "source": "worker_owned_private_sudo",
        "sends_alerts": False,
        "shares_production_database": False,
    }


def publish(summary: dict, target: Path) -> None:
    _public_dir(target.parent)
    if (
        target.name not in {"sudo-status.json", "sudo-activity.json", "sudo-integration.json"}
        or target.is_symlink()
    ):
        raise PermissionError("Only dedicated sudo snapshot filenames can be published")
    if target.exists():
        existing = target.stat()
        if (
            not stat.S_ISREG(existing.st_mode)
            or existing.st_uid != os.geteuid()
            or existing.st_gid != os.getegid()
            or stat.S_IMODE(existing.st_mode) & 0o137
        ):
            raise PermissionError("Refusing unsafe existing public summary")
    encoded = json.dumps(summary, sort_keys=True, separators=(",", ":"), allow_nan=False).encode(
        "utf-8"
    )
    if len(encoded) > 12_288:
        raise ValueError("Sudo public summary is unexpectedly large")
    temporary = None
    try:
        fd, name = tempfile.mkstemp(prefix=".sudo-status-", dir=target.parent)
        temporary = Path(name)
        os.fchmod(fd, 0o640)
        with os.fdopen(fd, "wb") as file:
            file.write(encoded)
            file.flush()
            os.fsync(file.fileno())
        os.replace(temporary, target)
        temporary = None
        fd = os.open(target.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
