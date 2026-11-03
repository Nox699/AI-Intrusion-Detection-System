#!/usr/bin/env python3
"""Publish only a bounded, anonymous sudo shadow summary for the web reader.

Run as yggdrasil-worker in a separate one-shot systemd unit.
Read private SQLite in query_only mode; atomically publish fixed-schema
aggregated JSON to a worker-owned, group-readable directory. Never expose
UID/PID, journal identity, commands, raw records, or secrets.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import sqlite3
import stat
import tempfile
import time
from pathlib import Path

PRIVATE = Path("/var/lib/yggdrasil-sudo-shadow/sudo-shadow.sqlite3")
PUBLIC = Path("/var/lib/yggdrasil-sudo-public/sudo-status.json")
FORMAT = "sudo-shadow-summary-v1"
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
    if path.is_symlink() or path.name != "sudo-shadow.sqlite3":
        raise PermissionError("Expected a dedicated, non-symlink sudo staging DB")
    folder, file = path.parent.stat(), path.stat()
    if (
        folder.st_uid != os.geteuid()
        or stat.S_IMODE(folder.st_mode) & 0o077
        or not stat.S_ISREG(file.st_mode)
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
    uri = "file:" + str(database) + "?mode=ro"
    with sqlite3.connect(uri, uri=True, timeout=5) as db:
        db.execute("PRAGMA query_only=ON")
        if db.execute("PRAGMA user_version").fetchone()[0] != 2:
            raise ValueError("Unexpected private sudo database schema")
        checkpoint_row = db.execute(
            "SELECT last_completed_until FROM shadow_poll_checkpoint WHERE id=1"
        ).fetchone()
        if checkpoint_row is None:
            raise ValueError("Sudo shadow poll has no completed checkpoint")
        checkpoint = float(checkpoint_row[0])
        if not math.isfinite(checkpoint) or not 0 < checkpoint <= now + 60:
            raise ValueError("Invalid sudo shadow checkpoint")

        start = now - 86400
        total = _count(db.execute("SELECT COUNT(*) FROM sudo_signals").fetchone()[0])
        total_matches = _count(
            db.execute("SELECT COUNT(*) FROM sudo_candidates").fetchone()[0]
        )
        recent = _count(
            db.execute(
                "SELECT COUNT(*) FROM sudo_signals WHERE timestamp > ? AND timestamp <= ?",
                (start, now),
            ).fetchone()[0]
        )
        kind_counts = {name: 0 for name in CATEGORIES}
        for kind, value in db.execute(
            "SELECT kind, COUNT(*) FROM sudo_signals "
            "WHERE timestamp > ? AND timestamp <= ? GROUP BY kind",
            (start, now),
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
            (start, now),
        ):
            if detector not in detector_counts:
                raise ValueError("Unexpected sudo detector in private DB")
            detector_counts[detector] = _count(value)
    return {
        "format": FORMAT,
        "mode": "shadow",
        "generated_at": now,
        "checkpoint_at": checkpoint,
        "period_seconds": 86400,
        "total_signals": total,
        "total_candidates": total_matches,
        "recent_signals": recent,
        "categories": kind_counts,
        "candidate_detectors": detector_counts,
        "source": "worker_owned_private_sudo_staging",
        "sends_alerts": False,
        "shares_production_database": False,
    }


def publish(summary: dict, target: Path) -> None:
    _public_dir(target.parent)
    if target.name != "sudo-status.json" or target.is_symlink():
        raise PermissionError("Only the dedicated sudo-status.json can be published")
    if target.exists():
        existing = target.stat()
        if (
            not stat.S_ISREG(existing.st_mode)
            or existing.st_uid != os.geteuid()
            or existing.st_gid != os.getegid()
            or stat.S_IMODE(existing.st_mode) & 0o137
        ):
            raise PermissionError("Refusing unsafe existing public summary")
    encoded = json.dumps(
        summary, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")
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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", type=Path, default=PRIVATE)
    parser.add_argument("--destination", type=Path, default=PUBLIC)
    args = parser.parse_args(argv)
    if os.geteuid() == 0:
        parser.error("Never export sudo signals as root")
    os.umask(0o027)
    summary = build_summary(args.database)
    publish(summary, args.destination)
    print(
        json.dumps(
            {
                "kind": "sudo_ui_summary_export",
                "mode": "shadow",
                "checkpoint_at": summary["checkpoint_at"],
                "recent_signals": summary["recent_signals"],
                "recent_candidates": sum(summary["candidate_detectors"].values()),
                "anonymous_public_summary": True,
                "production_database_modified": False,
                "discord_alerts_sent": 0,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
