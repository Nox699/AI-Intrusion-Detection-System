#!/usr/bin/env python3
"""Export only numeric SSH feature vectors from the live DB, read-only.

Run as yggdrasil-worker. Redirect stdout to a PRIVATE file (umask 077);
never commit that file. Only untrained, successful authentications are CANDIDATE
normal samples, not labels. No IPs, usernames, raw messages, or cursors.
"""

from __future__ import annotations

import json
import math
import sqlite3
import sys
from pathlib import Path

from yggdrasil_ids.features import FEATURE_NAMES

DATABASE = Path("/var/lib/yggdrasil-ids/events.sqlite3")
MAX_ROWS = 10000


def export(db: sqlite3.Connection) -> dict:
    db.execute("PRAGMA query_only=ON")
    count = db.execute("SELECT count(*) FROM events").fetchone()[0]
    rows = db.execute(
        "SELECT e.timestamp,o.features FROM events AS e "
        "JOIN observations AS o USING(event_id) "
        "WHERE e.outcome='success' AND o.state='untrained' "
        "ORDER BY e.timestamp,e.event_id LIMIT ?",
        (MAX_ROWS + 1,),
    ).fetchall()
    if len(rows) > MAX_ROWS:
        raise ValueError("Too many records for bounded private feature export")
    matrix = []
    stamps = []
    for stamp, raw in rows:
        values = json.loads(raw)
        if not isinstance(values, dict) or set(values) != set(FEATURE_NAMES):
            raise ValueError("Unexpected SSH observation feature schema")
        vector = [values[name] for name in FEATURE_NAMES]
        if any(type(x) not in (int, float) or not math.isfinite(x) for x in vector):
            raise ValueError("Invalid numeric feature")
        matrix.append(vector)
        stamps.append(stamp)
    return {
        "kind": "private_real_ssh_normal_candidates",
        "feature_names": list(FEATURE_NAMES),
        "window_seconds": 300,
        "all_authentication_event_count": count,
        "candidate_success_rows": len(matrix),
        "rows": matrix,
        "timestamps": stamps,
        "reviewed_as_normal": False,
        "warning": (
            "Successful SSH logins still require manual review; "
            "this file includes private numerical features and must never be committed."
        ),
    }


def main() -> int:
    try:
        if not DATABASE.is_file():
            raise ValueError("Expected live SQLite DB is absent")
        with sqlite3.connect(DATABASE.as_uri() + "?mode=ro", uri=True) as db:
            result = export(db)
        print(json.dumps(result, separators=(",", ":"), allow_nan=False))
        return 0
    except (OSError, sqlite3.Error, ValueError, TypeError, KeyError) as exc:
        print(
            f"Read-only feature export failed: {type(exc).__name__}. No data changed.",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
