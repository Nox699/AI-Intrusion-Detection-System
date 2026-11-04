"""Anonymous alert revisions for browser-local seen markers; no database writes."""

from __future__ import annotations

import math
import re
import time

from .storage import Repository

SECTIONS = ("ssh", "preauth", "network", "sudo", "alerts")
MEANING = "browser_unseen_alert_revisions_v1"
MAX_CASES = 10_000


def section(detector: str) -> str:
    if detector == "ssh.preauth_burst":
        return "preauth"
    for prefix in ("ssh", "network", "sudo"):
        if detector.startswith(prefix + "."):
            return prefix
    return "other"


def snapshot(repository: Repository, *, now: float | None = None) -> dict:
    end = time.time() if now is None else now
    with repository.reader() as db:
        instance = db.execute("SELECT instance FROM discord_outbox_meta WHERE id=1").fetchone()
        if not instance or not re.fullmatch(r"[0-9a-f]{32}", instance[0]):
            raise ValueError("Missing alert source identity")
        rows = db.execute(
            "SELECT id,detector_id,count,last_seen FROM alerts "
            "WHERE last_seen>=? AND last_seen<=? ORDER BY id LIMIT ?",
            (end - 86400, end, MAX_CASES + 1),
        ).fetchall()
    if len(rows) > MAX_CASES:
        raise ValueError("Navigation snapshot exceeds bounded case count")
    cases = []
    counts = dict.fromkeys(SECTIONS, 0)
    for row in rows:
        if (
            type(row["id"]) is not int
            or not 1 <= row["id"] <= 2**53 - 1
            or type(row["count"]) is not int
            or not 1 <= row["count"] <= 2**53 - 1
            or not math.isfinite(row["last_seen"])
        ):
            raise ValueError("Invalid alert revision")
        bucket = section(row["detector_id"])
        cases.append(
            {
                "id": row["id"],
                "section": bucket,
                "count": row["count"],
                "last_seen": row["last_seen"],
            }
        )
        counts["alerts"] += 1
        if bucket in counts:
            counts[bucket] += 1
    return {
        "meaning": MEANING,
        "period_hours": 24,
        "instance": instance[0],
        "counts": counts,
        "cases": cases,
    }
