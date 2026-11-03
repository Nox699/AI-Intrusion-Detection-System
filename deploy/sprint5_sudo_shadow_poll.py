#!/usr/bin/env python3
"""Gated, one-shot, persistent *shadow only* sudo journal sensor.

Run once via a systemd timer as unprivileged yggdrasil-worker. A private
worker-owned SQLite DB stores only normalized sudo categories, a journal
identity digest, and rule candidates. This never touches production events,
outbox, Discord, webhook credentials or any network interface.

Poll checkpoints are committed only after the complete, bounded journal
snapshot. Each pass replays overlapping history to reconstruct the 5-minute
window/cooldown and deduplicates stored rows. No lossless guarantee is made
for rotated journals, clock jumps or outages longer than MAX_OUTAGE_SECONDS.
"""

from __future__ import annotations

import argparse
import fcntl
import json
import math
import os
import selectors
import sqlite3
import subprocess
import sys
import time
from collections import Counter
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterable, Iterator

from yggdrasil_ids.sudo_rules import SudoRuleDetector, parse_sudo
from yggdrasil_ids.sudo_storage import SudoStagingStore

MAX_ROWS = 3_000
MAX_LINE_BYTES = 65_536
JOURNAL_TIMEOUT_SECONDS = 20
INITIAL_HISTORY_SECONDS = 900
OVERLAP_SECONDS = 661  # 300-second failure window + 300-second cooldown + 61 seconds
MAX_OUTAGE_SECONDS = 48 * 3_600
SCHEMA = """
CREATE TABLE IF NOT EXISTS shadow_poll_checkpoint (
 id INTEGER PRIMARY KEY CHECK(id=1),
 last_completed_until REAL NOT NULL
)
"""
FIELDS = "MESSAGE,_EXE,_UID,_PID,_BOOT_ID,__CURSOR,__REALTIME_TIMESTAMP"
DETECTORS = ("sudo.repeated_auth_failure", "sudo.permission_denied")


def journal_command(since: float, until: float) -> list[str]:
    if not (
        math.isfinite(since)
        and math.isfinite(until)
        and 0 <= since < until < 4_102_444_800
        and until - since <= MAX_OUTAGE_SECONDS + OVERLAP_SECONDS
    ):
        raise ValueError("Sudo shadow journal bounds are invalid or too old")
    return [
        "journalctl",
        "--quiet",
        "--no-pager",
        "--all",
        "--output=json",
        "--output-fields=" + FIELDS,
        f"--since=@{since:.6f}",
        f"--until=@{until:.6f}",
        "_EXE=/usr/bin/sudo",
    ]


def journal_records(since: float, until: float) -> Iterator[dict[str, Any]]:
    """Time- and size-bounded journal reader; never prints raw records."""
    child = subprocess.Popen(
        journal_command(since, until),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        bufsize=0,
        env={**os.environ, "LC_ALL": "C", "SYSTEMD_COLORS": "0"},
    )
    selector = selectors.DefaultSelector()
    buffer = b""
    deadline = time.monotonic() + JOURNAL_TIMEOUT_SECONDS
    count = 0
    try:
        assert child.stdout is not None
        selector.register(child.stdout, selectors.EVENT_READ)
        while selector.get_map():
            if time.monotonic() >= deadline:
                raise TimeoutError("Filtered sudo journal query timed out")
            ready = selector.select(min(0.5, max(0, deadline - time.monotonic())))
            if not ready and child.poll() is not None:
                # An exited reader may still have buffered stdout: keep reading
                # until the EOF notification arrives.
                continue
            for key, _ in ready:
                chunk = os.read(key.fileobj.fileno(), 16_384)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                buffer += chunk
                while b"\n" in buffer:
                    raw, buffer = buffer.split(b"\n", 1)
                    count += 1
                    if count > MAX_ROWS or len(raw) > MAX_LINE_BYTES:
                        raise ValueError("Bounded sudo journal query exceeded limits")
                    try:
                        record = json.loads(raw)
                    except (ValueError, UnicodeError, RecursionError) as exc:
                        raise ValueError("Invalid sudo journal JSON") from exc
                    if not isinstance(record, dict):
                        raise ValueError("Invalid sudo journal object")
                    yield record
                if len(buffer) > MAX_LINE_BYTES:
                    raise ValueError("Oversized sudo journal record")
        if buffer:
            raise ValueError("Truncated sudo journal record")
        remaining = max(0.1, deadline - time.monotonic())
        if child.wait(timeout=remaining) != 0:
            raise RuntimeError("Filtered sudo journal query failed")
    finally:
        selector.close()
        if child.poll() is None:
            child.terminate()
            try:
                child.wait(timeout=3)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()
        if child.stdout is not None:
            child.stdout.close()


@contextmanager
def exclusive_state(path: Path):
    """No concurrent poll can race a checkpoint or SQLite insert."""
    flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        os.close(fd)


def previous_checkpoint(path: Path) -> float | None:
    with sqlite3.connect(path) as db:
        db.execute(SCHEMA)
        row = db.execute(
            "SELECT last_completed_until FROM shadow_poll_checkpoint WHERE id=1"
        ).fetchone()
    if row is None:
        return None
    last = float(row[0])
    if not math.isfinite(last) or not 0 < last < 4_102_444_800:
        raise ValueError("Corrupt private sudo poll checkpoint")
    return last


def complete_checkpoint(path: Path, previous: float | None, until: float) -> None:
    with sqlite3.connect(path, timeout=5) as db:
        db.execute("BEGIN IMMEDIATE")
        row = db.execute(
            "SELECT last_completed_until FROM shadow_poll_checkpoint WHERE id=1"
        ).fetchone()
        current = float(row[0]) if row is not None else None
        if current != previous:
            raise RuntimeError("Sudo checkpoint changed during isolated poll")
        db.execute(
            "INSERT INTO shadow_poll_checkpoint(id,last_completed_until) VALUES(1,?) "
            "ON CONFLICT(id) DO UPDATE SET last_completed_until=excluded.last_completed_until",
            (until,),
        )


def poll_once(
    database: Path,
    *,
    now: float | None = None,
    records: Iterable[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    if os.geteuid() == 0:
        raise PermissionError("The sudo shadow sensor must run unprivileged")
    database = Path(database)
    if database.name != "sudo-shadow.sqlite3":
        raise ValueError("Use a separately named sudo-shadow.sqlite3 staging database")
    if database.parent == Path("/var/lib/yggdrasil-ids"):
        raise ValueError("Production IDS state is forbidden for sudo shadow")
    now = time.time() if now is None else now
    if not math.isfinite(now) or not 1 <= now < 4_102_444_800:
        raise ValueError("Invalid sudo poll time")
    until = now - 2.0
    store = SudoStagingStore(database)
    store.initialize()
    with exclusive_state(database.parent / "shadow-poll.lock"):
        prior = previous_checkpoint(database)
        if prior is not None:
            if prior > until or until - prior > MAX_OUTAGE_SECONDS:
                raise RuntimeError("Gap or clock jump: manual sudo shadow recovery required")
            since = max(0.0, prior - OVERLAP_SECONDS)
        else:
            since = until - INITIAL_HISTORY_SECONDS
        journal_command(since, until)

        rules = SudoRuleDetector()
        metrics: Counter[str] = Counter()
        categories: Counter[str] = Counter()
        matches: Counter[str] = Counter()
        journal = journal_records(since, until) if records is None else records
        for record in journal:
            metrics["read"] += 1
            if metrics["read"] > MAX_ROWS:
                raise ValueError("Sudo shadow poll exceeded bounded event count")
            parsed = parse_sudo(record)
            if parsed.status != "event" or parsed.signal is None:
                raise ValueError("Sudo journal record failed trusted metadata validation")
            signal = parsed.signal
            categories[signal.kind] += 1
            match = rules.evaluate(signal)
            if store.append(signal, match):
                metrics["new"] += 1
                if match:
                    matches[match.detector_id] += 1
            else:
                metrics["duplicates"] += 1

        # Do not advance a poll boundary after an incomplete/invalid journal read.
        complete_checkpoint(database, prior, until)
        store.prune(now - 30 * 86_400)
        result: dict[str, Any] = {
            "kind": "persistent_sudo_shadow_poll",
            "mode": "shadow",
            "previous_checkpoint_present": prior is not None,
            "journal_rows_read": metrics["read"],
            "new_normalized_sudo_rows": metrics["new"],
            "overlap_duplicates_skipped": metrics["duplicates"],
            "sudo_categories_in_snapshot": dict(categories),
            "new_candidate_rule_matches": {name: matches[name] for name in DETECTORS},
            "private_staging_summary": store.summary(),
            "private_database_only": True,
            "production_database_modified": False,
            "discord_alerts_sent": 0,
            "network_access_required": False,
            "lossless_journal_recovery_guarantee": False,
        }
        return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--database",
        type=Path,
        default=Path("/var/lib/yggdrasil-sudo-shadow/sudo-shadow.sqlite3"),
    )
    args = parser.parse_args(argv)
    os.umask(0o077)
    try:
        report = poll_once(args.database)
    except (
        OSError,
        ValueError,
        RuntimeError,
        PermissionError,
        sqlite3.Error,
        subprocess.SubprocessError,
    ):
        print(
            "STOP: Private sudo shadow poll failed; checkpoint not guaranteed to advance",
            file=sys.stderr,
        )
        return 1
    print(json.dumps(report, sort_keys=True, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
