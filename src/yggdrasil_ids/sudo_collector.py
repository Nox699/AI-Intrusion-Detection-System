"""Bounded production sudo journal collection with persistent replay checkpoints.

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

import fcntl
import json
import math
import os
import selectors
import sqlite3
import stat
import subprocess
import time
from collections import Counter
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterable, Iterator

from .sudo_rules import SudoRuleConfig, SudoRuleDetector, parse_sudo
from .sudo_storage import SudoStagingStore

MAX_ROWS = 3_000
MAX_LINE_BYTES = 65_536
JOURNAL_TIMEOUT_SECONDS = 20
INITIAL_HISTORY_SECONDS = 900
MAX_OUTAGE_SECONDS = 48 * 3_600
SCHEMA = """
CREATE TABLE IF NOT EXISTS shadow_poll_checkpoint (
 id INTEGER PRIMARY KEY CHECK(id=1),
 last_completed_until REAL NOT NULL
)
"""
RULE_SETTINGS_SCHEMA = """
CREATE TABLE IF NOT EXISTS sudo_rule_settings (
 id INTEGER PRIMARY KEY CHECK(id=1),
 window_seconds INTEGER NOT NULL,
 failure_process_threshold INTEGER NOT NULL,
 cooldown_seconds INTEGER NOT NULL
)
"""
FIELDS = "MESSAGE,_EXE,_UID,_PID,_BOOT_ID,__CURSOR,__REALTIME_TIMESTAMP"
DETECTORS = ("sudo.repeated_auth_failure", "sudo.permission_denied")


def journal_command(since: float, until: float, *, executable: str = "journalctl") -> list[str]:
    if not isinstance(executable, str) or not executable or "\x00" in executable:
        raise ValueError("Invalid journal executable")
    if not (
        math.isfinite(since)
        and math.isfinite(until)
        and 0 <= since < until < 4_102_444_800
        and until - since <= MAX_OUTAGE_SECONDS + 7261
    ):
        raise ValueError("Production sudo journal bounds are invalid or too old")
    return [
        executable,
        "--quiet",
        "--no-pager",
        "--all",
        "--output=json",
        "--output-fields=" + FIELDS,
        f"--since=@{since:.6f}",
        f"--until=@{until:.6f}",
        "_EXE=/usr/bin/sudo",
    ]


def journal_records(
    since: float, until: float, *, executable: str = "journalctl"
) -> Iterator[dict[str, Any]]:
    """Time- and size-bounded journal reader; never prints raw records."""
    child = subprocess.Popen(
        journal_command(since, until, executable=executable),
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
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) != 0o600
        ):
            raise PermissionError("Private sudo lock ownership is required")
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


def _require_worker() -> None:
    if os.geteuid() == 0:
        raise PermissionError("The sudo sensor must run unprivileged")


def private_directory(directory: Path) -> None:
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = directory.lstat()
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        raise PermissionError("Private sudo directory ownership is required")


def _rule_settings(database: Path, config: SudoRuleConfig, prior: float | None) -> None:
    """A changed rule policy must not silently reinterpret retained replay rows."""
    expected = (config.window_seconds, config.failure_process_threshold, config.cooldown_seconds)
    with sqlite3.connect(database, timeout=5) as db:
        db.execute(RULE_SETTINGS_SCHEMA)
        existing = db.execute(
            "SELECT window_seconds,failure_process_threshold,cooldown_seconds "
            "FROM sudo_rule_settings WHERE id=1"
        ).fetchone()
        if existing is not None and existing != expected:
            raise RuntimeError("Sudo rule settings changed; explicit migration is required")
        # The deployed predecessor used these defaults and had no settings row.
        if existing is None and prior is not None and expected != (300, 3, 300):
            raise RuntimeError("Legacy sudo rule settings require the original production defaults")
        if existing is None:
            db.execute("INSERT INTO sudo_rule_settings VALUES(1,?,?,?)", expected)


def _seed_cooldowns(database: Path, rules: SudoRuleDetector, since: float, until: float) -> None:
    """Persisted matches anchor cooldown when the replay's leading edge moves.

    Earlier rows still rebuild process windows, but cannot invent a different
    historical trigger and shift the next eligible production rule decision.
    """
    with sqlite3.connect(database, timeout=5) as db:
        rows = db.execute(
            "SELECT s.boot_id,s.uid,c.detector_id,MAX(c.timestamp) FROM sudo_candidates c "
            "JOIN sudo_signals s ON s.event_id=c.event_id "
            "WHERE c.timestamp>=? AND c.timestamp<=? "
            "GROUP BY s.boot_id,s.uid,c.detector_id",
            (since - rules.config.cooldown_seconds, until),
        ).fetchall()
    for boot, uid, detector, stamp in rows:
        if (
            detector not in DETECTORS
            or type(stamp) not in (int, float)
            or not math.isfinite(stamp)
            or not 0 <= stamp <= until
        ):
            raise ValueError("Invalid persisted sudo cooldown")
        rules.last_match[(boot, uid, detector)] = stamp


def poll_once(
    database: Path,
    *,
    now: float | None = None,
    records: Iterable[dict[str, Any]] | None = None,
    rule_config: SudoRuleConfig | None = None,
    retention_days: int = 30,
    executable: str = "journalctl",
) -> dict[str, Any]:
    _require_worker()
    database = Path(database)
    if database.name != "sudo.sqlite3":
        raise ValueError("Use the dedicated sudo.sqlite3 private database")
    if database.parent.resolve() == Path("/var/lib/yggdrasil-ids"):
        raise ValueError("Sudo signals require a separate private data directory")
    if type(retention_days) is not int or not 1 <= retention_days <= 365:
        raise ValueError("Invalid sudo retention interval")
    config = rule_config or SudoRuleConfig()
    overlap = config.window_seconds + config.cooldown_seconds + 61
    now = time.time() if now is None else now
    if type(now) not in (int, float) or not math.isfinite(now) or not 3 <= now < 4_102_444_800:
        raise ValueError("Invalid sudo poll time")
    # Match journalctl's six-digit timestamp precision exactly. A rounded-up
    # --until must not return a valid microsecond row we then reject as newer.
    until = math.floor((now - 2.0) * 1_000_000) / 1_000_000
    store = SudoStagingStore(database)
    private_directory(database.parent)
    with exclusive_state(database.parent / "sudo-poll.lock"):
        store.initialize()
        prior = previous_checkpoint(database)
        if prior is not None:
            if prior > until or until - prior > MAX_OUTAGE_SECONDS:
                raise RuntimeError("Gap or clock jump: manual sudo recovery required")
            since = max(0.0, round(prior - overlap, 6))
        else:
            since = max(0.0, round(until - max(INITIAL_HISTORY_SECONDS, overlap), 6))
        journal_command(since, until, executable=executable)
        _rule_settings(database, config, prior)

        rules = SudoRuleDetector(config)
        _seed_cooldowns(database, rules, since, until)
        metrics: Counter[str] = Counter()
        categories: Counter[str] = Counter()
        matches: Counter[str] = Counter()
        # Stage only normalized, bounded signals in MEMORY. An incomplete
        # journal stream must never persist a signal without its later
        # candidate: replaying that duplicate could silently lose evidence.
        staged = []
        journal = (
            journal_records(since, until, executable=executable) if records is None else records
        )
        for record in journal:
            metrics["read"] += 1
            if metrics["read"] > MAX_ROWS:
                raise ValueError("Production sudo poll exceeded bounded event count")
            parsed = parse_sudo(record)
            if parsed.status != "event" or parsed.signal is None:
                raise ValueError("Sudo journal record failed trusted metadata validation")
            signal = parsed.signal
            if not since <= signal.timestamp <= until:
                raise ValueError("Sudo journal row is outside the requested snapshot")
            categories[signal.kind] += 1
            match = rules.evaluate(signal)
            staged.append((signal, match))

        # Journal subprocess has now exited successfully and all records are
        # validated. Database writes can begin. Each append atomically stores
        # both the normalized signal AND its candidate (if any).
        for signal, match in staged:
            if store.append(signal, match):
                metrics["new"] += 1
                if match:
                    matches[match.detector_id] += 1
            else:
                metrics["duplicates"] += 1

        # Do not advance a poll boundary after an incomplete/invalid journal read.
        complete_checkpoint(database, prior, until)
        store.prune(max(0, now - retention_days * 86_400))
        result: dict[str, Any] = {
            "kind": "sudo_collection",
            "mode": "live",
            "previous_checkpoint_present": prior is not None,
            "journal_rows_read": metrics["read"],
            "new_normalized_sudo_rows": metrics["new"],
            "overlap_duplicates_skipped": metrics["duplicates"],
            "sudo_categories_in_snapshot": dict(categories),
            "new_candidate_rule_matches": {name: matches[name] for name in DETECTORS},
            "source_checkpoint": until,
            "private_database_only": True,
            "production_database_modified": False,
            "discord_alerts_sent": 0,
            "network_access_required": False,
            "lossless_journal_recovery_guarantee": False,
        }
        return result
