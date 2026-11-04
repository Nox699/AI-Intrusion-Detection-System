"""Private, opt-in SQLite staging store for *normalized* sudo signals only.

The separate journal poll owns this store. The live bridge imports only
redacted rule evidence into the production IDS; web reads anonymous exports.

Never persist sudo MESSAGE/COMMAND, raw journal JSON, username, or journal
cursor: only a cursor hash, timestamps, coarse category and numeric metadata
needed for process grouping. The entire database belongs to a private worker-
owned directory; no web process is granted access.
"""

from __future__ import annotations

import hashlib
import math
import os
import re
import sqlite3
import stat
from collections import Counter
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from .sudo_rules import KINDS, SudoRuleMatch, SudoSignal

SCHEMA_VERSION = 2
DETECTOR_IDS = frozenset({"sudo.repeated_auth_failure", "sudo.permission_denied"})
_BOOT = re.compile(r"[0-9a-fA-F]{32}\Z")
_DIGITS = re.compile(r"[0-9]+\Z")
SCHEMA = """
CREATE TABLE IF NOT EXISTS sudo_signals (
  event_id TEXT PRIMARY KEY,
  timestamp REAL NOT NULL,
  kind TEXT NOT NULL,
  boot_id TEXT NOT NULL,
  uid TEXT NOT NULL,
  pid INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS sudo_signals_time ON sudo_signals(timestamp);
CREATE INDEX IF NOT EXISTS sudo_signals_group ON sudo_signals(boot_id,uid,timestamp);
CREATE TABLE IF NOT EXISTS sudo_candidates (
  event_id TEXT NOT NULL REFERENCES sudo_signals(event_id) ON DELETE CASCADE,
  detector_id TEXT NOT NULL,
  timestamp REAL NOT NULL,
  severity TEXT NOT NULL,
  process_count INTEGER NOT NULL,
  PRIMARY KEY (event_id,detector_id)
);
CREATE INDEX IF NOT EXISTS sudo_candidates_time ON sudo_candidates(timestamp);
-- Store ONLY the maximum committed event timestamp, not a raw journald cursor.
-- This permits timestamp-overlap replay without persisting the private cursor.
CREATE TABLE IF NOT EXISTS sudo_checkpoint (
  id INTEGER PRIMARY KEY CHECK(id=1),
  last_committed_timestamp REAL NOT NULL
);
-- Safe migration of any pre-existing private schema-v1 staging DB.
INSERT OR IGNORE INTO sudo_checkpoint(id,last_committed_timestamp)
SELECT 1,MAX(timestamp) FROM sudo_signals HAVING COUNT(*)>0;
"""


def event_id(signal: SudoSignal) -> str:
    """Derive stable, non-reversible journal identity without storing cursor."""
    raw = ("sudo-v1\0" + signal.boot_id + "\0" + signal.cursor).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def validate_signal(signal: object) -> SudoSignal:
    if not isinstance(signal, SudoSignal):
        raise ValueError("Expected a normalized sudo signal")
    if (
        not isinstance(signal.cursor, str)
        or not 1 <= len(signal.cursor) <= 4096
        or not isinstance(signal.boot_id, str)
        or _BOOT.fullmatch(signal.boot_id) is None
        or signal.kind not in KINDS
        or not isinstance(signal.uid, str)
        or _DIGITS.fullmatch(signal.uid) is None
        or not 0 <= int(signal.uid) <= 2**32 - 1
        or type(signal.pid) is not int
        or not 1 <= signal.pid <= 2**31 - 1
        or type(signal.timestamp) not in (int, float)
        or not math.isfinite(signal.timestamp)
        or not 0 <= signal.timestamp < 4_102_444_800
    ):
        raise ValueError("Malformed normalized sudo event")
    return signal


def validate_candidate(candidate: SudoRuleMatch | None, signal: SudoSignal) -> None:
    if candidate is None:
        return
    if (
        not isinstance(candidate, SudoRuleMatch)
        or candidate.detector_id not in DETECTOR_IDS
        or candidate.severity not in {"medium", "high"}
        or type(candidate.count) is not int
        or not 1 <= candidate.count <= 50_000
        or type(candidate.timestamp) not in (float, int)
        or not math.isfinite(candidate.timestamp)
        or candidate.timestamp != signal.timestamp
    ):
        raise ValueError("Invalid candidate or timestamp mismatch")


class SudoStagingStore:
    """Separate private DB with atomic dedup, candidate evidence and retention.

    No creation occurs in __init__; initialize() is an explicit opt-in.
    The parent directory must be owned by this process and mode 0700
    (or stricter). Sudo signals are never written to the production IDS DB.
    """

    def __init__(self, database: Path | str):
        self.path = Path(database)
        self._initialized = False
        if self.path.name in ("", ".", ".."):
            raise ValueError("A concrete private database path is required")

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path, timeout=5)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys=ON")
        db.execute("PRAGMA busy_timeout=5000")
        return db

    def initialize(self) -> None:
        directory = self.path.parent
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        if directory.is_symlink():
            raise PermissionError("Refusing symlinked sudo state directory")
        folder = directory.stat()
        if folder.st_uid != os.geteuid() or stat.S_IMODE(folder.st_mode) & 0o077:
            raise PermissionError("Sudo staging directory must be private and worker-owned")
        flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(self.path, flags, 0o600)
        try:
            file_stat = os.fstat(fd)
            if (
                not stat.S_ISREG(file_stat.st_mode)
                or file_stat.st_uid != os.geteuid()
                or file_stat.st_nlink != 1
                or stat.S_IMODE(file_stat.st_mode) & 0o077
            ):
                raise PermissionError("Sudo staging SQLite file must be private and worker-owned")
        finally:
            os.close(fd)

        db = self._connect()
        try:
            version = db.execute("PRAGMA user_version").fetchone()[0]
            if version not in (0, 1, SCHEMA_VERSION):
                raise ValueError("Unsupported private sudo schema; do not overwrite")
            db.execute("PRAGMA journal_mode=DELETE")
            db.execute("PRAGMA synchronous=FULL")
            db.executescript(
                "BEGIN IMMEDIATE;\n" + SCHEMA + f"\nPRAGMA user_version={SCHEMA_VERSION};\nCOMMIT;"
            )
        finally:
            db.close()
        self._initialized = True

    def _require_ready(self) -> None:
        if not self._initialized:
            raise RuntimeError("Private sudo staging store must be explicitly initialized")

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        self._require_ready()
        db = self._connect()
        try:
            db.execute("BEGIN IMMEDIATE")
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    def append(self, signal: SudoSignal, candidate: SudoRuleMatch | None = None) -> bool:
        self._require_ready()
        validate_signal(signal)
        validate_candidate(candidate, signal)
        identity = event_id(signal)
        incoming = (
            identity,
            signal.timestamp,
            signal.kind,
            signal.boot_id.lower(),
            signal.uid,
            signal.pid,
        )
        with self._transaction() as db:
            row = db.execute(
                "SELECT event_id,timestamp,kind,boot_id,uid,pid FROM sudo_signals WHERE event_id=?",
                (identity,),
            ).fetchone()
            if row is not None:
                if tuple(row) != incoming:
                    raise ValueError("Conflicting sudo journal identity")
                return False
            db.execute(
                "INSERT INTO sudo_signals(event_id,timestamp,kind,boot_id,uid,pid) "
                "VALUES(?,?,?,?,?,?)",
                incoming,
            )
            if candidate is not None:
                db.execute(
                    "INSERT INTO sudo_candidates(event_id,detector_id,timestamp,severity,process_count) "
                    "VALUES(?,?,?,?,?)",
                    (
                        identity,
                        candidate.detector_id,
                        candidate.timestamp,
                        candidate.severity,
                        candidate.count,
                    ),
                )
            # Commit watermark and signal/candidate in the SAME transaction.
            # A failed candidate insert must not advance restart replay.
            db.execute(
                "INSERT INTO sudo_checkpoint(id,last_committed_timestamp) VALUES(1,?) "
                "ON CONFLICT(id) DO UPDATE SET "
                "last_committed_timestamp=MAX(last_committed_timestamp,excluded.last_committed_timestamp)",
                (signal.timestamp,),
            )
        return True

    def resume_since(self, overlap_seconds: int = 300) -> float | None:
        """Safe best-effort timestamp replay boundary, not a journal cursor.

        The overlap must include the rule window AND cooldown. Dedupe is
        journal-cursor-hash based. A missing/rotated journald segment or large
        clock jump can still cause a gap: no exactly-once guarantee is claimed.
        """
        self._require_ready()
        if type(overlap_seconds) is not int or not 60 <= overlap_seconds <= 7200:
            raise ValueError("Invalid restart overlap duration")
        db = self._connect()
        try:
            row = db.execute(
                "SELECT last_committed_timestamp FROM sudo_checkpoint WHERE id=1"
            ).fetchone()
        finally:
            db.close()
        if row is None:
            return None
        timestamp = float(row[0])
        if not math.isfinite(timestamp) or not 0 <= timestamp < 4_102_444_800:
            raise ValueError("Corrupt private sudo checkpoint")
        # One extra second avoids missing same-second timestamps due to --since rounding.
        return max(0.0, timestamp - overlap_seconds - 1.0)

    def prune(self, before_timestamp: float) -> int:
        self._require_ready()
        if (
            type(before_timestamp) not in (float, int)
            or not math.isfinite(before_timestamp)
            or not 0 <= before_timestamp < 4_102_444_800
        ):
            raise ValueError("Invalid retention cutoff")
        with self._transaction() as db:
            result = db.execute(
                "DELETE FROM sudo_signals WHERE timestamp<?",
                (before_timestamp,),
            )
            return result.rowcount

    def summary(self) -> dict:
        self._require_ready()
        db = self._connect()
        try:
            categories = Counter(
                {
                    row["kind"]: row["n"]
                    for row in db.execute(
                        "SELECT kind,COUNT(*) AS n FROM sudo_signals GROUP BY kind"
                    )
                }
            )
            matches = Counter(
                {
                    row["detector_id"]: row["n"]
                    for row in db.execute(
                        "SELECT detector_id,COUNT(*) AS n FROM sudo_candidates GROUP BY detector_id"
                    )
                }
            )
        finally:
            db.close()
        return {
            "kind": "private_sudo_summary",
            "persisted_log_rows": sum(categories.values()),
            "sudo_categories": {kind: categories[kind] for kind in KINDS},
            "candidate_rule_matches": {key: matches[key] for key in sorted(DETECTOR_IDS)},
            "raw_commands_or_cursors_persisted": False,
            "shares_production_database": False,
        }
