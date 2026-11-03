"""Bounded, provisional sudo ML snapshots from the private shadow store.

The original seven-feature model and saved threshold are used unchanged. Each
call reconstructs a fresh snapshot; later process evidence may revise an older
result. There is no accumulated ML history, cooldown, candidate or notification.
No process identity, feature vector or saved training row enters the result.
"""

from __future__ import annotations

import hashlib
import math
import os
import re
import sqlite3
import stat
import time
from collections import Counter, defaultdict
from pathlib import Path

from .sudo_live_source import source_snapshot_guard
from .sudo_ml import MAX_ARTIFACT_BYTES, SudoAttempt, SudoIsolationForest, feature_rows
from .sudo_rules import SudoSignal
from .sudo_storage import SCHEMA_VERSION, validate_signal

FORMAT = "sudo-ml-shadow-v1"
WINDOW_SECONDS = 900
WARMUP_SECONDS = 300
MAX_SOURCE_AGE_SECONDS = 180
MAX_SOURCE_ROWS = 3000
MAX_PROCESS_SPAN_SECONDS = 900
LATEST_LIMIT = 15
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_VERSION = re.compile(r"sudo-if-[0-9a-f]{16}\Z")
_MODEL_ERROR = "Frozen sudo ML model validation failed"
_SOURCE_ERROR = "Private sudo ML source snapshot unavailable"
_TERMINAL_KINDS = frozenset(
    {"command_invoked", "pam_session_opened", "incorrect_password", "not_in_sudoers"}
)


def _private_file(path: Path, modes: set[int]) -> None:
    folder = path.parent.lstat()
    file = path.lstat()
    if (
        not stat.S_ISDIR(folder.st_mode)
        or folder.st_uid != os.geteuid()
        or stat.S_IMODE(folder.st_mode) != 0o700
        or not stat.S_ISREG(file.st_mode)
        or file.st_uid != os.geteuid()
        or stat.S_IMODE(file.st_mode) not in modes
    ):
        raise ValueError("Private ownership or permissions differ")


def _load_model(path: Path, expected_version: str, expected_file_sha256: str):
    try:
        if not isinstance(expected_version, str) or not _VERSION.fullmatch(expected_version):
            raise ValueError("Invalid model pin")
        if not isinstance(expected_file_sha256, str) or not _HASH.fullmatch(expected_file_sha256):
            raise ValueError("Invalid model pin")
        _private_file(path, {0o400, 0o600})
        if path.stat().st_size > MAX_ARTIFACT_BYTES:
            raise ValueError("Model size exceeds bound")
        if hashlib.sha256(path.read_bytes()).hexdigest() != expected_file_sha256:
            raise ValueError("Model bytes differ")
        # The original loader deterministically reconstructs only its saved rows.
        model = SudoIsolationForest.load(path)
        if model.version != expected_version:
            raise ValueError("Model identity differs")
        _private_file(path, {0o400, 0o600})
        if hashlib.sha256(path.read_bytes()).hexdigest() != expected_file_sha256:
            raise ValueError("Model changed during reconstruction")
        return model
    except (OSError, ValueError, TypeError, OverflowError):
        raise ValueError(_MODEL_ERROR) from None


def _read_snapshot(database: Path, now: float):
    try:
        _private_file(database, {0o600})
        with (
            source_snapshot_guard(database),
            sqlite3.connect(database.absolute().as_uri() + "?mode=ro", uri=True, timeout=5) as db,
        ):
            db.execute("PRAGMA query_only=ON")
            # An explicit read transaction ties the checkpoint and rows to one
            # committed source view while the poll writer's lock is held.
            db.execute("BEGIN")
            if db.execute("PRAGMA user_version").fetchone()[0] != SCHEMA_VERSION:
                raise ValueError("Unexpected source schema")
            row = db.execute(
                "SELECT last_completed_until FROM shadow_poll_checkpoint WHERE id=1"
            ).fetchone()
            if row is None or type(row[0]) not in (int, float):
                raise ValueError("Missing source checkpoint")
            cutoff = float(row[0])
            if (
                not math.isfinite(cutoff)
                or not 0 < cutoff < 4_102_444_800
                or not 0 <= now - cutoff <= MAX_SOURCE_AGE_SECONDS
            ):
                raise ValueError("Source checkpoint is stale or in the future")
            rows = db.execute(
                "SELECT event_id,timestamp,kind,boot_id,uid,pid FROM sudo_signals "
                "WHERE timestamp>? AND timestamp<=? AND kind!='pam_session_closed' "
                "ORDER BY timestamp,event_id LIMIT ?",
                (
                    cutoff - WINDOW_SECONDS - WARMUP_SECONDS,
                    cutoff,
                    MAX_SOURCE_ROWS + 1,
                ),
            ).fetchall()
            db.commit()
        if len(rows) > MAX_SOURCE_ROWS:
            raise ValueError("Source window exceeds bounds")
        return cutoff, rows
    except (OSError, sqlite3.Error, ValueError, TypeError, OverflowError):
        raise ValueError(_SOURCE_ERROR) from None


def _processes(rows):
    groups = defaultdict(list)
    seen = {}
    for event_id, timestamp, kind, boot, uid, pid in rows:
        if not isinstance(event_id, str) or not _HASH.fullmatch(event_id):
            raise ValueError("Invalid normalized source identity")
        signal = validate_signal(SudoSignal(event_id, timestamp, boot, uid, pid, kind))
        previous = seen.get(event_id)
        if previous is not None:
            if previous != signal:
                raise ValueError("Conflicting normalized source identity")
            continue
        seen[event_id] = signal
        groups[(signal.boot_id, signal.uid, signal.pid)].append(signal)

    processes = []
    skipped = 0
    for (boot, uid, pid), signals in groups.items():
        kinds = Counter(signal.kind for signal in signals)
        if signals[-1].timestamp - signals[0].timestamp > MAX_PROCESS_SPAN_SECONDS or any(
            kinds[kind] > 1 for kind in _TERMINAL_KINDS
        ):
            # PID reuse cannot always be disambiguated with the stored fields.
            # Do not manufacture multiple attempts from an ambiguous group.
            skipped += 1
            continue
        if kinds["not_in_sudoers"]:
            outcome, category = "denied", "permission_denied"
        elif kinds["pam_auth_failure"] or kinds["incorrect_password"]:
            outcome, category = "failure", "authentication_failed"
        elif kinds["command_invoked"] or kinds["pam_session_opened"]:
            outcome = "success"
            category = "session_opened" if kinds["pam_session_opened"] else "command_logged"
        else:
            continue
        processes.append((SudoAttempt(signals[-1].timestamp, boot, uid, pid, outcome), category))
    processes.sort(key=lambda item: (item[0].timestamp, item[0].boot_id, item[0].uid, item[0].pid))
    return processes, skipped


def build_ml_snapshot(
    database: Path,
    model_path: Path,
    expected_version: str,
    expected_file_sha256: str,
    *,
    now: float | None = None,
) -> dict:
    """Return anonymous raw scores from one completed, bounded source snapshot.

    The checkpoint is already the collector's delayed journal boundary. No
    additional delay or process-finality claim is introduced here. Source rows
    after that boundary are removed BEFORE coalescing. The first 300 seconds
    reconstruct rolling context and are never counted as scored positions.
    """
    now = time.time() if now is None else now
    if type(now) not in (int, float) or not math.isfinite(now) or not 1 <= now < 4_102_444_800:
        raise ValueError(_SOURCE_ERROR)
    model = _load_model(Path(model_path), expected_version, expected_file_sha256)
    cutoff, rows = _read_snapshot(Path(database), now)
    try:
        processes, skipped = _processes(rows)
        attempts = [attempt for attempt, _ in processes]
        positions = [
            i for i, attempt in enumerate(attempts) if attempt.timestamp > cutoff - WINDOW_SECONDS
        ]
        scored = model.score_many(feature_rows(attempts)) if attempts else []
        latest = [
            {
                "timestamp": attempts[i].timestamp,
                "category": processes[i][1],
                "score": scored[i]["score"],
                "is_anomaly": scored[i]["is_anomaly"],
            }
            for i in reversed(positions[-LATEST_LIMIT:])
        ]
    except (ValueError, TypeError, OverflowError):
        raise ValueError(_SOURCE_ERROR) from None
    return {
        "format": FORMAT,
        "mode": "shadow",
        "generated_at": float(now),
        "source_checkpoint": cutoff,
        "snapshot_cutoff": cutoff,
        "window_seconds": WINDOW_SECONDS,
        "warmup_seconds": WARMUP_SECONDS,
        "model_version": model.version,
        "threshold": model.threshold,
        "provisional": True,
        "total_scored": len(positions),
        "anomalous": sum(scored[i]["is_anomaly"] for i in positions),
        "skipped_ambiguous_processes": skipped,
        "latest_limit": LATEST_LIMIT,
        "latest": latest,
        "sends_alerts": False,
        "shares_production_database": False,
    }
