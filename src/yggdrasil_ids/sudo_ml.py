"""Independent, experimental sudo Isolation Forest; OFFLINE/SHADOW only.

One feature vector PER sudo process, never one per journald message.
No usernames, commands, raw journal texts, UID or PID values are model features.
The trained normal-only model is a fingerprinted, non-executable JSON artifact.
Nothing in this module sends alerts, changes the production database, or
modifies the active rule-based sudo shadow sensor.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import tempfile
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Sequence

import numpy as np
import sklearn
from sklearn.ensemble import IsolationForest

from .sudo_rules import SudoSignal
from .sudo_storage import validate_signal

WINDOW = 300
MIN_TRAINING_ROWS = 80
MAX_TRAINING_ROWS = 10_000
MAX_SIGNALS = 10_000
MAX_ARTIFACT_BYTES = 3 * 1024 * 1024
MODEL_FORMAT = "sudo-isolation-forest-v1"
FEATURE_NAMES = (
    "processes_300s",
    "failed_processes_300s",
    "denied_processes_300s",
    "successful_processes_300s",
    "failure_ratio_300s",
    "hour_sin",
    "hour_cos",
)


@dataclass(frozen=True)
class SudoAttempt:
    timestamp: float
    boot_id: str
    uid: str
    pid: int
    outcome: str


def attempts_from_signals(signals: Iterable[SudoSignal]) -> list[SudoAttempt]:
    """Correlate multiple PAM, session and summary lines to one sudo PID.

    The journal metadata identifies the invoking sudo process. User/boot/PID
    are transient grouping fields only, not ML features or training artifacts.
    On historical large windows a reused PID can still be ambiguous; only
    short independent scenarios or bounded journal snapshots are supported.
    """
    seen: dict[str, SudoSignal] = {}
    groups: dict[tuple[str, str, int], list[SudoSignal]] = defaultdict(list)
    previous: float | None = None
    for count, event in enumerate(signals, start=1):
        if count > MAX_SIGNALS:
            raise ValueError("Too many sudo signals for a bounded ML scenario")
        validate_signal(event)
        if previous is not None and event.timestamp < previous:
            raise ValueError("Sudo signals must be chronological")
        previous = event.timestamp
        prior = seen.get(event.cursor)
        if prior is not None:
            if prior != event:
                raise ValueError("Conflicting sudo signal cursor")
            continue
        seen[event.cursor] = event
        groups[(event.boot_id, event.uid, event.pid)].append(event)

    attempts = []
    for (boot, uid, pid), rows in groups.items():
        kinds = {item.kind for item in rows}
        if "not_in_sudoers" in kinds:
            outcome = "denied"
        elif "pam_auth_failure" in kinds or "incorrect_password" in kinds:
            outcome = "failure"
        elif "pam_session_opened" in kinds or "command_invoked" in kinds:
            outcome = "success"
        else:
            # A session-closed line alone does not prove a new attempt.
            continue
        attempts.append(SudoAttempt(max(item.timestamp for item in rows), boot, uid, pid, outcome))
    attempts.sort(key=lambda x: (x.timestamp, x.boot_id, x.uid, x.pid))
    return attempts


def feature_rows(attempts: Sequence[SudoAttempt]) -> list[list[float]]:
    """Build process-level 300-second rolling features, separately per boot/UID."""
    windows: dict[tuple[str, str], deque[SudoAttempt]] = defaultdict(deque)
    rows = []
    previous: float | None = None
    for attempt in attempts:
        if not isinstance(attempt, SudoAttempt) or attempt.outcome not in {
            "failure",
            "denied",
            "success",
        }:
            raise ValueError("Invalid sudo ML attempt")
        if not math.isfinite(attempt.timestamp) or not 0 <= attempt.timestamp < 4_102_444_800:
            raise ValueError("Invalid sudo ML timestamp")
        if previous is not None and attempt.timestamp < previous:
            raise ValueError("Sudo ML attempts must be chronological")
        previous = attempt.timestamp
        window = windows[(attempt.boot_id, attempt.uid)]
        while window and window[0].timestamp <= attempt.timestamp - WINDOW:
            window.popleft()
        window.append(attempt)
        failed = sum(item.outcome == "failure" for item in window)
        denied = sum(item.outcome == "denied" for item in window)
        succeeded = sum(item.outcome == "success" for item in window)
        total = len(window)
        hour_phase = 2 * math.pi * ((attempt.timestamp % 86400) / 86400)
        rows.append(
            [
                float(total),
                float(failed),
                float(denied),
                float(succeeded),
                float((failed + denied) / total),
                math.sin(hour_phase),
                math.cos(hour_phase),
            ]
        )
    return rows


def _validated_rows(rows: Sequence[Sequence[float]], minimum: int = 1) -> np.ndarray:
    if isinstance(rows, (str, bytes, dict)) or not minimum <= len(rows) <= MAX_TRAINING_ROWS:
        raise ValueError("Invalid sudo ML feature matrix size")
    result = []
    for row in rows:
        if not isinstance(row, (list, tuple, np.ndarray)) or len(row) != len(FEATURE_NAMES):
            raise ValueError("Sudo ML requires the fixed seven-feature schema")
        if any(
            isinstance(item, (bool, np.bool_))
            or not isinstance(item, (int, float, np.integer, np.floating))
            for item in row
        ):
            raise ValueError("Sudo ML feature values must be numeric")
        values = [float(x) for x in row]
        if not all(math.isfinite(x) for x in values):
            raise ValueError("Sudo ML features must be finite")
        total, failed, denied, succeeded, ratio, sine, cosine = values
        if (
            not all(0 <= x <= 10_000 and x.is_integer() for x in values[:4])
            or total < 1
            or failed + denied + succeeded != total
            or not 0 <= ratio <= 1
            or not math.isclose(ratio, (failed + denied) / total, abs_tol=1e-7)
            or not (-1 <= sine <= 1 and -1 <= cosine <= 1)
            or not math.isclose(sine * sine + cosine * cosine, 1.0, abs_tol=1e-5)
        ):
            raise ValueError("Inconsistent sudo ML feature vector")
        result.append(values)
    return np.asarray(result, dtype=np.float64)


def _canonical(data: dict[str, Any]) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii")


class SudoIsolationForest:
    """Fixed seed, normal-only, reproducible experiment; never auto-alerts."""

    def __init__(
        self,
        rows: Sequence[Sequence[float]],
        provenance: str,
        trained_at: str,
    ) -> None:
        matrix = _validated_rows(rows, MIN_TRAINING_ROWS)
        if len(np.unique(matrix, axis=0)) < 4 or not np.any(np.ptp(matrix[:, :4], axis=0) > 0):
            raise ValueError("Sudo normal training lacks behavioral variation")
        if not isinstance(provenance, str) or not 10 <= len(provenance.strip()) <= 1500:
            raise ValueError("Sudo ML training provenance is missing or invalid")
        self.model = IsolationForest(
            contamination=0.03,
            n_estimators=128,
            random_state=42,
            max_samples=min(256, len(matrix)),
            n_jobs=1,
        )
        self.model.fit(matrix)
        self.threshold = float(-self.model.offset_)
        self.payload = {
            "format": MODEL_FORMAT,
            "features": list(FEATURE_NAMES),
            "window_seconds": WINDOW,
            "sklearn_version": sklearn.__version__,
            "provenance": provenance.strip(),
            "trained_at": trained_at,
            "normal_training_rows": matrix.tolist(),
            "threshold": self.threshold,
        }
        self.payload["sha256"] = hashlib.sha256(_canonical(self.payload)).hexdigest()
        self.version = "sudo-if-" + self.payload["sha256"][:16]

    @classmethod
    def train(cls, rows: Sequence[Sequence[float]], provenance: str) -> "SudoIsolationForest":
        timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
        return cls(rows, provenance, timestamp)

    def score_many(self, rows: Sequence[Sequence[float]]) -> list[dict[str, Any]]:
        """Score a complete bounded scenario in one batch, with no side effects."""
        clean = _validated_rows(rows)
        return [
            {
                "score": float(score),
                "threshold": self.threshold,
                "is_anomaly": float(score) > self.threshold,
                "version": self.version,
            }
            for score in -self.model.score_samples(clean)
        ]

    def score(self, row: Sequence[float]) -> dict[str, Any]:
        return self.score_many([row])[0]

    def save(self, path: Path | str) -> None:
        target = Path(path)
        if not target.parent.is_dir() or target.exists() or target.is_symlink():
            raise ValueError("Create a private output directory and a new model filename")
        encoded = _canonical(self.payload)
        if len(encoded) > MAX_ARTIFACT_BYTES:
            raise ValueError("Sudo model artifact exceeds maximum size")
        temp = None
        try:
            with tempfile.NamedTemporaryFile(
                dir=target.parent, prefix=".sudo-if-", delete=False
            ) as handle:
                temp = Path(handle.name)
                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temp, 0o600)
            os.link(temp, target)
        finally:
            if temp is not None:
                temp.unlink(missing_ok=True)

    @classmethod
    def load(cls, path: Path | str) -> "SudoIsolationForest":
        with Path(path).open("rb") as handle:
            raw = handle.read(MAX_ARTIFACT_BYTES + 1)
        if len(raw) > MAX_ARTIFACT_BYTES:
            raise ValueError("Sudo model file exceeds maximum size")

        def unique(pairs):
            obj = {}
            for key, value in pairs:
                if key in obj:
                    raise ValueError("Duplicate sudo ML JSON key")
                obj[key] = value
            return obj

        try:
            payload = json.loads(raw, object_pairs_hook=unique)
        except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
            raise ValueError("Sudo model JSON is invalid") from exc
        if not isinstance(payload, dict) or set(payload) != {
            "format",
            "features",
            "window_seconds",
            "sklearn_version",
            "provenance",
            "trained_at",
            "normal_training_rows",
            "threshold",
            "sha256",
        }:
            raise ValueError("Sudo model schema is invalid")
        if (
            payload["format"] != MODEL_FORMAT
            or payload["features"] != list(FEATURE_NAMES)
            or type(payload["window_seconds"]) is not int
            or payload["window_seconds"] != WINDOW
            or payload["sklearn_version"] != sklearn.__version__
            or not isinstance(payload["trained_at"], str)
        ):
            raise ValueError("Sudo model format or scikit-learn version mismatch")
        try:
            dt = datetime.fromisoformat(payload["trained_at"])
            if dt.utcoffset() is None or dt.utcoffset().total_seconds() != 0:
                raise ValueError("Invalid UTC model timestamp")
        except (ValueError, TypeError, OverflowError) as exc:
            raise ValueError("Sudo model timestamp is invalid") from exc
        signature = payload["sha256"]
        body = {key: value for key, value in payload.items() if key != "sha256"}
        if (
            not isinstance(signature, str)
            or hashlib.sha256(_canonical(body)).hexdigest() != signature
        ):
            raise ValueError("Sudo model fingerprint mismatch")
        restored = cls(
            payload["normal_training_rows"], payload["provenance"], payload["trained_at"]
        )
        if type(payload["threshold"]) not in (int, float) or not math.isclose(
            payload["threshold"], restored.threshold, rel_tol=0, abs_tol=1e-12
        ):
            raise ValueError("Sudo Isolation Forest threshold mismatch")
        return restored
