"""Independent preauth ML feature schema and non-executable Isolation Forest artifact.

Not loaded by the live SSH collector. This is isolated offline evaluation only.
A connection candidate may produce two or more journal messages; score
one completed candidate, not each message. No IP or username is an ML feature.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import os
import tempfile
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Sequence

import numpy as np
import sklearn
from sklearn.ensemble import IsolationForest

WINDOW = 300
CONNECTION_GAP = 120
MAX_RECORDS = 20000
MAX_MODEL_BYTES = 3 * 1024 * 1024
MIN_TRAINING = 80
MODEL_FORMAT = "preauth-isolation-forest-v1"
FEATURE_NAMES = (
    "connections_300s",
    "invalid_users_300s",
    "unique_usernames_300s",
    "disconnects_300s",
    "invalid_ratio_300s",
    "hour_sin",
    "hour_cos",
)


@dataclass
class PreauthConnection:
    cursor: str
    timestamp: float
    source_ip: str
    username: str
    source_port: int
    boot_id: str
    invalid_user: bool
    disconnected: bool


def connections_from_records(
    records: Iterable[dict[str, Any]], classifier: Callable[[Any], Any]
) -> list[PreauthConnection]:
    """Correlate dual-line preauth records by boot, source, port and short gap."""
    found: dict[tuple[str, str, int], PreauthConnection] = {}
    completed: list[PreauthConnection] = []
    previous: float | None = None
    for number, record in enumerate(records):
        if number >= MAX_RECORDS:
            raise ValueError("Preauth journal data exceeds bounded record limit")
        signal = classifier(record)
        if signal is None:
            continue
        stamp_value = record.get("__REALTIME_TIMESTAMP")
        if type(stamp_value) not in (str, int) or not str(stamp_value).isdigit():
            raise ValueError("Preauth event lacks a valid microsecond timestamp")
        timestamp = int(stamp_value) / 1_000_000
        if not math.isfinite(timestamp) or not 0 <= timestamp < 253402300800:
            raise ValueError("Preauth timestamp is outside the supported range")
        if previous is not None and timestamp < previous:
            raise ValueError("Preauth journal records must be chronological")
        previous = timestamp
        cursor = record.get("__CURSOR")
        if not isinstance(cursor, str) or not 1 <= len(cursor) <= 1024:
            raise ValueError("Preauth event lacks a bounded journal cursor")
        key = (signal.boot_id, signal.source_ip, signal.source_port)
        previous_conn = found.get(key)
        is_invalid = signal.category.startswith("invalid_user")
        is_disconnect = "disconnect" in signal.category
        if (
            previous_conn is None
            or timestamp - previous_conn.timestamp > CONNECTION_GAP
        ):
            current = PreauthConnection(
                cursor=cursor,
                timestamp=timestamp,
                source_ip=signal.source_ip,
                username=signal.username,
                source_port=signal.source_port,
                boot_id=signal.boot_id,
                invalid_user=is_invalid,
                disconnected=is_disconnect,
            )
            found[key] = current
            completed.append(current)
        else:
            if previous_conn.username != signal.username:
                raise ValueError("Conflicting usernames for a correlated SSH connection")
            previous_conn.invalid_user |= is_invalid
            previous_conn.disconnected |= is_disconnect
            previous_conn.timestamp = timestamp
    completed.sort(key=lambda item: (item.timestamp, item.cursor))
    return completed


def feature_rows(
    connections: Sequence[PreauthConnection], window_seconds: int = WINDOW
) -> list[list[float]]:
    """Build event-time rolling source windows; features contain no identities."""
    if type(window_seconds) is not int or not 10 <= window_seconds <= 3600:
        raise ValueError("Unsupported preauth feature window")
    history: dict[str, deque[PreauthConnection]] = defaultdict(deque)
    rows: list[list[float]] = []
    prior: float | None = None
    for current in connections:
        if prior is not None and current.timestamp < prior:
            raise ValueError("Connections must be sorted by timestamp")
        prior = current.timestamp
        group = history[current.source_ip]
        while group and group[0].timestamp <= current.timestamp - window_seconds:
            group.popleft()
        group.append(current)
        total = len(group)
        invalid = sum(item.invalid_user for item in group)
        disconnects = sum(item.disconnected for item in group)
        distinct = len({item.username for item in group})
        angle = 2 * math.pi * (current.timestamp % 86400) / 86400
        rows.append(
            [
                float(total),
                float(invalid),
                float(distinct),
                float(disconnects),
                float(invalid / total),
                math.sin(angle),
                math.cos(angle),
            ]
        )
    return rows


def _clean_rows(rows: Sequence[Sequence[float]], minimum: int = 1) -> np.ndarray:
    if isinstance(rows, (bytes, str, dict)) or not minimum <= len(rows) <= 10000:
        raise ValueError("Invalid preauth feature matrix size")
    normalized = []
    for row in rows:
        if not isinstance(row, (list, tuple, np.ndarray)) or len(row) != len(FEATURE_NAMES):
            raise ValueError("Preauth model requires the versioned 7-feature schema")
        if any(type(value) not in (int, float, np.float64) for value in row):
            raise ValueError("Preauth features must be numeric")
        values = list(map(float, row))
        if not all(math.isfinite(value) for value in values):
            raise ValueError("Non-finite feature value")
        count, invalid, users, disconnected, ratio, sine, cosine = values
        if (
            count < 1
            or count > 10000
            or not all(value.is_integer() for value in values[:4])
            or not 0 <= invalid <= count
            or not 1 <= users <= count
            or not 0 <= disconnected <= count
            or not math.isclose(ratio, invalid / count, abs_tol=1e-7)
            or not math.isclose(sine * sine + cosine * cosine, 1, abs_tol=1e-5)
        ):
            raise ValueError("Inconsistent preauth feature vector")
        normalized.append(values)
    return np.asarray(normalized, dtype=np.float64)


def _canonical(data: dict[str, Any]) -> bytes:
    return json.dumps(
        data, sort_keys=True, ensure_ascii=True, separators=(",", ":"), allow_nan=False
    ).encode("ascii")


class PreauthIsolationForest:
    """Separate sklearn model; never accepted as an SSH-auth IsolationForest."""

    def __init__(self, rows: Sequence[Sequence[float]], provenance: str, trained_at: str):
        matrix = _clean_rows(rows, MIN_TRAINING)
        if len(np.unique(matrix, axis=0)) < 4 or not np.any(np.ptp(matrix[:, :4], axis=0) > 0):
            raise ValueError("Preauth normal training has too little behavioral variation")
        self._rows = matrix
        self.model = IsolationForest(
            contamination=0.03, n_estimators=128, random_state=42,
            max_samples=min(256, len(matrix)), n_jobs=1,
        )
        self.model.fit(matrix)
        self.threshold = float(-self.model.offset_)
        self.payload = {
            "format": MODEL_FORMAT,
            "features": list(FEATURE_NAMES),
            "window_seconds": WINDOW,
            "sklearn_version": sklearn.__version__,
            "normal_only": True,
            "provenance": provenance,
            "trained_at": trained_at,
            "training_rows": matrix.tolist(),
            "threshold": self.threshold,
        }
        self.payload["sha256"] = hashlib.sha256(_canonical(self.payload)).hexdigest()
        self.version = "preauth-if-" + self.payload["sha256"][:16]

    @classmethod
    def train(cls, rows: Sequence[Sequence[float]], provenance: str) -> "PreauthIsolationForest":
        if not isinstance(provenance, str) or not 10 <= len(provenance) <= 1000:
            raise ValueError("Model training provenance must be explicit")
        stamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
        return cls(rows, provenance, stamp)

    def score(self, vector: Sequence[float]) -> dict[str, Any]:
        matrix = _clean_rows([vector])
        value = float(-self.model.score_samples(matrix)[0])
        return {
            "score": value,
            "threshold": self.threshold,
            "is_anomaly": value > self.threshold,
            "version": self.version,
        }

    def save(self, path: Path | str) -> None:
        target = Path(path)
        if target.exists():
            raise FileExistsError("Never overwrite an existing preauth model")
        encoded = _canonical(self.payload)
        if len(encoded) > MAX_MODEL_BYTES:
            raise ValueError("Preauth model artifact exceeds size limit")
        temp = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="wb", dir=target.parent, prefix=".preauth-model-", delete=False
            ) as file:
                temp = Path(file.name)
                file.write(encoded)
                file.flush()
                os.fsync(file.fileno())
            os.chmod(temp, 0o600)
            os.link(temp, target)
        finally:
            if temp is not None:
                temp.unlink(missing_ok=True)

    @classmethod
    def load(cls, path: Path | str) -> "PreauthIsolationForest":
        with Path(path).open("rb") as handle:
            encoded = handle.read(MAX_MODEL_BYTES + 1)
        if len(encoded) > MAX_MODEL_BYTES:
            raise ValueError("Preauth model file too large")
        def reject_duplicates(items: list[tuple[str, Any]]) -> dict[str, Any]:
            result: dict[str, Any] = {}
            for key, value in items:
                if key in result:
                    raise ValueError("Repeated preauth model field")
                result[key] = value
            return result
        data = json.loads(encoded, object_pairs_hook=reject_duplicates)
        if not isinstance(data, dict) or set(data) != {
            "format", "features", "window_seconds", "sklearn_version",
            "normal_only", "provenance", "trained_at", "training_rows",
            "threshold", "sha256",
        }:
            raise ValueError("Unrecognized preauth model artifact structure")
        if (
            data["format"] != MODEL_FORMAT
            or data["features"] != list(FEATURE_NAMES)
            or type(data["window_seconds"]) is not int
            or data["window_seconds"] != WINDOW
            or data["sklearn_version"] != sklearn.__version__
            or data["normal_only"] is not True
            or not isinstance(data["provenance"], str)
            or not 10 <= len(data["provenance"]) <= 1000
            or not isinstance(data["trained_at"], str)
        ):
            raise ValueError("Incompatible preauth ML model schema/version/provenance")
        try:
            date = datetime.fromisoformat(data["trained_at"])
            if date.utcoffset() is None or date.utcoffset().total_seconds() != 0:
                raise ValueError("Training time is not UTC")
        except (ValueError, TypeError):
            raise ValueError("Invalid model timestamp") from None
        expect = data["sha256"]
        raw = {name: value for name, value in data.items() if name != "sha256"}
        if not isinstance(expect, str) or hashlib.sha256(_canonical(raw)).hexdigest() != expect:
            raise ValueError("Preauth model fingerprint mismatch")
        model = cls(data["training_rows"], data["provenance"], data["trained_at"])
        threshold = data["threshold"]
        if type(threshold) not in (int, float) or not math.isclose(
            model.threshold, threshold, rel_tol=0, abs_tol=1e-12
        ):
            raise ValueError("Preauth model threshold changed")
        return model
