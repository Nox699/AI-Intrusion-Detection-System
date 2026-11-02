#!/usr/bin/env python3
"""Read-only, aggregate-only production SSH ML readiness audit.

No model training, IP/username output, private logs, or writes.
Use as yggdrasil-worker with the *installed* Python interpreter.
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
import tomllib
from pathlib import Path

FEATURE_NAMES = (
    "failed_count",
    "success_count",
    "unique_users",
    "failure_ratio",
    "hour_sin",
    "hour_cos",
)


def inspect(config_path: Path) -> dict:
    with config_path.open("rb") as handle:
        config = tomllib.load(handle)
    raw_db = config["paths"]["database"]
    raw_model = config["paths"]["model"]
    db_path = Path(raw_db)
    model_path = Path(raw_model)
    if not db_path.is_absolute():
        db_path = config_path.parent / db_path
    if not model_path.is_absolute():
        model_path = config_path.parent / model_path
    min_samples = config["ml"]["min_samples"]
    if type(min_samples) is not int or not 20 <= min_samples <= 10000:
        raise ValueError("Invalid model minimum")
    # sqlite read-only URI never creates a missing file or writes a journal.
    with sqlite3.connect(db_path.resolve().as_uri() + "?mode=ro", uri=True) as db:
        db.execute("PRAGMA query_only=ON")
        if db.execute("PRAGMA quick_check").fetchone()[0] != "ok":
            raise ValueError("Database integrity check failed")
        event_total = db.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        outcomes = dict(
            db.execute("SELECT outcome, COUNT(*) FROM events GROUP BY outcome").fetchall()
        )
        observation_total = db.execute("SELECT COUNT(*) FROM observations").fetchone()[0]
        states = dict(
            db.execute("SELECT state, COUNT(*) FROM observations GROUP BY state").fetchall()
        )
        # Only active stored observations; late/out-of-order data are not
        # automatically a clean normal baseline.
        observations = db.execute(
            "SELECT features FROM observations WHERE state!='late' "
            "ORDER BY timestamp,event_id LIMIT 10001"
        ).fetchall()
        if len(observations) > 10000:
            raise ValueError("Select a smaller training review period")
        unique_features = set()
        for (raw,) in observations:
            obj = json.loads(raw)
            if not isinstance(obj, dict) or not all(name in obj for name in FEATURE_NAMES):
                raise ValueError("Unexpected SSH feature schema")
            values = tuple(obj[name] for name in FEATURE_NAMES)
            if not all(type(v) in (int, float) for v in values):
                raise ValueError("Nonnumeric SSH features")
            unique_features.add(values)
        distinct_days, distinct_sources = db.execute(
            "SELECT COUNT(DISTINCT DATE(timestamp,'unixepoch')), "
            "COUNT(DISTINCT source_ip) FROM events"
        ).fetchone()
        row = db.execute("SELECT value FROM state WHERE key='model'").fetchone()
    model_state = "unknown"
    if row:
        parsed = json.loads(row[0])
        if isinstance(parsed, dict) and parsed.get("state") in {"untrained", "ready", "error"}:
            model_state = parsed["state"]
    candidate_total = len(observations)
    return {
        "kind": "production_ssh_readiness_read_only",
        "event_total": event_total,
        "outcomes": {label: outcomes.get(label, 0) for label in ("success", "failure")},
        "observation_total": observation_total,
        "observation_states": {name: states[name] for name in sorted(states)},
        "candidate_rows_not_vetted_as_normal": candidate_total,
        "unique_feature_vectors": len(unique_features),
        "active_days": distinct_days,
        "distinct_source_count_only": distinct_sources,
        "min_samples": min_samples,
        "rows_missing_for_minimum": max(0, min_samples - candidate_total),
        "model_file_exists": model_path.is_file(),
        "model_state": model_state,
        "manual_normality_review_required": True,
        "production_training_authorized": False,
        "warning": (
            "Counts alone cannot prove normality or independence. "
            "Do not train on unlabeled suspicious SSH traffic or deploy a synthetic lab model."
        ),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=Path("/etc/yggdrasil-ids/config.toml"))
    args = parser.parse_args(argv)
    try:
        result = inspect(args.config)
    except (OSError, ValueError, KeyError, TypeError, sqlite3.Error) as exc:
        print(f"Audit failed safely ({type(exc).__name__}); no data modified.", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
