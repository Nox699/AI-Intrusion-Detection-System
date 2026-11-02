#!/usr/bin/env python3
"""Read-only summary of older trusted OpenSSH journal authentication events.

This is a *historical inventory* to decide if genuine training data might
exist. It does not export IPs/usernames, write to SQLite or train a model.
Journal events still require review before any training.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from collections import Counter, defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from yggdrasil_ids.features import SSHFeatureBuilder
from yggdrasil_ids.ssh import SSHParser

MAX_JOURNAL_RECORDS = 200_000
WINDOW_SECONDS = 300
PRODUCERS = ("_COMM=sshd", "_COMM=sshd-session", "_COMM=sshd-auth")


def summarize(records: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """Keep source addresses local in memory; emit only aggregates."""
    parser = SSHParser()
    builder = SSHFeatureBuilder(WINDOW_SECONDS)
    counters: Counter[str] = Counter()
    days: Counter[str] = Counter()
    sources: set[str] = set()
    seen: set[str] = set()
    unique_features: set[tuple[float, ...]] = set()
    recent: dict[str, deque] = defaultdict(deque)
    first: float | None = None
    latest: float | None = None

    for record in records:
        counters["journal_records_inspected"] += 1
        if counters["journal_records_inspected"] > MAX_JOURNAL_RECORDS:
            raise ValueError("Journal history exceeds bounded record limit")
        result = parser.parse(record, namespace="historical-audit")
        if result.event is None:
            counters["ignored_or_malformed_records"] += 1
            continue
        event = result.event
        if event.event_id in seen:
            counters["duplicate_auth_records"] += 1
            continue
        seen.add(event.event_id)
        if latest is not None and event.timestamp < latest:
            raise ValueError("Journal events must be supplied chronologically")
        source_window = recent[event.source_ip]
        while source_window and source_window[0].timestamp <= event.timestamp - WINDOW_SECONDS:
            source_window.popleft()
        vector = builder.build(list(source_window), event)
        source_window.append(event)
        unique_features.add(tuple(vector))
        sources.add(event.source_ip)
        days[datetime.fromtimestamp(event.timestamp, timezone.utc).date().isoformat()] += 1
        counters[event.outcome] += 1
        counters["auth_events"] += 1
        first = event.timestamp if first is None else first
        latest = event.timestamp

    return {
        "kind": "historical_ssh_journal_inventory",
        "data_source": "trusted_root_openssh_journal",
        "journal_records_inspected": counters["journal_records_inspected"],
        "ssh_auth_events": counters["auth_events"],
        "ssh_success": counters["success"],
        "ssh_failure": counters["failure"],
        "ignored_or_malformed_records": counters["ignored_or_malformed_records"],
        "duplicate_auth_records": counters["duplicate_auth_records"],
        "distinct_sources_count_only": len(sources),
        "unique_feature_vectors": len(unique_features),
        "daily_ssh_auth_counts_utc": dict(sorted(days.items())),
        "first_event_utc": (
            datetime.fromtimestamp(first, timezone.utc).isoformat() if first is not None else None
        ),
        "last_event_utc": (
            datetime.fromtimestamp(latest, timezone.utc).isoformat() if latest is not None else None
        ),
        "sufficiently_vetted_training_data": False,
        "explanation": (
            "Historical event counts may overlap existing SQLite observations. "
            "Manual normality review and separated hold-out validation remain mandatory."
        ),
    }


def journal_stream(since: str) -> Iterable[dict[str, Any]]:
    """Use journalctl filters exactly as the existing trusted collector."""
    command = [
        "journalctl",
        "--quiet",
        "--no-pager",
        "--output=json",
        "--since=" + since,
        "_UID=0",
        *PRODUCERS,
    ]
    with subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
    ) as process:
        assert process.stdout is not None
        assert process.stderr is not None
        for line in process.stdout:
            try:
                item = json.loads(line)
            except (ValueError, TypeError):
                continue
            if isinstance(item, dict):
                yield item
        status = process.wait()
        if status:
            raise RuntimeError("Journal read failed (no raw logs disclosed)")


def main(argv: list[str] | None = None) -> int:
    argument_parser = argparse.ArgumentParser(description=__doc__)
    argument_parser.add_argument(
        "--since",
        default="2026-10-22 00:00:00",
        help="Pi-local journal start date, e.g. '2026-10-22 00:00:00'",
    )
    args = argument_parser.parse_args(argv)
    try:
        # Reject shell control characters even though subprocess uses no shell.
        if not 10 <= len(args.since) <= 32 or any(ord(c) < 32 for c in args.since):
            raise ValueError("Invalid start date")
        output = summarize(journal_stream(args.since))
    except (OSError, RuntimeError, ValueError, TypeError) as error:
        print(f"Historical journal audit failed: {type(error).__name__}", file=sys.stderr)
        return 1
    print(json.dumps(output, indent=2, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
