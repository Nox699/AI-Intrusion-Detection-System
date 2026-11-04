"""Bounded preparation of explicitly reviewed normal SSH journal observations.

This module converts local input into the same six features used at runtime.
It does not label events as normal, fit a model or modify the running collector.
"""

from __future__ import annotations

import json
from collections import defaultdict, deque
from pathlib import Path

from .domain import SSHEvent
from .features import SSHFeatureBuilder
from .ml import MAX_TRAINING_ROWS
from .ssh import SSHParser

MAX_INPUT_RECORDS = 50_000
MAX_INPUT_BYTES = 64 * 1024 * 1024
MAX_LINE_BYTES = 65_536


def _reject_constant(value: str) -> None:
    raise ValueError(f"Ugyldig numerisk JSON-konstant: {value}")


def _read_events(path: Path) -> list[SSHEvent]:
    parser = SSHParser()
    events: list[SSHEvent] = []
    seen: dict[str, SSHEvent] = {}
    previous = float("-inf")
    consumed_bytes = 0
    with Path(path).open("rb") as handle:
        line_number = 0
        while raw := handle.readline(MAX_LINE_BYTES + 1):
            line_number += 1
            consumed_bytes += len(raw)
            if (
                len(raw) > MAX_LINE_BYTES
                or consumed_bytes > MAX_INPUT_BYTES
                or line_number > MAX_INPUT_RECORDS
            ):
                raise ValueError(f"{path.name}: inputgrænse overskredet ved linje {line_number}.")
            if not raw.strip():
                continue
            try:
                record = json.loads(raw, parse_constant=_reject_constant)
            except (ValueError, UnicodeError, RecursionError) as exc:
                raise ValueError(f"{path.name}: ugyldig JSON ved linje {line_number}.") from exc
            result = parser.parse(record, namespace="training")
            if result.status == "malformed":
                raise ValueError(
                    f"{path.name}: ugyldig SSH-post ved linje {line_number}: {result.reason}"
                )
            if result.event is None:
                continue
            event = result.event
            if event.event_id in seen:
                if seen[event.event_id] != event:
                    raise ValueError(
                        f"{path.name}: modstridende hændelses-ID ved linje {line_number}."
                    )
                continue
            if event.timestamp < previous:
                raise ValueError(
                    f"{path.name}: hændelserne er ikke i kronologisk rækkefølge ved linje {line_number}."
                )
            previous = event.timestamp
            events.append(event)
            seen[event.event_id] = event
            if len(events) > MAX_TRAINING_ROWS:
                raise ValueError(
                    f"{path.name}: højst {MAX_TRAINING_ROWS} autentificeringshændelser understøttes."
                )
    if not events:
        raise ValueError(f"{path.name}: ingen gyldige SSH-autentificeringer blev fundet.")
    return events


def _feature_rows(events: list[SSHEvent], window_seconds: int) -> list[list[float]]:
    builder = SSHFeatureBuilder(window_seconds)
    history: dict[str, deque[SSHEvent]] = defaultdict(deque)
    rows = []
    for event in events:
        group = history[event.source_ip]
        while group and group[0].timestamp <= event.timestamp - window_seconds:
            group.popleft()
        group.append(event)
        rows.append(builder.build(group, event))
    return rows


def prepare_rows(path: Path, window_seconds: int = 300) -> list[list[float]]:
    """Turn chronologically ordered journal JSONL into bounded feature rows.

    PAM/context rows are ignored and exact duplicate auth rows are deduplicated.
    Malformed authentication records, reversed event times and empty input fail
    with a concrete error. This function does not read labels or train a model.
    """
    return _feature_rows(_read_events(Path(path)), window_seconds)
