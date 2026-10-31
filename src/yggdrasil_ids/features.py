"""Deterministic SSH observations derived from past events only.

There is one observation per authenticated/failed authentication event. Windows
are (event time - window size, event time], grouped by source. Adjacent rows can
overlap: split whole sessions/scenarios with a window-sized gap for evaluation.
"""

import math
from collections.abc import Sequence

from .domain import SSHEvent

FEATURE_NAMES = (
    "failed_count",
    "success_count",
    "unique_users",
    "failure_ratio",
    "hour_sin",
    "hour_cos",
)


class SSHFeatureBuilder:
    """Build a fixed, documented numeric schema; identities are never encoded."""

    def __init__(self, window_seconds: int = 300) -> None:
        if type(window_seconds) is not int or not 1 <= window_seconds <= 86400:
            raise ValueError("window_seconds skal være mellem 1 og 86400.")
        self.window_seconds = window_seconds

    def build(self, events: Sequence[SSHEvent], event: SSHEvent) -> list[float]:
        if not math.isfinite(event.timestamp) or not 0 <= event.timestamp < 253402300800:
            raise ValueError("Ugyldigt tidspunkt for SSH-observationen.")
        if event.outcome not in {"success", "failure"}:
            raise ValueError("SSH-observationen skal have et kendt loginresultat.")
        start = event.timestamp - self.window_seconds
        # Re-read rows after a restart and duplicate input objects must not change
        # the result. The anchor is included exactly once even for a caller that
        # supplied only preceding events. Stored event IDs are unique in SQLite.
        selected: dict[str, SSHEvent] = {}
        for candidate in events:
            if candidate.source_ip != event.source_ip:
                continue
            if not math.isfinite(candidate.timestamp):
                raise ValueError("Ikke-endeligt tidspunkt i SSH-historikken.")
            if start < candidate.timestamp <= event.timestamp:
                if candidate.outcome not in {"success", "failure"}:
                    raise ValueError("Ukendt loginresultat i SSH-historikken.")
                if candidate.event_id in selected and selected[candidate.event_id] != candidate:
                    raise ValueError("Samme hændelses-ID har modstridende indhold.")
                selected[candidate.event_id] = candidate
        if event.event_id in selected and selected[event.event_id] != event:
            raise ValueError("Ankerhændelsen har modstridende indhold.")
        selected[event.event_id] = event
        failed = sum(item.outcome == "failure" for item in selected.values())
        succeeded = len(selected) - failed
        users = len({item.username for item in selected.values()})
        # Unix timestamps express UTC. This is independent of the host timezone
        # and DST; display timezone does not change the model's feature schema.
        phase = 2 * math.pi * ((event.timestamp % 86400) / 86400)
        return [
            float(failed),
            float(succeeded),
            float(users),
            float(failed / len(selected)),
            math.sin(phase),
            math.cos(phase),
        ]
