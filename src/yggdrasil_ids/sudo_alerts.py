"""Safe, offline representation of sudo rule candidates for notifier previews.

No webhook, database write, dashboard or network action occurs here.
The source signal remains local; only a stable short SHA-256 reference,
coarse detector, severity and event time enter the notification view.
"""

from __future__ import annotations

from .sudo_rules import SudoRuleMatch, SudoSignal
from .sudo_storage import event_id, validate_candidate, validate_signal


def notification_event(signal: SudoSignal, candidate: SudoRuleMatch) -> dict[str, object]:
    """Translate a verified sudo rule match to the existing notifier's fields."""
    validate_signal(signal)
    if not isinstance(candidate, SudoRuleMatch):
        raise ValueError("A real sudo rule candidate is required")
    validate_candidate(candidate, signal)
    return {
        "detector_id": candidate.detector_id,
        "severity": candidate.severity,
        "happened_at": candidate.timestamp,
        "ref": "sudo-" + event_id(signal)[:20],
    }
