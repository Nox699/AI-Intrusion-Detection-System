"""Stateless SSH rules; incident grouping belongs to the persistence layer."""

from __future__ import annotations

import ipaddress
from collections.abc import Sequence
from typing import TYPE_CHECKING

from .domain import Finding, SSHEvent

if TYPE_CHECKING:
    from .config import RulesConfig


class SSHRuleDetector:
    """Explain explicit policy/threshold matches on an event-time window."""

    def __init__(self, config: RulesConfig):
        self.config = config
        for name in ("window_seconds", "failure_threshold", "username_threshold"):
            value = getattr(config, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise ValueError(f"{name} skal være et positivt heltal.")
        self._networks = tuple(
            ipaddress.ip_network(value, strict=False) for value in config.expected_sources
        )
        self._users = frozenset(config.expected_users)

    def detect(self, event: SSHEvent, history: Sequence[SSHEvent]) -> list[Finding]:
        if event.outcome not in {"success", "failure"}:
            return []
        start = event.timestamp - self.config.window_seconds
        # Repeated replay input and the current event must each count only once.
        by_id = {
            item.event_id: item
            for item in history
            if item.source_ip == event.source_ip
            and start < item.timestamp <= event.timestamp
            and item.outcome in {"success", "failure"}
        }
        by_id[event.event_id] = event
        recent = sorted(by_id.values(), key=lambda item: (item.timestamp, item.event_id))
        failures = [item for item in recent if item.outcome == "failure"]
        users = sorted({item.username for item in failures})
        evidence = {
            "window_start": start,
            "window_end": event.timestamp,
            "window_seconds": self.config.window_seconds,
            "failure_count": len(failures),
            "unique_users": len(users),
            "usernames": users[:20],
            "event_ids": [item.event_id for item in failures[-20:]],
        }
        findings: list[Finding] = []
        if event.outcome == "failure" and len(failures) >= self.config.failure_threshold:
            findings.append(
                Finding(
                    detector_id="ssh.failed_burst",
                    title="Mange fejlede SSH-loginforsøg",
                    severity="high",
                    reason=(
                        f"{len(failures)} fejlede autentificeringer fra {event.source_ip} "
                        f"inden for {self.config.window_seconds} sekunder. "
                        f"Reglens grænse er {self.config.failure_threshold}."
                    ),
                    source_ip=event.source_ip,
                    event_id=event.event_id,
                    timestamp=event.timestamp,
                    details={**evidence, "threshold": self.config.failure_threshold},
                )
            )
        if event.outcome == "failure" and len(users) >= self.config.username_threshold:
            findings.append(
                Finding(
                    detector_id="ssh.user_spray",
                    title="Fejlede SSH-forsøg mod flere brugernavne",
                    severity="high",
                    reason=(
                        f"Fejlede forsøg mod {len(users)} forskellige brugernavne fra "
                        f"{event.source_ip} inden for {self.config.window_seconds} sekunder. "
                        f"Reglens grænse er {self.config.username_threshold}."
                    ),
                    source_ip=event.source_ip,
                    event_id=event.event_id,
                    timestamp=event.timestamp,
                    details={**evidence, "threshold": self.config.username_threshold},
                )
            )
        if event.outcome == "success":
            source = ipaddress.ip_address(event.source_ip)
            unexpected_source = bool(self._networks) and not any(
                source in network for network in self._networks
            )
            unexpected_user = bool(self._users) and event.username not in self._users
            if unexpected_source or unexpected_user:
                reasons = []
                if unexpected_source:
                    reasons.append("kilden er uden for de forventede adresser")
                if unexpected_user:
                    reasons.append("brugeren er uden for den forventede brugergruppe")
                findings.append(
                    Finding(
                        detector_id="ssh.unexpected_success",
                        title="SSH-login uden for forventet profil",
                        severity="medium",
                        reason="Vellykket autentificering: " + "; ".join(reasons) + ".",
                        source_ip=event.source_ip,
                        event_id=event.event_id,
                        timestamp=event.timestamp,
                        details={
                            "unexpected_source": unexpected_source,
                            "unexpected_user": unexpected_user,
                            "username": event.username,
                            "auth_method": event.auth_method,
                            "event_ids": [event.event_id],
                        },
                    )
                )
        return findings
