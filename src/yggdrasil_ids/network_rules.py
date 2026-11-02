"""Pure, bounded detection of a suspected blocked TCP SYN port scan.

The caller supplies parsed events from one bounded historical window. There
is no live collector, DB write, firewall change or Discord call in this module.
Integration must persist unique findings and apply incident grouping separately.
"""

from __future__ import annotations

import ipaddress
import math
from collections.abc import Iterable
from dataclasses import dataclass

from .firewall import FirewallEvent

MAX_EVIDENCE_PORTS = 64


@dataclass(frozen=True)
class NetworkRuleConfig:
    window_seconds: int = 60
    distinct_ports_threshold: int = 6
    max_history_records: int = 10_000

    def __post_init__(self) -> None:
        for value, low, high in (
            (self.window_seconds, 10, 3600),
            (self.distinct_ports_threshold, 2, MAX_EVIDENCE_PORTS),
            (self.max_history_records, self.distinct_ports_threshold, 50_000),
        ):
            if type(value) is not int or not low <= value <= high:
                raise ValueError("Ugyldig netværksregelkonfiguration.")


@dataclass(frozen=True)
class NetworkFinding:
    """Separate from SSH findings, which reference authentication events."""

    event_id: str
    source_ip: str
    destination_ip: str
    in_interface: str
    timestamp: float
    first_seen: float
    last_seen: float
    window_seconds: int
    threshold: int
    distinct_ports: int
    recorded_packets: int
    destination_ports: tuple[int, ...]
    evidence_ids: tuple[str, ...]
    evidence_truncated: bool
    detector_id: str = "network.tcp_port_scan"
    title: str = "Mulig TCP-portscanning"
    severity: str = "medium"

    @property
    def reason(self) -> str:
        return (
            f"Registrerede blokerede TCP SYN-pakker til {self.distinct_ports} forskellige "
            f"destinationsporte inden for {self.window_seconds} sekunder "
            f"(grænse: {self.threshold}). Samme kilde, destination og indgående interface. "
            "Logningen kan være ratebegrænset; mønstret er ikke bevis for et angreb."
        )


class NetworkWindowOverflow(ValueError):
    """A window was truncated: report a quality error, never a normal result."""


def _eligible(event: FirewallEvent) -> bool:
    if (
        event.action not in {"BLOCK", "REJECT", "LIMIT BLOCK"}
        or event.direction != "incoming"
        or not event.in_interface
        or event.out_interface
        or event.protocol_number != 6
        or event.destination_port is None
        or "SYN" not in event.tcp_flags
        or {"ACK", "RST", "FIN"}.intersection(event.tcp_flags)
    ):
        return False
    for value in (event.source_ip, event.destination_ip):
        address = ipaddress.ip_address(value)
        if (
            address.is_multicast
            or address.is_unspecified
            or address.is_loopback
            or value == "255.255.255.255"
        ):
            return False
    return True


def _group(event: FirewallEvent) -> tuple[str, ...]:
    return (
        event.namespace,
        event.host,
        event.boot_id,
        event.source_ip,
        event.destination_ip,
        event.in_interface,
    )


class TCPPortScanDetector:
    """Evaluate unique destination ports in (event_time-window, event_time].

    This first detector intentionally excludes UDP, multicast, outbound and
    forwarded traffic, and TCP ACK/FIN/RST-only probes. It is not a complete
    network IDS. Private-address sources are not silently allowlisted.
    """

    def __init__(self, config: NetworkRuleConfig | None = None):
        self.config = config or NetworkRuleConfig()

    def evaluate(
        self, event: FirewallEvent, history: Iterable[FirewallEvent]
    ) -> NetworkFinding | None:
        if not isinstance(event, FirewallEvent):
            raise TypeError("Forventede en fortolket firewallhændelse.")
        if not math.isfinite(event.timestamp):
            raise ValueError("Ugyldigt hændelsestidspunkt.")
        if not _eligible(event):
            return None
        start = event.timestamp - self.config.window_seconds
        group = _group(event)
        eligible: dict[str, FirewallEvent] = {}
        seen: dict[str, FirewallEvent] = {event.event_id: event}
        for index, item in enumerate(history):
            if index >= self.config.max_history_records:
                raise NetworkWindowOverflow("Netværksvinduet overstiger datagrænsen.")
            if not isinstance(item, FirewallEvent) or not math.isfinite(item.timestamp):
                raise ValueError("Ugyldig hændelse i netværksvinduet.")
            old = seen.get(item.event_id)
            if old is not None and old != item:
                raise ValueError("Samme hændelses-ID har forskelligt indhold.")
            seen[item.event_id] = item
            if start < item.timestamp <= event.timestamp and _group(item) == group:
                if _eligible(item):
                    eligible[item.event_id] = item
        eligible[event.event_id] = event
        ports: dict[int, FirewallEvent] = {}
        for item in sorted(eligible.values(), key=lambda value: (value.timestamp, value.event_id)):
            ports.setdefault(item.destination_port, item)
        if len(ports) < self.config.distinct_ports_threshold:
            return None
        sampled_ports = tuple(sorted(ports)[:MAX_EVIDENCE_PORTS])
        return NetworkFinding(
            event_id=event.event_id,
            source_ip=event.source_ip,
            destination_ip=event.destination_ip,
            in_interface=event.in_interface,
            timestamp=event.timestamp,
            first_seen=min(item.timestamp for item in eligible.values()),
            last_seen=event.timestamp,
            window_seconds=self.config.window_seconds,
            threshold=self.config.distinct_ports_threshold,
            distinct_ports=len(ports),
            recorded_packets=len(eligible),
            destination_ports=sampled_ports,
            evidence_ids=tuple(ports[port].event_id for port in sampled_ports),
            evidence_truncated=len(ports) > MAX_EVIDENCE_PORTS,
        )
