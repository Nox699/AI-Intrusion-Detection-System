"""Bounded UFW journal parser, independent of SSH authentication and ML.

Only journal-provided _TRANSPORT=kernel establishes provenance. A matching
MESSAGE or SYSLOG_IDENTIFIER alone does not. This does not defend against
root modifying the journal, or an untrusted imported JSON file. No network,
filesystem, subprocess or database operations are performed by this module.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
import unicodedata
from dataclasses import dataclass

MAX_MESSAGE_LENGTH = 16_384
MAX_TIMESTAMP_US = 4_102_444_800_000_000  # 2100-01-01, consistent with ingestion.
_PREFIX = re.compile(r"^\[UFW (BLOCK|REJECT|ALLOW|AUDIT|LIMIT BLOCK)\] +(.+)$")
_NAMESPACE = re.compile(r"[A-Za-z0-9_./-]{1,128}\Z")
_INTERFACE = re.compile(r"[A-Za-z0-9_.:@+-]{0,64}\Z")
_KEY = re.compile(r"[A-Z][A-Z0-9_]{0,31}\Z")
_DIGITS = re.compile(r"[0-9]{1,18}\Z")
_FLAGS = frozenset({"SYN", "ACK", "FIN", "RST", "PSH", "URG", "ECE", "CWR"})
_REQUIRED = frozenset({"IN", "OUT", "SRC", "DST", "PROTO"})
_SINGLE = _REQUIRED | {"SPT", "DPT"}
_PROTOCOL_NUMBERS = {
    "ICMP": 1,
    "IGMP": 2,
    "TCP": 6,
    "UDP": 17,
    "GRE": 47,
    "ESP": 50,
    "AH": 51,
    "ICMPV6": 58,
    "IPV6-ICMP": 58,
    "SCTP": 132,
    "UDPLITE": 136,
}
_PROTOCOL_NAMES = {value: key for key, value in _PROTOCOL_NUMBERS.items()}
_PROTOCOL_NAMES[58] = "ICMPV6"


@dataclass(frozen=True)
class FirewallEvent:
    """A recorded packet, not a unique connection, attack or authenticated user."""

    event_id: str
    namespace: str
    timestamp: float
    cursor: str
    boot_id: str
    host: str
    action: str
    direction: str
    in_interface: str
    out_interface: str
    source_ip: str
    destination_ip: str
    ip_version: int
    protocol: str
    protocol_number: int
    source_port: int | None
    destination_port: int | None
    packet_length: int | None
    transport_length: int | None
    tcp_flags: tuple[str, ...]


@dataclass(frozen=True)
class FirewallParseResult:
    status: str
    event: FirewallEvent | None = None
    reason: str = ""


def _plain_text(value: object, limit: int, *, empty: bool = False) -> bool:
    return (
        isinstance(value, str)
        and (empty or bool(value))
        and len(value) <= limit
        and not any(unicodedata.category(char) in {"Cc", "Cf", "Cs"} for char in value)
    )


def _number(value: str, maximum: int) -> int:
    if not _DIGITS.fullmatch(value):
        raise ValueError("Not an unsigned decimal integer")
    result = int(value)
    if result > maximum:
        raise ValueError("Integer outside supported bounds")
    return result


def _fields(body: str) -> tuple[dict[str, str], list[int], tuple[str, ...]]:
    # Nested ICMP packet dumps may repeat SRC/DST/PROTO; never confuse their
    # embedded headers with the outer packet. Such formats are not supported.
    if "[" in body or "]" in body:
        raise ValueError("Nested packet headers not supported")
    fields: dict[str, str] = {}
    lengths: list[int] = []
    flags: set[str] = set()
    tokens = body.split(" ")
    if len(tokens) > 256:
        raise ValueError("Too many log tokens")
    for token in tokens:
        if not token:
            continue
        if "=" not in token:
            if token in _FLAGS:
                flags.add(token)
            continue
        key, value = token.split("=", 1)
        if not _KEY.fullmatch(key):
            raise ValueError("Invalid field name")
        if key == "LEN":
            # UFW UDP examples have IP LEN and UDP LEN. Do not overwrite one.
            lengths.append(_number(value, 1_048_576))
            if len(lengths) > 2:
                raise ValueError("Ambiguous length fields")
        elif key in _SINGLE:
            if key in fields:
                raise ValueError("Duplicate identity or port field")
            fields[key] = value
    if not _REQUIRED <= fields.keys():
        raise ValueError("Missing packet identity fields")
    return fields, lengths, tuple(sorted(flags))


class UFWParser:
    """Recognize the supported kernel UFW format; never infer an attack."""

    def parse(self, record: object, namespace: str = "live") -> FirewallParseResult:
        if not isinstance(record, dict):
            return FirewallParseResult("malformed", reason="Journalposten er ikke et objekt.")
        if not isinstance(namespace, str) or not _NAMESPACE.fullmatch(namespace):
            return FirewallParseResult("malformed", reason="Ugyldigt datanavnerum.")
        if record.get("_TRANSPORT") != "kernel":
            return FirewallParseResult("ignored", reason="Posten er ikke fra kernel-transporten.")
        message = record.get("MESSAGE")
        if not _plain_text(message, MAX_MESSAGE_LENGTH):
            return FirewallParseResult("malformed", reason="Ugyldig eller for stor meddelelse.")
        match = _PREFIX.fullmatch(message)
        if match is None:
            return FirewallParseResult("ignored", reason="Ikke et understøttet UFW-logpræfiks.")
        try:
            fields, lengths, flags = _fields(match[2])
            cursor = record.get("__CURSOR")
            if not _plain_text(cursor, 4096):
                raise ValueError("Missing or invalid journal cursor")
            raw_timestamp = record.get("__REALTIME_TIMESTAMP")
            if type(raw_timestamp) not in (str, int):
                raise ValueError("Invalid journal timestamp type")
            timestamp = _number(str(raw_timestamp), MAX_TIMESTAMP_US) / 1_000_000
            host = record.get("_HOSTNAME", "")
            boot_id = record.get("_BOOT_ID", "")
            if not _plain_text(host, 255, empty=True):
                raise ValueError("Invalid host label")
            if not isinstance(boot_id, str) or (
                boot_id and not re.fullmatch(r"[0-9a-fA-F]{32}", boot_id)
            ):
                raise ValueError("Invalid boot identity")
            incoming, outgoing = fields["IN"], fields["OUT"]
            if not _INTERFACE.fullmatch(incoming) or not _INTERFACE.fullmatch(outgoing):
                raise ValueError("Invalid interface")
            if "%" in fields["SRC"] or "%" in fields["DST"]:
                raise ValueError("Address scope must come from interface fields")
            source = ipaddress.ip_address(fields["SRC"])
            destination = ipaddress.ip_address(fields["DST"])
            if source.version != destination.version:
                raise ValueError("Mixed IP families")
            raw_protocol = fields["PROTO"].upper()
            number = _PROTOCOL_NUMBERS.get(raw_protocol)
            if number is None:
                number = _number(raw_protocol, 255)
            if (number in {1, 2} and source.version != 4) or (
                number == 58 and source.version != 6
            ):
                raise ValueError("Protocol incompatible with IP family")
            source_port = destination_port = None
            if ("SPT" in fields) != ("DPT" in fields):
                raise ValueError("Incomplete port pair")
            if "SPT" in fields:
                if number not in {6, 17, 132, 136}:
                    raise ValueError("Ports on a protocol without supported port semantics")
                source_port = _number(fields["SPT"], 65_535)
                destination_port = _number(fields["DPT"], 65_535)
            if len(lengths) == 2 and number not in {17, 136}:
                raise ValueError("Unexpected second length")
            if number != 6 and flags:
                raise ValueError("TCP flags on another protocol")
        except (ValueError, TypeError, OverflowError):
            # Never copy arbitrary log text, addresses or metadata into errors.
            return FirewallParseResult("malformed", reason="Ugyldige eller tvetydige UFW-felter.")

        if incoming and outgoing:
            direction = "forwarded"
        elif incoming:
            direction = "incoming"
        elif outgoing:
            direction = "outgoing"
        else:
            direction = "unknown"
        event_id = hashlib.sha256(f"{namespace}\0ufw\0{cursor}".encode()).hexdigest()
        return FirewallParseResult(
            "event",
            FirewallEvent(
                event_id=event_id,
                namespace=namespace,
                timestamp=timestamp,
                cursor=cursor,
                boot_id=boot_id.lower(),
                host=host,
                action=match[1],
                direction=direction,
                in_interface=incoming,
                out_interface=outgoing,
                source_ip=source.compressed,
                destination_ip=destination.compressed,
                ip_version=source.version,
                protocol=_PROTOCOL_NAMES.get(number, str(number)),
                protocol_number=number,
                source_port=source_port,
                destination_port=destination_port,
                packet_length=lengths[0] if lengths else None,
                transport_length=lengths[1] if len(lengths) == 2 else None,
                tcp_flags=flags,
            ),
        )
