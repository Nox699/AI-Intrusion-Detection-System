"""Parse authenticated OpenSSH journal records without counting PAM twice.

Only journal fields prefixed with ``_`` are used to establish the producer. A
SYSLOG_IDENTIFIER of ``sshd`` alone is not sufficient: ``logger -t sshd`` can
set that tag. This is a provenance check for ordinary processes, not a defence
against an attacker already controlling root or supplied replay files.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import unicodedata
from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any

from .domain import ParseResult, SSHEvent

_PRODUCERS = frozenset({"sshd", "sshd-session", "sshd-auth"})
_AUTH = re.compile(
    r"^(?P<action>Accepted|Failed) "
    r"(?P<method>[A-Za-z0-9][A-Za-z0-9@._+/-]{0,63}) for "
    r"(?:invalid user )?(?P<username>.+?) from "
    r"(?P<address>\S+) port (?P<port>[0-9]{1,5}) ssh[12](?:[ :].*)?$"
)
_AUTH_PREFIX = re.compile(r"^(?:Accepted|Failed) \S+ for(?: |$)")
_DIGITS = re.compile(r"^[0-9]{1,18}$")
_SCOPE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
MAX_MESSAGE_LENGTH = 16_384
MAX_STORED_MESSAGE_LENGTH = 4_096
MAX_RECORD_BYTES = 65_536


def _has_control(value: str) -> bool:
    """Reject log-injection controls, bidi overrides and invalid surrogates."""
    return any(unicodedata.category(char) in {"Cc", "Cf", "Cs"} for char in value)


def _timestamp(value: Any) -> float:
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        raise ValueError("Tidsstemplet skal være journalens heltal i mikrosekunder.")
    text = str(value)
    if not _DIGITS.fullmatch(text):
        raise ValueError("Journalens tidsstempel er ugyldigt.")
    microseconds = int(text)
    # datetime's supported UTC range also bounds integer-to-float conversion.
    if microseconds > 253_402_300_799_999_999:
        raise ValueError("Journalens tidsstempel ligger uden for det understøttede område.")
    result = microseconds / 1_000_000
    try:
        datetime.fromtimestamp(result, timezone.utc)
    except (ValueError, OverflowError, OSError) as exc:
        raise ValueError("Journalens tidsstempel kan ikke fortolkes.") from exc
    return result


def _event_id(record: Mapping[str, Any], namespace: str, cursor: str) -> str:
    digest = hashlib.sha256()
    digest.update(namespace.encode("utf-8"))
    digest.update(b"\0")
    if cursor:
        digest.update(b"cursor\0")
        digest.update(cursor.encode("utf-8"))
    else:
        digest.update(b"record\0")
        # Streaming canonical encoding bounds work on accidentally huge records.
        size = 0
        encoder = json.JSONEncoder(
            sort_keys=True, ensure_ascii=True, separators=(",", ":"), allow_nan=False
        )
        for chunk in encoder.iterencode(record):
            encoded = chunk.encode("ascii")
            size += len(encoded)
            if size > MAX_RECORD_BYTES:
                raise ValueError("Journalposten er for stor.")
            digest.update(encoded)
    return digest.hexdigest()


def _optional_text(record: Mapping[str, Any], name: str, limit: int) -> str:
    value = record.get(name, "")
    if not isinstance(value, str) or _has_control(value):
        return ""
    return value[:limit]


class SSHParser:
    """Convert one journal JSON object into zero or one authentication event."""

    def parse(self, record: dict, namespace: str = "live") -> ParseResult:
        if not isinstance(record, dict):
            return ParseResult("malformed", reason="Journalposten er ikke et JSON-objekt.")
        if (
            not isinstance(namespace, str)
            or not namespace
            or len(namespace) > 1_024
            or _has_control(namespace)
        ):
            return ParseResult("malformed", reason="Datakildens navnerum er ugyldigt.")

        uid = record.get("_UID")
        comm = record.get("_COMM")
        is_root_uid = (isinstance(uid, str) and uid == "0") or (type(uid) is int and uid == 0)
        if not is_root_uid or not isinstance(comm, str) or comm not in _PRODUCERS:
            return ParseResult(
                "ignored", reason="Posten har ikke en verificeret OpenSSH-producent med UID 0."
            )

        message = record.get("MESSAGE")
        if not isinstance(message, str):
            return ParseResult("malformed", reason="Journalpostens MESSAGE er ikke tekst.")
        if len(message) > MAX_MESSAGE_LENGTH:
            return ParseResult("malformed", reason="SSH-meddelelsen overskrider længdegrænsen.")
        # Invalid-user notices and PAM session messages supply context, but they
        # are not additional successful or failed authentication attempts.
        if not _AUTH_PREFIX.match(message):
            return ParseResult("ignored", reason="Posten er ikke et autentificeringsresultat.")
        if _has_control(message):
            return ParseResult("malformed", reason="SSH-meddelelsen indeholder kontroltegn.")
        match = _AUTH.fullmatch(message)
        if match is None:
            return ParseResult("malformed", reason="SSH-autentificeringsformatet genkendes ikke.")

        username = match["username"]
        if not username.strip() or len(username) > 256:
            return ParseResult("malformed", reason="Brugernavnet er tomt eller for langt.")
        port = int(match["port"])
        if not 1 <= port <= 65_535:
            return ParseResult("malformed", reason="Kildeporten er ugyldig.")

        try:
            address = ipaddress.ip_address(match["address"])
            if getattr(address, "scope_id", None) and not _SCOPE.fullmatch(address.scope_id):
                raise ValueError("Ugyldigt IPv6-interface.")
            timestamp = _timestamp(record.get("__REALTIME_TIMESTAMP"))
            cursor = record.get("__CURSOR", "")
            if not isinstance(cursor, str) or len(cursor) > 4_096 or _has_control(cursor):
                raise ValueError("Journalens cursor er ugyldig.")
            event_id = _event_id(record, namespace, cursor)
        except (ValueError, TypeError, OverflowError, RecursionError, UnicodeError):
            return ParseResult(
                "malformed", reason="IP, tidsstempel eller kildeidentitet er ugyldig."
            )

        stored_message = message
        if len(stored_message) > MAX_STORED_MESSAGE_LENGTH:
            stored_message = stored_message[: MAX_STORED_MESSAGE_LENGTH - 1] + "…"
        return ParseResult(
            "event",
            event=SSHEvent(
                event_id=event_id,
                timestamp=timestamp,
                source_ip=address.compressed,
                username=username,
                outcome="success" if match["action"] == "Accepted" else "failure",
                auth_method=match["method"],
                host=_optional_text(record, "_HOSTNAME", 255),
                message=stored_message,
                pid=_optional_text(record, "_PID", 20),
                cursor=cursor,
            ),
        )
