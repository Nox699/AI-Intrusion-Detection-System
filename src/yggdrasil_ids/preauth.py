"""Recognize the two observed OpenSSH preauth disconnect formats."""

from __future__ import annotations

import ipaddress
import re
import unicodedata
from dataclasses import dataclass
from typing import Any, Mapping

PRODUCERS = frozenset({"sshd", "sshd-session", "sshd-auth"})
DISCONNECT = re.compile(
    r"^Connection (?P<kind>closed|reset) by authenticating user "
    r"(?P<username>.+?) (?P<address>\S+) port (?P<port>[0-9]{1,5}) \[preauth\]$"
)


@dataclass(frozen=True)
class PreauthDisconnect:
    source_ip: str
    username: str
    kind: str


def parse_preauth(record: Mapping[str, Any]) -> PreauthDisconnect | None:
    uid = record.get("_UID")
    if not ((type(uid) is int and uid == 0) or (type(uid) is str and uid == "0")):
        return None
    if record.get("_COMM") not in PRODUCERS:
        return None
    message = record.get("MESSAGE")
    if not isinstance(message, str) or len(message) > 4096:
        return None
    if any(unicodedata.category(ch) in {"Cc", "Cf", "Cs"} for ch in message):
        return None
    match = DISCONNECT.fullmatch(message)
    if not match or not 1 <= len(match["username"]) <= 256:
        return None
    if not 1 <= int(match["port"]) <= 65535:
        return None
    try:
        source = ipaddress.ip_address(match["address"])
    except ValueError:
        return None
    return PreauthDisconnect(source.compressed, match["username"], match["kind"])
