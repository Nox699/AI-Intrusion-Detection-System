"""Isolated, explainable sudo rule prototype. NOT wired to the live collector.

Only journald-trusted _EXE=/usr/bin/sudo is accepted. Parsed signals contain
no commands, usernames, passwords, or free-form messages. Rules are bounded
and meant for offline replay; they do not send notifications or write data.
"""

from __future__ import annotations

import re
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Mapping

MAX_MESSAGE_BYTES = 16_384
MAX_TIMESTAMP_US = 4_102_444_800_000_000
_UID_MAX = 2**32 - 1
_PID_MAX = 2**31 - 1
_BOOT = re.compile(r"[0-9a-fA-F]{32}\Z")
_DIGITS = re.compile(r"[0-9]+\Z")

# Command records can contain adversarial text. Recognize their envelope
# BEFORE any error wording, so COMMAND arguments cannot masquerade as PAM.
_COMMAND = re.compile(
    r"^\s*[^\s:]{1,64}\s*:\s+TTY=[^;\r\n]{1,512}\s*;\s*"
    r"PWD=[^;\r\n]{1,1024}\s*;\s*USER=[^;\r\n]{1,64}\s*;\s*COMMAND=",
    re.I,
)
_AUTH_FAILURE = re.compile(r"^pam_unix\(sudo:auth\): authentication failure(?:;|\s|$)", re.I)
_PASSWORD_SUMMARY = re.compile(
    r"^\s*[^\s:]{1,64}\s*:\s*[0-9]+ incorrect password attempt(?:s)?(?:\s*;|$)",
    re.I,
)
_DENIED = re.compile(
    r"^\s*[^\s:]{1,64}\s+(?:is not in (?:the )?sudoers file|may not run sudo)\b",
    re.I,
)
_PAM_OPEN = re.compile(r"^pam_unix\(sudo:session\): session opened(?:\s|$)", re.I)
_PAM_CLOSE = re.compile(r"^pam_unix\(sudo:session\): session closed(?:\s|$)", re.I)

KINDS = (
    "command_invoked",
    "pam_auth_failure",
    "incorrect_password",
    "not_in_sudoers",
    "pam_session_opened",
    "pam_session_closed",
    "other_sudo",
)
_FAILURE_KINDS = frozenset({"pam_auth_failure", "incorrect_password"})


def _number(value: object, minimum: int, maximum: int) -> int | None:
    if type(value) is int:
        result = value
    elif isinstance(value, str) and len(value) <= 20 and _DIGITS.fullmatch(value):
        result = int(value)
    else:
        return None
    return result if minimum <= result <= maximum else None


def _kind(message: str) -> str:
    if _COMMAND.match(message):
        return "command_invoked"
    if _AUTH_FAILURE.match(message):
        return "pam_auth_failure"
    if _PASSWORD_SUMMARY.match(message):
        return "incorrect_password"
    if _DENIED.match(message):
        return "not_in_sudoers"
    if _PAM_OPEN.match(message):
        return "pam_session_opened"
    if _PAM_CLOSE.match(message):
        return "pam_session_closed"
    return "other_sudo"


@dataclass(frozen=True)
class SudoSignal:
    """Only trusted journal metadata and one coarse category; kept in memory."""

    cursor: str
    timestamp: float
    boot_id: str
    uid: str
    pid: int
    kind: str


@dataclass(frozen=True)
class SudoParseResult:
    status: str
    signal: SudoSignal | None = None


def parse_sudo(record: object) -> SudoParseResult:
    if not isinstance(record, Mapping):
        return SudoParseResult("malformed")
    if record.get("_EXE") != "/usr/bin/sudo":
        return SudoParseResult("ignored")
    message = record.get("MESSAGE")
    if (
        not isinstance(message, str)
        or len(message.encode("utf-8", "replace")) > MAX_MESSAGE_BYTES
        or any(char in message for char in ("\x00", "\r", "\n"))
    ):
        return SudoParseResult("malformed")

    cursor = record.get("__CURSOR")
    boot = record.get("_BOOT_ID")
    uid = _number(record.get("_UID"), 0, _UID_MAX)
    pid = _number(record.get("_PID"), 1, _PID_MAX)
    timestamp = _number(record.get("__REALTIME_TIMESTAMP"), 0, MAX_TIMESTAMP_US)
    if (
        not isinstance(cursor, str)
        or not 1 <= len(cursor) <= 4096
        or not isinstance(boot, str)
        or _BOOT.fullmatch(boot) is None
        or uid is None
        or pid is None
        or timestamp is None
    ):
        return SudoParseResult("malformed")
    return SudoParseResult(
        "event",
        SudoSignal(
            cursor=cursor,
            timestamp=timestamp / 1_000_000,
            boot_id=boot.lower(),
            uid=str(uid),
            pid=pid,
            kind=_kind(message),
        ),
    )


@dataclass(frozen=True)
class SudoRuleConfig:
    window_seconds: int = 300
    failure_process_threshold: int = 3
    cooldown_seconds: int = 300
    max_records: int = 10_000

    def __post_init__(self) -> None:
        for value, minimum, maximum in (
            (self.window_seconds, 60, 3600),
            (self.failure_process_threshold, 2, 20),
            (self.cooldown_seconds, 60, 3600),
            (self.max_records, 100, 50_000),
        ):
            if type(value) is not int or not minimum <= value <= maximum:
                raise ValueError("Invalid offline sudo rule configuration")


@dataclass(frozen=True)
class SudoRuleMatch:
    detector_id: str
    severity: str
    count: int
    timestamp: float


class SudoRuleDetector:
    """Host-local offline replay with per-process deduplication and cooldown.

    Failure counts represent distinct sudo process IDs per boot/user-UID in a
    window, NOT incorrect password counts. UID is only an internal grouping
    approximation: it is not a validated human identity. No persistent state.
    """

    def __init__(self, config: SudoRuleConfig | None = None):
        self.config = config or SudoRuleConfig()
        self.seen: dict[str, SudoSignal] = {}
        self.failure_windows: dict[tuple[str, str], deque[tuple[float, int]]] = defaultdict(
            deque
        )
        self.last_match: dict[tuple[str, str, str], float] = {}
        self.last_timestamp: float | None = None

    def evaluate(self, event: SudoSignal) -> SudoRuleMatch | None:
        if not isinstance(event, SudoSignal) or event.kind not in KINDS:
            raise ValueError("Unexpected sudo signal")
        if self.last_timestamp is not None and event.timestamp < self.last_timestamp:
            raise ValueError("Sudo replay must be chronological")
        previous = self.seen.get(event.cursor)
        if previous is not None:
            if previous != event:
                raise ValueError("Conflicting sudo journal cursor")
            return None
        if len(self.seen) >= self.config.max_records:
            raise ValueError("Sudo replay exceeded record bound")
        self.seen[event.cursor] = event
        self.last_timestamp = event.timestamp

        if event.kind in _FAILURE_KINDS:
            group = (event.boot_id, event.uid)
            window = self.failure_windows[group]
            cutoff = event.timestamp - self.config.window_seconds
            while window and window[0][0] <= cutoff:
                window.popleft()
            # The PAM failure and later summary of the same sudo process
            # constitute ONE candidate attempt, even if several prompts failed.
            if not any(pid == event.pid for _, pid in window):
                window.append((event.timestamp, event.pid))
            if len(window) < self.config.failure_process_threshold:
                return None
            return self._maybe_match(
                event, "sudo.repeated_auth_failure", len(window), "medium"
            )

        if event.kind == "not_in_sudoers":
            return self._maybe_match(event, "sudo.permission_denied", 1, "medium")
        return None

    def _maybe_match(
        self, event: SudoSignal, detector_id: str, count: int, severity: str
    ) -> SudoRuleMatch | None:
        group = (event.boot_id, event.uid, detector_id)
        last = self.last_match.get(group)
        if last is not None and event.timestamp - last < self.config.cooldown_seconds:
            return None
        self.last_match[group] = event.timestamp
        return SudoRuleMatch(detector_id, severity, count, event.timestamp)
