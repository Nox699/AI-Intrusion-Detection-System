#!/usr/bin/env python3
"""Read-only, aggregate-only inventory of sudo journal events on the Pi.

Deliberately NOT a production detector: this probes the available journald
producer and message formats without writing to SQLite or exposing users,
commands, directories or process identifiers. Logging formats vary by OS.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Iterable

MAX_JOURNAL_ROWS = 50000
MAX_MESSAGE_BYTES = 16384
KNOWN_CATEGORIES = (
    "command_invoked",
    "pam_auth_failure",
    "incorrect_password",
    "not_in_sudoers",
    "pam_session_opened",
    "pam_session_closed",
    "other_sudo",
)
INCORRECT_PASSWORD = re.compile(r"\b\d+ incorrect password attempt(?:s)?\b", re.I)


def classify(record: object) -> str:
    """Classify only root-owned, genuine sudo journal records.

    SYSLOG_IDENTIFIER alone is untrusted, as an ordinary user can spoof it.
    The journal metadata is used to establish the producing process.
    """
    if not isinstance(record, dict):
        return "ignored"
    uid = record.get("_UID")
    if record.get("_COMM") != "sudo" or not (uid == "0" or type(uid) is int and uid == 0):
        return "ignored"
    message = record.get("MESSAGE")
    if not isinstance(message, str) or len(message.encode("utf-8", "replace")) > MAX_MESSAGE_BYTES:
        return "invalid"
    msg = message.casefold()
    if "not in the sudoers" in msg or "not in sudoers" in msg or "may not run sudo" in msg:
        return "not_in_sudoers"
    if "pam_unix(sudo:auth): authentication failure" in msg:
        return "pam_auth_failure"
    if INCORRECT_PASSWORD.search(message):
        return "incorrect_password"
    if "pam_unix(sudo:session): session opened" in msg:
        return "pam_session_opened"
    if "pam_unix(sudo:session): session closed" in msg:
        return "pam_session_closed"
    if " ; command=" in msg and (" ; user=" in msg or msg.startswith("user=")):
        return "command_invoked"
    return "other_sudo"


def aggregate(records: Iterable[dict[str, Any]]) -> dict[str, Any]:
    counts: Counter[str] = Counter()
    days: Counter[str] = Counter()
    for record in records:
        counts["rows_seen"] += 1
        if counts["rows_seen"] > MAX_JOURNAL_ROWS:
            raise ValueError("Journal scan exceeded bounded row limit")
        category = classify(record)
        counts[category] += 1
        if category in KNOWN_CATEGORIES:
            micros = record.get("__REALTIME_TIMESTAMP")
            try:
                stamp = int(micros)
                if isinstance(micros, bool) or not 0 <= stamp <= 253_402_300_799_999_999:
                    continue
                day = datetime.fromtimestamp(stamp / 1_000_000, timezone.utc).date()
                days[day.isoformat()] += 1
            except (TypeError, ValueError, OverflowError, OSError):
                continue
    return {
        "kind": "read_only_sudo_journal_inventory",
        "rows_seen": counts["rows_seen"],
        "trusted_sudo_rows": sum(counts[category] for category in KNOWN_CATEGORIES),
        "ignored_untrusted_rows": counts["ignored"],
        "invalid_sudo_rows": counts["invalid"],
        "categories": {category: counts[category] for category in KNOWN_CATEGORIES},
        "active_days_utc": dict(sorted(days.items())),
        "production_sudo_detection_active": False,
        "raw_command_lines_exposed": False,
        "warning": (
            "An audit of journal formats, not proof of attack or full sudo coverage. "
            "One command can create multiple messages; category counts are log entries, "
            "not independent privilege escalations."
        ),
    }


def read_journal(since: str) -> Iterable[dict[str, Any]]:
    command = [
        "journalctl",
        "--quiet",
        "--no-pager",
        "--output=json",
        "--since=" + since,
        "_COMM=sudo",
        "_UID=0",
    ]
    child = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        encoding="utf-8",
        errors="replace",
        text=True,
    )
    try:
        assert child.stdout is not None
        for line in child.stdout:
            try:
                record = json.loads(line)
            except (json.JSONDecodeError, UnicodeDecodeError):
                continue
            if isinstance(record, dict):
                yield record
        if child.wait() != 0:
            raise RuntimeError("Journal read failed without disclosing sensitive fields")
    finally:
        if child.poll() is None:
            child.terminate()
            try:
                child.wait(timeout=3)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()
        if child.stdout is not None:
            child.stdout.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--since", default="2026-10-22 00:00:00")
    args = parser.parse_args(argv)
    if not 10 <= len(args.since) <= 32 or any(ord(char) < 32 for char in args.since):
        print("STOP: Invalid --since date format", file=sys.stderr)
        return 2
    records = read_journal(args.since)
    try:
        try:
            result = aggregate(records)
        finally:
            records.close()
    except (OSError, RuntimeError, ValueError, TypeError) as exc:
        print(f"STOP: Read-only sudo audit failed ({type(exc).__name__})", file=sys.stderr)
        return 1
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
