#!/usr/bin/env python3
"""Read-only, privacy-preserving sudo event inventory based on executable provenance.

The original audit required (_COMM=sudo AND _UID=0) and missed all real Pi
records. This version requires journald's trusted _EXE=/usr/bin/sudo field,
irrespective of the logging process's UID or _COMM, and emits aggregate
counts only. It reads all journals accessible to the worker, not just --system. No SQLite, systemd, sudoers, firewall or notifier changes.
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

EXPECTED_EXE = "/usr/bin/sudo"
MAX_ROWS = 10000
MAX_MESSAGE_BYTES = 16384
CATEGORIES = (
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
    """Only kernel/journal-attributed sudo executable records qualify.

    SYSLOG_IDENTIFIER is *never* considered provenance: it can be spoofed.
    Classification is heuristic and is not proof of attack or authorization.
    """
    if not isinstance(record, dict):
        return "invalid_json_or_structure"
    if record.get("_EXE") != EXPECTED_EXE:
        return "untrusted_executable"
    message = record.get("MESSAGE")
    if not isinstance(message, str) or len(message.encode("utf-8", "replace")) > MAX_MESSAGE_BYTES:
        return "invalid_sudo_message"
    lowered = message.casefold()
    if (
        "not in the sudoers" in lowered
        or "not in sudoers" in lowered
        or "may not run sudo" in lowered
    ):
        return "not_in_sudoers"
    if "pam_unix(sudo:auth): authentication failure" in lowered:
        return "pam_auth_failure"
    if INCORRECT_PASSWORD.search(message):
        return "incorrect_password"
    if "pam_unix(sudo:session): session opened" in lowered:
        return "pam_session_opened"
    if "pam_unix(sudo:session): session closed" in lowered:
        return "pam_session_closed"
    if " ; command=" in lowered and (" ; user=" in lowered or lowered.startswith("user=")):
        return "command_invoked"
    return "other_sudo"


def aggregate(records: Iterable[dict[str, Any]]) -> dict[str, Any]:
    counts: Counter[str] = Counter()
    days: Counter[str] = Counter()
    for record in records:
        counts["rows_seen"] += 1
        if counts["rows_seen"] > MAX_ROWS:
            raise ValueError("Sudo journal inventory exceeded bounded record limit")
        kind = classify(record)
        counts[kind] += 1
        if kind not in CATEGORIES:
            continue
        if record.get("_COMM") == "sudo":
            counts["comm_sudo"] += 1
        else:
            counts["comm_other_or_missing"] += 1
        uid = record.get("_UID")
        if (type(uid) is str and uid == "0") or (type(uid) is int and uid == 0):
            counts["uid_root"] += 1
        else:
            counts["uid_nonroot_or_missing"] += 1
        if record.get("_TRANSPORT") == "syslog":
            counts["transport_syslog"] += 1
        else:
            counts["transport_other_or_missing"] += 1
        micros = record.get("__REALTIME_TIMESTAMP")
        try:
            if isinstance(micros, bool):
                continue
            stamp = int(micros)
            if not 0 <= stamp <= 253_402_300_799_999_999:
                continue
            day = datetime.fromtimestamp(stamp / 1_000_000, timezone.utc).date()
            days[day.isoformat()] += 1
        except (TypeError, ValueError, OverflowError, OSError):
            continue

    return {
        "kind": "read_only_sudo_trusted_executable_inventory",
        "provenance": "_EXE=/usr/bin/sudo (journald trusted executable metadata)",
        "rows_seen": counts["rows_seen"],
        "trusted_sudo_rows": sum(counts[key] for key in CATEGORIES),
        "ignored_untrusted_executable": counts["untrusted_executable"],
        "invalid_json_or_structure": counts["invalid_json_or_structure"],
        "invalid_sudo_messages": counts["invalid_sudo_message"],
        "categories": {key: counts[key] for key in CATEGORIES},
        "trusted_comm_sudo": counts["comm_sudo"],
        "trusted_comm_other_or_missing": counts["comm_other_or_missing"],
        "trusted_uid_root": counts["uid_root"],
        "trusted_uid_nonroot_or_missing": counts["uid_nonroot_or_missing"],
        "trusted_transport_syslog": counts["transport_syslog"],
        "trusted_transport_other_or_missing": counts["transport_other_or_missing"],
        "active_days_utc": dict(sorted(days.items())),
        "private_identifiers_exposed": False,
        "production_sudo_detection_active": False,
        "interpretation": (
            "One sudo action may produce several journal rows. Metadata proves only "
            "which executable emitted a record, not intent or successful privilege "
            "escalation. Classification is a tentative format inventory; do not "
            "use its output to trigger alarms without separate validation."
        ),
    }


def read_journal(since: str) -> Iterable[dict[str, Any]]:
    command = [
        "journalctl",
        "--quiet",
        "--no-pager",
        "--output=json",
        "--since=" + since,
        "_EXE=/usr/bin/sudo",
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
        for index, line in enumerate(child.stdout):
            if index >= MAX_ROWS:
                raise ValueError("Too many sudo journal rows for bounded audit")
            try:
                data = json.loads(line)
            except (json.JSONDecodeError, UnicodeError):
                data = {"__invalid_json__": True}
            if isinstance(data, dict):
                yield data
            else:
                yield {"__invalid_json__": True}
        if child.wait(timeout=20) != 0:
            raise RuntimeError("Journald exited with an error")
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
    if len(args.since) != 19:
        parser.error("Expected YYYY-MM-DD HH:MM:SS local date")
    try:
        datetime.strptime(args.since, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        parser.error("Invalid local date")
    source = read_journal(args.since)
    try:
        try:
            report = aggregate(source)
        finally:
            source.close()
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired):
        print("STOP: Read-only sudo executable inventory failed", file=sys.stderr)
        return 1
    print(json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
