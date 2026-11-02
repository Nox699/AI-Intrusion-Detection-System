#!/usr/bin/env python3
"""Bounded read-only OpenSSH preauth coverage audit; emits aggregate counts only.

This is an input coverage experiment for a FUTURE second ML feature schema,
NOT a production IDS detector and NOT model training. Source addresses,
usernames, source ports, journal messages and cursors stay in memory only.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import subprocess
import sys
import unicodedata
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Iterable

from yggdrasil_ids.preauth import parse_preauth

MAX_JOURNAL_ROWS = 50000
MAX_MESSAGE_LENGTH = 4096
PRODUCERS = frozenset({"sshd", "sshd-session", "sshd-auth"})
# Matches observed OpenSSH message families, not every possible distro format.
PATTERNS = (
    (
        "invalid_user_notice",
        re.compile(
            r"^Invalid user (?P<username>.+?) from (?P<address>\S+) "
            r"port (?P<port>[0-9]{1,5})$"
        ),
    ),
    (
        "invalid_user_disconnect",
        re.compile(
            r"^Connection (?P<kind>closed|reset) by invalid user "
            r"(?P<username>.+?) (?P<address>\S+) port (?P<port>[0-9]{1,5}) "
            r"\[preauth\]$"
        ),
    ),
    (
        "authenticating_user_disconnect",
        re.compile(
            r"^Connection (?P<kind>closed|reset) by authenticating user "
            r"(?P<username>.+?) (?P<address>\S+) port (?P<port>[0-9]{1,5}) "
            r"\[preauth\]$"
        ),
    ),
    (
        "invalid_user_disconnected",
        re.compile(
            r"^Disconnected from invalid user (?P<username>.+?) "
            r"(?P<address>\S+) port (?P<port>[0-9]{1,5}) \[preauth\]$"
        ),
    ),
)
TEST_USERNAME = "ids-ml-test-no-user"


@dataclass(frozen=True)
class Signal:
    category: str
    source_ip: str
    source_port: int
    username: str
    boot_id: str


def classify(record: Any) -> Signal | None:
    """Parse only trusted root sshd producers; reject merely spoofed syslog tags."""
    if not isinstance(record, dict):
        return None
    uid = record.get("_UID")
    if not ((type(uid) is str and uid == "0") or (type(uid) is int and uid == 0)):
        return None
    if record.get("_COMM") not in PRODUCERS:
        return None
    message = record.get("MESSAGE")
    if not isinstance(message, str) or len(message) > MAX_MESSAGE_LENGTH:
        return None
    if any(unicodedata.category(ch) in {"Cc", "Cf", "Cs"} for ch in message):
        return None
    for category, pattern in PATTERNS:
        match = pattern.fullmatch(message)
        if not match:
            continue
        username = match["username"]
        if not 1 <= len(username) <= 256:
            return None
        port = int(match["port"])
        if not 1 <= port <= 65535:
            return None
        try:
            ip = ipaddress.ip_address(match["address"])
            if getattr(ip, "scope_id", None) is not None:
                return None
        except ValueError:
            return None
        boot_id = record.get("_BOOT_ID")
        if not isinstance(boot_id, str) or len(boot_id) > 100:
            boot_id = ""
        return Signal(
            category=category,
            source_ip=ip.compressed,
            source_port=port,
            username=username,
            boot_id=boot_id,
        )
    return None


def aggregate(records: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """Correlate source/port IN MEMORY so two messages are not two attacks."""
    counts: Counter[str] = Counter()
    category_counts: Counter[str] = Counter()
    unique_connections: set[tuple[str, str, int]] = set()
    unique_test_connections: set[tuple[str, str, int]] = set()
    for record in records:
        counts["journal_rows_seen"] += 1
        if counts["journal_rows_seen"] > MAX_JOURNAL_ROWS:
            raise ValueError("Too many journal rows; audit halted")
        if not isinstance(record, dict):
            counts["malformed_json_rows"] += 1
            continue
        uid = record.get("_UID")
        if record.get("_COMM") not in PRODUCERS or not (
            (type(uid) is str and uid == "0") or (type(uid) is int and uid == 0)
        ):
            counts["untrusted_rows"] += 1
            continue
        counts["trusted_root_ssh_rows"] += 1
        if parse_preauth(record) is not None:
            counts["recognized_by_existing_preauth_parser"] += 1
        message = record.get("MESSAGE")
        is_test_related = isinstance(message, str) and TEST_USERNAME in message
        if is_test_related:
            counts["journal_rows_mentioning_test_username"] += 1
        signal = classify(record)
        if signal is None:
            counts["trusted_root_ssh_rows_unclassified_as_candidate_signals"] += 1
            continue
        category_counts[signal.category] += 1
        key = (signal.boot_id, signal.source_ip, signal.source_port)
        unique_connections.add(key)
        if signal.username == TEST_USERNAME:
            counts["parsed_test_signal_rows"] += 1
            unique_test_connections.add(key)
    return {
        "kind": "read_only_ssh_preauth_ml_coverage_audit",
        "journal_rows_seen": counts["journal_rows_seen"],
        "trusted_root_ssh_rows": counts["trusted_root_ssh_rows"],
        "untrusted_rows": counts["untrusted_rows"],
        "malformed_json_rows": counts["malformed_json_rows"],
        "candidate_message_families": {
            category: category_counts[category] for category, _ in PATTERNS
        },
        "candidate_signal_rows_total": sum(category_counts.values()),
        "distinct_candidate_source_port_keys_count_only": len(unique_connections),
        "recognized_by_existing_preauth_parser": counts[
            "recognized_by_existing_preauth_parser"
        ],
        "trusted_root_ssh_rows_unclassified_as_candidate_signals": counts[
            "trusted_root_ssh_rows_unclassified_as_candidate_signals"
        ],
        "journal_rows_mentioning_test_username": counts[
            "journal_rows_mentioning_test_username"
        ],
        "parsed_test_signal_rows": counts["parsed_test_signal_rows"],
        "test_distinct_source_port_keys_count_only": len(unique_test_connections),
        "producer_rule": "_UID=0 and _COMM in known OpenSSH executables",
        "output_contains_private_identifiers": False,
        "new_ml_model_trained": False,
        "production_ids_changed": False,
        "warning": (
            "Multiple log lines may describe one connection. A unique source/port "
            "key is an approximation and not proof of an attack or a verified "
            "failed authentication. These are preauth candidates, not normal "
            "training rows; no automatic alerting or model training follows."
        ),
    }


def journal_records(since: str) -> Iterable[dict[str, Any]]:
    command = [
        "journalctl",
        "--system",
        "--quiet",
        "--no-pager",
        "--output=json",
        "--since=" + since,
        "_COMM=sshd",
        "_COMM=sshd-session",
        "_COMM=sshd-auth",
        "_UID=0",
    ]
    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        encoding="utf-8",
        errors="replace",
        text=True,
    )
    try:
        assert process.stdout is not None
        for line in process.stdout:
            try:
                value = json.loads(line)
            except (ValueError, TypeError):
                continue
            if isinstance(value, dict):
                yield value
        if process.wait(timeout=20) != 0:
            raise RuntimeError("Journalctl failed without emitting private details")
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        if process.stdout:
            process.stdout.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--since",
        default="2026-11-02 15:00:00",
        help="Date/time in the Pi's local timezone (defaults to test afternoon)",
    )
    args = parser.parse_args(argv)
    if not 10 <= len(args.since) <= 40 or any(ord(ch) < 32 for ch in args.since):
        print("STOP: Invalid --since argument", file=sys.stderr)
        return 2
    records = journal_records(args.since)
    try:
        try:
            report = aggregate(records)
        finally:
            records.close()
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired):
        print("STOP: Historical OpenSSH audit failed; no data changed", file=sys.stderr)
        return 1
    print(json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
