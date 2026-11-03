#!/usr/bin/env python3
"""Read-only sudo journald provenance diagnostic with strictly aggregate output.

The previous strict (_COMM=sudo AND _UID=0) query returned zero on the Pi.
This diagnostic probes all accessible journal visibility and two broader indexed filters.
SYSLOG_IDENTIFIER=sudo is a DISCOVERY hint only, never trusted evidence.
Raw messages, user identities, commands, ports, paths and cursors are not shown.
No SQLite, sudoers, services, firewall, model, or notification changes.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from collections import Counter
from datetime import datetime
from typing import Any, Iterable

MAX_ROWS_PER_QUERY = 10000
PROBES = ("recent_accessible", "comm_sudo", "tag_sudo")


def journal_command(since: str, probe: str) -> list[str]:
    if probe not in PROBES:
        raise ValueError("Unexpected diagnostic probe")
    command = [
        "journalctl",
        "--quiet",
        "--no-pager",
        "--output=json",
        "--since=" + since,
    ]
    if probe == "recent_accessible":
        command.append("--lines=1")
    elif probe == "comm_sudo":
        command.append("_COMM=sudo")
    else:
        command.append("SYSLOG_IDENTIFIER=sudo")
    return command


def read_journal(since: str, probe: str) -> Iterable[dict[str, Any]]:
    """Yield bounded journal records; never print private subprocess output."""
    command = journal_command(since, probe)
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
        limit = 1 if probe == "recent_accessible" else MAX_ROWS_PER_QUERY
        seen = 0
        for line in child.stdout:
            seen += 1
            if seen > limit:
                raise ValueError("Too many journal records for bounded diagnostic")
            try:
                record = json.loads(line)
            except (json.JSONDecodeError, UnicodeError):
                yield {"__malformed__": True}
                continue
            if isinstance(record, dict):
                yield record
            else:
                yield {"__malformed__": True}
        if child.wait(timeout=20) != 0:
            raise RuntimeError("Read-only journald command failed")
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


def metadata_summary(records: Iterable[dict[str, Any]]) -> dict[str, int]:
    """Aggregate metadata without returning any raw field values or messages."""
    counts: Counter[str] = Counter()
    for record in records:
        counts["rows"] += 1
        if counts["rows"] > MAX_ROWS_PER_QUERY:
            raise ValueError("Too many rows for summary")
        if record.get("__malformed__") is True:
            counts["unparseable_json"] += 1
            continue

        comm = record.get("_COMM")
        uid = record.get("_UID")
        exe = record.get("_EXE")
        transport = record.get("_TRANSPORT")

        if comm == "sudo":
            counts["comm_sudo"] += 1
        elif isinstance(comm, str) and comm:
            counts["comm_other"] += 1
        else:
            counts["comm_missing"] += 1

        if (type(uid) is str and uid == "0") or (type(uid) is int and uid == 0):
            counts["uid_root"] += 1
        elif uid is None:
            counts["uid_missing"] += 1
        else:
            counts["uid_nonroot_or_invalid"] += 1

        if exe == "/usr/bin/sudo":
            counts["exe_usr_bin_sudo"] += 1
        elif exe is None:
            counts["exe_missing"] += 1
        else:
            counts["exe_other"] += 1

        if record.get("SYSLOG_IDENTIFIER") == "sudo":
            counts["tag_sudo"] += 1
        else:
            counts["tag_other_or_missing"] += 1

        if transport == "syslog":
            counts["transport_syslog"] += 1
        elif transport == "journal":
            counts["transport_journal"] += 1
        else:
            counts["transport_other_or_missing"] += 1

        if comm == "sudo" and (
            (type(uid) is str and uid == "0") or (type(uid) is int and uid == 0)
        ):
            counts["matches_original_strict_filter"] += 1

    keys = (
        "rows",
        "unparseable_json",
        "comm_sudo",
        "comm_other",
        "comm_missing",
        "uid_root",
        "uid_nonroot_or_invalid",
        "uid_missing",
        "exe_usr_bin_sudo",
        "exe_other",
        "exe_missing",
        "tag_sudo",
        "tag_other_or_missing",
        "transport_syslog",
        "transport_journal",
        "transport_other_or_missing",
        "matches_original_strict_filter",
    )
    return {key: counts[key] for key in keys}


def audit(since: str) -> dict[str, Any]:
    seen = {}
    for probe in PROBES:
        source = read_journal(since, probe)
        try:
            seen[probe] = metadata_summary(source)
        finally:
            source.close()

    return {
        "kind": "read_only_sudo_journald_metadata_diagnostic",
        "recent_accessible_entry_visible": seen["recent_accessible"]["rows"] > 0,
        "comm_sudo_query": seen["comm_sudo"],
        "tag_sudo_query": seen["tag_sudo"],
        "production_sudo_detection_active": False,
        "only_aggregated_metadata_exposed": True,
        "note": (
            "Journal visibility is a limited probe; lack of matching rows "
            "does not prove absence of sudo activity. A sudo syslog tag is "
            "spoofable and MUST NOT qualify as trusted evidence. Rows can "
            "represent multiple messages from one action."
        ),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--since", default="2026-10-22 00:00:00")
    args = parser.parse_args(argv)
    if len(args.since) != 19:
        parser.error("Expected local date in YYYY-MM-DD HH:MM:SS form")
    try:
        datetime.strptime(args.since, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        parser.error("Invalid local date")
    try:
        report = audit(args.since)
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired):
        print("STOP: Read-only journal metadata diagnostic failed", file=sys.stderr)
        return 1
    print(json.dumps(report, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
