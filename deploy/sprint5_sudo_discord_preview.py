#!/usr/bin/env python3
"""Read-only lab preview of sudo alarms using real VM journal and existing formatter.

This does NOT contact Discord, use a webhook, modify databases, run attacks,
or install a service. It reads only the trusted sudo executable's entries
from journald, runs the real rule detector, and previews one redacted message.
Keep all raw journal content on the lab host.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from collections import Counter
from datetime import datetime

from yggdrasil_ids.notify import DiscordNotifier
from yggdrasil_ids.sudo_alerts import notification_event
from yggdrasil_ids.sudo_rules import SudoRuleDetector, parse_sudo

MAX_ROWS = 3000
MAX_RECORD_BYTES = 65536
FIELDS = "MESSAGE,_EXE,_UID,_PID,_BOOT_ID,__CURSOR,__REALTIME_TIMESTAMP"
DEFAULT_SINCE = "2026-11-03 00:00:00"


def read_sudo(since: str):
    """Bounded, non-root journal query without leaking subprocess output."""
    cmd = [
        "journalctl",
        "--quiet",
        "--no-pager",
        "--all",
        "--output=json",
        "--output-fields=" + FIELDS,
        "--since=" + since,
        "_EXE=/usr/bin/sudo",
    ]
    child = subprocess.Popen(
        cmd,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        bufsize=0,
    )
    try:
        assert child.stdout is not None
        for index, line in enumerate(child.stdout):
            if index >= MAX_ROWS or len(line) > MAX_RECORD_BYTES:
                raise ValueError("Bounded sudo journal scan exceeded")
            try:
                entry = json.loads(line)
            except (ValueError, UnicodeError, RecursionError) as exc:
                raise ValueError("Invalid JSON in sudo journal") from exc
            if not isinstance(entry, dict):
                raise ValueError("Unexpected journald record type")
            yield entry
        if child.wait(timeout=20) != 0:
            raise RuntimeError("Could not read sudo journal")
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


def preview(records) -> dict:
    rules = SudoRuleDetector()
    counts = Counter()
    formatted = None
    notify = DiscordNotifier(
        "/nonexistent/sudo-lab-source",
        "/nonexistent/sudo-lab-notifier",
        host_label="ubuntu-gateway (isolated lab)",
        zone="Europe/Copenhagen",
        sender=lambda _webhook, _body: (_ for _ in ()).throw(
            AssertionError("Network send is prohibited in a preview")
        ),
    )

    for record in records:
        counts["rows_seen"] += 1
        parsed = parse_sudo(record)
        if parsed.status != "event" or parsed.signal is None:
            counts["malformed_or_untrusted"] += 1
            continue
        counts["parsed_sudo_rows"] += 1
        finding = rules.evaluate(parsed.signal)
        if finding is not None:
            counts[finding.detector_id] += 1
            if formatted is None:
                formatted = notify.message(notification_event(parsed.signal, finding))

    return {
        "kind": "isolated_sudo_discord_message_dry_run",
        "journal_rows_seen": counts["rows_seen"],
        "parsed_sudo_rows": counts["parsed_sudo_rows"],
        "malformed_or_untrusted": counts["malformed_or_untrusted"],
        "candidate_rule_matches": {
            "sudo.repeated_auth_failure": counts["sudo.repeated_auth_failure"],
            "sudo.permission_denied": counts["sudo.permission_denied"],
        },
        "one_redacted_message_preview": formatted,
        "discord_messages_sent": 0,
        "webhook_read": False,
        "production_database_modified": False,
        "notifier_state_modified": False,
        "raw_logs_or_identifiers_exposed": False,
        "note": (
            "This previews a message using a real positive lab detection. "
            "It is NOT a sent Discord notification or a live alert pipeline."
        ),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--since", default=DEFAULT_SINCE)
    args = parser.parse_args(argv)
    try:
        datetime.strptime(args.since, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        parser.error("Use a full local timestamp: YYYY-MM-DD HH:MM:SS")
    try:
        report = preview(read_sudo(args.since))
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
        print("STOP: Isolated sudo message preview failed safely", file=sys.stderr)
        return 1
    print(json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
