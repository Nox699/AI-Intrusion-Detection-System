"""Read real sudo history; emit only pseudonymized process candidates to stdout."""

import json
import subprocess
from bisect import bisect_left
from collections import Counter, defaultdict

from yggdrasil_ids.sudo_rules import parse_sudo


def aggregate(records):
    groups = defaultdict(list)
    seen = {}
    rejected = 0
    for record in records:
        parsed = parse_sudo(record)
        if parsed.status != "event":
            rejected += 1
            continue
        signal = parsed.signal
        if signal.cursor in seen:
            if seen[signal.cursor] != signal:
                raise ValueError("Conflicting journal identity")
            continue
        seen[signal.cursor] = signal
        groups[(signal.boot_id, signal.uid, signal.pid)].append(signal)
    identities = {}
    processes = []
    ambiguous = 0
    for (boot, uid, _), signals in groups.items():
        start = min(s.timestamp for s in signals)
        end = max(s.timestamp for s in signals)
        if end - start > 900:
            ambiguous += 1
            continue
        kinds = {s.kind for s in signals}
        had_failure = bool(kinds & {"pam_auth_failure", "incorrect_password"})
        had_success = bool(kinds & {"command_invoked", "pam_session_opened"})
        outcome = (
            "denied"
            if "not_in_sudoers" in kinds
            else "failure"
            if had_failure
            else "success"
            if had_success
            else "unknown"
        )
        if outcome == "unknown":
            continue
        key = (boot, uid)
        identities.setdefault(key, len(identities) + 1)
        # Session-close-only timing must not move an earlier outcome into the future.
        timestamp = max(s.timestamp for s in signals if s.kind != "pam_session_closed")
        processes.append(
            {
                "timestamp": timestamp,
                "group": identities[key],
                "outcome": outcome,
                "also_had_success": had_success,
            }
        )
    processes.sort(key=lambda row: (row["timestamp"], row["group"]))
    failures = sorted(row["timestamp"] for row in processes if row["outcome"] != "success")
    for row in processes:
        index = bisect_left(failures, row["timestamp"])
        nearby = failures[max(0, index - 1) : index + 1]
        row["normal_candidate"] = row["outcome"] == "success" and all(
            abs(row["timestamp"] - stamp) > 900 for stamp in nearby
        )
    return {
        "format": "sudo-process-candidates-v1",
        "normal_labels_verified": False,
        "rejected_journal_rows": rejected,
        "ambiguous_process_groups_skipped": ambiguous,
        "source_rows_deduplicated": len(seen),
        "process_count": len(processes),
        "outcomes": dict(Counter(row["outcome"] for row in processes)),
        "normal_candidates": sum(row["normal_candidate"] for row in processes),
        "processes": processes,
    }


def main():
    result = subprocess.run(
        [
            "journalctl",
            "--quiet",
            "--no-pager",
            "--all",
            "--output=json",
            "--since=2026-10-22 00:00:00",
            "_EXE=/usr/bin/sudo",
            "--output-fields=MESSAGE,_EXE,_UID,_PID,_BOOT_ID,__CURSOR,__REALTIME_TIMESTAMP",
        ],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=30,
        cwd="/",
    )
    if result.returncode or len(result.stdout) > 10_000_000:
        raise RuntimeError("Filtered sudo journal unavailable or exceeds export bound")
    lines = result.stdout.splitlines()
    if not 1 <= len(lines) <= 10_000:
        raise ValueError("Expected between 1 and 10000 sudo journal rows")
    payload = aggregate(json.loads(line) for line in lines)
    if not payload["processes"]:
        raise ValueError("No recognized sudo processes")
    print(json.dumps(payload, indent=2, allow_nan=False))


if __name__ == "__main__":
    main()
