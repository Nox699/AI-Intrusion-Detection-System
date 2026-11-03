#!/usr/bin/env python3
"""Short, isolated sudo shadow observation; never installs a running service.

Runs as yggdrasil-worker and reads only its accessible sudo journal records.
No --system: it would miss the relevant journal scope on Yggdrasil.
Default behavior is read-only. --stage-temporary explicitly enables a private
ephemeral SQLite database, destroyed when the process exits. Neither mode
writes to the production IDS database, dashboard, or Discord outbox.
Output contains only aggregate counts, never IDs, commands or raw messages.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import selectors
import subprocess
import sys
import time
from collections import Counter
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from yggdrasil_ids.sudo_rules import KINDS, SudoRuleDetector, parse_sudo
from yggdrasil_ids.sudo_storage import SudoStagingStore

MAX_SECONDS = 60
MAX_RECORDS = 2000
MAX_RECORD_BYTES = 65536
OUTPUT_FIELDS = "MESSAGE,_EXE,_UID,_PID,_BOOT_ID,__CURSOR,__REALTIME_TIMESTAMP"
RULE_IDS = ("sudo.repeated_auth_failure", "sudo.permission_denied")


def journal_command(start_epoch: float) -> list[str]:
    """One bounded, producer-filtered journal stream; no unfiltered -f."""
    if not math.isfinite(start_epoch) or not 0 < start_epoch < 4102444800:
        raise ValueError("Invalid journal start timestamp")
    return [
        "journalctl",
        "--quiet",
        "--no-pager",
        "--output=json",
        "--all",
        "--follow",
        "--no-tail",
        "--output-fields=" + OUTPUT_FIELDS,
        f"--since=@{start_epoch:.6f}",
        "_EXE=/usr/bin/sudo",
    ]


class AggregateObserver:
    """Short-lived rule state, optionally with separate private staging."""

    def __init__(self, store: SudoStagingStore | None = None) -> None:
        self.detector = SudoRuleDetector()
        self.store = store
        self.counters: Counter[str] = Counter()
        self.categories: Counter[str] = Counter()
        self.matches: Counter[str] = Counter()

    def ingest(self, line: bytes) -> None:
        self.counters["journal_rows_seen"] += 1
        if self.counters["journal_rows_seen"] > MAX_RECORDS:
            raise ValueError("Bounded sudo shadow observation exceeded record limit")
        if len(line) > MAX_RECORD_BYTES:
            self.counters["oversized"] += 1
            return
        try:
            record = json.loads(line)
        except (ValueError, UnicodeError, RecursionError):
            self.counters["invalid_json"] += 1
            return
        parsed = parse_sudo(record)
        if parsed.status != "event":
            self.counters[parsed.status] += 1
            return
        assert parsed.signal is not None
        self.categories[parsed.signal.kind] += 1
        try:
            finding = self.detector.evaluate(parsed.signal)
        except ValueError:
            # Clock changes and reordered records must not cause an alarm.
            self.counters["replay_quality_errors"] += 1
            return
        if self.store is not None:
            # No journal JSON, command line or username is sent to storage.
            # A storage error is fatal: never quietly lose candidate evidence.
            if self.store.append(parsed.signal, finding):
                self.counters["stored_unique"] += 1
            else:
                self.counters["stored_duplicates"] += 1
        if finding:
            self.matches[finding.detector_id] += 1

    def report(self, seconds: int) -> dict[str, Any]:
        return {
            "kind": "isolated_live_sudo_shadow_observation",
            "observation_seconds": seconds,
            "journal_scope": "all_worker_accessible",
            "trusted_executable_filter": "/usr/bin/sudo",
            "journal_rows_seen": self.counters["journal_rows_seen"],
            "parsed_sudo_rows": sum(self.categories.values()),
            "malformed_or_untrusted": (
                self.counters["malformed"]
                + self.counters["ignored"]
                + self.counters["invalid_json"]
                + self.counters["oversized"]
            ),
            "replay_quality_errors": self.counters["replay_quality_errors"],
            "sudo_categories": {name: self.categories[name] for name in KINDS},
            "candidate_rule_matches": {name: self.matches[name] for name in RULE_IDS},
            "production_sudo_detection_active": False,
            "database_writes": self.store is not None,
            "production_database_writes": False,
            "private_staging_enabled": self.store is not None,
            "staged_unique_rows": self.counters["stored_unique"],
            "staged_duplicate_rows": self.counters["stored_duplicates"],
            "private_staging_summary": self.store.summary() if self.store is not None else None,
            "discord_alerts_sent": False,
            "raw_user_command_or_journal_data_exposed": False,
            "interpretation": (
                "This is a short manual shadow observation of journal messages, "
                "not independent commands, verified attacks, or an estimated "
                "false-positive rate. Candidate rule matches never alert."
            ),
        }


def observe(seconds: int, *, store: SudoStagingStore | None = None) -> dict[str, Any]:
    if type(seconds) is not int or not 5 <= seconds <= MAX_SECONDS:
        raise ValueError("Observation duration must be 5-60 seconds")
    if os.geteuid() == 0:
        raise PermissionError("Run with the existing unprivileged worker account")
    start = time.time() - 1.0
    command = journal_command(start)
    child = subprocess.Popen(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        bufsize=0,
        env={**os.environ, "LC_ALL": "C", "SYSTEMD_COLORS": "0"},
    )
    observer = AggregateObserver(store)
    select = selectors.DefaultSelector()
    buffer = b""
    discard = False
    deadline = time.monotonic() + seconds
    try:
        assert child.stdout is not None
        select.register(child.stdout, selectors.EVENT_READ)
        while time.monotonic() < deadline:
            timeout = min(0.5, max(0.0, deadline - time.monotonic()))
            for key, _ in select.select(timeout):
                chunk = os.read(key.fileobj.fileno(), 65536)
                if not chunk:
                    select.unregister(key.fileobj)
                    continue
                buffer += chunk
                while b"\n" in buffer:
                    line, buffer = buffer.split(b"\n", 1)
                    if discard:
                        discard = False
                        continue
                    observer.ingest(line)
                if len(buffer) > MAX_RECORD_BYTES:
                    observer.counters["oversized"] += 1
                    buffer = b""
                    discard = True
            if child.poll() is not None and not select.get_map():
                raise RuntimeError("Sudo journal reader stopped unexpectedly")
        return observer.report(seconds)
    finally:
        select.close()
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
    parser.add_argument("--seconds", type=int, default=15)
    parser.add_argument(
        "--stage-temporary",
        action="store_true",
        help="Store normalized events in a worker-owned private SQLite DB; delete it on exit",
    )
    args = parser.parse_args(argv)
    try:
        if args.stage_temporary:
            if os.geteuid() == 0:
                raise PermissionError("Do not run the sudo staging test as root")
            with TemporaryDirectory(prefix="yggdrasil-sudo-shadow-") as folder:
                store = SudoStagingStore(Path(folder) / "sudo.sqlite3")
                store.initialize()
                report = observe(args.seconds, store=store)
            # This is emitted only after TemporaryDirectory has been removed.
            report["temporary_staging_database_deleted"] = True
        else:
            report = observe(args.seconds)
    except (OSError, RuntimeError, ValueError, PermissionError, subprocess.SubprocessError):
        print("STOP: Isolated sudo shadow observation failed safely", file=sys.stderr)
        return 1
    print(json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
