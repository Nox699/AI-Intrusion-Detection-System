#!/usr/bin/env python3
"""Private, bounded journal restart acceptance test on existing sudo log events.

Reads a FIXED snapshot of journalctl _EXE=/usr/bin/sudo rows in the worker's
available journal scopes. Simulates three process lifetimes and uses a
worker-owned, ephemeral SQLite DB with a committed timestamp checkpoint.
No raw messages, commands, usernames, cursors or private filesystem paths
are included in output. Never configures a service or touches production DBs.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import subprocess
import sys
import time
from collections import Counter
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, Iterable

from yggdrasil_ids.sudo_rules import SudoRuleDetector, parse_sudo
from yggdrasil_ids.sudo_storage import SudoStagingStore

MAX_ROWS_PER_PASS = 3000
MAX_LINE_BYTES = 65536
MAX_SPAN_HOURS = 48
OVERLAP_SECONDS = 300
FIELDS = "MESSAGE,_EXE,_UID,_PID,_BOOT_ID,__CURSOR,__REALTIME_TIMESTAMP"


def command(since: float, until: float, *, timestamps_only: bool = False) -> list[str]:
    if not (
        type(since) in (float, int)
        and type(until) in (float, int)
        and math.isfinite(since)
        and math.isfinite(until)
        and 0 <= since <= until < 4_102_444_800
    ):
        raise ValueError("Invalid fixed journal snapshot bounds")
    fields = "__REALTIME_TIMESTAMP" if timestamps_only else FIELDS
    return [
        "journalctl",
        "--quiet",
        "--no-pager",
        "--output=json",
        "--all",
        "--output-fields=" + fields,
        f"--since=@{since:.6f}",
        f"--until=@{until:.6f}",
        "_EXE=/usr/bin/sudo",
    ]


def read_snapshot(
    since: float, until: float, *, timestamps_only: bool = False
) -> Iterable[dict[str, Any]]:
    """Read at most MAX_ROWS_PER_PASS; fail closed if journald cannot be read.

    No stderr from journalctl or malformed source data is printed to the user.
    """
    child = subprocess.Popen(
        command(since, until, timestamps_only=timestamps_only),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=False,
        bufsize=0,
        env={**os.environ, "LC_ALL": "C", "SYSTEMD_COLORS": "0"},
    )
    try:
        assert child.stdout is not None
        for count, line in enumerate(child.stdout, 1):
            if count > MAX_ROWS_PER_PASS or len(line) > MAX_LINE_BYTES:
                raise ValueError("Bounded private journal scan exceeded")
            try:
                obj = json.loads(line)
            except (UnicodeError, ValueError, RecursionError) as exc:
                raise ValueError("Invalid JSON from filtered sudo journal") from exc
            if not isinstance(obj, dict):
                raise ValueError("Invalid sudo journal record structure")
            yield obj
        if child.wait(timeout=20) != 0:
            raise RuntimeError("Filtered sudo journal read failed")
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


def timestamps(records: Iterable[dict[str, Any]]) -> list[float]:
    """Extract bounded times without any raw journal content."""
    values: list[float] = []
    for record in records:
        try:
            stamp = int(record["__REALTIME_TIMESTAMP"])
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError("Missing timestamp in sudo journal") from exc
        if not 0 <= stamp < 4_102_444_800_000_000:
            raise ValueError("Invalid sudo timestamp")
        values.append(stamp / 1_000_000)
    return sorted(values)


def replay_pass(store: SudoStagingStore, records: Iterable[dict[str, Any]]) -> dict[str, int]:
    """A new in-memory rule engine represents each simulated process start.

    Replay the overlap into the engine EVEN when the DB already has the row.
    That reconstructs its failure windows and cooldown before new messages.
    """
    rules = SudoRuleDetector()
    counts: Counter[str] = Counter()
    for record in records:
        counts["read"] += 1
        parsed = parse_sudo(record)
        if parsed.status != "event" or parsed.signal is None:
            counts["unparseable"] += 1
            raise ValueError("Trusted sudo journal had incomplete parser metadata")
        finding = rules.evaluate(parsed.signal)
        if store.append(parsed.signal, finding):
            counts["new"] += 1
            if finding is not None:
                counts["new_candidates"] += 1
        else:
            counts["duplicates"] += 1
    return dict(counts)


def evaluate_restarts(hours: int = 24) -> dict[str, object]:
    if type(hours) is not int or not 1 <= hours <= MAX_SPAN_HOURS:
        raise ValueError("Hours must be bounded from 1 through 48")
    if os.geteuid() == 0:
        raise PermissionError("Run only as the existing unprivileged IDS worker")

    # Fixed bounds make all three reads refer to the same historical snapshot.
    end = time.time() - 5
    begin = end - hours * 3600
    moments = timestamps(read_snapshot(begin, end, timestamps_only=True))
    if len(moments) < 2 or moments[-1] - moments[0] < 1.0:
        return {
            "kind": "sudo_real_journal_restart_accept",
            "result": "insufficient_real_journal_history",
            "historical_rows_available": len(moments),
            "production_database_modified": False,
            "discord_alerts_sent": False,
            "raw_private_data_exposed": False,
        }

    # Cut by observed EVENT TIME to guarantee data on both sides, and replay
    # an overlapping time interval. Do not persist this split or log identities.
    split = moments[(len(moments) - 1) // 2]
    if split >= moments[-1]:
        return {
            "kind": "sudo_real_journal_restart_accept",
            "result": "insufficient_temporal_variation",
            "historical_rows_available": len(moments),
            "production_database_modified": False,
            "discord_alerts_sent": False,
            "raw_private_data_exposed": False,
        }

    with TemporaryDirectory(prefix="yggdrasil-sudo-real-restart-") as folder:
        database = Path(folder) / "sudo.sqlite3"
        first_store = SudoStagingStore(database)
        first_store.initialize()
        phase_one = replay_pass(first_store, read_snapshot(begin, split))
        if phase_one.get("new", 0) < 1:
            raise RuntimeError("First pass had no valid sudo events")

        # Create NEW Python storage/detector objects; replay the prior time
        # range and all later entries, using a timestamp-only durable boundary.
        second_store = SudoStagingStore(database)
        second_store.initialize()
        restart_from = second_store.resume_since(OVERLAP_SECONDS)
        if restart_from is None:
            raise RuntimeError("First sudo journal checkpoint missing")
        phase_two = replay_pass(second_store, read_snapshot(restart_from, end))

        third_store = SudoStagingStore(database)
        third_store.initialize()
        third_from = third_store.resume_since(OVERLAP_SECONDS)
        if third_from is None:
            raise RuntimeError("Second sudo journal checkpoint missing")
        phase_three = replay_pass(third_store, read_snapshot(third_from, end))

        stored = third_store.summary()
        all_new = phase_one.get("new", 0) + phase_two.get("new", 0)
        if stored["persisted_log_rows"] != all_new:
            raise RuntimeError("Private sudo journal restart lost or duplicated SQLite rows")
        if all_new != len(moments):
            raise RuntimeError("Private sudo journal restart did not cover the fixed snapshot")
        if phase_three.get("new", 0) != 0:
            raise RuntimeError("Second replay unexpectedly created new sudo events")
        if phase_three.get("new_candidates", 0) != 0:
            raise RuntimeError("Second replay unexpectedly created candidate evidence")

        report = {
            "kind": "sudo_real_journal_restart_accept",
            "result": "success",
            "historical_rows_available": len(moments),
            "first_pass_new_rows": phase_one.get("new", 0),
            "second_pass_new_rows": phase_two.get("new", 0),
            "second_pass_replayed_duplicates": phase_two.get("duplicates", 0),
            "third_pass_new_rows": phase_three.get("new", 0),
            "third_pass_replayed_duplicates": phase_three.get("duplicates", 0),
            "unique_rows_in_private_sqlite": stored["persisted_log_rows"],
            "candidate_rule_matches": stored["candidate_rule_matches"],
            "checkpoint_type": "timestamp_overlap_not_raw_cursor",
            "database_scope": "private_temporary_worker_owned",
            "production_database_modified": False,
            "discord_alerts_sent": False,
            "raw_private_data_exposed": False,
            "real_journald_access": True,
            "guarantee": "fixed_historical_snapshot_only_not_lossless_live_recovery",
        }

    if database.exists():
        raise RuntimeError("Temporary sudo acceptance DB unexpectedly survived")
    report["temporary_database_deleted"] = True
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hours", type=int, default=24)
    args = parser.parse_args(argv)
    try:
        report = evaluate_restarts(args.hours)
    except (
        ValueError,
        RuntimeError,
        OSError,
        PermissionError,
        subprocess.SubprocessError,
    ):
        print("STOP: Private real-sudo restart acceptance test failed", file=sys.stderr)
        return 1
    print(json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
