#!/usr/bin/env python3
"""Synthetic restart/dedup/retention lab for private Sprint 5 sudo staging.

Runs without journalctl, sudo, a service, a network socket or a production DB.
Creates a new mode-0700 temporary folder, writes only test signals to an
isolated SQLite file, and removes that directory before reporting aggregate
results. This validates timestamp-overlap replay, NOT guaranteed lossless
journal recovery after rotation or major clock changes.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from tempfile import TemporaryDirectory

from yggdrasil_ids.sudo_rules import SudoRuleDetector, SudoSignal
from yggdrasil_ids.sudo_storage import SudoStagingStore

BASE = 1_793_500_000.0
BOOT = "e" * 32
OVERLAP_SECONDS = 300


def sample(index: int, offset: int, *, kind: str = "pam_auth_failure") -> SudoSignal:
    return SudoSignal(
        cursor=f"synthetic-journal-id-{index}",
        timestamp=BASE + offset,
        boot_id=BOOT,
        uid="1000",
        pid=5000 + index,
        kind=kind,
    )


def play(
    store: SudoStagingStore,
    signals: tuple[SudoSignal, ...],
) -> tuple[int, int, int]:
    """One simulated process lifetime, including fresh in-memory rule state."""
    detector = SudoRuleDetector()
    new_rows = 0
    duplicates = 0
    new_candidates = 0
    for item in signals:
        finding = detector.evaluate(item)
        if store.append(item, finding):
            new_rows += 1
            if finding is not None:
                new_candidates += 1
        else:
            duplicates += 1
    return new_rows, duplicates, new_candidates


def run_lab() -> dict[str, object]:
    if os.geteuid() == 0:
        raise PermissionError("Run this synthetic lab as an unprivileged user")

    first = sample(1, 10)
    second = sample(2, 40)
    third = sample(3, 65)
    fourth = sample(4, 80)

    with TemporaryDirectory(prefix="yggdrasil-sudo-restart-lab-") as folder:
        path = Path(folder) / "private-sudo.sqlite3"
        one = SudoStagingStore(path)
        one.initialize()
        if one.resume_since(OVERLAP_SECONDS) is not None:
            raise AssertionError("New store unexpectedly has a checkpoint")
        session_one = play(one, (first, second))
        if session_one != (2, 0, 0):
            raise AssertionError("Unexpected first ingestion")

        two = SudoStagingStore(path)
        two.initialize()
        boundary_two = two.resume_since(OVERLAP_SECONDS)
        if boundary_two is None or boundary_two >= first.timestamp:
            raise AssertionError("Resume overlap excludes previously saved evidence")
        session_two = play(two, (first, second, third))
        if session_two != (1, 2, 1):
            raise AssertionError("Replay failed to deduplicate or detect a threshold")

        three = SudoStagingStore(path)
        three.initialize()
        boundary_three = three.resume_since(OVERLAP_SECONDS)
        if boundary_three is None or boundary_three >= first.timestamp:
            raise AssertionError("Restart overlap excludes previous candidate history")
        session_three = play(three, (first, second, third, fourth))
        if session_three != (1, 3, 0):
            raise AssertionError("Replay generated a duplicate candidate or lost evidence")

        before = three.summary()
        if before["persisted_log_rows"] != 4:
            raise AssertionError("Unexpected unique row count")
        if before["candidate_rule_matches"]["sudo.repeated_auth_failure"] != 1:
            raise AssertionError("A candidate was lost or duplicated")

        removed = three.prune(BASE + 70)
        after = three.summary()
        if removed != 3 or after["persisted_log_rows"] != 1:
            raise AssertionError("Retention failed")
        if after["candidate_rule_matches"]["sudo.repeated_auth_failure"] != 0:
            raise AssertionError("Stale candidate evidence was not pruned")
        checkpoint_after_prune = three.resume_since(OVERLAP_SECONDS)
        if checkpoint_after_prune is None or checkpoint_after_prune != BASE + 80 - 301:
            raise AssertionError("Retention unexpectedly deleted the restart checkpoint")
        # No output here: we never disclose any cursors, IDs or private storage paths.

    if path.exists():
        raise AssertionError("Temporary private SQLite database still exists")
    return {
        "kind": "synthetic_sudo_restart_replay_lab",
        "session_one_unique_rows": session_one[0],
        "session_two_replayed_duplicates": session_two[1],
        "session_two_new_unique_rows": session_two[0],
        "session_two_candidate_events": session_two[2],
        "session_three_replayed_duplicates": session_three[1],
        "session_three_new_unique_rows": session_three[0],
        "session_three_new_candidate_events": session_three[2],
        "unique_rows_before_retention": before["persisted_log_rows"],
        "candidate_rows_before_retention": before["candidate_rule_matches"][
            "sudo.repeated_auth_failure"
        ],
        "retention_removed_rows": removed,
        "unique_rows_after_retention": after["persisted_log_rows"],
        "checkpoint_survived_retention": True,
        "temporary_database_deleted": True,
        "real_journald_access": False,
        "production_database_modified": False,
        "discord_alerts_sent": False,
        "raw_private_ids_exposed": False,
        "recovery_guarantee": "best_effort_timestamp_overlap_not_lossless_cursor",
    }


def main() -> int:
    try:
        report = run_lab()
    except (OSError, RuntimeError, ValueError, PermissionError, AssertionError):
        print("STOP: Synthetic sudo restart/replay lab failed", file=sys.stderr)
        return 1
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
