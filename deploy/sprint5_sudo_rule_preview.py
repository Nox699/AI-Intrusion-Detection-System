#!/usr/bin/env python3
"""Read-only replay of *candidate* sudo rules against private Pi journald.

This is an experiment, NOT a running production sudo detector. It displays
aggregate counts only. It never exposes usernames, commands, raw messages,
journal cursors, PIDs, or UIDs, and never changes services/SQLite/Discord.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from datetime import datetime
from typing import Any, Iterable

from sprint5_sudo_trusted_exe_audit import read_journal

from yggdrasil_ids.sudo_rules import KINDS, SudoRuleDetector, parse_sudo

MAX_PREVIEW_ROWS = 10_000
DETECTOR_IDS = ("sudo.repeated_auth_failure", "sudo.permission_denied")


def evaluate(records: Iterable[dict[str, Any]]) -> dict[str, Any]:
    detector = SudoRuleDetector()
    counters: Counter[str] = Counter()
    categories: Counter[str] = Counter()
    candidate_rules: Counter[str] = Counter()

    for record in records:
        counters["journal_rows_seen"] += 1
        if counters["journal_rows_seen"] > MAX_PREVIEW_ROWS:
            raise ValueError("Bounded sudo replay input exceeded")
        parsed = parse_sudo(record)
        if parsed.status != "event":
            counters[parsed.status] += 1
            continue
        assert parsed.signal is not None
        categories[parsed.signal.kind] += 1
        match = detector.evaluate(parsed.signal)
        if match is not None:
            candidate_rules[match.detector_id] += 1

    return {
        "kind": "offline_sudo_rule_preview_on_existing_journal",
        "journal_rows_seen": counters["journal_rows_seen"],
        "parsed_sudo_rows": sum(categories.values()),
        "ignored_non_sudo_rows": counters["ignored"],
        "malformed_or_incomplete_metadata": counters["malformed"],
        "sudo_categories": {name: categories[name] for name in KINDS},
        "candidate_rule_matches": {name: candidate_rules[name] for name in DETECTOR_IDS},
        "failure_distinct_process_threshold": detector.config.failure_process_threshold,
        "window_seconds": detector.config.window_seconds,
        "cooldown_seconds": detector.config.cooldown_seconds,
        "candidate_matches_are_not_proven_intrusions": True,
        "source_contains_no_verified_attack_examples": (
            categories["pam_auth_failure"]
            + categories["incorrect_password"]
            + categories["not_in_sudoers"]
            == 0
        ),
        "production_sudo_detection_active": False,
        "production_ids_changed": False,
        "sqlite_or_services_modified": False,
        "raw_identifiers_exposed": False,
        "interpretation": (
            "Rule matches are experimental candidate patterns only. Distinct sudo "
            "PIDs per invoking UID/boot are proxies for separate failed invocations, "
            "not password attempts. A denial is not proof of malicious intent. "
            "No true-positive sensitivity is validated without controlled labeled "
            "examples. Unrecognized records reduce coverage."
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
    source = read_journal(args.since)
    try:
        try:
            report = evaluate(source)
        finally:
            source.close()
    except (ValueError, TypeError, OSError, RuntimeError, TimeoutError):
        print("STOP: Read-only sudo rule preview failed safely", file=sys.stderr)
        return 1
    print(json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
