#!/usr/bin/env python3
"""Safe end-to-end sudo alarm/outbox/notifier lab with an in-memory fake sender.

Real, previously collected sudo journal records -> trusted sudo parser ->
rule detector -> temporary alerts/Discord outbox -> existing DiscordNotifier
-> fake sender. NEVER contacts Discord or uses a real webhook. Neither the
production database nor the production notifier nor its secret is touched.
All lab SQLite files are deleted before a sanitised aggregate is printed.
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, Iterable

from sprint5_sudo_discord_preview import read_sudo
from yggdrasil_ids.notify import DiscordNotifier
from yggdrasil_ids.storage import Repository
from yggdrasil_ids.sudo_alerts import notification_event
from yggdrasil_ids.sudo_rules import SudoRuleDetector, parse_sudo

# Deliberately invalid real-world credentials; delivery is an injected fake.
FAKE_WEBHOOK = "https://discord.com/api/webhooks/" + "1" * 18 + "/" + "x" * 60
ALLOWED = frozenset({"sudo.repeated_auth_failure", "sudo.permission_denied"})
MAX_RECORDS = 3_000


def run_lab(records: Iterable[dict[str, Any]]) -> dict[str, Any]:
    rules = SudoRuleDetector()
    counters: Counter[str] = Counter()
    sent: list[str] = []

    def fake_sender(webhook: str, message: str) -> str:
        if webhook != FAKE_WEBHOOK:
            raise AssertionError("Only a synthetic webhook can be used in this lab")
        if not message.startswith("🛡️ Yggdrasil IDS"):
            raise AssertionError("Unexpected notification format")
        sent.append(message)
        return str(100000 + len(sent))

    with TemporaryDirectory(prefix="yggdrasil-sudo-outbox-lab-") as folder:
        root = Path(folder)
        repository = Repository(root / "fake-events.sqlite3")
        repository.initialize()
        secret = root / "fake-webhook.url"
        secret.write_text(FAKE_WEBHOOK, encoding="utf-8")
        secret.chmod(0o600)
        notifier = DiscordNotifier(
            repository.path,
            root / "fake-notifier.sqlite3",
            host_label="ubuntu-gateway (isolated lab)",
            webhook_file=secret,
            sender=fake_sender,
        )
        bootstrap = notifier.bootstrap()
        if bootstrap["last_seq"] != 0:
            raise AssertionError("Fresh fake notifier cannot have prior events")

        for entry in records:
            counters["journal_rows_seen"] += 1
            if counters["journal_rows_seen"] > MAX_RECORDS:
                raise ValueError("Sudo outbox lab exceeded bounded journal rows")
            parsed = parse_sudo(entry)
            if parsed.status != "event" or parsed.signal is None:
                counters["not_parsed"] += 1
                continue
            counters["parsed_sudo_rows"] += 1
            match = rules.evaluate(parsed.signal)
            if match is None:
                continue
            if match.detector_id not in ALLOWED:
                raise ValueError("Unsupported sudo detector candidate")
            event = notification_event(parsed.signal, match)
            # No source IP exists for local sudo actions. Never store raw
            # journal payload, username, command line or the journal cursor.
            with repository.transaction() as db:
                db.execute(
                    "INSERT INTO alerts"
                    "(detector_id,title,severity,reason,source_ip,"
                    "first_seen,last_seen,count,details)"
                    "VALUES(?,?,?,?,?,?,?,?,?)",
                    (
                        event["detector_id"],
                        "Sudo-kandidat fra isoleret lab",
                        event["severity"],
                        "Kontrolleret mønster af sudo-autentificeringsfejl",
                        "local",
                        event["happened_at"],
                        event["happened_at"],
                        match.count,
                        '{"source":"isolated_sudo_lab"}',
                    ),
                )
            counters[match.detector_id] += 1

        with repository.reader() as db:
            outbox = db.execute("SELECT COUNT(*) FROM discord_outbox").fetchone()[0]
            alert_count = db.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        if outbox != alert_count:
            raise RuntimeError("Fake alerts/outbox row counts diverged")

        notifier.poll()
        status = notifier.status()
        if status["pending"] or status["delivered"] != outbox or len(sent) != outbox:
            raise RuntimeError("Fake notifier delivery did not acknowledge all alerts")
        # Assert rendering and privacy without printing the actual fake webhook.
        for message in sent:
            if "Undersøg hændelsen i den autoriserede lokale sudo-journal." not in message:
                raise AssertionError("The sudo message must not refer to an absent dashboard view")
        report: dict[str, Any] = {
            "kind": "isolated_sudo_outbox_notifier_fake_delivery_lab",
            "journal_rows_seen": counters["journal_rows_seen"],
            "parsed_sudo_rows": counters["parsed_sudo_rows"],
            "unparsed_rows": counters["not_parsed"],
            "candidate_rule_matches": {name: counters[name] for name in sorted(ALLOWED)},
            "temporary_alert_rows": alert_count,
            "temporary_outbox_rows": outbox,
            "fake_notifier_deliveries": len(sent),
            "fake_notifier_pending": status["pending"],
            "one_redacted_message_preview": sent[0] if sent else None,
            "discord_messages_sent": 0,
            "real_webhook_read": False,
            "fake_sender_only": True,
            "production_database_modified": False,
            "production_notifier_state_modified": False,
            "raw_journal_identifiers_exposed": False,
        }

    if root.exists():
        raise RuntimeError("Temporary sudo outbox lab directory unexpectedly survived")
    report["temporary_databases_deleted"] = True
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--since", default="2026-11-03 00:00:00")
    args = parser.parse_args(argv)
    try:
        datetime.strptime(args.since, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        parser.error("Expected YYYY-MM-DD HH:MM:SS local timestamp")
    try:
        result = run_lab(read_sudo(args.since))
    except (RuntimeError, AssertionError, ValueError, OSError, sqlite3.Error):
        print("STOP: Sudo outbox test failed; production was not modified", file=sys.stderr)
        return 1
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
