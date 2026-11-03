#!/usr/bin/env python3
"""One gated, clearly marked sudo LABTEST through the real notifier outbox.

Default mode: offline fake sender, never network. --send-real PLUS
--confirm-lab-message is the *only* way to send a real Discord message.
Run --send-real only as the restricted yggdrasil-notifier system account
with a systemd LoadCredential named discord-webhook.url. The test creates a
separate temporary SQLite alert database and notifier state and destroys both.
It never reads VM logs, credentials from source files, or the production IDS DB.
This tests *delivery* of a LABELED simulated sudo alert, NOT automatic
live detection and delivery from the Ubuntu VM.
"""

from __future__ import annotations

import argparse
import json
import os
import pwd
import secrets
import sqlite3
import sys
import time
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, Callable

from yggdrasil_ids.notify import DiscordNotifier, deliver
from yggdrasil_ids.storage import Repository

TEST_WEBHOOK = "https://discord.com/api/webhooks/" + "1" * 18 + "/" + "x" * 60
SERVICE_ACCOUNT = "yggdrasil-notifier"
DETECTOR = "sudo.repeated_auth_failure"
SEVERITY = "medium"


def run(
    *,
    real: bool = False,
    sender: Callable[[str, str], str] | None = None,
) -> dict[str, Any]:
    """Send at most one explicitly labeled lab message from a private test DB."""
    if real and pwd.getpwuid(os.geteuid()).pw_name != SERVICE_ACCOUNT:
        raise PermissionError("Real test requires the restricted notifier service account")
    if real and sender is not None:
        raise ValueError("Real delivery must use the real, existing notifier transport")

    acknowledgements: list[str] = []

    def fake_sender(webhook: str, message: str) -> str:
        if webhook != TEST_WEBHOOK:
            raise ValueError("Unexpected webhook in offline test")
        acknowledgements.append(message)
        return "123456789012345678"

    with TemporaryDirectory(prefix="yggdrasil-sudo-delivery-lab-") as folder:
        base = Path(folder)
        repo = Repository(base / "lab-alerts.sqlite3")
        repo.initialize()
        webhook_file = None
        if real:
            credentials = os.environ.get("CREDENTIALS_DIRECTORY", "")
            if not credentials:
                raise ValueError("Missing systemd credentials directory")
            webhook_file = Path(credentials) / "discord-webhook.url"
            chosen_sender = deliver
        else:
            webhook_file = base / "fake-webhook.url"
            webhook_file.write_text(TEST_WEBHOOK, encoding="utf-8")
            webhook_file.chmod(0o600)
            chosen_sender = sender if sender is not None else fake_sender

        notifier = DiscordNotifier(
            repo.path,
            base / "notifier" / "state.sqlite3",
            host_label="Yggdrasil – SUDO LABTEST (ikke produktionsalarm)",
            zone="Europe/Copenhagen",
            webhook_file=webhook_file,
            sender=chosen_sender,
        )
        if notifier.bootstrap()["last_seq"] != 0:
            raise RuntimeError("Temporary lab notifier has unexpected old state")

        with repo.transaction() as db:
            db.execute(
                "INSERT INTO alerts("
                "detector_id,title,severity,reason,source_ip,"
                "first_seen,last_seen,count,details"
                ") VALUES(?,?,?,?,?,?,?,?,?)",
                (
                    DETECTOR,
                    "SIMULERET sudo-sikkerhedsalarm – leveringsprøve",
                    SEVERITY,
                    "Manuel test af Discord leveringskæden; ingen ny sudo-hændelse",
                    "local-lab",
                    time.time(),
                    time.time(),
                    3,
                    json.dumps(
                        {"kind": "manual_test_only", "token": secrets.token_hex(8)}
                    ),
                ),
            )
        with repo.reader() as db:
            event = db.execute(
                "SELECT ref,detector_id,severity,happened_at FROM discord_outbox"
            ).fetchone()
            outbox_count = db.execute("SELECT COUNT(*) FROM discord_outbox").fetchone()[0]
        if event is None or outbox_count != 1:
            raise RuntimeError("Exactly one temporary sudo outbox event required")

        # This is the identical codepath as the real notifier, but private
        # test-only source data and a separate notification state.
        message = notifier.message(dict(event))
        if "SUDO LABTEST" not in message or "Gentagne sudo-autentificeringsfejl" not in message:
            raise ValueError("The message must be visibly marked as a sudo lab test")
        notifier.poll()
        result = notifier.status()
        if result["delivered"] != 1 or result["pending"] != 0:
            raise RuntimeError("Test delivery was not acknowledged")
        if not real and sender is None and len(acknowledgements) != 1:
            raise RuntimeError("Offline fake sender did not acknowledge exactly once")
        report = {
            "kind": "sudo_discord_delivery_smoketest",
            "mode": "real_discord" if real else "offline_fake_sender",
            "detector_id": DETECTOR,
            "test_message_clearly_labeled": True,
            "temporary_outbox_events": 1,
            "notifier_acknowledged": 1,
            "notifier_pending": result["pending"],
            "real_discord_send_attempted": real,
            "real_discord_acknowledged": real,
            "production_database_modified": False,
            "production_notifier_state_modified": False,
            "ubuntu_gateway_contacted": False,
            "real_sudo_attack_detected_in_this_test": False,
            "webhook_value_exposed": False,
        }
    if base.exists():
        raise RuntimeError("Temporary lab database was not deleted")
    report["temporary_databases_deleted"] = True
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--send-real", action="store_true")
    parser.add_argument("--confirm-lab-message", action="store_true")
    args = parser.parse_args(argv)
    if args.send_real != args.confirm_lab_message:
        parser.error("Real send requires BOTH --send-real and --confirm-lab-message")
    try:
        result = run(real=args.send_real)
    except (OSError, ValueError, RuntimeError, PermissionError, sqlite3.Error):
        print("STOP: Isolated sudo Discord lab delivery failed; no production state changed", file=sys.stderr)
        return 1
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
