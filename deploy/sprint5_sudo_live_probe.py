#!/usr/bin/env python3
"""Three bounded real sudo failures, followed through the existing live pipeline.

No inserts into production, notifier bootstrap, direct webhook use, service
restarts, model changes or raw-identity exports. Private inspection is read-only.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import pwd
import re
import sqlite3
import subprocess
import sys
import time
from contextlib import closing
from pathlib import Path

CODE = Path("/opt/yggdrasil-sudo-integration")
INSTALLED_SHA = "9ced7d60ab7b6776af95a12e83596683e04676ae"
MODEL_VERSION = "sudo-if-15207a3b77b40fe2"
SOURCE = Path("/var/lib/yggdrasil-sudo-shadow/sudo-shadow.sqlite3")
DATABASE = Path("/var/lib/yggdrasil-ids/events.sqlite3")
DELIVERY = Path("/var/lib/yggdrasil-notifier/delivery.sqlite3")
PUBLIC = Path("/var/lib/yggdrasil-sudo-public/sudo-integration.json")
DETECTOR = "sudo.repeated_auth_failure"
FAILURES = ("pam_auth_failure", "incorrect_password")
UNITS = (
    "yggdrasil-collector.service",
    "yggdrasil-web.service",
    "yggdrasil-notifier.service",
    "yggdrasil-sudo-shadow.timer",
    "yggdrasil-sudo-integration.timer",
    "yggdrasil-sudo-ui-export.timer",
)


def read_db(path: Path):
    if path.is_symlink() or not path.is_file():
        raise ValueError("Expected existing database")
    db = sqlite3.connect(path.absolute().as_uri() + "?mode=ro", uri=True, timeout=5)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA query_only=ON")
    db.execute("BEGIN")
    return db


def validate_request(value: object) -> dict:
    if value == {"stage": "preflight"}:
        return value
    if not isinstance(value, dict) or set(value) != {"stage", "boot", "pids", "start", "end"}:
        raise ValueError("Invalid probe request")
    if (
        value["stage"] != "watch"
        or not isinstance(value["boot"], str)
        or not re.fullmatch(r"[0-9a-f]{32}", value["boot"])
    ):
        raise ValueError("Invalid probe identity")
    pids = value["pids"]
    if (
        not isinstance(pids, list)
        or len(pids) != 3
        or any(type(pid) is not int or not 1 <= pid <= 2**31 - 1 for pid in pids)
        or len(set(pids)) != 3
    ):
        raise ValueError("Exactly three unique probe processes required")
    for key in ("start", "end"):
        if type(value[key]) not in (int, float) or not math.isfinite(value[key]):
            raise ValueError("Invalid probe interval")
    if (
        not 1 <= value["start"] <= value["end"] < 4_102_444_800
        or value["end"] - value["start"] >= 300
    ):
        raise ValueError("Probe must fit within one rule window")
    return value


def public_status() -> dict:
    from yggdrasil_ids.sudo_integration_dashboard import read_integration

    return read_integration(PUBLIC)


def inspect(request: dict, *, now: float | None = None) -> dict:
    request = validate_request(request)
    now = time.time() if now is None else now
    public = public_status()
    if request["stage"] == "preflight" and (
        public["state"] != "ready"
        or public["ml"]["state"] != "ready"
        or public["ml"]["model_version"] != MODEL_VERSION
    ):
        raise ValueError("Fresh rule integration and pinned ML shadow required")
    source = read_db(SOURCE)
    try:
        if source.execute("PRAGMA user_version").fetchone()[0] != 2:
            raise ValueError("Unexpected private source schema")
        row = source.execute(
            "SELECT last_completed_until FROM shadow_poll_checkpoint WHERE id=1"
        ).fetchone()
        checkpoint = float(row[0]) if row else float("nan")
        if not math.isfinite(checkpoint) or not 0 <= now - checkpoint <= 180:
            raise ValueError("Private poll checkpoint unavailable")
        if request["stage"] == "preflight":
            with closing(read_db(DATABASE)) as prod, closing(read_db(DELIVERY)) as notifier_db:
                if prod.execute("PRAGMA user_version").fetchone()[0] != 5:
                    raise ValueError("Expected activated schema5")
                identity = prod.execute(
                    "SELECT instance FROM discord_outbox_meta WHERE id=1"
                ).fetchone()
                notifier = notifier_db.execute("SELECT instance FROM meta").fetchone()
                if not identity or not notifier or identity[0] != notifier[0]:
                    raise ValueError("Notifier source identity mismatch")
            recent = source.execute(
                "SELECT COUNT(*) FROM sudo_signals WHERE timestamp>=? AND kind IN (?,?)",
                (now - 300, *FAILURES),
            ).fetchone()[0]
            return {"ready": recent == 0, "recent_failure_rows": recent}
        params = (
            request["boot"],
            *request["pids"],
            request["start"] - 1,
            min(checkpoint, request["end"] + 2),
        )
        rows = source.execute(
            "SELECT event_id,uid,pid,kind,timestamp FROM sudo_signals "
            "WHERE boot_id=? AND pid IN (?,?,?) AND timestamp>=? AND timestamp<=?",
            params,
        ).fetchall()
        failed = {row["pid"] for row in rows if row["kind"] in FAILURES}
        groups = {row["uid"] for row in rows if row["kind"] in FAILURES}
        stamps = {
            pid: max(
                row["timestamp"]
                for row in rows
                if row["pid"] == pid and row["kind"] != "pam_session_closed"
            )
            for pid in failed
        }
        candidates = source.execute(
            "SELECT c.event_id,c.timestamp,c.process_count,s.uid FROM sudo_candidates c "
            "JOIN sudo_signals s ON s.event_id=c.event_id WHERE s.boot_id=? "
            "AND s.pid IN (?,?,?) AND c.timestamp>=? AND c.timestamp<=? "
            "AND c.detector_id=? ORDER BY c.timestamp",
            (*params, DETECTOR),
        ).fetchall()
        background = set()
        for candidate in candidates:
            background.update(
                row[0]
                for row in source.execute(
                    "SELECT DISTINCT pid FROM sudo_signals WHERE boot_id=? AND uid=? "
                    "AND timestamp>=? AND timestamp<=? AND kind IN (?,?) AND pid NOT IN (?,?,?)",
                    (
                        request["boot"],
                        candidate["uid"],
                        candidate["timestamp"] - 300,
                        candidate["timestamp"],
                        *FAILURES,
                        *request["pids"],
                    ),
                )
            )
    finally:
        source.close()
    result = {
        "failed_probe_processes": len(failed),
        "probe_groups": len(groups),
        "source_completed_after_probe": checkpoint >= request["end"] + 2,
        "matching_candidates": len(candidates),
        "other_failure_processes": len(background),
        "registered_alarms": [],
        "outbox_match_ambiguous": False,
        "ml_probe_positions_matched": 0,
        "ml_probe_flags": None,
        "integration_state": public["state"],
        "ml_state": public["ml"]["state"],
        "model_version": public["ml"].get("model_version"),
        "ml_alerts_emitted": False,
    }
    latest = public["ml"].get("latest", []) if public["ml"]["state"] == "ready" else []
    if len(stamps) == 3 and len(set(stamps.values())) == 3:
        matched = [
            item
            for item in latest
            if item["timestamp"] in stamps.values() and item["category"] == "authentication_failed"
        ]
        result["ml_probe_positions_matched"] = len(matched)
        if len(matched) == 3:
            result["ml_probe_flags"] = sum(item["is_anomaly"] for item in matched)
    production = read_db(DATABASE)
    delivery = read_db(DELIVERY)
    try:
        if production.execute("PRAGMA user_version").fetchone()[0] != 5:
            raise ValueError("Expected activated schema5")
        instance = production.execute(
            "SELECT instance FROM discord_outbox_meta WHERE id=1"
        ).fetchone()[0]
        notifier = delivery.execute("SELECT instance FROM meta").fetchone()
        if not notifier or notifier[0] != instance:
            raise ValueError("Notifier source identity mismatch")
        for candidate in candidates:
            alarm = production.execute(
                "SELECT a.id,a.detector_id,a.first_seen,a.severity,e.process_count FROM sudo_evidence e "
                "JOIN alerts a ON a.id=e.alert_id WHERE e.event_id=? AND e.detector_id=?",
                (candidate["event_id"], DETECTOR),
            ).fetchone()
            if alarm is None:
                continue
            identity = (alarm["detector_id"], alarm["first_seen"], alarm["severity"])
            same_alarms = production.execute(
                "SELECT COUNT(*) FROM alerts WHERE detector_id=? AND first_seen=? AND severity=?",
                identity,
            ).fetchone()[0]
            outbox = production.execute(
                "SELECT ref FROM discord_outbox WHERE detector_id=? AND happened_at=? AND severity=?",
                identity,
            ).fetchall()
            if same_alarms != 1 or len(outbox) != 1:
                result["outbox_match_ambiguous"] = True
                continue
            reference = outbox[0][0]
            receipt = delivery.execute(
                "SELECT sent_at FROM deliveries WHERE ref=?", (reference,)
            ).fetchone()
            result["registered_alarms"].append(
                {
                    "alarm_id": alarm["id"],
                    "process_count": alarm["process_count"],
                    "reference": reference,
                    "discord_acknowledged": receipt is not None,
                }
            )
    finally:
        production.close()
        delivery.close()
    return result


def complete(result: dict) -> bool:
    alarms = result["registered_alarms"]
    return (
        result["failed_probe_processes"] == 3
        and result["probe_groups"] == 1
        and result["source_completed_after_probe"]
        and result["matching_candidates"] == 1
        and result["other_failure_processes"] == 0
        and not result["outbox_match_ambiguous"]
        and len(alarms) == 1
        and alarms[0]["process_count"] == 3
        and alarms[0]["discord_acknowledged"]
    )


def watch(request: dict) -> bool:
    deadline = time.monotonic() + 180
    last_progress = None
    next_update = 0.0
    result = None
    while time.monotonic() < deadline:
        result = inspect(request)
        progress = (
            result["failed_probe_processes"],
            result["matching_candidates"],
            len(result["registered_alarms"]),
            sum(item["discord_acknowledged"] for item in result["registered_alarms"]),
        )
        if progress != last_progress or time.monotonic() >= next_update:
            print(
                "Progress: failed processes=%d/3; candidates=%d; alarms=%d; Discord receipts=%d"
                % progress,
                flush=True,
            )
            last_progress = progress
            next_update = time.monotonic() + 15
        if complete(result):
            break
        time.sleep(3)
    passed = result is not None and complete(result)
    print(
        "PASS: live sudo rule alarm and recorded Discord acknowledgement"
        if passed
        else "INCOMPLETE: no further test attempts generated",
        flush=True,
    )
    print(json.dumps(result, indent=2, sort_keys=True), flush=True)
    print(
        "One controlled episode; no population FPR/recall claim. ML flags are shadow observations.",
        flush=True,
    )
    return passed


def inspector_args() -> list[str]:
    return [
        "/usr/bin/sudo",
        "-n",
        "/usr/bin/env",
        f"PYTHONPATH={CODE}/src",
        "PYTHONDONTWRITEBYTECODE=1",
        "/usr/bin/python3",
        str(Path(__file__).resolve()),
        "--inspect",
    ]


def run() -> bool:
    if (CODE / "COMMIT").read_text().strip() != INSTALLED_SHA:
        raise ValueError("Installed integration release differs from reviewed live probe")
    status = subprocess.run(
        ["systemctl", "is-active", *UNITS], capture_output=True, text=True, timeout=10
    )
    if status.stdout.splitlines() != ["active"] * len(UNITS):
        raise ValueError("Expected production services and all sudo timers active")
    preflight = subprocess.run(
        inspector_args(),
        input=json.dumps({"stage": "preflight"}),
        capture_output=True,
        text=True,
        timeout=15,
    )
    if preflight.returncode or not json.loads(preflight.stdout)["ready"]:
        raise ValueError(
            "Probe held: verify fresh integration and allow five minutes without auth failures"
        )
    # Reuse the already exercised bounded service-account invocation, never its
    # 30-normal-command research workflow, fitting or journal export functions.
    from sprint5_sudo_frozen_probe import invoke

    boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip().replace("-", "")
    pids = []
    start = time.time()
    for i in range(3):
        print(f"=== Live sudo failure {i + 1}/3 as yggdrasil-web ===", flush=True)
        pids.append(invoke(failure=True))
        print("Confirmed rejected authentication attempt", flush=True)
    end = time.time()
    request = validate_request(
        {"stage": "watch", "boot": boot, "pids": pids, "start": start, "end": end}
    )
    print(
        "Waiting up to 180 seconds for the existing timers and notifier. No forced polls or repeat probes.",
        flush=True,
    )
    result = subprocess.run(inspector_args(), input=json.dumps(request), text=True, timeout=195)
    return result.returncode == 0


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inspect", action="store_true")
    parser.add_argument("--run-live-probe", action="store_true")
    args = parser.parse_args()
    if os.uname().nodename != "yggdrasil":
        parser.exit(2, "STOP: run only on Yggdrasil\n")
    try:
        if args.inspect:
            if os.geteuid() != 0:
                raise ValueError("Private inspection requires the pinned sudo invocation")
            raw = sys.stdin.read(4097)
            if len(raw) > 4096:
                raise ValueError("Oversized probe request")
            request = validate_request(json.loads(raw))
            if request["stage"] == "preflight":
                print(json.dumps(inspect(request)))
                return
            success = watch(request)
        else:
            if (
                os.geteuid() == 0
                or pwd.getpwuid(os.geteuid()).pw_name != "vidar"
                or not args.run_live_probe
            ):
                raise ValueError("Run as vidar with --run-live-probe")
            success = run()
    except (
        OSError,
        ValueError,
        RuntimeError,
        TypeError,
        KeyError,
        sqlite3.Error,
        subprocess.SubprocessError,
    ) as exc:
        reason = str(exc) if isinstance(exc, (ValueError, RuntimeError)) else type(exc).__name__
        parser.exit(1, "STOP: " + reason + "; no further probe attempts generated\n")
    if not success:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
