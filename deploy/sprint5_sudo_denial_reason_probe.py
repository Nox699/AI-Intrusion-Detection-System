#!/usr/bin/env python3
"""One authorized non-interactive sudo probe, reporting only a coarse error category.

This is a manually initiated, one-shot diagnostic. It executes ONLY /usr/bin/true
through the existing unprivileged yggdrasil-web service account. No shell,
configuration writes, database changes, notifier or service restarts.
Stdout/stderr are captured privately and NEVER emitted.
Run as vidar (non-root), after separately validating sudo credentials.
"""

from __future__ import annotations

import json
import os
import pwd
import subprocess
import sys

TARGET_USER = "yggdrasil-web"
EXPECTED_COMMAND = (
    "/usr/bin/sudo",
    "-n",
    "-u",
    TARGET_USER,
    "/usr/bin/sudo",
    "-n",
    "/usr/bin/true",
)


def categorize_error(message: str, returncode: int) -> str:
    """Coarse, English-locale categories; no original error text returned."""
    if returncode == 0:
        return "unexpected_success"
    lowered = message.casefold()
    if "is not in the sudoers file" in lowered or "is not in sudoers" in lowered:
        return "not_in_sudoers"
    if "not allowed to execute" in lowered or "may not run sudo" in lowered:
        return "command_not_permitted"
    if "a password is required" in lowered or "password is required" in lowered:
        return "password_required_noninteractive"
    if "a terminal is required" in lowered or "must have a tty" in lowered:
        return "tty_required"
    if "effective uid is not 0" in lowered or "no new privileges" in lowered:
        return "privilege_execution_blocked"
    if "nosuid" in lowered:
        return "privilege_execution_blocked"
    return "unclassified_failure"


def probe() -> dict[str, object]:
    if os.geteuid() == 0:
        raise ValueError("Run only as a normal login user")
    target = pwd.getpwnam(TARGET_USER)
    if target.pw_uid == 0:
        raise ValueError("Refusing to test a privileged target identity")
    try:
        completed = subprocess.run(
            EXPECTED_COMMAND,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            errors="replace",
            timeout=15,
            env={**os.environ, "LC_ALL": "C", "LANG": "C"},
            check=False,
        )
    except subprocess.TimeoutExpired:
        return {
            "kind": "one_shot_sudo_denial_reason_probe",
            "status": "timed_out",
            "reason_category": "timeout",
            "raw_stdout_stderr_exposed": False,
            "production_ids_changed": False,
        }
    return {
        "kind": "one_shot_sudo_denial_reason_probe",
        "status": "completed",
        "exit_code": completed.returncode,
        "reason_category": categorize_error(completed.stderr, completed.returncode),
        "inner_command": "harmless_true",
        "one_noninteractive_inner_sudo_attempt": True,
        "raw_stdout_stderr_exposed": False,
        "production_ids_changed": False,
        "sudoers_or_services_modified": False,
        "note": (
            "This categorizes one sudo stderr message, not a logged security event. "
            "The outer sudo or its authentication may write ordinary audit logs. "
            "A success would require separate review of unexpected permissions."
        ),
    }


def main() -> int:
    try:
        report = probe()
    except (ValueError, KeyError, OSError, subprocess.SubprocessError):
        print("STOP: Cannot safely run the one-shot sudo probe", file=sys.stderr)
        return 1
    print(json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
