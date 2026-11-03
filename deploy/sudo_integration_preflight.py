#!/usr/bin/env python3
"""Read-only Pi inventory for coordinated sudo integration; aggregate output only."""

from __future__ import annotations

import grp
import hashlib
import json
import os
import pwd
import re
import shlex
import sqlite3
import stat
import subprocess
import time
from pathlib import Path

UNITS = (
    "yggdrasil-collector.service",
    "yggdrasil-web.service",
    "yggdrasil-notifier.service",
    "yggdrasil-sudo-shadow.service",
    "yggdrasil-sudo-shadow.timer",
    "yggdrasil-sudo-ui-export.service",
    "yggdrasil-sudo-ui-export.timer",
)
PROPERTIES = (
    "ActiveState",
    "UnitFileState",
    "User",
    "Group",
    "SupplementaryGroups",
    "FragmentPath",
    "DropInPaths",
    "Environment",
    "ExecStart",
)
MODEL = Path(
    "/home/vidar/yggdrasil-sudo-ml-private/sudo-original-baseline-20261103T200046-156301/mixed_full-model.json"
)
MODEL_SHA = "5839076103232763379a2ae401ee1590b39d22cb28e31ea272fe7ced539bf370"
MODEL_VERSION = "sudo-if-15207a3b77b40fe2"


def describe_path(path: Path) -> dict:
    try:
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode):
            return {"state": "symlink_refused"}
        return {
            "state": "present",
            "mode": f"{stat.S_IMODE(info.st_mode):04o}",
            "owner": pwd.getpwuid(info.st_uid).pw_name,
            "group": grp.getgrgid(info.st_gid).gr_name,
        }
    except (OSError, KeyError):
        return {"state": "unavailable"}


def safe_unit_properties(raw: str) -> dict:
    values = dict(line.split("=", 1) for line in raw.splitlines() if "=" in line)
    result = {
        key: values.get(key, "") for key in PROPERTIES if key not in {"Environment", "ExecStart"}
    }
    environment = {}
    try:
        for item in shlex.split(values.get("Environment", "")):
            key, separator, value = item.partition("=")
            if separator and key in {"PYTHONPATH", "YGGDRASIL_CONFIG"}:
                # These values must be simple local paths, never reflected secrets.
                if value and all(
                    re.fullmatch(r"/[A-Za-z0-9_./+ -]+", part) for part in value.split(":")
                ):
                    environment[key] = value
                else:
                    environment[key] = "unrecognized_path"
    except ValueError:
        environment = {"state": "unrecognized"}
    result["selected_environment"] = environment
    match = re.search(
        r"(?:^|[ {;])path=(/[A-Za-z0-9_./+-]+)(?:[ ;}]|$)", values.get("ExecStart", "")
    )
    result["executable"] = match.group(1) if match else "unresolved"
    return result


def unit_inventory(unit: str) -> dict:
    try:
        process = subprocess.run(
            ["systemctl", "show", unit, "--no-pager", "--property=" + ",".join(PROPERTIES)],
            capture_output=True,
            text=True,
            timeout=8,
            check=True,
        )
        result = safe_unit_properties(process.stdout)
    except (OSError, subprocess.SubprocessError):
        return {"state": "unavailable"}
    candidates = []
    for entry in result["selected_environment"].get("PYTHONPATH", "").split(":"):
        if entry.startswith("/"):
            candidates.append(Path(entry) / "yggdrasil_ids/storage.py")
    executable = Path(result["executable"])
    if executable.is_absolute():
        candidates.extend(
            executable.parent.parent.glob("lib/python*/site-packages/yggdrasil_ids/storage.py")
        )
    schemas = []
    for candidate in candidates[:16]:
        try:
            if candidate.stat().st_size > 200_000:
                continue
            match = re.search(
                r"^SCHEMA_VERSION\s*=\s*(\d+)\s*$", candidate.read_text(), re.MULTILINE
            )
            if match:
                schemas.append({"source": str(candidate), "schema": int(match.group(1))})
        except (OSError, UnicodeError):
            continue
    result["storage_source_candidates"] = schemas
    result["source_resolution"] = "candidate_found" if schemas else "unresolved"
    return result


def database_inventory(path: Path, *, private: bool, now: float) -> dict:
    result = {"file": describe_path(path), "directory": describe_path(path.parent)}
    if result["file"]["state"] != "present" or result["directory"]["state"] != "present":
        return {**result, "state": "unavailable"}
    try:
        with sqlite3.connect(path.absolute().as_uri() + "?mode=ro", uri=True, timeout=5) as db:
            db.execute("PRAGMA query_only=ON")
            db.execute("BEGIN")
            result["schema"] = db.execute("PRAGMA user_version").fetchone()[0]
            tables = (
                ("sudo_signals", "sudo_candidates")
                if private
                else ("events", "alerts", "discord_outbox")
            )
            result["counts"] = {
                table: db.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] for table in tables
            }
            if private:
                row = db.execute(
                    "SELECT last_completed_until FROM shadow_poll_checkpoint WHERE id=1"
                ).fetchone()
                result["checkpoint_age_seconds"] = round(now - row[0], 1) if row else None
            else:
                # Never print arbitrary state values: mode and namespace are enums.
                for key in ("mode", "namespace"):
                    row = db.execute("SELECT value FROM state WHERE key=?", (key,)).fetchone()
                    result[key] = (
                        json.loads(row[0])
                        if row and json.loads(row[0]) in {"live", "demo"}
                        else "unrecognized"
                    )
        return {**result, "state": "readable_readonly"}
    except (OSError, sqlite3.Error, ValueError, TypeError):
        return {**result, "state": "unavailable"}


def model_inventory(path: Path = MODEL) -> dict:
    result = {"file": describe_path(path), "directory": describe_path(path.parent)}
    try:
        if result["file"]["state"] != "present" or path.stat().st_size > 5_000_000:
            raise ValueError("Invalid model file")
        raw = path.read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        result["file_sha256"] = digest
        if digest != MODEL_SHA:
            return {**result, "state": "hash_mismatch"}
        data = json.loads(raw)
        signature = data.get("sha256", "")
        version = "sudo-if-" + signature[:16] if isinstance(signature, str) else "unexpected"
        result["version"] = version if version == MODEL_VERSION else "unexpected"
        result["state"] = (
            "frozen_artifact_verified" if version == MODEL_VERSION else "version_mismatch"
        )
        # Training data stays private; no vectors or arbitrary metadata printed.
        result["saved_training_rows"] = len(data.get("normal_training_rows", []))
        return result
    except (OSError, ValueError, TypeError):
        return {**result, "state": "unavailable"}


def inventory() -> dict:
    now = time.time()
    manifests = {}
    for directory in ("yggdrasil-sudo-ui", "yggdrasil-sudo-ui-web", "yggdrasil-sudo-shadow"):
        try:
            value = (Path("/opt") / directory / "COMMIT").read_text().strip()
            manifests[directory] = value if re.fullmatch(r"[0-9a-f]{40}", value) else "unrecognized"
        except OSError:
            manifests[directory] = "unavailable"
    accounts = {}
    for name in ("yggdrasil-worker", "yggdrasil-web"):
        try:
            account = pwd.getpwnam(name)
            accounts[name] = {"primary_group": grp.getgrgid(account.pw_gid).gr_name}
        except KeyError:
            accounts[name] = {"state": "missing"}
    return {
        "format": "sudo-integration-preflight-v1",
        "read_only": True,
        "services": {unit: unit_inventory(unit) for unit in UNITS},
        "accounts": accounts,
        "production": database_inventory(
            Path("/var/lib/yggdrasil-ids/events.sqlite3"), private=False, now=now
        ),
        "sudo_source": database_inventory(
            Path("/var/lib/yggdrasil-sudo-shadow/sudo-shadow.sqlite3"), private=True, now=now
        ),
        "public_directory": describe_path(Path("/var/lib/yggdrasil-sudo-public")),
        "model": model_inventory(),
        "manifests": manifests,
        "next_step": "Review installed source paths before coordinated schema5 deployment",
        "services_changed": False,
        "database_migrated": False,
        "models_activated": False,
    }


if __name__ == "__main__":
    if os.geteuid() != 0:
        raise SystemExit("Run the read-only inventory via the pinned Pi wrapper")
    print(json.dumps(inventory(), ensure_ascii=False, indent=2, allow_nan=False))
