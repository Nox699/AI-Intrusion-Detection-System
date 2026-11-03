#!/usr/bin/env python3
"""Coordinated Pi-only sudo integration deployment with data-preserving recovery.

Called by a pinned Git wrapper. No pip replacement, config edits, credential
reads, notifier bootstrap, synthetic alarms or probe commands are performed.
"""

from __future__ import annotations

import argparse
import fcntl
import grp
import hashlib
import json
import math
import os
import pwd
import re
import shlex
import shutil
import sqlite3
import stat
import subprocess
import time
from pathlib import Path
from urllib.request import urlopen

CODE = Path("/opt/yggdrasil-sudo-integration")
PRIVATE = Path("/var/lib/yggdrasil-sudo-integration-private")
DATABASE = Path("/var/lib/yggdrasil-ids/events.sqlite3")
CONFIG = Path("/etc/yggdrasil-ids/config.toml")
PUBLIC = Path("/var/lib/yggdrasil-sudo-public/sudo-integration.json")
PYTHON = "/opt/yggdrasil-ids/venv/bin/python"
MODEL = Path(
    "/home/vidar/yggdrasil-sudo-ml-private/sudo-original-baseline-20261103T200046-156301/mixed_full-model.json"
)
MODEL_HASH = "5839076103232763379a2ae401ee1590b39d22cb28e31ea272fe7ced539bf370"
MODEL_VERSION = "sudo-if-15207a3b77b40fe2"
PRODUCTION = ("yggdrasil-collector.service", "yggdrasil-web.service", "yggdrasil-notifier.service")
TIMER = "yggdrasil-sudo-integration.timer"
SERVICE = "yggdrasil-sudo-integration.service"
UNIT_DIR = Path("/etc/systemd/system")
OVERRIDE_NAME = "60-sudo-integration.conf"
BACKUP_ROOT = Path("/var/backups/yggdrasil-ids")
ARM_KEY = "sudo_integration_activation_v1"
PROGRESS_KEY = "sudo_integration_progress_v1"
BASE_TABLES = (
    "records",
    "events",
    "firewall_events",
    "observations",
    "alerts",
    "findings",
    "preauth_disconnects",
    "preauth_evidence",
    "network_evidence",
    "discord_outbox",
    "discord_outbox_meta",
    "state",
    "sqlite_sequence",
)
CHILD_ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}


class DeployError(RuntimeError):
    pass


def command(args: list[str], *, check: bool = True, timeout: int = 45):
    result = subprocess.run(
        args,
        capture_output=True,
        text=True,
        timeout=timeout,
        cwd="/opt/yggdrasil-ids",
        env=CHILD_ENV,
    )
    if check and result.returncode:
        # Never reflect arbitrary child output, environment or credentials.
        raise DeployError("Deployment command failed: " + Path(args[0]).name)
    return result


def properties(unit: str) -> dict:
    raw = command(
        [
            "systemctl",
            "show",
            unit,
            "--no-pager",
            "--property=ActiveState,UnitFileState,User,Group,SupplementaryGroups,DropInPaths,Environment",
        ]
    ).stdout
    return dict(line.split("=", 1) for line in raw.splitlines() if "=" in line)


def overlay(unit: str) -> str:
    readonly = "ReadOnlyPaths=/var/lib/yggdrasil-sudo-public\n" if unit == PRODUCTION[1] else ""
    return (
        "[Service]\n# Coordinated sudo schema5 release for all production roles.\n"
        f"Environment=PYTHONPATH={CODE}/src\nEnvironment=PYTHONDONTWRITEBYTECODE=1\n" + readonly
    )


def override_path(unit: str) -> Path:
    return UNIT_DIR / f"{unit}.d" / OVERRIDE_NAME


def readonly(path: Path):
    db = sqlite3.connect(path.absolute().as_uri() + "?mode=ro", uri=True, timeout=10)
    db.execute("PRAGMA query_only=ON")
    return db


def fingerprint(path: Path) -> dict:
    """Private table contents are hashed, never returned or logged as records."""
    with readonly(path) as db:
        db.execute("BEGIN")
        result = {}
        for table in BASE_TABLES:
            digest = hashlib.sha256()
            count = 0
            for row in db.execute(f"SELECT * FROM {table} ORDER BY rowid"):
                raw = repr(tuple(row)).encode("utf-8")
                digest.update(len(raw).to_bytes(8, "big") + raw)
                count += 1
            result[table] = {"count": count, "sha256": digest.hexdigest()}
        return result


def backup_database(source: Path, target: Path) -> dict:
    if target.exists() or target.is_symlink():
        raise DeployError("Database backup already exists")
    with readonly(source) as db, sqlite3.connect(target) as copy:
        db.backup(copy)
        if copy.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            raise DeployError("Database backup failed integrity check")
    target.chmod(0o600)
    return fingerprint(target)


def reversible_database(path: Path) -> bool:
    with readonly(path) as db:
        version = db.execute("PRAGMA user_version").fetchone()[0]
        if version == 4:
            return True
        if version != 5:
            raise DeployError("Unexpected database version during rollback")
        return db.execute("SELECT COUNT(*) FROM sudo_evidence").fetchone()[0] == 0


def downgrade_empty_sudo(path: Path) -> None:
    """Keep all SSH/UFW/outbox changes; never restore an older live DB image."""
    with sqlite3.connect(path, timeout=10) as db:
        db.execute("PRAGMA foreign_keys=ON")
        db.execute("BEGIN IMMEDIATE")
        version = db.execute("PRAGMA user_version").fetchone()[0]
        if version not in {4, 5}:
            raise DeployError("Unexpected database version during rollback")
        if version == 5:
            if db.execute("SELECT COUNT(*) FROM sudo_evidence").fetchone()[0]:
                raise DeployError(
                    "New sudo alarm evidence requires keeping compatible schema5 code"
                )
            db.execute("DROP TABLE sudo_evidence")
            db.execute("DELETE FROM state WHERE key IN (?,?)", (ARM_KEY, PROGRESS_KEY))
            db.execute("PRAGMA user_version=4")
        if db.execute("PRAGMA foreign_key_check").fetchall():
            raise DeployError("Foreign key check failed during rollback")


def worker(code: str, *, user: str = "yggdrasil-worker", check: bool = True):
    group = "yggdrasil-data" if user == "yggdrasil-worker" else user
    groups = "yggdrasil-data,systemd-journal" if user == "yggdrasil-worker" else "yggdrasil-data"
    return command(
        [
            "/usr/bin/setpriv",
            f"--reuid={user}",
            f"--regid={group}",
            f"--groups={groups}",
            "/usr/bin/env",
            f"PYTHONPATH={CODE}/src",
            "PYTHONDONTWRITEBYTECODE=1",
            f"YGGDRASIL_CONFIG={CONFIG}",
            "OPENBLAS_NUM_THREADS=1",
            "OMP_NUM_THREADS=1",
            PYTHON,
            "-c",
            code,
        ],
        check=check,
    )


def write_exclusive(path: Path, data: bytes, mode: int = 0o644) -> None:
    with path.open("xb") as stream:
        stream.write(data)
        stream.flush()
        os.fchmod(stream.fileno(), mode)
        os.fsync(stream.fileno())


def check_runtime() -> None:
    expected = {
        PRODUCTION[0]: ("yggdrasil-worker", "yggdrasil-data"),
        PRODUCTION[1]: ("yggdrasil-web", "yggdrasil-web"),
        PRODUCTION[2]: ("yggdrasil-notifier", "yggdrasil-notifier"),
    }
    for unit, (user, group) in expected.items():
        info = properties(unit)
        if (
            info.get("ActiveState") != "active"
            or info.get("UnitFileState") != "enabled"
            or info.get("User") != user
            or info.get("Group") != group
            or info.get("DropInPaths")
        ):
            raise DeployError("Production runtime changed since reviewed preflight: " + unit)
        env = dict(
            item.split("=", 1) for item in shlex.split(info.get("Environment", "")) if "=" in item
        )
        if "PYTHONPATH" in env or env.get("YGGDRASIL_CONFIG", str(CONFIG)) != str(CONFIG):
            raise DeployError("Unexpected production source or config override")
    for timer in ("yggdrasil-sudo-shadow.timer", "yggdrasil-sudo-ui-export.timer"):
        if properties(timer).get("ActiveState") != "active":
            raise DeployError("Existing sudo timer is not active")
    with readonly(DATABASE) as db:
        if db.execute("PRAGMA user_version").fetchone()[0] != 4:
            raise DeployError("Expected reviewed production schema4")
        for key in ("mode", "namespace"):
            row = db.execute("SELECT value FROM state WHERE key=?", (key,)).fetchone()
            if not row or json.loads(row[0]) != "live":
                raise DeployError("Existing live database required")
    if (
        not MODEL.is_file()
        or MODEL.is_symlink()
        or hashlib.sha256(MODEL.read_bytes()).hexdigest() != MODEL_HASH
    ):
        raise DeployError("Frozen model bytes differ from the reviewed probe")
    if pwd.getpwnam("yggdrasil-worker").pw_gid != grp.getgrnam("yggdrasil-data").gr_gid:
        raise DeployError("Worker primary group differs from preflight")


def copy_source(source: Path, sha: str) -> None:
    package = source / "src/yggdrasil_ids"
    files = list(package.rglob("*"))
    if not files or any(path.is_symlink() for path in files):
        raise DeployError("Invalid source snapshot")
    CODE.mkdir(mode=0o755)
    CODE.chmod(0o755)
    shutil.copytree(package, CODE / "src/yggdrasil_ids")
    for path in CODE.rglob("*"):
        path.chmod(0o755 if path.is_dir() else 0o644)
    (CODE / "deploy").mkdir(mode=0o755)
    (CODE / "deploy").chmod(0o755)
    for filename in ("sprint5_sudo_integration_poll.py", "sudo_integration_deploy.py"):
        write_exclusive(CODE / "deploy" / filename, (source / "deploy" / filename).read_bytes())
    write_exclusive(CODE / "COMMIT", (sha + "\n").encode())
    PRIVATE.mkdir(mode=0o700)
    worker_uid = pwd.getpwnam("yggdrasil-worker").pw_uid
    data_gid = grp.getgrnam("yggdrasil-data").gr_gid
    os.chown(PRIVATE, worker_uid, data_gid)
    model_bytes = MODEL.read_bytes()
    if hashlib.sha256(model_bytes).hexdigest() != MODEL_HASH:
        raise DeployError("Frozen model changed during staging")
    model_copy = PRIVATE / "mixed_full-model.json"
    write_exclusive(model_copy, model_bytes, 0o400)
    os.chown(model_copy, worker_uid, data_gid)


def check_roles(*, migrated: bool) -> None:
    common = (
        "from pathlib import Path; from yggdrasil_ids.config import load_config; "
        "import yggdrasil_ids.storage as storage; "
        f"assert Path(storage.__file__).resolve()==Path('{CODE}/src/yggdrasil_ids/storage.py'); "
        "assert storage.SCHEMA_VERSION==5; cfg=load_config(); "
        f"assert cfg.mode=='live' and cfg.database_path==Path('{DATABASE}'); "
        "assert cfg.web.bind=='127.0.0.1' and cfg.web.port==8765; "
    )
    for role in ("yggdrasil-worker", "yggdrasil-web", "yggdrasil-notifier"):
        extra = ""
        if migrated:
            extra += "repo=storage.Repository(cfg.database_path,readonly=True); "
            extra += "db=repo.connect(); assert db.execute('PRAGMA user_version').fetchone()[0]==5; db.close(); "
        if role == "yggdrasil-worker":
            extra += (
                "from yggdrasil_ids.cli import doctor; assert doctor(cfg,role='collector')['ok']; "
                "from yggdrasil_ids.sudo_live_ml import build_ml_snapshot; "
                "snapshot=build_ml_snapshot(Path('/var/lib/yggdrasil-sudo-shadow/sudo-shadow.sqlite3'),"
                f"Path('{PRIVATE}/mixed_full-model.json'),'{MODEL_VERSION}','{MODEL_HASH}'); "
                "assert snapshot['mode']=='shadow' and snapshot['sends_alerts'] is False; "
            )
        elif role == "yggdrasil-web":
            extra += (
                "from yggdrasil_ids.web import create_app; app=create_app(cfg); "
                "assert app.test_client().get('/sudo').status_code==302; "
                f"assert not __import__('os').access('{PRIVATE}/mixed_full-model.json',4); "
                "assert not __import__('os').access('/var/lib/yggdrasil-sudo-shadow/sudo-shadow.sqlite3',4); "
            )
        else:
            extra += "from yggdrasil_ids.notify import DiscordNotifier; "
        result = worker(common + extra, user=role, check=False)
        # A journal poll lock can transiently block the provisional ML snapshot.
        if result.returncode and role == "yggdrasil-worker":
            for _ in range(3):
                time.sleep(1)
                result = worker(common + extra, user=role, check=False)
                if not result.returncode:
                    break
        if result.returncode:
            raise DeployError("Candidate source/config/model check failed for " + role)


def stop_production() -> None:
    command(["systemctl", "stop", *PRODUCTION])


def start_production() -> None:
    command(["systemctl", "start", *PRODUCTION])
    for _ in range(10):
        if all(properties(unit).get("ActiveState") == "active" for unit in PRODUCTION):
            return
        time.sleep(1)
    raise DeployError("Production services did not become active")


def login_check() -> None:
    for _ in range(10):
        try:
            with urlopen("http://127.0.0.1:8765/login", timeout=3) as response:
                if response.status == 200 and b"Yggdrasil" in response.read(16_384):
                    return
        except (OSError, ValueError):
            pass
        time.sleep(1)
    raise DeployError("Production login page is not healthy")


def initial_snapshot(activated_at: float) -> None:
    """Wait for a real current export, not disposable oneshot unit metadata."""
    for attempt in range(4):
        snapshot_exit = None
        started_at = time.time()
        result = command(["systemctl", "start", SERVICE], check=False)
        if not result.returncode:
            verification = worker(
                "from yggdrasil_ids.sudo_integration_dashboard import require_current_run; "
                f"require_current_run(not_before={started_at!r}, "
                f"expected_activation={activated_at!r}, expected_model={MODEL_VERSION!r})",
                user="yggdrasil-web",
                check=False,
            )
            snapshot_exit = verification.returncode
            if not snapshot_exit:
                print("PASS: current rule and frozen-ML snapshot verified as web user", flush=True)
                return
        if attempt == 3:
            raise DeployError(
                "Initial integration verification failed "
                f"(start_exit={result.returncode}, snapshot_check_exit={snapshot_exit})"
            )
        command(["systemctl", "reset-failed", SERVICE], check=False)
        time.sleep(1)


def recover(*, manual: bool = False) -> bool:
    """Disable integration, preserving post-install history and notifier state."""
    if manual and not reversible_database(DATABASE):
        raise DeployError(
            "Sudo alarms already exist: retain schema5 and its evidence; review a forward repair"
        )
    command(["systemctl", "disable", "--now", TIMER], check=False)
    command(["systemctl", "stop", SERVICE], check=False)
    stop_production()
    if not reversible_database(DATABASE):
        # New genuine evidence must never be discarded by automatic recovery.
        PUBLIC.unlink(missing_ok=True)
        start_production()
        print(
            "RECOVERY: integration disabled; compatible schema5 services retained because sudo alarms exist",
            flush=True,
        )
        return False
    downgrade_empty_sudo(DATABASE)
    for unit in PRODUCTION:
        override_path(unit).unlink(missing_ok=True)
    for unit in (SERVICE, TIMER):
        (UNIT_DIR / unit).unlink(missing_ok=True)
    PUBLIC.unlink(missing_ok=True)
    command(["systemctl", "daemon-reload"])
    start_production()
    login_check()
    # These paths were created exclusively for this deployment. Processes
    # using them have stopped or returned to the original installed package.
    for path in (CODE, PRIVATE):
        if path.is_symlink():
            raise DeployError("Unexpected linked integration directory during recovery")
        if path.exists():
            shutil.rmtree(path)
    print(
        "RECOVERY: schema4 and original role source restored; current SSH/UFW/outbox history preserved",
        flush=True,
    )
    return True


def install(source: Path, sha: str) -> None:
    backup = BACKUP_ROOT / f"sprint5-sudo-integration-before-{sha}"
    forbidden = [CODE, PRIVATE, PUBLIC, backup, UNIT_DIR / SERVICE, UNIT_DIR / TIMER]
    forbidden.extend(override_path(unit) for unit in PRODUCTION)
    if any(path.exists() or path.is_symlink() for path in forbidden):
        raise DeployError(
            "Integration path or backup already exists; inspect instead of overwriting"
        )
    check_runtime()
    config_hash = hashlib.sha256(CONFIG.read_bytes()).hexdigest()
    print(
        "=== Stage frozen model and coordinated source; validate all role identities ===",
        flush=True,
    )
    try:
        copy_source(source, sha)
        check_roles(migrated=False)
    except BaseException:
        for path in (CODE, PRIVATE):
            if path.exists() and not path.is_symlink():
                shutil.rmtree(path)
        raise
    BACKUP_ROOT.mkdir(parents=True, exist_ok=True, mode=0o700)
    backup.mkdir(mode=0o700)
    for unit in PRODUCTION:
        shutil.copyfile(UNIT_DIR / unit, backup / unit)
        (backup / unit).chmod(0o600)
    changed = False
    try:
        print("=== Stop production roles together and back up schema4 ===", flush=True)
        changed = True
        stop_production()
        baseline = backup_database(DATABASE, backup / "events-schema4.sqlite3")
        write_exclusive(
            backup / "manifest.json",
            json.dumps(
                {
                    "format": "sudo-integration-deploy-v1",
                    "sha": sha,
                    "config_sha256": config_hash,
                    "baseline": baseline,
                    "notifier_delivery_state_replaced": False,
                },
                indent=2,
            ).encode(),
            0o600,
        )
        for unit in PRODUCTION:
            override_path(unit).parent.mkdir(exist_ok=True, mode=0o755)
            write_exclusive(override_path(unit), overlay(unit).encode())
        for unit in (SERVICE, TIMER):
            write_exclusive(UNIT_DIR / unit, (source / "deploy" / unit).read_bytes())
        command(
            [
                "systemd-analyze",
                "verify",
                *(str(UNIT_DIR / unit) for unit in (*PRODUCTION, SERVICE, TIMER)),
            ]
        )
        command(["systemctl", "daemon-reload"])
        print(
            "=== Migrate to schema5 as worker; verify preserved tables and role access ===",
            flush=True,
        )
        worker(
            f"from yggdrasil_ids.storage import Repository; Repository('{DATABASE}').initialize()"
        )
        if fingerprint(DATABASE) != baseline:
            raise DeployError("Existing table contents changed during schema migration")
        check_roles(migrated=True)
        if hashlib.sha256(CONFIG.read_bytes()).hexdigest() != config_hash:
            raise DeployError("Config changed during deployment")
        start_production()
        login_check()
        print(
            "=== Arm new rule cases only; validate frozen ML snapshot and start timer ===",
            flush=True,
        )
        activation = worker(
            "import json; from yggdrasil_ids.storage import Repository; "
            "from yggdrasil_ids.sudo_live_bridge import arm_rules; "
            f"print(json.dumps({{'activated_at':arm_rules(Repository('{DATABASE}'))}}))"
        )
        try:
            activated_at = json.loads(activation.stdout)["activated_at"]
        except (ValueError, KeyError, TypeError):
            raise DeployError("Worker activation response was not verified") from None
        if type(activated_at) not in (float, int) or not math.isfinite(activated_at):
            raise DeployError("Worker activation timestamp was not verified")
        initial_snapshot(activated_at)
        command(["systemctl", "enable", "--now", TIMER])
        if properties(TIMER).get("ActiveState") != "active":
            raise DeployError("Sudo integration timer is not active")
        if not all(properties(unit).get("ActiveState") == "active" for unit in PRODUCTION):
            raise DeployError("A production role stopped during activation")
        print(
            "PASS: sudo rules integrated; frozen mixed ML in shadow; dashboard http://127.0.0.1:8765/sudo",
            flush=True,
        )
        print(
            "Model:", MODEL_VERSION, "| Training on new live data: NO | ML alerts: NO", flush=True
        )
        print("Backup:", backup, flush=True)
        print(
            "No controlled alarm generated; verify the dashboard before a separate live probe",
            flush=True,
        )
    except BaseException as exc:
        if changed:
            if isinstance(exc, DeployError):
                print("ERROR: " + str(exc), flush=True)
            print(
                "ERROR: deployment interrupted; recovering compatible production roles", flush=True
            )
            recover()
        raise


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("install", "rollback"))
    parser.add_argument("--sha", required=True)
    parser.add_argument("--source", type=Path)
    args = parser.parse_args()
    if (
        os.geteuid() != 0
        or os.uname().nodename != "yggdrasil"
        or not re.fullmatch(r"[0-9a-f]{40}", args.sha)
    ):
        parser.exit(2, "STOP: use the pinned Pi wrapper on Yggdrasil\n")
    os.umask(0o077)
    lock_fd = os.open(
        "/run/lock/yggdrasil-sudo-integration-deploy.lock",
        os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW,
        0o600,
    )
    with os.fdopen(lock_fd, "a") as lock:
        lock_info = os.fstat(lock.fileno())
        if not stat.S_ISREG(lock_info.st_mode) or lock_info.st_uid != 0:
            parser.exit(2, "STOP: invalid deployment lock ownership\n")
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            if args.action == "install":
                if args.source is None:
                    raise DeployError("Pinned source snapshot required")
                install(args.source, args.sha)
            else:
                if (CODE / "COMMIT").read_text().strip() != args.sha:
                    raise DeployError("Installed release does not match rollback SHA")
                for unit in PRODUCTION:
                    if override_path(unit).read_text() != overlay(unit):
                        raise DeployError("An integration override was modified after installation")
                if not recover(manual=True):
                    raise DeployError("New sudo evidence arrived; compatible schema5 retained")
        except (
            OSError,
            ValueError,
            RuntimeError,
            sqlite3.Error,
            subprocess.SubprocessError,
        ) as exc:
            reason = str(exc) if isinstance(exc, DeployError) else type(exc).__name__
            parser.exit(
                1,
                "STOP: sudo integration deployment did not complete: " + reason + "\n",
            )


if __name__ == "__main__":
    main()
