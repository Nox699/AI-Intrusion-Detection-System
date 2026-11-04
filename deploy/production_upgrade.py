#!/usr/bin/env python3
"""Coordinated production release without replacing live history or notifier state.

The pinned wrappers provide the source tree. Upgrades reuse the existing locked
venv, preserve the reviewed SSH model and promote SSH ML to normal alarm mode.
Fresh installs require an explicitly supplied reviewed model and a separately
provisioned root-private Discord credential; no synthetic model is generated.
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
import tempfile
import time
import tomllib
from contextlib import closing
from pathlib import Path
from urllib.request import urlopen

ROOT = Path("/opt/yggdrasil-ids")
RELEASES = ROOT / "releases"
CURRENT = ROOT / "current"
PYTHON = ROOT / "venv/bin/python"
ENTRYPOINT = ROOT / "venv/bin/yggdrasil-ids"
CONFIG = Path("/etc/yggdrasil-ids/config.toml")
DATABASE = Path("/var/lib/yggdrasil-ids/events.sqlite3")
MODEL = Path("/var/lib/yggdrasil-ids/model.json")
DELIVERY = Path("/var/lib/yggdrasil-notifier/delivery.sqlite3")
SUDO_DATABASE = Path("/var/lib/yggdrasil-sudo/sudo.sqlite3")
OLD_SUDO_DATABASE = Path("/var/lib/yggdrasil-sudo-shadow/sudo-shadow.sqlite3")
PUBLIC = Path("/var/lib/yggdrasil-sudo-public")
UNIT_DIR = Path("/etc/systemd/system")
BACKUPS = Path("/var/backups/yggdrasil-ids")
PRODUCTION = ("yggdrasil-collector.service", "yggdrasil-web.service", "yggdrasil-notifier.service")
SUDO_SERVICE = "yggdrasil-sudo.service"
SUDO_TIMER = "yggdrasil-sudo.timer"
OLD_TIMERS = tuple(
    "yggdrasil-sudo-" + name + ".timer" for name in ("shadow", "ui-export", "integration")
)
OLD_SERVICES = tuple(name.removesuffix(".timer") + ".service" for name in OLD_TIMERS)
UNITS = (*PRODUCTION, SUDO_SERVICE, SUDO_TIMER)
LEGACY_INTEGRATION = Path("/opt/yggdrasil-sudo-integration")
LEGACY_WEB = Path("/opt/yggdrasil-nav-unread-web")
EXPECTED_MODEL_VERSION = "ssh-if-7cc1f15288d0c73b"
ARM_KEY = "sudo_integration_activation_v1"
ENVIRONMENT = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}


class ReleaseError(RuntimeError):
    pass


def command(args: list[str], *, check: bool = True, timeout: int = 45):
    result = subprocess.run(
        args, capture_output=True, text=True, timeout=timeout, cwd=ROOT, env=ENVIRONMENT
    )
    if check and result.returncode:
        raise ReleaseError("Release command failed: " + Path(args[0]).name)
    return result


def properties(unit: str) -> dict:
    result = command(
        [
            "systemctl",
            "show",
            unit,
            "--no-pager",
            "--property=LoadState,ActiveState,UnitFileState,User,Group,SupplementaryGroups,Environment,DropInPaths",
        ],
        check=False,
    )
    values = dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)
    if result.returncode and values.get("LoadState") != "not-found":
        raise ReleaseError("Cannot read production service state: " + unit)
    return values


def readonly(path: Path):
    if path.is_symlink() or not path.is_file():
        raise ReleaseError("Expected an existing regular database")
    db = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=10)
    db.execute("PRAGMA query_only=ON")
    return db


def database_identity(*, require_activation: bool = True) -> dict:
    with closing(readonly(DATABASE)) as db, closing(readonly(DELIVERY)) as receipts:
        db.execute("BEGIN")
        if db.execute("PRAGMA user_version").fetchone()[0] != 5:
            raise ReleaseError("This upgrade requires the verified schema5 installation")
        for key in ("mode", "namespace"):
            row = db.execute("SELECT value FROM state WHERE key=?", (key,)).fetchone()
            if not row or json.loads(row[0]) != "live":
                raise ReleaseError("Existing live database required")
        source = db.execute("SELECT instance FROM discord_outbox_meta WHERE id=1").fetchone()
        target = receipts.execute("SELECT instance,last_seq FROM meta").fetchone()
        if not source or not target or source[0] != target[0]:
            raise ReleaseError("Existing notifier identity differs from the alarm outbox")
        maximum = db.execute("SELECT COALESCE(MAX(seq),0) FROM discord_outbox").fetchone()[0]
        if target[1] > maximum:
            raise ReleaseError("Notifier checkpoint is beyond the existing outbox")
        row = db.execute("SELECT value FROM state WHERE key=?", (ARM_KEY,)).fetchone()
        activated = json.loads(row[0]) if row else None
        if require_activation and (
            type(activated) not in (int, float)
            or not math.isfinite(activated)
            or not 1 <= activated <= time.time()
        ):
            raise ReleaseError("Existing sudo activation boundary is missing or invalid")
        state = db.execute("SELECT value FROM state WHERE key='model'").fetchone()
        model = json.loads(state[0]) if state else {}
        return {
            "instance": source[0],
            "last_seq": target[1],
            "outbox_maximum": maximum,
            "activated_at": activated,
            "model_version": model.get("metadata", {}).get("version"),
        }


def require_identity(previous: dict) -> None:
    current = database_identity()
    if (
        current["instance"] != previous["instance"]
        or current["last_seq"] < previous["last_seq"]
        or current["outbox_maximum"] < previous["outbox_maximum"]
    ):
        raise ReleaseError("Alarm or notifier history moved backwards")
    if (
        previous.get("activated_at") is not None
        and current["activated_at"] != previous["activated_at"]
    ):
        raise ReleaseError("Existing sudo activation boundary changed")


def check_private_source(path: Path) -> None:
    if path.parent.is_symlink():
        raise ReleaseError("Private sudo source directory is linked")
    with closing(readonly(path)) as db:
        if db.execute("PRAGMA user_version").fetchone()[0] != 2:
            raise ReleaseError("Existing sudo source schema is incompatible")
        row = db.execute(
            "SELECT last_completed_until FROM shadow_poll_checkpoint WHERE id=1"
        ).fetchone()
        if (
            not row
            or type(row[0]) not in (int, float)
            or not math.isfinite(row[0])
            or not 0 <= time.time() - row[0] <= 180
        ):
            raise ReleaseError("Existing sudo source checkpoint is not fresh")


def role(
    code: str, *, source: Path, config: Path, user: str = "yggdrasil-worker", check: bool = True
):
    group = "yggdrasil-data" if user == "yggdrasil-worker" else user
    groups = "yggdrasil-data,systemd-journal" if user == "yggdrasil-worker" else "yggdrasil-data"
    return command(
        [
            "/usr/bin/setpriv",
            f"--reuid={user}",
            f"--regid={group}",
            f"--groups={groups}",
            "/usr/bin/env",
            f"PYTHONPATH={source / 'src'}",
            "PYTHONDONTWRITEBYTECODE=1",
            "OPENBLAS_NUM_THREADS=1",
            "OMP_NUM_THREADS=1",
            f"YGGDRASIL_CONFIG={config}",
            str(PYTHON),
            "-c",
            code,
        ],
        check=check,
    )


def role_cli(args: list[str], *, source: Path, config: Path, user: str = "yggdrasil-worker"):
    return role(
        "import sys; from yggdrasil_ids.cli import main; "
        f"sys.exit(main({args + ['--config', str(config)]!r}))",
        source=source,
        config=config,
        user=user,
    )


def json_result(result, message: str) -> dict:
    try:
        data = json.loads(result.stdout)
        if not isinstance(data, dict):
            raise ValueError
        return data
    except (ValueError, TypeError):
        raise ReleaseError(message) from None


def model_identity(source: Path, config: Path, *, expected: str | None = None) -> dict:
    code = """
import hashlib,json
from yggdrasil_ids.config import load_config
from yggdrasil_ids.ml import IsolationForestDetector
cfg=load_config()
before=hashlib.sha256(cfg.model_path.read_bytes()).hexdigest()
model=IsolationForestDetector.load(cfg.model_path)
if model.metadata['window_seconds'] != cfg.ml.window_seconds:
    raise RuntimeError('Model window differs')
if hashlib.sha256(cfg.model_path.read_bytes()).hexdigest() != before:
    raise RuntimeError('Model changed while loading')
print(json.dumps({'version':model.metadata['version'],'sha256':before}))
"""
    data = json_result(
        role(code, source=source, config=config), "SSH model identity could not be read"
    )
    if not re.fullmatch(r"ssh-if-[0-9a-f]{16}", data.get("version", "")) or not re.fullmatch(
        r"[0-9a-f]{64}", data.get("sha256", "")
    ):
        raise ReleaseError("Invalid SSH model identity")
    if expected is not None and data["version"] != expected:
        raise ReleaseError("SSH model differs from the explicitly reviewed production candidate")
    return data


def expected_legacy_overrides() -> dict[Path, bytes]:
    result = {}
    for unit in PRODUCTION:
        extra = "ReadOnlyPaths=/var/lib/yggdrasil-sudo-public\n" if unit == PRODUCTION[1] else ""
        result[UNIT_DIR / f"{unit}.d/60-sudo-integration.conf"] = (
            "[Service]\n# Coordinated sudo schema5 release for all production roles.\n"
            f"Environment=PYTHONPATH={LEGACY_INTEGRATION}/src\nEnvironment=PYTHONDONTWRITEBYTECODE=1\n"
            + extra
        ).encode()
    result[UNIT_DIR / "yggdrasil-web.service.d/70-nav-unread.conf"] = (
        f"[Service]\nEnvironment=PYTHONPATH={LEGACY_WEB}/src\nEnvironment=PYTHONDONTWRITEBYTECODE=1\n"
    ).encode()
    return result


def validate_service_accounts() -> None:
    journal_gid = grp.getgrnam("systemd-journal").gr_gid
    for user, group in (
        ("yggdrasil-worker", "yggdrasil-data"),
        ("yggdrasil-web", "yggdrasil-web"),
        ("yggdrasil-notifier", "yggdrasil-notifier"),
    ):
        account = pwd.getpwnam(user)
        if account.pw_uid == 0 or account.pw_gid != grp.getgrnam(group).gr_gid:
            raise ReleaseError("Service account identity differs: " + user)
        if user != "yggdrasil-worker" and journal_gid in os.getgrouplist(user, account.pw_gid):
            raise ReleaseError("Web/notifier accounts must not have journal membership")


def runtime_check() -> tuple[Path, bool]:
    validate_service_accounts()
    unified = CURRENT.is_symlink()
    if CURRENT.exists() and not unified:
        raise ReleaseError("Production source pointer must be a reviewed symlink")
    source = CURRENT.resolve() if unified else LEGACY_INTEGRATION
    if unified:
        if not source.is_relative_to(RELEASES) or not re.fullmatch(
            r"[0-9a-f]{40}", (source / "COMMIT").read_text().strip()
        ):
            raise ReleaseError("Unexpected existing release pointer")
    else:
        for directory, sha in (
            (LEGACY_INTEGRATION, "9ced7d60ab7b6776af95a12e83596683e04676ae"),
            (LEGACY_WEB, "614579ca2ab6fb246c363a8a95dc9a15a7135db3"),
        ):
            if (directory / "COMMIT").read_text().strip() != sha:
                raise ReleaseError("Legacy source release differs from the verified installation")
    expected = expected_legacy_overrides()
    for unit, user, group in zip(
        PRODUCTION,
        ("yggdrasil-worker", "yggdrasil-web", "yggdrasil-notifier"),
        ("yggdrasil-data", "yggdrasil-web", "yggdrasil-notifier"),
    ):
        info = properties(unit)
        environment = dict(
            item.split("=", 1) for item in shlex.split(info.get("Environment", "")) if "=" in item
        )
        path = (
            CURRENT / "src"
            if unified
            else (LEGACY_WEB if unit == PRODUCTION[1] else source) / "src"
        )
        if (
            info.get("ActiveState") != "active"
            or info.get("UnitFileState") != "enabled"
            or info.get("User") != user
            or info.get("Group") != group
            or environment.get("PYTHONPATH") != str(path)
        ):
            raise ReleaseError("Existing production role differs: " + unit)
        actual = set(shlex.split(info.get("DropInPaths", "")))
        wanted = set() if unified else {str(p) for p in expected if p.parent.name == unit + ".d"}
        if actual != wanted:
            raise ReleaseError("Unexpected source override for " + unit)
        for filename in (UNIT_DIR / (unit + ".d")).glob("*.conf"):
            if (
                unified
                or filename not in expected
                or filename.is_symlink()
                or filename.read_bytes() != expected[filename]
            ):
                raise ReleaseError("Unreviewed service override must be inspected before upgrade")
    timers = (SUDO_TIMER,) if unified else OLD_TIMERS
    for timer in timers:
        info = properties(timer)
        if info.get("ActiveState") != "active" or info.get("UnitFileState") != "enabled":
            raise ReleaseError("Existing sudo timer is not active and enabled: " + timer)
    return source, unified


def scalar(value) -> str:
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if type(value) is bool:
        return "true" if value else "false"
    if type(value) is int or type(value) is float and math.isfinite(value):
        return repr(value)
    if isinstance(value, list):
        return "[" + ", ".join(scalar(item) for item in value) + "]"
    raise ReleaseError("Unsupported existing configuration value")


def production_config(raw: bytes) -> bytes:
    data = tomllib.loads(raw.decode())
    if data.get("app", {}).get("mode", "live") != "live":
        raise ReleaseError("A live configuration is required")
    paths = data.setdefault("paths", {})
    for key, expected in (("database", DATABASE), ("model", MODEL)):
        if paths.get(key) != str(expected):
            raise ReleaseError("Expected the reviewed production " + key + " path")
    paths["sudo_database"] = str(SUDO_DATABASE)
    paths["sudo_public_directory"] = str(PUBLIC)
    data.setdefault("ml", {}).pop("alert_mode", None)
    data.setdefault("network", {})["enabled"] = True
    sudo = data.setdefault("sudo", {})
    sudo["enabled"] = True
    for key, value in (
        ("window_seconds", 300),
        ("failure_process_threshold", 3),
        ("cooldown_seconds", 300),
    ):
        sudo.setdefault(key, value)
    return (
        "# Consolidated production release; existing profiles and tuned thresholds preserved.\n"
        + "\n".join(
            "["
            + section
            + "]\n"
            + "\n".join(key + " = " + scalar(value) for key, value in values.items())
            + "\n"
            for section, values in data.items()
        )
    ).encode()


def atomic_file(path: Path, data: bytes, *, mode: int = 0o644, group: int | None = None) -> None:
    fd, temporary = tempfile.mkstemp(prefix=".yggdrasil-release-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fchmod(stream.fileno(), mode)
            if group is not None:
                os.fchown(stream.fileno(), 0, group)
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def source_files(source: Path) -> dict[str, str]:
    package = source / "src/yggdrasil_ids"
    files = {}
    for path in package.rglob("*"):
        if path.is_symlink():
            raise ReleaseError("Source snapshot contains symlinks")
        if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc":
            files[str(path.relative_to(source))] = hashlib.sha256(path.read_bytes()).hexdigest()
    if not files:
        raise ReleaseError("Pinned source package is empty")
    return files


def stage_release(source: Path, sha: str, config_bytes: bytes) -> Path:
    release = RELEASES / sha
    if (
        ROOT.is_symlink()
        or not ROOT.is_dir()
        or ROOT.stat().st_uid != os.geteuid()
        or RELEASES.is_symlink()
    ):
        raise ReleaseError("Public source directory ownership differs")
    RELEASES.mkdir(parents=True, exist_ok=True, mode=0o755)
    for directory in (ROOT, RELEASES):
        if (
            directory.is_symlink()
            or not directory.is_dir()
            or directory.stat().st_uid != os.geteuid()
        ):
            raise ReleaseError("Public source directory ownership differs")
        directory.chmod(0o755)
    if release.exists() or release.is_symlink():
        if (
            release.is_symlink()
            or (release / "COMMIT").read_text().strip() != sha
            or source_files(release) != source_files(source)
        ):
            raise ReleaseError("Release path already exists with different contents")
    else:
        release.mkdir(mode=0o755)
        shutil.copytree(
            source / "src", release / "src", ignore=shutil.ignore_patterns("__pycache__", "*.pyc")
        )
        for path in release.rglob("*"):
            path.chmod(0o755 if path.is_dir() else 0o644)
        (release / "COMMIT").write_text(sha + "\n")
        (release / "COMMIT").chmod(0o644)
    # mkdir's requested mode is reduced by the deployment's private umask.
    # Service accounts must traverse both new and interrupted release stages.
    release.chmod(0o755)
    atomic_file(
        release / "candidate-config.toml",
        config_bytes,
        mode=0o640,
        group=grp.getgrnam("yggdrasil-data").gr_gid,
    )
    return release


def check_dependencies(source: Path) -> None:
    expected = {}
    for line in (source / "requirements.lock").read_text().splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        match = re.fullmatch(r"([A-Za-z0-9_.-]+)==([A-Za-z0-9_.+-]+)", line.strip())
        if not match:
            raise ReleaseError("Unexpected locked dependency syntax")
        expected[match[1]] = match[2]
    code = "from importlib.metadata import version; expected=" + repr(expected) + "; "
    code += "assert all(version(name)==value for name,value in expected.items())"
    command([str(PYTHON), "-c", code])


def check_candidate(release: Path, model: dict, *, require_ready: bool = False) -> None:
    config = CONFIG if require_ready else release / "candidate-config.toml"
    common = (
        "from pathlib import Path; from yggdrasil_ids.config import load_config; "
        "from yggdrasil_ids.storage import Repository; import yggdrasil_ids.storage as storage; cfg=load_config(); "
        f"assert Path(storage.__file__).resolve()==Path({str(release / 'src/yggdrasil_ids/storage.py')!r}); "
        "assert storage.SCHEMA_VERSION==5 and cfg.mode=='live' and cfg.network.enabled and cfg.sudo.enabled; "
        "assert getattr(cfg.ml,'alert_mode','alert')=='alert'; "
        "assert cfg.web.bind=='127.0.0.1' and cfg.web.port==8765; "
        f"assert cfg.database_path==Path({str(DATABASE)!r}); "
    )
    worker = common + (
        "from yggdrasil_ids.ml import IsolationForestDetector; model=IsolationForestDetector.load(cfg.model_path); "
        f"assert model.metadata['version']=={model['version']!r}; "
        "assert model.metadata['window_seconds']==cfg.ml.window_seconds; "
    )
    if require_ready:
        worker += "from yggdrasil_ids.cli import doctor; assert doctor(cfg,role='collector',require_ready=True)['ok']; "
    role(worker, source=release, config=config)
    web = (
        common
        + "from yggdrasil_ids.web import create_app; import time,os; app=create_app(cfg); client=app.test_client(); "
    )
    web += "assert client.get('/sudo').status_code==302 and client.get('/api/nav-alerts').status_code==401; "
    web += "with_context=client.session_transaction(); session=with_context.__enter__(); session['authenticated']=True; session['authenticated_at']=time.time(); with_context.__exit__(None,None,None); "
    web += "assert all(client.get(p).status_code==200 for p in ('/sudo','/events','/preauth','/network','/model','/status','/alerts')); "
    web += "assert client.get('/api/nav-alerts').get_json()['meaning']=='browser_unseen_alert_revisions_v1'; "
    web += f"assert not os.access({str(SUDO_DATABASE)!r},os.R_OK); "
    role(web, source=release, config=config, user="yggdrasil-web")
    role(
        common + "from yggdrasil_ids.notify import DiscordNotifier; ",
        source=release,
        config=config,
        user="yggdrasil-notifier",
    )


def backup_database(source: Path, target: Path) -> None:
    if target.exists():
        raise ReleaseError("Database backup target already exists")
    with closing(readonly(source)) as db, sqlite3.connect(target) as copy:
        db.backup(copy)
        if copy.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            raise ReleaseError("SQLite backup integrity check failed")
    target.chmod(0o600)


def entrypoint() -> bytes:
    return (
        "#!/bin/sh\nexport PYTHONPATH=/opt/yggdrasil-ids/current/src\n"
        "export PYTHONDONTWRITEBYTECODE=1\n"
        'exec /opt/yggdrasil-ids/venv/bin/python -m yggdrasil_ids "$@"\n'
    ).encode()


def save_before(backup: Path, *, identity: dict, model: dict) -> dict:
    backup.mkdir(parents=True, mode=0o700)
    paths = {"config": CONFIG, "entrypoint": ENTRYPOINT}
    for unit in (*UNITS, *OLD_TIMERS, *OLD_SERVICES):
        paths["unit-" + unit] = UNIT_DIR / unit
    for index, path in enumerate(expected_legacy_overrides()):
        paths["override-" + str(index)] = path
    for name in ("sudo-status.json", "sudo-activity.json", "sudo-integration.json"):
        paths["public-" + name] = PUBLIC / name
    manifest = {
        "format": "production-release-backup-v1",
        "current": str(CURRENT.readlink()) if CURRENT.is_symlink() else None,
        "identity": identity,
        "model": model,
        "files": {},
        "states": {},
    }
    for key, path in paths.items():
        if path.is_symlink():
            raise ReleaseError("Unexpected symlink in a production configuration path")
        if path.exists():
            info = path.stat()
            if not stat.S_ISREG(info.st_mode):
                raise ReleaseError("Expected regular production configuration file")
            (backup / key).write_bytes(path.read_bytes())
            (backup / key).chmod(0o600)
            manifest["files"][key] = {
                "path": str(path),
                "mode": stat.S_IMODE(info.st_mode),
                "uid": info.st_uid,
                "gid": info.st_gid,
            }
        else:
            manifest["files"][key] = {"path": str(path), "absent": True}
    for unit in (*PRODUCTION, SUDO_TIMER, *OLD_TIMERS):
        manifest["states"][unit] = {
            key: properties(unit).get(key, "") for key in ("ActiveState", "UnitFileState")
        }
    atomic_file(backup / "manifest.json", json.dumps(manifest, indent=2).encode(), mode=0o600)
    return manifest


def stop_roles() -> None:
    timers = [
        unit
        for unit in (*OLD_TIMERS, SUDO_TIMER)
        if properties(unit).get("LoadState") != "not-found"
    ]
    if timers:
        command(["systemctl", "disable", "--now", *timers])
    services = [
        unit
        for unit in (*OLD_SERVICES, SUDO_SERVICE)
        if properties(unit).get("LoadState") != "not-found"
    ]
    if services:
        command(["systemctl", "stop", *services])
    command(["systemctl", "stop", *PRODUCTION])
    for unit in (*timers, *services, *PRODUCTION):
        if properties(unit).get("ActiveState") not in {"inactive", "failed"}:
            raise ReleaseError("A writer did not stop: " + unit)


def install_pointer(release: Path) -> None:
    temporary = ROOT / ".current-release"
    if temporary.exists() or temporary.is_symlink():
        raise ReleaseError("Temporary production source pointer already exists")
    temporary.symlink_to(release)
    os.replace(temporary, CURRENT)


def copy_sudo_database(source: Path) -> None:
    if source == SUDO_DATABASE:
        return
    if SUDO_DATABASE.exists() or SUDO_DATABASE.is_symlink():
        raise ReleaseError("New private sudo database already exists; inspect before copying")
    folder = SUDO_DATABASE.parent
    uid, gid = pwd.getpwnam("yggdrasil-worker").pw_uid, grp.getgrnam("yggdrasil-data").gr_gid
    if folder.is_symlink():
        raise ReleaseError("Private sudo directory must not be a symlink")
    if folder.exists():
        info = folder.stat()
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != uid
            or stat.S_IMODE(info.st_mode) != 0o700
        ):
            raise ReleaseError("Existing private sudo directory ownership differs")
    else:
        folder.mkdir(mode=0o700, parents=True)
        os.chown(folder, uid, gid)
    temporary = folder / ".sudo-copy.sqlite3"
    try:
        backup_database(source, temporary)
        os.chown(temporary, uid, gid)
        os.replace(temporary, SUDO_DATABASE)
    finally:
        temporary.unlink(missing_ok=True)


def replace_runtime(source: Path, release: Path) -> None:
    install_pointer(release)
    atomic_file(
        CONFIG,
        (release / "candidate-config.toml").read_bytes(),
        mode=0o640,
        group=grp.getgrnam("yggdrasil-data").gr_gid,
    )
    for unit in UNITS:
        atomic_file(UNIT_DIR / unit, (source / "deploy" / unit).read_bytes())
    for path in expected_legacy_overrides():
        path.unlink(missing_ok=True)
    atomic_file(ENTRYPOINT, entrypoint(), mode=0o755)
    command(["systemd-analyze", "verify", *(str(UNIT_DIR / unit) for unit in UNITS)])
    command(["systemctl", "daemon-reload"])


def start_roles() -> None:
    command(["systemctl", "enable", "--now", *PRODUCTION, SUDO_TIMER])


def acceptance(release: Path, model: dict, *, not_before: float, previous: dict) -> dict:
    deadline = time.monotonic() + 180
    print(
        "Waiting for fresh collector and sudo timer results; no test attack or notification is generated.",
        flush=True,
    )
    while True:
        check = role(
            "import json; from yggdrasil_ids.sudo_integration_dashboard import read_integration; "
            "x=read_integration(); "
            f"assert x['state']=='ready' and x['rules_active'] and x['generated_at']>={not_before!r}; "
            "print(json.dumps({'sudo_rules_active':True,'sudo_generated_at':x['generated_at']}))",
            source=release,
            config=CONFIG,
            user="yggdrasil-web",
            check=False,
        )
        try:
            if check.returncode == 0:
                check_candidate(release, model, require_ready=True)
                role(
                    "from yggdrasil_ids.storage import Repository; from yggdrasil_ids.config import load_config; "
                    "status=Repository(load_config().database_path,readonly=True).status(); "
                    f"assert status['collector']['heartbeat_at']>={not_before!r}",
                    source=release,
                    config=CONFIG,
                )
                break
        except (ReleaseError, OSError):
            pass
        if time.monotonic() >= deadline:
            raise ReleaseError("Fresh full production acceptance did not complete")
        time.sleep(3)
    for unit in (*PRODUCTION, SUDO_TIMER):
        info = properties(unit)
        if info.get("ActiveState") != "active" or info.get("UnitFileState") != "enabled":
            raise ReleaseError("A required production component is not active: " + unit)
    for unit in OLD_TIMERS:
        if properties(unit).get("ActiveState") == "active":
            raise ReleaseError("A retired sudo timer is still active")
    require_identity(previous)
    with urlopen("http://127.0.0.1:8765/login", timeout=5) as response:
        if response.status != 200 or b"Yggdrasil" not in response.read(16384):
            raise ReleaseError("HTTP login page unavailable")
    return json_result(check, "Sudo acceptance result could not be verified")


def recover(backup: Path) -> None:
    """Restore source/config/units, never production DB or notifier delivery DB."""
    manifest = json.loads((backup / "manifest.json").read_text())
    atomic_file(backup / "RECOVERING", (str(time.time()) + "\n").encode(), mode=0o600)
    stop_roles()
    if manifest["current"] is None and SUDO_DATABASE.exists():
        # A failed legacy upgrade may already have collected new normalized
        # rows. Carry those forward to the compatible old private store, then
        # preserve the new private directory in the backup so retry is possible.
        temporary = OLD_SUDO_DATABASE.parent / ".production-recovery.sqlite3"
        try:
            backup_database(SUDO_DATABASE, temporary)
            with closing(readonly(temporary)) as db:
                if db.execute("PRAGMA user_version").fetchone()[0] != 2:
                    raise ReleaseError("Private sudo recovery requires compatible schema2")
            info = OLD_SUDO_DATABASE.stat()
            os.chown(temporary, info.st_uid, info.st_gid)
            os.replace(temporary, OLD_SUDO_DATABASE)
            quarantine = backup / "retired-production-sudo-state"
            if quarantine.exists():
                raise ReleaseError("Private sudo recovery archive already exists")
            shutil.move(str(SUDO_DATABASE.parent), quarantine)
        finally:
            temporary.unlink(missing_ok=True)
    for key, info in manifest["files"].items():
        path = Path(info["path"])
        if info.get("absent"):
            path.unlink(missing_ok=True)
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            atomic_file(path, (backup / key).read_bytes(), mode=info["mode"])
            os.chown(path, info["uid"], info["gid"])
    previous = manifest["current"]
    if previous is None:
        CURRENT.unlink(missing_ok=True)
    else:
        install_pointer(Path(previous))
    command(["systemctl", "daemon-reload"])
    for unit, state in manifest["states"].items():
        if state["UnitFileState"] == "enabled":
            command(["systemctl", "enable", unit])
        if state["ActiveState"] == "active":
            command(["systemctl", "start", unit])
    require_identity(manifest["identity"])
    atomic_file(backup / "RECOVERED", (str(time.time()) + "\n").encode(), mode=0o600)
    (backup / "RECOVERING").unlink(missing_ok=True)
    print(
        "RECOVERY: previous source/config/services restored; current alarm and notifier history preserved",
        flush=True,
    )


def upgrade(source: Path, sha: str) -> dict:
    backup = BACKUPS / ("production-before-" + sha)
    if (backup / "RECOVERING").is_file():
        manifest = json.loads((backup / "manifest.json").read_text())
        current = str(CURRENT.readlink()) if CURRENT.is_symlink() else None
        if current not in {str(RELEASES / sha), manifest["current"]}:
            raise ReleaseError("Interrupted recovery source pointer changed")
        recover(backup)
    if CURRENT.is_symlink() and (CURRENT / "COMMIT").read_text().strip() == sha:
        release = CURRENT.resolve()
        if source_files(release) != source_files(source):
            raise ReleaseError("Active release source differs from the pinned snapshot")
        backup = BACKUPS / ("production-before-" + sha)
        if not (release / "ACCEPTED.json").exists():
            manifest = json.loads((backup / "manifest.json").read_text())
            if SUDO_DATABASE.parent.is_symlink():
                raise ReleaseError("Interrupted release private directory is linked")
            with closing(readonly(SUDO_DATABASE)) as db:
                if db.execute("PRAGMA user_version").fetchone()[0] != 2:
                    raise ReleaseError(
                        "Interrupted release private sudo state is missing or invalid"
                    )
            if CONFIG.read_bytes() != (release / "candidate-config.toml").read_bytes():
                raise ReleaseError("Interrupted release configuration was modified")
            for unit in UNITS:
                if (UNIT_DIR / unit).read_bytes() != (source / "deploy" / unit).read_bytes():
                    raise ReleaseError("Interrupted release unit needs review")
            model = model_identity(release, CONFIG)
            if model != manifest["model"]:
                raise ReleaseError("Interrupted release model changed")
            require_identity(manifest["identity"])
            command(["systemctl", "daemon-reload"])
            started = time.time()
            start_roles()
            report = acceptance(release, model, not_before=started, previous=manifest["identity"])
            atomic_file(
                release / "ACCEPTED.json",
                json.dumps(
                    {"sha": sha, "accepted_at": time.time(), "ssh_model": model["version"]}
                ).encode(),
            )
            return {"status": "ready", "release": sha, "resumed": True, **report}
        runtime_check()
        model = model_identity(release, CONFIG)
        identity = database_identity()
        report = acceptance(release, model, not_before=0, previous=identity)
        return {"status": "ready", "release": sha, "already_active": True, **report}
    previous_source, unified = runtime_check()
    if not unified and (SUDO_DATABASE.exists() or SUDO_DATABASE.is_symlink()):
        raise ReleaseError("Canonical private sudo state already exists outside a unified release")
    check_private_source(SUDO_DATABASE if unified else OLD_SUDO_DATABASE)
    identity = database_identity()
    old_config = CONFIG.read_bytes()
    candidate_config = production_config(old_config)
    expected_model = None if unified else EXPECTED_MODEL_VERSION
    model = model_identity(previous_source, CONFIG, expected=expected_model)
    if identity["model_version"] != model["version"]:
        raise ReleaseError("Recorded SSH model identity differs from the reviewed artifact")
    release = stage_release(source, sha, candidate_config)
    check_dependencies(source)
    if model_identity(release, release / "candidate-config.toml") != model:
        raise ReleaseError("Candidate would change the existing SSH model")
    check_candidate(release, model)
    backup = BACKUPS / ("production-before-" + sha)
    if backup.exists():
        if not (backup / "RECOVERED").is_file():
            raise ReleaseError(
                "Release backup already exists; review recovery rather than overwrite it"
            )
        archive = BACKUPS / ("production-recovered-" + sha + "-" + str(time.time_ns()))
        backup.rename(archive)
    BACKUPS.mkdir(parents=True, exist_ok=True, mode=0o700)
    save_before(backup, identity=identity, model=model)
    changed = False
    try:
        if CONFIG.read_bytes() != old_config:
            raise ReleaseError("Configuration changed during preparation")
        print("Stopping the existing writers together and backing up schema5...", flush=True)
        changed = True
        stop_roles()
        backup_database(DATABASE, backup / "events-schema5.sqlite3")
        if model_identity(previous_source, CONFIG) != model:
            raise ReleaseError("SSH model changed during release preparation")
        copy_sudo_database(SUDO_DATABASE if unified else OLD_SUDO_DATABASE)
        replace_runtime(source, release)
        # Upgrade must preserve the existing activation, not repair/rearm it.
        require_identity(identity)
        started = time.time()
        start_roles()
        report = acceptance(release, model, not_before=started, previous=identity)
        require_identity(identity)
        for unit in (*OLD_TIMERS, *OLD_SERVICES):
            (UNIT_DIR / unit).unlink(missing_ok=True)
        command(["systemctl", "daemon-reload"])
        atomic_file(
            release / "ACCEPTED.json",
            json.dumps(
                {
                    "sha": sha,
                    "accepted_at": time.time(),
                    "ssh_model": model["version"],
                    "ssh_model_sha256": model["sha256"],
                }
            ).encode(),
        )
        return {
            "status": "ready",
            "release": sha,
            "ssh_model": model["version"],
            "ssh_ml_alerts_enabled": True,
            "portscan_rules_enabled": True,
            **report,
            "notifier_identity_preserved": True,
            "model_retrained": False,
            "test_attack_generated": False,
            "new_discord_delivery_claimed": False,
        }
    except BaseException:
        if changed:
            recover(backup)
        raise


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("upgrade", "rollback"))
    parser.add_argument("--source", type=Path)
    parser.add_argument("--sha", required=True)
    args = parser.parse_args()
    if os.geteuid() != 0 or not re.fullmatch(r"[0-9a-f]{40}", args.sha):
        parser.exit(2, "STOP: use the pinned production wrapper\n")
    os.umask(0o077)
    lock_fd = os.open(
        "/run/lock/yggdrasil-production-release.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600
    )
    try:
        info = os.fstat(lock_fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != 0
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_nlink != 1
        ):
            raise ReleaseError("Invalid deployment lock ownership")
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if args.action == "rollback":
            backup = BACKUPS / ("production-before-" + args.sha)
            manifest = json.loads((backup / "manifest.json").read_text())
            current = str(CURRENT.readlink()) if CURRENT.is_symlink() else None
            matches_release = (
                CURRENT.is_symlink() and (CURRENT / "COMMIT").read_text().strip() == args.sha
            )
            if not matches_release and current != manifest["current"]:
                raise ReleaseError("Rollback SHA differs from the active release")
            recover(backup)
            return
        if args.source is None:
            raise ReleaseError("Pinned source tree required")
        result = upgrade(args.source, args.sha)
        print(json.dumps(result, indent=2))
        print("PASS: production SSH rules + ML, portscan rules, sudo rules and unified dashboard")
    except (OSError, ValueError, RuntimeError, sqlite3.Error, subprocess.SubprocessError) as exc:
        reason = str(exc) if isinstance(exc, ReleaseError) else type(exc).__name__
        parser.exit(1, "STOP: " + reason + "\n")
    finally:
        os.close(lock_fd)


if __name__ == "__main__":
    main()
