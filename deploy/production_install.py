#!/usr/bin/env python3
"""First production installation using a caller-reviewed SSH model, never lab data.

An interrupted installation can resume only with its recorded SHA and exact
model bytes. Existing configured installations must use upgrade_pi.sh instead.
"""

from __future__ import annotations

import argparse
import fcntl
import grp
import hashlib
import json
import os
import pwd
import re
import sqlite3
import stat
import subprocess
import time
from pathlib import Path

import production_upgrade as release


def owned_directory(path: Path, user: str, group: str, mode: int) -> None:
    if path.is_symlink():
        raise release.ReleaseError("Installation directory is a symlink")
    path.mkdir(parents=True, exist_ok=True, mode=mode)
    if not path.is_dir():
        raise release.ReleaseError("Expected an installation directory")
    os.chown(path, pwd.getpwnam(user).pw_uid, grp.getgrnam(group).gr_gid)
    path.chmod(mode)


def ensure_accounts() -> None:
    for group in ("yggdrasil-data", "yggdrasil-web", "yggdrasil-notifier"):
        try:
            grp.getgrnam(group)
        except KeyError:
            release.command(["groupadd", "--system", group])
    for user, group, supplementary, home in (
        ("yggdrasil-worker", "yggdrasil-data", "systemd-journal", "/var/lib/yggdrasil-ids"),
        ("yggdrasil-web", "yggdrasil-web", "yggdrasil-data", "/nonexistent"),
        (
            "yggdrasil-notifier",
            "yggdrasil-notifier",
            "yggdrasil-data",
            "/var/lib/yggdrasil-notifier",
        ),
    ):
        try:
            account = pwd.getpwnam(user)
        except KeyError:
            release.command(
                [
                    "useradd",
                    "--system",
                    "--gid",
                    group,
                    "--groups",
                    supplementary,
                    "--home-dir",
                    home,
                    "--no-create-home",
                    "--shell",
                    "/usr/sbin/nologin",
                    user,
                ]
            )
            account = pwd.getpwnam(user)
        if account.pw_gid != grp.getgrnam(group).gr_gid or account.pw_shell not in {
            "/usr/sbin/nologin",
            "/sbin/nologin",
        }:
            raise release.ReleaseError("Existing service account has unexpected identity or shell")
        release.command(["usermod", "--append", "--groups", supplementary, user])
    release.validate_service_accounts()


def check_root() -> None:
    if release.ROOT.is_symlink():
        raise release.ReleaseError("Installation root must not be a symlink")
    if release.ROOT.exists():
        info = release.ROOT.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise release.ReleaseError("Installation root must be root-owned and protected")


def fresh_guard(sha: str, model: Path) -> tuple[Path, dict]:
    check_root()
    if model.is_symlink() or not model.is_file() or model.stat().st_size > 8 * 1024 * 1024:
        raise release.ReleaseError("A regular, reviewed SSH model JSON file is required")
    identity = {"sha": sha, "model_sha256": hashlib.sha256(model.read_bytes()).hexdigest()}
    marker = release.ROOT / "INSTALLING.json"
    if marker.exists() or marker.is_symlink():
        info = marker.lstat()
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != 0
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_nlink != 1
            or info.st_size > 4096
        ):
            raise release.ReleaseError("Installation resume marker is not protected")
        if json.loads(marker.read_text()) != identity:
            raise release.ReleaseError("Installation resume SHA or model differs")
        if (release.CURRENT.exists() or release.CURRENT.is_symlink()) and (
            not release.CURRENT.is_symlink() or release.CURRENT.resolve() != release.RELEASES / sha
        ):
            raise release.ReleaseError("Installation resume source pointer changed")
        return marker, identity
    forbidden = [
        release.CONFIG,
        release.DATABASE,
        release.DELIVERY,
        release.CURRENT,
        release.MODEL,
        release.SUDO_DATABASE,
        release.OLD_SUDO_DATABASE,
        release.ENTRYPOINT,
        release.ROOT / "venv",
        release.CONFIG.parent / "web-secrets.json",
    ]
    forbidden.extend(
        release.UNIT_DIR / unit
        for unit in (*release.UNITS, *release.OLD_SERVICES, *release.OLD_TIMERS)
    )
    forbidden.extend(release.expected_legacy_overrides())
    if any(path.exists() or path.is_symlink() for path in forbidden):
        raise release.ReleaseError("Existing installation detected; use the coordinated upgrade")
    return marker, identity


def check_discord_credential() -> None:
    path = release.CONFIG.parent / "discord-webhook.url"
    info = path.lstat()
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != 0
        or stat.S_IMODE(info.st_mode) != 0o600
        or not 20 <= info.st_size <= 1024
    ):
        raise release.ReleaseError(
            "Provision a root-owned 0600 Discord webhook file before installation"
        )
    # Contents are consumed only by the existing systemd LoadCredential path.


def create_credentials(source: Path) -> None:
    # Keep getpass connected to the terminal; never capture, log or place a
    # password on argv. This is the only interactive installation step.
    env = {
        **release.ENVIRONMENT,
        "PYTHONPATH": str(source / "src"),
        "PYTHONDONTWRITEBYTECODE": "1",
        "YGGDRASIL_CONFIG": str(release.CONFIG),
    }
    subprocess.run(
        [
            str(release.PYTHON),
            "-m",
            "yggdrasil_ids",
            "credentials",
            "--config",
            str(release.CONFIG),
        ],
        check=True,
        env=env,
        cwd=release.ROOT,
    )
    finalize_credentials()


def finalize_credentials() -> None:
    credential = release.CONFIG.parent / "web-secrets.json"
    info = credential.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1:
        raise release.ReleaseError("Dashboard credential file ownership or type differs")
    os.chown(credential, 0, grp.getgrnam("yggdrasil-web").gr_gid)
    credential.chmod(0o640)


def publish_venv_code() -> None:
    """Make fresh public dependency code readable without following symlinks."""
    directory = release.ROOT / "venv"
    if directory.is_symlink() or not directory.is_dir():
        raise release.ReleaseError("Expected the installer-owned Python environment")
    for path in (directory, *directory.rglob("*")):
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode):
            continue
        if info.st_uid != os.geteuid() or not (
            stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)
        ):
            raise release.ReleaseError("Unexpected Python environment file ownership or type")
        path.chmod(0o755 if stat.S_ISDIR(info.st_mode) or info.st_mode & 0o111 else 0o644)


def stop_owned_setup() -> None:
    release.command(
        ["systemctl", "disable", "--now", *release.PRODUCTION, release.SUDO_TIMER], check=False
    )
    release.command(["systemctl", "stop", release.SUDO_SERVICE, *release.PRODUCTION], check=False)
    for unit in (*release.PRODUCTION, release.SUDO_SERVICE, release.SUDO_TIMER):
        info = release.properties(unit)
        if info.get("LoadState") != "not-found" and info.get("ActiveState") not in {
            "inactive",
            "failed",
        }:
            raise release.ReleaseError("Partially installed service did not stop: " + unit)


def install_owned(source: Path, sha: str, model: Path, marker: Path, identity: dict) -> dict:
    ensure_accounts()
    owned_directory(release.DATABASE.parent, "yggdrasil-worker", "yggdrasil-data", 0o2750)
    owned_directory(release.CONFIG.parent, "root", "yggdrasil-data", 0o750)
    owned_directory(release.SUDO_DATABASE.parent, "yggdrasil-worker", "yggdrasil-data", 0o700)
    owned_directory(release.PUBLIC, "yggdrasil-worker", "yggdrasil-data", 0o750)
    owned_directory(release.DELIVERY.parent, "yggdrasil-notifier", "yggdrasil-notifier", 0o700)
    if not release.PYTHON.exists():
        release.command(["/usr/bin/python3", "-m", "venv", str(release.ROOT / "venv")])
    print("Installing only the release-locked Python dependencies...", flush=True)
    release.command(
        [
            str(release.PYTHON),
            "-m",
            "pip",
            "install",
            "--disable-pip-version-check",
            "--only-binary=:all:",
            "-r",
            str(source / "requirements.lock"),
        ],
        timeout=600,
    )
    publish_venv_code()
    release.check_dependencies(source)
    config_bytes = (
        release.CONFIG.read_bytes()
        if release.CONFIG.exists()
        else (source / "deploy/config.pi.toml").read_bytes()
    )
    staged = release.stage_release(source, sha, release.production_config(config_bytes))
    if release.MODEL.exists():
        if hashlib.sha256(release.MODEL.read_bytes()).hexdigest() != identity["model_sha256"]:
            raise release.ReleaseError("Installation model changed while resuming")
    else:
        raw_model = model.read_bytes()
        if (
            len(raw_model) > 8 * 1024 * 1024
            or hashlib.sha256(raw_model).hexdigest() != identity["model_sha256"]
        ):
            raise release.ReleaseError("Reviewed source model changed during installation")
        release.atomic_file(release.MODEL, raw_model, mode=0o400)
        os.chown(
            release.MODEL,
            pwd.getpwnam("yggdrasil-worker").pw_uid,
            grp.getgrnam("yggdrasil-data").gr_gid,
        )
    # Finalize both branches: power loss could have happened between creating
    # the reviewed bytes and assigning the worker ownership on the prior run.
    if release.MODEL.is_symlink() or not release.MODEL.is_file():
        raise release.ReleaseError("Reviewed model path is not a regular file")
    os.chown(
        release.MODEL,
        pwd.getpwnam("yggdrasil-worker").pw_uid,
        grp.getgrnam("yggdrasil-data").gr_gid,
    )
    release.MODEL.chmod(0o400)
    trained = release.model_identity(staged, staged / "candidate-config.toml")
    if trained["sha256"] != identity["model_sha256"]:
        raise release.ReleaseError("Reviewed model identity changed during installation")
    release.atomic_file(
        release.CONFIG,
        (staged / "candidate-config.toml").read_bytes(),
        mode=0o640,
        group=grp.getgrnam("yggdrasil-data").gr_gid,
    )
    if not (release.CONFIG.parent / "web-secrets.json").exists():
        create_credentials(staged)
    # Also completes an interrupted credentials CLI/chown sequence without
    # rotating the existing password or session key.
    finalize_credentials()
    if not release.DATABASE.exists():
        release.role_cli(["init"], source=staged, config=release.CONFIG)
    # Bootstrap is allowed ONLY for this independently guarded fresh setup and
    # only while no receipt DB exists. A resume never resets its watermark.
    if not release.DELIVERY.exists():
        release.role_cli(
            ["notify", "--state-file", str(release.DELIVERY), "--bootstrap"],
            source=staged,
            config=release.CONFIG,
            user="yggdrasil-notifier",
        )
    baseline = release.database_identity(require_activation=False)
    release.role_cli(["sudo-arm"], source=staged, config=release.CONFIG)
    baseline = release.database_identity()
    release.check_candidate(staged, trained)
    # No legacy timer or override exists on the guarded first install.
    if not release.CURRENT.is_symlink():
        release.install_pointer(staged)
    elif release.CURRENT.resolve() != staged:
        raise release.ReleaseError("Installation source pointer changed")
    release.UNIT_DIR.mkdir(parents=True, exist_ok=True)
    for unit in release.UNITS:
        release.atomic_file(release.UNIT_DIR / unit, (source / "deploy" / unit).read_bytes())
    release.atomic_file(release.ENTRYPOINT, release.entrypoint(), mode=0o755)
    release.command(
        ["systemd-analyze", "verify", *(str(release.UNIT_DIR / unit) for unit in release.UNITS)]
    )
    release.command(["systemctl", "daemon-reload"])
    started = time.time()
    release.start_roles()
    result = release.acceptance(staged, trained, not_before=started, previous=baseline)
    release.atomic_file(
        staged / "ACCEPTED.json",
        json.dumps(
            {
                "sha": sha,
                "accepted_at": time.time(),
                "ssh_model": trained["version"],
                "fresh_install": True,
            }
        ).encode(),
    )
    marker.unlink()
    return {
        "status": "ready",
        "release": sha,
        "fresh_install": True,
        "ssh_model": trained["version"],
        "model_retrained": False,
        "test_attack_generated": False,
        **result,
    }


def install(source: Path, sha: str, model: Path) -> dict:
    marker, identity = fresh_guard(sha, model)
    check_discord_credential()
    release.ROOT.mkdir(parents=True, exist_ok=True, mode=0o755)
    release.ROOT.chmod(0o755)
    resuming = marker.exists()
    release.atomic_file(marker, json.dumps(identity).encode(), mode=0o600)
    try:
        if resuming:
            # A power loss could leave previously started roles running. Stop
            # only this marker-owned setup before dependency/config mutation.
            stop_owned_setup()
        return install_owned(source, sha, model, marker, identity)
    except BaseException:
        # Only reached after the guarded fresh marker was created/verified.
        # Never stop an unrelated existing installation on a guard rejection.
        stop_owned_setup()
        raise


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--sha", required=True)
    parser.add_argument("--reviewed-model", type=Path, required=True)
    args = parser.parse_args()
    if os.geteuid() != 0 or not re.fullmatch(r"[0-9a-f]{40}", args.sha):
        parser.exit(2, "STOP: use the pinned first-install wrapper\n")
    os.umask(0o077)
    lock = os.open(
        "/run/lock/yggdrasil-production-release.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600
    )
    try:
        info = os.fstat(lock)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != 0
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_nlink != 1
        ):
            raise release.ReleaseError("Invalid deployment lock ownership")
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        result = install(args.source, args.sha, args.reviewed_model)
        print(json.dumps(result, indent=2))
        print("PASS: fresh production installation; verify a new real SSH login separately")
    except (OSError, ValueError, RuntimeError, sqlite3.Error, subprocess.SubprocessError) as exc:
        reason = str(exc) if isinstance(exc, release.ReleaseError) else type(exc).__name__
        parser.exit(1, "STOP: " + reason + "; installation files retained for a matching retry\n")
    finally:
        os.close(lock)


if __name__ == "__main__":
    main()
