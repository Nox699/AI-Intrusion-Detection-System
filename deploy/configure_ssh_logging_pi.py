#!/usr/bin/env python3
"""Explicitly enable SSH key-rejection logging; never generate authentication attempts."""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import shlex
import socket
import subprocess
from pathlib import Path

ACCEPTED = Path("/opt/yggdrasil-ids/current/ACCEPTED.json")
DROPIN = Path("/etc/ssh/sshd_config.d/00-yggdrasil-ids-logging.conf")
PROC = Path("/proc")
SSHD = "/usr/sbin/sshd"
CONTENT = b"# Explicit Yggdrasil IDS key-rejection logging.\nLogLevel VERBOSE\n"


class LoggingError(RuntimeError):
    pass


def run(args: list[str]) -> str:
    try:
        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=20,
            cwd="/",
            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"},
        )
    except subprocess.SubprocessError as exc:
        raise LoggingError("Command could not complete: " + " ".join(args[:2])) from exc
    if result.returncode:
        raise LoggingError("Command failed: " + " ".join(args[:2]))
    return result.stdout


def check_daemon() -> None:
    output = run(["systemctl", "show", "ssh.service", "-p", "ActiveState", "-p", "MainPID"])
    properties = dict(line.split("=", 1) for line in output.splitlines() if "=" in line)
    pid = properties.get("MainPID", "")
    if properties.get("ActiveState") != "active" or not pid.isdecimal() or int(pid) < 2:
        raise LoggingError("The regular ssh.service is not active")
    process = PROC / pid
    if (process / "exe").resolve(strict=True) != Path(SSHD).resolve(strict=True):
        raise LoggingError("The SSH listener executable is unexpected")
    title = (process / "cmdline").read_bytes().replace(b"\0", b" ").decode().strip()
    title = title.removeprefix("sshd: ").split("[listener]", 1)[0].strip()
    args = shlex.split(title)
    if not args or args[0] != SSHD or args[1:] != ["-D"]:
        raise LoggingError("The SSH listener has unreviewed command-line options")


def ignored_client(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    output = run(["fail2ban-client", "get", "sshd", "ignoreip"])
    for token in output.split():
        try:
            network = ipaddress.ip_network(token.strip("[](),;'\"|`+-─├└"), strict=False)
        except ValueError:
            continue
        if address.version == network.version and address in network:
            return True
    return False


def effective(context: str) -> tuple[str, ...]:
    return tuple(sorted(run([SSHD, "-T", "-C", context]).splitlines()))


def setting(lines: tuple[str, ...], name: str) -> str:
    values = [line.split(None, 1)[1] for line in lines if line.startswith(name + " ")]
    if len(values) != 1:
        raise LoggingError("Missing or repeated SSH setting: " + name)
    return values[0]


def configure(connection: str, expected_release: str) -> dict:
    if os.geteuid() != 0 or socket.gethostname() != "yggdrasil":
        raise LoggingError("Run through sudo on Yggdrasil")
    if not re.fullmatch(r"[0-9a-f]{40}", expected_release):
        raise LoggingError("Expected a full reviewed release SHA")
    accepted = json.loads(ACCEPTED.read_text())
    if not isinstance(accepted, dict) or accepted.get("sha") != expected_release:
        raise LoggingError("The accepted application release does not match")
    fields = connection.split()
    if len(fields) != 4:
        raise LoggingError("Run from the laptop's current SSH session")
    client, client_port, local, local_port = fields
    peer, server = ipaddress.ip_address(client), ipaddress.ip_address(local)
    if peer.version != server.version or not all(
        value.isdecimal() and 1 <= int(value) <= 65535 for value in (client_port, local_port)
    ):
        raise LoggingError("Invalid SSH connection metadata")
    if not ignored_client(peer):
        raise LoggingError("The current laptop address is not exempted in Fail2ban's sshd jail")
    check_daemon()
    context = f"user=vidar,addr={peer},laddr={server},lport={local_port}"
    run([SSHD, "-t"])
    before = effective(context)
    for name, expected in (
        ("passwordauthentication", "no"),
        ("kbdinteractiveauthentication", "no"),
        ("pubkeyauthentication", "yes"),
    ):
        if setting(before, name) != expected:
            raise LoggingError("Unexpected key-only SSH setting: " + name)
    level = setting(before, "loglevel")
    if level not in {"INFO", "VERBOSE"}:
        raise LoggingError("Unexpected existing SSH log level")
    report = {
        "format": "ssh-logging-readiness-v1",
        "status": "ready",
        "release": expected_release,
        "loglevel": "VERBOSE",
        "key_only_authentication_preserved": True,
        "dropin_created": False,
        "ssh_reloaded": False,
        "test_attempt_generated": False,
        "live_key_rejection_verified": False,
    }
    if level == "VERBOSE":
        return report
    created = reload_attempted = write_completed = False
    created_identity = None
    try:
        fd = os.open(DROPIN, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
        created = True
        with os.fdopen(fd, "wb") as handle:
            info = os.fstat(handle.fileno())
            created_identity = (info.st_dev, info.st_ino)
            os.fchmod(handle.fileno(), 0o644)
            handle.write(CONTENT)
            handle.flush()
            os.fsync(handle.fileno())
            write_completed = True
        run([SSHD, "-t"])
        after = effective(context)
        if setting(after, "loglevel") != "VERBOSE" or tuple(
            line for line in before if not line.startswith("loglevel ")
        ) != tuple(line for line in after if not line.startswith("loglevel ")):
            raise LoggingError("The drop-in did not change only the effective log level")
        reload_attempted = True
        run(["systemctl", "reload", "ssh.service"])
        run(["systemctl", "is-active", "--quiet", "ssh.service"])
        check_daemon()
        if effective(context) != after:
            raise LoggingError("SSH settings changed during reload")
    except BaseException as exc:
        if not created:
            raise
        try:
            current = DROPIN.lstat()
            if (current.st_dev, current.st_ino) != created_identity or (
                write_completed and DROPIN.read_bytes() != CONTENT
            ):
                raise LoggingError("Logging drop-in changed concurrently; manual recovery required")
            DROPIN.unlink()
            run([SSHD, "-t"])
            if reload_attempted:
                run(["systemctl", "reload", "ssh.service"])
                run(["systemctl", "is-active", "--quiet", "ssh.service"])
        except BaseException as recovery:
            raise LoggingError(
                f"SSH logging setup failed; recovery also failed: {recovery}"
            ) from recovery
        reason = str(exc) or type(exc).__name__
        raise LoggingError(f"{reason}; the new logging drop-in was removed") from exc
    return {**report, "dropin_created": True, "ssh_reloaded": True}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--connection", required=True)
    parser.add_argument("--expected-release", required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(configure(args.connection, args.expected_release), indent=2))
    except (OSError, ValueError, LoggingError, subprocess.SubprocessError) as exc:
        parser.exit(1, "STOP: " + str(exc) + "\n")


if __name__ == "__main__":
    main()
