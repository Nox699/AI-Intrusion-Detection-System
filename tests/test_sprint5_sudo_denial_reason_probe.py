"""One-shot sudo failure reason probe must not expose sensitive stderr."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "deploy" / "sprint5_sudo_denial_reason_probe.py"


@pytest.fixture(scope="module")
def probe():
    spec = importlib.util.spec_from_file_location("sprint5_sudo_denial_reason_probe", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize(
    "stderr,code,expected",
    [
        ("sudo: a password is required", 1, "password_required_noninteractive"),
        ("sudo: yggdrasil-web is not in the sudoers file", 1, "not_in_sudoers"),
        (
            "Sorry, user yggdrasil-web is not allowed to execute /usr/bin/true as root",
            1,
            "command_not_permitted",
        ),
        ("sudo: a terminal is required to read the password", 1, "tty_required"),
        ("sudo: effective uid is not 0, is /usr/bin/sudo on nosuid?", 1, "privilege_execution_blocked"),
        ("system-specific diagnostic: private-token", 1, "unclassified_failure"),
        ("", 0, "unexpected_success"),
    ],
)
def test_categorizes_without_revealing_raw_error(probe, stderr, code, expected):
    assert probe.categorize_error(stderr, code) == expected


def test_probe_one_harmless_command_and_sanitized_response(probe, monkeypatch):
    called = []

    monkeypatch.setattr(probe.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(
        probe.pwd, "getpwnam", lambda name: SimpleNamespace(pw_uid=997)
    )

    def fake_run(command, **kwargs):
        called.append((command, kwargs))
        return SimpleNamespace(
            stderr="sudo: a password is required for secret-user /private",
            stdout="private stdout",
            returncode=1,
        )

    monkeypatch.setattr(probe.subprocess, "run", fake_run)
    report = probe.probe()
    assert len(called) == 1
    command, kwargs = called[0]
    assert tuple(command) == (
        "/usr/bin/sudo",
        "-n",
        "-u",
        "yggdrasil-web",
        "/usr/bin/sudo",
        "-n",
        "/usr/bin/true",
    )
    assert kwargs["shell"] is not True if "shell" in kwargs else True
    assert kwargs["stdout"] is probe.subprocess.PIPE
    assert kwargs["stderr"] is probe.subprocess.PIPE
    assert kwargs["env"]["LC_ALL"] == "C"
    assert kwargs["timeout"] == 15
    assert report["exit_code"] == 1
    assert report["reason_category"] == "password_required_noninteractive"
    assert report["raw_stdout_stderr_exposed"] is False
    serialized = json.dumps(report)
    for secret in ("secret-user", "/private", "private stdout"):
        assert secret not in serialized


def test_probe_refuses_root_and_root_target(probe, monkeypatch):
    def no_subprocess(*args, **kwargs):
        pytest.fail("The sudo command must not be attempted")

    monkeypatch.setattr(probe.subprocess, "run", no_subprocess)
    monkeypatch.setattr(probe.os, "geteuid", lambda: 0)
    with pytest.raises(ValueError, match="normal login"):
        probe.probe()
    monkeypatch.setattr(probe.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(
        probe.pwd, "getpwnam", lambda name: SimpleNamespace(pw_uid=0)
    )
    with pytest.raises(ValueError, match="privileged target"):
        probe.probe()


def test_probe_timeout_is_sanitized(probe, monkeypatch):
    monkeypatch.setattr(probe.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(
        probe.pwd, "getpwnam", lambda name: SimpleNamespace(pw_uid=997)
    )

    def fake_timeout(*args, **kwargs):
        raise probe.subprocess.TimeoutExpired(args[0], 15, output=b"private-output")

    monkeypatch.setattr(probe.subprocess, "run", fake_timeout)
    report = probe.probe()
    assert report["reason_category"] == "timeout"
    assert "private" not in json.dumps(report)


def test_cli_never_emits_raw_stderr(probe, monkeypatch, capsys):
    monkeypatch.setattr(
        probe,
        "probe",
        lambda: {
            "reason_category": "not_in_sudoers",
            "raw_stdout_stderr_exposed": False,
        },
    )
    assert probe.main() == 0
    output = capsys.readouterr().out
    assert json.loads(output)["reason_category"] == "not_in_sudoers"
