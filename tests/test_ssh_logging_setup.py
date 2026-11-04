"""The explicit SSH logging setup preserves authentication and recovers on failure."""

import importlib.util
import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

RELEASE = "3ca24a114c52d2ac0ea24fe013d7c469db5b83e4"
CONNECTION = "192.0.2.10 41000 192.0.2.20 22"


@pytest.fixture
def setup(tmp_path, monkeypatch):
    helper = Path(__file__).parents[1] / "deploy/configure_ssh_logging_pi.py"
    spec = importlib.util.spec_from_file_location("ssh_logging_setup_test", helper)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    accepted = tmp_path / "release/ACCEPTED.json"
    accepted.parent.mkdir()
    accepted.write_text(json.dumps({"sha": RELEASE}))
    dropin = tmp_path / "ssh/sshd_config.d/00-yggdrasil-ids-logging.conf"
    dropin.parent.mkdir(parents=True)
    proc = tmp_path / "proc"
    process = proc / "9876"
    process.mkdir(parents=True)
    (process / "cmdline").write_bytes(b"sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups\0")
    (process / "exe").symlink_to("/usr/sbin/sshd")
    monkeypatch.setattr(m, "ACCEPTED", accepted)
    monkeypatch.setattr(m, "DROPIN", dropin)
    monkeypatch.setattr(m, "PROC", proc)
    monkeypatch.setattr(m.os, "geteuid", lambda: 0)
    monkeypatch.setattr(m.socket, "gethostname", lambda: "yggdrasil")
    state = SimpleNamespace(
        calls=[],
        ignored="These IP addresses/networks are ignored:\n`- 192.0.2.10/32\n",
        initial_level="INFO",
        ignore_dropin=False,
        change_auth=False,
        syntax_failure=False,
        reload_failures=0,
    )

    def run(args):
        args = list(args)
        state.calls.append(args)
        if args[:2] == [m.SSHD, "-T"]:
            changed = dropin.exists() and not state.ignore_dropin
            level = "VERBOSE" if changed else state.initial_level
            password = "yes" if changed and state.change_auth else "no"
            return (
                f"loglevel {level}\npasswordauthentication {password}\n"
                "kbdinteractiveauthentication no\npubkeyauthentication yes\n"
                "authenticationmethods any\nport 22\n"
                "hostkey /etc/ssh/ssh_host_ed25519_key\n"
                "hostkey /etc/ssh/ssh_host_rsa_key\n"
            )
        if args[:2] == [m.SSHD, "-t"]:
            if dropin.exists() and state.syntax_failure:
                raise subprocess.CalledProcessError(1, args, stderr="invalid configuration")
            return ""
        if "fail2ban-client" in args[0]:
            assert args[1:] == ["get", "sshd", "ignoreip"]
            return state.ignored
        if args[:2] == ["systemctl", "show"]:
            return "ActiveState=active\nMainPID=9876\n"
        if args[:2] == ["systemctl", "reload"]:
            if state.reload_failures:
                state.reload_failures -= 1
                raise subprocess.CalledProcessError(1, args, stderr="reload failed")
            return ""
        if args[:2] == ["systemctl", "is-active"]:
            return "active\n"
        raise AssertionError(f"Unexpected external operation: {args!r}")

    monkeypatch.setattr(m, "run", run)
    state.module = m
    state.dropin = dropin
    state.process = process
    return state


def reloads(setup):
    return [args for args in setup.calls if args[:2] == ["systemctl", "reload"]]


def test_enables_only_logging_and_reloads_once(setup):
    report = setup.module.configure(CONNECTION, RELEASE)
    assert setup.dropin.read_bytes() == setup.module.CONTENT
    assert setup.dropin.stat().st_mode & 0o777 == 0o644
    assert len(reloads(setup)) == 1
    assert report["live_key_rejection_verified"] is False


def test_verified_verbose_configuration_needs_no_write_or_reload(setup):
    setup.initial_level = "VERBOSE"
    setup.module.configure(CONNECTION, RELEASE)
    assert not setup.dropin.exists()
    assert not reloads(setup)


def test_nonignored_client_stops_before_configuration_write(setup):
    setup.ignored = "No IP address/network is ignored\n"
    with pytest.raises(setup.module.LoggingError, match="not exempted"):
        setup.module.configure(CONNECTION, RELEASE)
    assert not setup.dropin.exists()
    assert not reloads(setup)


@pytest.mark.parametrize("guard", ["host", "root", "release"])
def test_preflight_guards_leave_configuration_untouched(setup, monkeypatch, guard):
    m = setup.module
    if guard == "host":
        monkeypatch.setattr(m.socket, "gethostname", lambda: "another-host")
    elif guard == "root":
        monkeypatch.setattr(m.os, "geteuid", lambda: 1000)
    else:
        m.ACCEPTED.write_text(json.dumps({"sha": "0" * 40}))
    with pytest.raises(m.LoggingError):
        m.configure(CONNECTION, RELEASE)
    assert not setup.dropin.exists()
    assert not reloads(setup)


def test_invalid_connection_cannot_create_configuration(setup):
    for connection in ("", "not-an-ip 41000 192.0.2.20 22"):
        with pytest.raises((setup.module.LoggingError, ValueError)):
            setup.module.configure(connection, RELEASE)
    assert not setup.dropin.exists()
    assert not reloads(setup)


def test_custom_daemon_configuration_is_refused(setup):
    for argument in ("-f /etc/ssh/custom.conf", "-o LogLevel=INFO"):
        (setup.process / "cmdline").write_bytes(
            f"sshd: /usr/sbin/sshd -D {argument} [listener]\0".encode()
        )
        with pytest.raises(setup.module.LoggingError, match="command-line options"):
            setup.module.configure(CONNECTION, RELEASE)
    assert not setup.dropin.exists()
    assert not reloads(setup)


def test_earlier_log_directive_rolls_back_before_reload(setup):
    setup.ignore_dropin = True
    with pytest.raises(setup.module.LoggingError, match="effective log level.*drop-in was removed"):
        setup.module.configure(CONNECTION, RELEASE)
    assert not setup.dropin.exists()
    assert not reloads(setup)


def test_authentication_change_rolls_back_before_reload(setup):
    setup.change_auth = True
    with pytest.raises(setup.module.LoggingError, match="effective log level.*drop-in was removed"):
        setup.module.configure(CONNECTION, RELEASE)
    assert not setup.dropin.exists()
    assert not reloads(setup)


def test_invalid_configuration_is_removed_without_reload(setup):
    setup.syntax_failure = True
    with pytest.raises(setup.module.LoggingError, match="drop-in was removed"):
        setup.module.configure(CONNECTION, RELEASE)
    assert not setup.dropin.exists()
    assert not reloads(setup)


def test_reload_failure_restores_previous_configuration_and_reloads_it(setup):
    setup.reload_failures = 1
    with pytest.raises(setup.module.LoggingError, match="drop-in was removed"):
        setup.module.configure(CONNECTION, RELEASE)
    assert not setup.dropin.exists()
    assert len(reloads(setup)) == 2


def test_failed_recovery_is_reported_explicitly(setup):
    setup.reload_failures = 2
    with pytest.raises(setup.module.LoggingError, match="recovery also failed"):
        setup.module.configure(CONNECTION, RELEASE)
    assert not setup.dropin.exists()
    assert len(reloads(setup)) == 2


def test_concurrent_administrator_edit_is_retained(setup, monkeypatch):
    original_run = setup.module.run
    changed = b"# administrator edit\nLogLevel INFO\n"

    def run(args):
        if args[:2] == ["systemctl", "reload"]:
            setup.dropin.write_bytes(changed)
            raise setup.module.LoggingError("reload failed")
        return original_run(args)

    monkeypatch.setattr(setup.module, "run", run)
    with pytest.raises(setup.module.LoggingError, match="recovery also failed"):
        setup.module.configure(CONNECTION, RELEASE)
    assert setup.dropin.read_bytes() == changed


def test_interrupt_during_reload_restores_original_configuration(setup, monkeypatch):
    original_run = setup.module.run
    interrupted = False

    def run(args):
        nonlocal interrupted
        if args[:2] == ["systemctl", "reload"] and not interrupted:
            interrupted = True
            raise KeyboardInterrupt
        return original_run(args)

    monkeypatch.setattr(setup.module, "run", run)
    with pytest.raises(setup.module.LoggingError, match="KeyboardInterrupt.*drop-in was removed"):
        setup.module.configure(CONNECTION, RELEASE)
    assert not setup.dropin.exists()
    assert len(reloads(setup)) == 1


def test_existing_different_file_is_preserved(setup):
    setup.dropin.write_bytes(b"# existing administrator configuration\nLogLevel INFO\n")
    before = setup.dropin.read_bytes()
    # This fake models a nonincluded administrator file: effective level is still INFO.
    setup.ignore_dropin = True
    with pytest.raises(FileExistsError):
        setup.module.configure(CONNECTION, RELEASE)
    assert setup.dropin.read_bytes() == before
    assert not reloads(setup)


def test_existing_symlink_and_target_are_preserved(setup, tmp_path):
    target = tmp_path / "administrator-config"
    target.write_bytes(b"LogLevel INFO\n")
    setup.dropin.symlink_to(target)
    setup.ignore_dropin = True
    with pytest.raises(FileExistsError):
        setup.module.configure(CONNECTION, RELEASE)
    assert setup.dropin.is_symlink()
    assert target.read_bytes() == b"LogLevel INFO\n"
    assert not reloads(setup)
