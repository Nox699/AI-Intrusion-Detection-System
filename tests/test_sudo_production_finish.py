"""Small unit-only release preserves running roles and rejects false acceptance."""

import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest


@pytest.fixture
def finish(monkeypatch, tmp_path):
    deploy = Path(__file__).parents[1] / "deploy"
    monkeypatch.syspath_prepend(str(deploy))
    spec = importlib.util.spec_from_file_location(
        "sudo_finish_test", deploy / "sudo_production_finish.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    # The helper has its own dependency instance; other deployment tests patch
    # their separately loaded module, so production paths cannot leak into tests.
    module.deployment = importlib.util.module_from_spec(
        importlib.util.spec_from_file_location(
            "finish_deploy_test", deploy / "sudo_integration_deploy.py"
        )
    )
    module.deployment.__spec__.loader.exec_module(module.deployment)
    units = tmp_path / "units"
    units.mkdir()
    monkeypatch.setattr(module.deployment, "UNIT_DIR", units)
    monkeypatch.setattr(module.deployment, "BACKUP_ROOT", tmp_path / "backups")
    candidate = deploy / module.deployment.SERVICE
    updated = candidate.read_bytes()
    old = updated.replace(module.NEW_READONLY.encode(), module.OLD_READONLY.encode()).replace(
        b"After=yggdrasil-sudo-shadow.service yggdrasil-collector.service\n",
        b"After=yggdrasil-sudo-shadow.service yggdrasil-collector.service\n"
        + module.OLD_CONDITION.encode(),
    )
    target = units / module.deployment.SERVICE
    target.write_bytes(old)
    target.chmod(0o644)
    # Normal CI is nonroot. Fake ownership metadata only for the fixture file;
    # production ownership validation and the root entrypoint guard stay intact.
    original_lstat = Path.lstat

    def lstat(path):
        result = original_lstat(path)
        if path == target or path.name.startswith("sudo-production-finish-before-"):
            return SimpleNamespace(st_mode=result.st_mode, st_uid=0)
        return result

    monkeypatch.setattr(Path, "lstat", lstat)
    calls = []

    def command(args, **kwargs):
        calls.append(tuple(args))
        output = ""
        if args[0] == "busctl":
            output = (
                'o "/org/freedesktop/systemd1/unit/yggdrasil_2dsudo_2dintegration_2eservice"\n'
                if "LoadUnit" in args
                else "a(sbbsi) 0\n"
            )
        elif args[:2] == ["systemctl", "show"]:
            # Actual systemd generic-property rendering is not an empty string.
            output = "Conditions=[unprintable]\n"
        return SimpleNamespace(stdout=output, returncode=0)

    monkeypatch.setattr(module.deployment, "command", command)
    return SimpleNamespace(
        module=module,
        candidate=candidate,
        target=target,
        old=old,
        updated=updated,
        calls=calls,
        sha="a" * 40,
    )


def test_unit_upgrade_is_backed_up_idempotent_and_does_not_restart_services(finish):
    m = finish.module
    assert m.finish_unit(finish.candidate, finish.sha)
    assert finish.target.read_bytes() == finish.updated
    backup = m.deployment.BACKUP_ROOT / ("sudo-production-finish-before-" + finish.sha)
    assert backup.stat().st_mode & 0o777 == 0o700
    assert (backup / m.deployment.SERVICE).read_bytes() == finish.old
    assert not m.finish_unit(finish.candidate, finish.sha)
    assert not m.finish_unit(finish.candidate, finish.sha, check_only=True)
    assert all(
        call[:2] == ("systemctl", "daemon-reload") or call[0] == "busctl" for call in finish.calls
    )
    assert b"ConditionPathExists" not in finish.updated
    assert b"-/var/lib/yggdrasil-sudo-integration-private" in finish.updated


def test_changed_unit_and_check_before_install_cannot_pass(finish):
    m = finish.module
    with pytest.raises(m.deployment.DeployError, match="has not been installed"):
        m.finish_unit(finish.candidate, finish.sha, check_only=True)
    finish.target.write_bytes(finish.old + b"# unexpected local modification\n")
    with pytest.raises(m.deployment.DeployError, match="changed"):
        m.finish_unit(finish.candidate, finish.sha)
    assert not finish.calls
    assert not m.deployment.BACKUP_ROOT.exists()


def test_reload_failure_restores_only_original_unit_without_touching_other_state(
    finish, monkeypatch
):
    m = finish.module

    def fail(args, **kwargs):
        finish.calls.append(tuple(args))
        if kwargs.get("check", True):
            raise m.deployment.DeployError("reload failed")

    monkeypatch.setattr(m.deployment, "command", fail)
    with pytest.raises(m.deployment.DeployError, match="reload failed"):
        m.finish_unit(finish.candidate, finish.sha)
    assert finish.target.read_bytes() == finish.old
    assert finish.calls == [("systemctl", "daemon-reload")] * 2


def test_effective_condition_override_is_not_accepted(finish, monkeypatch):
    m = finish.module
    original = m.deployment.command

    def command(args, **kwargs):
        if "get-property" in args:
            return SimpleNamespace(
                stdout='a(sbbsi) 1 "ConditionPathExists" false false "/private-model" 1\n'
            )
        return original(args, **kwargs)

    monkeypatch.setattr(m.deployment, "command", command)
    with pytest.raises(m.deployment.DeployError, match="still has a start condition"):
        m.finish_unit(finish.candidate, finish.sha)


@pytest.mark.parametrize(
    "output", ["", "Conditions=[unprintable]\n", "a(sbbsi)\n", "as 0\n", "a(sbbsi) 0 unexpected\n"]
)
def test_unreadable_typed_conditions_never_pass(finish, monkeypatch, output):
    m = finish.module
    original = m.deployment.command

    def command(args, **kwargs):
        return (
            SimpleNamespace(stdout=output) if "get-property" in args else original(args, **kwargs)
        )

    monkeypatch.setattr(m.deployment, "command", command)
    with pytest.raises(m.deployment.DeployError, match="Cannot verify.*condition list"):
        m.require_no_start_conditions()


def test_wrong_loaded_unit_cannot_pass_conditions_check(finish, monkeypatch):
    m = finish.module
    monkeypatch.setattr(
        m.deployment, "command", lambda *a, **kw: SimpleNamespace(stdout='o "/wrong/unit"\n')
    )
    with pytest.raises(m.deployment.DeployError, match="unit identity"):
        m.require_no_start_conditions()


def test_resume_after_previous_false_rejection_uses_existing_unit_and_backup(finish, monkeypatch):
    m = finish.module
    finish.target.write_bytes(finish.updated)
    backup = m.deployment.BACKUP_ROOT / ("sudo-production-finish-before-" + "b" * 40)
    backup.mkdir(parents=True, mode=0o700)
    saved = backup / m.deployment.SERVICE
    saved.write_bytes(finish.old)
    assert not m.finish_unit(finish.candidate, finish.sha)
    assert finish.target.read_bytes() == finish.updated
    assert saved.read_bytes() == finish.old
    assert not (m.deployment.BACKUP_ROOT / ("sudo-production-finish-before-" + finish.sha)).exists()
    assert not any("--property=Conditions" in call for call in finish.calls)


def test_retry_after_reload_failure_reuses_verified_backup(finish, monkeypatch):
    m = finish.module
    command = m.deployment.command
    failures = [True]

    def fail_once(args, **kwargs):
        if failures.pop() if failures else False:
            raise m.deployment.DeployError("reload failed")
        return command(args, **kwargs)

    monkeypatch.setattr(m.deployment, "command", fail_once)
    with pytest.raises(m.deployment.DeployError, match="reload failed"):
        m.finish_unit(finish.candidate, finish.sha)
    assert finish.target.read_bytes() == finish.old
    assert m.finish_unit(finish.candidate, finish.sha)
    backup = m.deployment.BACKUP_ROOT / ("sudo-production-finish-before-" + finish.sha)
    assert (backup / m.deployment.SERVICE).read_bytes() == finish.old


def test_previous_export_cannot_pass_post_reload_acceptance(finish, monkeypatch):
    m = finish.module
    clock = [0.0]
    monkeypatch.setattr(m.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(m.time, "sleep", lambda seconds: clock.__setitem__(0, clock[0] + seconds))
    monkeypatch.setattr(m, "role_check", lambda *a, **kw: {"generated_at": 99.0})
    monkeypatch.setattr(
        m, "urlopen", lambda *a, **kw: pytest.fail("Old result reached HTTP acceptance")
    )
    with pytest.raises(m.deployment.DeployError, match="No fresh healthy sudo export"):
        m.verify(not_before=100.0)
    assert clock[0] == 150
    assert not finish.calls


def test_new_export_is_checked_with_authenticated_routes_before_pass(finish, monkeypatch):
    m = finish.module
    stamps = iter([99.0, 100.0])
    calls = []

    def role(user, code, *, routes=False):
        calls.append((user, routes))
        return (
            {"generated_at": 100.0 if routes else next(stamps)} if user == "yggdrasil-web" else {}
        )

    class Response:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def read(self, size):
            return b"Yggdrasil"

    monkeypatch.setattr(m, "role_check", role)
    monkeypatch.setattr(m.time, "sleep", lambda *a: None)
    monkeypatch.setattr(m, "urlopen", lambda *a, **kw: Response())
    monkeypatch.setattr(m, "runtime_check", lambda: None)
    assert m.verify(not_before=100.0)["status"] == "ready"
    assert calls[-1] == ("yggdrasil-web", True)
    assert not finish.calls


@pytest.mark.parametrize("changed", ["source", "role", "timer"])
def test_unreviewed_runtime_cannot_be_modified(finish, monkeypatch, tmp_path, changed):
    m = finish.module
    integration, web = tmp_path / "integration", tmp_path / "web"
    for directory, sha in ((integration, m.INTEGRATION_SHA), (web, m.WEB_SHA)):
        directory.mkdir()
        (directory / "COMMIT").write_text(sha)
    monkeypatch.setattr(m.deployment, "CODE", integration)
    monkeypatch.setattr(m, "WEB_CODE", web)

    def properties(unit):
        result = {"ActiveState": "active", "UnitFileState": "enabled", "DropInPaths": ""}
        if unit == m.deployment.SERVICE:
            result.update(User="yggdrasil-worker", Group="yggdrasil-data")
        elif unit in m.deployment.PRODUCTION:
            i = m.deployment.PRODUCTION.index(unit)
            user, group, source = (
                ("yggdrasil-worker", "yggdrasil-data", integration),
                ("yggdrasil-web", "yggdrasil-web", web),
                ("yggdrasil-notifier", "yggdrasil-notifier", integration),
            )[i]
            result.update(User=user, Group=group, Environment=f"PYTHONPATH={source}/src")
        if changed == "role" and unit == m.deployment.PRODUCTION[0]:
            result["Group"] = "yggdrasil-worker"
        if changed == "timer" and unit == m.deployment.TIMER:
            result["UnitFileState"] = "disabled"
        return result

    monkeypatch.setattr(m.deployment, "properties", properties)
    if changed == "source":
        (web / "COMMIT").write_text("b" * 40)
    with pytest.raises(m.deployment.DeployError):
        m.runtime_check()
    assert finish.target.read_bytes() == finish.old
    assert not finish.calls


def test_role_commands_use_real_groups_and_do_not_reflect_child_secrets(finish, monkeypatch):
    m = finish.module
    calls = []

    def command(args, **kwargs):
        calls.append(args)
        return SimpleNamespace(returncode=0, stdout='{"ready":true}')

    monkeypatch.setattr(m.deployment, "command", command)
    assert m.role_check("yggdrasil-worker", "pass") == {"ready": True}
    assert "--regid=yggdrasil-data" in calls[-1]
    assert "--groups=yggdrasil-data,systemd-journal" in calls[-1]
    m.role_check("yggdrasil-web", "pass")
    assert "--regid=yggdrasil-web" in calls[-1]
    assert f"PYTHONPATH={m.WEB_CODE}/src" in calls[-1]
    monkeypatch.setattr(
        m.deployment,
        "command",
        lambda *a, **kw: SimpleNamespace(
            returncode=1, stdout="private username", stderr="private command"
        ),
    )
    with pytest.raises(m.deployment.DeployError, match="yggdrasil-web") as error:
        m.role_check("yggdrasil-web", "pass")
    assert "private" not in str(error.value)


@pytest.mark.parametrize("failed_role", ["yggdrasil-worker", "yggdrasil-notifier", "yggdrasil-web"])
def test_unhealthy_roles_cannot_pass_acceptance(finish, monkeypatch, failed_role):
    m = finish.module

    def role(user, *args, **kwargs):
        if user == failed_role:
            raise m.deployment.DeployError("unhealthy role")
        return {}

    monkeypatch.setattr(m, "role_check", role)
    with pytest.raises(m.deployment.DeployError, match="unhealthy role"):
        m.verify()


def test_readonly_worker_program_checks_actual_sqlite_and_model(tmp_path, finish):
    """Run the embedded acceptance program on real private fixtures, not a mock reader."""
    import hashlib
    import sqlite3
    import time

    from yggdrasil_ids.storage import Repository
    from yggdrasil_ids.sudo_live_bridge import ARM_KEY
    from yggdrasil_ids.sudo_storage import SudoStagingStore

    now = time.time()
    repo = Repository(tmp_path / "production.sqlite3")
    repo.initialize()
    for key, value in (("mode", "live"), ("namespace", "live"), (ARM_KEY, now - 100)):
        repo.set_state(key, value)
    source = SudoStagingStore(tmp_path / "private-source" / "source.sqlite3")
    source.initialize()
    with sqlite3.connect(source.path) as db:
        db.executescript(
            "CREATE TABLE shadow_poll_checkpoint(id INTEGER PRIMARY KEY,last_completed_until REAL);"
        )
        db.execute("INSERT INTO shadow_poll_checkpoint VALUES(1,?)", (now - 2,))
    model = tmp_path / "private-model" / "model.json"
    model.parent.mkdir(mode=0o700)
    model.write_bytes(b"private saved rows")
    model.chmod(0o400)
    code = (
        finish.module.WORKER_CHECK.replace("/var/lib/yggdrasil-ids/events.sqlite3", str(repo.path))
        .replace("/var/lib/yggdrasil-sudo-shadow/sudo-shadow.sqlite3", str(source.path))
        .replace("/var/lib/yggdrasil-sudo-integration-private/mixed_full-model.json", str(model))
    )
    code = code.replace(
        "cfg = load_config()",
        f"cfg = type('Cfg', (), {{'mode':'live', 'database_path':Path({str(repo.path)!r})}})()",
    )
    code = f"MODEL_HASH={hashlib.sha256(model.read_bytes()).hexdigest()!r}\n" + code
    before = [path.read_bytes() for path in (repo.path, source.path, model)]
    result = subprocess.run(
        [sys.executable, "-c", code],
        text=True,
        capture_output=True,
        env={**os.environ, "PYTHONPATH": str(Path(__file__).parents[1] / "src")},
    )
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {"registered_sudo_evidence": 0}
    assert before == [path.read_bytes() for path in (repo.path, source.path, model)]
    with sqlite3.connect(source.path) as db:
        db.execute("UPDATE shadow_poll_checkpoint SET last_completed_until=?", (now - 1000,))
    result = subprocess.run(
        [sys.executable, "-c", code],
        text=True,
        capture_output=True,
        env={**os.environ, "PYTHONPATH": str(Path(__file__).parents[1] / "src")},
    )
    assert result.returncode != 0
