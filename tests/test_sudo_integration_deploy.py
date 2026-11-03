"""Coordinated migration and rollback preserve current history and outbox identity."""

import hashlib
import importlib.util
import os
import sqlite3
from pathlib import Path
from types import SimpleNamespace

import pytest

from yggdrasil_ids.domain import Finding, SSHEvent
from yggdrasil_ids.storage import Repository


@pytest.fixture
def deploy():
    path = Path(__file__).parents[1] / "deploy/sudo_integration_deploy.py"
    spec = importlib.util.spec_from_file_location("sudo_deploy_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def machine(deploy, tmp_path, monkeypatch):
    paths = {
        "CODE": tmp_path / "opt/integration",
        "PRIVATE": tmp_path / "var/private-model",
        "DATABASE": tmp_path / "var/production/events.sqlite3",
        "CONFIG": tmp_path / "etc/config.toml",
        "PUBLIC": tmp_path / "var/public/integration.json",
        "UNIT_DIR": tmp_path / "etc/systemd/system",
        "BACKUP_ROOT": tmp_path / "var/backups",
        "MODEL": tmp_path / "original-model/model.json",
    }
    for name, value in paths.items():
        value.parent.mkdir(parents=True, exist_ok=True)
        monkeypatch.setattr(deploy, name, value)
    deploy.UNIT_DIR.mkdir(exist_ok=True)
    deploy.CONFIG.write_text("existing config must stay unchanged")
    deploy.MODEL.write_text('{"private_training_fixture":true}')
    monkeypatch.setattr(deploy, "MODEL_HASH", hashlib.sha256(deploy.MODEL.read_bytes()).hexdigest())
    monkeypatch.setattr(
        deploy.pwd, "getpwnam", lambda _: SimpleNamespace(pw_uid=os.geteuid(), pw_gid=os.getegid())
    )
    monkeypatch.setattr(deploy.grp, "getgrnam", lambda _: SimpleNamespace(gr_gid=os.getegid()))
    repo = Repository(deploy.DATABASE)
    repo.initialize()
    with repo.transaction() as db:
        db.execute("DROP TABLE sudo_evidence")
        db.execute("PRAGMA user_version=4")
        repo.put_state(db, "mode", "live")
        repo.put_state(db, "namespace", "live")
    for unit in deploy.PRODUCTION:
        (deploy.UNIT_DIR / unit).write_text("[Service]\n# original unit\n")
    source = tmp_path / "source"
    package = source / "src/yggdrasil_ids"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("# fixture source")
    (package / "storage.py").write_text("SCHEMA_VERSION = 5\n")
    (source / "deploy").mkdir()
    for filename in (
        "sprint5_sudo_integration_poll.py",
        "sudo_integration_deploy.py",
        deploy.SERVICE,
        deploy.TIMER,
    ):
        (source / "deploy" / filename).write_text("# fixture code or unit\n")
    active = set(deploy.PRODUCTION) | {
        "yggdrasil-sudo-shadow.timer",
        "yggdrasil-sudo-ui-export.timer",
    }
    calls = []
    users = ["yggdrasil-worker", "yggdrasil-web", "yggdrasil-notifier"]
    groups = ["yggdrasil-data", "yggdrasil-web", "yggdrasil-notifier"]

    def properties(unit):
        result = {
            "ActiveState": "active" if unit in active else "inactive",
            "UnitFileState": "enabled",
            "DropInPaths": "",
            "Environment": "",
            "Result": "success",
            "ConditionResult": "yes",
        }
        if unit in deploy.PRODUCTION:
            i = deploy.PRODUCTION.index(unit)
            result.update(User=users[i], Group=groups[i])
        return result

    def command(args, **kwargs):
        calls.append(tuple(args))
        if args[:2] == ["systemctl", "stop"]:
            active.difference_update(args[2:])
        elif args[:2] == ["systemctl", "start"]:
            active.update(args[2:])
            if deploy.SERVICE in args:
                deploy.PUBLIC.write_text("{}")
                deploy.PUBLIC.chmod(0o640)
        elif args[:3] == ["systemctl", "enable", "--now"]:
            active.update(args[3:])
        elif args[:3] == ["systemctl", "disable", "--now"]:
            active.difference_update(args[3:])
        return SimpleNamespace(returncode=0, stdout="")

    def worker(code, **kwargs):
        calls.append(("worker", kwargs.get("user", "yggdrasil-worker"), code))
        if ".initialize()" in code:
            assert not set(deploy.PRODUCTION) & active
            assert all(deploy.override_path(unit).exists() for unit in deploy.PRODUCTION)
            repo.initialize()
        elif "arm_rules" in code:
            assert set(deploy.PRODUCTION) <= active
            repo.set_state(deploy.ARM_KEY, 1000.0)
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(deploy, "command", command)
    monkeypatch.setattr(deploy, "properties", properties)
    monkeypatch.setattr(deploy, "worker", worker)
    monkeypatch.setattr(deploy, "login_check", lambda: None)
    monkeypatch.setattr(deploy.time, "sleep", lambda _: None)
    return SimpleNamespace(repo=repo, source=source, active=active, calls=calls)


def new_ssh_alarm(repo, index=1):
    event = SSHEvent(
        str(index), 1_800_000_000.0 + index, "192.0.2.7", "test-user", "failure", "password"
    )
    with repo.transaction() as db:
        repo.insert_event(db, event)
        repo.add_finding(
            db,
            Finding(
                "ssh.failed_burst",
                "SSH",
                "medium",
                "rule",
                event.source_ip,
                event.event_id,
                event.timestamp,
                {},
            ),
            300,
        )


def test_successful_release_stops_all_roles_before_migration_and_arms_after_health(deploy, machine):
    before_config = deploy.CONFIG.read_bytes()
    new_ssh_alarm(machine.repo)
    before = deploy.fingerprint(deploy.DATABASE)
    deploy.install(machine.source, "a" * 40)
    assert set(deploy.PRODUCTION) | {deploy.TIMER} <= machine.active
    assert all(
        deploy.override_path(unit).read_text() == deploy.overlay(unit) for unit in deploy.PRODUCTION
    )
    with machine.repo.reader() as db:
        assert db.execute("PRAGMA user_version").fetchone()[0] == 5
        assert db.execute("SELECT COUNT(*) FROM sudo_evidence").fetchone()[0] == 0
    after = deploy.fingerprint(deploy.DATABASE)
    assert {key: value for key, value in after.items() if key != "state"} == {
        key: value for key, value in before.items() if key != "state"
    }
    assert deploy.CONFIG.read_bytes() == before_config
    backup = deploy.BACKUP_ROOT / ("sprint5-sudo-integration-before-" + "a" * 40)
    assert (backup / "events-schema4.sqlite3").stat().st_mode & 0o777 == 0o600
    assert "test-user" not in (backup / "manifest.json").read_text()
    assert not any("bootstrap" in " ".join(call) for call in machine.calls)


def test_late_failure_rolls_back_without_losing_new_ssh_or_replacing_delivery_state(
    deploy, machine, monkeypatch, tmp_path
):
    delivery = tmp_path / "notifier-private.sqlite3"
    delivery.write_bytes(b"existing-delivery-cursor-and-receipts")
    attempts = []

    def login_check():
        attempts.append(1)
        if len(attempts) == 1:
            new_ssh_alarm(machine.repo)
            raise deploy.DeployError("simulated post-restart failure")

    monkeypatch.setattr(deploy, "login_check", login_check)
    with pytest.raises(deploy.DeployError, match="post-restart"):
        deploy.install(machine.source, "b" * 40)
    with machine.repo.reader() as db:
        assert db.execute("PRAGMA user_version").fetchone()[0] == 4
        assert db.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 1
        assert db.execute("SELECT COUNT(*) FROM alerts").fetchone()[0] == 1
        assert db.execute("SELECT COUNT(*) FROM discord_outbox").fetchone()[0] == 1
    assert delivery.read_bytes() == b"existing-delivery-cursor-and-receipts"
    assert set(deploy.PRODUCTION) <= machine.active and deploy.TIMER not in machine.active
    assert all(not deploy.override_path(unit).exists() for unit in deploy.PRODUCTION)
    assert not deploy.CODE.exists() and not deploy.PRIVATE.exists()


def test_manual_rollback_refuses_to_discard_new_sudo_alarm_evidence(deploy, machine):
    machine.repo.initialize()
    with machine.repo.transaction() as db:
        machine.repo.add_sudo_alert(
            db,
            event_id="a" * 64,
            detector_id="sudo.repeated_auth_failure",
            timestamp=1_800_000_000.0,
            process_count=3,
        )
    before = deploy.DATABASE.read_bytes()
    with pytest.raises(deploy.DeployError, match="Sudo alarms already exist"):
        deploy.recover(manual=True)
    assert deploy.DATABASE.read_bytes() == before
    assert not machine.calls


def test_automatic_recovery_keeps_compatible_code_when_new_sudo_evidence_exists(deploy, machine):
    machine.repo.initialize()
    with machine.repo.transaction() as db:
        machine.repo.add_sudo_alert(
            db,
            event_id="a" * 64,
            detector_id="sudo.permission_denied",
            timestamp=1_800_000_000.0,
            process_count=1,
        )
    for unit in deploy.PRODUCTION:
        deploy.override_path(unit).parent.mkdir()
        deploy.override_path(unit).write_text(deploy.overlay(unit))
    assert deploy.recover() is False
    with machine.repo.reader() as db:
        assert db.execute("PRAGMA user_version").fetchone()[0] == 5
        assert db.execute("SELECT COUNT(*) FROM sudo_evidence").fetchone()[0] == 1
        assert db.execute("SELECT COUNT(*) FROM discord_outbox").fetchone()[0] == 1
    assert all(deploy.override_path(unit).exists() for unit in deploy.PRODUCTION)
    assert set(deploy.PRODUCTION) <= machine.active


def test_staging_permissions_allow_role_imports_despite_private_umask(deploy, machine):
    previous = os.umask(0o077)
    try:
        deploy.copy_source(machine.source, "c" * 40)
    finally:
        os.umask(previous)
    assert deploy.CODE.stat().st_mode & 0o777 == 0o755
    assert (deploy.CODE / "deploy").stat().st_mode & 0o777 == 0o755
    assert (deploy.CODE / "src/yggdrasil_ids").stat().st_mode & 0o777 == 0o755
    assert deploy.PRIVATE.stat().st_mode & 0o777 == 0o700
    assert (deploy.PRIVATE / "mixed_full-model.json").stat().st_mode & 0o777 == 0o400
    assert (deploy.PRIVATE / "mixed_full-model.json").read_bytes() == deploy.MODEL.read_bytes()


def test_early_role_failure_removes_only_new_staging_and_leaves_production_running(
    deploy, machine, monkeypatch
):
    before = deploy.DATABASE.read_bytes()

    def reject(**kwargs):
        raise deploy.DeployError("incompatible saved model")

    monkeypatch.setattr(deploy, "check_roles", reject)
    with pytest.raises(deploy.DeployError, match="incompatible"):
        deploy.install(machine.source, "d" * 40)
    assert deploy.DATABASE.read_bytes() == before
    assert set(deploy.PRODUCTION) <= machine.active
    assert not deploy.CODE.exists() and not deploy.PRIVATE.exists()
    assert not any(call[:2] == ("systemctl", "stop") for call in machine.calls)


def test_schema_downgrade_is_atomic_when_alarm_evidence_exists(deploy, machine):
    machine.repo.initialize()
    with machine.repo.transaction() as db:
        machine.repo.add_sudo_alert(
            db,
            event_id="a" * 64,
            detector_id="sudo.permission_denied",
            timestamp=1_800_000_000.0,
            process_count=1,
        )
    with pytest.raises(deploy.DeployError, match="evidence"):
        deploy.downgrade_empty_sudo(deploy.DATABASE)
    with sqlite3.connect(deploy.DATABASE) as db:
        assert db.execute("PRAGMA user_version").fetchone()[0] == 5
        assert db.execute("SELECT COUNT(*) FROM sudo_evidence").fetchone()[0] == 1


def test_backup_is_readonly_for_source_and_preserves_outbox_identity(deploy, machine, tmp_path):
    new_ssh_alarm(machine.repo)
    before = deploy.DATABASE.read_bytes()
    path = tmp_path / "offline-backup.sqlite3"
    signature = deploy.backup_database(deploy.DATABASE, path)
    assert signature == deploy.fingerprint(deploy.DATABASE)
    assert deploy.DATABASE.read_bytes() == before
    assert path.stat().st_mode & 0o777 == 0o600
    with pytest.raises(deploy.DeployError, match="already exists"):
        deploy.backup_database(deploy.DATABASE, path)
