"""A coordinated production release preserves live history and role boundaries."""

import ast
import hashlib
import importlib.util
import json
import os
import shutil
import sqlite3
import time
import tomllib
from pathlib import Path
from types import SimpleNamespace

import pytest

from yggdrasil_ids.storage import Repository
from yggdrasil_ids.sudo_rules import SudoSignal
from yggdrasil_ids.sudo_storage import SudoStagingStore


def simulate_root_metadata(monkeypatch, paths):
    original = Path.lstat

    def lstat(path):
        info = original(path)
        if path in paths:
            values = list(info)
            values[4] = 0
            return os.stat_result(values)
        return info

    monkeypatch.setattr(Path, "lstat", lstat)


@pytest.fixture
def deployment(tmp_path, monkeypatch):
    deploy = Path(__file__).parents[1] / "deploy"
    spec = importlib.util.spec_from_file_location(
        "production_deployment_test", deploy / "production_upgrade.py"
    )
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    paths = {
        "ROOT": tmp_path / "opt/ids",
        "RELEASES": tmp_path / "opt/ids/releases",
        "CURRENT": tmp_path / "opt/ids/current",
        "PYTHON": tmp_path / "opt/ids/venv/bin/python",
        "ENTRYPOINT": tmp_path / "opt/ids/venv/bin/yggdrasil-ids",
        "CONFIG": tmp_path / "etc/ids/config.toml",
        "DATABASE": tmp_path / "var/ids/events.sqlite3",
        "MODEL": tmp_path / "var/ids/model.json",
        "DELIVERY": tmp_path / "var/notifier/delivery.sqlite3",
        "SUDO_DATABASE": tmp_path / "var/sudo/sudo.sqlite3",
        "OLD_SUDO_DATABASE": tmp_path / "var/sudo-old/sudo.sqlite3",
        "PUBLIC": tmp_path / "var/sudo-public",
        "UNIT_DIR": tmp_path / "etc/systemd/system",
        "BACKUPS": tmp_path / "backups",
        "LEGACY_INTEGRATION": tmp_path / "old-integration",
        "LEGACY_WEB": tmp_path / "old-web",
    }
    for key, path in paths.items():
        monkeypatch.setattr(m, key, path)
        path.parent.mkdir(parents=True, exist_ok=True)
    m.SUDO_DATABASE.parent.rmdir()
    for path in (m.ROOT, m.UNIT_DIR, m.PUBLIC):
        path.mkdir(exist_ok=True)
    m.ENTRYPOINT.write_bytes(b"original entrypoint\n")
    m.ENTRYPOINT.chmod(0o755)
    m.CONFIG.write_text(f"""[app]
mode="live"
host_label="Yggdrasil"
[paths]
database={str(m.DATABASE)!r}
model={str(m.MODEL)!r}
credentials="/etc/ids/secrets.json"
[ml]
alert_mode="shadow"
[network]
enabled=true
distinct_ports_threshold=5
[rules]
expected_users=["private-login"]
cooldown_seconds=300
""")
    m.MODEL.write_bytes(b"reviewed model saved rows")
    repo = Repository(m.DATABASE)
    repo.initialize()
    for key, value in (
        ("mode", "live"),
        ("namespace", "live"),
        (m.ARM_KEY, 1000.0),
        ("model", {"state": "ready", "metadata": {"version": m.EXPECTED_MODEL_VERSION}}),
    ):
        repo.set_state(key, value)
    with sqlite3.connect(m.DELIVERY) as db:
        db.executescript(
            "CREATE TABLE meta(instance TEXT,last_seq INTEGER,not_before REAL); CREATE TABLE deliveries(ref TEXT,discord_id TEXT,sent_at REAL);"
        )
        with repo.reader() as source:
            instance = source.execute(
                "SELECT instance FROM discord_outbox_meta WHERE id=1"
            ).fetchone()[0]
        db.execute("INSERT INTO meta VALUES(?,0,0)", (instance,))
    private = SudoStagingStore(m.OLD_SUDO_DATABASE)
    private.path.parent.chmod(0o700)
    private.initialize()
    with sqlite3.connect(private.path) as db:
        db.executescript(
            "CREATE TABLE shadow_poll_checkpoint(id INTEGER PRIMARY KEY,last_completed_until REAL);"
        )
        db.execute("INSERT INTO shadow_poll_checkpoint VALUES(1,?)", (time.time() - 2,))
    for unit in (*m.PRODUCTION, *m.OLD_SERVICES, *m.OLD_TIMERS):
        (m.UNIT_DIR / unit).write_text("original " + unit)
    for path, data in m.expected_legacy_overrides().items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    for name in ("sudo-status.json", "sudo-activity.json", "sudo-integration.json"):
        (m.PUBLIC / name).write_text("original " + name)
    source = tmp_path / "source"
    (source / "src/yggdrasil_ids").mkdir(parents=True)
    (source / "src/yggdrasil_ids/storage.py").write_text("SCHEMA_VERSION=5\n")
    (source / "src/yggdrasil_ids/__init__.py").write_text("# production package\n")
    (source / "deploy").mkdir()
    (source / "requirements.lock").write_text("numpy==2.3.5\n")
    for unit in m.UNITS:
        (source / "deploy" / unit).write_bytes((deploy / unit).read_bytes())
    active = set(m.PRODUCTION) | set(m.OLD_TIMERS) | set(m.OLD_SERVICES)
    enabled = set(m.PRODUCTION) | set(m.OLD_TIMERS)
    calls = []
    model = {
        "version": m.EXPECTED_MODEL_VERSION,
        "sha256": hashlib.sha256(m.MODEL.read_bytes()).hexdigest(),
    }

    def props(unit):
        return {
            "ActiveState": "active" if unit in active else "inactive",
            "UnitFileState": "enabled" if unit in enabled else "disabled",
            "LoadState": "loaded" if (m.UNIT_DIR / unit).exists() else "not-found",
        }

    def command(args, **kwargs):
        calls.append(tuple(args))
        if args[:2] == ["systemctl", "stop"]:
            active.difference_update(args[2:])
        elif args[:3] == ["systemctl", "disable", "--now"]:
            active.difference_update(args[3:])
            enabled.difference_update(args[3:])
        elif args[:3] == ["systemctl", "enable", "--now"]:
            active.update(args[3:])
            enabled.update(args[3:])
        elif args[:2] == ["systemctl", "start"]:
            active.update(args[2:])
        elif args[:2] == ["systemctl", "enable"]:
            enabled.update(args[2:])
        return SimpleNamespace(returncode=0, stdout="")

    def role(code, **kwargs):
        ast.parse(code)
        calls.append(("role", kwargs.get("user", "yggdrasil-worker"), code))
        return SimpleNamespace(returncode=0, stdout="{}")

    monkeypatch.setattr(m, "command", command)
    monkeypatch.setattr(m, "properties", props)
    monkeypatch.setattr(m, "role", role)
    monkeypatch.setattr(m, "runtime_check", lambda: (m.LEGACY_INTEGRATION, False))
    monkeypatch.setattr(m, "model_identity", lambda *a, **kw: dict(model))
    monkeypatch.setattr(m, "check_dependencies", lambda *a: None)
    monkeypatch.setattr(m, "check_candidate", lambda *a, **kw: None)
    monkeypatch.setattr(m, "acceptance", lambda *a, **kw: {"sudo_rules_active": True})
    monkeypatch.setattr(
        m.pwd, "getpwnam", lambda _: SimpleNamespace(pw_uid=os.geteuid(), pw_gid=os.getegid())
    )
    monkeypatch.setattr(m.grp, "getgrnam", lambda _: SimpleNamespace(gr_gid=os.getegid()))
    monkeypatch.setattr(m.os, "chown", lambda *a: None)
    monkeypatch.setattr(m.os, "fchown", lambda *a: None)
    return SimpleNamespace(
        m=m,
        source=source,
        sha="a" * 40,
        calls=calls,
        active=active,
        enabled=enabled,
        repo=repo,
        model=model,
        original_config=m.CONFIG.read_bytes(),
    )


def add_alarm(machine, index=1):
    with machine.repo.transaction() as db:
        machine.repo.add_sudo_alert(
            db,
            event_id=f"{index:064x}",
            detector_id="sudo.repeated_auth_failure",
            timestamp=time.time(),
            process_count=3,
        )


def test_release_preserves_model_identity_and_moves_only_reviewed_configuration(deployment):
    x, m = deployment, deployment.m
    before_model = m.MODEL.read_bytes()
    before_identity = m.database_identity()
    add_alarm(x)
    report = m.upgrade(x.source, x.sha)
    assert report["status"] == "ready" and report["ssh_ml_alerts_enabled"]
    assert m.MODEL.read_bytes() == before_model
    assert m.CURRENT.resolve() == m.RELEASES / x.sha
    assert (m.RELEASES / x.sha / "ACCEPTED.json").exists()
    cfg = tomllib.loads(m.CONFIG.read_text())
    assert "alert_mode" not in cfg["ml"]
    assert cfg["network"]["distinct_ports_threshold"] == 5
    assert cfg["rules"]["expected_users"] == ["private-login"]
    assert cfg["sudo"]["enabled"]
    assert m.SUDO_DATABASE.is_file()
    assert m.database_identity()["instance"] == before_identity["instance"]
    assert m.database_identity()["activated_at"] == 1000.0
    with x.repo.reader() as db:
        assert db.execute("SELECT COUNT(*) FROM sudo_evidence").fetchone()[0] == 1
    assert all(not (m.UNIT_DIR / unit).exists() for unit in (*m.OLD_SERVICES, *m.OLD_TIMERS))
    assert all(not path.exists() for path in m.expected_legacy_overrides())
    assert not any("sudo-arm" in str(call) or "--bootstrap" in str(call) for call in x.calls)
    stop = next(
        i
        for i, call in enumerate(x.calls)
        if call[:2] == ("systemctl", "stop") and set(m.OLD_SERVICES) <= set(call)
    )
    core_stop = next(
        i
        for i, call in enumerate(x.calls)
        if call[:2] == ("systemctl", "stop") and set(m.PRODUCTION) <= set(call)
    )
    assert stop < core_stop


def test_failed_acceptance_restores_files_but_preserves_new_alarm_history(deployment, monkeypatch):
    x, m = deployment, deployment.m
    original_units = {unit: (m.UNIT_DIR / unit).read_bytes() for unit in m.PRODUCTION}

    def fail(*args, **kwargs):
        add_alarm(x, 2)
        private = SudoStagingStore(m.SUDO_DATABASE)
        private.initialize()
        private.append(
            SudoSignal("new-runtime-row", time.time() - 2, "a" * 32, "999", 4001, "command_invoked")
        )
        (m.PUBLIC / "sudo-status.json").write_text("new incompatible export")
        raise m.ReleaseError("forced acceptance failure")

    monkeypatch.setattr(m, "acceptance", fail)
    with pytest.raises(m.ReleaseError, match="forced acceptance failure"):
        m.upgrade(x.source, x.sha)
    assert m.CONFIG.read_bytes() == x.original_config
    assert m.ENTRYPOINT.read_bytes() == b"original entrypoint\n"
    assert not m.CURRENT.exists()
    assert all((m.UNIT_DIR / unit).read_bytes() == data for unit, data in original_units.items())
    assert set(m.PRODUCTION) | set(m.OLD_TIMERS) <= x.active
    assert not m.SUDO_DATABASE.exists()
    backup = m.BACKUPS / ("production-before-" + x.sha)
    assert (backup / "retired-production-sudo-state/sudo.sqlite3").exists()
    assert (backup / "RECOVERED").exists()
    assert (m.PUBLIC / "sudo-status.json").read_text() == "original sudo-status.json"
    with sqlite3.connect(m.OLD_SUDO_DATABASE) as db:
        assert db.execute("SELECT COUNT(*) FROM sudo_signals").fetchone()[0] == 1
    with x.repo.reader() as db:
        assert db.execute("SELECT COUNT(*) FROM sudo_evidence").fetchone()[0] == 1
        assert db.execute("SELECT COUNT(*) FROM discord_outbox").fetchone()[0] == 1


def test_recovered_release_can_retry_without_overwriting_prior_backup(deployment, monkeypatch):
    x, m = deployment, deployment.m
    monkeypatch.setattr(
        m, "acceptance", lambda *a, **kw: (_ for _ in ()).throw(m.ReleaseError("fail"))
    )
    with pytest.raises(m.ReleaseError):
        m.upgrade(x.source, x.sha)
    monkeypatch.setattr(m, "acceptance", lambda *a, **kw: {"sudo_rules_active": True})
    assert m.upgrade(x.source, x.sha)["status"] == "ready"
    assert len(list(m.BACKUPS.glob("production-recovered-" + x.sha + "-*"))) == 1


@pytest.mark.parametrize(
    "key,value", [("missing", None), ("future", 9_000_000_000), ("wrong", "bad")]
)
def test_invalid_existing_activation_stops_before_any_service_change(deployment, key, value):
    x, m = deployment, deployment.m
    if key == "missing":
        with x.repo.transaction() as db:
            db.execute("DELETE FROM state WHERE key=?", (m.ARM_KEY,))
    else:
        x.repo.set_state(m.ARM_KEY, value)
    with pytest.raises(m.ReleaseError, match="activation boundary"):
        m.upgrade(x.source, x.sha)
    assert not x.calls
    assert not m.CURRENT.exists()
    assert m.CONFIG.read_bytes() == x.original_config


def test_model_failure_stops_before_any_writer_is_stopped(deployment, monkeypatch):
    x, m = deployment, deployment.m
    monkeypatch.setattr(
        m,
        "model_identity",
        lambda *a, **kw: (_ for _ in ()).throw(m.ReleaseError("model unavailable")),
    )
    with pytest.raises(m.ReleaseError, match="model unavailable"):
        m.upgrade(x.source, x.sha)
    assert not x.calls
    assert m.CONFIG.read_bytes() == x.original_config


def test_private_copy_refuses_symlinked_parent_without_changing_victim(deployment, tmp_path):
    m = deployment.m
    victim = tmp_path / "victim"
    victim.mkdir(mode=0o755)
    m.SUDO_DATABASE.parent.symlink_to(victim, target_is_directory=True)
    with pytest.raises(m.ReleaseError, match="symlink"):
        m.copy_sudo_database(m.OLD_SUDO_DATABASE)
    assert victim.stat().st_mode & 0o777 == 0o755
    assert not list(victim.iterdir())


def test_configuration_preserves_later_sudo_and_network_tunables(deployment):
    m = deployment.m
    raw = (
        deployment.original_config
        + b"\n[sudo]\nenabled=true\nwindow_seconds=600\nfailure_process_threshold=4\ncooldown_seconds=600\n"
    )
    result = tomllib.loads(m.production_config(raw).decode())
    assert result["sudo"]["window_seconds"] == 600
    assert result["sudo"]["failure_process_threshold"] == 4
    assert result["network"]["distinct_ports_threshold"] == 5


def test_repeated_accepted_release_is_read_only_and_model_state_checked(deployment):
    x, m = deployment, deployment.m
    m.upgrade(x.source, x.sha)
    calls_before = len(x.calls)
    assert m.upgrade(x.source, x.sha)["already_active"]
    assert len(x.calls) == calls_before


def test_interrupted_unaccepted_release_resumes_without_resetting_data(deployment, monkeypatch):
    x, m = deployment, deployment.m
    m.upgrade(x.source, x.sha)
    (m.CURRENT / "ACCEPTED.json").unlink()
    add_alarm(x, 9)
    model_before = m.MODEL.read_bytes()
    assert m.upgrade(x.source, x.sha)["resumed"]
    assert m.MODEL.read_bytes() == model_before
    with x.repo.reader() as db:
        assert db.execute("SELECT COUNT(*) FROM sudo_evidence").fetchone()[0] == 1


def test_missing_private_state_during_resume_does_not_create_empty_database(deployment):
    x, m = deployment, deployment.m
    m.upgrade(x.source, x.sha)
    (m.CURRENT / "ACCEPTED.json").unlink()
    m.SUDO_DATABASE.unlink()
    with pytest.raises(m.ReleaseError, match="existing regular database"):
        m.upgrade(x.source, x.sha)
    assert not m.SUDO_DATABASE.exists()


def test_interrupted_recovery_finishes_before_attempting_release_resume(deployment):
    x, m = deployment, deployment.m
    m.upgrade(x.source, x.sha)
    (m.CURRENT / "ACCEPTED.json").unlink()
    backup = m.BACKUPS / ("production-before-" + x.sha)
    # Power loss immediately after private-state quarantine, before restoring
    # the former config/source/units. A resume must recover first.
    m.SUDO_DATABASE.parent.rename(backup / "retired-production-sudo-state")
    (backup / "RECOVERING").write_text("interrupted\n")
    assert m.upgrade(x.source, x.sha)["status"] == "ready"
    assert m.SUDO_DATABASE.exists()
    assert len(list(m.BACKUPS.glob("production-recovered-" + x.sha + "-*"))) == 1


def test_stale_private_source_stops_before_service_changes(deployment):
    x, m = deployment, deployment.m
    with sqlite3.connect(m.OLD_SUDO_DATABASE) as db:
        db.execute("UPDATE shadow_poll_checkpoint SET last_completed_until=1")
    with pytest.raises(m.ReleaseError, match="checkpoint is not fresh"):
        m.upgrade(x.source, x.sha)
    assert not x.calls


def test_service_journal_membership_is_not_hidden_by_role_setpriv(deployment, monkeypatch):
    m = deployment.m
    monkeypatch.setattr(m.pwd, "getpwnam", lambda user: SimpleNamespace(pw_uid=999, pw_gid=10))
    monkeypatch.setattr(
        m.grp,
        "getgrnam",
        lambda group: SimpleNamespace(gr_gid=20 if group == "systemd-journal" else 10),
    )
    monkeypatch.setattr(
        m.os, "getgrouplist", lambda user, gid: [10, 20] if user == "yggdrasil-web" else [10]
    )
    with pytest.raises(m.ReleaseError, match="journal membership"):
        m.validate_service_accounts()


def test_role_subprocess_uses_actual_worker_group_and_private_source(deployment):
    x, m = deployment, deployment.m
    # Exercise the real wrapper rather than the fixture's role stub.
    spec = importlib.util.spec_from_file_location(
        "role_wrapper", Path(__file__).parents[1] / "deploy/production_upgrade.py"
    )
    real = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(real)
    real.command = m.command
    real.role("pass", source=Path("/opt/release"), config=Path("/etc/config"))
    args = x.calls[-1]
    assert "--reuid=yggdrasil-worker" in args and "--regid=yggdrasil-data" in args
    assert "--groups=yggdrasil-data,systemd-journal" in args
    assert "PYTHONPATH=/opt/release/src" in args


def test_fresh_installer_refuses_existing_setup_and_only_resumes_matching_model(
    deployment, monkeypatch
):
    x, m = deployment, deployment.m
    monkeypatch.syspath_prepend(str(Path(__file__).parents[1] / "deploy"))
    spec = importlib.util.spec_from_file_location(
        "production_fresh_test", Path(__file__).parents[1] / "deploy/production_install.py"
    )
    fresh = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fresh)
    fresh.release = m
    monkeypatch.setattr(fresh, "check_root", lambda: None)
    with pytest.raises(m.ReleaseError, match="Existing installation"):
        fresh.fresh_guard(x.sha, m.MODEL)
    marker = m.ROOT / "INSTALLING.json"
    marker.write_text(
        json.dumps({"sha": x.sha, "model_sha256": hashlib.sha256(m.MODEL.read_bytes()).hexdigest()})
    )
    simulate_root_metadata(monkeypatch, {marker})
    marker.chmod(0o600)
    assert fresh.fresh_guard(x.sha, m.MODEL)[0] == marker
    with pytest.raises(m.ReleaseError, match="resume SHA or model differs"):
        fresh.fresh_guard("b" * 40, m.MODEL)


@pytest.fixture
def fresh_machine(deployment, monkeypatch, tmp_path):
    x, m = deployment, deployment.m
    for path in (m.CONFIG, m.DATABASE, m.DELIVERY, m.MODEL, m.ENTRYPOINT, m.OLD_SUDO_DATABASE):
        path.unlink()
    shutil.rmtree(m.ROOT / "venv")
    for unit in (*m.UNITS, *m.OLD_TIMERS, *m.OLD_SERVICES):
        (m.UNIT_DIR / unit).unlink(missing_ok=True)
    for path in m.expected_legacy_overrides():
        path.unlink()
    x.active.clear()
    x.enabled.clear()
    x.calls.clear()
    reviewed = tmp_path / "reviewed-ssh-model.json"
    reviewed.write_bytes(b"reviewed model saved rows")
    (x.source / "deploy/config.pi.toml").write_bytes(x.original_config)
    webhook = m.CONFIG.parent / "discord-webhook.url"
    webhook.write_bytes(b"private provisioned credential placeholder")
    webhook.chmod(0o600)
    monkeypatch.syspath_prepend(str(Path(__file__).parents[1] / "deploy"))
    spec = importlib.util.spec_from_file_location(
        "fresh_state_machine", Path(__file__).parents[1] / "deploy/production_install.py"
    )
    fresh = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fresh)
    fresh.release = m
    marker = m.ROOT / "INSTALLING.json"
    credentials = m.CONFIG.parent / "web-secrets.json"
    simulate_root_metadata(monkeypatch, {m.ROOT, marker, credentials, webhook})
    monkeypatch.setattr(fresh, "ensure_accounts", lambda: x.calls.append(("ensure_accounts",)))
    previous_command = m.command

    def command(args, **kwargs):
        if args[:3] == ["/usr/bin/python3", "-m", "venv"]:
            (m.ROOT / "venv/bin").mkdir(parents=True, mode=0o700, exist_ok=True)
            m.PYTHON.write_text("# fixture interpreter\n")
            m.PYTHON.chmod(0o700)
        return previous_command(args, **kwargs)

    monkeypatch.setattr(m, "command", command)

    def credential(source):
        credentials.write_text('{"private":"existing session key"}')
        credentials.chmod(0o600)
        x.calls.append(("credentials",))

    monkeypatch.setattr(fresh, "create_credentials", credential)

    def cli(args, **kwargs):
        x.calls.append(("cli", *args))
        if args[0] == "init":
            x.repo.initialize()
            for key, value in (
                ("mode", "live"),
                ("namespace", "live"),
                ("model", {"state": "ready", "metadata": {"version": m.EXPECTED_MODEL_VERSION}}),
            ):
                x.repo.set_state(key, value)
        elif args[0] == "notify":
            with x.repo.reader() as db:
                identity = db.execute(
                    "SELECT instance FROM discord_outbox_meta WHERE id=1"
                ).fetchone()[0]
            with sqlite3.connect(m.DELIVERY) as db:
                db.executescript(
                    "CREATE TABLE meta(instance TEXT,last_seq INTEGER,not_before REAL); CREATE TABLE deliveries(ref TEXT,discord_id TEXT,sent_at REAL);"
                )
                db.execute("INSERT INTO meta VALUES(?,0,0)", (identity,))
        elif args[0] == "sudo-arm":
            if x.repo.get_state(m.ARM_KEY) is None:
                x.repo.set_state(m.ARM_KEY, time.time())

    monkeypatch.setattr(m, "role_cli", cli)
    controls = SimpleNamespace(fail_acceptance=False)

    def accept(*args, **kwargs):
        x.calls.append(("acceptance",))
        if not m.SUDO_DATABASE.exists():
            SudoStagingStore(m.SUDO_DATABASE).initialize()
        if controls.fail_acceptance:
            raise m.ReleaseError("late first-install failure")
        assert set(m.PRODUCTION) | {m.SUDO_TIMER} <= x.active
        assert m.database_identity()["activated_at"] > 0
        return {"sudo_rules_active": True}

    monkeypatch.setattr(m, "acceptance", accept)
    return SimpleNamespace(
        x=x,
        m=m,
        fresh=fresh,
        model=reviewed,
        marker=marker,
        credentials=credentials,
        controls=controls,
    )


def test_fresh_install_initializes_notifier_before_any_collectors_start(fresh_machine):
    f, x, m = fresh_machine, fresh_machine.x, fresh_machine.m
    assert f.fresh.install(x.source, x.sha, f.model)["status"] == "ready"
    assert not f.marker.exists()
    assert f.credentials.stat().st_mode & 0o777 == 0o640
    assert m.MODEL.read_bytes() == f.model.read_bytes()
    assert m.CURRENT.resolve() == m.RELEASES / x.sha
    bootstrap = next(i for i, c in enumerate(x.calls) if c[:2] == ("cli", "notify"))
    arm = next(i for i, c in enumerate(x.calls) if c[:2] == ("cli", "sudo-arm"))
    start = next(i for i, c in enumerate(x.calls) if c[:3] == ("systemctl", "enable", "--now"))
    assert bootstrap < arm < start


def test_failed_fresh_acceptance_stops_own_roles_and_resume_never_rebootstraps(fresh_machine):
    f, x, m = fresh_machine, fresh_machine.x, fresh_machine.m
    f.controls.fail_acceptance = True
    with pytest.raises(m.ReleaseError, match="late first-install failure"):
        f.fresh.install(x.source, x.sha, f.model)
    assert not x.active and not x.enabled
    assert f.marker.exists()
    identity = m.database_identity()
    credential_bytes = f.credentials.read_bytes()
    # Simulate interrupted permission finalization while preserving the key.
    f.credentials.chmod(0o600)
    f.controls.fail_acceptance = False
    assert f.fresh.install(x.source, x.sha, f.model)["status"] == "ready"
    assert m.database_identity()["instance"] == identity["instance"]
    assert m.database_identity()["activated_at"] == identity["activated_at"]
    assert sum(c[:2] == ("cli", "notify") for c in x.calls) == 1
    assert sum(c == ("credentials",) for c in x.calls) == 1
    assert f.credentials.read_bytes() == credential_bytes
    assert f.credentials.stat().st_mode & 0o777 == 0o640


def test_fresh_guard_rejection_cannot_stop_an_existing_installation(deployment, monkeypatch):
    x, m = deployment, deployment.m
    monkeypatch.syspath_prepend(str(Path(__file__).parents[1] / "deploy"))
    spec = importlib.util.spec_from_file_location(
        "fresh_guard_no_cleanup", Path(__file__).parents[1] / "deploy/production_install.py"
    )
    fresh = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fresh)
    fresh.release = m
    monkeypatch.setattr(fresh, "check_root", lambda: None)
    with pytest.raises(m.ReleaseError, match="Existing installation"):
        fresh.install(x.source, x.sha, m.MODEL)
    assert not x.calls
    assert set(m.PRODUCTION) <= x.active


def test_model_changed_during_dependency_install_does_not_poison_target(fresh_machine, monkeypatch):
    f, x, m = fresh_machine, fresh_machine.x, fresh_machine.m
    original = m.command

    def command(args, **kwargs):
        result = original(args, **kwargs)
        if "pip" in args:
            f.model.write_bytes(b"unreviewed replacement")
        return result

    monkeypatch.setattr(m, "command", command)
    with pytest.raises(m.ReleaseError, match="source model changed"):
        f.fresh.install(x.source, x.sha, f.model)
    assert not m.MODEL.exists()
    assert not x.active


def test_private_umask_does_not_make_release_code_unreadable(deployment):
    x, m = deployment, deployment.m
    m.ROOT.chmod(0o700)
    previous = os.umask(0o077)
    try:
        staged = m.stage_release(x.source, x.sha, m.production_config(x.original_config))
        assert all(
            path.stat().st_mode & 0o777 == 0o755
            for path in (m.ROOT, m.RELEASES, staged, staged / "src")
        )
        assert (staged / "candidate-config.toml").stat().st_mode & 0o777 == 0o640
        m.RELEASES.chmod(0o700)
        staged.chmod(0o700)
        m.stage_release(x.source, x.sha, m.production_config(x.original_config))
        assert m.RELEASES.stat().st_mode & 0o777 == 0o755
        assert staged.stat().st_mode & 0o777 == 0o755
    finally:
        os.umask(previous)


def test_fresh_venv_publication_skips_external_symlinks_and_private_state(fresh_machine, tmp_path):
    f, m = fresh_machine, fresh_machine.m
    venv = m.ROOT / "venv"
    previous = os.umask(0o077)
    try:
        venv.mkdir(mode=0o700)
        code = venv / "lib/python/site-packages/public.py"
        code.parent.mkdir(parents=True)
        code.write_text("# public dependency")
        script = venv / "bin/public-command"
        script.parent.mkdir()
        script.write_text("#!/bin/sh\n")
        script.chmod(0o700)
        private = tmp_path / "private-model"
        private.write_text("private rows")
        private.chmod(0o600)
        (venv / "external-link").symlink_to(private)
        f.fresh.publish_venv_code()
        assert venv.stat().st_mode & 0o777 == 0o755
        assert code.parent.stat().st_mode & 0o777 == 0o755
        assert code.stat().st_mode & 0o777 == 0o644
        assert script.stat().st_mode & 0o777 == 0o755
        assert private.stat().st_mode & 0o777 == 0o600
    finally:
        os.umask(previous)


def test_failed_fresh_resume_stop_blocks_dependency_or_config_mutations(fresh_machine, monkeypatch):
    f, x, m = fresh_machine, fresh_machine.x, fresh_machine.m
    f.controls.fail_acceptance = True
    with pytest.raises(m.ReleaseError):
        f.fresh.install(x.source, x.sha, f.model)
    x.active.add(m.PRODUCTION[0])
    before = len(x.calls)

    def cannot_stop(args, **kwargs):
        x.calls.append(tuple(args))
        return SimpleNamespace(returncode=1, stdout="")

    monkeypatch.setattr(m, "command", cannot_stop)
    with pytest.raises(m.ReleaseError, match="did not stop"):
        f.fresh.install(x.source, x.sha, f.model)
    assert not any("pip" in call or call == ("ensure_accounts",) for call in x.calls[before:])


def test_matching_fresh_model_is_finalized_after_interrupted_owner_change(
    fresh_machine, monkeypatch
):
    f, x, m = fresh_machine, fresh_machine.x, fresh_machine.m
    f.controls.fail_acceptance = True
    with pytest.raises(m.ReleaseError):
        f.fresh.install(x.source, x.sha, f.model)
    m.MODEL.chmod(0o600)
    changed = []
    monkeypatch.setattr(m.os, "chown", lambda *args: changed.append(args))
    f.controls.fail_acceptance = False
    f.fresh.install(x.source, x.sha, f.model)
    assert any(call[0] == m.MODEL for call in changed)
    assert m.MODEL.stat().st_mode & 0o777 == 0o400


def test_first_install_rejects_an_unowned_existing_venv_before_execution(fresh_machine):
    f, x, m = fresh_machine, fresh_machine.x, fresh_machine.m
    (m.ROOT / "venv").mkdir()
    before = list(x.calls)
    with pytest.raises(m.ReleaseError, match="Existing installation"):
        f.fresh.install(x.source, x.sha, f.model)
    assert x.calls == before
    assert not f.marker.exists()
