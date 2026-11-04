"""The production sudo job links real normalized rules to one existing outbox."""

import fcntl
import sqlite3

import pytest

from tests.sudo_helpers import NOW, row
from yggdrasil_ids import sudo_collector as collector
from yggdrasil_ids import sudo_service as service
from yggdrasil_ids.config import AppConfig, SudoConfig
from yggdrasil_ids.storage import Repository
from yggdrasil_ids.sudo_bridge import ARM_KEY
from yggdrasil_ids.sudo_integration_dashboard import read_integration


@pytest.fixture
def installed(tmp_path, monkeypatch):
    monkeypatch.setattr(collector, "_require_worker", lambda: None)
    monkeypatch.setattr(service, "_require_worker", lambda: None)
    public = tmp_path / "public"
    public.mkdir(mode=0o750)
    cfg = AppConfig(
        database_path=tmp_path / "production" / "events.sqlite3",
        sudo_database_path=tmp_path / "private" / "sudo.sqlite3",
        sudo_public_directory=public,
        sudo=SudoConfig(enabled=True),
    )
    repo = Repository(cfg.database_path)
    repo.initialize()
    repo.set_state("mode", "live")
    repo.set_state("namespace", "live")
    return cfg, repo


def counts(repo):
    with repo.reader() as db:
        return tuple(
            db.execute("SELECT COUNT(*) FROM " + name).fetchone()[0]
            for name in ("alerts", "sudo_evidence", "discord_outbox")
        )


def test_unarmed_runtime_cannot_arm_itself_or_process_journal(installed):
    cfg, repo = installed
    with pytest.raises(service.SudoServiceError):
        service.run_once(cfg, now=NOW, records=[])
    assert repo.get_state(ARM_KEY) is None
    assert not cfg.sudo_database_path.exists()
    assert counts(repo) == (0, 0, 0)
    public = read_integration(cfg.sudo_public_directory / "sudo-integration.json", now=NOW)
    assert public["state"] == "error" and not public["rules_active"]


def test_three_failed_processes_create_one_alarm_and_one_outbox_on_repeat(installed):
    cfg, repo = installed
    service.arm(cfg, now=NOW - 100)
    events = [
        row(1, NOW - 80),
        row(1, NOW - 79, "summary"),
        row(2, NOW - 60),
        row(2, NOW - 59, "summary"),
        row(3, NOW - 20),
        row(3, NOW - 19, "summary"),
    ]
    first = service.run_once(cfg, now=NOW, records=events)
    assert first["rules"]["state"] == "active"
    assert counts(repo) == (1, 1, 1)
    assert set(first) == {"schema", "generated_at", "activated_at", "source_checkpoint", "rules"}
    assert first["schema"] == "sudo-integration-v2"
    service.run_once(cfg, now=NOW + 60, records=events)
    assert counts(repo) == (1, 1, 1)
    assert service.arm(cfg, now=NOW + 70) == NOW - 100
    public = read_integration(cfg.sudo_public_directory / "sudo-integration.json", now=NOW + 60)
    assert public["state"] == "ready" and public["rules_active"]
    assert "ml" not in public
    for name in ("sudo-status.json", "sudo-activity.json", "sudo-integration.json"):
        text = (cfg.sudo_public_directory / name).read_text()
        assert "private-user" not in text and "private-cursor" not in text
        assert "shadow" not in text
        assert (cfg.sudo_public_directory / name).stat().st_mode & 0o777 == 0o640


def test_prior_candidates_are_not_reissued_when_first_armed(installed):
    cfg, repo = installed
    service.arm(cfg, now=NOW - 10)
    service.run_once(cfg, now=NOW, records=[row(1, NOW - 80), row(2, NOW - 60), row(3, NOW - 20)])
    assert counts(repo) == (0, 0, 0)


def test_permission_denial_enters_same_rule_alarm_pipeline(installed):
    cfg, repo = installed
    service.arm(cfg, now=NOW - 100)
    service.run_once(cfg, now=NOW, records=[row(1, NOW - 20, "denied")])
    assert counts(repo) == (1, 1, 1)
    with repo.reader() as db:
        assert (
            db.execute("SELECT detector_id FROM alerts").fetchone()[0] == "sudo.permission_denied"
        )


def test_reader_failure_publishes_error_without_partial_database_or_private_exception(installed):
    cfg, repo = installed
    service.arm(cfg, now=NOW - 100)
    service.run_once(cfg, now=NOW, records=[])

    def broken():
        yield row(1, NOW + 20)
        raise RuntimeError("private command password username")

    with pytest.raises(service.SudoServiceError) as error:
        service.run_once(cfg, now=NOW + 60, records=broken())
    assert "private command" not in str(error.value)
    path = cfg.sudo_public_directory / "sudo-integration.json"
    assert read_integration(path, now=NOW + 60)["state"] == "error"
    assert "private command" not in path.read_text()
    with sqlite3.connect(cfg.sudo_database_path) as db:
        assert db.execute("SELECT COUNT(*) FROM sudo_signals").fetchone()[0] == 0
        assert (
            db.execute("SELECT last_completed_until FROM shadow_poll_checkpoint").fetchone()[0]
            == NOW - 2
        )


def test_export_failure_does_not_lose_rule_alarm_or_duplicate_it_on_recovery(
    installed, monkeypatch
):
    cfg, repo = installed
    service.arm(cfg, now=NOW - 100)
    original = service.publish

    def fail_activity(payload, path):
        if path.name == "sudo-activity.json":
            raise OSError("private exporter detail")
        return original(payload, path)

    monkeypatch.setattr(service, "publish", fail_activity)
    events = [row(1, NOW - 80), row(2, NOW - 60), row(3, NOW - 20)]
    with pytest.raises(service.SudoServiceError):
        service.run_once(cfg, now=NOW, records=events)
    assert counts(repo) == (1, 1, 1)
    assert (
        read_integration(cfg.sudo_public_directory / "sudo-integration.json", now=NOW)["state"]
        == "error"
    )
    monkeypatch.setattr(service, "publish", original)
    service.run_once(cfg, now=NOW + 60, records=events)
    assert counts(repo) == (1, 1, 1)


def test_duplicate_job_cannot_overwrite_another_jobs_ready_marker(installed):
    cfg, repo = installed
    service.arm(cfg, now=NOW - 100)
    service.run_once(cfg, now=NOW, records=[])
    path = cfg.sudo_public_directory / "sudo-integration.json"
    before = path.read_bytes()
    with (cfg.sudo_database_path.parent / "sudo-service.lock").open() as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        with pytest.raises(service.SudoServiceError, match="already running"):
            service.run_once(cfg, now=NOW + 60, records=[])
    assert path.read_bytes() == before


def test_failure_marker_is_published_while_whole_job_lock_remains_held(installed, monkeypatch):
    cfg, repo = installed
    service.arm(cfg, now=NOW - 100)
    original = service.publish
    observed = []

    def publish(payload, path):
        if payload.get("rules", {}).get("state") == "error":
            with (cfg.sudo_database_path.parent / "sudo-service.lock").open() as lock:
                with pytest.raises(BlockingIOError):
                    fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            observed.append(True)
        return original(payload, path)

    monkeypatch.setattr(service, "publish", publish)
    with pytest.raises(service.SudoServiceError):
        service.run_once(cfg, now=NOW, records=[{"invalid": True}])
    assert observed == [True]
