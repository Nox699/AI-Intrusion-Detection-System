"""Boundary, recovery and atomic delivery evidence for the opt-in sudo bridge."""

import fcntl
import importlib.util
import json
import sqlite3
from pathlib import Path

import pytest

from yggdrasil_ids.storage import Repository
from yggdrasil_ids.sudo_live_bridge import ARM_KEY, PROGRESS_KEY, arm_rules, forward_rules
from yggdrasil_ids.sudo_rules import SudoRuleMatch, SudoSignal
from yggdrasil_ids.sudo_storage import SudoStagingStore, event_id

NOW = 1_800_000_000.0
FAILURE = "sudo.repeated_auth_failure"


@pytest.fixture
def setup_bridge(tmp_path):
    repo = Repository(tmp_path / "production/events.sqlite3")
    repo.initialize()
    with repo.transaction() as db:
        repo.put_state(db, "mode", "live")
        repo.put_state(db, "namespace", "live")
    source = SudoStagingStore(tmp_path / "private/sudo-shadow.sqlite3")
    source.initialize()
    lock = source.path.parent / "shadow-poll.lock"
    lock.touch(mode=0o600)
    with sqlite3.connect(source.path) as db:
        db.execute(
            "CREATE TABLE shadow_poll_checkpoint(id INTEGER PRIMARY KEY,last_completed_until REAL)"
        )
        db.execute("INSERT INTO shadow_poll_checkpoint VALUES(1,?)", (NOW - 2,))
    return repo, source


def candidate(source, index, timestamp, count=3):
    signal = SudoSignal(
        f"private-cursor-{index}", timestamp, "a" * 32, "1000", 4000 + index, "incorrect_password"
    )
    source.append(signal, SudoRuleMatch(FAILURE, "medium", count, timestamp))
    return event_id(signal)


def counts(repo):
    with repo.reader() as db:
        return tuple(
            db.execute(f"SELECT COUNT(*) FROM {name}").fetchone()[0]
            for name in ("alerts", "sudo_evidence", "discord_outbox")
        )


def test_explicit_arm_skips_history_and_replays_without_duplicate_alarms(setup_bridge):
    repo, source = setup_bridge
    candidate(source, 1, NOW - 100)
    with pytest.raises(ValueError):
        forward_rules(repo, source.path, now=NOW)
    assert arm_rules(repo, now=NOW - 30) == NOW - 30
    assert arm_rules(repo, now=NOW - 10) == NOW - 30
    wanted = candidate(source, 2, NOW - 20)
    # Rows beyond the committed cutoff must wait for a subsequent poll.
    candidate(source, 3, NOW - 1)
    result = forward_rules(repo, source.path, now=NOW)
    assert result["rules"] == {"state": "active", "imported_total": 1, "message": ""}
    assert counts(repo) == (1, 1, 1)
    assert forward_rules(repo, source.path, now=NOW) == result
    assert counts(repo) == (1, 1, 1)
    with repo.reader() as db:
        assert db.execute("SELECT event_id FROM sudo_evidence").fetchone()[0] == wanted
        assert db.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 0
    assert "private-cursor" not in json.dumps(result)


def test_late_candidate_older_than_progress_is_not_lost(setup_bridge):
    repo, source = setup_bridge
    arm_rules(repo, now=NOW - 100)
    forward_rules(repo, source.path, now=NOW)
    candidate(source, 1, NOW - 50)
    result = forward_rules(repo, source.path, now=NOW + 10)
    assert result["rules"]["imported_total"] == 1
    assert counts(repo) == (1, 1, 1)


def test_bad_candidate_rolls_back_whole_batch_and_progress(setup_bridge):
    repo, source = setup_bridge
    arm_rules(repo, now=NOW - 100)
    candidate(source, 1, NOW - 50)
    candidate(source, 2, NOW - 40)
    with sqlite3.connect(source.path) as db:
        db.execute("UPDATE sudo_candidates SET process_count=0 WHERE timestamp=?", (NOW - 40,))
    with pytest.raises(ValueError):
        forward_rules(repo, source.path, now=NOW)
    assert counts(repo) == (0, 0, 0)
    assert repo.get_state(PROGRESS_KEY) is None


@pytest.mark.parametrize("age", [181, -1])
def test_stale_or_future_source_cannot_create_alarms(setup_bridge, age):
    repo, source = setup_bridge
    arm_rules(repo, now=NOW - 100)
    candidate(source, 1, NOW - 50)
    with sqlite3.connect(source.path) as db:
        db.execute("UPDATE shadow_poll_checkpoint SET last_completed_until=?", (NOW - age,))
    with pytest.raises(RuntimeError, match="stale or in the future"):
        forward_rules(repo, source.path, now=NOW)
    assert counts(repo) == (0, 0, 0)


def test_source_rollback_requires_recovery(setup_bridge):
    repo, source = setup_bridge
    arm_rules(repo, now=NOW - 100)
    forward_rules(repo, source.path, now=NOW)
    with sqlite3.connect(source.path) as db:
        db.execute("UPDATE shadow_poll_checkpoint SET last_completed_until=?", (NOW - 3,))
    with pytest.raises(RuntimeError, match="backwards"):
        forward_rules(repo, source.path, now=NOW)


def test_poll_in_progress_holds_forwarding_until_complete(setup_bridge):
    repo, source = setup_bridge
    arm_rules(repo, now=NOW - 100)
    candidate(source, 1, NOW - 50)
    with (source.path.parent / "shadow-poll.lock").open() as stream:
        fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        with pytest.raises(BlockingIOError):
            forward_rules(repo, source.path, now=NOW)
    assert counts(repo) == (0, 0, 0)
    assert forward_rules(repo, source.path, now=NOW)["rules"]["imported_total"] == 1


def test_schema4_or_demo_cannot_be_armed_or_migrated_by_bridge(setup_bridge):
    repo, source = setup_bridge
    with repo.transaction() as db:
        db.execute("PRAGMA user_version=4")
    with pytest.raises(RuntimeError, match="migration"):
        arm_rules(repo, now=NOW)
    with repo.reader() as db:
        assert db.execute("PRAGMA user_version").fetchone()[0] == 4
    repo.initialize()
    repo.set_state("namespace", "demo")
    with pytest.raises(RuntimeError, match="live"):
        arm_rules(repo, now=NOW)
    assert repo.get_state(ARM_KEY) is None


def test_expired_source_candidate_is_not_reimported_after_retention(setup_bridge):
    repo, source = setup_bridge
    arm_rules(repo, now=NOW - 2 * 86400)
    candidate(source, 1, NOW - 86401)
    candidate(source, 2, NOW - 60)
    result = forward_rules(repo, source.path, now=NOW, retention_seconds=86400)
    assert result["rules"]["imported_total"] == 1


@pytest.fixture
def poll_module():
    path = Path(__file__).parents[1] / "deploy/sprint5_sudo_integration_poll.py"
    spec = importlib.util.spec_from_file_location("sudo_integration_poll", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_model_failure_does_not_block_rules_or_expose_private_exception(
    setup_bridge, poll_module, monkeypatch
):
    repo, source = setup_bridge
    arm_rules(repo, now=NOW - 100)
    candidate(source, 1, NOW - 50)

    def fail(*args, **kwargs):
        raise ValueError("secret command private-username")

    monkeypatch.setattr(poll_module, "build_ml_snapshot", fail)
    result = poll_module.run_once(
        repo, source.path, Path("unused"), now=NOW, retention_seconds=86400
    )
    assert result["rules"]["state"] == "active"
    assert result["ml"]["state"] == "unavailable"
    assert counts(repo) == (1, 1, 1)
    assert "private-username" not in json.dumps(result)


@pytest.mark.parametrize("model_state", ["missing_file", "missing_directory", "corrupt_file"])
def test_actual_missing_or_corrupt_model_keeps_rule_delivery_idempotent(
    setup_bridge, poll_module, tmp_path, model_state
):
    repo, source = setup_bridge
    arm_rules(repo, now=NOW - 100)
    candidate(source, 1, NOW - 50)
    model = tmp_path / "model-private" / "mixed_full-model.json"
    if model_state != "missing_directory":
        model.parent.mkdir(mode=0o700)
    if model_state == "corrupt_file":
        model.write_text("private-training-data-corrupt")
        model.chmod(0o400)
    for _ in range(2):
        result = poll_module.run_once(repo, source.path, model, now=NOW, retention_seconds=86400)
        assert result["rules"]["state"] == "active"
        assert result["ml"]["state"] == "unavailable"
        assert counts(repo) == (1, 1, 1)
        assert "private-training-data" not in json.dumps(result)


def test_atomic_publication_rejects_symlink_and_preserves_previous_snapshot(tmp_path, poll_module):
    folder = tmp_path / "public"
    folder.mkdir(mode=0o750)
    target = folder / "sudo-integration.json"
    poll_module.publish(target, {"schema": "example"})
    assert target.stat().st_mode & 0o777 == 0o640
    previous = target.read_bytes()
    with pytest.raises(ValueError):
        poll_module.publish(target, {"invalid": float("nan")})
    assert target.read_bytes() == previous
    victim = tmp_path / "victim"
    victim.write_text("keep")
    target.unlink()
    target.symlink_to(victim)
    with pytest.raises(PermissionError):
        poll_module.publish(target, {})
    assert victim.read_text() == "keep"
