"""Private Sprint 5 sudo staging DB: bounded data, dedup and atomic candidate writes."""

from __future__ import annotations

import json
import sqlite3
import stat
from dataclasses import replace

import pytest

from yggdrasil_ids.sudo_rules import SudoRuleMatch, SudoSignal
from yggdrasil_ids.sudo_storage import SCHEMA_VERSION, SudoStagingStore, event_id

STAMP = 1793500000.0
BOOT = "a" * 32


def signal(index=1, *, kind="command_invoked", cursor=None, stamp=None):
    return SudoSignal(
        cursor=cursor or f"private-journal-cursor-{index}",
        timestamp=STAMP + index if stamp is None else stamp,
        boot_id=BOOT,
        uid="1000",
        pid=4000 + index,
        kind=kind,
    )


@pytest.fixture
def private_store(tmp_path):
    path = tmp_path / "private-sudo" / "sudo.sqlite3"
    store = SudoStagingStore(path)
    store.initialize()
    return store


def test_explicit_initialization_required_and_schema_is_separate(tmp_path):
    private = tmp_path / "sudo-private" / "sudo.sqlite3"
    production = tmp_path / "prod.sqlite3"
    production.write_bytes(b"existing-production-data-unchanged")
    store = SudoStagingStore(private)
    assert not private.parent.exists()
    with pytest.raises(RuntimeError, match="explicitly initialized"):
        store.append(signal())
    with pytest.raises(RuntimeError, match="explicitly initialized"):
        store.summary()
    assert not private.exists()
    store.initialize()
    assert stat.S_IMODE(private.parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(private.stat().st_mode) == 0o600
    with sqlite3.connect(private) as db:
        assert db.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION
        tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert "sudo_signals" in tables
    assert "sudo_candidates" in tables
    assert "events" not in tables
    assert "discord_outbox" not in tables
    assert production.read_bytes() == b"existing-production-data-unchanged"


def test_persist_normalized_events_without_raw_journal_or_names(private_store):
    item = signal(kind="command_invoked")
    assert private_store.append(item)
    assert not private_store.append(item)
    assert private_store.append(signal(2, kind="pam_session_opened"))
    assert private_store.append(signal(3, kind="pam_session_closed"))
    report = private_store.summary()
    assert report["persisted_log_rows"] == 3
    assert report["sudo_categories"]["command_invoked"] == 1
    assert report["sudo_categories"]["pam_session_opened"] == 1
    assert report["candidate_rule_matches"]["sudo.permission_denied"] == 0
    assert report["shares_production_database"] is False
    assert report["discord_alerts_sent"] is False
    serialized = json.dumps(report)
    assert "private-journal-cursor" not in serialized
    assert "1000" not in serialized
    assert "4001" not in serialized

    with sqlite3.connect(private_store.path) as db:
        columns = {row[1] for row in db.execute("PRAGMA table_info(sudo_signals)")}
        row = db.execute("SELECT event_id FROM sudo_signals ORDER BY timestamp LIMIT 1").fetchone()
        assert row[0] == event_id(item)
        assert not {"MESSAGE", "COMMAND", "raw_json", "cursor", "username"} & columns
        persisted_rows = [tuple(row) for row in db.execute("SELECT * FROM sudo_signals")]
        assert "private-journal-cursor" not in json.dumps(persisted_rows)


def test_candidate_insert_is_atomic_and_idempotent(private_store):
    item = signal(kind="not_in_sudoers")
    finding = SudoRuleMatch(
        detector_id="sudo.permission_denied",
        severity="medium",
        count=1,
        timestamp=item.timestamp,
    )
    assert private_store.append(item, finding)
    assert not private_store.append(item, finding)
    report = private_store.summary()
    assert report["persisted_log_rows"] == 1
    assert report["candidate_rule_matches"]["sudo.permission_denied"] == 1
    assert report["production_sudo_detector_active"] is False

    other = signal(2, kind="pam_auth_failure")
    wrong_timestamp = replace(finding, timestamp=other.timestamp + 1)
    with pytest.raises(ValueError, match="candidate"):
        private_store.append(other, wrong_timestamp)
    assert private_store.summary()["persisted_log_rows"] == 1

    with sqlite3.connect(private_store.path) as db:
        db.execute("""
            CREATE TRIGGER abort_candidates BEFORE INSERT ON sudo_candidates
            BEGIN SELECT RAISE(ABORT, 'simulated storage failure'); END
        """)
    new = signal(3, kind="not_in_sudoers")
    with pytest.raises(sqlite3.IntegrityError):
        private_store.append(new, replace(finding, timestamp=new.timestamp))
    assert private_store.summary()["persisted_log_rows"] == 1


def test_conflicting_event_data_with_same_cursor_is_rejected(private_store):
    first = signal(kind="pam_session_opened")
    assert private_store.append(first)
    with pytest.raises(ValueError, match="Conflicting"):
        private_store.append(replace(first, kind="pam_session_closed"))
    assert private_store.summary()["persisted_log_rows"] == 1


def test_prune_removes_old_events_and_cascades_candidate_evidence(private_store):
    old = signal(1, kind="not_in_sudoers", stamp=STAMP)
    fresh = signal(2, kind="pam_session_opened", stamp=STAMP + 400)
    finding = SudoRuleMatch("sudo.permission_denied", "medium", 1, STAMP)
    private_store.append(old, finding)
    private_store.append(fresh)
    assert private_store.prune(STAMP + 1) == 1
    report = private_store.summary()
    assert report["persisted_log_rows"] == 1
    assert report["sudo_categories"]["pam_session_opened"] == 1
    assert report["candidate_rule_matches"]["sudo.permission_denied"] == 0
    assert private_store.prune(STAMP + 1) == 0


@pytest.mark.parametrize("invalid", [float("nan"), float("inf"), -1, True])
def test_invalid_retention_cutoff_fails_safely(private_store, invalid):
    private_store.append(signal())
    with pytest.raises(ValueError, match="cutoff"):
        private_store.prune(invalid)
    assert private_store.summary()["persisted_log_rows"] == 1


def test_invalid_signal_and_unrecognized_candidate_are_rejected(private_store):
    bad_uid = replace(signal(), uid="-1")
    with pytest.raises(ValueError):
        private_store.append(bad_uid)
    bad_time = replace(signal(), timestamp=float("nan"))
    with pytest.raises(ValueError):
        private_store.append(bad_time)
    bad_pid = replace(signal(), pid=True)
    with pytest.raises(ValueError):
        private_store.append(bad_pid)
    disallowed = SudoRuleMatch("ssh.failed_burst", "medium", 1, STAMP + 1)
    with pytest.raises(ValueError):
        private_store.append(signal(), disallowed)
    assert private_store.summary()["persisted_log_rows"] == 0


def test_insecure_parent_dir_rejected_before_db_creation(tmp_path):
    directory = tmp_path / "unsafe"
    directory.mkdir(mode=0o700)
    directory.chmod(0o755)
    store = SudoStagingStore(directory / "sudo.sqlite3")
    with pytest.raises(PermissionError, match="private"):
        store.initialize()
    assert not store.path.exists()


def test_symlinked_database_does_not_touch_target(tmp_path):
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    target = tmp_path / "victim"
    target.write_bytes(b"never-touch")
    (private / "sudo.sqlite3").symlink_to(target)
    store = SudoStagingStore(private / "sudo.sqlite3")
    with pytest.raises((OSError, PermissionError)):
        store.initialize()
    assert target.read_bytes() == b"never-touch"


def test_future_schema_rejected_without_overwriting_existing_private_db(tmp_path):
    directory = tmp_path / "state"
    directory.mkdir(mode=0o700)
    path = directory / "sudo.sqlite3"
    with sqlite3.connect(path) as db:
        db.execute("CREATE TABLE sentinel(message TEXT)")
        db.execute("INSERT INTO sentinel VALUES('preserve me')")
        db.execute("PRAGMA user_version=99")
    path.chmod(0o600)
    store = SudoStagingStore(path)
    with pytest.raises(ValueError, match="Unsupported"):
        store.initialize()
    with sqlite3.connect(path) as db:
        assert db.execute("SELECT message FROM sentinel").fetchone() == ("preserve me",)


def test_explicit_store_reopen_preserves_dedup(private_store):
    original = signal()
    assert private_store.append(original)
    another = SudoStagingStore(private_store.path)
    another.initialize()
    assert not another.append(original)
    assert another.summary()["persisted_log_rows"] == 1


def test_checkpoint_starts_unset_and_tracks_only_committed_max_timestamp(private_store):
    assert private_store.resume_since(300) is None
    later = signal(5, stamp=STAMP + 1000)
    earlier = signal(6, stamp=STAMP + 900)
    assert private_store.append(later)
    assert private_store.append(earlier)
    assert private_store.resume_since(300) == pytest.approx(STAMP + 699)
    # Repeated input must not change the timestamp-only checkpoint.
    assert not private_store.append(later)
    assert private_store.resume_since(300) == pytest.approx(STAMP + 699)

    with sqlite3.connect(private_store.path) as db:
        columns = {row[1] for row in db.execute("PRAGMA table_info(sudo_checkpoint)")}
        assert columns == {"id", "last_committed_timestamp"}
        row = db.execute("SELECT last_committed_timestamp FROM sudo_checkpoint").fetchone()
    assert row == (STAMP + 1000,)


def test_checkpoint_survives_retention_and_reopen(private_store):
    initial = signal(1, stamp=STAMP)
    private_store.append(initial)
    assert private_store.prune(STAMP + 1) == 1
    assert private_store.summary()["persisted_log_rows"] == 0
    again = SudoStagingStore(private_store.path)
    again.initialize()
    assert again.resume_since(300) == pytest.approx(STAMP - 301)


def test_rejected_candidate_does_not_advance_checkpoint(private_store):
    initial = signal(1, stamp=STAMP)
    assert private_store.append(initial)
    with sqlite3.connect(private_store.path) as db:
        db.executescript(
            """
            CREATE TRIGGER deny_test_candidate BEFORE INSERT ON sudo_candidates
            BEGIN SELECT RAISE(ABORT, 'offline injected failure'); END;
            """
        )

    later = signal(3, kind="not_in_sudoers", stamp=STAMP + 100)
    finding = SudoRuleMatch("sudo.permission_denied", "medium", 1, later.timestamp)
    with pytest.raises(sqlite3.IntegrityError):
        private_store.append(later, finding)
    assert private_store.summary()["persisted_log_rows"] == 1
    assert private_store.resume_since(300) == pytest.approx(STAMP - 301)


@pytest.mark.parametrize("overlap", [59, 7201, True, -1, 1.5, float("nan")])
def test_restart_overlap_must_be_explicitly_bounded(private_store, overlap):
    with pytest.raises(ValueError, match="overlap"):
        private_store.resume_since(overlap)


def test_schema_v1_is_migrated_in_place_with_reconstructed_checkpoint(tmp_path):
    directory = tmp_path / "private"
    directory.mkdir(mode=0o700)
    path = directory / "sudo.sqlite3"
    old = signal(1, stamp=STAMP + 10)
    with sqlite3.connect(path) as db:
        db.execute(
            "CREATE TABLE sudo_signals ("
            "event_id TEXT PRIMARY KEY,timestamp REAL NOT NULL,kind TEXT NOT NULL,"
            "boot_id TEXT NOT NULL,uid TEXT NOT NULL,pid INTEGER NOT NULL)"
        )
        db.execute(
            "INSERT INTO sudo_signals VALUES(?,?,?,?,?,?)",
            (event_id(old), old.timestamp, old.kind, old.boot_id, old.uid, old.pid),
        )
        db.execute("PRAGMA user_version=1")
    path.chmod(0o600)

    migrated = SudoStagingStore(path)
    migrated.initialize()
    assert migrated.resume_since(300) == pytest.approx(STAMP + 10 - 301)
    assert migrated.summary()["persisted_log_rows"] == 1
    with sqlite3.connect(path) as db:
        assert db.execute("PRAGMA user_version").fetchone() == (SCHEMA_VERSION,)
        assert db.execute("SELECT kind FROM sudo_signals").fetchone() == ("command_invoked",)


def test_singleton_checkpoint_is_not_raw_journal_cursor(private_store):
    item = signal(cursor="PRIVATE-RAW-CURSOR-AND-COMMAND")
    private_store.append(item)
    with sqlite3.connect(private_store.path) as db:
        column_names = {row[1] for row in db.execute("PRAGMA table_info(sudo_checkpoint)")}
        assert "cursor" not in column_names
    assert b"PRIVATE-RAW-CURSOR-AND-COMMAND" not in private_store.path.read_bytes()
