"""Causal, private, revisable snapshots from a pinned original sudo model."""

import fcntl
import hashlib
import json
import math
import os
import sqlite3

import pytest

from yggdrasil_ids.sudo_live_ml import build_ml_snapshot
from yggdrasil_ids.sudo_ml import SudoAttempt, SudoIsolationForest, feature_rows

BOOT = "b" * 32
CUTOFF = 1_793_700_000.0


@pytest.fixture(scope="module")
def frozen(tmp_path_factory):
    folder = tmp_path_factory.mktemp("sudo-live-model")
    folder.chmod(0o700)
    rows = []
    for i in range(120):
        count = float(i % 20 + 1)
        phase = 2 * math.pi * (i % 24) / 24
        rows.append([count, 0.0, 0.0, count, 0.0, math.sin(phase), math.cos(phase)])
    model = SudoIsolationForest.train(rows, "Private original-format live snapshot test fixture")
    path = folder / "model.json"
    model.save(path)
    path.chmod(0o400)
    return path, model, hashlib.sha256(path.read_bytes()).hexdigest()


def event(i, stamp, kind, pid=1001, uid="1000", boot=BOOT):
    return (f"{i:064x}", float(stamp), kind, boot, uid, pid)


def database(tmp_path, records, checkpoint=CUTOFF):
    folder = tmp_path / "private-source"
    folder.mkdir(mode=0o700)
    (folder / "shadow-poll.lock").touch(mode=0o600)
    path = folder / "sudo-shadow.sqlite3"
    with sqlite3.connect(path) as db:
        db.executescript(
            "PRAGMA user_version=2;"
            "CREATE TABLE sudo_signals(event_id TEXT PRIMARY KEY,timestamp REAL,kind TEXT,"
            "boot_id TEXT,uid TEXT,pid INTEGER);"
            "CREATE TABLE shadow_poll_checkpoint(id INTEGER PRIMARY KEY,last_completed_until REAL);"
        )
        db.execute("INSERT INTO shadow_poll_checkpoint VALUES(1,?)", (checkpoint,))
        db.executemany("INSERT INTO sudo_signals VALUES(?,?,?,?,?,?)", records)
    path.chmod(0o600)
    return path


def snapshot(path, frozen, **kwargs):
    model_path, model, sha = frozen
    return build_ml_snapshot(path, model_path, model.version, sha, now=CUTOFF + 2, **kwargs)


def test_snapshot_waits_for_poll_batch_instead_of_reading_partial_write(tmp_path, frozen):
    path = database(tmp_path, [event(1, CUTOFF - 10, "command_invoked")])
    with (path.parent / "shadow-poll.lock").open() as stream:
        fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        with pytest.raises(ValueError, match="source snapshot unavailable"):
            snapshot(path, frozen)
    assert snapshot(path, frozen)["total_scored"] == 1


def test_future_evidence_is_removed_before_process_coalescing(tmp_path, frozen):
    path = database(
        tmp_path,
        [
            event(1, CUTOFF - 10, "command_invoked"),
            # The collector may have staged newer rows without moving its checkpoint yet.
            event(2, CUTOFF + 1, "pam_auth_failure"),
            event(3, CUTOFF + 2, "not_in_sudoers", pid=1002),
        ],
    )
    result = snapshot(path, frozen)
    assert result["total_scored"] == 1
    assert result["latest"][0]["category"] == "command_logged"
    assert result["latest"][0]["timestamp"] == CUTOFF - 10
    expected = frozen[1].score(
        feature_rows([SudoAttempt(CUTOFF - 10, BOOT, "1000", 1001, "success")])[0]
    )
    assert result["latest"][0]["score"] == expected["score"]


def test_delayed_closing_record_changes_neither_time_nor_score(tmp_path, frozen):
    path = database(tmp_path, [event(1, CUTOFF - 60, "command_invoked")])
    first = snapshot(path, frozen)
    with sqlite3.connect(path) as db:
        db.execute(
            "INSERT INTO sudo_signals VALUES(?,?,?,?,?,?)",
            event(2, CUTOFF - 1, "pam_session_closed"),
        )
    assert snapshot(path, frozen) == first


def test_later_password_summary_revises_one_process_and_dependent_scores(tmp_path, frozen):
    path = database(
        tmp_path,
        [
            event(1, CUTOFF - 40, "pam_auth_failure"),
            event(2, CUTOFF - 20, "command_invoked", pid=1002),
        ],
    )
    first = snapshot(path, frozen)
    with sqlite3.connect(path) as db:
        db.execute(
            "INSERT INTO sudo_signals VALUES(?,?,?,?,?,?)",
            event(3, CUTOFF - 5, "incorrect_password"),
        )
    revised = snapshot(path, frozen)
    assert first["total_scored"] == revised["total_scored"] == 2
    assert revised["latest"][0]["category"] == "authentication_failed"
    assert revised["latest"][0]["timestamp"] == CUTOFF - 5
    expected = frozen[1].score_many(
        feature_rows(
            [
                SudoAttempt(CUTOFF - 20, BOOT, "1000", 1002, "success"),
                SudoAttempt(CUTOFF - 5, BOOT, "1000", 1001, "failure"),
            ]
        )
    )
    assert revised["latest"][0]["score"] == expected[1]["score"]
    assert revised["latest"][1]["score"] == expected[0]["score"]
    assert revised["latest"][1]["score"] != first["latest"][0]["score"]


def test_warmup_contributes_to_features_without_being_scored(tmp_path, frozen):
    path = database(
        tmp_path,
        [
            event(1, CUTOFF - 1000, "pam_auth_failure"),
            event(2, CUTOFF - 800, "command_invoked", pid=1002),
        ],
    )
    result = snapshot(path, frozen)
    assert result["total_scored"] == 1
    rows = feature_rows(
        [
            SudoAttempt(CUTOFF - 1000, BOOT, "1000", 1001, "failure"),
            SudoAttempt(CUTOFF - 800, BOOT, "1000", 1002, "success"),
        ]
    )
    assert rows[1][:5] == [2, 1, 0, 1, 0.5]
    assert result["latest"][0]["score"] == frozen[1].score(rows[1])["score"]


def test_repeated_snapshots_are_idempotent_bounded_and_public_safe(tmp_path, frozen):
    path = database(
        tmp_path,
        [event(i + 1, CUTOFF - 50 + i, "command_invoked", pid=1000 + i) for i in range(20)],
    )
    before = path.read_bytes()
    result = snapshot(path, frozen)
    assert snapshot(path, frozen) == result
    assert path.read_bytes() == before
    assert result["format"] == "sudo-ml-shadow-v1" and result["provisional"] is True
    assert result["total_scored"] == 20 and len(result["latest"]) == 15
    assert result["latest"][0]["timestamp"] > result["latest"][-1]["timestamp"]
    assert result["source_checkpoint"] == result["snapshot_cutoff"] == CUTOFF
    assert result["sends_alerts"] is False and result["shares_production_database"] is False
    assert result["anomalous"] <= result["total_scored"]
    assert all(
        set(row) == {"timestamp", "category", "score", "is_anomaly"} for row in result["latest"]
    )
    serialized = json.dumps(result, allow_nan=False)
    for private in (
        BOOT,
        str(path),
        "normal_training_rows",
        "event_id",
        '"uid"',
        '"pid"',
        "features",
    ):
        assert private not in serialized


def test_checkpoint_and_rows_share_one_read_transaction(tmp_path, frozen, monkeypatch):
    path = database(tmp_path, [event(1, CUTOFF - 10, "command_invoked")])
    connect = sqlite3.connect
    with connect(path) as db:
        # WAL permits a committed collector update while the scorer is reading.
        db.execute("PRAGMA journal_mode=WAL")
    updated = False

    class Row:
        def __init__(self, value):
            self.value = value

        def fetchone(self):
            return self.value

    class Connection(sqlite3.Connection):
        def execute(self, sql, *args, **kwargs):
            nonlocal updated
            cursor = super().execute(sql, *args, **kwargs)
            if sql.startswith("SELECT last_completed_until") and not updated:
                value = cursor.fetchone()
                cursor.close()
                with connect(path) as writer:
                    writer.execute(
                        "INSERT INTO sudo_signals VALUES(?,?,?,?,?,?)",
                        event(2, CUTOFF - 5, "command_invoked", pid=1002),
                    )
                    writer.execute(
                        "UPDATE shadow_poll_checkpoint SET last_completed_until=?", (CUTOFF + 1,)
                    )
                updated = True
                return Row(value)
            return cursor

    monkeypatch.setattr(
        "yggdrasil_ids.sudo_live_ml.sqlite3.connect",
        lambda *args, **kwargs: connect(*args, **kwargs, factory=Connection),
    )
    result = snapshot(path, frozen)
    assert updated is True
    assert result["source_checkpoint"] == CUTOFF and result["total_scored"] == 1
    with connect(path) as db:
        assert db.execute("SELECT COUNT(*) FROM sudo_signals").fetchone()[0] == 2


def test_ambiguous_pid_groups_are_skipped_without_manufacturing_attempts(tmp_path, frozen):
    path = database(
        tmp_path,
        [
            event(1, CUTOFF - 1000, "pam_auth_failure"),
            event(2, CUTOFF - 20, "incorrect_password"),
            event(3, CUTOFF - 30, "command_invoked", pid=1002),
            event(4, CUTOFF - 10, "command_invoked", pid=1002),
            event(5, CUTOFF - 5, "command_invoked", pid=1003),
        ],
    )
    result = snapshot(path, frozen)
    assert result["skipped_ambiguous_processes"] == 2
    assert result["total_scored"] == 1


def test_source_row_bound_and_invalid_normalized_evidence_are_sanitized(tmp_path, frozen):
    path = database(
        tmp_path,
        [event(i + 1, CUTOFF - 10, "command_invoked", pid=1000 + i) for i in range(3001)],
    )
    with pytest.raises(ValueError, match="^Private sudo ML source snapshot unavailable$"):
        snapshot(path, frozen)
    with sqlite3.connect(path) as db:
        db.execute("DELETE FROM sudo_signals")
        db.execute(
            "INSERT INTO sudo_signals VALUES(?,?,?,?,?,?)",
            event(1, CUTOFF - 1, "private-invalid-kind"),
        )
    with pytest.raises(ValueError, match="^Private sudo ML source snapshot unavailable$"):
        snapshot(path, frozen)


@pytest.mark.parametrize("checkpoint", [None, CUTOFF - 181, CUTOFF + 3, float("inf")])
def test_missing_stale_or_future_checkpoint_fails_safely(tmp_path, frozen, checkpoint):
    path = database(tmp_path, [event(1, CUTOFF - 1, "command_invoked")], checkpoint)
    with pytest.raises(ValueError, match="^Private sudo ML source snapshot unavailable$"):
        snapshot(path, frozen)


def test_fresh_empty_and_warmup_only_sources_are_valid_quiet_snapshots(tmp_path, frozen):
    path = database(tmp_path, [])
    result = snapshot(path, frozen)
    assert result["total_scored"] == result["anomalous"] == 0 and result["latest"] == []
    with sqlite3.connect(path) as db:
        db.execute(
            "INSERT INTO sudo_signals VALUES(?,?,?,?,?,?)",
            event(1, CUTOFF - 1000, "command_invoked"),
        )
    result = snapshot(path, frozen)
    assert result["total_scored"] == result["anomalous"] == 0 and result["latest"] == []


def test_frozen_hash_and_version_guards(tmp_path, frozen):
    path = database(tmp_path, [event(1, CUTOFF - 1, "command_invoked")])
    model_path, model, sha = frozen
    for version, digest in ((model.version, "0" * 64), ("sudo-if-" + "0" * 16, sha)):
        with pytest.raises(ValueError, match="^Frozen sudo ML model validation failed$"):
            build_ml_snapshot(path, model_path, version, digest, now=CUTOFF + 2)


@pytest.mark.parametrize("target", ["model", "source"])
def test_shared_or_symlinked_private_files_are_rejected(tmp_path, frozen, target):
    path = database(tmp_path, [event(1, CUTOFF - 1, "command_invoked")])
    model_path, model, sha = frozen
    if target == "source":
        path.chmod(0o640)
    else:
        folder = tmp_path / "model-copy"
        folder.mkdir(mode=0o700)
        copied = folder / "model.json"
        copied.write_bytes(model_path.read_bytes())
        copied.chmod(0o640)
        model_path = copied
    with pytest.raises(ValueError):
        build_ml_snapshot(path, model_path, model.version, sha, now=CUTOFF + 2)
    (path if target == "source" else model_path).chmod(0o600)
    symlink = (
        path.parent / "linked.sqlite3" if target == "source" else model_path.parent / "linked.json"
    )
    symlink.symlink_to(path if target == "source" else model_path)
    with pytest.raises(ValueError):
        build_ml_snapshot(
            symlink if target == "source" else path,
            symlink if target == "model" else model_path,
            model.version,
            sha,
            now=CUTOFF + 2,
        )


def test_corrupt_private_database_details_are_sanitized(tmp_path, frozen):
    path = database(tmp_path, [event(1, CUTOFF - 1, "command_invoked")])
    path.write_bytes(b"private corrupt contents and identities")
    with pytest.raises(ValueError) as exc:
        snapshot(path, frozen)
    assert str(exc.value) == "Private sudo ML source snapshot unavailable"
    assert str(path) not in str(exc.value)


def test_model_parent_must_be_private_even_when_file_is_private(tmp_path, frozen):
    path = database(tmp_path, [event(1, CUTOFF - 1, "command_invoked")])
    original, model, sha = frozen
    folder = tmp_path / "shared-model-parent"
    folder.mkdir(mode=0o755)
    copied = folder / "model.json"
    copied.write_bytes(original.read_bytes())
    copied.chmod(0o400)
    with pytest.raises(ValueError, match="Frozen sudo ML model validation failed"):
        build_ml_snapshot(path, copied, model.version, sha, now=CUTOFF + 2)


def test_model_and_source_must_belong_to_current_worker(tmp_path, frozen, monkeypatch):
    path = database(tmp_path, [event(1, CUTOFF - 1, "command_invoked")])
    current = os.geteuid()
    monkeypatch.setattr("yggdrasil_ids.sudo_live_ml.os.geteuid", lambda: current + 1)
    with pytest.raises(ValueError, match="Frozen sudo ML model validation failed"):
        snapshot(path, frozen)
