"""Production sudo collection: bounded private replay, failures and restart safety."""

import sqlite3

import pytest

from tests.sudo_helpers import NOW, row
from yggdrasil_ids import sudo_collector as collector
from yggdrasil_ids.sudo_rules import SudoRuleConfig


@pytest.fixture
def database(tmp_path, monkeypatch):
    # The executor is root-only. Replace only the entry guard for pure temporary
    # fixture calls; ownership, mode, lock and DB checks still use the real UID.
    monkeypatch.setattr(collector, "_require_worker", lambda: None)
    return tmp_path / "private" / "sudo.sqlite3"


def checkpoint(path):
    with sqlite3.connect(path) as db:
        return db.execute(
            "SELECT last_completed_until FROM shadow_poll_checkpoint WHERE id=1"
        ).fetchone()


def test_command_reads_trusted_sudo_across_all_journals():
    command = collector.journal_command(NOW - 60, NOW)
    assert "--all" in command and "--system" not in command
    assert command[-1] == "_EXE=/usr/bin/sudo"
    assert "--output=json" in command
    with pytest.raises(ValueError):
        collector.journal_command(NOW, NOW - 1)


def test_successful_sudo_and_restart_replay_have_no_candidates(database):
    rows = [row(1, NOW - 40, "success")]
    first = collector.poll_once(database, now=NOW, records=rows)
    second = collector.poll_once(database, now=NOW + 60, records=rows)
    assert first["new_normalized_sudo_rows"] == 1
    assert second["new_normalized_sudo_rows"] == 0
    assert second["overlap_duplicates_skipped"] == 1
    assert second["new_candidate_rule_matches"] == {
        "sudo.permission_denied": 0,
        "sudo.repeated_auth_failure": 0,
    }
    assert checkpoint(database)[0] == NOW + 58


def test_three_distinct_failure_processes_trigger_one_candidate_across_restarts(database):
    rows = [
        row(1, NOW - 80),
        row(1, NOW - 79, "summary"),
        row(2, NOW - 60),
        row(2, NOW - 59, "summary"),
    ]
    collector.poll_once(database, now=NOW - 40, records=rows)
    rows += [row(3, NOW - 20), row(3, NOW - 19, "summary")]
    result = collector.poll_once(database, now=NOW, records=rows)
    assert result["new_candidate_rule_matches"]["sudo.repeated_auth_failure"] == 1
    repeat = collector.poll_once(database, now=NOW + 60, records=rows)
    assert repeat["new_candidate_rule_matches"]["sudo.repeated_auth_failure"] == 0
    with sqlite3.connect(database) as db:
        assert db.execute("SELECT COUNT(*) FROM sudo_signals").fetchone()[0] == 6
        assert db.execute("SELECT process_count FROM sudo_candidates").fetchall() == [(3,)]


def test_empty_complete_poll_advances_checkpoint(database):
    collector.poll_once(database, now=NOW, records=[])
    collector.poll_once(database, now=NOW + 60, records=[])
    assert checkpoint(database) == (NOW + 58,)


def test_sustained_burst_keeps_persisted_cooldowns_as_replay_window_moves(database, monkeypatch):
    events = [row(i + 1, NOW + i * 60) for i in range(24)]

    def journal(since, until, **kwargs):
        return [
            event
            for event in events
            if since <= int(event["__REALTIME_TIMESTAMP"]) / 1_000_000 <= until
        ]

    monkeypatch.setattr(collector, "journal_records", journal)
    for offset in range(150, 1440, 60):
        collector.poll_once(database, now=NOW + offset)
    with sqlite3.connect(database) as db:
        timestamps = [
            item[0]
            for item in db.execute("SELECT timestamp FROM sudo_candidates ORDER BY timestamp")
        ]
    assert timestamps == [NOW + offset for offset in (120, 420, 720, 1020, 1320)]


def test_first_poll_uses_full_nondefault_rule_context(database, monkeypatch):
    events = [row(1, NOW - 1800), row(2, NOW - 1200), row(3, NOW - 20)]
    seen = []

    def journal(since, until, **kwargs):
        seen.append((since, until))
        return [
            event
            for event in events
            if since <= int(event["__REALTIME_TIMESTAMP"]) / 1_000_000 <= until
        ]

    monkeypatch.setattr(collector, "journal_records", journal)
    result = collector.poll_once(
        database, now=NOW, rule_config=SudoRuleConfig(window_seconds=3600, cooldown_seconds=3600)
    )
    assert seen[0][0] <= NOW - 7260
    assert result["new_candidate_rule_matches"]["sudo.repeated_auth_failure"] == 1


def test_poll_bounds_use_the_same_microseconds_as_journalctl(database, monkeypatch):
    def journal(since, until, **kwargs):
        return [row(1, until, "success")]

    monkeypatch.setattr(collector, "journal_records", journal)
    result = collector.poll_once(database, now=NOW + 0.1234567)
    assert result["new_normalized_sudo_rows"] == 1
    boundary = checkpoint(database)[0]
    assert float(f"{boundary:.6f}") == boundary


def test_interrupted_journal_never_saves_partial_rows_or_advances_boundary(database):
    collector.poll_once(database, now=NOW, records=[row(1, NOW - 20)])
    previous = checkpoint(database)

    def interrupted():
        yield row(2, NOW + 20)
        raise RuntimeError("private journal-reader error")

    with pytest.raises(RuntimeError):
        collector.poll_once(database, now=NOW + 60, records=interrupted())
    assert checkpoint(database) == previous
    with sqlite3.connect(database) as db:
        assert db.execute("SELECT COUNT(*) FROM sudo_signals").fetchone()[0] == 1


@pytest.mark.parametrize("problem", ["metadata", "future", "old", "out_of_order", "bound"])
def test_invalid_journal_snapshot_cannot_commit(database, monkeypatch, problem):
    events = [row(1, NOW - 20)]
    if problem == "metadata":
        events[0].pop("_BOOT_ID")
    if problem == "future":
        events = [row(1, NOW + 20)]
    if problem == "old":
        events = [row(1, NOW - 2000)]
    if problem == "out_of_order":
        events += [row(2, NOW - 30)]
    if problem == "bound":
        monkeypatch.setattr(collector, "MAX_ROWS", 1)
        events += [row(2, NOW - 10)]
    with pytest.raises(ValueError):
        collector.poll_once(database, now=NOW, records=events)
    assert checkpoint(database) is None
    with sqlite3.connect(database) as db:
        assert db.execute("SELECT COUNT(*) FROM sudo_signals").fetchone()[0] == 0


def test_outage_and_clock_regression_preserve_checkpoint(database):
    collector.poll_once(database, now=NOW, records=[])
    for stamp in (NOW - 10, NOW + collector.MAX_OUTAGE_SECONDS + 60):
        with pytest.raises(RuntimeError, match="Gap or clock"):
            collector.poll_once(database, now=stamp, records=[])
    assert checkpoint(database) == (NOW - 2,)


def test_changed_rule_settings_require_explicit_migration(database):
    collector.poll_once(database, now=NOW, records=[])
    with pytest.raises(RuntimeError, match="settings changed"):
        collector.poll_once(
            database,
            now=NOW + 60,
            records=[],
            rule_config=SudoRuleConfig(failure_process_threshold=4),
        )
    assert checkpoint(database) == (NOW - 2,)


def test_store_contains_no_raw_journal_command_or_cursor(database):
    collector.poll_once(database, now=NOW, records=[row(1, NOW - 20)])
    data = database.read_bytes()
    assert b"private-user" not in data and b"private-cursor" not in data
    assert b"pam_unix" not in data
    assert database.stat().st_mode & 0o777 == 0o600
    assert database.parent.stat().st_mode & 0o777 == 0o700


def test_root_entrypoint_has_no_side_effects(tmp_path, monkeypatch):
    monkeypatch.setattr(collector.os, "geteuid", lambda: 0)
    path = tmp_path / "private" / "sudo.sqlite3"
    with pytest.raises(PermissionError, match="unprivileged"):
        collector.poll_once(path, now=NOW, records=[])
    assert not path.parent.exists()


def test_lock_cannot_be_a_symlink_or_nonprivate_file(database):
    database.parent.mkdir(mode=0o700)
    victim = database.parent / "victim"
    victim.write_text("preserve")
    (database.parent / "sudo-poll.lock").symlink_to(victim)
    with pytest.raises(OSError):
        collector.poll_once(database, now=NOW, records=[])
    assert victim.read_text() == "preserve"
