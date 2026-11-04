"""Sudo UI exporter and consumer: privacy, integrity and fail-closed HTTP data."""

from __future__ import annotations

import json
import os
import sqlite3
import stat
import time

import pytest

from yggdrasil_ids.sudo_dashboard import (
    MAX_AGE,
    read_activity,
    read_summary,
    validate_summary,
)


@pytest.fixture(scope="module")
def exporter():
    from yggdrasil_ids import sudo_export

    return sudo_export


@pytest.fixture
def staging(tmp_path):
    private = tmp_path / "sudo-private"
    private.mkdir(mode=0o700)
    (private / "sudo-poll.lock").touch(mode=0o600)
    database = private / "sudo.sqlite3"
    now = time.time()
    with sqlite3.connect(database) as db:
        db.executescript(
            """
            PRAGMA user_version=2;
            CREATE TABLE sudo_signals (
              event_id TEXT PRIMARY KEY, timestamp REAL, kind TEXT,
              boot_id TEXT, uid TEXT, pid INTEGER
            );
            CREATE TABLE sudo_candidates (
              event_id TEXT, detector_id TEXT, timestamp REAL,
              severity TEXT, process_count INTEGER
            );
            CREATE TABLE shadow_poll_checkpoint (
              id INTEGER PRIMARY KEY, last_completed_until REAL
            );
            """
        )
        for idx, kind in enumerate(
            (
                "command_invoked",
                "pam_session_opened",
                "pam_session_closed",
                "pam_auth_failure",
                "incorrect_password",
            )
        ):
            db.execute(
                "INSERT INTO sudo_signals VALUES(?,?,?,?,?,?)",
                (f"cursor-hash-{idx}", now - 20, kind, "a" * 32, "1000", 1000 + idx),
            )
        db.execute(
            "INSERT INTO sudo_candidates VALUES(?,?,?,?,?)",
            ("cursor-hash-3", "sudo.repeated_auth_failure", now - 20, "medium", 3),
        )
        db.execute(
            "INSERT INTO shadow_poll_checkpoint VALUES(1,?)",
            (now - 2,),
        )
    database.chmod(0o600)
    public = tmp_path / "sudo-public"
    public.mkdir(mode=0o750)
    return database, public / "sudo-status.json", now


def test_exporter_only_publishes_anonymized_aggregates(exporter, staging):
    database, published, now = staging
    summary = exporter.build_summary(database, now=now)
    assert summary["format"] == "sudo-status-v1"
    assert summary["recent_signals"] == 5
    assert summary["categories"]["pam_auth_failure"] == 1
    assert summary["categories"]["incorrect_password"] == 1
    assert summary["candidate_detectors"]["sudo.repeated_auth_failure"] == 1
    exporter.publish(summary, published)
    assert stat.S_IMODE(published.stat().st_mode) == 0o640
    assert published.stat().st_uid == os.geteuid()
    encoded = published.read_text(encoding="utf-8")
    for secret in ("command_line", "MESSAGE", "uid", "pid", "cursor-hash"):
        assert secret not in encoded

    state = read_summary(published, now=now)
    assert state["state"] == "ready"
    assert state["recent_signals"] == 5
    assert state["recent_candidates"] == 1
    assert state["categories"]["command_invoked"] == 1
    assert state["checkpoint_at"] == pytest.approx(now - 2)


def test_recent_sudo_processes_and_rule_candidates_are_anonymous(exporter, staging):
    database, published, now = staging
    # Journald may record multiple messages for ONE sudo invocation.
    with sqlite3.connect(database) as db:
        db.execute(
            "INSERT INTO sudo_signals VALUES(?,?,?,?,?,?)",
            ("cursor-hash-more", now - 10, "pam_session_opened", "a" * 32, "1000", 1000),
        )
    activity = exporter.build_activity(database, now=now)
    assert activity["format"] == "sudo-activity-v1"
    assert activity["mode"] == "live"
    assert len(activity["latest"]) == 5
    assert activity["latest"][0]["category"] == "session_opened"
    assert len(activity["candidates"]) == 1
    assert activity["candidates"][0]["detector_id"] == "sudo.repeated_auth_failure"
    assert activity["candidates"][0]["process_count"] == 3
    assert any(row["attention"] == "rule_candidate" for row in activity["latest"])

    activity_file = published.with_name("sudo-activity.json")
    exporter.publish(activity, activity_file)
    assert read_activity(activity_file, now=now)["state"] == "ready"
    payload = json.loads(activity_file.read_text(encoding="utf-8"))
    for field in ("uid", "pid", "boot_id", "event_id", "cursor", "MESSAGE", "COMMAND"):
        assert field not in json.dumps(payload)
    assert set(payload["latest"][0]) == {"timestamp", "category", "attention", "detector_id"}


def test_candidate_remains_visible_when_later_normal_activity_fills_latest(exporter, staging):
    database, published, now = staging
    with sqlite3.connect(database) as db:
        for idx in range(18):
            db.execute(
                "INSERT INTO sudo_signals VALUES(?,?,?,?,?,?)",
                (
                    f"normal-{idx}",
                    now - 12 + idx / 3,
                    "command_invoked",
                    "a" * 32,
                    "1000",
                    2000 + idx,
                ),
            )
    activity = exporter.build_activity(database, now=now)
    assert len(activity["latest"]) == 15
    assert not any(row["attention"] == "rule_candidate" for row in activity["latest"])
    assert len(activity["candidates"]) == 1
    assert activity["candidates"][0]["detector_id"] == "sudo.repeated_auth_failure"
    exporter.publish(activity, published.with_name("sudo-activity.json"))


def test_sudo_activity_fails_closed_when_missing_stale_or_tampered(exporter, staging):
    database, published, now = staging
    activity_file = published.with_name("sudo-activity.json")
    assert read_activity(activity_file, now=now)["state"] == "unavailable"
    activity = exporter.build_activity(database, now=now)
    exporter.publish(activity, activity_file)
    assert read_activity(activity_file, now=now + MAX_AGE + 2)["state"] == "stale"
    activity["latest"][0]["category"] = "raw command /usr/bin/secret"
    activity_file.write_text(json.dumps(activity), encoding="utf-8")
    assert read_activity(activity_file, now=now)["state"] == "unavailable"
    activity_file.unlink()
    activity["latest"] = [{}] * 16
    exporter.publish(activity, activity_file)
    assert read_activity(activity_file, now=now)["state"] == "unavailable"


def test_unavailable_or_stale_export_never_claims_zero_or_healthy(exporter, staging):
    database, published, now = staging
    missing = read_summary(published, now=now)
    assert missing["state"] == "unavailable"
    assert "recent_signals" not in missing
    exporter.publish(exporter.build_summary(database, now=now), published)
    assert read_summary(published, now=now + MAX_AGE + 2)["state"] == "stale"
    published.write_text('{"not_a_real_sudo_summary":1}', encoding="utf-8")
    assert read_summary(published, now=now)["state"] == "unavailable"


def test_group_or_world_writable_or_symlinked_file_is_rejected(exporter, staging):
    database, published, now = staging
    exporter.publish(exporter.build_summary(database, now=now), published)
    published.chmod(0o666)
    assert read_summary(published, now=now)["state"] == "unavailable"
    published.chmod(0o640)
    link = published.parent / "status-link"
    link.symlink_to(published)
    assert read_summary(link, now=now)["state"] == "unavailable"
    with pytest.raises(PermissionError):
        exporter.publish(exporter.build_summary(database, now=now), published.parent / "wrong.json")


def test_summary_validator_rejects_nonproduction_mode_and_fake_counts(exporter, staging):
    database, _, now = staging
    summary = exporter.build_summary(database, now=now)
    summary["mode"] = "shadow"
    with pytest.raises(ValueError, match="provenance"):
        validate_summary(summary, now=now)
    summary["mode"] = "live"
    summary["recent_signals"] = 0
    with pytest.raises(ValueError, match="counts"):
        validate_summary(summary, now=now)


def test_exporter_refuses_private_database_with_loose_permissions(exporter, staging):
    database, _, now = staging
    database.chmod(0o644)
    with pytest.raises(PermissionError):
        exporter.build_summary(database, now=now)


def test_export_publishes_only_finite_bounded_json(exporter, staging):
    database, published, now = staging
    summary = exporter.build_summary(database, now=now)
    summary["recent_signals"] = float("inf")
    with pytest.raises(ValueError):
        exporter.publish(summary, published)
    assert not published.exists()
    valid = exporter.build_summary(database, now=now)
    exporter.publish(valid, published)
    payload = json.loads(published.read_text())
    assert payload["sends_alerts"] is False
    assert payload["shares_production_database"] is False
    assert "raw_commands" not in payload


@pytest.mark.parametrize("field", ["generated_at", "checkpoint_at"])
def test_future_summary_never_becomes_ready_after_clock_regression(exporter, staging, field):
    database, published, now = staging
    summary = exporter.build_summary(database, now=now)
    summary[field] = now + 30
    exporter.publish(summary, published)
    assert read_summary(published, now=now)["state"] == "unavailable"


def test_activity_after_its_source_checkpoint_is_rejected(exporter, staging):
    database, published, now = staging
    activity = exporter.build_activity(database, now=now)
    activity["latest"][0]["timestamp"] = now - 1
    path = published.with_name("sudo-activity.json")
    exporter.publish(activity, path)
    assert read_activity(path, now=now)["state"] == "unavailable"
