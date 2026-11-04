"""Bounded live exports are consistent, private and atomic for the web reader."""

import json
import sqlite3

import pytest

from tests.sudo_helpers import NOW, row
from yggdrasil_ids import sudo_collector as collector
from yggdrasil_ids.sudo_dashboard import read_activity, read_summary
from yggdrasil_ids.sudo_export import build_activity, build_summary, publish
from yggdrasil_ids.sudo_rules import SudoRuleMatch, parse_sudo
from yggdrasil_ids.sudo_storage import SudoStagingStore


@pytest.fixture
def source(tmp_path, monkeypatch):
    monkeypatch.setattr(collector, "_require_worker", lambda: None)
    path = tmp_path / "private" / "sudo.sqlite3"
    events = [
        row(1, NOW - 80),
        row(1, NOW - 79, "summary"),
        row(2, NOW - 60),
        row(2, NOW - 59, "summary"),
        row(3, NOW - 20),
        row(3, NOW - 19, "summary"),
    ]
    collector.poll_once(path, now=NOW, records=events)
    return path


def test_public_snapshots_reconcile_log_counts_and_group_processes_without_identities(
    source, tmp_path
):
    summary, activity = build_summary(source, now=NOW), build_activity(source, now=NOW)
    assert summary["format"] == "sudo-status-v1" and activity["format"] == "sudo-activity-v1"
    assert summary["mode"] == activity["mode"] == "live"
    assert summary["source"] == activity["source"] == "worker_owned_private_sudo"
    assert summary["recent_signals"] == 6
    assert summary["total_candidates"] == 1
    assert len(activity["latest"]) == 3
    assert activity["candidates"] == [
        {"timestamp": NOW - 20, "detector_id": "sudo.repeated_auth_failure", "process_count": 3}
    ]
    output = json.dumps([summary, activity])
    for private in ("private-user", "private-cursor", "MESSAGE", "boot_id", '"uid"', '"pid"'):
        assert private not in output
    public = tmp_path / "public"
    public.mkdir(mode=0o750)
    for name, data in (("sudo-status.json", summary), ("sudo-activity.json", activity)):
        publish(data, public / name)
    assert read_summary(public / "sudo-status.json", now=NOW)["state"] == "ready"
    assert read_activity(public / "sudo-activity.json", now=NOW)["state"] == "ready"


def test_rows_beyond_completed_checkpoint_do_not_enter_counts_or_latest(source):
    store = SudoStagingStore(source)
    store.initialize()
    signal = parse_sudo(row(20, NOW - 1, "denied")).signal
    store.append(signal, SudoRuleMatch("sudo.permission_denied", "medium", 1, NOW - 1))
    summary, activity = build_summary(source, now=NOW), build_activity(source, now=NOW)
    assert summary["total_signals"] == 6
    assert summary["total_candidates"] == 1
    assert len(activity["latest"]) == 3
    assert all(item["timestamp"] <= NOW - 2 for item in activity["latest"])


@pytest.mark.parametrize("changed", ["stale", "future", "schema", "mode"])
def test_unhealthy_private_source_cannot_be_published_as_fresh(source, changed):
    if changed == "mode":
        source.chmod(0o640)
    else:
        with sqlite3.connect(source) as db:
            if changed == "schema":
                db.execute("PRAGMA user_version=3")
            else:
                db.execute(
                    "UPDATE shadow_poll_checkpoint SET last_completed_until=?",
                    (NOW - 181 if changed == "stale" else NOW + 1,),
                )
    for build in (build_summary, build_activity):
        with pytest.raises((ValueError, PermissionError)):
            build(source, now=NOW)


def test_atomic_publication_rejects_bad_data_links_and_unknown_targets(tmp_path):
    public = tmp_path / "public"
    public.mkdir(mode=0o750)
    target = public / "sudo-status.json"
    publish({"valid": True}, target)
    assert target.stat().st_mode & 0o777 == 0o640
    previous = target.read_bytes()
    with pytest.raises(ValueError):
        publish({"bad": float("nan")}, target)
    assert target.read_bytes() == previous
    victim = tmp_path / "victim"
    victim.write_text("preserve")
    target.unlink()
    target.symlink_to(victim)
    with pytest.raises(PermissionError):
        publish({"bad": True}, target)
    assert victim.read_text() == "preserve"
    with pytest.raises(PermissionError):
        publish({}, public / "arbitrary.json")
