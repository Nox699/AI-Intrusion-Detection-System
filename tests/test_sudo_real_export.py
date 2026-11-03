"""The real-data export keeps process context but excludes raw identities."""

import importlib.util
from pathlib import Path

import pytest


@pytest.fixture(scope="module")
def exporter():
    path = Path(__file__).resolve().parents[1] / "deploy" / "sudo_real_export.py"
    spec = importlib.util.spec_from_file_location("sudo_real_export", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def record(i, timestamp, message, pid=100, uid="1000"):
    return {
        "_EXE": "/usr/bin/sudo",
        "_UID": uid,
        "_PID": str(pid),
        "_BOOT_ID": "b" * 32,
        "__CURSOR": f"private-cursor-{i}",
        "__REALTIME_TIMESTAMP": str(int(timestamp * 1_000_000)),
        "MESSAGE": message,
    }


COMMAND = "private-user : TTY=pts/1 ; PWD=/private ; USER=root ; COMMAND=/secret-command"
FAILURE = "pam_unix(sudo:auth): authentication failure; user=private-user"


def test_process_deduplication_and_private_identifiers_not_exported(exporter):
    import json

    rows = [
        record(1, 1000, COMMAND),
        record(2, 1001, "pam_unix(sudo:session): session opened for user root"),
    ]
    report = exporter.aggregate(rows + rows[:1])
    assert report["process_count"] == 1 and report["source_rows_deduplicated"] == 2
    assert report["normal_candidates"] == 1
    serialized = json.dumps(report)
    for secret in ("private-user", "private-cursor", "secret-command", "_UID", "_PID", "_BOOT_ID"):
        assert secret not in serialized
    with pytest.raises(ValueError, match="Conflicting"):
        exporter.aggregate(rows + [record(1, 1002, COMMAND)])


def test_failure_context_excluded_but_failed_data_retained_for_review(exporter):
    report = exporter.aggregate(
        [
            record(1, 1000, COMMAND),
            record(2, 3000, FAILURE, 200, "997"),
            record(3, 3001, "private-user : 1 incorrect password attempt", 200, "997"),
            record(4, 3010, COMMAND, 300),
            record(5, 5000, COMMAND, 400),
        ]
    )
    assert report["process_count"] == 4
    assert report["outcomes"] == {"success": 3, "failure": 1}
    assert report["normal_candidates"] == 2
    assert [r["normal_candidate"] for r in report["processes"]] == [True, False, False, True]
    assert report["normal_labels_verified"] is False


def test_long_ambiguous_process_group_is_not_merged(exporter):
    report = exporter.aggregate([record(1, 100, COMMAND), record(2, 2000, COMMAND)])
    assert report["process_count"] == 0
    assert report["ambiguous_process_groups_skipped"] == 1


def test_failed_then_successful_same_process_requires_review(exporter):
    report = exporter.aggregate(
        [
            record(1, 1000, FAILURE),
            record(2, 1010, COMMAND),
            record(3, 1100, "pam_unix(sudo:session): session closed for user root"),
        ]
    )
    row = report["processes"][0]
    assert row["outcome"] == "failure" and row["also_had_success"] is True
    assert row["timestamp"] == 1010 and row["normal_candidate"] is False
