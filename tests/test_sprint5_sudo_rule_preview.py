"""Read-only sudo candidate preview never exposes private log fields."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

DEPLOY = Path(__file__).resolve().parents[1] / "deploy"
SCRIPT = DEPLOY / "sprint5_sudo_rule_preview.py"
BOOT = "f" * 32


@pytest.fixture(scope="module")
def preview():
    sys.path.insert(0, str(DEPLOY))
    try:
        spec = importlib.util.spec_from_file_location("sprint5_sudo_rule_preview", SCRIPT)
        assert spec and spec.loader
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        return module
    finally:
        sys.path.remove(str(DEPLOY))


def records():
    types = [
        " labuser : TTY=pts/0 ; PWD=/secret ; USER=root ; COMMAND=/usr/bin/id --token=x",
        "pam_unix(sudo:session): session opened for user root(uid=0) by labuser(uid=1000)",
        "pam_unix(sudo:session): session closed for user root",
        "pam_unix(sudo:auth): authentication failure; logname=labuser",
        "pam_unix(sudo:auth): authentication failure; logname=labuser",
        "pam_unix(sudo:auth): authentication failure; logname=labuser",
        "labuser is not in the sudoers file. This incident will be reported.",
    ]
    return [
        {
            "_EXE": "/usr/bin/sudo",
            "_COMM": "sudo",
            "_UID": "1000",
            "_PID": str(2010 + index),
            "_BOOT_ID": BOOT,
            "__CURSOR": f"cursor-private-{index}",
            "__REALTIME_TIMESTAMP": str(1793500000000000 + index * 1_000_000),
            "MESSAGE": message,
        }
        for index, message in enumerate(types)
    ]


def test_aggregate_offline_preview_reports_only_safe_counts(preview):
    output = preview.evaluate(records())
    assert output["journal_rows_seen"] == 7
    assert output["parsed_sudo_rows"] == 7
    assert output["malformed_or_incomplete_metadata"] == 0
    assert output["sudo_categories"]["command_invoked"] == 1
    assert output["candidate_rule_matches"]["sudo.repeated_auth_failure"] == 1
    assert output["candidate_rule_matches"]["sudo.permission_denied"] == 1
    assert output["source_contains_no_verified_attack_examples"] is False
    assert output["production_sudo_detection_active"] is False
    assert output["sqlite_or_services_modified"] is False
    text = json.dumps(output)
    for private in ("labuser", "/secret", "--token", "cursor-private", "2010"):
        assert private not in text


def test_existing_normal_journal_types_produce_zero_matches(preview):
    input_records = records()[:3]
    # Replay the final record at the same timestamp; it must not raise a finding.
    input_records.append(input_records[-1])
    output = preview.evaluate(input_records)
    assert output["candidate_rule_matches"] == {
        "sudo.repeated_auth_failure": 0,
        "sudo.permission_denied": 0,
    }
    assert output["source_contains_no_verified_attack_examples"] is True


def test_replay_aborts_on_invalid_metadata_order(preview):
    rows = records()
    with pytest.raises(ValueError, match="chronological"):
        preview.evaluate(list(reversed(rows)))


def test_replay_aborts_when_too_many_records(preview, monkeypatch):
    monkeypatch.setattr(preview, "MAX_PREVIEW_ROWS", 2)
    with pytest.raises(ValueError, match="Bounded"):
        preview.evaluate(records())


def test_cli_uses_fake_records_and_does_not_print_private_information(
    preview, monkeypatch, capsys
):
    def fake_journal(since):
        assert since == "2026-10-22 00:00:00"
        yield from records()

    monkeypatch.setattr(preview, "read_journal", fake_journal)
    assert preview.main([]) == 0
    output = capsys.readouterr().out
    assert "labuser" not in output
    assert "--token" not in output
    assert json.loads(output)["parsed_sudo_rows"] == 7
