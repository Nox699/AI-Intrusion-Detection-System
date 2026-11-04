"""Safety and threshold tests for the isolated sudo rule prototype."""

from __future__ import annotations

from dataclasses import replace

import pytest

from yggdrasil_ids.sudo_rules import (
    SudoRuleConfig,
    SudoRuleDetector,
    parse_sudo,
)

BOOT = "a" * 32
BASE = 1793500000000000


def journal(
    index: int,
    message: str,
    *,
    pid: int | None = None,
    uid: str = "1000",
    boot: str = BOOT,
    timestamp: int | None = None,
    exe: str = "/usr/bin/sudo",
):
    return {
        "_EXE": exe,
        "_COMM": "sudo",
        "_UID": uid,
        "_PID": str(index + 2000 if pid is None else pid),
        "_BOOT_ID": boot,
        "__CURSOR": f"sample-{index}",
        "__REALTIME_TIMESTAMP": str(BASE + index * 1_000_000 if timestamp is None else timestamp),
        "SYSLOG_IDENTIFIER": "sudo",
        "MESSAGE": message,
    }


def event(index, text, **kwargs):
    parsed = parse_sudo(journal(index, text, **kwargs))
    assert parsed.status == "event"
    assert parsed.signal is not None
    return parsed.signal


COMMAND = " labuser : TTY=pts/0 ; PWD=/home/labuser ; USER=root ; COMMAND=/usr/bin/id"
OPEN = "pam_unix(sudo:session): session opened for user root(uid=0) by labuser(uid=1000)"
CLOSE = "pam_unix(sudo:session): session closed for user root"
FAIL = "pam_unix(sudo:auth): authentication failure; logname=labuser uid=1000"
SUMMARY = " labuser : 2 incorrect password attempts ; TTY=pts/0"
DENIED = "labuser is not in the sudoers file. This incident will be reported."


def test_benign_sudo_command_and_sessions_do_not_trigger_rules():
    detector = SudoRuleDetector()
    signals = [
        event(1, COMMAND),
        event(2, OPEN),
        event(3, CLOSE),
        event(4, COMMAND),
    ]
    assert [signal.kind for signal in signals] == [
        "command_invoked",
        "pam_session_opened",
        "pam_session_closed",
        "command_invoked",
    ]
    assert all(detector.evaluate(signal) is None for signal in signals)


def test_three_distinct_failed_sudo_processes_in_five_minutes_trigger_once():
    detector = SudoRuleDetector()
    first = event(1, FAIL, pid=200)
    summary_same_process = event(2, SUMMARY, pid=200)
    second = event(3, FAIL, pid=201)
    third = event(4, FAIL, pid=202)
    fourth = event(5, FAIL, pid=203)
    assert detector.evaluate(first) is None
    assert detector.evaluate(summary_same_process) is None
    assert detector.evaluate(second) is None
    found = detector.evaluate(third)
    assert found is not None
    assert found.detector_id == "sudo.repeated_auth_failure"
    assert found.count == 3
    assert detector.evaluate(fourth) is None
    assert detector.evaluate(fourth) is None  # duplicate cursor does not add attempts


def test_window_boundary_prevents_old_failures_from_counting():
    detector = SudoRuleDetector()
    assert detector.evaluate(event(1, FAIL, timestamp=BASE)) is None
    assert detector.evaluate(event(2, FAIL, timestamp=BASE + 300_000_000)) is None
    assert detector.evaluate(event(3, FAIL, timestamp=BASE + 301_000_000)) is None
    finding = detector.evaluate(event(4, FAIL, timestamp=BASE + 302_000_000))
    assert finding is not None
    assert finding.count == 3


def test_unauthorized_sudo_attempt_reports_candidate_and_suppresses_repeats():
    detector = SudoRuleDetector()
    first = detector.evaluate(event(1, DENIED))
    assert first is not None
    assert first.detector_id == "sudo.permission_denied"
    assert first.severity == "medium"
    assert detector.evaluate(event(2, DENIED)) is None
    other = detector.evaluate(event(3, DENIED, uid="1001"))
    assert other is not None


def test_no_cross_user_or_cross_boot_failure_aggregation():
    detector = SudoRuleDetector()
    signals = [
        event(1, FAIL, uid="1000"),
        event(2, FAIL, uid="1001"),
        event(3, FAIL, uid="1000", boot="b" * 32),
        event(4, FAIL, uid="1001", boot="b" * 32),
    ]
    assert all(detector.evaluate(signal) is None for signal in signals)


def test_command_arguments_cannot_inject_failure_or_sudoers_denial():
    dangerous_command = COMMAND + " pam_unix(sudo:auth): authentication failure; not in sudoers"
    parsed = parse_sudo(journal(1, dangerous_command))
    assert parsed.status == "event"
    assert parsed.signal is not None
    assert parsed.signal.kind == "command_invoked"
    assert SudoRuleDetector().evaluate(parsed.signal) is None


def test_spoofed_tag_does_not_override_executable_metadata():
    fake = journal(1, FAIL, exe="/usr/bin/logger")
    assert parse_sudo(fake).status == "ignored"


@pytest.mark.parametrize(
    "field,bad",
    [
        ("_BOOT_ID", "fake"),
        ("_PID", "not-a-pid"),
        ("_UID", True),
        ("__CURSOR", ""),
        ("__REALTIME_TIMESTAMP", "-1"),
        ("MESSAGE", None),
        ("MESSAGE", "fake\nnot-in-sudoers"),
        ("MESSAGE", "a" * 17000),
    ],
)
def test_rejects_malformed_records(field, bad):
    record = journal(1, FAIL)
    record[field] = bad
    assert parse_sudo(record).status == "malformed"


def test_replay_rejects_out_of_order_or_conflicting_cursor():
    detector = SudoRuleDetector()
    first = event(2, OPEN)
    detector.evaluate(first)
    with pytest.raises(ValueError, match="chronological"):
        detector.evaluate(event(1, CLOSE))
    other = replace(first, kind="pam_session_closed")
    with pytest.raises(ValueError, match="Conflicting"):
        detector.evaluate(other)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"window_seconds": 0},
        {"failure_process_threshold": True},
        {"failure_process_threshold": 1},
        {"cooldown_seconds": -1},
        {"max_records": 2},
    ],
)
def test_configuration_is_bounded(kwargs):
    with pytest.raises(ValueError):
        SudoRuleConfig(**kwargs)


def test_replay_bounded_to_limit():
    detector = SudoRuleDetector(SudoRuleConfig(max_records=100))
    for index in range(100):
        detector.evaluate(event(index, OPEN))
    with pytest.raises(ValueError, match="record bound"):
        detector.evaluate(event(100, OPEN))
