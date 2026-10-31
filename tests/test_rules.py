"""Tests for threshold semantics, expected profiles and source separation."""

from dataclasses import replace

import pytest

from yggdrasil_ids.config import RulesConfig
from yggdrasil_ids.domain import SSHEvent
from yggdrasil_ids.rules import SSHRuleDetector


def event(number, *, timestamp=None, source="192.0.2.8", username="labuser", outcome="failure"):
    return SSHEvent(
        str(number),
        1000.0 + number if timestamp is None else timestamp,
        source,
        username,
        outcome,
        "publickey",
    )


def ids(findings):
    return {finding.detector_id for finding in findings}


def test_burst_appears_at_threshold_and_has_explanatory_evidence():
    detector = SSHRuleDetector(RulesConfig())
    history = [event(i) for i in range(5)]
    assert "ssh.failed_burst" not in ids(detector.detect(history[3], history[:4]))
    findings = detector.detect(history[4], history)
    assert ids(findings) == {"ssh.failed_burst"}
    finding = findings[0]
    assert finding.details["failure_count"] == 5
    assert finding.details["threshold"] == 5
    assert finding.details["event_ids"] == [str(i) for i in range(5)]
    assert finding.event_id == history[4].event_id


def test_exclusive_start_inclusive_end_and_no_future_events():
    detector = SSHRuleDetector(RulesConfig(failure_threshold=3))
    current = event(5, timestamp=1000)
    history = [event(1, timestamp=700), event(2, timestamp=701), current, event(6, timestamp=1001)]
    assert not detector.detect(current, history)
    history.append(event(4, timestamp=999))
    findings = detector.detect(current, history)
    assert findings[0].details["failure_count"] == 3
    assert set(findings[0].details["event_ids"]) == {"2", "4", "5"}


def test_duplicate_events_do_not_inflate_counts():
    detector = SSHRuleDetector(RulesConfig(failure_threshold=3))
    current = event(2)
    assert not detector.detect(current, [event(1), current, current, current])


def test_unrelated_source_and_successes_do_not_count_as_failures():
    detector = SSHRuleDetector(RulesConfig(failure_threshold=3))
    current = event(5)
    history = [event(1, source="192.0.2.9"), event(2, outcome="success"), current]
    assert not detector.detect(current, history)


def test_spray_counts_distinct_users_among_failures():
    detector = SSHRuleDetector(RulesConfig(failure_threshold=50, username_threshold=3))
    history = [
        event(1, username="one"),
        event(2, username="one"),
        event(3, username="two"),
        event(4, username="success-only", outcome="success"),
        event(5, username="three"),
    ]
    assert not detector.detect(history[2], history[:3])
    findings = detector.detect(history[-1], history)
    assert ids(findings) == {"ssh.user_spray"}
    assert findings[0].details["usernames"] == ["one", "three", "two"]
    assert findings[0].details["unique_users"] == 3


def test_success_does_not_retrigger_old_failure_burst():
    detector = SSHRuleDetector(RulesConfig())
    history = [event(i) for i in range(6)] + [event(7, outcome="success")]
    assert not detector.detect(history[-1], history)


def test_empty_baselines_disable_unexpected_login_rule():
    current = event(1, outcome="success", username="root")
    assert not SSHRuleDetector(RulesConfig()).detect(current, [current])


@pytest.mark.parametrize("address", ["192.0.2.8", "2001:db8::42"])
def test_configured_cidr_accepts_expected_source(address):
    config = RulesConfig(expected_sources=("192.0.2.0/24", "2001:db8::/32"))
    current = event(1, source=address, outcome="success")
    assert not SSHRuleDetector(config).detect(current, [current])


def test_unexpected_source_has_explicit_cause():
    detector = SSHRuleDetector(RulesConfig(expected_sources=("192.0.2.0/24",)))
    current = event(1, source="198.51.100.9", outcome="success")
    finding = detector.detect(current, [current])[0]
    assert finding.detector_id == "ssh.unexpected_success"
    assert finding.details["unexpected_source"] is True
    assert finding.details["unexpected_user"] is False
    assert "forventede adresser" in finding.reason


def test_user_and_source_profile_are_independent():
    detector = SSHRuleDetector(RulesConfig(expected_users=("labuser",)))
    current = event(1, source="2001:db8::44", outcome="success", username="root")
    finding = detector.detect(current, [current])[0]
    assert finding.details["unexpected_source"] is False
    assert finding.details["unexpected_user"] is True
    current = replace(current, username="labuser")
    assert not detector.detect(current, [current])


def test_successful_ssh_does_not_establish_a_new_baseline_automatically():
    detector = SSHRuleDetector(RulesConfig(expected_users=("labuser",)))
    first = event(1, outcome="success", username="root")
    second = event(2, outcome="success", username="root")
    assert ids(detector.detect(first, [first])) == {"ssh.unexpected_success"}
    assert ids(detector.detect(second, [first, second])) == {"ssh.unexpected_success"}


def test_separate_failure_and_spray_findings_preserve_detector_origin():
    history = [event(i, username=f"user{i}") for i in range(5)]
    findings = SSHRuleDetector(RulesConfig()).detect(history[-1], history)
    assert ids(findings) == {"ssh.failed_burst", "ssh.user_spray"}


def test_unsorted_history_is_still_event_time_based():
    history = [event(i) for i in range(5)]
    detector = SSHRuleDetector(RulesConfig())
    assert detector.detect(history[-1], list(reversed(history))) == detector.detect(
        history[-1], history
    )


def test_evidence_is_bounded_without_truncating_detection_counts():
    history = [event(i, username=f"user{i}") for i in range(100)]
    findings = SSHRuleDetector(RulesConfig()).detect(history[-1], history)
    for finding in findings:
        assert finding.details["failure_count"] == 100
        assert finding.details["unique_users"] == 100
        assert len(finding.details["event_ids"]) == 20
        assert len(finding.details["usernames"]) == 20


@pytest.mark.parametrize("name", ["window_seconds", "failure_threshold", "username_threshold"])
@pytest.mark.parametrize("value", [0, -1, True, 1.5])
def test_invalid_rule_thresholds_fail_early(name, value):
    # Direct constructor use should be as safe as the validated config loader.
    with pytest.raises(ValueError):
        SSHRuleDetector(RulesConfig(**{name: value}))
