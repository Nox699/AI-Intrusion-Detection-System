"""Behavioural checks for event-time windows and stable model input."""

import math
from dataclasses import replace
from datetime import datetime

import pytest

from yggdrasil_ids.domain import SSHEvent
from yggdrasil_ids.features import FEATURE_NAMES, SSHFeatureBuilder


def event(identifier, timestamp, outcome="failure", username="labuser", source="192.0.2.1"):
    return SSHEvent(identifier, timestamp, source, username, outcome, "publickey")


def test_window_excludes_boundary_future_and_other_source():
    anchor = event("now", 1000, "success")
    history = [
        event("boundary", 700),
        event("old", 699),
        event("inside", 701, username="guest"),
        event("another", 999, username="guest"),
        event("future", 1001),
        event("other-source", 950, source="198.51.100.2"),
        anchor,
    ]
    values = SSHFeatureBuilder(300).build(history, anchor)
    assert values[:4] == [2, 1, 2, 2 / 3]
    assert len(values) == len(FEATURE_NAMES)


def test_anchor_is_added_once_and_replay_order_does_not_change_features():
    anchor = event("b", 1200, "success")
    preceding = event("a", 1100)
    builder = SSHFeatureBuilder()
    expected = builder.build([preceding], anchor)
    assert builder.build([anchor, preceding, preceding, anchor], anchor) == expected
    assert expected[:4] == [1, 1, 1, 0.5]


def test_no_raw_ip_username_or_identifier_becomes_numeric_feature():
    anchor = event("a", 1200, username="<img src=x>", source="2001:db8::1")
    builder = SSHFeatureBuilder()
    renamed = replace(anchor, username="anything-else", source_ip="198.51.100.8", event_id="new")
    assert builder.build([anchor], anchor) == builder.build([renamed], renamed)


def test_conflicting_duplicate_id_is_not_silently_counted():
    anchor = event("same", 1200)
    conflicting = replace(anchor, outcome="success")
    with pytest.raises(ValueError, match="modstridende"):
        SSHFeatureBuilder().build([anchor, conflicting], anchor)


def test_time_features_use_absolute_utc_even_during_dst_fallback():
    summer = datetime.fromisoformat("2026-10-25T02:30:00+02:00").timestamp()
    winter = datetime.fromisoformat("2026-10-25T02:30:00+01:00").timestamp()
    builder = SSHFeatureBuilder()
    before = builder.build([], event("summer", summer))
    after = builder.build([], event("winter", winter))
    assert winter - summer == 3600
    assert before[4:] != after[4:]
    assert before[4] == pytest.approx(math.sin(2 * math.pi * 0.5 / 24))
    assert after[4] == pytest.approx(math.sin(2 * math.pi * 1.5 / 24))


@pytest.mark.parametrize("seconds", [0, -1, 86401, True, 1.5, "300"])
def test_invalid_window_configuration_is_rejected(seconds):
    with pytest.raises(ValueError):
        SSHFeatureBuilder(seconds)


@pytest.mark.parametrize("timestamp", [float("nan"), float("inf"), -1, 253402300800])
def test_invalid_anchor_timestamp_is_rejected(timestamp):
    with pytest.raises(ValueError):
        SSHFeatureBuilder().build([], event("bad", timestamp))


def test_unknown_outcome_does_not_masquerade_as_success():
    with pytest.raises(ValueError, match="loginresultat"):
        SSHFeatureBuilder().build([], event("bad", 1200, "unknown"))
