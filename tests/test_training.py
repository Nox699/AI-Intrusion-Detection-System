"""Reviewed-input preparation keeps runtime feature semantics and bounded reads."""

import json

import pytest

from tests.factories import normal_journal_records
from yggdrasil_ids import training
from yggdrasil_ids.features import FEATURE_NAMES, SSHFeatureBuilder
from yggdrasil_ids.ssh import SSHParser


def write(path, records):
    path.write_text("\n".join(json.dumps(item) for item in records) + "\n")
    return path


def test_preparation_matches_runtime_features_without_touching_input(tmp_path):
    records = normal_journal_records(count=12)
    source = write(tmp_path / "reviewed-normal.jsonl", records)
    before = source.read_bytes()
    actual = training.prepare_rows(source)
    events = [SSHParser().parse(item, namespace="training").event for item in records]
    builder = SSHFeatureBuilder(300)
    assert actual == [builder.build(events, event) for event in events]
    assert len(actual) == 12
    assert all(len(row) == len(FEATURE_NAMES) for row in actual)
    assert source.read_bytes() == before


def test_context_rows_and_exact_authentication_duplicates_are_not_samples(tmp_path):
    records = normal_journal_records(count=4)
    context = {
        **records[0],
        "__CURSOR": "context",
        "MESSAGE": "pam_unix(sshd:session): session opened for user operator(uid=1000) by (uid=0)",
    }
    clean = write(tmp_path / "clean.jsonl", records)
    mixed = write(tmp_path / "mixed.jsonl", [context, records[0], records[0], *records[1:]])
    assert training.prepare_rows(mixed) == training.prepare_rows(clean)


def test_conflicting_identity_and_reversed_time_are_rejected(tmp_path):
    records = normal_journal_records(count=3)
    conflicting = {
        **records[0],
        "MESSAGE": "Failed password for changed from 192.0.2.10 port 54321 ssh2",
    }
    with pytest.raises(ValueError, match="modstridende"):
        training.prepare_rows(write(tmp_path / "conflict.jsonl", [records[0], conflicting]))
    with pytest.raises(ValueError, match="kronologisk"):
        training.prepare_rows(write(tmp_path / "reversed.jsonl", [records[1], records[0]]))


@pytest.mark.parametrize("data", [b"", b"\n", b"{broken}\n", b'{"bad":NaN}\n', b"[]\n"])
def test_empty_or_invalid_input_does_not_create_training_rows(tmp_path, data):
    source = tmp_path / "invalid.jsonl"
    source.write_bytes(data)
    with pytest.raises(ValueError):
        training.prepare_rows(source)


@pytest.mark.parametrize(
    "bound,value", [("MAX_LINE_BYTES", 12), ("MAX_INPUT_BYTES", 40), ("MAX_INPUT_RECORDS", 1)]
)
def test_file_line_and_record_bounds_fail_closed(tmp_path, monkeypatch, bound, value):
    source = write(tmp_path / "bounded.jsonl", normal_journal_records(count=4))
    monkeypatch.setattr(training, bound, value)
    with pytest.raises(ValueError, match="inputgrænse"):
        training.prepare_rows(source)
