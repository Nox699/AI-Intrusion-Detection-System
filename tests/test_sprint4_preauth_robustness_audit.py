"""Reproducibility and safety controls for the isolated preauth stress audit."""

from __future__ import annotations

import hashlib
import importlib
import json
from pathlib import Path

import pytest

DEPLOY = Path(__file__).resolve().parents[1] / "deploy"


@pytest.fixture
def modules(monkeypatch):
    monkeypatch.syspath_prepend(str(DEPLOY))
    return (
        importlib.import_module("sprint4_preauth_ml_lab"),
        importlib.import_module("sprint4_preauth_robustness_audit"),
    )


def test_stress_records_are_fixed_and_have_independent_labels(modules):
    _, audit = modules
    records, labels = audit.make_records()
    records_again, labels_again = audit.make_records()
    assert records_again == records
    assert labels_again == labels
    assert len(labels) == len(records)
    assert len(records) > 4 * 112
    assert all("_UID" in record and record["_UID"] == "0" for record in records)
    assert all(record["_COMM"] == "sshd-session" for record in records)
    assert all(
        "192.0.2." in record["MESSAGE"] and "test@example.com" not in record["MESSAGE"]
        for record in records
    )
    assert all("expected" not in record and "scenario" not in record for record in records)
    assert {value[1] for value in labels.values()} == set(audit.HOURS_UTC)
    assert len(audit.cases()) == 11
    assert sum(len(case.steps) for case in audit.cases()) == 112


def test_model_and_original_lab_files_unchanged(tmp_path, modules):
    lab, audit = modules
    directory = tmp_path / "private-lab"
    lab.generate(directory)
    lab.evaluate(directory)

    filenames = (
        "train.jsonl",
        "validation.jsonl",
        "test.jsonl",
        "labels.json",
        "manifest.json",
        "report.json",
        "preauth-lab-model.json",
    )
    before = {
        filename: hashlib.sha256((directory / filename).read_bytes()).hexdigest()
        for filename in filenames
    }
    result = audit.analyse(directory)
    after = {
        filename: hashlib.sha256((directory / filename).read_bytes()).hexdigest()
        for filename in filenames
    }
    assert before == after
    assert result["model_retrained"] is False
    assert result["model_threshold_unchanged"] is True
    assert result["production_ids_changed"] is False
    assert result["files_written"] is False
    assert result["synthetic_scenario_labels_are_not_verified_attack_truth"] is True
    assert len(result["cases"]) == 11

    for hour in audit.HOURS_UTC:
        metric = result["per_utc_hour"][str(hour)]
        assert metric["candidates"] == 112
        for method in audit.METHODS:
            counts = metric[method]
            assert counts["tp"] + counts["fn"] == 69
            assert counts["tn"] + counts["fp"] == 43
        assert (
            result["opposite_label_identical_features"][
                "feature_vectors_identical_at_each_utc_hour"
            ][str(hour)]
            is True
        )

    by_name = {case["scenario"]: case for case in result["cases"]}
    benign = by_name["benign_connection_retry_storm"]
    suspicious = by_name["simulated_preauth_disconnect_surge"]
    for hour in audit.HOURS_UTC:
        assert (
            benign["first_detection_by_hour"][str(hour)]
            == suspicious["first_detection_by_hour"][str(hour)]
        )

    # The report includes aggregate counts, but no synthetic addresses or journal cursors.
    output = json.dumps(result)
    assert "192.0.2." not in output
    assert "__CURSOR" not in output
    assert "synthetic-fixed-stress-boot" not in output


def test_refuses_original_report_model_mismatch(tmp_path, modules):
    lab, audit = modules
    directory = tmp_path / "private-lab"
    lab.generate(directory)
    lab.evaluate(directory)
    path = directory / "report.json"
    report = json.loads(path.read_text(encoding="utf-8"))
    report["model"]["threshold"] += 0.01
    path.write_text(json.dumps(report), encoding="utf-8")
    with pytest.raises(ValueError, match="Existing model version or threshold changed"):
        audit.analyse(directory)
