"""Experimental SSH ML bootstrap: real benign features stay private and unactivated."""

from __future__ import annotations

import importlib.util
import json
import sqlite3
from pathlib import Path

import pytest

from yggdrasil_ids.config import MLConfig
from yggdrasil_ids.features import FEATURE_NAMES
from yggdrasil_ids.lab import evaluate_lab, generate_lab, prepare_rows

DEPLOY = Path(__file__).resolve().parents[1] / "deploy"


def script(name: str):
    spec = importlib.util.spec_from_file_location(name, DEPLOY / f"{name}.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def synthetic_lab(tmp_path_factory):
    directory = tmp_path_factory.mktemp("experimental-ml-lab")
    generate_lab(directory, anchor=1_793_480_000)
    evaluate_lab(directory, ml=MLConfig(n_estimators=16))
    return directory


def sample_real_rows(synthetic_lab, count=15):
    # Reuse known benign held-out rows as synthetic *stand-ins* for a real Pi
    # export. Their provenance is test-only; no private Pi data in repository.
    base = prepare_rows(synthetic_lab / "train.jsonl")
    sample = [row for row in base[:count]]
    return {
        "kind": "private_real_ssh_normal_candidates",
        "feature_names": list(FEATURE_NAMES),
        "window_seconds": 300,
        "all_authentication_event_count": count,
        "candidate_success_rows": count,
        "rows": sample,
        "timestamps": [1_793_000_000 + 100 * i for i in range(count)],
        "reviewed_as_normal": False,
    }


def test_readonly_export_filters_only_success_and_omits_identifiers():
    exporter = script("sprint4_real_ml_export")
    db = sqlite3.connect(":memory:")
    db.executescript(
        "CREATE TABLE events(event_id TEXT, timestamp REAL, source_ip TEXT,"
        "username TEXT, outcome TEXT);"
        "CREATE TABLE observations(event_id TEXT, state TEXT, features TEXT);"
    )
    benign = {
        "failed_count": 0.0,
        "success_count": 1.0,
        "unique_users": 1.0,
        "failure_ratio": 0.0,
        "hour_sin": 0.0,
        "hour_cos": 1.0,
    }
    db.execute(
        "INSERT INTO events VALUES(?,?,?,?,?)",
        ("one", 123.0, "192.0.2.55", "labadmin", "success"),
    )
    db.execute(
        "INSERT INTO observations VALUES(?,?,?)",
        ("one", "untrained", json.dumps(benign)),
    )
    db.execute(
        "INSERT INTO events VALUES(?,?,?,?,?)",
        ("two", 124.0, "192.0.2.55", "labadmin", "failure"),
    )
    db.execute(
        "INSERT INTO observations VALUES(?,?,?)",
        ("two", "untrained", json.dumps(benign)),
    )
    original_dump = list(db.iterdump())
    result = exporter.export(db)
    assert result["candidate_success_rows"] == 1
    assert len(result["rows"]) == 1
    assert result["reviewed_as_normal"] is False
    assert "192.0.2.55" not in json.dumps(result)
    assert "labadmin" not in json.dumps(result)
    assert list(db.iterdump()) == original_dump
    db.close()


def test_experimental_model_trains_privately_and_only_from_normal_rows(synthetic_lab, tmp_path):
    trainer = script("sprint4_hybrid_ml_preview")
    real = sample_real_rows(synthetic_lab)
    private = tmp_path / "candidates.json"
    private.write_text(json.dumps(real))
    destination = tmp_path / "private-experiment"
    result = trainer.build_preview(synthetic_lab, private, destination)
    assert result["synthetic_train_rows"] == 312
    assert result["real_train_rows"] == 10
    assert result["real_heldout_rows"] == 5
    assert result["production_model_activated"] is False
    assert Path(result["candidate_model_file"]).is_file()
    assert destination.stat().st_mode & 0o777 == 0o700
    assert (destination / "candidate-model.json").stat().st_mode & 0o777 == 0o640
    report = json.loads((destination / "preview.json").read_text())
    assert report["synthetic_heldout_test_rows"] == 41
    assert report["model"]["sample_count"] == 322
    assert report["real_candidate_heldout_rows"] == 5
    assert "192.0.2." not in json.dumps(report)
    assert "labadmin" not in json.dumps(report)
    with pytest.raises(FileExistsError):
        trainer.build_preview(synthetic_lab, private, destination)


def test_bootstrap_requires_owner_approval_and_never_writes_without_it(
    synthetic_lab, tmp_path, capsys
):
    trainer = script("sprint4_hybrid_ml_preview")
    path = tmp_path / "real.json"
    path.write_text(json.dumps(sample_real_rows(synthetic_lab)))
    output = tmp_path / "no-approval"
    status = trainer.main(
        [
            "--lab-directory",
            str(synthetic_lab),
            "--real-candidates",
            str(path),
            "--output-directory",
            str(output),
        ]
    )
    assert status == 2
    assert not output.exists()
    assert "approval" in capsys.readouterr().err


def test_training_rejects_tampered_lab_and_short_real_sample(synthetic_lab, tmp_path):
    trainer = script("sprint4_hybrid_ml_preview")
    data = sample_real_rows(synthetic_lab, count=3)
    path = tmp_path / "real.json"
    path.write_text(json.dumps(data))
    with pytest.raises(ValueError, match="Insufficient"):
        trainer._validated_real(path)
    lab_report = json.loads((synthetic_lab / "report.json").read_text())
    assert lab_report["kind"] == "synthetic_laboratory"
    assert trainer._check_lab(synthetic_lab)[0]


def test_real_export_rejects_mixed_malformed_features():
    exporter = script("sprint4_real_ml_export")
    db = sqlite3.connect(":memory:")
    db.executescript(
        "CREATE TABLE events(event_id TEXT, timestamp REAL, outcome TEXT);"
        "CREATE TABLE observations(event_id TEXT, state TEXT, features TEXT);"
    )
    db.execute("INSERT INTO events VALUES('id',123,'success')")
    db.execute("INSERT INTO observations VALUES('id','untrained','{}')")
    with pytest.raises(ValueError, match="schema"):
        exporter.export(db)
