"""Read-only production readiness and synthetic lab integrity/evaluation checks."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import shutil
import sqlite3
from pathlib import Path

import pytest

from yggdrasil_ids.config import MLConfig
from yggdrasil_ids.lab import evaluate_lab, generate_lab

ROOT = Path(__file__).resolve().parents[1] / "deploy"


def load_script(name: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / f"{name}.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def lab(tmp_path_factory):
    directory = tmp_path_factory.mktemp("sprint4-synthetic")
    generate_lab(directory, anchor=1_793_480_000, seed=42)
    evaluate_lab(directory, ml=MLConfig(n_estimators=16))
    return directory


def test_synthetic_lab_verification_checks_actual_heldout_records(lab):
    verifier = load_script("sprint4_verify_lab")
    result = verifier.verify(lab)
    assert result["kind"] == "verified_synthetic_lab_only"
    assert result["production_model_activated"] is False
    assert result["training_rows"] == 312
    assert result["splits"]["validation"]["events"] == 44
    assert result["splits"]["test"]["events"] == 41
    assert result["comparisons"]["test"]["ml"]["total"] == 41
    assert result["comparisons"]["test"]["rules"]["total"] == 41
    assert result["comparisons"]["test"]["ml"]["tp"] >= 0
    assert "192.0.2." not in json.dumps(result)
    assert "198.51.100." not in json.dumps(result)


def test_synthetic_verifier_rejects_tampered_confusion_matrix(tmp_path, lab):
    verifier = load_script("sprint4_verify_lab")
    shutil.copytree(lab, tmp_path / "lab")
    folder = tmp_path / "lab"
    report = json.loads((folder / "report.json").read_text())
    report["test"]["ml"]["tp"] += 1
    (folder / "report.json").write_text(json.dumps(report))
    with pytest.raises(ValueError, match="Confusion matrix"):
        verifier.verify(folder)


def test_synthetic_verifier_rejects_changed_training_data(tmp_path, lab):
    verifier = load_script("sprint4_verify_lab")
    shutil.copytree(lab, tmp_path / "lab")
    folder = tmp_path / "lab"
    with (folder / "train.jsonl").open("a") as handle:
        handle.write("{}\n")
    with pytest.raises(ValueError, match="SHA-256"):
        verifier.verify(folder)


def test_synthetic_verifier_rejects_attacker_training_labels_even_after_rehash(tmp_path, lab):
    verifier = load_script("sprint4_verify_lab")
    shutil.copytree(lab, tmp_path / "lab")
    folder = tmp_path / "lab"
    labels = json.loads((folder / "labels.json").read_text())
    labels["splits"]["train"][0]["expected"] = "simulated_suspicious"
    (folder / "labels.json").write_text(json.dumps(labels))
    report = json.loads((folder / "report.json").read_text())
    report["labels_sha256"] = hashlib.sha256((folder / "labels.json").read_bytes()).hexdigest()
    (folder / "report.json").write_text(json.dumps(report))
    with pytest.raises(ValueError, match="Train split"):
        verifier.verify(folder)


def test_synthetic_verifier_rejects_overlap_across_splits(tmp_path, lab):
    verifier = load_script("sprint4_verify_lab")
    shutil.copytree(lab, tmp_path / "lab")
    folder = tmp_path / "lab"
    report = json.loads((folder / "report.json").read_text())
    report["splits"]["validation"]["first_timestamp"] = (
        report["splits"]["train"]["last_timestamp"] + 1
    )
    (folder / "report.json").write_text(json.dumps(report))
    with pytest.raises(ValueError, match="time leakage"):
        verifier.verify(folder)


def test_synthetic_verifier_rejects_labels_changed_only_in_report(tmp_path, lab):
    verifier = load_script("sprint4_verify_lab")
    shutil.copytree(lab, tmp_path / "lab")
    folder = tmp_path / "lab"
    report = json.loads((folder / "report.json").read_text())
    report["test"]["observations"][0]["expected_positive"] = True
    (folder / "report.json").write_text(json.dumps(report))
    with pytest.raises(ValueError, match="label differs"):
        verifier.verify(folder)


def test_synthetic_verifier_rejects_score_prediction_disagreement(tmp_path, lab):
    verifier = load_script("sprint4_verify_lab")
    shutil.copytree(lab, tmp_path / "lab")
    folder = tmp_path / "lab"
    report = json.loads((folder / "report.json").read_text())
    report["test"]["observations"][0]["score"] = 1.0
    (folder / "report.json").write_text(json.dumps(report))
    with pytest.raises(ValueError, match="anomaly score"):
        verifier.verify(folder)


def test_readonly_readiness_audit_redacts_identities_and_never_writes(tmp_path):
    audit = load_script("sprint4_ml_readiness")
    db_path = tmp_path / "events.sqlite3"
    model_path = tmp_path / "no-model.json"
    config_path = tmp_path / "config.toml"
    config_path.write_text(
        f'[paths]\ndatabase = "{db_path}"\nmodel = "{model_path}"\n[ml]\nmin_samples = 80\n'
    )
    with sqlite3.connect(db_path) as db:
        db.executescript(
            "CREATE TABLE events(timestamp REAL, source_ip TEXT, outcome TEXT);"
            "CREATE TABLE observations("
            "timestamp REAL,event_id TEXT,state TEXT,features TEXT);"
            "CREATE TABLE state(key TEXT PRIMARY KEY,value TEXT);"
        )
        db.execute("INSERT INTO events VALUES(?,?,?)", (1793500000, "192.0.2.55", "success"))
        db.execute("INSERT INTO events VALUES(?,?,?)", (1793500001, "192.0.2.55", "failure"))
        features = {
            "failed_count": 1,
            "success_count": 1,
            "unique_users": 1,
            "failure_ratio": 0.5,
            "hour_sin": 0.0,
            "hour_cos": 1.0,
        }
        db.execute(
            "INSERT INTO observations VALUES(?,?,?,?)",
            (1793500000, "first", "untrained", json.dumps(features)),
        )
        db.execute(
            "INSERT INTO observations VALUES(?,?,?,?)",
            (1793500001, "second", "untrained", json.dumps(features)),
        )
        db.execute(
            "INSERT INTO state VALUES(?,?)",
            ("model", json.dumps({"state": "untrained"})),
        )
        snapshot = list(db.iterdump())
    actual = audit.inspect(config_path)
    assert actual["event_total"] == 2
    assert actual["candidate_rows_not_vetted_as_normal"] == 2
    assert actual["unique_feature_vectors"] == 1
    assert actual["rows_missing_for_minimum"] == 78
    assert actual["model_state"] == "untrained"
    assert not actual["production_training_authorized"]
    assert "192.0.2.55" not in json.dumps(actual)
    with sqlite3.connect(db_path) as db:
        assert list(db.iterdump()) == snapshot


def test_readiness_fails_closed_if_database_is_missing(tmp_path):
    audit = load_script("sprint4_ml_readiness")
    config_path = tmp_path / "config.toml"
    config_path.write_text(
        f'[paths]\ndatabase = "{tmp_path / "missing.sqlite3"}"\n'
        f'model = "{tmp_path / "model.json"}"\n[ml]\nmin_samples = 80\n'
    )
    with pytest.raises(sqlite3.Error):
        audit.inspect(config_path)
    assert not (tmp_path / "missing.sqlite3").exists()
