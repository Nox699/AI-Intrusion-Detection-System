"""Retroactive hybrid diagnostics preserve the original synthetic evaluation."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
DEPLOY = ROOT / "deploy"


@pytest.fixture(scope="module")
def lab_modules():
    sys.path.insert(0, str(DEPLOY))
    try:
        spec_lab = importlib.util.spec_from_file_location(
            "sprint4_preauth_ml_lab", DEPLOY / "sprint4_preauth_ml_lab.py"
        )
        assert spec_lab and spec_lab.loader
        lab = importlib.util.module_from_spec(spec_lab)
        sys.modules[spec_lab.name] = lab
        spec_lab.loader.exec_module(lab)
        spec_analysis = importlib.util.spec_from_file_location(
            "sprint4_preauth_hybrid_diagnostics",
            DEPLOY / "sprint4_preauth_hybrid_diagnostics.py",
        )
        assert spec_analysis and spec_analysis.loader
        diagnostics = importlib.util.module_from_spec(spec_analysis)
        sys.modules[spec_analysis.name] = diagnostics
        spec_analysis.loader.exec_module(diagnostics)
        return lab, diagnostics
    finally:
        sys.path.remove(str(DEPLOY))


@pytest.fixture
def lab_directory(tmp_path, lab_modules):
    lab, _ = lab_modules
    path = tmp_path / "private-offline"
    lab.generate(path, seed=42, anchor=1_793_500_000)
    lab.evaluate(path)
    return path


def test_hybrid_reproduces_original_scores_without_touching_files(lab_directory, lab_modules):
    _, diagnostics = lab_modules
    filenames = ("train.jsonl", "validation.jsonl", "test.jsonl", "labels.json",
                 "manifest.json", "report.json", "preauth-lab-model.json")
    before = {
        name: hashlib.sha256((lab_directory / name).read_bytes()).hexdigest()
        for name in filenames
    }
    data = diagnostics.analyse(lab_directory)
    after = {
        name: hashlib.sha256((lab_directory / name).read_bytes()).hexdigest()
        for name in filenames
    }
    assert before == after
    assert data["model_retrained"] is False
    assert data["production_ids_changed"] is False
    assert data["original_threshold_unchanged"] is True
    assert data["test"]["metrics"]["ml"]["tp"] == 17
    assert data["test"]["metrics"]["rules"]["tp"] == 19
    assert data["test"]["metrics"]["ml"]["fn"] == 18
    assert data["validation"]["metrics"]["ml"]["tp"] == 15
    assert data["validation"]["metrics"]["rules"]["tp"] == 22
    assert data["test"]["connections_with_disconnected_equal_to_count"] == 49
    assert data["validation"]["connections_with_disconnected_equal_to_count"] == 54
    for split in ("validation", "test"):
        metrics = data[split]["metrics"]
        for key in ("tp", "fp", "tn", "fn"):
            assert isinstance(metrics["hybrid"][key], int)
        assert metrics["hybrid"]["tp"] >= metrics["rules"]["tp"]
        assert metrics["hybrid"]["tp"] >= metrics["ml"]["tp"]
        assert metrics["hybrid"]["fp"] == 0
        assert len(data[split]["scenarios"]) == 7
        coverage = data[split]["scenario_coverage"]
        assert coverage["ml"]["suspicious_scenarios_detected"] == 2
        assert coverage["rules"]["suspicious_scenarios_detected"] == 3
        assert coverage["hybrid"]["suspicious_scenarios_detected"] == 3
        assert coverage["hybrid"]["normal_scenarios_flagged"] == 0
        for item in data[split]["scenarios"]:
            onset = item["first_detection_at"]
            seen = [v for v in (onset["ml"], onset["rules"]) if v is not None]
            assert onset["hybrid"] == (min(seen) if seen else None)
    output = json.dumps(data)
    for private_identifier in ("192.0.2.", "198.51.100.", "203.0.113."):
        assert private_identifier not in output


def test_refuses_rewritten_historical_model_metrics(lab_directory, lab_modules):
    _, diagnostics = lab_modules
    path = lab_directory / "report.json"
    report = json.loads(path.read_text())
    report["test"]["ml"]["tp"] = 999
    path.write_text(json.dumps(report))
    with pytest.raises(ValueError, match="Historical test ml counts changed"):
        diagnostics.analyse(lab_directory)


def test_refuses_changed_model_identity(lab_directory, lab_modules):
    _, diagnostics = lab_modules
    path = lab_directory / "report.json"
    report = json.loads(path.read_text())
    report["model"]["version"] = "forged-model"
    path.write_text(json.dumps(report))
    with pytest.raises(ValueError, match="version"):
        diagnostics.analyse(lab_directory)
