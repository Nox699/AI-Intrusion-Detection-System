"""Controlled identities, live feature context and immutable saved models."""

import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from yggdrasil_ids.sudo_ml import SudoAttempt

BOOT = "b" * 32


@pytest.fixture(scope="module")
def probe():
    path = Path(__file__).resolve().parents[1] / "deploy" / "sprint5_sudo_frozen_probe.py"
    spec = importlib.util.spec_from_file_location("sudo_frozen_probe", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def fixture_attempts():
    # Same group deliberately: features must retain successful context for failures.
    rows = [SudoAttempt(900.0, BOOT, "0", 900, "success")]
    rows += [SudoAttempt(1000.0 + i, BOOT, "0", 100 + i, "success") for i in range(30)]
    rows += [SudoAttempt(1040.0 + i, BOOT, "0", 200 + i, "failure") for i in range(3)]
    return rows


def model(positive=True):
    def scores(rows):
        return [{"is_anomaly": bool(positive and values[1] > 0)} for values in rows]

    return SimpleNamespace(score_many=scores, version="frozen", threshold=0.6)


def test_identity_labels_preserve_warmup_and_mixed_phase_context(probe):
    result = probe.evaluate(
        {"mixed_full": model()},
        fixture_attempts(),
        BOOT,
        list(range(100, 130)),
        list(range(200, 203)),
        1000,
        1050,
    )
    mixed = result["results"]["mixed_full"]
    assert mixed["normal_flagged"] == 0 and mixed["failure_flagged"] == 3
    assert mixed["controlled_criterion_passed"] is True
    assert result["probe_groups_overlap"] is True
    assert result["first_failure_context"]["success_count_300s"] == 31
    assert result["context_processes_before_probe"] == 1


def test_missing_or_duplicate_pid_evidence_is_incomplete(probe):
    rows = fixture_attempts()
    with pytest.raises(ValueError, match="identity counts"):
        probe.evaluate(
            {"mixed_full": model()},
            rows[:-1],
            BOOT,
            list(range(100, 130)),
            list(range(200, 203)),
            1000,
            1050,
        )
    # Equal row count is insufficient if a different UID duplicates one target PID.
    changed = rows.copy()
    changed[2] = SudoAttempt(1001.0, BOOT, "99", 100, "success")
    with pytest.raises(ValueError, match="identity counts"):
        probe.evaluate(
            {"mixed_full": model()},
            changed,
            BOOT,
            list(range(100, 130)),
            list(range(200, 203)),
            1000,
            1050,
        )


def test_a_completed_negative_result_is_reported_as_failure_not_retried(probe):
    result = probe.evaluate(
        {"mixed_full": model(False)},
        fixture_attempts(),
        BOOT,
        list(range(100, 130)),
        list(range(200, 203)),
        1000,
        1050,
    )
    assert result["results"]["mixed_full"]["controlled_criterion_passed"] is False


def test_unexpected_service_account_success_stops_probe(probe, monkeypatch):
    calls = []

    class Child:
        returncode = 0
        pid = 99

        def communicate(self, data, timeout):
            calls.append((data, timeout))
            return "123\n", ""

    monkeypatch.setattr(probe.subprocess, "Popen", lambda *a, **k: Child())
    with pytest.raises(RuntimeError, match="unexpectedly succeeded"):
        probe.invoke(failure=True)
    assert len(calls) == 1


def test_timeout_cleanup_is_bounded_even_if_a_descendant_retains_pipes(probe, monkeypatch):
    waits = []

    class Child:
        stdin = stdout = stderr = None

        def communicate(self, data=None, timeout=None):
            waits.append(timeout)
            raise probe.subprocess.TimeoutExpired("controlled", timeout)

        def terminate(self):
            pass

        def kill(self):
            pass

    monkeypatch.setattr(probe.subprocess, "Popen", lambda *a, **k: Child())
    with pytest.raises(RuntimeError, match="timed out"):
        probe.invoke(failure=True)
    assert waits == [15, 2, 2]


def test_original_model_loading_checks_frozen_report_and_training_hash(probe, tmp_path):
    rows = [[float(i % 20 + 1), 0.0, 0.0, float(i % 20 + 1), 0.0, 0.0, 1.0] for i in range(100)]
    matrix_sha = probe.hashlib.sha256(
        json.dumps(rows, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    ).hexdigest()
    metadata = {
        "kind": "restored_sprint5_full_data_baseline",
        "models_frozen_at": 1.0,
        "results": {},
    }
    for name in probe.MODES:
        model = probe.SudoIsolationForest.train(rows, "Frozen probe synthetic unit-test setup")
        filename = f"{name}-model.json"
        model.save(tmp_path / filename)
        metadata["results"][name] = {
            "model_file": filename,
            "threshold": model.threshold,
            "feature_names": model.payload["features"],
            "matrix_sha256": matrix_sha,
        }
    path = tmp_path / "report.json"
    path.write_text(json.dumps(metadata))
    models, hashes, _ = probe.load_frozen(tmp_path)
    assert set(models) == set(probe.MODES) and len(hashes) == 4
    metadata["results"]["mixed_full"]["matrix_sha256"] = "0" * 64
    path.write_text(json.dumps(metadata))
    with pytest.raises(ValueError, match="training matrices"):
        probe.load_frozen(tmp_path)


def test_full_mocked_probe_does_not_modify_frozen_files_or_save_identities(
    probe, tmp_path, monkeypatch
):
    folder = tmp_path / "baseline"
    folder.mkdir()
    original = {"report.json": b"frozen-report", "model.json": b"frozen-model"}
    for name, data in original.items():
        (folder / name).write_bytes(data)
    hashes = {name: probe.file_hash(folder / name) for name in original}
    models = {name: model() for name in probe.MODES}
    monkeypatch.setattr(
        probe, "load_frozen", lambda p: (models, hashes, {"models_frozen_at": 800.0})
    )
    monkeypatch.setattr(probe.pwd, "getpwnam", lambda p: SimpleNamespace(pw_uid=997))
    original_read = Path.read_text

    def read(path, *args, **kwargs):
        if str(path) == "/proc/sys/kernel/random/boot_id":
            return BOOT
        return original_read(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", read)
    monkeypatch.setattr(probe.time, "time", iter([950.0, 1000.0, 1050.0]).__next__)
    monkeypatch.setattr(probe.time, "sleep", lambda _: None)
    normal = iter(range(100, 130))
    failures = iter(range(200, 203))
    monkeypatch.setattr(
        probe, "invoke", lambda failure=False: next(failures if failure else normal)
    )
    queries = []
    monkeypatch.setattr(probe, "read_journal", lambda a, b: queries.append((a, b)) or [])
    monkeypatch.setattr(probe, "observations", lambda rows: fixture_attempts())
    report = probe.run(folder, tmp_path / "probe")
    assert report["status"] == "complete" and report["frozen_files_unchanged"] is True
    assert report["probe_used_for_fitting"] is False and report["thresholds_changed"] is False
    assert queries[-1] == (700.0, 1050.0)
    assert all((folder / name).read_bytes() == data for name, data in original.items())
    serialized = json.dumps(report)
    assert "_UID" not in serialized and "_PID" not in serialized and BOOT not in serialized
    assert (tmp_path / "probe" / "report.json").stat().st_mode & 0o077 == 0
