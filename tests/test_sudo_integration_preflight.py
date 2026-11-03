"""Read-only inventory reports useful metadata without reflecting secrets."""

import hashlib
import importlib.util
import json
import sqlite3
from pathlib import Path

import pytest


@pytest.fixture
def audit():
    path = Path(__file__).parents[1] / "deploy/sudo_integration_preflight.py"
    spec = importlib.util.spec_from_file_location("sudo_preflight", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_unit_output_redacts_environment_and_exec_arguments(audit):
    report = audit.safe_unit_properties(
        "ActiveState=active\nUser=yggdrasil-worker\nGroup=yggdrasil-data\n"
        'Environment="DISCORD_WEBHOOK=https://private-secret" "PYTHONPATH=/opt/source/src" '
        '"YGGDRASIL_CONFIG=/etc/yggdrasil-ids/config.toml"\n'
        "ExecStart={ path=/opt/yggdrasil-ids/venv/bin/yggdrasil-ids ; "
        "argv[]=/opt/yggdrasil-ids/venv/bin/yggdrasil-ids --token secret-token ; }\n"
    )
    output = json.dumps(report)
    assert "private-secret" not in output and "secret-token" not in output
    assert "DISCORD_WEBHOOK" not in output and "argv" not in output
    assert report["executable"] == "/opt/yggdrasil-ids/venv/bin/yggdrasil-ids"
    assert report["selected_environment"] == {
        "PYTHONPATH": "/opt/source/src",
        "YGGDRASIL_CONFIG": "/etc/yggdrasil-ids/config.toml",
    }
    assert report["Group"] == "yggdrasil-data"


def test_private_sqlite_inventory_is_readonly_and_aggregate_only(audit, tmp_path):
    path = tmp_path / "private.sqlite3"
    with sqlite3.connect(path) as db:
        db.executescript(
            "PRAGMA user_version=2; CREATE TABLE sudo_signals(secret TEXT);"
            "CREATE TABLE sudo_candidates(secret TEXT);"
            "CREATE TABLE shadow_poll_checkpoint(id INTEGER,last_completed_until REAL);"
            "INSERT INTO sudo_signals VALUES('private-command');"
            "INSERT INTO sudo_candidates VALUES('private-identity');"
            "INSERT INTO shadow_poll_checkpoint VALUES(1,1000);"
        )
    before = path.read_bytes()
    report = audit.database_inventory(path, private=True, now=1010)
    assert report["state"] == "readable_readonly"
    assert report["counts"] == {"sudo_signals": 1, "sudo_candidates": 1}
    assert report["checkpoint_age_seconds"] == 10
    assert "private-command" not in json.dumps(report)
    assert "private-identity" not in json.dumps(report)
    assert path.read_bytes() == before
    missing = tmp_path / "absent.sqlite3"
    assert audit.database_inventory(missing, private=True, now=1010)["state"] == "unavailable"
    assert not missing.exists()


def test_model_identity_comes_from_saved_fingerprint_without_training_data_output(
    audit, tmp_path, monkeypatch
):
    path = tmp_path / "model.json"
    payload = {
        "sha256": "1" * 64,
        "normal_training_rows": [[12345, 67890]],
        "provenance": "private-host-metadata",
    }
    path.write_text(json.dumps(payload))
    monkeypatch.setattr(audit, "MODEL_SHA", hashlib.sha256(path.read_bytes()).hexdigest())
    monkeypatch.setattr(audit, "MODEL_VERSION", "sudo-if-" + "1" * 16)
    report = audit.model_inventory(path)
    assert report["state"] == "frozen_artifact_verified"
    assert report["saved_training_rows"] == 1
    assert "12345" not in json.dumps(report) and "private-host-metadata" not in json.dumps(report)
    path.write_text("invalid, different model")
    assert audit.model_inventory(path)["state"] == "hash_mismatch"


def test_readonly_inventory_refuses_database_symlinks(audit, tmp_path):
    target = tmp_path / "target"
    target.write_bytes(b"keep")
    link = tmp_path / "database"
    link.symlink_to(target)
    report = audit.database_inventory(link, private=True, now=1000)
    assert report["state"] == "unavailable"
    assert report["file"]["state"] == "symlink_refused"
    assert target.read_bytes() == b"keep"
