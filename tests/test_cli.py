"""End-to-end administration flows using real files, SQLite and model code."""

from __future__ import annotations

import json
import os
import re
import sqlite3

import pytest
from werkzeug.security import check_password_hash

from tests.factories import normal_journal_records, write_normal_journal
from yggdrasil_ids.cli import main
from yggdrasil_ids.config import load_config
from yggdrasil_ids.features import FEATURE_NAMES
from yggdrasil_ids.ml import IsolationForestDetector
from yggdrasil_ids.training import prepare_rows
from yggdrasil_ids.web import create_app


@pytest.fixture(autouse=True)
def restore_process_umask():
    previous = os.umask(0o027)
    os.umask(previous)
    yield
    os.umask(previous)


def config_file(directory, mode="live"):
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "config.toml"
    path.write_text(f'''[app]
mode = "{mode}"
[paths]
database = "state/events.sqlite3"
model = "state/model.json"
credentials = "private/web-secrets.json"
[ml]
n_estimators = 16
''')
    return path


def password_input(monkeypatch, first="a-long-local-password", second=None):
    answers = iter([first, first if second is None else second])
    monkeypatch.setattr("yggdrasil_ids.cli.getpass.getpass", lambda _: next(answers))


def first_json(text):
    return json.JSONDecoder().raw_decode(text.lstrip())[0]


def db_snapshot(path):
    with sqlite3.connect(path) as database:
        return list(database.iterdump())


def test_init_and_credentials_enable_real_login_without_plaintext_storage(
    tmp_path, monkeypatch, capsys
):
    path = config_file(tmp_path)
    assert main(["init", "--config", str(path)]) == 0
    password_input(monkeypatch)
    assert main(["credentials", "--config", str(path)]) == 0
    cfg = load_config(path)
    contents = cfg.credentials_path.read_text()
    credentials = json.loads(contents)
    assert "a-long-local-password" not in contents
    assert check_password_hash(credentials["password_hash"], "a-long-local-password")
    assert len(credentials["secret_key"]) >= 32
    assert cfg.credentials_path.stat().st_mode & 0o777 == 0o600
    output = capsys.readouterr()
    assert "a-long-local-password" not in output.out + output.err
    app = create_app(cfg)
    app.config["TESTING"] = True
    client = app.test_client()
    assert client.get("/api/overview").status_code == 401
    login = client.get("/login")
    csrf = re.search(rb'name="csrf_token" value="([^"]+)"', login.data).group(1).decode()
    result = client.post("/login", data={"password": "a-long-local-password", "csrf_token": csrf})
    assert result.status_code == 302
    assert client.get("/api/overview").status_code == 200


@pytest.mark.parametrize(
    "first,second",
    [("short", "short"), ("x" * 257, "x" * 257), ("long-enough-password", "different-password")],
)
def test_invalid_credentials_do_not_create_secret_file(
    tmp_path, monkeypatch, capsys, first, second
):
    path = config_file(tmp_path)
    password_input(monkeypatch, first, second)
    assert main(["credentials", "--config", str(path)]) == 2
    assert "Fejl:" in capsys.readouterr().err
    assert not load_config(path).credentials_path.exists()


def test_credential_replacement_requires_flag_and_rotates_session_secret(
    tmp_path, monkeypatch, capsys
):
    path = config_file(tmp_path)
    cfg = load_config(path)
    password_input(monkeypatch)
    assert main(["credentials", "--config", str(path)]) == 0
    before = cfg.credentials_path.read_bytes()
    previous = json.loads(before)
    password_input(monkeypatch, "another-long-password")
    assert main(["credentials", "--config", str(path)]) == 2
    assert cfg.credentials_path.read_bytes() == before
    password_input(monkeypatch, "another-long-password")
    assert main(["credentials", "--config", str(path), "--replace"]) == 0
    after = json.loads(cfg.credentials_path.read_text())
    assert after["secret_key"] != previous["secret_key"]
    assert check_password_hash(after["password_hash"], "another-long-password")
    assert not check_password_hash(after["password_hash"], "a-long-local-password")
    assert list(cfg.credentials_path.parent.glob(".credentials-*")) == []
    capsys.readouterr()


def test_prepare_then_train_preserves_schema_provenance_and_existing_model(tmp_path, capsys):
    path = config_file(tmp_path)
    cfg = load_config(path)
    normal = write_normal_journal(tmp_path / "normal.jsonl")
    prepared = tmp_path / "normal-features.json"
    assert (
        main(
            [
                "prepare-training",
                str(normal),
                "--config",
                str(path),
                "--output",
                str(prepared),
            ]
        )
        == 0
    )
    data = json.loads(prepared.read_text())
    assert data["feature_names"] == list(FEATURE_NAMES)
    assert data["window_seconds"] == cfg.ml.window_seconds
    assert data["rows"] == prepare_rows(normal)
    original_prepared = prepared.read_bytes()
    assert (
        main(
            [
                "prepare-training",
                str(normal),
                "--config",
                str(path),
                "--output",
                str(prepared),
            ]
        )
        == 2
    )
    assert prepared.read_bytes() == original_prepared
    capsys.readouterr()
    arguments = [
        "train",
        str(prepared),
        "--config",
        str(path),
        "--provenance",
        "Reviewed synthetic normal training sessions only",
        "--approve-reviewed-normal",
    ]
    assert main(arguments) == 0
    metadata = first_json(capsys.readouterr().out)
    assert metadata["provenance"] == "Reviewed synthetic normal training sessions only"
    assert metadata["sample_count"] == len(data["rows"])
    assert IsolationForestDetector.load(cfg.model_path).metadata == metadata
    before = cfg.model_path.read_bytes()
    assert main(arguments) == 2
    assert "findes allerede" in capsys.readouterr().err
    assert cfg.model_path.read_bytes() == before


@pytest.mark.parametrize("change", ["feature_names", "window_seconds", "rows"])
def test_training_rejects_incompatible_input_without_creating_model(tmp_path, capsys, change):
    path = config_file(tmp_path)
    source = tmp_path / "incompatible.json"
    data = {"feature_names": list(FEATURE_NAMES), "window_seconds": 300, "rows": []}
    if change == "rows":
        del data[change]
    elif change == "feature_names":
        data[change] = ["ip_number"]
    else:
        data[change] = 600
    source.write_text(json.dumps(data))
    assert (
        main(
            [
                "train",
                str(source),
                "--config",
                str(path),
                "--provenance",
                "reviewed data",
                "--approve-reviewed-normal",
            ]
        )
        == 2
    )
    assert "Fejl:" in capsys.readouterr().err
    assert not load_config(path).model_path.exists()


@pytest.mark.parametrize(
    "since,until",
    [("-inf", "10"), ("0", "inf"), ("nan", "10"), ("0", "nan"), ("10", "10"), ("20", "10")],
)
def test_export_requires_a_finite_ordered_range(tmp_path, capsys, since, until):
    path = config_file(tmp_path)
    assert main(["init", "--config", str(path)]) == 0
    destination = tmp_path / "invalid.json"
    result = main(
        [
            "export-features",
            "--config",
            str(path),
            f"--since={since}",
            f"--until={until}",
            "--output",
            str(destination),
        ]
    )
    assert result == 2
    assert not destination.exists()
    assert "Fejl:" in capsys.readouterr().err


def test_doctor_distinguishes_missing_setup_untrained_and_broken_model(
    tmp_path, monkeypatch, capsys
):
    path = config_file(tmp_path)
    assert main(["doctor", "--config", str(path)]) == 1
    missing = json.loads(capsys.readouterr().out)
    assert missing["checks"]["database"]["ok"] is False
    assert missing["checks"]["web"]["ok"] is False
    assert main(["init", "--config", str(path)]) == 0
    password_input(monkeypatch)
    assert main(["credentials", "--config", str(path)]) == 0
    capsys.readouterr()
    assert main(["doctor", "--config", str(path)]) == 0
    untrained = json.loads(capsys.readouterr().out)
    assert untrained["checks"]["database"]["ok"] is True
    assert untrained["checks"]["web"]["ok"] is True
    assert untrained["checks"]["model"]["ok"] is None
    cfg = load_config(path)
    cfg.model_path.write_text("broken model file")
    assert main(["doctor", "--config", str(path)]) == 1
    broken = json.loads(capsys.readouterr().out)
    assert broken["checks"]["model"]["ok"] is False
    assert broken["checks"]["database"]["ok"] is True


def test_doctor_roles_respect_separate_service_access(tmp_path, monkeypatch, capsys):
    path = config_file(tmp_path)
    assert main(["init", "--config", str(path)]) == 0
    capsys.readouterr()
    monkeypatch.setattr(
        "yggdrasil_ids.cli.probe_journal", lambda _: {"ok": True, "message": "fixture journal"}
    )
    # Collector needs no dashboard credential file, which does not exist here.
    assert main(["doctor", "--config", str(path), "--role", "collector", "--journal"]) == 0
    collector = json.loads(capsys.readouterr().out)
    assert "web" not in collector["checks"]
    assert collector["checks"]["journal"]["ok"] is True
    # Web needs its own credentials, but must not load the collector's model.
    password_input(monkeypatch)
    assert main(["credentials", "--config", str(path)]) == 0
    load_config(path).model_path.write_text("invalid model")
    capsys.readouterr()
    assert main(["doctor", "--config", str(path), "--role", "web"]) == 0
    web = json.loads(capsys.readouterr().out)
    assert "model" not in web["checks"]
    assert "journal" not in web["checks"]
    assert web["checks"]["web"]["ok"] is True


@pytest.mark.parametrize("command", ["demo", "lab", "replay"])
def test_retired_experiment_commands_are_not_available(tmp_path, command):
    with pytest.raises(SystemExit) as exit:
        main([command])
    assert exit.value.code == 2
    assert not (tmp_path / "events.sqlite3").exists()


def test_training_requires_explicit_normal_review_without_writing_model(tmp_path, capsys):
    path = config_file(tmp_path)
    normal = write_normal_journal(tmp_path / "normal.jsonl")
    prepared = tmp_path / "normal-features.json"
    assert (
        main(["prepare-training", str(normal), "--config", str(path), "--output", str(prepared)])
        == 0
    )
    assert main(["train", str(prepared), "--config", str(path), "--provenance", "unreviewed"]) == 2
    assert "approve-reviewed-normal" in capsys.readouterr().err
    assert not load_config(path).model_path.exists()


def test_export_and_backup_preserve_production_history(tmp_path, monkeypatch, capsys):
    from yggdrasil_ids.engine import AnalysisEngine

    path = config_file(tmp_path)
    cfg = load_config(path)
    records = normal_journal_records(count=6)
    now = int(records[-1]["__REALTIME_TIMESTAMP"]) / 1_000_000 + 1
    monkeypatch.setattr("yggdrasil_ids.engine.time.time", lambda: now)
    engine = AnalysisEngine(cfg)
    for record in records:
        engine.process(record)
    before = db_snapshot(cfg.database_path)
    since = int(records[0]["__REALTIME_TIMESTAMP"]) / 1_000_000
    until = now
    output = tmp_path / "observations.json"
    export = [
        "export-features",
        "--config",
        str(path),
        "--since",
        str(since),
        "--until",
        str(until),
        "--output",
        str(output),
    ]
    assert main(export) == 0
    rows = json.loads(output.read_text())["rows"]
    source = tmp_path / "source.jsonl"
    source.write_text("\n".join(json.dumps(item) for item in records))
    assert rows == prepare_rows(source)
    assert main(export) == 2
    assert db_snapshot(cfg.database_path) == before
    backup = tmp_path / "backup.sqlite3"
    assert main(["backup", "--config", str(path), "--output", str(backup)]) == 0
    assert db_snapshot(backup) == before
    assert main(["backup", "--config", str(path), "--output", str(backup)]) == 2
    assert db_snapshot(backup) == before
    capsys.readouterr()


def test_doctor_requires_loaded_alerting_model_and_fresh_all_detector_state(
    tmp_path, monkeypatch, capsys
):
    from dataclasses import replace

    from yggdrasil_ids.cli import doctor
    from yggdrasil_ids.config import NetworkConfig, SudoConfig
    from yggdrasil_ids.engine import AnalysisEngine

    path = config_file(tmp_path)
    path.write_text(path.read_text() + "\n[network]\nenabled = true\n[sudo]\nenabled = true\n")
    cfg = load_config(path)
    source = write_normal_journal(tmp_path / "reviewed-normal.jsonl")
    model = IsolationForestDetector.train(
        prepare_rows(source), cfg.ml, "Synthetic unit-test observations only"
    )
    model.save(cfg.model_path)
    engine = AnalysisEngine(cfg)
    engine.heartbeat("running")
    monkeypatch.setattr(
        "yggdrasil_ids.sudo_integration_dashboard.read_integration",
        lambda _: {"state": "ready", "rules_active": True},
    )
    before = db_snapshot(cfg.database_path)
    assert main(["doctor", "--config", str(path), "--role", "collector", "--require-ready"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["ready"] is True
    assert db_snapshot(cfg.database_path) == before
    assert not doctor(
        replace(cfg, network=NetworkConfig(enabled=False)), role="collector", require_ready=True
    )["ready"]
    assert not doctor(
        replace(cfg, sudo=SudoConfig(enabled=False)), role="collector", require_ready=True
    )["ready"]
    engine.heartbeat("stopped")
    assert doctor(cfg, role="collector", require_ready=True)["checks"]["production"]["ok"] is False
    engine.heartbeat("running")
    current = engine.repository.get_state("model")
    engine.repository.set_state(
        "model", {**current, "metadata": {**current["metadata"], "version": "different-model"}}
    )
    assert not doctor(cfg, role="collector", require_ready=True)["ready"]
    engine.repository.set_state("model", current)
    engine.repository.set_state("collector", {"state": "running", "heartbeat_at": 0})
    assert not doctor(cfg, role="collector", require_ready=True)["ready"]


def test_sudo_commands_use_the_loaded_production_config_and_propagate_failures(
    tmp_path, monkeypatch, capsys
):
    path = config_file(tmp_path)
    path.write_text(path.read_text() + "\n[sudo]\nenabled = true\n")
    seen = []

    def arm(config):
        seen.append(("arm", config))
        return 1_790_000_000.0

    def poll(config):
        seen.append(("poll", config))
        return {"rules": {"state": "active"}}

    monkeypatch.setattr("yggdrasil_ids.sudo_service.arm", arm)
    monkeypatch.setattr("yggdrasil_ids.sudo_service.run_once", poll)
    assert main(["sudo-arm", "--config", str(path)]) == 0
    assert json.loads(capsys.readouterr().out) == 1_790_000_000.0
    assert main(["sudo-poll", "--config", str(path)]) == 0
    assert json.loads(capsys.readouterr().out)["rules"]["state"] == "active"
    assert [name for name, config in seen] == ["arm", "poll"]
    assert all(config == load_config(path) for _, config in seen)

    def unavailable(config):
        raise RuntimeError("Sudo source unavailable")

    monkeypatch.setattr("yggdrasil_ids.sudo_service.run_once", unavailable)
    assert main(["sudo-poll", "--config", str(path)]) == 2
    assert "Sudo source unavailable" in capsys.readouterr().err


def test_notify_has_no_synthetic_test_command(tmp_path):
    path = config_file(tmp_path)
    with pytest.raises(SystemExit) as error:
        main(
            [
                "notify",
                "--config",
                str(path),
                "--state-file",
                str(tmp_path / "delivery.sqlite3"),
                "--test",
            ]
        )
    assert error.value.code == 2
    assert not (tmp_path / "delivery.sqlite3").exists()


@pytest.mark.parametrize(
    "key,value",
    [
        ("collector", []),
        ("collector", "corrupt-state"),
        ("model", 42),
        ("model", {"state": "ready", "alert_mode": "alert", "metadata": []}),
    ],
)
def test_strict_doctor_reports_corrupt_state_shapes_without_writes(
    tmp_path, monkeypatch, key, value
):
    from yggdrasil_ids.cli import doctor
    from yggdrasil_ids.engine import AnalysisEngine

    path = config_file(tmp_path)
    path.write_text(path.read_text() + "\n[network]\nenabled = true\n[sudo]\nenabled = true\n")
    cfg = load_config(path)
    normal = write_normal_journal(tmp_path / "normal.jsonl")
    model = IsolationForestDetector.train(
        prepare_rows(normal), cfg.ml, "Synthetic unit-test normal observations"
    )
    model.save(cfg.model_path)
    engine = AnalysisEngine(cfg)
    engine.heartbeat("running")
    engine.repository.set_state(key, value)
    monkeypatch.setattr(
        "yggdrasil_ids.sudo_integration_dashboard.read_integration",
        lambda _: {"state": "ready", "rules_active": True},
    )
    before = db_snapshot(cfg.database_path)
    model_before = cfg.model_path.read_bytes()
    report = doctor(cfg, role="collector", require_ready=True)
    assert report["ok"] is False and report["ready"] is False
    assert report["checks"]["production"]["ok"] is False
    assert db_snapshot(cfg.database_path) == before
    assert cfg.model_path.read_bytes() == model_before
