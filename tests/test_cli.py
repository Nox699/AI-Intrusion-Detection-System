"""End-to-end administration flows using real files, SQLite and model code."""

from __future__ import annotations

import json
import os
import re
import sqlite3

import pytest
from werkzeug.security import check_password_hash

from yggdrasil_ids.cli import main
from yggdrasil_ids.config import load_config
from yggdrasil_ids.features import FEATURE_NAMES
from yggdrasil_ids.lab import generate_lab, prepare_rows
from yggdrasil_ids.ml import IsolationForestDetector
from yggdrasil_ids.storage import Repository
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


def test_demo_builds_a_real_isolated_application_and_refuses_overwrite(tmp_path, capsys):
    directory = tmp_path / "demo"
    assert main(["demo", "--directory", str(directory)]) == 0
    output = json.loads(capsys.readouterr().out)
    cfg = load_config(directory / "config.toml")
    report = json.loads((directory / "lab" / "report.json").read_text())
    repo = Repository(cfg.database_path, readonly=True)
    with repo.reader() as database:
        assert (
            database.execute("SELECT count(*) FROM events").fetchone()[0]
            == report["test"]["event_count"]
        )
        assert (
            database.execute("SELECT count(*) FROM observations WHERE state='scored'").fetchone()[0]
            == report["test"]["event_count"]
        )
    assert repo.get_state("mode") == "demo"
    assert repo.get_state("collector")["state"] == "replay"
    assert repo.get_state("model")["state"] == "ready"
    assert output["password"] == "demo-yggdrasil"
    assert output["mode"] == "demo"
    assert "Syntetisk" in output["message"]
    snapshot = db_snapshot(cfg.database_path)
    assert main(["demo", "--directory", str(directory)]) == 2
    assert "ikke tom" in capsys.readouterr().err
    assert db_snapshot(cfg.database_path) == snapshot
    assert not (tmp_path / "events.sqlite3").exists()


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
    fixtures = generate_lab(tmp_path / "lab", anchor=1_793_480_000)
    prepared = tmp_path / "normal-features.json"
    assert (
        main(
            [
                "prepare-training",
                str(fixtures["train_path"]),
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
    assert data["rows"] == prepare_rows(fixtures["train_path"])
    original_prepared = prepared.read_bytes()
    assert (
        main(
            [
                "prepare-training",
                str(fixtures["train_path"]),
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
    assert main(["train", str(source), "--config", str(path), "--provenance", "reviewed data"]) == 2
    assert "Fejl:" in capsys.readouterr().err
    assert not load_config(path).model_path.exists()


def test_replay_on_fresh_live_configuration_does_not_create_a_poisoned_database(tmp_path, capsys):
    path = config_file(tmp_path)
    source = tmp_path / "input.jsonl"
    source.write_text("")
    assert main(["replay", str(source), "--config", str(path)]) == 2
    assert not load_config(path).database_path.exists()
    assert "demo" in capsys.readouterr().err


def test_replay_refusal_preserves_existing_live_data_and_state(tmp_path, capsys):
    path = config_file(tmp_path)
    assert main(["init", "--config", str(path)]) == 0
    cfg = load_config(path)
    repo = Repository(cfg.database_path)
    repo.set_state("sentinel", {"important": "preserve me"})
    before = db_snapshot(cfg.database_path)
    source = tmp_path / "input.jsonl"
    source.write_text("")
    assert main(["replay", str(source), "--config", str(path)]) == 2
    assert db_snapshot(cfg.database_path) == before
    assert repo.get_state("namespace") == "live"
    capsys.readouterr()


def test_replay_dedup_export_and_consistent_backup(tmp_path, capsys):
    path = config_file(tmp_path, mode="demo")
    fixtures = generate_lab(tmp_path / "lab", anchor=1_793_480_000)
    arguments = ["replay", str(fixtures["test_path"]), "--config", str(path)]
    assert main(arguments) == 0
    first = json.loads(capsys.readouterr().out)
    assert first["events"] == 41
    assert main(arguments) == 0
    repeated = json.loads(capsys.readouterr().out)
    assert repeated["events"] == first["events"]
    assert repeated["duplicates"] > 0
    cfg = load_config(path)
    repo = Repository(cfg.database_path, readonly=True)
    with repo.reader() as database:
        since, last = database.execute(
            "SELECT min(timestamp),max(timestamp) FROM events"
        ).fetchone()
    output = tmp_path / "observations.json"
    export = [
        "export-features",
        "--config",
        str(path),
        "--since",
        str(since),
        "--until",
        str(last + 1),
        "--output",
        str(output),
    ]
    assert main(export) == 0
    data = json.loads(output.read_text())
    assert data["rows"] == prepare_rows(fixtures["test_path"])
    assert data["range"] == [since, last + 1]
    before_export = output.read_bytes()
    assert main(export) == 2
    assert output.read_bytes() == before_export
    backup = tmp_path / "backup.sqlite3"
    assert main(["backup", "--config", str(path), "--output", str(backup)]) == 0
    assert db_snapshot(backup) == db_snapshot(cfg.database_path)
    before_backup = backup.read_bytes()
    assert main(["backup", "--config", str(path), "--output", str(backup)]) == 2
    assert backup.read_bytes() == before_backup
    capsys.readouterr()


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
