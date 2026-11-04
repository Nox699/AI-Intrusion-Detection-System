"""Production sudo provenance, authenticated alarm views and missing-data states."""

import json
import time
from dataclasses import replace

import pytest
from werkzeug.security import generate_password_hash

from yggdrasil_ids.config import AppConfig, SudoConfig
from yggdrasil_ids.storage import Repository
from yggdrasil_ids.sudo_integration_dashboard import (
    read_integration,
    require_current_run,
    validate_integration,
)
from yggdrasil_ids.web import create_app


def payload(now):
    return {
        "schema": "sudo-integration-v2",
        "generated_at": now,
        "source_checkpoint": now - 2,
        "activated_at": now - 100,
        "rules": {"state": "active", "imported_total": 1, "message": ""},
    }


def write(path, value):
    path.write_text(json.dumps(value))
    path.chmod(0o640)


def test_strict_reader_distinguishes_fresh_stale_and_unavailable(tmp_path):
    now = time.time()
    path = tmp_path / "integration.json"
    assert read_integration(path, now=now)["state"] == "unavailable"
    write(path, payload(now))
    assert read_integration(path, now=now)["rules_active"] is True
    assert read_integration(path, now=now + 181)["state"] == "stale"
    data = payload(now)
    data["uid"] = "private-identity"
    write(path, data)
    assert read_integration(path, now=now)["state"] == "unavailable"


def test_current_run_requires_fresh_active_rules_and_expected_activation(tmp_path):
    now = time.time()
    path = tmp_path / "integration.json"
    write(path, payload(now))
    result = require_current_run(path, not_before=now - 1, expected_activation=now - 100, now=now)
    assert result["rules_active"]
    assert "ml" not in result


@pytest.mark.parametrize("changed", ["old_export", "different_activation", "error"])
def test_recent_export_is_not_proof_of_the_requested_run(tmp_path, changed):
    now = time.time()
    path = tmp_path / "integration.json"
    data = payload(now)
    expected_activation = data["activated_at"]
    if changed == "old_export":
        data["generated_at"] -= 10
    elif changed == "different_activation":
        data["activated_at"] -= 1
    else:
        data["rules"]["state"] = "error"
    write(path, data)
    with pytest.raises(ValueError, match="not verified"):
        require_current_run(
            path, not_before=now - 1, expected_activation=expected_activation, now=now
        )


@pytest.mark.parametrize(
    "mutation",
    [
        lambda p: p.update(schema="sudo-integration-v1"),
        lambda p: p.update(ml={"state": "ready"}),
        lambda p: p.update(source_checkpoint=None),
        lambda p: p.update(activated_at=None),
        lambda p: p["rules"].update(imported_total=True),
        lambda p: p["rules"].update(imported_total=-1),
    ],
)
def test_public_status_rejects_inconsistent_or_retired_provenance(mutation):
    now = time.time()
    data = payload(now)
    mutation(data)
    with pytest.raises(ValueError):
        validate_integration(data, now=now)


def test_rule_error_has_no_invented_activation_or_private_message():
    now = time.time()
    data = payload(now)
    data.update(source_checkpoint=None, activated_at=None)
    data["rules"].update(state="error", message="private-command-private-username")
    report = validate_integration(data, now=now)
    assert report["state"] == "error"
    assert not report["rules_active"]
    assert report["activated_at"] is None
    assert "private-command" not in json.dumps(report)


def test_authenticated_sudo_alarm_details_and_navigation_are_production_only(tmp_path):
    now = time.time()
    credentials = tmp_path / "credentials.json"
    credentials.write_text(
        json.dumps(
            {
                "secret_key": "a-test-secret-that-is-longer-than-thirty-two-characters",
                "password_hash": generate_password_hash("test", method="pbkdf2:sha256:1000"),
            }
        )
    )
    cfg = AppConfig(
        database_path=tmp_path / "events.sqlite3",
        credentials_path=credentials,
        sudo=SudoConfig(enabled=True),
    )
    repo = Repository(cfg.database_path)
    repo.initialize()
    with repo.transaction() as db:
        alarm = repo.add_sudo_alert(
            db,
            event_id="a" * 64,
            detector_id="sudo.repeated_auth_failure",
            timestamp=now - 10,
            process_count=3,
        )
    app = create_app(cfg)
    app.config.update(TESTING=True)
    source = tmp_path / "integration.json"
    app.config["SUDO_PUBLIC_INTEGRATION_PATH"] = source
    app.config["SUDO_PUBLIC_STATUS_PATH"] = tmp_path / "missing-status"
    app.config["SUDO_PUBLIC_ACTIVITY_PATH"] = tmp_path / "missing-activity"
    client = app.test_client()
    assert client.get("/sudo").status_code == 302
    with client.session_transaction() as session:
        session["authenticated"] = True
        session["authenticated_at"] = now
    write(source, payload(now))
    before = repo.path.read_bytes()
    html = client.get("/sudo").get_data(as_text=True)
    assert "Sudo-regler opretter alarmer" in html
    assert "Registrerede sudo-alarmer" in html
    assert "sudo-ml-live" not in html
    assert "Isolation Forest" not in html
    assert "shadow" not in html.lower()
    assert "benchmark" not in html.lower()
    assert 'data-alert-section="sudo"' in html
    assert client.get("/api/nav-alerts").get_json()["counts"]["sudo"] == 1
    assert client.get("/alerts?detector=sudo.repeated_auth_failure").status_code == 200
    detail = client.get(f"/alerts/{alarm}").get_data(as_text=True)
    assert "Sudo-processer i regelfundet" in detail
    assert "Se sudo-overvågning" in detail
    assert "Se SSH-hændelser fra kilden" not in detail
    assert repo.path.read_bytes() == before
    write(source, payload(now - 181))
    html = client.get("/sudo").get_data(as_text=True)
    assert "Sudo-integrationen kræver opmærksomhed" in html
    assert "Sudo-regler opretter alarmer" not in html
    source.unlink()
    assert "Sudo-overvågningen kan ikke bekræftes aktiv" in client.get("/sudo").get_data(
        as_text=True
    )


def test_disabled_sudo_never_claims_active_from_cached_ready_export(tmp_path):
    now = time.time()
    credentials = tmp_path / "credentials.json"
    credentials.write_text(
        json.dumps(
            {
                "secret_key": "a-test-secret-that-is-longer-than-thirty-two-characters",
                "password_hash": generate_password_hash("test", method="pbkdf2:sha256:1000"),
            }
        )
    )
    public = tmp_path / "public"
    public.mkdir()
    write(public / "sudo-integration.json", payload(now))
    cfg = AppConfig(
        database_path=tmp_path / "events.sqlite3",
        credentials_path=credentials,
        sudo_public_directory=public,
        sudo=SudoConfig(enabled=False),
    )
    Repository(cfg.database_path).initialize()
    client = create_app(cfg).test_client()
    with client.session_transaction() as session:
        session["authenticated"] = True
        session["authenticated_at"] = now
    for route in ("/sudo", "/status"):
        html = client.get(route).get_data(as_text=True)
        assert "Deaktiveret" in html or "deaktiveret" in html
        assert "Sudo-regler opretter alarmer" not in html
    active = create_app(replace(cfg, sudo=SudoConfig(enabled=True))).test_client()
    with active.session_transaction() as session:
        session["authenticated"] = True
        session["authenticated_at"] = now
    assert "Sudo-regler opretter alarmer" in active.get("/sudo").get_data(as_text=True)


def test_shared_dashboard_exposes_production_detectors_and_configured_status(tmp_path):
    credentials = tmp_path / "credentials.json"
    credentials.write_text(
        json.dumps(
            {
                "secret_key": "a-test-secret-that-is-longer-than-thirty-two-characters",
                "password_hash": generate_password_hash("test", method="pbkdf2:sha256:1000"),
            }
        )
    )
    cfg = AppConfig(database_path=tmp_path / "events.sqlite3", credentials_path=credentials)
    Repository(cfg.database_path).initialize()
    client = create_app(cfg).test_client()
    with client.session_transaction() as session:
        session["authenticated"] = True
        session["authenticated_at"] = time.time()
    overview = client.get("/").get_data(as_text=True)
    for title in ("SSH-regler", "Isolation Forest", "Portscanningsregler", "Sudo-regler"):
        assert title in overview
    preauth = client.get("/preauth").get_data(as_text=True)
    assert "Gentagne afbrud kan udløse preauth-reglen" in preauth
    assert "som input til Isolation Forest" in preauth
    for route in ("/", "/events", "/preauth", "/network", "/sudo", "/model", "/status", "/alerts"):
        response = client.get(route)
        assert response.status_code == 200
        html = response.get_data(as_text=True).lower()
        assert "demonstrationsmiljø" not in html
        assert "skyggemodel" not in html
        assert "løbende shadow" not in html
        assert "syntetisk sluttest" not in html


@pytest.mark.parametrize("field", ["generated_at", "source_checkpoint", "activated_at"])
def test_future_export_fields_cannot_advertise_ready_after_clock_regression(tmp_path, field):
    now = time.time()
    data = payload(now)
    data[field] = now + 30
    path = tmp_path / "integration.json"
    write(path, data)
    report = read_integration(path, now=now)
    assert report["state"] == "unavailable"
    assert not report["rules_active"]


def test_checkpoint_cannot_follow_its_export_timestamp(tmp_path):
    now = time.time()
    data = payload(now)
    data["generated_at"] = now - 10
    path = tmp_path / "integration.json"
    write(path, data)
    assert read_integration(path, now=now)["state"] == "unavailable"
