"""Public integration provenance and authenticated sudo alarm/shadow views."""

import copy
import json
import time

import pytest
from werkzeug.security import generate_password_hash

from yggdrasil_ids.config import AppConfig
from yggdrasil_ids.storage import Repository
from yggdrasil_ids.sudo_integration_dashboard import read_integration, validate_integration
from yggdrasil_ids.web import create_app


def payload(now):
    return {
        "schema": "sudo-integration-v1",
        "generated_at": now,
        "source_checkpoint": now - 2,
        "activated_at": now - 100,
        "rules": {"state": "active", "imported_total": 1, "message": ""},
        "ml": {
            "format": "sudo-ml-shadow-v1",
            "mode": "shadow",
            "generated_at": now,
            "source_checkpoint": now - 2,
            "snapshot_cutoff": now - 2,
            "window_seconds": 900,
            "warmup_seconds": 300,
            "model_version": "sudo-if-15207a3b77b40fe2",
            "threshold": 0.66,
            "provisional": True,
            "total_scored": 1,
            "anomalous": 1,
            "skipped_ambiguous_processes": 0,
            "latest_limit": 15,
            "latest": [
                {
                    "timestamp": now - 10,
                    "category": "authentication_failed",
                    "score": 0.7,
                    "is_anomaly": True,
                }
            ],
            "sends_alerts": False,
            "shares_production_database": False,
        },
    }


def test_strict_reader_distinguishes_fresh_stale_and_unavailable(tmp_path):
    now = time.time()
    path = tmp_path / "integration.json"
    assert read_integration(path, now=now)["state"] == "unavailable"
    path.write_text(json.dumps(payload(now)))
    path.chmod(0o640)
    assert read_integration(path, now=now)["rules_active"] is True
    assert read_integration(path, now=now + 181)["state"] == "stale"
    data = payload(now)
    data["ml"]["latest"][0]["uid"] = "private-identity"
    path.write_text(json.dumps(data))
    assert read_integration(path, now=now)["state"] == "unavailable"


@pytest.mark.parametrize(
    "mutation",
    [
        lambda p: p["ml"].update(sends_alerts=True),
        lambda p: p["ml"]["latest"][0].update(is_anomaly=False),
        lambda p: p["ml"].update(total_scored=3001),
        lambda p: p.update(source_checkpoint=None),
    ],
)
def test_public_status_rejects_inconsistent_provenance(mutation):
    now = time.time()
    data = payload(now)
    mutation(data)
    with pytest.raises(ValueError):
        validate_integration(data, now=now)


def test_model_unavailable_and_rules_error_are_independent():
    now = time.time()
    data = payload(now)
    data["ml"] = {"state": "unavailable", "message": "private-error-must-not-be-reflected"}
    report = validate_integration(data, now=now)
    assert report["rules_active"] is True
    assert "private-error" not in json.dumps(report)
    data["source_checkpoint"] = None
    data["rules"]["state"] = "error"
    assert validate_integration(data, now=now)["state"] == "error"


def test_authenticated_sudo_alarm_details_filter_nav_and_model_shadow(tmp_path):
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
    cfg = AppConfig(database_path=tmp_path / "events.sqlite3", credentials_path=credentials)
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
    source.write_text(json.dumps(payload(now)))
    source.chmod(0o640)
    html = client.get("/sudo").get_data(as_text=True)
    assert "Sudo-regler opretter alarmer" in html
    assert "sudo-if-15207a3b77b40fe2" in html
    assert "Registrerede sudo-alarmer" in html
    assert "Løbende shadow" in html
    assert 'data-alert-section="sudo"' in html
    assert client.get("/api/nav-alerts").get_json()["counts"]["sudo"] == 1
    assert client.get("/alerts?detector=sudo.repeated_auth_failure").status_code == 200
    detail = client.get(f"/alerts/{alarm}").get_data(as_text=True)
    assert "Sudo-processer i regelfundet" in detail
    assert "Se sudo-overvågning" in detail
    assert "Se SSH-hændelser fra kilden" not in detail
    stale = copy.deepcopy(payload(now - 181))
    source.write_text(json.dumps(stale))
    html = client.get("/sudo").get_data(as_text=True)
    assert "Sudo-integrationen kræver opmærksomhed" in html
    assert "Sudo-regler opretter alarmer" not in html
    source.unlink()
    assert "Ingen automatiske sudo-alarmer" in client.get("/sudo").get_data(as_text=True)
