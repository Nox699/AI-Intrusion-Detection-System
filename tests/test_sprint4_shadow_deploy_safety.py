"""Safety invariants for the explicit, two-stage shadow-model Pi rollout.

These checks complement 'bash -n' in CI; they are not a substitute for the
operator's live preflight or a hardware acceptance test.
"""

from pathlib import Path

import pytest

DEPLOY = Path(__file__).resolve().parents[1] / "deploy"


@pytest.fixture(scope="module")
def scripts():
    return {
        name: (DEPLOY / f"sprint4_shadow_{name}.sh").read_text()
        for name in ("prepare", "deploy", "rollback")
    }


def test_staging_has_no_install_stop_restart_or_production_model_write(scripts):
    stage = scripts["prepare"]
    assert "git archive" in stage
    assert "previous-venv.tar.gz" in stage
    assert "sha256sum --check" in stage
    assert "candidate-model.json" in stage
    assert "IsolationForestDetector.load" in stage
    assert "git diff --name-only" in stage
    assert "systemctl stop" not in stage
    assert "systemctl restart" not in stage
    assert "pip install --no-index" not in stage
    assert '"$model"' not in stage
    assert "model.json" in stage


def test_deployment_is_shadow_before_model_load_and_keeps_backups(scripts):
    deploy = scripts["deploy"]
    assert "pre-shadow-v4.sqlite3" in deploy
    assert "ids-data.tar.gz" in deploy
    assert "notifier-data.tar.gz" in deploy
    assert "config.tar.gz" in deploy
    assert "previous-venv.tar.gz" in scripts["prepare"]
    assert "sha256sum --check" in deploy
    assert "offline" in deploy
    assert 'alert_mode = "shadow"' in deploy
    assert '"state"]=="ready"' in deploy
    assert '"alert_mode"]=="shadow"' in deploy
    assert "source-sha.txt" in deploy
    assert deploy.index('phase="offline-backup"') < deploy.index('phase="installing-wheel"')
    assert deploy.index('phase="configuring-shadow"') < deploy.index(
        'sudo systemctl start yggdrasil-collector.service'
    )
    assert deploy.index('alert_mode = "shadow"') < deploy.index(
        'sudo install -o yggdrasil-worker'
    )
    assert deploy.index('sudo install -o yggdrasil-worker') < deploy.index(
        'sudo systemctl start yggdrasil-collector.service'
    )
    assert 'sudo install -o yggdrasil-worker -g yggdrasil-data -m 0600' in deploy
    assert 'grep -F "Logging: on (low)"' in deploy
    assert 'git status --porcelain' in deploy
    assert 'Path("/var/lib/yggdrasil-ids/model.json")' in deploy
    assert '"$offline"/*.gz' not in deploy


def test_rollback_keeps_new_events_and_does_not_reset_notifier(scripts):
    rollback = scripts["rollback"]
    assert 'sudo cmp -s "$model"' in rollback
    assert "model no longer" not in rollback.lower() or "manual review" in rollback.lower()
    assert "sha256sum --check" in rollback
    assert "config.toml" in rollback
    assert "previous-venv.tar.gz" in rollback
    assert "sudo systemctl start yggdrasil-collector.service" in rollback
    assert "sudo systemctl start yggdrasil-web.service" in rollback
    assert "sudo systemctl start yggdrasil-notifier.service" in rollback
    assert 'sqlite3' in rollback
    assert "restoring data" not in rollback.lower()
    assert "sudo tar -C /var/lib -x" not in rollback
    assert "sudo ufw allow" not in rollback
    assert "sudo ufw disable" not in rollback


def test_deployment_scripts_do_not_modify_network_or_administration_settings(scripts):
    for source in scripts.values():
        for command in (
            "ufw allow",
            "ufw delete",
            "ufw disable",
            "tailscale up",
            "tailscale down",
            "systemctl restart ssh",
            "systemctl stop ssh",
            "passwd ",
            "useradd ",
        ):
            assert command not in source
