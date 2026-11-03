#!/usr/bin/env bash
# Validate the persistent sudo shadow poll against real Yggdrasil journal
# without installing systemd units, changing the production IDS, or sending.
set -euo pipefail
umask 077

sha="${1:-}"
if [[ ! "$sha" =~ ^[0-9a-f]{40}$ ]]; then
  echo "STOP: Expected pinned commit SHA" >&2
  exit 2
fi
if [[ "$(hostname)" != "yggdrasil" || "$(id -un)" != "vidar" ]]; then
  echo "STOP: Run as vidar on Yggdrasil only" >&2
  exit 2
fi
cd /home/vidar/AI-Intrusion-Detection-System
git fetch --no-tags origin integration/sprint5-sudo-clean
if [[ "$(git rev-parse origin/integration/sprint5-sudo-clean)" != "$sha" ]]; then
  echo "STOP: Git branch changed; recheck the exact new commit" >&2
  exit 2
fi

echo "=== Kontrol af eksisterende IDS-tjenester ==="
for unit in yggdrasil-collector.service yggdrasil-web.service yggdrasil-notifier.service; do
  if [[ "$(systemctl is-active "$unit")" != "active" ]]; then
    echo "STOP: $unit is not active" >&2
    exit 2
  fi
done

tmp="$(mktemp -d -t yggdrasil-sudo-code-XXXXXX)"
trap 'rm -rf -- "$tmp"' EXIT

git archive "$sha" \
  src/yggdrasil_ids/__init__.py \
  src/yggdrasil_ids/sudo_rules.py \
  src/yggdrasil_ids/sudo_storage.py \
  deploy/sprint5_sudo_shadow_poll.py |
  tar -xf - -C "$tmp"

# No secrets in this extracted subset; the unprivileged worker may read it.
chmod -R a+rX "$tmp"

echo "=== To sudo-shadow-polls som yggdrasil-worker i midlertidig database ==="

sudo -u yggdrasil-worker -- \
  env "PYTHONPATH=$tmp/src" \
  /opt/yggdrasil-ids/venv/bin/python - "$tmp" <<'PY'
import json
import sys
from pathlib import Path
from tempfile import TemporaryDirectory

sys.path.insert(0, str(Path(sys.argv[1]) / "deploy"))
from sprint5_sudo_shadow_poll import poll_once

with TemporaryDirectory(prefix="yggdrasil-sudo-shadow-probe-") as root:
    db = Path(root) / "sudo-shadow.sqlite3"
    first = poll_once(db)
    second = poll_once(db)

    if second["new_normalized_sudo_rows"] != 0:
        raise RuntimeError("An unchanged journal was unexpectedly stored twice")
    if second["new_candidate_rule_matches"]["sudo.repeated_auth_failure"] != 0:
        raise RuntimeError("An existing sudo candidate was emitted twice")

    summary = {
        "kind": "sudo_shadow_pi_two_poll_probe",
        "first_poll": first,
        "second_poll": second,
        "expected_no_new_auth_failure": True,
        "production_services_modified": False,
        "discord_messages_sent": 0,
    }

if db.exists():
    raise RuntimeError("Temporary sudo shadow probe DB survived cleanup")
summary["temporary_staging_deleted"] = True
print(json.dumps(summary, indent=2, ensure_ascii=False))
PY

echo "=== Ingen sudo shadow systemd-service installeret eller aktiveret ==="
