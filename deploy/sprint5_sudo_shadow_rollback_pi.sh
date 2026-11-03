#!/usr/bin/env bash
# Immediate rollback of the isolated Sprint 5 shadow timer/service.
# Keeps worker-owned sudo shadow SQLite evidence for later inspection.
# NEVER touches production IDS services, DB, webhook or security controls.
set -euo pipefail

if [[ "$(hostname)" != "yggdrasil" || "$(id -un)" != "vidar" ]]; then
  echo "STOP: Run as vidar on Yggdrasil" >&2
  exit 2
fi

echo "=== Disabling only the separate sudo shadow timer ==="
sudo systemctl disable --now yggdrasil-sudo-shadow.timer || :
sudo systemctl stop yggdrasil-sudo-shadow.service || :

code=/opt/yggdrasil-sudo-shadow
if [[ ! -f "$code/COMMIT" ]]; then
  echo "Shadow timer stopped. No pinned install manifest; manually review files" >&2
  exit 1
fi
sha="$(cat "$code/COMMIT")"
if [[ ! "$sha" =~ ^[0-9a-f]{40}$ ]]; then
  echo "Shadow timer stopped. Unexpected installed manifest, refuse code deletion" >&2
  exit 1
fi

echo "=== Removing only exact sudo shadow source and unit paths ==="
sudo rm -f -- \
  /etc/systemd/system/yggdrasil-sudo-shadow.timer \
  /etc/systemd/system/yggdrasil-sudo-shadow.service \
  "$code/deploy/sprint5_sudo_shadow_poll.py" \
  "$code/src/yggdrasil_ids/sudo_storage.py" \
  "$code/src/yggdrasil_ids/sudo_rules.py" \
  "$code/src/yggdrasil_ids/__init__.py" \
  "$code/COMMIT"

sudo rmdir -- \
  "$code/src/yggdrasil_ids" \
  "$code/src" \
  "$code/deploy" \
  "$code" || {
    echo "WARNING: Unexpected extra files in shadow source directory; manual review needed" >&2
  }

sudo systemctl daemon-reload

echo "Rollback: sudo shadow timer disabled and installed source removed"
echo "Preserved private evidence: /var/lib/yggdrasil-sudo-shadow"
echo "Production IDS services, SQLite and Discord credentials: unchanged"
