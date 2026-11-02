#!/usr/bin/env bash
# Explicit operator-controlled rollback of shadow ML code/config/model ONLY.
# Preserves current SQLite and notifier state; never rewinds live events.
set -Eeuo pipefail
umask 077
phase="preflight"
stop() { echo "STOP ($phase): $*" >&2; exit 1; }
on_exit() {
  code=$?
  if ((code)); then
    echo "Rollback incomplete. Do not rerun blindly; inspect installed files/services." >&2
  fi
}
trap on_exit EXIT
[[ $# == 2 && "$1" =~ ^[0-9a-f]{40}$ ]] \
  || stop "Usage: rollback <source-SHA> <exact-offline-backup-directory>"
[[ "$(id -u)" -ne 0 ]] || stop "Run as vidar, not root."
sha="$1"
offline="$2"
[[ "$offline" =~ ^/var/backups/yggdrasil-ids/sprint4-shadow-offline-[a-zA-Z0-9]{8}$ ]] \
  || stop "Offline backup path must be a previously produced Sprint 4 directory."
stage="/var/backups/yggdrasil-ids/sprint4-shadow-prepared-$sha"
prev="$stage/previous-venv.tar.gz"
model="/var/lib/yggdrasil-ids/model.json"
config="/etc/yggdrasil-ids/config.toml"
venv="/opt/yggdrasil-ids/venv"
sudo -v
sudo test -s "$prev" || stop "Original venv archive missing."
sudo test -s "$offline/config.tar.gz" || stop "Offline config backup missing."
sudo test -s "$offline/pre-shadow-v4.sqlite3" || stop "Offline SQLite reference missing."
sudo test -s "$offline/sha256sums.txt" || stop "Backup checksum manifest missing."
sudo sha256sum --check --status "$stage/sha256sums.txt" || stop "Staging integrity failed."
sudo sha256sum --check --status "$offline/sha256sums.txt" || stop "Offline integrity failed."
sudo tar -tzf "$prev" | grep -Fx 'venv/bin/yggdrasil-ids' >/dev/null \
  || stop "Original CLI missing in backup."
sudo tar -tzf "$offline/config.tar.gz" | grep -Fx 'yggdrasil-ids/config.toml' >/dev/null \
  || stop "Original configuration missing in backup."

# A later user-created model must never be removed as if it were our candidate.
if sudo test -e "$model"; then
  sudo cmp -s "$model" "$stage/private-candidate-model.json" \
    || stop "Model no longer matches experimental candidate; manual review needed."
fi

echo "Rollback does not restore old SQLite or Discord state (prevents event loss/replay)."
echo "Only code, config and this verified experimental model will be reverted."
phase="stopping-services"
sudo systemctl stop yggdrasil-notifier.service yggdrasil-web.service yggdrasil-collector.service
for service in yggdrasil-collector.service yggdrasil-web.service yggdrasil-notifier.service; do
  ! systemctl is-active --quiet "$service" || stop "Failed to stop $service."
done

phase="restore-config"
sudo tar -C /etc -xzf "$offline/config.tar.gz" yggdrasil-ids/config.toml \
  || stop "Could not restore original configuration."
if sudo test -e "$model"; then
  sudo rm -f -- "$model" || stop "Cannot remove experimental model."
fi
phase="restore-venv"
# Keep the failed wheel environment as a private diagnostic archive.
sudo tar -C /opt/yggdrasil-ids -czf "$offline/shadow-venv-before-rollback.tar.gz" venv \
  || stop "Cannot preserve failed runtime environment."
sudo chmod 0600 "$offline/shadow-venv-before-rollback.tar.gz"
sudo rm -rf -- "$venv" || stop "Cannot remove installed experimental venv."
sudo tar -C /opt/yggdrasil-ids -xzf "$prev" \
  || stop "Cannot restore previous venv snapshot."
sudo "$venv/bin/python" -m pip check >/dev/null || stop "Recovered venv dependencies failed."
for account in yggdrasil-worker yggdrasil-web yggdrasil-notifier; do
  sudo -u "$account" "$venv/bin/yggdrasil-ids" --version >/dev/null \
    || stop "Recovered CLI unavailable for $account."
done
sudo "$venv/bin/python" - "$config" "$model" <<'PY'
import sqlite3,sys
from pathlib import Path
from yggdrasil_ids.config import load_config
from yggdrasil_ids.storage import SCHEMA_VERSION
cfg=load_config(Path(sys.argv[1]))
assert cfg.mode=="live" and cfg.network.enabled
assert cfg.network.distinct_ports_threshold==5
assert cfg.web.bind in ("127.0.0.1","::1")
assert not Path(sys.argv[2]).exists()
assert SCHEMA_VERSION==4
with sqlite3.connect(cfg.database_path.as_uri()+"?mode=ro",uri=True) as db:
    assert db.execute("PRAGMA user_version").fetchone()[0]==4
    assert db.execute("PRAGMA quick_check").fetchone()[0]=="ok"
print("PASS: Previous config and schema-v4 history retained.")
PY

phase="starting-services"
sudo systemctl start yggdrasil-collector.service
sleep 3
systemctl is-active --quiet yggdrasil-collector.service || stop "Collector restart failed."
sudo -u yggdrasil-worker "$venv/bin/yggdrasil-ids" doctor \
  --config "$config" --role collector --journal >/dev/null || stop "Collector doctor."
sudo systemctl start yggdrasil-web.service
sleep 3
systemctl is-active --quiet yggdrasil-web.service || stop "Web restart failed."
sudo -u yggdrasil-web "$venv/bin/yggdrasil-ids" doctor \
  --config "$config" --role web >/dev/null || stop "Web doctor."
sudo systemctl start yggdrasil-notifier.service
sleep 3
systemctl is-active --quiet yggdrasil-notifier.service || stop "Notifier restart failed."
phase="complete"
echo "PASS: Previous IDS package/config restored; experimental model removed."
echo "PASS: Current SSH/UFW/alert/Discord history preserved (no DB rewind)."
echo "OFFLINE_BACKUP=$offline"
echo "FAILED_SHADOW_VENV=$offline/shadow-venv-before-rollback.tar.gz"
