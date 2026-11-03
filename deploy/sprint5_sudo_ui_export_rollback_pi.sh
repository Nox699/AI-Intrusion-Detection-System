#!/usr/bin/env bash
# Remove only optional sudo UI export timer/units; preserve private sensor/DB.
set -Eeuo pipefail
if [[ "$(hostname)" != "yggdrasil" || "$(id -un)" != "vidar" ]]; then
  echo "STOP: Run as vidar on Yggdrasil" >&2
  exit 2
fi
echo "=== Disable only anonymized sudo UI exporter ==="
sudo systemctl disable --now yggdrasil-sudo-ui-export.timer || :
sudo systemctl stop yggdrasil-sudo-ui-export.service || :
code=/opt/yggdrasil-sudo-ui
if [[ ! -f "$code/COMMIT" ||
      ! "$(cat "$code/COMMIT")" =~ ^[0-9a-f]{40}$ ]]; then
  echo "STOP: Export timer disabled; inspect unexpected source manifest before cleanup" >&2
  exit 1
fi
sudo rm -f -- \
  /etc/systemd/system/yggdrasil-sudo-ui-export.service \
  /etc/systemd/system/yggdrasil-sudo-ui-export.timer \
  "$code/sudo_ui_export.py" "$code/COMMIT"
sudo rmdir -- "$code" || {
  echo "WARNING: Extra exporter files remain; inspect manually" >&2
}
# Leave the root/systemd-owned state directory intact for audit,
# but remove the only anonymous status snapshot so the UI fails closed.
sudo rm -f -- /var/lib/yggdrasil-sudo-public/sudo-status.json
sudo systemctl daemon-reload
echo "PASS: Export timer removed; private sudo shadow sensor and database untouched"
echo "Existing web route (if deployed) now reports summary unavailable, not zero"
