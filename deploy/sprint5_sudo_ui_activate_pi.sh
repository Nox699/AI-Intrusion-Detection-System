#!/usr/bin/env bash
# Explicit second-stage activation of the anonymous sudo UI export timer.
set -Eeuo pipefail
umask 077
sha="${1:-}"
if [[ ! "$sha" =~ ^[0-9a-f]{40}$ ||
      "$(hostname)" != "yggdrasil" || "$(id -un)" != "vidar" ]]; then
  echo "STOP: Run as vidar on Yggdrasil with pinned SHA" >&2
  exit 2
fi
cd /home/vidar/AI-Intrusion-Detection-System
if [[ "$(cat /opt/yggdrasil-sudo-ui/COMMIT)" != "$sha" ]]; then
  echo "STOP: Installed sudo UI exporter does not match pinned SHA" >&2
  exit 2
fi
for entry in \
  deploy/sprint5_sudo_ui_export.py \
  deploy/yggdrasil-sudo-ui-export.service \
  deploy/yggdrasil-sudo-ui-export.timer; do
  case "$entry" in
    deploy/sprint5_sudo_ui_export.py)
      installed=/opt/yggdrasil-sudo-ui/sudo_ui_export.py ;;
    *)
      installed=/etc/systemd/system/${entry#deploy/} ;;
  esac
  cmp -s <(git show "$sha:$entry") "$installed" ||
    { echo "STOP: Staged file differs from Git: $entry" >&2; exit 2; }
done
if systemctl is-active --quiet yggdrasil-sudo-ui-export.timer ||
   systemctl is-enabled --quiet yggdrasil-sudo-ui-export.timer; then
  echo "STOP: Export timer already active/enabled" >&2
  exit 2
fi
for unit in yggdrasil-collector.service yggdrasil-web.service yggdrasil-notifier.service yggdrasil-sudo-shadow.timer; do
  systemctl is-active --quiet "$unit" ||
    { echo "STOP: Required IDS component inactive: $unit" >&2; exit 2; }
done

enabled=0
rollback_timer() {
  status=$?
  if ((status != 0 && enabled == 1)); then
    sudo systemctl disable --now yggdrasil-sudo-ui-export.timer || :
    sudo systemctl stop yggdrasil-sudo-ui-export.service || :
  fi
}
trap rollback_timer EXIT

echo "=== First export from private sudo SQLite as worker ==="
sudo systemctl start yggdrasil-sudo-ui-export.service
[[ "$(systemctl show yggdrasil-sudo-ui-export.service -p Result --value)" == "success" ]] ||
  { echo "STOP: Export service failed" >&2; exit 1; }
if ! sudo -u yggdrasil-web test -r /var/lib/yggdrasil-sudo-public/sudo-status.json; then
  echo "STOP: Web user cannot read the anonymous snapshot" >&2
  exit 1
fi
if sudo -u yggdrasil-web test -r /var/lib/yggdrasil-sudo-shadow/sudo-shadow.sqlite3; then
  echo "STOP: Web user unexpectedly accesses private sudo SQLite" >&2
  exit 1
fi
sudo -u yggdrasil-web /usr/bin/python3 - <<'PY'
import json
from pathlib import Path
file = Path("/var/lib/yggdrasil-sudo-public/sudo-status.json")
data = json.loads(file.read_text())
assert data["format"] == "sudo-shadow-summary-v1"
assert data["mode"] == "shadow"
assert data["sends_alerts"] is False
assert data["shares_production_database"] is False
assert type(data["recent_signals"]) is int
assert set(data["categories"]) == {
    "command_invoked", "pam_auth_failure", "incorrect_password", "not_in_sudoers",
    "pam_session_opened", "pam_session_closed", "other_sudo",
}
assert set(data["candidate_detectors"]) == {
    "sudo.permission_denied", "sudo.repeated_auth_failure"
}
print("PASS: Web user can read only safe anonymous sudo summary")
print("Export checkpoint:", data["checkpoint_at"])
print("Last 24h sudo log entries:", data["recent_signals"])
print("Last 24h rule matches:", sum(data["candidate_detectors"].values()))
PY

echo "=== Enable separate 60-second sudo UI exporter timer ==="
enabled=1
sudo systemctl enable --now yggdrasil-sudo-ui-export.timer
systemctl is-active --quiet yggdrasil-sudo-ui-export.timer
systemctl is-enabled --quiet yggdrasil-sudo-ui-export.timer
for unit in yggdrasil-collector.service yggdrasil-web.service yggdrasil-notifier.service yggdrasil-sudo-shadow.timer; do
  systemctl is-active --quiet "$unit" ||
    { echo "STOP: Existing IDS service changed state: $unit" >&2; exit 1; }
done
systemctl list-timers yggdrasil-sudo-ui-export.timer --no-pager
echo "PASS: Anonymous sudo dashboard export ACTIVE; production web, ML, SQLite and Discord unchanged"
echo "Rollback: sudo systemctl disable --now yggdrasil-sudo-ui-export.timer"
enabled=0
