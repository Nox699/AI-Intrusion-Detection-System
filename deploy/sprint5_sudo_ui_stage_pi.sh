#!/usr/bin/env bash
# Stage root-owned anonymous sudo UI exporter, but DO NOT activate it.
# No changes to the running sudo detector, SSH/UFW collectors, web, or Discord.
set -Eeuo pipefail
umask 077
sha="${1:-}"
if [[ ! "$sha" =~ ^[0-9a-f]{40}$ ||
      "$(hostname)" != "yggdrasil" || "$(id -un)" != "vidar" ]]; then
  echo "STOP: Run as vidar on Yggdrasil with reviewed 40-char Git SHA" >&2
  exit 2
fi
cd /home/vidar/AI-Intrusion-Detection-System
git fetch --no-tags origin integration/sprint5-sudo-clean
[[ "$(git rev-parse origin/integration/sprint5-sudo-clean)" == "$sha" ]] ||
  { echo "STOP: Branch changed; recheck SHA" >&2; exit 2; }

for unit in yggdrasil-collector.service yggdrasil-web.service yggdrasil-notifier.service yggdrasil-sudo-shadow.timer; do
  systemctl is-active --quiet "$unit" ||
    { echo "STOP: Existing required service inactive: $unit" >&2; exit 2; }
done
systemctl show yggdrasil-web.service -p SupplementaryGroups --value |
  tr ' ' '\n' | grep -Fxq yggdrasil-data ||
  { echo "STOP: Web reader is not in the existing yggdrasil-data group" >&2; exit 2; }
sudo -u yggdrasil-worker test -r /var/lib/yggdrasil-sudo-shadow/sudo-shadow.sqlite3 ||
  { echo "STOP: Worker cannot read private sudo staging database" >&2; exit 2; }

code=/opt/yggdrasil-sudo-ui
service=/etc/systemd/system/yggdrasil-sudo-ui-export.service
timer=/etc/systemd/system/yggdrasil-sudo-ui-export.timer
for item in "$code" "$service" "$timer" /var/lib/yggdrasil-sudo-public; do
  if sudo test -e "$item" || sudo test -L "$item"; then
    echo "STOP: Existing sudo UI installation/state; do not overwrite: $item" >&2
    exit 2
  fi
done

tmp="$(mktemp -d -t sudo-ui-stage-XXXXXX)"
staged=0
cleanup() {
  status=$?
  if ((status != 0 && staged == 1)); then
    sudo rm -f -- "$service" "$timer" "$code/sudo_ui_export.py" "$code/COMMIT"
    sudo rmdir -- "$code" 2>/dev/null || :
    sudo systemctl daemon-reload || :
  fi
  rm -rf -- "$tmp"
}
trap cleanup EXIT

git archive "$sha" \
  deploy/sprint5_sudo_ui_export.py \
  deploy/yggdrasil-sudo-ui-export.service \
  deploy/yggdrasil-sudo-ui-export.timer |
  tar -xf - -C "$tmp"
/usr/bin/python3 -m py_compile "$tmp/deploy/sprint5_sudo_ui_export.py"
staged=1
sudo install -d -o root -g root -m 0755 "$code"
sudo install -o root -g root -m 0644 \
  "$tmp/deploy/sprint5_sudo_ui_export.py" "$code/sudo_ui_export.py"
printf '%s\n' "$sha" > "$tmp/COMMIT"
sudo install -o root -g root -m 0644 "$tmp/COMMIT" "$code/COMMIT"
sudo install -o root -g root -m 0644 \
  "$tmp/deploy/yggdrasil-sudo-ui-export.service" "$service"
sudo install -o root -g root -m 0644 \
  "$tmp/deploy/yggdrasil-sudo-ui-export.timer" "$timer"
sudo systemd-analyze verify "$service" "$timer"
sudo systemctl daemon-reload
if systemctl is-active --quiet yggdrasil-sudo-ui-export.timer ||
   systemctl is-enabled --quiet yggdrasil-sudo-ui-export.timer; then
  echo "STOP: Export timer unexpectedly active/enabled" >&2
  exit 2
fi
staged=0
echo "PASS: sudo UI exporter staged; service and timer NOT started/enabled"
echo "Private sudo database and all existing IDS services unchanged"
