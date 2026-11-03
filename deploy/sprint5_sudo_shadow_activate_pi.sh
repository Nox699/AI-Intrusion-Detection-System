#!/usr/bin/env bash
# Second, explicit activation gate after manual sudo-shadow Pi probe + staging.
# Tests one systemd oneshot before enabling the every-minute shadow timer.
# No Discord, production DB, SSH/UFW, AI model, or active IDS service changes.
set -euo pipefail

sha="${1:-}"
if [[ ! "$sha" =~ ^[0-9a-f]{40}$ ]]; then
  echo "STOP: Full pinned SHA required" >&2
  exit 2
fi
if [[ "$(hostname)" != "yggdrasil" || "$(id -un)" != "vidar" ]]; then
  echo "STOP: Run as vidar on Yggdrasil only" >&2
  exit 2
fi
cd /home/vidar/AI-Intrusion-Detection-System
if [[ ! -f /opt/yggdrasil-sudo-shadow/COMMIT ]] ||
   [[ "$(cat /opt/yggdrasil-sudo-shadow/COMMIT)" != "$sha" ]]; then
  echo "STOP: Installed sudo shadow commit does not match pinned SHA" >&2
  exit 2
fi
for file in \
  src/yggdrasil_ids/__init__.py \
  src/yggdrasil_ids/sudo_rules.py \
  src/yggdrasil_ids/sudo_storage.py \
  deploy/sprint5_sudo_shadow_poll.py; do
  if ! cmp -s <(git show "$sha:$file") "/opt/yggdrasil-sudo-shadow/$file"; then
    echo "STOP: Installed source differs: $file" >&2
    exit 2
  fi
done
for unit in yggdrasil-sudo-shadow.service yggdrasil-sudo-shadow.timer; do
  if ! cmp -s \
    <(git show "$sha:deploy/$unit") \
    "/etc/systemd/system/$unit"; then
    echo "STOP: Installed sudo unit differs: $unit" >&2
    exit 2
  fi
done
if systemctl is-active --quiet yggdrasil-sudo-shadow.timer ||
   systemctl is-enabled --quiet yggdrasil-sudo-shadow.timer; then
  echo "STOP: Sudo shadow timer is already active/enabled" >&2
  exit 2
fi
for unit in yggdrasil-collector.service yggdrasil-web.service yggdrasil-notifier.service; do
  if ! systemctl is-active --quiet "$unit"; then
    echo "STOP: Existing IDS service is not active: $unit" >&2
    exit 2
  fi
done

activated=0
cleanup() {
  status=$?
  if (( status != 0 && activated == 1 )); then
    echo "STOP: Disabling just-activated sudo shadow timer after validation failure" >&2
    sudo systemctl disable --now yggdrasil-sudo-shadow.timer || :
    sudo systemctl stop yggdrasil-sudo-shadow.service || :
  fi
}
trap cleanup EXIT

echo "=== Run exactly one isolated sudo shadow service poll ==="
sudo systemctl start yggdrasil-sudo-shadow.service

result="$(systemctl show yggdrasil-sudo-shadow.service -p Result --value)"
if [[ "$result" != "success" ]]; then
  echo "STOP: Sudo shadow one-shot did not complete successfully: $result" >&2
  exit 1
fi

echo "=== Enable the isolated one-minute shadow timer ==="
activated=1
sudo systemctl enable --now yggdrasil-sudo-shadow.timer
if ! systemctl is-active --quiet yggdrasil-sudo-shadow.timer ||
   ! systemctl is-enabled --quiet yggdrasil-sudo-shadow.timer; then
  echo "STOP: Sudo shadow timer was not enabled and active" >&2
  exit 1
fi
for unit in yggdrasil-collector.service yggdrasil-web.service yggdrasil-notifier.service; do
  if ! systemctl is-active --quiet "$unit"; then
    echo "STOP: Existing IDS service changed status: $unit" >&2
    exit 1
  fi
done

echo "=== Shadow-only sudo unit summary ==="
systemctl list-timers yggdrasil-sudo-shadow.timer --no-pager
systemctl show yggdrasil-sudo-shadow.timer -p ActiveState -p Unit
systemctl show yggdrasil-sudo-shadow.service -p Result -p User -p Group -p PrivateNetwork -p NoNewPrivileges -p ProtectSystem
echo "=== Last 25 lines of sanitized sudo shadow poll output ==="
sudo journalctl -u yggdrasil-sudo-shadow.service -n 25 --no-pager --output=cat

echo "RESULT: sudo shadow timer enabled and active"
echo "Notification state: SHADOW ONLY (no Discord/outbox)"
echo "Existing collector/web/notifier services: active"
echo "Rollback (immediate): sudo systemctl disable --now yggdrasil-sudo-shadow.timer"
activated=0
