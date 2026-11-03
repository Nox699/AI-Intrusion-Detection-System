#!/usr/bin/env bash
# Stage isolated sudo shadow sensor code + units. DOES NOT start or enable them.
# No changes to production SSH/UFW/ML/web/notifier services or SQLite.
set -euo pipefail
umask 077

sha="${1:-}"
if [[ ! "$sha" =~ ^[0-9a-f]{40}$ ]]; then
  echo "STOP: Supply one reviewed, full commit SHA" >&2
  exit 2
fi
if [[ "$(hostname)" != "yggdrasil" || "$(id -un)" != "vidar" ]]; then
  echo "STOP: Run as vidar on Yggdrasil, never in the Ubuntu VM" >&2
  exit 2
fi

cd /home/vidar/AI-Intrusion-Detection-System
git fetch --no-tags origin integration/sprint5-sudo-clean
if [[ "$(git rev-parse origin/integration/sprint5-sudo-clean)" != "$sha" ]]; then
  echo "STOP: The reviewed branch SHA changed; recheck before installing" >&2
  exit 2
fi

for unit in yggdrasil-collector.service yggdrasil-web.service yggdrasil-notifier.service; do
  if ! systemctl is-active --quiet "$unit"; then
    echo "STOP: Required existing IDS service is not running: $unit" >&2
    exit 2
  fi
done
if ! id yggdrasil-worker >/dev/null; then
  echo "STOP: Existing worker account missing" >&2
  exit 2
fi
if [[ ! -x /opt/yggdrasil-ids/venv/bin/python ]]; then
  echo "STOP: Expected existing IDS virtualenv Python missing" >&2
  exit 2
fi

code=/opt/yggdrasil-sudo-shadow
service=/etc/systemd/system/yggdrasil-sudo-shadow.service
timer=/etc/systemd/system/yggdrasil-sudo-shadow.timer
if sudo test -e "$code" || sudo test -L "$code" ||
   sudo test -e "$service" || sudo test -L "$service" ||
   sudo test -e "$timer" || sudo test -L "$timer"; then
  echo "STOP: Shadow installation already exists; review it, do not overwrite" >&2
  exit 2
fi
if systemctl is-active --quiet yggdrasil-sudo-shadow.timer ||
   systemctl is-active --quiet yggdrasil-sudo-shadow.service; then
  echo "STOP: Shadow timer/service unexpectedly active" >&2
  exit 2
fi

tmp="$(mktemp -d -t yggdrasil-sudo-stage-XXXXXX)"
installed=0
cleanup() {
  status=$?
  if (( status != 0 && installed == 1 )); then
    echo "Installation failed: removing newly staged code/units only" >&2
    sudo rm -f -- "$service" "$timer"
    sudo rm -f -- \
      "$code/src/yggdrasil_ids/__init__.py" \
      "$code/src/yggdrasil_ids/sudo_rules.py" \
      "$code/src/yggdrasil_ids/sudo_storage.py" \
      "$code/deploy/sprint5_sudo_shadow_poll.py" "$code/COMMIT"
    sudo rmdir -- \
      "$code/src/yggdrasil_ids" "$code/src" "$code/deploy" "$code" 2>/dev/null || :
    sudo systemctl daemon-reload || :
  fi
  rm -rf -- "$tmp"
}
trap cleanup EXIT

git archive "$sha" \
  src/yggdrasil_ids/__init__.py \
  src/yggdrasil_ids/sudo_rules.py \
  src/yggdrasil_ids/sudo_storage.py \
  deploy/sprint5_sudo_shadow_poll.py \
  deploy/yggdrasil-sudo-shadow.service \
  deploy/yggdrasil-sudo-shadow.timer |
  tar -xf - -C "$tmp"

python3 -m py_compile "$tmp/deploy/sprint5_sudo_shadow_poll.py"

echo "=== Installing only isolated sudo shadow source and units ==="
installed=1
sudo install -d -o root -g root -m 0755 \
  "$code" "$code/src" "$code/src/yggdrasil_ids" "$code/deploy"

for file in __init__.py sudo_rules.py sudo_storage.py; do
  sudo install -o root -g root -m 0644 \
    "$tmp/src/yggdrasil_ids/$file" "$code/src/yggdrasil_ids/$file"
done
sudo install -o root -g root -m 0644 \
  "$tmp/deploy/sprint5_sudo_shadow_poll.py" "$code/deploy/sprint5_sudo_shadow_poll.py"
sudo install -o root -g root -m 0644 \
  "$tmp/deploy/yggdrasil-sudo-shadow.service" "$service"
sudo install -o root -g root -m 0644 \
  "$tmp/deploy/yggdrasil-sudo-shadow.timer" "$timer"
printf '%s\n' "$sha" > "$tmp/COMMIT"
sudo install -o root -g root -m 0644 "$tmp/COMMIT" "$code/COMMIT"

sudo systemd-analyze verify "$service" "$timer"
sudo systemctl daemon-reload

if systemctl is-active --quiet yggdrasil-sudo-shadow.timer ||
   systemctl is-active --quiet yggdrasil-sudo-shadow.service; then
  echo "STOP: Unexpected service activation during install" >&2
  exit 2
fi
if systemctl is-enabled --quiet yggdrasil-sudo-shadow.timer; then
  echo "STOP: Shadow timer unexpectedly enabled during install" >&2
  exit 2
fi

echo "RESULT: shadow code and units staged successfully"
echo "Shadow timer started: NO"
echo "Shadow timer enabled: NO"
echo "Production IDS services modified: NO"
echo "Production SQLite or Discord modified: NO"
echo "NEXT: Start the service one time, verify output, then separately enable timer"
installed=0
