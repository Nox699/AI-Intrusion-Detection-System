#!/usr/bin/env bash
# Upgrade ONLY the anonymous sudo UI exporter to publish a second compatible
# sudo-activity.json timeline. Existing sudo-status.json schema is unchanged.
# No production web, collector, sudo sensor or notifier restart.
set -Eeuo pipefail
umask 077

sha="$1"
old="02de116b4a2a90435b4135e220be8371687c2576"
if [[ ! "$sha" =~ ^[0-9a-f]{40}$ ||
      "$(hostname)" != "yggdrasil" || "$(id -un)" != "vidar" ]]; then
  echo "STOP: Run as vidar on Yggdrasil with reviewed full source SHA" >&2
  exit 2
fi

cd /home/vidar/AI-Intrusion-Detection-System
git fetch --no-tags origin integration/sprint5-sudo-clean
if [[ "$(git rev-parse origin/integration/sprint5-sudo-clean)" != "$sha" ]]; then
  echo "STOP: GitHub branch changed; review and pin again" >&2
  exit 2
fi

code=/opt/yggdrasil-sudo-ui/sudo_ui_export.py
manifest=/opt/yggdrasil-sudo-ui/COMMIT
status=/var/lib/yggdrasil-sudo-public/sudo-status.json
activity=/var/lib/yggdrasil-sudo-public/sudo-activity.json
backup="/var/backups/yggdrasil-ids/sprint5-sudo-activity-before-$sha"
if [[ "$(cat "$manifest")" != "$old" ]] ||
   ! cmp -s "$code" <(git show "$old:deploy/sprint5_sudo_ui_export.py"); then
  echo "STOP: Previous installed exporter does not match reviewed v1" >&2
  exit 2
fi
if sudo test -e "$activity" || sudo test -L "$activity" ||
   sudo test -e "$backup" || sudo test -L "$backup"; then
  echo "STOP: Activity export or backup already exists; inspect, do not overwrite" >&2
  exit 2
fi
for unit in yggdrasil-collector.service yggdrasil-web.service yggdrasil-notifier.service yggdrasil-sudo-shadow.timer yggdrasil-sudo-ui-export.timer; do
  systemctl is-active --quiet "$unit" ||
    { echo "STOP: Required existing unit inactive: $unit" >&2; exit 2; }
done
systemctl is-enabled --quiet yggdrasil-sudo-ui-export.timer ||
  { echo "STOP: Existing exporter timer not enabled" >&2; exit 2; }
sudo test -s "$status" || { echo "STOP: Existing status export missing" >&2; exit 2; }

tmp="$(mktemp -d -t sudo-activity-upgrade-XXXXXX)"
paused=0
changed=0
recover() {
  result=$?
  if ((result != 0)); then
    echo "STOP: Upgrading exporter failed, restoring v1 exporter and timer" >&2
    if ((changed == 1)); then
      sudo install -o root -g root -m 0644 "$backup/sudo_ui_export.py" "$code" || :
      sudo rm -f -- "$activity" || :
      sudo systemctl start yggdrasil-sudo-ui-export.service || :
    fi
    if ((paused == 1)); then
      sudo systemctl start yggdrasil-sudo-ui-export.timer || :
    fi
  fi
  rm -rf -- "$tmp"
}
trap recover EXIT

git show "$sha:deploy/sprint5_sudo_ui_export.py" > "$tmp/sudo_ui_export.py"
/usr/bin/python3 -m py_compile "$tmp/sudo_ui_export.py"
sudo install -d -o root -g root -m 0700 "$backup"
sudo install -o root -g root -m 0600 "$code" "$backup/sudo_ui_export.py"
printf '%s\n' "$old" > "$tmp/old-commit"
sudo install -o root -g root -m 0600 "$tmp/old-commit" "$backup/previous-commit"

sudo systemctl stop yggdrasil-sudo-ui-export.timer
paused=1
sudo systemctl stop yggdrasil-sudo-ui-export.service
changed=1
sudo install -o root -g root -m 0644 "$tmp/sudo_ui_export.py" "$code"

echo "=== Verify first process-level export; no raw identities ==="
sudo systemctl start yggdrasil-sudo-ui-export.service
[[ "$(systemctl show yggdrasil-sudo-ui-export.service -p Result --value)" == "success" ]] ||
  { echo "STOP: Upgraded exporter service not successful" >&2; exit 1; }

sudo /usr/bin/setpriv --reuid=yggdrasil-web --regid=yggdrasil-web --groups=yggdrasil-data \
  /usr/bin/python3 - <<'PY'
import json
from pathlib import Path
directory = Path("/var/lib/yggdrasil-sudo-public")
old = json.loads((directory / "sudo-status.json").read_text())
new = json.loads((directory / "sudo-activity.json").read_text())
assert old["format"] == "sudo-shadow-summary-v1"
assert new["format"] == "sudo-shadow-activity-v1"
assert new["mode"] == "shadow" and new["sends_alerts"] is False
assert new["shares_production_database"] is False
assert new["latest_limit"] == 15 and len(new["latest"]) <= 15
assert new["candidate_limit"] == 8 and len(new["candidates"]) <= 8
for item in new["latest"]:
    assert set(item) == {"timestamp", "category", "attention", "detector_id"}
for item in new["candidates"]:
    assert set(item) == {"timestamp", "detector_id", "process_count"}
raw = json.dumps(new)
for secret in ("uid", "pid", "boot_id", "event_id", "cursor", "MESSAGE", "COMMAND"):
    assert secret not in raw
print("PASS: Original status format compatible; new anonymous process timeline readable")
print("Visible sudo processes:", len(new["latest"]))
print("Visible recent rule candidates:", len(new["candidates"]))
PY

sudo /usr/bin/setpriv --reuid=yggdrasil-web --regid=yggdrasil-web --groups=yggdrasil-data \
  /usr/bin/test ! -r /var/lib/yggdrasil-sudo-shadow/sudo-shadow.sqlite3

sudo systemctl start yggdrasil-sudo-ui-export.timer
paused=0
systemctl is-active --quiet yggdrasil-sudo-ui-export.timer
for unit in yggdrasil-collector.service yggdrasil-web.service yggdrasil-notifier.service yggdrasil-sudo-shadow.timer; do
  systemctl is-active --quiet "$unit" ||
    { echo "STOP: Existing IDS component inactive after exporter upgrade: $unit" >&2; exit 1; }
done
echo "PASS: Recent sudo timeline exporter active; existing dashboard remains unchanged"
echo "Original exporter backed up: $backup"
echo "No raw journal/command/UID/PID stored in public JSON"
changed=0
