#!/usr/bin/env bash
# Explicit rollback of ONLY the anonymous sudo process timeline exporter.
# The original status.json schema and private sudo shadow sensor remain intact.
set -Eeuo pipefail
umask 077

sha="$1"
if [[ ! "$sha" =~ ^[0-9a-f]{40}$ ||
      "$(hostname)" != "yggdrasil" || "$(id -un)" != "vidar" ]]; then
  echo "STOP: Run as vidar on Yggdrasil with original upgrade SHA" >&2
  exit 2
fi
cd /home/vidar/AI-Intrusion-Detection-System
code=/opt/yggdrasil-sudo-ui/sudo_ui_export.py
manifest=/opt/yggdrasil-sudo-ui/COMMIT
activity=/var/lib/yggdrasil-sudo-public/sudo-activity.json
backup="/var/backups/yggdrasil-ids/sprint5-sudo-activity-before-$sha"

if [[ "$(cat "$manifest")" != "$sha" ]] ||
   ! cmp -s "$code" <(git show "$sha:deploy/sprint5_sudo_ui_export.py"); then
  echo "STOP: Installed exporter changed; refuse to replace unknown code" >&2
  exit 2
fi
sudo test -s "$backup/sudo_ui_export.py" &&
sudo test -s "$backup/previous-commit" ||
  { echo "STOP: Verified original exporter backup not found" >&2; exit 2; }
[[ "$(sudo cat "$backup/previous-commit")" == "02de116b4a2a90435b4135e220be8371687c2576" ]] ||
  { echo "STOP: Unexpected previous exporter revision" >&2; exit 2; }

echo "=== Restore original anonymous sudo summary exporter only ==="
sudo systemctl stop yggdrasil-sudo-ui-export.timer
sudo systemctl stop yggdrasil-sudo-ui-export.service
sudo install -o root -g root -m 0644 "$backup/sudo_ui_export.py" "$code"
sudo install -o root -g root -m 0644 "$backup/previous-commit" "$manifest"
sudo rm -f -- "$activity"
sudo systemctl start yggdrasil-sudo-ui-export.service
sudo systemctl start yggdrasil-sudo-ui-export.timer
systemctl is-active --quiet yggdrasil-sudo-ui-export.timer
echo "PASS: v1 exporter restored; no changes to private sudo or production IDS"
echo "The optional new activity page will correctly show unavailable until reactivated"
