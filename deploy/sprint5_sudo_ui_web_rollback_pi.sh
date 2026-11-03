#!/usr/bin/env bash
# Revert only web-overlay drop-in, restoring original dashboard import path.
# Do not rewind or modify production IDS SQLite/Discord or sudo shadow data.
set -Eeuo pipefail
umask 077
sha="${1:-}"
if [[ ! "$sha" =~ ^[0-9a-f]{40}$ ||
      "$(hostname)" != "yggdrasil" || "$(id -un)" != "vidar" ]]; then
  echo "STOP: Run as vidar on Yggdrasil with original UI source SHA" >&2
  exit 2
fi
base=/opt/yggdrasil-sudo-ui-web
[[ "$(cat "$base/COMMIT")" == "$sha" ]] ||
  { echo "STOP: Preview source SHA mismatch" >&2; exit 2; }
override=/etc/systemd/system/yggdrasil-web.service.d/50-sudo-dashboard.conf
if ! sudo test -e "$override" || sudo test -L "$override"; then
  echo "STOP: Exact sudo web override not found as a regular file" >&2
  exit 2
fi
expected="$(cat <<'CONF'
[Service]
# Web-only import overlay. Existing virtualenv, collector and notifier untouched.
Environment=PYTHONPATH=/opt/yggdrasil-sudo-ui-web/src
ReadOnlyPaths=/var/lib/yggdrasil-sudo-public
CONF
)"
if [[ "$(sudo cat "$override")" != "$expected" ]]; then
  echo "STOP: Override contents were modified; refuse to delete unknown config" >&2
  exit 2
fi
sudo rm -f -- "$override"
sudo systemctl daemon-reload
sudo systemctl restart yggdrasil-web.service
systemctl is-active --quiet yggdrasil-web.service ||
  { echo "STOP: Original web service did not recover" >&2; exit 1; }
for unit in yggdrasil-collector.service yggdrasil-notifier.service yggdrasil-sudo-shadow.timer yggdrasil-sudo-ui-export.timer; do
  systemctl is-active --quiet "$unit" ||
    { echo "STOP: Existing IDS component inactive: $unit" >&2; exit 1; }
done
echo "PASS: Original web package restored through original systemd service; SQLite untouched"
echo "Anonymous exporter and sudo shadow remain active independently"
