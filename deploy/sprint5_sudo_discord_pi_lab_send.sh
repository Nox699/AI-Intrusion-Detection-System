#!/usr/bin/env bash
# Explicitly gated, one-message Discord SUDO LABTEST from the trusted Pi.
# No webhook is printed or copied, and no production databases are touched.
set -euo pipefail
umask 077

sha="${1:-}"
if [[ ! "$sha" =~ ^[0-9a-f]{40}$ ]]; then
  echo "STOP: Expected a full, pinned Git commit SHA" >&2
  exit 2
fi

if [[ "$(hostname)" != "yggdrasil" || "$(id -un)" != "vidar" ]]; then
  echo "STOP: Run on Yggdrasil as vidar, not inside the Ubuntu VM" >&2
  exit 2
fi

cd /home/vidar/AI-Intrusion-Detection-System

git fetch --no-tags origin integration/sprint5-sudo-clean
if [[ "$(git rev-parse origin/integration/sprint5-sudo-clean)" != "$sha" ]]; then
  echo "STOP: Branch SHA changed; review the new commit before sending" >&2
  exit 2
fi
if ! systemctl is-active --quiet yggdrasil-notifier.service; then
  echo "STOP: Existing production notifier is not active; do not send" >&2
  exit 2
fi
if ! id yggdrasil-notifier >/dev/null 2>&1; then
  echo "STOP: Restricted notifier service account does not exist" >&2
  exit 2
fi

tmp="$(mktemp -d -t yggdrasil-sudo-labcode-XXXXXX)"
cleanup() { rm -rf -- "$tmp"; }
trap cleanup EXIT

git archive "$sha" \
  src \
  deploy/sprint5_sudo_discord_delivery_smoketest.py |
  tar -xf - -C "$tmp"

# The source checkout has no credentials. Let the restricted systemd service
# read its code while it obtains its webhook ONLY via LoadCredential.
chmod -R a+rX "$tmp"

echo "=== Offline sudo-LABTEST (no network) ==="
PYTHONPATH="$tmp/src" /opt/yggdrasil-ids/venv/bin/python \
  "$tmp/deploy/sprint5_sudo_discord_delivery_smoketest.py"

echo
echo "Næste trin sender PRÆCIS ÉN rigtig Discord-LABTEST fra Yggdrasil."
echo "Det er IKKE en ny sudo-hændelse eller en automatisk produktionsalarm."
printf "Skriv SEND for at fortsætte, eller andet for at afbryde: "

choice=""
IFS= read -r choice </dev/tty
if [[ "$choice" != "SEND" ]]; then
  echo "Ingen rigtig Discord-besked sendt."
  exit 0
fi

echo "=== Sender én mærket sudo-LABTEST gennem eksisterende notifierkode ==="

unit="yggdrasil-sudo-labtest-$(date +%s)-$$"

sudo systemd-run \
  --unit="$unit" \
  --wait --pipe --collect \
  --property=User=yggdrasil-notifier \
  --property=Group=yggdrasil-notifier \
  --property=LoadCredential=discord-webhook.url:/etc/yggdrasil-ids/discord-webhook.url \
  --property=NoNewPrivileges=yes \
  --property=ProtectSystem=strict \
  --property=ReadWritePaths=/tmp \
  --property=ProtectHome=yes \
  --property=PrivateDevices=yes \
  --property=ProtectKernelTunables=yes \
  --property=ProtectKernelModules=yes \
  --property=ProtectControlGroups=yes \
  --property=RestrictSUIDSGID=yes \
  --property=LockPersonality=yes \
  --property="RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6" \
  --property=UMask=0077 \
  --property=MemoryMax=128M \
  --property=TasksMax=16 \
  /usr/bin/env "PYTHONPATH=$tmp/src" \
  /opt/yggdrasil-ids/venv/bin/python \
  "$tmp/deploy/sprint5_sudo_discord_delivery_smoketest.py" \
  --send-real --confirm-lab-message

echo "Kontroller SUDO LABTEST-beskeden i Discord, og gem screenshot som S5-07."
