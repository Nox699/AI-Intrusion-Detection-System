#!/usr/bin/env bash
# Isolated synthetic sudo Isolation Forest experiment. DOES NOT deploy a model.
# Never reads production journal, sudo-shadow SQLite, notifier or webhook.
set -euo pipefail
umask 077

sha="${1:-}"
if [[ ! "$sha" =~ ^[0-9a-f]{40}$ ]]; then
  echo "STOP: Provide the approved full commit SHA" >&2
  exit 2
fi
if [[ "$(hostname)" != "yggdrasil" || "$(id -un)" != "vidar" ]]; then
  echo "STOP: Run as vidar on Yggdrasil" >&2
  exit 2
fi

cd /home/vidar/AI-Intrusion-Detection-System
git fetch --no-tags origin integration/sprint5-sudo-clean
if [[ "$(git rev-parse origin/integration/sprint5-sudo-clean)" != "$sha" ]]; then
  echo "STOP: Branch SHA changed; do not run an unreviewed version" >&2
  exit 2
fi

for unit in yggdrasil-collector.service yggdrasil-web.service yggdrasil-notifier.service yggdrasil-sudo-shadow.timer; do
  if ! systemctl is-active --quiet "$unit"; then
    echo "STOP: Required existing service not active: $unit" >&2
    exit 2
  fi
done
if [[ ! -x /opt/yggdrasil-ids/venv/bin/python ]]; then
  echo "STOP: Existing Python environment missing" >&2
  exit 2
fi

source_dir="$(mktemp -d -t sudo-if-lab-source-XXXXXX)"
trap 'rm -rf -- "$source_dir"' EXIT

git archive "$sha" \
  src/yggdrasil_ids/__init__.py \
  src/yggdrasil_ids/sudo_rules.py \
  src/yggdrasil_ids/sudo_storage.py \
  src/yggdrasil_ids/sudo_ml.py \
  deploy/sprint5_sudo_ml_lab.py |
  tar -xf - -C "$source_dir"

private="$HOME/yggdrasil-sudo-ml-private"
mkdir -p -m 0700 -- "$private"
chmod 0700 -- "$private"
target="$private/sudo-if-$(date -u +%Y%m%dT%H%M%S)-$$"

echo "=== Isoleret sudo ML vs. regelbaseret benchmark ==="
PYTHONPATH="$source_dir/src" \
  /opt/yggdrasil-ids/venv/bin/python \
  "$source_dir/deploy/sprint5_sudo_ml_lab.py" \
  --directory "$target"

echo "=== Resultater gemt privat ==="
echo "Private experiment folder: $target"
echo "Only synthetic normal training; NO real sudo data included"
echo "Production sudo-shadow: unchanged"
echo "Production SSH/ML/UFW/Discord: unchanged"
