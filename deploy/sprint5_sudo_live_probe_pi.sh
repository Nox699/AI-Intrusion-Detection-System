#!/usr/bin/env bash
# Three real auth failures through the active detector and existing notifier.
set -Eeuo pipefail
umask 077
sha="${1:-}"
branch=experiment/sudo-if-v2
if [[ ! "$sha" =~ ^[0-9a-f]{40}$ || "$(hostname)" != yggdrasil || "$(id -un)" != vidar ]]; then
  echo "STOP: Run as vidar on Yggdrasil with the reviewed full commit SHA" >&2
  exit 2
fi
cd /home/vidar/AI-Intrusion-Detection-System
git fetch --no-tags origin "refs/heads/$branch:refs/remotes/origin/$branch"
[[ "$(git rev-parse "origin/$branch")" == "$sha" ]] ||
  { echo "STOP: Research branch changed" >&2; exit 2; }
source_dir="$(mktemp -d -t sudo-live-probe-XXXXXX)"
trap 'rm -rf -- "$source_dir"' EXIT
git archive "$sha" deploy/sprint5_sudo_live_probe.py deploy/sprint5_sudo_frozen_probe.py |
  tar -xf - -C "$source_dir"
# Public code only; the sudo inspector must be able to traverse it.
chmod -R a+rX "$source_dir"
cd /opt/yggdrasil-ids
PYTHONPATH=/opt/yggdrasil-sudo-integration/src PYTHONDONTWRITEBYTECODE=1 \
  OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 \
  /opt/yggdrasil-ids/venv/bin/python "$source_dir/deploy/sprint5_sudo_live_probe.py" --run-live-probe
