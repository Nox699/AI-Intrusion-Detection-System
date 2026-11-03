#!/usr/bin/env bash
# Explicit bounded controlled test. Scoring only; no deployment/model changes.
set -Eeuo pipefail
umask 077
sha="${1:-}"
baseline="${2:-}"
branch=experiment/sudo-if-v2
if [[ ! "$sha" =~ ^[0-9a-f]{40}$ || "$(hostname)" != yggdrasil || "$(id -un)" != vidar ]]; then
  echo "STOP: Run as vidar on Yggdrasil with reviewed full source SHA" >&2
  exit 2
fi
if [[ "$baseline" != /home/vidar/yggdrasil-sudo-ml-private/sudo-original-baseline-* || ! -f "$baseline/report.json" ]]; then
  echo "STOP: Supply the existing private original-baseline folder" >&2
  exit 2
fi
cd /home/vidar/AI-Intrusion-Detection-System
git fetch --no-tags origin "refs/heads/$branch:refs/remotes/origin/$branch"
[[ "$(git rev-parse "origin/$branch")" == "$sha" ]] ||
  { echo "STOP: Research branch changed" >&2; exit 2; }
source_dir="$(mktemp -d -t sudo-frozen-probe-XXXXXX)"
trap 'rm -rf -- "$source_dir"' EXIT
git archive "$sha" \
  src/yggdrasil_ids/__init__.py \
  src/yggdrasil_ids/sudo_rules.py \
  src/yggdrasil_ids/sudo_storage.py \
  src/yggdrasil_ids/sudo_ml.py \
  deploy/sprint5_sudo_frozen_probe.py | tar -xf - -C "$source_dir"
target="/home/vidar/yggdrasil-sudo-ml-private/sudo-frozen-probe-$(date -u +%Y%m%dT%H%M%S)-$$"
PYTHONPATH="$source_dir/src" PYTHONDONTWRITEBYTECODE=1 \
  OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 \
  /opt/yggdrasil-ids/venv/bin/python "$source_dir/deploy/sprint5_sudo_frozen_probe.py" \
  --baseline "$baseline" --directory "$target" --run-controlled-probe
