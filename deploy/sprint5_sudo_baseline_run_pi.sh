#!/usr/bin/env bash
# Restore original Sprint5 experimental policy with full data; no deployment.
set -Eeuo pipefail
umask 077
sha="${1:-}"
dataset="${2:-}"
branch=experiment/sudo-if-v2
if [[ ! "$sha" =~ ^[0-9a-f]{40}$ || "$(hostname)" != yggdrasil || "$(id -un)" != vidar ]]; then
  echo "STOP: Run as vidar on Yggdrasil with the reviewed full SHA" >&2
  exit 2
fi
if [[ "$dataset" != /home/vidar/yggdrasil-sudo-real-private/*.json || ! -f "$dataset" ]]; then
  echo "STOP: Supply the existing private sudo process export" >&2
  exit 2
fi
cd /home/vidar/AI-Intrusion-Detection-System
git fetch --no-tags origin "refs/heads/$branch:refs/remotes/origin/$branch"
[[ "$(git rev-parse "origin/$branch")" == "$sha" ]] ||
  { echo "STOP: Research branch changed" >&2; exit 2; }
source_dir="$(mktemp -d -t sudo-baseline-source-XXXXXX)"
trap 'rm -rf -- "$source_dir"' EXIT
git archive "$sha" \
  src/yggdrasil_ids/__init__.py \
  src/yggdrasil_ids/sudo_rules.py \
  src/yggdrasil_ids/sudo_storage.py \
  src/yggdrasil_ids/sudo_ml.py \
  deploy/sprint5_sudo_ml_lab.py \
  deploy/sprint5_sudo_ml_v2_lab.py \
  deploy/sprint5_sudo_mixed_ml_lab.py \
  deploy/sprint5_sudo_baseline_replay.py | tar -xf - -C "$source_dir"
private=/home/vidar/yggdrasil-sudo-ml-private
mkdir -p -m 0700 -- "$private"
chmod 0700 -- "$private"
target="$private/sudo-original-baseline-$(date -u +%Y%m%dT%H%M%S)-$$"
PYTHONPATH="$source_dir/src" PYTHONDONTWRITEBYTECODE=1 \
  OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 \
  /opt/yggdrasil-ids/venv/bin/python "$source_dir/deploy/sprint5_sudo_baseline_replay.py" \
  --dataset "$dataset" --directory "$target"
