#!/usr/bin/env bash
# Inspect frozen private validation scores. Never deploy or change thresholds.
set -Eeuo pipefail
umask 077

sha="${1:-}"
dataset="${2:-}"
report="${3:-}"
branch=experiment/sudo-if-v2
if [[ ! "$sha" =~ ^[0-9a-f]{40}$ || "$(hostname)" != yggdrasil || "$(id -un)" != vidar ]]; then
  echo "STOP: Run as vidar on Yggdrasil with reviewed full source SHA" >&2
  exit 2
fi
if [[ "$dataset" != /home/vidar/yggdrasil-sudo-real-private/*.json || ! -f "$dataset" ||
      "$report" != /home/vidar/yggdrasil-sudo-ml-private/*/report.json || ! -f "$report" ]]; then
  echo "STOP: Supply the existing private dataset and original report" >&2
  exit 2
fi
cd /home/vidar/AI-Intrusion-Detection-System
git fetch --no-tags origin "refs/heads/$branch:refs/remotes/origin/$branch"
[[ "$(git rev-parse "origin/$branch")" == "$sha" ]] ||
  { echo "STOP: Research branch changed" >&2; exit 2; }

source_dir="$(mktemp -d -t sudo-score-source-XXXXXX)"
trap 'rm -rf -- "$source_dir"' EXIT
git archive "$sha" \
  src/yggdrasil_ids/__init__.py \
  src/yggdrasil_ids/sudo_rules.py \
  src/yggdrasil_ids/sudo_storage.py \
  src/yggdrasil_ids/sudo_ml.py \
  deploy/sprint5_sudo_ml_lab.py \
  deploy/sprint5_sudo_ml_v2_lab.py \
  deploy/sprint5_sudo_mixed_ml_lab.py \
  deploy/sprint5_sudo_score_diagnostics.py | tar -xf - -C "$source_dir"

private=/home/vidar/yggdrasil-sudo-ml-private
target="$private/sudo-score-diagnostics-$(date -u +%Y%m%dT%H%M%S)-$$"
PYTHONPATH="$source_dir/src" PYTHONDONTWRITEBYTECODE=1 \
  OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 \
  /opt/yggdrasil-ids/venv/bin/python \
  "$source_dir/deploy/sprint5_sudo_score_diagnostics.py" \
  --dataset "$dataset" --report "$report" --directory "$target"
