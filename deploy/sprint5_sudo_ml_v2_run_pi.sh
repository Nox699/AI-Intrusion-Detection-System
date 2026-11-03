#!/usr/bin/env bash
# Run only the isolated synthetic research branch; never install a live model.
set -Eeuo pipefail
umask 077

sha="${1:-}"
branch=experiment/sudo-if-v2
if [[ ! "$sha" =~ ^[0-9a-f]{40}$ || "$(hostname)" != yggdrasil || "$(id -un)" != vidar ]]; then
  echo "STOP: Run as vidar on Yggdrasil with the full reviewed commit SHA" >&2
  exit 2
fi
cd /home/vidar/AI-Intrusion-Detection-System
git fetch --no-tags origin "refs/heads/$branch:refs/remotes/origin/$branch"
if [[ "$(git rev-parse "origin/$branch")" != "$sha" ]]; then
  echo "STOP: Research branch changed; inspect the new commit first" >&2
  exit 2
fi
python=/opt/yggdrasil-ids/venv/bin/python
test -x "$python"
source_dir="$(mktemp -d -t sudo-if-v2-source-XXXXXX)"
trap 'rm -rf -- "$source_dir"' EXIT
git archive "$sha" \
  src/yggdrasil_ids/__init__.py \
  src/yggdrasil_ids/sudo_rules.py \
  src/yggdrasil_ids/sudo_storage.py \
  src/yggdrasil_ids/sudo_ml.py \
  deploy/sprint5_sudo_ml_lab.py \
  deploy/sprint5_sudo_ml_v2_lab.py | tar -xf - -C "$source_dir"

private="/home/vidar/yggdrasil-sudo-ml-private"
mkdir -p -m 0700 -- "$private"
chmod 0700 -- "$private"
target="$private/sudo-if-v2-$(date -u +%Y%m%dT%H%M%S)-$$"
PYTHONPATH="$source_dir/src" PYTHONDONTWRITEBYTECODE=1 \
  OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 \
  "$python" "$source_dir/deploy/sprint5_sudo_ml_v2_lab.py" --directory "$target"
