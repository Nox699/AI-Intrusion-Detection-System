#!/usr/bin/env bash
# First installation only. The model argument is an explicitly reviewed SSH artifact.
set -Eeuo pipefail
umask 077
sha="${1:-}"
model="${2:-}"
branch=main
if [[ ! "$sha" =~ ^[0-9a-f]{40}$ || "$model" != /* || "$(hostname)" != yggdrasil || "$(id -un)" != vidar ]]; then
  echo "STOP: Run as vidar on Yggdrasil with SHA and an absolute reviewed SSH model path" >&2
  exit 2
fi
cd /home/vidar/AI-Intrusion-Detection-System
git fetch --no-tags origin "refs/heads/$branch:refs/remotes/origin/$branch"
[[ "$(git rev-parse "origin/$branch")" == "$sha" ]] ||
  { echo "STOP: Production branch changed; review the new commit" >&2; exit 2; }
source_dir="$(mktemp -d -t yggdrasil-install-XXXXXX)"
trap 'rm -rf -- "$source_dir"' EXIT
git archive "$sha" src/yggdrasil_ids requirements.lock deploy/production_install.py \
  deploy/production_upgrade.py deploy/config.pi.toml deploy/yggdrasil-collector.service \
  deploy/yggdrasil-web.service deploy/yggdrasil-notifier.service deploy/yggdrasil-sudo.service \
  deploy/yggdrasil-sudo.timer | tar -xf - -C "$source_dir"
sudo /usr/bin/env PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 \
  "$source_dir/deploy/production_install.py" --sha "$sha" --source "$source_dir" --reviewed-model "$model"
