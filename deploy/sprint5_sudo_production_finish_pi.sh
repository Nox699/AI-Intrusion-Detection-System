#!/usr/bin/env bash
# Finish the existing verified installation; only the integration unit changes.
set -Eeuo pipefail
umask 077
sha="${1:-}"
action="${2:-finish}"
branch=experiment/sudo-if-v2
if [[ ! "$sha" =~ ^[0-9a-f]{40}$ || "$(hostname)" != yggdrasil || "$(id -un)" != vidar ]]; then
  echo "STOP: Run as vidar on Yggdrasil with the reviewed full SHA" >&2
  exit 2
fi
[[ "$action" == finish || "$action" == check ]] ||
  { echo "STOP: Expected finish or check" >&2; exit 2; }
cd /home/vidar/AI-Intrusion-Detection-System
git fetch --no-tags origin "refs/heads/$branch:refs/remotes/origin/$branch"
[[ "$(git rev-parse "origin/$branch")" == "$sha" ]] ||
  { echo "STOP: Branch changed; review the new commit" >&2; exit 2; }
source_dir="$(mktemp -d -t sudo-production-finish-XXXXXX)"
trap 'rm -rf -- "$source_dir"' EXIT
git archive "$sha" deploy/sudo_production_finish.py deploy/sudo_integration_deploy.py \
  deploy/yggdrasil-sudo-integration.service | tar -xf - -C "$source_dir"
arguments=(--source "$source_dir" --sha "$sha")
[[ "$action" == check ]] && arguments+=(--check-only)
sudo /usr/bin/env PYTHONDONTWRITEBYTECODE=1 \
  /usr/bin/python3 "$source_dir/deploy/sudo_production_finish.py" "${arguments[@]}"
