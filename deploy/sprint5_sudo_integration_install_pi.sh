#!/usr/bin/env bash
# Coordinated schema5 deployment. Optional second argument: rollback.
set -Eeuo pipefail
umask 077
sha="${1:-}"
action="${2:-install}"
branch=experiment/sudo-if-v2
if [[ ! "$sha" =~ ^[0-9a-f]{40}$ || "$(hostname)" != yggdrasil || "$(id -un)" != vidar ]]; then
  echo "STOP: Run as vidar on Yggdrasil with the reviewed full commit SHA" >&2
  exit 2
fi
[[ "$action" == install || "$action" == rollback ]] ||
  { echo "STOP: Expected install or rollback" >&2; exit 2; }
cd /home/vidar/AI-Intrusion-Detection-System
git fetch --no-tags origin "refs/heads/$branch:refs/remotes/origin/$branch"
if [[ "$action" == install && "$(git rev-parse "origin/$branch")" != "$sha" ]]; then
  echo "STOP: Branch changed; review the new commit" >&2
  exit 2
fi
git cat-file -e "$sha^{commit}"
source_dir="$(mktemp -d -t sudo-integration-install-XXXXXX)"
trap 'rm -rf -- "$source_dir"' EXIT
git archive "$sha" src/yggdrasil_ids \
  deploy/sudo_integration_deploy.py \
  deploy/sprint5_sudo_integration_poll.py \
  deploy/yggdrasil-sudo-integration.service \
  deploy/yggdrasil-sudo-integration.timer | tar -xf - -C "$source_dir"
sudo /usr/bin/python3 "$source_dir/deploy/sudo_integration_deploy.py" \
  "$action" --sha "$sha" --source "$source_dir"
