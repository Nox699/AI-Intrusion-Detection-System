#!/usr/bin/env bash
# Coordinated production release. Optional second argument: rollback.
set -Eeuo pipefail
umask 077
sha="${1:-}"
action="${2:-upgrade}"
branch=main
if [[ ! "$sha" =~ ^[0-9a-f]{40}$ || "$(hostname)" != yggdrasil || "$(id -un)" != vidar ]]; then
  echo "STOP: Run as vidar on Yggdrasil with the reviewed full commit SHA" >&2
  exit 2
fi
[[ "$action" == upgrade || "$action" == rollback ]] ||
  { echo "STOP: Expected upgrade or rollback" >&2; exit 2; }
cd /home/vidar/AI-Intrusion-Detection-System
git fetch --no-tags origin "refs/heads/$branch:refs/remotes/origin/$branch"
if [[ "$action" == upgrade && "$(git rev-parse "origin/$branch")" != "$sha" ]]; then
  echo "STOP: Production branch changed; review the new commit" >&2
  exit 2
fi
git cat-file -e "$sha^{commit}"
source_dir="$(mktemp -d -t yggdrasil-production-XXXXXX)"
trap 'rm -rf -- "$source_dir"' EXIT
git archive "$sha" src/yggdrasil_ids requirements.lock deploy/production_upgrade.py \
  deploy/yggdrasil-collector.service deploy/yggdrasil-web.service \
  deploy/yggdrasil-notifier.service deploy/yggdrasil-sudo.service \
  deploy/yggdrasil-sudo.timer | tar -xf - -C "$source_dir"
sudo /usr/bin/env PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 \
  "$source_dir/deploy/production_upgrade.py" "$action" --sha "$sha" --source "$source_dir"
