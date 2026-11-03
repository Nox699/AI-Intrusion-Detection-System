#!/usr/bin/env bash
# Read installed runtime metadata only; no installation, migration or activation.
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
if [[ "$(git rev-parse "origin/$branch")" != "$sha" ]]; then
  echo "STOP: Branch changed; review the new commit" >&2
  exit 2
fi
source_dir="$(mktemp -d -t sudo-integration-preflight-XXXXXX)"
trap 'rm -rf -- "$source_dir"' EXIT
git archive "$sha" deploy/sudo_integration_preflight.py | tar -xf - -C "$source_dir"
sudo /usr/bin/python3 "$source_dir/deploy/sudo_integration_preflight.py"
