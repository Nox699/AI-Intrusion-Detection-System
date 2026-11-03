#!/usr/bin/env bash
# Private real-data export for research. No model installation or service changes.
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
  echo "STOP: Research branch changed; review the new commit" >&2
  exit 2
fi

private=/home/vidar/yggdrasil-sudo-real-private
mkdir -p -m 0700 -- "$private"
chmod 0700 -- "$private"
source_dir="$(mktemp -d -t sudo-real-source-XXXXXX)"
export_tmp=""
cleanup() {
  rm -rf -- "$source_dir"
  if [[ -n "$export_tmp" ]]; then
    rm -f -- "$export_tmp"
  fi
}
trap cleanup EXIT

git archive "$sha" \
  src/yggdrasil_ids/__init__.py \
  src/yggdrasil_ids/sudo_rules.py \
  deploy/sudo_real_export.py | tar -xf - -C "$source_dir"
# Only public source code is placed here. The worker must traverse this directory.
chmod -R a+rX "$source_dir"

export_tmp="$(mktemp "$private/sudo-export-XXXXXX.json")"
target="$private/sudo-processes-$(date -u +%Y%m%dT%H%M%S)-$$.json"
if [[ -e "$target" || -L "$target" ]]; then
  echo "STOP: Target export already exists" >&2
  exit 2
fi

cd /opt/yggdrasil-ids
sudo /usr/bin/setpriv \
  --reuid=yggdrasil-worker \
  --regid=yggdrasil-data \
  --groups=yggdrasil-data,systemd-journal \
  /usr/bin/env PYTHONPATH="$source_dir/src" PYTHONDONTWRITEBYTECODE=1 \
  /usr/bin/python3 "$source_dir/deploy/sudo_real_export.py" > "$export_tmp"

/usr/bin/python3 - "$export_tmp" <<'PY'
import json
import math
import sys
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

data = json.loads(Path(sys.argv[1]).read_text())
assert data["format"] == "sudo-process-candidates-v1"
assert data["normal_labels_verified"] is False
assert data["process_count"] == len(data["processes"]) > 0
days = defaultdict(Counter)
for row in data["processes"]:
    assert set(row) == {"timestamp", "group", "outcome", "also_had_success", "normal_candidate"}
    assert type(row["timestamp"]) in (int, float) and math.isfinite(row["timestamp"])
    assert type(row["group"]) is int and row["group"] > 0
    assert row["outcome"] in {"success", "failure", "denied"}
    assert type(row["normal_candidate"]) is bool
    day = datetime.fromtimestamp(row["timestamp"], ZoneInfo("Europe/Copenhagen")).date()
    days[str(day)][row["outcome"]] += 1
    days[str(day)]["normal_candidates"] += int(row["normal_candidate"])
print("=== Private sudo process export ===")
print("Recognized process groups:", data["process_count"])
print("Outcomes:", data["outcomes"])
print("Provisional normal candidates:", data["normal_candidates"])
print("Rejected journal rows:", data["rejected_journal_rows"])
print("Ambiguous process groups skipped:", data["ambiguous_process_groups_skipped"])
for day, counts in sorted(days.items()):
    print(day, dict(counts))
print("Normal candidates are NOT verified labels. Error contexts remain excluded.")
PY

# Hard link creates the final filename without overwriting an existing export.
ln -- "$export_tmp" "$target"
echo "Private dataset: $target"
echo "Only code is fetched from GitHub. No dataset is uploaded."
