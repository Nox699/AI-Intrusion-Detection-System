#!/usr/bin/env bash
# Stage only; no production service, package, configuration or model is changed.
set -Eeuo pipefail
umask 077

repo="/home/vidar/AI-Intrusion-Detection-System"
venv="/opt/yggdrasil-ids/venv"
config="/etc/yggdrasil-ids/config.toml"
candidate="/home/vidar/yggdrasil-ml-private/preview-v1/candidate-model.json"
branch="sprint-4/live-ml-shadow"
work=""
phase="preflight"
stop() { echo "STOP ($phase): $*" >&2; exit 1; }
cleanup() {
  code=$?
  [[ -z "$work" ]] || rm -rf -- "$work"
  if ((code)); then
    echo "No production service, model or config was intentionally changed." >&2
  fi
}
trap cleanup EXIT
[[ $# == 1 && "$1" =~ ^[0-9a-f]{40}$ ]] || stop "Provide full CI-approved SHA."
[[ "$(id -u)" -ne 0 ]] || stop "Run as vidar, not root."
sha="$1"
stage="/var/backups/yggdrasil-ids/sprint4-shadow-prepared-$sha"
cd "$repo"
[[ -z "$(git status --porcelain)" ]] || stop "Local Git checkout has uncommitted changes."
git fetch --no-tags origin "$branch"
[[ "$(git rev-parse "origin/$branch")" == "$sha" ]] || stop "Branch moved from approved SHA."
git cat-file -e "$sha^{commit}"
sudo -v
sudo test ! -e "$stage" || stop "Stage directory already exists."
sudo test ! -e /var/lib/yggdrasil-ids/model.json || stop "Production model already present."
test -s "$candidate" || stop "Hybrid candidate file missing."
for service in yggdrasil-collector.service yggdrasil-web.service yggdrasil-notifier.service; do
  systemctl is-active --quiet "$service" || stop "$service not active."
done
sudo ufw status verbose | grep -F "Logging: on (low)" >/dev/null \
  || stop "UFW logging mode differs from accepted setup."
sudo "$venv/bin/python" - "$config" "$candidate" <<'PY'
import sqlite3,sys,tomllib
from pathlib import Path
from yggdrasil_ids.ml import IsolationForestDetector
from yggdrasil_ids.storage import SCHEMA_VERSION
assert SCHEMA_VERSION == 4
raw=tomllib.loads(Path(sys.argv[1]).read_text())
assert raw["app"]["mode"] == "live"
assert raw["network"]["enabled"] is True
assert raw["network"]["distinct_ports_threshold"] == 5
assert raw["web"]["bind"] in ("127.0.0.1", "::1")
assert raw["ml"].get("alert_mode","alert") == "alert"
assert not Path(raw["paths"]["model"]).exists()
with sqlite3.connect(Path(raw["paths"]["database"]).as_uri()+"?mode=ro",uri=True) as db:
    db.execute("PRAGMA query_only=ON")
    assert db.execute("PRAGMA user_version").fetchone()[0] == 4
    assert db.execute("PRAGMA quick_check").fetchone()[0] == "ok"
model=IsolationForestDetector.load(sys.argv[2])
assert model.metadata["version"] == "ssh-if-7cc1f15288d0c73b"
assert model.metadata["sample_count"] == 324
assert model.metadata["window_seconds"] == raw["ml"]["window_seconds"]
assert "EXPERIMENTAL hybrid bootstrap" in model.metadata["provenance"]
print("PASS: Live DB schema, network settings and hybrid model verified.")
PY
sudo -u yggdrasil-worker "$venv/bin/yggdrasil-ids" doctor \
  --config "$config" --role collector --journal >/dev/null || stop "Collector doctor failed."
sudo -u yggdrasil-web "$venv/bin/yggdrasil-ids" doctor \
  --config "$config" --role web >/dev/null || stop "Web doctor failed."
sudo "$venv/bin/python" -m pip check >/dev/null || stop "Installed dependencies fail."

installed="0cdcf4c3b6c62718f1ef4d5c5d35ee96362bd581"
git cat-file -e "$installed^{commit}" || stop "Installed source SHA unavailable."
while IFS= read -r changed; do
  [[ -z "$changed" ]] && continue
  case "$changed" in
    src/yggdrasil_ids/config.py|src/yggdrasil_ids/engine.py|src/yggdrasil_ids/templates/model.html) ;;
    *) stop "Unexpected application/dependency delta: $changed" ;;
  esac
done < <(git diff --name-only "$installed" "$sha" -- src pyproject.toml requirements.lock requirements-dev.txt)
echo "PASS: Only reviewed shadow-model application code differs from installed release."

free_mb="$(df -Pm /var/backups/yggdrasil-ids | awk 'NR==2{print $4}')"
[[ "$free_mb" =~ ^[0-9]+$ && "$free_mb" -ge 512 ]] || stop "Less than 512 MB free."
phase="build"
work="$(mktemp -d)"
mkdir -m 700 "$work/source" "$work/dist"
git archive "$sha" | tar -xf - -C "$work/source"
python3 -m venv "$work/buildenv"
"$work/buildenv/bin/python" -m pip wheel --disable-pip-version-check \
  --no-deps --wheel-dir "$work/dist" "$work/source"
count="$(find "$work/dist" -maxdepth 1 -name 'yggdrasil_ids-*.whl' -type f | wc -l)"
[[ "$count" == 1 ]] || stop "Expected exactly one wheel."
wheel="$(find "$work/dist" -maxdepth 1 -name 'yggdrasil_ids-*.whl' -type f -print -quit)"
python3 - "$wheel" <<'PY'
import sys
from zipfile import ZipFile
with ZipFile(sys.argv[1]) as wheel:
    assert wheel.testzip() is None
    required={"yggdrasil_ids/config.py","yggdrasil_ids/engine.py",
              "yggdrasil_ids/ml.py","yggdrasil_ids/templates/model.html"}
    assert required.issubset(wheel.namelist())
print("PASS: Shadow-code release wheel passes integrity/content check.")
PY
phase="backup"
sudo install -d -o root -g root -m 0700 "$stage"
sudo install -o root -g root -m 0600 "$wheel" \
  "$stage/yggdrasil_ids-0.1.0-py3-none-any.whl"
sudo install -o root -g root -m 0600 "$candidate" \
  "$stage/private-candidate-model.json"
printf '%s\n' "$sha" | sudo tee "$stage/source-sha.txt" >/dev/null
sudo chmod 0600 "$stage/source-sha.txt"
sudo tar -C /opt/yggdrasil-ids -czf "$stage/previous-venv.tar.gz" venv
sudo chmod 0600 "$stage/previous-venv.tar.gz"
sudo tar -tzf "$stage/previous-venv.tar.gz" |
  grep -Fx 'venv/bin/yggdrasil-ids' >/dev/null || stop "Venv snapshot is incomplete."
sudo sha256sum "$stage/yggdrasil_ids-0.1.0-py3-none-any.whl" \
  "$stage/private-candidate-model.json" "$stage/previous-venv.tar.gz" |
  sudo tee "$stage/sha256sums.txt" >/dev/null
sudo chmod 0600 "$stage/sha256sums.txt"
sudo sha256sum --check --status "$stage/sha256sums.txt" \
  || stop "Staged files failed SHA-256 validation."
for service in yggdrasil-collector.service yggdrasil-web.service yggdrasil-notifier.service; do
  systemctl is-active --quiet "$service" || stop "$service stopped during staging."
done
phase="complete"
echo "PASS: Shadow release staged without modifying production."
echo "STAGED=$stage"
echo "SOURCE_SHA=$sha"
sudo sha256sum "$stage/yggdrasil_ids-0.1.0-py3-none-any.whl" \
  "$stage/private-candidate-model.json" "$stage/previous-venv.tar.gz"
sudo du -sh "$stage"
