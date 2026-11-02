#!/usr/bin/env bash
# Safe staging only: build Sprint 3 chart wheel and snapshot current venv.
set -Eeuo pipefail
umask 077
repository="/home/vidar/AI-Intrusion-Detection-System"
venv="/opt/yggdrasil-ids/venv"
config="/etc/yggdrasil-ids/config.toml"
stage=""
work=""
phase="preflight"
stop() { printf 'STOP (%s): %s\n' "$phase" "$*" >&2; exit 1; }
on_exit() {
  code=$?
  [[ -z "$work" ]] || rm -rf -- "$work"
  if ((code)); then
    echo "Afbrudt ($phase); ingen IDS-tjenester blev med vilje stoppet." >&2
    [[ -z "$stage" ]] || echo "Undersøg eventuelt ufuldstændig backup: $stage" >&2
  fi
}
trap on_exit EXIT
[[ $# == 1 && "$1" =~ ^[0-9a-f]{40}$ ]] || stop "Angiv fuld Git SHA."
[[ "$(id -u)" != 0 ]] || stop "Kør som vidar, ikke root."
sha="$1"
cd "$repository"
[[ -z "$(git status --porcelain)" ]] || stop "Uafklarede lokale Git-ændringer."
git fetch --no-tags origin sprint-3/network-monitoring
[[ "$(git rev-parse origin/sprint-3/network-monitoring)" == "$sha" ]] \
  || stop "Branchen matcher ikke den forventede commit."
git cat-file -e "$sha^{commit}"
for service in yggdrasil-collector.service yggdrasil-web.service yggdrasil-notifier.service; do
  systemctl is-active --quiet "$service" || stop "$service er ikke aktiv."
done
sudo -v
sudo ufw status verbose | grep -F "Logging: on (low)" >/dev/null \
  || stop "UFW logging er ikke low."
sudo "$venv/bin/python" - <<'PY'
from pathlib import Path
from yggdrasil_ids.config import load_config
from yggdrasil_ids.storage import SCHEMA_VERSION
import sqlite3
cfg = load_config(Path("/etc/yggdrasil-ids/config.toml"))
assert cfg.mode == "live" and cfg.network.enabled
assert cfg.network.window_seconds == 60
assert cfg.network.distinct_ports_threshold == 5
assert cfg.web.bind in {"127.0.0.1", "::1"}
assert SCHEMA_VERSION == 4
with sqlite3.connect(cfg.database_path.as_uri() + "?mode=ro", uri=True) as db:
    assert db.execute("PRAGMA user_version").fetchone()[0] == 4
    assert db.execute("PRAGMA quick_check").fetchone()[0] == "ok"
print("PASS: Produktionsprofil og schema v4 verificeret")
PY
sudo -u yggdrasil-worker "$venv/bin/yggdrasil-ids" doctor \
  --config "$config" --role collector --journal >/dev/null || stop "Worker doctor fejlede."
sudo -u yggdrasil-web "$venv/bin/yggdrasil-ids" doctor \
  --config "$config" --role web >/dev/null || stop "Web doctor fejlede."
sudo "$venv/bin/python" -m pip check >/dev/null || stop "Installerede afhængigheder fejlede."

phase="staging"
stage="/var/backups/yggdrasil-ids/sprint3-charts-prepared-$sha"
sudo test ! -e "$stage" || stop "Stagingmappen eksisterer allerede."
work="$(mktemp -d)"
mkdir -m 700 "$work/source" "$work/dist"
git archive "$sha" | tar -xf - -C "$work/source"
python3 -m venv "$work/buildenv"
"$work/buildenv/bin/python" -m pip wheel --disable-pip-version-check \
  --no-deps --wheel-dir "$work/dist" "$work/source"
count="$(find "$work/dist" -maxdepth 1 -name 'yggdrasil_ids-*.whl' -type f | wc -l)"
[[ "$count" == 1 ]] || stop "Forventede præcis én wheel."
wheel="$(find "$work/dist" -maxdepth 1 -name 'yggdrasil_ids-*.whl' -type f -print -quit)"
python3 - "$wheel" <<'PY'
import sys
from zipfile import ZipFile
with ZipFile(sys.argv[1]) as archive:
    assert archive.testzip() is None
    required = {
        "yggdrasil_ids/cli.py",
        "yggdrasil_ids/storage.py",
        "yggdrasil_ids/web.py",
        "yggdrasil_ids/templates/network.html",
        "yggdrasil_ids/static/network.js",
        "yggdrasil_ids/static/app.css",
    }
    assert required.issubset(archive.namelist())
print("PASS: Wheel har både dashboard, API og grafassets")
PY
sudo install -d -o root -g root -m 0700 "$stage"
sudo install -o root -g root -m 0600 "$wheel" "$stage/yggdrasil_ids-0.1.0-py3-none-any.whl"
printf '%s\n' "$sha" | sudo tee "$stage/source-sha.txt" >/dev/null
sudo chmod 0600 "$stage/source-sha.txt"
sudo tar -C /opt/yggdrasil-ids -czf "$stage/previous-venv.tar.gz" venv
sudo chmod 0600 "$stage/previous-venv.tar.gz"
sudo tar -tzf "$stage/previous-venv.tar.gz" | grep -Fx 'venv/bin/yggdrasil-ids' >/dev/null \
  || stop "Backup af installeret venv indeholder ikke CLI."
for service in yggdrasil-collector.service yggdrasil-web.service yggdrasil-notifier.service; do
  systemctl is-active --quiet "$service" || stop "$service stoppede under staging."
done
phase="complete"
echo "PASS: Graf-release klargjort UDEN ændring af aktive IDS-tjenester."
echo "SOURCE_SHA=$sha"
echo "STAGED=$stage"
sudo sha256sum "$stage/yggdrasil_ids-0.1.0-py3-none-any.whl" "$stage/previous-venv.tar.gz"
sudo du -sh "$stage"
