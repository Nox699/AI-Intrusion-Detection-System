#!/usr/bin/env bash
# Safe pre-install staging only. Does not install software or stop IDS services.
set -Eeuo pipefail
umask 077

stop() {
  printf 'STOP: %s\n' "$*" >&2
  exit 1
}

if [[ $# -ne 1 || ! "$1" =~ ^[0-9a-f]{40}$ ]]; then
  stop "Brug: bash deploy/sprint3_prepare.sh <40-tegns-godkendt-commit>"
fi
if [[ "$(id -u)" -eq 0 ]]; then
  stop "Kør scriptet som vidar, ikke som root."
fi

expected_sha="$1"
repository="/home/vidar/AI-Intrusion-Detection-System"
release_dir="/var/backups/yggdrasil-ids/sprint3-prepared-$expected_sha"
venv="/opt/yggdrasil-ids/venv"

cd "$repository"
if [[ -n "$(git status --porcelain)" ]]; then
  git status --short
  stop "Uafklarede lokale ændringer i Git-projektet."
fi

git fetch --no-tags origin sprint-3/network-monitoring
actual_sha="$(git rev-parse --verify refs/remotes/origin/sprint-3/network-monitoring)"
if [[ "$actual_sha" != "$expected_sha" ]]; then
  stop "Fjernbranchen matcher ikke den forventede, godkendte commit."
fi
git cat-file -e "$expected_sha^{commit}"

for service in yggdrasil-collector.service yggdrasil-web.service yggdrasil-notifier.service; do
  systemctl is-active --quiet "$service" || stop "Tjenesten $service er ikke aktiv."
done

sudo -v
sudo "$venv/bin/python" - <<'PY'
import sqlite3
import tomllib
from pathlib import Path

with Path("/etc/yggdrasil-ids/config.toml").open("rb") as handle:
    cfg = tomllib.load(handle)
if cfg.get("app", {}).get("mode") != "live":
    raise SystemExit("STOP: app.mode er ikke live")
if cfg.get("network", {}).get("enabled", False) is not False:
    raise SystemExit("STOP: Netværksindsamling skal være deaktiveret")
if cfg.get("web", {}).get("bind", "127.0.0.1") not in {"127.0.0.1", "::1"}:
    raise SystemExit("STOP: Dashboardet må kun binde på loopback")
with sqlite3.connect(
    "file:/var/lib/yggdrasil-ids/events.sqlite3?mode=ro", uri=True
) as db:
    schema = db.execute("PRAGMA user_version").fetchone()[0]
    check = db.execute("PRAGMA quick_check").fetchone()[0]
if schema != 3 or check != "ok":
    raise SystemExit(f"STOP: Forventede schema 3 / integritet ok, fik {schema} / {check}")
print("PASS: live konfiguration, netværk slået fra og SQLite v3 i orden")
PY

if sudo test -e "$release_dir"; then
  stop "Release-mappen eksisterer allerede; overskriv ikke eksisterende backups."
fi

work="$(mktemp -d)"
trap 'rm -rf -- "$work"' EXIT
mkdir -m 700 "$work/source" "$work/dist"
git archive "$expected_sha" | tar -xf - -C "$work/source"

# Only the temporary build environment gets new build tools. The running venv
# and its locked runtime dependencies are not modified in this preparation.
python3 -m venv "$work/buildenv"
"$work/buildenv/bin/python" -m pip wheel --disable-pip-version-check \
  --no-deps --wheel-dir "$work/dist" "$work/source"

shopt -s nullglob
wheels=("$work"/dist/yggdrasil_ids-*.whl)
if [[ ${#wheels[@]} -ne 1 ]]; then
  stop "Forventede præcis én ny Yggdrasil-wheel."
fi
wheel="${wheels[0]}"
wheel_name="$(basename "$wheel")"

python3 - "$wheel" <<'PY'
import sys
from zipfile import ZipFile
with ZipFile(sys.argv[1]) as archive:
    assert archive.testzip() is None, "Wheel indeholder fejl"
    expected = {
        "yggdrasil_ids/engine.py",
        "yggdrasil_ids/network_rules.py",
        "yggdrasil_ids/templates/network.html",
    }
    missing = expected.difference(archive.namelist())
    assert not missing, f"Wheel mangler filer: {missing}"
print("PASS: Wheel-integritet og nødvendige filer verificeret")
PY

sudo install -d -o root -g root -m 0700 "$release_dir"
sudo install -o root -g root -m 0600 "$wheel" "$release_dir/$wheel_name"
printf '%s\n' "$expected_sha" | sudo tee "$release_dir/source-sha.txt" >/dev/null
sudo chmod 0600 "$release_dir/source-sha.txt"

# Preserve exactly the installed program and its dependencies. Do not assume
# the local Git checkout or the package version identifies installed code.
sudo tar -C /opt/yggdrasil-ids -czf "$release_dir/previous-venv.tar.gz" venv
sudo chmod 0600 "$release_dir/previous-venv.tar.gz"
sudo tar -tzf "$release_dir/previous-venv.tar.gz" |
  grep -Fx 'venv/bin/yggdrasil-ids' >/dev/null ||
  stop "Snapshot af tidligere venv mangler programmet."

for service in yggdrasil-collector.service yggdrasil-web.service yggdrasil-notifier.service; do
  systemctl is-active --quiet "$service" || stop "Tjenesten $service stoppede under forberedelsen."
done
printf '\nPASS: Forberedelse færdig; intet er installeret eller genstartet.\n'
printf 'Source SHA: %s\n' "$expected_sha"
printf 'Release-artifakter (root-beskyttet): %s\n' "$release_dir"
sudo sha256sum "$release_dir/$wheel_name" "$release_dir/previous-venv.tar.gz"
sudo du -sh "$release_dir"
