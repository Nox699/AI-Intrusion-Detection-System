#!/usr/bin/env bash
# Opt-in UFW journal collection on a verified Sprint 3 schema-v4 installation.
# Does NOT change UFW, SSH, router, Tailscale, or notifier settings.
set -Eeuo pipefail
umask 077

phase="preflight"
backup_dir=""
venv="/opt/yggdrasil-ids/venv"
config="/etc/yggdrasil-ids/config.toml"
db_path="/var/lib/yggdrasil-ids/events.sqlite3"
repository="/home/vidar/AI-Intrusion-Detection-System"
release_sha="07fab99c88fe51a2cc455f51788bb17fd6c37fa4"

on_exit() {
  code=$?
  if (( code != 0 )); then
    printf '\nSTOP: Opt-in afbrudt i fase %s (exit %d).\n' "$phase" "$code" >&2
    if [[ -n "$backup_dir" ]]; then
      printf 'Privat konfigurations- og databasebackup: %s\n' "$backup_dir" >&2
    fi
    printf 'Genkør ikke automatisk. Bevar backups og kontrollér IDS-service-status.\n' >&2
  fi
}
trap on_exit EXIT
stop() { printf 'STOP: %s\n' "$*" >&2; exit 1; }

if [[ $# -ne 1 || ! "$1" =~ ^[0-9a-f]{40}$ ]]; then
  stop "Brug den fulde, grønt CI-testede Git-SHA som eneste argument."
fi
script_sha="$1"
[[ "$(id -u)" -ne 0 ]] || stop "Kør som vidar, ikke root."
cd "$repository"
if [[ -n "$(git status --porcelain)" ]]; then
  git status --short
  stop "Uafklarede lokale Git-ændringer."
fi
git fetch --no-tags origin sprint-3/network-monitoring
remote_sha="$(git rev-parse --verify refs/remotes/origin/sprint-3/network-monitoring)"
[[ "$remote_sha" == "$script_sha" ]] || stop "Remote-SHA ændrede sig. Afbryd og kontrollér igen."
git cat-file -e "$release_sha^{commit}"
git diff --quiet "$release_sha" "$script_sha" -- \
  src pyproject.toml requirements.lock requirements-dev.txt \
  || stop "Kilden har ændret sig siden den installerede wheel."

for service in yggdrasil-collector.service yggdrasil-web.service yggdrasil-notifier.service; do
  systemctl is-active --quiet "$service" || stop "$service er ikke aktiv."
done

sudo -v
# Checking the current logging level does not change UFW.
sudo ufw status verbose | grep -F "Logging: on (low)" >/dev/null \
  || stop "UFW er ikke på det forventede logniveau low."
sudo "$venv/bin/python" -m pip check >/dev/null || stop "Python-afhængigheder er defekte."
sudo -u yggdrasil-worker "$venv/bin/yggdrasil-ids" doctor \
  --config "$config" --role collector --journal >/dev/null \
  || stop "Collector doctor/journaladgang fejlede."
sudo -u yggdrasil-web "$venv/bin/yggdrasil-ids" doctor \
  --config "$config" --role web >/dev/null \
  || stop "Dashboardets doctor fejlede."

sudo "$venv/bin/python" - "$config" "$db_path" <<'PY'
import sqlite3
import sys
import tomllib
from pathlib import Path
from yggdrasil_ids.storage import SCHEMA_VERSION

config_path, db_path = map(Path, sys.argv[1:])
with config_path.open("rb") as source:
    cfg = tomllib.load(source)
assert cfg.get("app", {}).get("mode") == "live"
assert cfg.get("web", {}).get("bind", "127.0.0.1") in {"127.0.0.1", "::1"}
# Opt-in only from the known Pi profile that omitted the network section.
# An existing network section needs an explicit reviewed edit.
assert "network" not in cfg, "Eksisterende [network]-sektion kræver manuel gennemgang"
with sqlite3.connect(f"file:{db_path}?mode=ro", uri=True) as db:
    assert SCHEMA_VERSION == 4
    assert db.execute("PRAGMA user_version").fetchone()[0] == 4
    assert db.execute("PRAGMA quick_check").fetchone()[0] == "ok"
    assert not db.execute("PRAGMA foreign_key_check").fetchone()
    # Repeated activation after another run must not change historic state.
    assert db.execute("SELECT value FROM state WHERE key='firewall_started_at'").fetchone() is None
print("PASS: Privat live schema-v4-installation, endnu ikke aktiveret til UFW")
PY

phase="backup"
backup_dir="$(sudo mktemp -d -p /var/backups/yggdrasil-ids sprint3-network-optin-XXXXXXXX)"
sudo install -o root -g root -m 0600 "$config" "$backup_dir/config-before-optin.toml"
sudo "$venv/bin/yggdrasil-ids" backup --config "$config" \
  --output "$backup_dir/events-before-optin.sqlite3"
sudo "$venv/bin/python" - "$backup_dir/events-before-optin.sqlite3" <<'PY'
import sqlite3
import sys
with sqlite3.connect(sys.argv[1]) as db:
    assert db.execute("PRAGMA user_version").fetchone()[0] == 4
    assert db.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
print("PASS: Frisk, konsistent schema-v4-backup")
PY

phase="enabling-network"
activation_lower="$(date +%s)"
# Preserve the existing file's owner/group/mode and replace it atomically.
# An existing [network] section is rejected rather than rewritten.
sudo "$venv/bin/python" - "$config" <<'PY'
import os
import stat
import sys
import tempfile
import tomllib
from pathlib import Path

path = Path(sys.argv[1])
if path.is_symlink():
    raise SystemExit("STOP: Konfiguration må ikke være et symlink")
before = path.read_bytes()
cfg = tomllib.loads(before.decode("utf-8"))
assert "network" not in cfg
new = before.rstrip(b"\n") + (
    b"\n\n# Sprint 3: explicitly enabled UFW journal collection.\n"
    b"[network]\n"
    b"enabled = true\n"
    b"window_seconds = 60\n"
    b"distinct_ports_threshold = 6\n"
)
tomllib.loads(new.decode("utf-8"))
st = path.stat()
assert stat.S_ISREG(st.st_mode)
fd, temp = tempfile.mkstemp(prefix=".ids-network-", dir=path.parent)
try:
    os.fchmod(fd, stat.S_IMODE(st.st_mode))
    os.fchown(fd, st.st_uid, st.st_gid)
    with os.fdopen(fd, "wb") as stream:
        stream.write(new)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temp, path)
finally:
    if os.path.exists(temp):
        os.unlink(temp)
print("PASS: [network] enabled=true gemt uden ændring af øvrige indstillinger")
PY

sudo -u yggdrasil-worker "$venv/bin/yggdrasil-ids" doctor \
  --config "$config" --role collector --journal >/dev/null \
  || stop "Worker kan ikke indlæse netværkskonfigurationen."
sudo -u yggdrasil-web "$venv/bin/yggdrasil-ids" doctor \
  --config "$config" --role web >/dev/null \
  || stop "Webkonto kan ikke indlæse netværkskonfigurationen."

phase="restarting-collector"
sudo systemctl restart yggdrasil-collector.service
sleep 8
systemctl is-active --quiet yggdrasil-collector.service || stop "Collector starter ikke."
sudo -u yggdrasil-worker "$venv/bin/yggdrasil-ids" doctor \
  --config "$config" --role collector --journal >/dev/null \
  || stop "Collector doctor fejlede efter genstart."

phase="restarting-dashboard"
sudo systemctl restart yggdrasil-web.service
sleep 3
systemctl is-active --quiet yggdrasil-web.service || stop "Webdashboard starter ikke."
python3 - <<'PY'
from urllib.request import ProxyHandler, build_opener
with build_opener(ProxyHandler({})).open(
    "http://127.0.0.1:8765/login", timeout=5
) as response:
    assert response.status == 200
print("PASS: Login på privat dashboard (HTTP 200)")
PY
systemctl is-active --quiet yggdrasil-notifier.service || stop "Notifier er ikke aktiv."

phase="verify"
sudo "$venv/bin/python" - "$config" "$db_path" "$activation_lower" <<'PY'
import json
import sqlite3
import sys
import time
from pathlib import Path
from yggdrasil_ids.config import load_config

cfg = load_config(sys.argv[1])
assert cfg.network.enabled is True
assert cfg.network.window_seconds == 60
assert cfg.network.distinct_ports_threshold == 6
now = time.time()
with sqlite3.connect(f"file:{Path(sys.argv[2])}?mode=ro", uri=True) as db:
    assert db.execute("PRAGMA user_version").fetchone()[0] == 4
    assert db.execute("PRAGMA quick_check").fetchone()[0] == "ok"
    row = db.execute(
        "SELECT value FROM state WHERE key='firewall_started_at'"
    ).fetchone()
    assert row is not None, "Collector har ikke initialiseret firewall-indlæsning"
    started_at = json.loads(row[0])
    assert float(sys.argv[3]) - 5 <= started_at <= now + 5
    firewall_count = db.execute("SELECT COUNT(*) FROM firewall_events").fetchone()[0]
    alert_count = db.execute(
        "SELECT COUNT(*) FROM alerts WHERE detector_id='network.tcp_port_scan'"
    ).fetchone()[0]
print("PASS: Netværksindsamling aktiveret og første aktiveringstid gemt")
print("Registrerede firewallposter indtil nu:", firewall_count)
print("Portscan-alarmer indtil nu:", alert_count)
print("OBS: Ingen eller få firewallposter er ikke bevis for fuld dækning.")
PY
sudo ufw status verbose | grep -F "Logging: on (low)" >/dev/null \
  || stop "UFW-logniveau blev uventet ændret."
phase="complete"
printf '\nPASS: Sprint 3 UFW-opt-in er aktiv med UFW logging low.\n'
printf 'PASS: Collector, privat dashboard og notifier er aktive.\n'
printf 'Private opt-in backups: %s\n' "$backup_dir"
printf 'INGEN portscanning er udført af dette script.\n'
