#!/usr/bin/env bash
# One-time tuning of live Sprint 3's scan threshold, from 6 to 5.
# No package install, UFW changes, network connection, or history rewrite.
set -Eeuo pipefail
umask 077
phase="preflight"
backup=""
repository="/home/vidar/AI-Intrusion-Detection-System"
config="/etc/yggdrasil-ids/config.toml"
venv="/opt/yggdrasil-ids/venv"
db="/var/lib/yggdrasil-ids/events.sqlite3"
source_sha="07fab99c88fe51a2cc455f51788bb17fd6c37fa4"

on_exit() {
  status=$?
  if (( status != 0 )); then
    echo "STOP: threshold tuning afbrudt i fase $phase ($status)." >&2
    [[ -z "$backup" ]] || echo "Bevar privat backup: $backup" >&2
    echo "Genkør ikke automatisk. Undersøg aktuel konfiguration og service-status." >&2
  fi
}
trap on_exit EXIT
fail() { echo "STOP: $*" >&2; exit 1; }

[[ $# -eq 1 && "$1" =~ ^[0-9a-f]{40}$ ]] || fail "Angiv den fulde, beståede Git-commit."
[[ "$(id -u)" -ne 0 ]] || fail "Kør som vidar, ikke root."
script_sha="$1"
cd "$repository"
[[ -z "$(git status --porcelain)" ]] || fail "Lokale Git-ændringer skal gennemgås."
git fetch --no-tags origin sprint-3/network-monitoring
[[ "$(git rev-parse origin/sprint-3/network-monitoring)" == "$script_sha" ]] \
  || fail "Branchen matcher ikke den valgte script-SHA."
git cat-file -e "$source_sha^{commit}"
git diff --quiet "$source_sha" "$script_sha" -- \
  src pyproject.toml requirements.lock requirements-dev.txt \
  || fail "Den installerede applikationskode er ændret i Git."

for service in yggdrasil-collector.service yggdrasil-web.service yggdrasil-notifier.service; do
  systemctl is-active --quiet "$service" || fail "$service er ikke aktiv."
done
sudo -v
sudo ufw status verbose | grep -F "Logging: on (low)" >/dev/null \
  || fail "UFW low er ikke verificeret."
sudo -u yggdrasil-worker "$venv/bin/yggdrasil-ids" doctor \
  --config "$config" --role collector --journal >/dev/null \
  || fail "Collector/journal preflight fejlede."
sudo -u yggdrasil-web "$venv/bin/yggdrasil-ids" doctor \
  --config "$config" --role web >/dev/null \
  || fail "Dashboard preflight fejlede."

sudo "$venv/bin/python" - "$config" "$db" <<'PY'
import sqlite3
import sys
from pathlib import Path
from yggdrasil_ids.config import load_config

p, db_path = map(Path, sys.argv[1:])
assert not p.is_symlink(), "Konfiguration er symlink"
cfg = load_config(p)
assert cfg.mode == "live"
assert cfg.network.enabled is True
assert cfg.network.window_seconds == 60
assert cfg.network.distinct_ports_threshold == 6
assert cfg.web.bind in ("127.0.0.1", "::1")
with sqlite3.connect(db_path.resolve().as_uri() + "?mode=ro", uri=True) as db:
    assert db.execute("PRAGMA user_version").fetchone()[0] == 4
    assert db.execute("PRAGMA quick_check").fetchone()[0] == "ok"
    assert db.execute(
        "SELECT value FROM state WHERE key='firewall_started_at'"
    ).fetchone() is not None
print("PASS: Live schema v4 og eksisterende 6-port-konfiguration er verificeret")
PY

phase="backup-config"
backup="$(sudo mktemp -d -p /var/backups/yggdrasil-ids sprint3-threshold5-XXXXXXXX)"
sudo install -o root -g root -m 0600 "$config" "$backup/config-before-threshold5.toml"
sudo test -s "$backup/config-before-threshold5.toml" || fail "Konfigurationsbackup er tom."

phase="editing-config"
sudo "$venv/bin/python" - "$config" <<'PY'
import os
import re
import stat
import sys
import tempfile
import tomllib
from pathlib import Path

p = Path(sys.argv[1])
assert p.is_file() and not p.is_symlink()
original = p.read_bytes()
text = original.decode("utf-8")
cfg = tomllib.loads(text)
assert cfg["network"]["enabled"] is True
assert cfg["network"]["window_seconds"] == 60
assert cfg["network"]["distinct_ports_threshold"] == 6
# Verify exactly one key inside [network], never edit an unrelated section.
lines = text.splitlines(keepends=True)
section = None
changes = 0
for i, line in enumerate(lines):
    clean = line.strip()
    if clean.startswith("[") and clean.endswith("]"):
        section = clean[1:-1]
    if section == "network" and re.fullmatch(
        r"\s*distinct_ports_threshold\s*=\s*6\s*", line
    ):
        ending = "\n" if line.endswith("\n") else ""
        lines[i] = "distinct_ports_threshold = 5" + ending
        changes += 1
assert changes == 1, "Forventede præcis ét match i [network]"
modified = "".join(lines).encode("utf-8")
updated = tomllib.loads(modified.decode("utf-8"))
assert updated["network"]["distinct_ports_threshold"] == 5
updated_copy = {**updated, "network": {**updated["network"], "distinct_ports_threshold": 6}}
assert updated_copy == cfg, "Andre indstillinger blev ændret"
st = p.stat()
assert stat.S_ISREG(st.st_mode)
fd, tmp = tempfile.mkstemp(prefix=".ids-threshold-", dir=p.parent)
try:
    os.fchmod(fd, stat.S_IMODE(st.st_mode))
    os.fchown(fd, st.st_uid, st.st_gid)
    with os.fdopen(fd, "wb") as out:
        out.write(modified)
        out.flush()
        os.fsync(out.fileno())
    os.replace(tmp, p)
finally:
    if os.path.exists(tmp):
        os.unlink(tmp)
print("PASS: Kun distinct_ports_threshold ændret fra 6 til 5")
PY

sudo -u yggdrasil-worker "$venv/bin/yggdrasil-ids" doctor \
  --config "$config" --role collector --journal >/dev/null \
  || fail "Worker kan ikke læse konfigurationen."
sudo -u yggdrasil-web "$venv/bin/yggdrasil-ids" doctor \
  --config "$config" --role web >/dev/null \
  || fail "Web kan ikke læse konfigurationen."

phase="restarting-collector"
sudo systemctl restart yggdrasil-collector.service
sleep 6
systemctl is-active --quiet yggdrasil-collector.service \
  || fail "Collector kører ikke efter restart."
sudo -u yggdrasil-worker "$venv/bin/yggdrasil-ids" doctor \
  --config "$config" --role collector --journal >/dev/null \
  || fail "Collector doctor fejlede efter restart."

phase="restarting-web"
sudo systemctl restart yggdrasil-web.service
sleep 3
systemctl is-active --quiet yggdrasil-web.service || fail "Dashboard kører ikke."
sudo -u yggdrasil-web "$venv/bin/yggdrasil-ids" doctor \
  --config "$config" --role web >/dev/null || fail "Web doctor fejlede."
systemctl is-active --quiet yggdrasil-notifier.service \
  || fail "Discord-notifier er ikke aktiv."
sudo ufw status verbose | grep -F "Logging: on (low)" >/dev/null \
  || fail "UFW blev uventet ændret."
sudo "$venv/bin/python" - "$config" <<'PY'
import sys
from yggdrasil_ids.config import load_config
cfg = load_config(sys.argv[1])
assert cfg.network.enabled and cfg.network.window_seconds == 60
assert cfg.network.distinct_ports_threshold == 5
print("PASS: Ny eksperimentel tærskel = 5 porte på 60 sekunder")
PY

phase="complete"
echo "PASS: Alle tre IDS-tjenester aktive; UFW low og netværksindsamling bevaret."
echo "Privat backup af tidligere konfiguration: $backup"
echo "OBS: Tidligere firewallhændelser bliver ikke retroaktivt til nye alarmer."
