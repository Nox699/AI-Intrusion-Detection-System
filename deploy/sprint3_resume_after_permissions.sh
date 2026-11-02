#!/usr/bin/env bash
# One-time recovery of the interrupted Sprint 3 deployment on Yggdrasil.
# PRECONDITION: installed package import permissions have been repaired as
# confirmed by the three non-root account tests. No wheel reinstall is made.
set -Eeuo pipefail
umask 077

phase="preflight"
backup_dir="/var/backups/yggdrasil-ids/sprint3-offline-Ga0vDrfK"
backup="$backup_dir/pre-sprint3-v3.sqlite3"
venv="/opt/yggdrasil-ids/venv"
config="/etc/yggdrasil-ids/config.toml"
notifier_state="/var/lib/yggdrasil-notifier/delivery.sqlite3"
repository="/home/vidar/AI-Intrusion-Detection-System"
expected_code_sha="07fab99c88fe51a2cc455f51788bb17fd6c37fa4"

on_exit() {
  code=$?
  if (( code != 0 )); then
    printf '\nSTOP: Genoptagelse afbrudt i fase %s (exit %d).\n' "$phase" "$code" >&2
    printf 'Genkør IKKE dette script; behold alle backupfiler uændrede.\n' >&2
    printf 'Send fejlen og tjenestestatus til gennemgang.\n' >&2
  fi
}
trap on_exit EXIT
stop() { printf 'STOP: %s\n' "$*" >&2; exit 1; }

if [[ $# -ne 1 || ! "$1" =~ ^[0-9a-f]{40}$ ]]; then
  stop "Angiv kun den fulde SHA på det grønne recovery-script."
fi
script_sha="$1"
[[ "$(id -u)" -ne 0 ]] || stop "Kør som vidar, ikke som root."
cd "$repository"
[[ -z "$(git status --porcelain)" ]] || stop "Lokale Git-ændringer skal undersøges."
git fetch --no-tags origin sprint-3/network-monitoring
remote_sha="$(git rev-parse --verify refs/remotes/origin/sprint-3/network-monitoring)"
[[ "$remote_sha" == "$script_sha" ]] || stop "Branchen har ændret sig fra den godkendte script-commit."
git cat-file -e "$expected_code_sha^{commit}"
git diff --quiet "$expected_code_sha" "$script_sha" -- \
  src pyproject.toml requirements.lock requirements-dev.txt \
  || stop "Programkoden er ændret siden den installerede wheel."
sudo -v

# All three services must still be stopped; starting old code against a
# partially migrated database can be dangerous.
for service in yggdrasil-collector.service yggdrasil-web.service yggdrasil-notifier.service; do
  if systemctl is-active --quiet "$service"; then
    stop "$service kører allerede. Ændr ikke en live installation."
  fi
done
sudo test -f "$backup" || stop "Den friskoprettede v3-backup fra fejlkørslen mangler."
sudo test -f "$notifier_state" || stop "Discord-notifierens leveringsstate mangler."
for name in ids-data-v3.tar.gz notifier-state.tar.gz config-and-secrets.tar.gz systemd-units.tar.gz; do
  sudo test -f "$backup_dir/$name" || stop "Backup-artefakt mangler: $name"
done
sudo "$venv/bin/python" -m pip check >/dev/null || stop "Installerede Python-afhængigheder er defekte."

for user in yggdrasil-worker yggdrasil-web yggdrasil-notifier; do
  sudo -u "$user" "$venv/bin/yggdrasil-ids" --version >/dev/null \
    || stop "CLI kan ikke startes af $user."
  sudo -u "$user" "$venv/bin/python" - <<'PY'
from yggdrasil_ids.cli import main
from yggdrasil_ids.storage import SCHEMA_VERSION
assert SCHEMA_VERSION == 4 and callable(main)
PY
  printf 'PASS: Pakken kan indlæses som %s\n' "$user"
done

sudo "$venv/bin/python" - "$backup" <<'PY'
import sqlite3
import sys
import tomllib
from pathlib import Path

with Path("/etc/yggdrasil-ids/config.toml").open("rb") as fh:
    cfg = tomllib.load(fh)
assert cfg.get("app", {}).get("mode") == "live"
assert cfg.get("network", {}).get("enabled", False) is False
assert cfg.get("web", {}).get("bind", "127.0.0.1") in {"127.0.0.1", "::1"}
paths = [Path(sys.argv[1]), Path("/var/lib/yggdrasil-ids/events.sqlite3")]
for path in paths:
    assert path.is_file(), "Databasen mangler"
    with sqlite3.connect(f"file:{path}?mode=ro", uri=True) as db:
        assert db.execute("PRAGMA user_version").fetchone()[0] == 3
        assert db.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        assert not db.execute("PRAGMA foreign_key_check").fetchone()
with sqlite3.connect(f"file:{paths[0]}?mode=ro", uri=True) as before, sqlite3.connect(
    f"file:{paths[1]}?mode=ro", uri=True
) as current:
    # No other process should have written events after the offline backup.
    for table in ("records", "events", "observations", "alerts", "findings",
                  "preauth_disconnects", "preauth_evidence", "discord_outbox",
                  "discord_outbox_meta"):
        old_rows = before.execute(f"SELECT * FROM {table} ORDER BY rowid").fetchall()
        current_rows = current.execute(f"SELECT * FROM {table} ORDER BY rowid").fetchall()
        assert old_rows == current_rows, f"Driftsdatabasen er ændret: {table}"
    assert before.execute("SELECT value FROM state WHERE key='cursor'").fetchone() == \
        current.execute("SELECT value FROM state WHERE key='cursor'").fetchone()
print("PASS: Frisk backup og uændret driftsdatabase v3; konfiguration er sikker")
PY

# This status opens the existing notifier state for read-only queries.
# It must agree with source outbox before we can start the notifier again.
status="$(sudo "$venv/bin/yggdrasil-ids" notify --config "$config" \
  --state-file "$notifier_state" --status)" || stop "Discord-state matcher ikke kilde-outbox."
printf '%s' "$status" | python3 -c \
  'import json,sys; s=json.load(sys.stdin); assert s["pending"]>=0 and s["last_seq"]>=0; print("PASS: Notifier checkpoint og outbox stemmer overens")'

phase="migrating-db"
sudo -u yggdrasil-worker "$venv/bin/yggdrasil-ids" init --config "$config" \
  || stop "Migrationen fejlede. Undlad at starte services eller gendanne automatisk."

phase="verifying-migration"
sudo "$venv/bin/python" - "$backup" <<'PY'
import sqlite3
import sys

with sqlite3.connect(sys.argv[1]) as before, sqlite3.connect(
    "/var/lib/yggdrasil-ids/events.sqlite3"
) as after:
    assert before.execute("PRAGMA user_version").fetchone()[0] == 3
    assert after.execute("PRAGMA user_version").fetchone()[0] == 4
    assert after.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    assert not after.execute("PRAGMA foreign_key_check").fetchone()
    # The migration may update collector/settings state, but existing SSH
    # evidence, alert identities and outbox must not change.
    for table in ("records", "events", "observations", "alerts", "findings",
                  "preauth_disconnects", "preauth_evidence", "discord_outbox",
                  "discord_outbox_meta"):
        old = before.execute(f"SELECT * FROM {table} ORDER BY rowid").fetchall()
        new = after.execute(f"SELECT * FROM {table} ORDER BY rowid").fetchall()
        assert old == new, f"Ændrede eksisterende data: {table}"
    assert before.execute("SELECT value FROM state WHERE key='cursor'").fetchone() == \
        after.execute("SELECT value FROM state WHERE key='cursor'").fetchone()
    assert after.execute("SELECT COUNT(*) FROM firewall_events").fetchone()[0] == 0
    assert after.execute("SELECT COUNT(*) FROM network_evidence").fetchone()[0] == 0
print("PASS: Schema v4, SQLite-integritet og al SSH/Discord-historik bevaret")
PY

phase="starting-collector"
sudo systemctl reset-failed yggdrasil-collector.service
sudo systemctl start yggdrasil-collector.service
sleep 5
systemctl is-active --quiet yggdrasil-collector.service || stop "Collector starter ikke."
worker_doctor="$(sudo -u yggdrasil-worker "$venv/bin/yggdrasil-ids" doctor \
  --config "$config" --role collector --journal)" || stop "Collector doctor fejlede."
printf '%s' "$worker_doctor" | python3 -c \
  'import json,sys; d=json.load(sys.stdin); assert d["ok"]; print("PASS: Collector doctor og journal")'
printf 'PASS: Collector service aktiv\n'

phase="starting-web"
sudo systemctl start yggdrasil-web.service
sleep 3
systemctl is-active --quiet yggdrasil-web.service || stop "Webserveren starter ikke."
web_doctor="$(sudo -u yggdrasil-web "$venv/bin/yggdrasil-ids" doctor \
  --config "$config" --role web)" || stop "Web doctor fejlede."
printf '%s' "$web_doctor" | python3 -c \
  'import json,sys; d=json.load(sys.stdin); assert d["ok"]; print("PASS: Web doctor")'
python3 - <<'PY'
import urllib.request
with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(
    "http://127.0.0.1:8765/login", timeout=5
) as response:
    assert response.status == 200
print("PASS: Login på lokalt dashboard giver HTTP 200")
PY

phase="starting-notifier"
sudo systemctl start yggdrasil-notifier.service
sleep 3
systemctl is-active --quiet yggdrasil-notifier.service || stop "Notifier starter ikke."
final_status="$(sudo "$venv/bin/yggdrasil-ids" notify \
  --config "$config" --state-file "$notifier_state" --status)" \
  || stop "Notifier-checkpoint er inkonsistent efter opstart."
printf '%s' "$final_status" | python3 -c \
  'import json,sys; s=json.load(sys.stdin); print("PASS: Notifier pending=%s, delivered=%s" % (s["pending"],s["delivered"]))'

phase="complete"
printf '\nPASS: Yggdrasil Sprint 3 schema v4 installeret med netværksindsamling DEAKTIVERET.\n'
printf 'PASS: Collector, web og notifier er aktive og kontrolleret.\n'
printf 'Bevar eksisterende backup: %s\n' "$backup_dir"
printf 'UFW, SSH og Tailscale er ikke ændret.\n'
