#!/usr/bin/env bash
# Controlled Sprint 3 deployment. Stop only the three IDS services.
# Private offline backups are verified before touching installed code or DB.
set -Eeuo pipefail
umask 077

release_sha="07fab99c88fe51a2cc455f51788bb17fd6c37fa4"
expected_wheel="859726739016d0876e14a31d4762c203062f6a5530ad6da3013ad6df8da72b5e"
expected_venv="fb38bc7b05024d6f52873fd3ec85093e157b2b4a7e607e0b70a88690a994faeb"
repository="/home/vidar/AI-Intrusion-Detection-System"
venv="/opt/yggdrasil-ids/venv"
config="/etc/yggdrasil-ids/config.toml"
notifier_state="/var/lib/yggdrasil-notifier/delivery.sqlite3"
prepared="/var/backups/yggdrasil-ids/sprint3-prepared-$release_sha"
wheel="$prepared/yggdrasil_ids-0.1.0-py3-none-any.whl"
old_venv="$prepared/previous-venv.tar.gz"
offline=""
phase="preflight"

stop() { printf 'STOP under %s: %s\n' "$phase" "$*" >&2; exit 1; }

on_exit() {
  code=$?
  if (( code != 0 )); then
    printf '\nAFBRUDT: fase=%s, exit=%d\n' "$phase" "$code" >&2
    [[ -z "$offline" ]] || printf 'Private offline-backups: %s\n' "$offline" >&2
    printf 'Kør ikke scriptet igen automatisk. Bevar alle backups.\n' >&2
    printf 'Del fejl og tjenestestatus før rollback eller genstart.\n' >&2
  fi
}
trap on_exit EXIT

if [[ $# -ne 1 || ! "$1" =~ ^[0-9a-f]{40}$ ]]; then
  stop "Kald med fuldt SHA på det grønt CI-testede deploy-script."
fi
if [[ "$(id -u)" -eq 0 ]]; then
  stop "Kør som vidar, ikke som root."
fi
script_sha="$1"
cd "$repository"
if [[ -n "$(git status --porcelain)" ]]; then
  git status --short
  stop "Git-arbejdsområdet har lokale ændringer."
fi
git fetch --no-tags origin sprint-3/network-monitoring
remote_sha="$(git rev-parse --verify refs/remotes/origin/sprint-3/network-monitoring)"
[[ "$remote_sha" == "$script_sha" ]] || stop "Remote-branchen svarer ikke til den angivne script-SHA."
git cat-file -e "$release_sha^{commit}"
git cat-file -e "$script_sha^{commit}"
git diff --quiet "$release_sha" "$script_sha" -- \
  src pyproject.toml requirements.lock requirements-dev.txt \
  || stop "Kildekode eller afhængigheder er ændret siden den byggede wheel."

for service in yggdrasil-collector.service yggdrasil-web.service yggdrasil-notifier.service; do
  systemctl is-active --quiet "$service" || stop "Tjenesten $service er ikke aktiv."
done
sudo -v
for service in yggdrasil-collector.service yggdrasil-web.service yggdrasil-notifier.service; do
  sudo test -f "/etc/systemd/system/$service" || stop "Manglende unit: $service"
done
sudo test -f "$wheel" && sudo test -f "$old_venv" \
  || stop "Den forberedte wheel eller gammel venv mangler."
[[ "$(sudo cat "$prepared/source-sha.txt")" == "$release_sha" ]] || stop "Uventet kilde-SHA."
[[ "$(sudo sha256sum "$wheel" | awk '{print $1}')" == "$expected_wheel" ]] \
  || stop "Wheel SHA-256 matcher ikke det verificerede build."
[[ "$(sudo sha256sum "$old_venv" | awk '{print $1}')" == "$expected_venv" ]] \
  || stop "Tidligere Python-miljø matcher ikke det verificerede snapshot."
sudo tar -tzf "$old_venv" | grep -Fx 'venv/bin/yggdrasil-ids' >/dev/null \
  || stop "Gammelt venv-snapshot kan ikke verificeres."

sudo "$venv/bin/python" - <<'PY'
import sqlite3
import tomllib
from pathlib import Path

with Path("/etc/yggdrasil-ids/config.toml").open("rb") as stream:
    cfg = tomllib.load(stream)
assert cfg.get("app", {}).get("mode") == "live"
assert cfg.get("network", {}).get("enabled", False) is False
assert cfg.get("web", {}).get("bind", "127.0.0.1") in {"127.0.0.1", "::1"}
with sqlite3.connect("file:/var/lib/yggdrasil-ids/events.sqlite3?mode=ro", uri=True) as db:
    assert db.execute("PRAGMA user_version").fetchone()[0] == 3
    assert db.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    assert not db.execute("PRAGMA foreign_key_check").fetchone()
print("PASS: Produktionsdatabase v3 intakt og network.enabled=false")
PY
sudo "$venv/bin/python" -m pip check >/dev/null || stop "Eksisterende venv dependency-fejl."
sudo test -f "$notifier_state" || stop "Notifierens state-fil mangler."
notifier_status="$(sudo "$venv/bin/yggdrasil-ids" notify \
  --config "$config" --state-file "$notifier_state" --status)" \
  || stop "Notifierens state stemmer ikke overens med outbox."
printf '%s' "$notifier_status" | python3 -c \
  'import json,sys; d=json.load(sys.stdin); assert d["pending"]>=0 and d["last_seq"]>=0; print("PASS: Notifier-checkpoint konsistent")'
free_mb="$(df -Pm /var/backups/yggdrasil-ids | awk 'NR==2 {print $4}')"
[[ "$free_mb" =~ ^[0-9]+$ && "$free_mb" -ge 512 ]] || stop "Utilstrækkelig diskplads."
printf 'PASS: Godkendt release-wheel og tidligere venv verificeret med SHA-256\n'

phase="stopping"
printf '\nStopper kun Yggdrasil notifier, web og collector ...\n'
sudo systemctl stop yggdrasil-notifier.service
sudo systemctl stop yggdrasil-web.service
sudo systemctl stop yggdrasil-collector.service
for service in yggdrasil-notifier.service yggdrasil-web.service yggdrasil-collector.service; do
  if systemctl is-active --quiet "$service"; then stop "Tjenesten $service kører stadig."; fi
done

phase="offline-backups"
offline="$(sudo mktemp -d -p /var/backups/yggdrasil-ids sprint3-offline-XXXXXXXX)"
sudo "$venv/bin/yggdrasil-ids" backup --config "$config" \
  --output "$offline/pre-sprint3-v3.sqlite3"
sudo tar -czf "$offline/ids-data-v3.tar.gz" -C /var/lib yggdrasil-ids
sudo tar -czf "$offline/notifier-state.tar.gz" -C /var/lib yggdrasil-notifier
sudo tar -czf "$offline/config-and-secrets.tar.gz" -C /etc yggdrasil-ids
sudo tar -czf "$offline/systemd-units.tar.gz" -C /etc/systemd/system \
  yggdrasil-collector.service yggdrasil-web.service yggdrasil-notifier.service
sudo find "$offline" -maxdepth 1 -type f -exec chmod 0600 {} +
sudo "$venv/bin/python" - "$offline/pre-sprint3-v3.sqlite3" <<'PY'
import sqlite3
import sys
with sqlite3.connect(sys.argv[1]) as db:
    assert db.execute("PRAGMA user_version").fetchone()[0] == 3
    assert db.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    assert not db.execute("PRAGMA foreign_key_check").fetchone()
print("PASS: Frisk offline-backup v3 med godkendt SQLite-integritet")
PY
for archive in "$offline/ids-data-v3.tar.gz" "$offline/notifier-state.tar.gz" \
  "$offline/config-and-secrets.tar.gz" "$offline/systemd-units.tar.gz"; do
  sudo tar -tzf "$archive" >/dev/null || stop "Backup-arkivet kan ikke læses."
done
printf 'PASS: Data, notifier-state, konfiguration og systemd-units arkiveret privat\n'

phase="installing-wheel"
# pip writes new package paths via open(..., 'wb') and mkdir. A process-wide
# umask 077 can make Python modules inaccessible to yggdrasil-worker, even
# though root can import them. Limit 022 to this code-only wheel install;
# retain 077 for all backup and secrets operations above and below.
sudo /bin/sh -c 'umask 022; exec "$1" -m pip install --no-index --no-deps --force-reinstall "$2"' \
  _ "$venv/bin/python" "$wheel"
sudo "$venv/bin/python" -m pip check >/dev/null || stop "Dependency-fejl efter installation."
sudo "$venv/bin/python" - <<'PY'
from yggdrasil_ids.cli import main
from yggdrasil_ids.storage import SCHEMA_VERSION
from yggdrasil_ids.network_rules import TCPPortScanDetector
assert SCHEMA_VERSION == 4
assert TCPPortScanDetector is not None and callable(main)
print("PASS: Sprint 3-kode installeret (CLI, schema v4, netværksregel)")
PY

# A root-only import proves nothing about the three non-root services.
# Fail BEFORE mutating the production schema if any service user cannot
# execute the actual console entry point.
for account in yggdrasil-worker yggdrasil-web yggdrasil-notifier; do
  sudo -u "$account" "$venv/bin/yggdrasil-ids" --version >/dev/null \
    || stop "Ny CLI er ikke tilgængelig for $account; schema v3 er endnu ikke ændret."
  printf 'PASS: CLI importeres som %s\n' "$account"
done

phase="migrating-db"
sudo -u yggdrasil-worker "$venv/bin/yggdrasil-ids" init --config "$config"
sudo "$venv/bin/python" - "$offline/pre-sprint3-v3.sqlite3" <<'PY'
import sqlite3
import sys

tables = (
    "records", "events", "observations", "alerts", "findings",
    "preauth_disconnects", "preauth_evidence", "discord_outbox",
    "discord_outbox_meta"
)
with sqlite3.connect(sys.argv[1]) as old, sqlite3.connect(
    "/var/lib/yggdrasil-ids/events.sqlite3"
) as new:
    assert old.execute("PRAGMA user_version").fetchone()[0] == 3
    assert new.execute("PRAGMA user_version").fetchone()[0] == 4
    assert new.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    assert not new.execute("PRAGMA foreign_key_check").fetchone()
    for table in tables:
        before = old.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
        after = new.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
        assert before == after, (table, before, after)
    assert old.execute(
        "SELECT instance FROM discord_outbox_meta WHERE id=1"
    ).fetchone() == new.execute(
        "SELECT instance FROM discord_outbox_meta WHERE id=1"
    ).fetchone()
    assert old.execute(
        "SELECT seq,ref,detector_id,severity,happened_at FROM discord_outbox ORDER BY seq"
    ).fetchall() == new.execute(
        "SELECT seq,ref,detector_id,severity,happened_at FROM discord_outbox ORDER BY seq"
    ).fetchall()
    assert new.execute("SELECT COUNT(*) FROM firewall_events").fetchone()[0] == 0
    assert new.execute("SELECT COUNT(*) FROM network_evidence").fetchone()[0] == 0
print("PASS: Live v3->v4, alle SSH-rækker og Discord-outbox bevaret")
PY

phase="starting"
sudo systemctl start yggdrasil-collector.service
sleep 8
systemctl is-active --quiet yggdrasil-collector.service || stop "Collector er ikke aktiv."
worker_check="$(sudo -u yggdrasil-worker "$venv/bin/yggdrasil-ids" doctor \
  --config "$config" --role collector --journal)" || stop "Collector doctor fejlede."
printf '%s' "$worker_check" | python3 -c \
  'import json,sys; x=json.load(sys.stdin); assert x["ok"],x["checks"]; print("PASS: Collector doctor og journaladgang")'

sudo systemctl start yggdrasil-web.service
sleep 3
systemctl is-active --quiet yggdrasil-web.service || stop "Web er ikke aktiv."
web_check="$(sudo -u yggdrasil-web "$venv/bin/yggdrasil-ids" doctor \
  --config "$config" --role web)" || stop "Web doctor fejlede."
printf '%s' "$web_check" | python3 -c \
  'import json,sys; x=json.load(sys.stdin); assert x["ok"],x["checks"]; print("PASS: Web doctor og credentials")'
python3 - <<'PY'
from urllib.request import ProxyHandler, build_opener
opener = build_opener(ProxyHandler({}))
with opener.open("http://127.0.0.1:8765/login", timeout=5) as response:
    assert response.status == 200
print("PASS: Dashboardets login-side svarer på localhost")
PY

sudo systemctl start yggdrasil-notifier.service
sleep 3
systemctl is-active --quiet yggdrasil-notifier.service || stop "Notifier er ikke aktiv."
after_status="$(sudo "$venv/bin/yggdrasil-ids" notify \
  --config "$config" --state-file "$notifier_state" --status)" \
  || stop "Notifier-state er ikke konsistent med outbox efter restart."
printf '%s' "$after_status" | python3 -c \
  'import json,sys; x=json.load(sys.stdin); assert x["pending"]>=0; print("PASS: Discord-state pending=%s delivered=%s" % (x["pending"],x["delivered"]))'

phase="complete"
printf '\nPASS: Sprint 3 installeret med produktionsschema v4 og network.enabled=false\n'
printf 'PASS: Collector, web og notifier er startet og kontrolleret\n'
printf 'UFW, Tailscale, SSH og Fail2ban er ikke ændret.\n'
printf 'Release-kode: %s\n' "$release_sha"
printf 'Friske offline- og rollbackbackups (root-only): %s\n' "$offline"
printf 'Tidligere installeret venv: %s\n' "$old_venv"
printf 'Separat portscan-accept og langtidstest afventer.\n'
