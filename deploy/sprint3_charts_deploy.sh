#!/usr/bin/env bash
# Deploy staged Sprint 3 charts without any SQLite migration or UFW change.
set -Eeuo pipefail
umask 077
phase="preflight"
offline=""
repo="/home/vidar/AI-Intrusion-Detection-System"
venv="/opt/yggdrasil-ids/venv"
config="/etc/yggdrasil-ids/config.toml"
db="/var/lib/yggdrasil-ids/events.sqlite3"
notifier="/var/lib/yggdrasil-notifier/delivery.sqlite3"
stop() { echo "STOP ($phase): $*" >&2; exit 1; }
on_exit() {
  result=$?
  if ((result != 0)); then
    echo "ABORT ($phase): Bevar alle backups; genkør ikke automatisk." >&2
    [[ -z "$offline" ]] || echo "Offline-backups: $offline" >&2
    echo "Undersøg tjenestestatus og script-output før rollback." >&2
  fi
}
trap on_exit EXIT
[[ $# == 1 && "$1" =~ ^[0-9a-f]{40}$ ]] || stop "Angiv fuld, godkendt source SHA."
[[ "$(id -u)" != 0 ]] || stop "Kør som vidar, ikke som root."
sha="$1"
stage="/var/backups/yggdrasil-ids/sprint3-charts-prepared-$sha"
wheel="$stage/yggdrasil_ids-0.1.0-py3-none-any.whl"
previous="$stage/previous-venv.tar.gz"
cd "$repo"
[[ -z "$(git status --porcelain)" ]] || stop "Uafklarede lokale Git-ændringer."
git fetch --no-tags origin sprint-3/network-monitoring
[[ "$(git rev-parse origin/sprint-3/network-monitoring)" == "$sha" ]] \
  || stop "Fjernbranchens head afviger fra godkendt SHA."
git cat-file -e "$sha^{commit}"
sudo -v
sudo test -s "$wheel" && sudo test -s "$previous" && sudo test -s "$stage/sha256sums.txt" \
  || stop "Staging-backup eller wheel mangler."
[[ "$(sudo cat "$stage/source-sha.txt")" == "$sha" ]] || stop "Staging-SHA er forkert."
sudo sha256sum --check --status "$stage/sha256sums.txt" \
  || stop "Wheel-/rollback-SHA-256 matcher ikke."
sudo tar -tzf "$previous" | grep -Fx 'venv/bin/yggdrasil-ids' >/dev/null \
  || stop "Rollback-venv er ufuldstændig."
for service in yggdrasil-collector.service yggdrasil-web.service yggdrasil-notifier.service; do
  systemctl is-active --quiet "$service" || stop "$service er ikke aktiv før deploy."
done
sudo ufw status verbose | grep -F "Logging: on (low)" >/dev/null \
  || stop "UFW logging level er ændret."
sudo "$venv/bin/python" - <<'PY'
from pathlib import Path
from yggdrasil_ids.config import load_config
from yggdrasil_ids.storage import SCHEMA_VERSION, Repository
cfg = load_config(Path("/etc/yggdrasil-ids/config.toml"))
assert SCHEMA_VERSION == 4
assert cfg.mode == "live" and cfg.network.enabled is True
assert cfg.network.window_seconds == 60
assert cfg.network.distinct_ports_threshold == 5
assert cfg.web.bind in {"127.0.0.1", "::1"}
assert not hasattr(Repository, "firewall_charts"), "Charts allerede installeret; stop!"
print("PASS: Eksisterende schema v4 og netværksregler bevares")
PY
sudo "$venv/bin/python" -m pip check >/dev/null || stop "Dependency-fejl."
sudo -u yggdrasil-worker "$venv/bin/yggdrasil-ids" doctor \
  --config "$config" --role collector --journal >/dev/null || stop "Collector doctor."
sudo -u yggdrasil-web "$venv/bin/yggdrasil-ids" doctor \
  --config "$config" --role web >/dev/null || stop "Web doctor."
before="$(sudo "$venv/bin/yggdrasil-ids" notify \
  --config "$config" --state-file "$notifier" --status)" || stop "Notifier state preflight."
printf '%s' "$before" | python3 -c \
  'import json,sys; a=json.load(sys.stdin); assert a["pending"]>=0; print("PASS: Notifier state konsistent")'
free_mb="$(df -Pm /var/backups/yggdrasil-ids | awk 'NR==2{print $4}')"
[[ "$free_mb" =~ ^[0-9]+$ && "$free_mb" -ge 512 ]] || stop "Utilstrækkelig diskplads."

phase="stopping-ids"
sudo systemctl stop yggdrasil-notifier.service yggdrasil-web.service yggdrasil-collector.service
for service in yggdrasil-collector.service yggdrasil-web.service yggdrasil-notifier.service; do
  if systemctl is-active --quiet "$service"; then stop "$service blev ikke stoppet."; fi
done

phase="offline-backup"
offline="$(sudo mktemp -d -p /var/backups/yggdrasil-ids sprint3-charts-offline-XXXXXXXX)"
sudo "$venv/bin/yggdrasil-ids" backup --config "$config" \
  --output "$offline/pre-charts-v4.sqlite3" || stop "Backup fejlede."
sudo tar -czf "$offline/ids-data.tar.gz" -C /var/lib yggdrasil-ids
sudo tar -czf "$offline/notifier-data.tar.gz" -C /var/lib yggdrasil-notifier
sudo tar -czf "$offline/config.tar.gz" -C /etc yggdrasil-ids
sudo tar -czf "$offline/systemd.tar.gz" -C /etc/systemd/system \
  yggdrasil-collector.service yggdrasil-web.service yggdrasil-notifier.service
sudo find "$offline" -maxdepth 1 -type f -exec chmod 0600 {} +
sudo "$venv/bin/python" - "$offline/pre-charts-v4.sqlite3" <<'PY'
import sqlite3,sys
with sqlite3.connect(sys.argv[1]) as db:
    assert db.execute("PRAGMA user_version").fetchone()[0] == 4
    assert db.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    assert not db.execute("PRAGMA foreign_key_check").fetchone()
print("PASS: Offline schema-v4-backup verificeret")
PY
for archive in "$offline/ids-data.tar.gz" "$offline/notifier-data.tar.gz" \
  "$offline/config.tar.gz" "$offline/systemd.tar.gz"; do
  sudo tar -tzf "$archive" >/dev/null || stop "Kunne ikke verificere backup-arkiv."
done

phase="install"
# Critical: Python package files must be accessible to all 3 service accounts.
sudo /bin/sh -c 'umask 022; exec "$1" -m pip install --no-index --no-deps --force-reinstall "$2"' \
  _ "$venv/bin/python" "$wheel" || stop "Wheel-installation fejlede."
sudo "$venv/bin/python" -m pip check >/dev/null || stop "Dependency-fejl efter install."
for account in yggdrasil-worker yggdrasil-web yggdrasil-notifier; do
  sudo -u "$account" "$venv/bin/yggdrasil-ids" --version >/dev/null \
    || stop "CLI utilgængelig for $account."
  echo "PASS: CLI tilgængelig for $account"
done
sudo -u yggdrasil-web "$venv/bin/python" - "$config" <<'PY'
import sys
from pathlib import Path
from yggdrasil_ids.config import load_config
from yggdrasil_ids.storage import Repository, SCHEMA_VERSION
from yggdrasil_ids.web import create_app
assert SCHEMA_VERSION == 4
cfg=load_config(Path(sys.argv[1]))
assert cfg.network.enabled and cfg.network.distinct_ports_threshold == 5
assert callable(getattr(Repository,"firewall_charts",None))
app=create_app(cfg)
assert "/api/network-charts" in {str(rule) for rule in app.url_map.iter_rules()}
sample=Repository(cfg.database_path,readonly=True).firewall_charts(hours=1)
assert len(sample["top_ports"])<=10
assert sample["other_ports_packets"]>=0
print("PASS: Webkonto kan bruge nye diagrammer (maks 10 porte) og schema v4")
PY

phase="starting-services"
sudo systemctl start yggdrasil-collector.service
sleep 5
systemctl is-active --quiet yggdrasil-collector.service || stop "Collector ikke aktiv."
sudo -u yggdrasil-worker "$venv/bin/yggdrasil-ids" doctor \
  --config "$config" --role collector --journal >/dev/null || stop "Collector doctor fejlede."
sudo systemctl start yggdrasil-web.service
sleep 3
systemctl is-active --quiet yggdrasil-web.service || stop "Web ikke aktiv."
sudo -u yggdrasil-web "$venv/bin/yggdrasil-ids" doctor \
  --config "$config" --role web >/dev/null || stop "Web doctor fejlede."
python3 - <<'PY'
from urllib.request import build_opener, ProxyHandler, HTTPError
opener=build_opener(ProxyHandler({}))
with opener.open("http://127.0.0.1:8765/login",timeout=5) as res:
    assert res.status==200
try:
    opener.open("http://127.0.0.1:8765/api/network-charts?hours=1",timeout=5)
except HTTPError as err:
    assert err.code==401
else:
    raise AssertionError("Graf-API må ikke være offentligt tilgængeligt.")
print("PASS: Dashboard login HTTP200 og graf-API kræver login (401)")
PY
sudo systemctl start yggdrasil-notifier.service
sleep 3
systemctl is-active --quiet yggdrasil-notifier.service || stop "Notifier ikke aktiv."
after="$(sudo "$venv/bin/yggdrasil-ids" notify \
  --config "$config" --state-file "$notifier" --status)" || stop "Notifier checkpoint fejlede."
BEFORE="$before" AFTER="$after" python3 - <<'PY'
import json,os
before=json.loads(os.environ["BEFORE"])
after=json.loads(os.environ["AFTER"])
assert after["delivered"]>=before["delivered"]
assert after["last_seq"]>=before["last_seq"]
print("PASS: Discord checkpoint bevaret; pending=%s, delivered=%s" %
      (after["pending"],after["delivered"]))
PY
sudo "$venv/bin/python" - "$offline/pre-charts-v4.sqlite3" "$db" <<'PY'
import sqlite3,sys
with sqlite3.connect(sys.argv[1]) as old, sqlite3.connect(
    f"file:{sys.argv[2]}?mode=ro",uri=True
) as new:
    assert old.execute("PRAGMA user_version").fetchone()[0]==4
    assert new.execute("PRAGMA user_version").fetchone()[0]==4
    assert new.execute("PRAGMA quick_check").fetchone()[0]=="ok"
    for table in ("events","observations","alerts","network_evidence","discord_outbox"):
        before=old.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
        after=new.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
        assert after>=before,(table,before,after)
print("PASS: Eksisterende SSH-, netværks- og alarmhistorik bevaret")
PY
sudo ufw status verbose | grep -F "Logging: on (low)" >/dev/null || stop "UFW logging ændret."
phase="complete"
echo "PASS: Sprint 3-grafer installeret; collector/web/notifier aktive; UFW low."
echo "OFFLINE_BACKUP=$offline"
echo "ROLLBACK_VENV=$previous"
echo "Nu kan dashboardets /network-grafer accepttestes og fotograferes."
