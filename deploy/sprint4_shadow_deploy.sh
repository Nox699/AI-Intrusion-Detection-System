#!/usr/bin/env bash
# Install a vetted private experimental hybrid SSH model ONLY in shadow mode.
# Explicit second-stage operation. No network/SSH/firewall/systemd-unit edits.
set -Eeuo pipefail
umask 077
phase="preflight"
offline=""
repo="/home/vidar/AI-Intrusion-Detection-System"
venv="/opt/yggdrasil-ids/venv"
config="/etc/yggdrasil-ids/config.toml"
db="/var/lib/yggdrasil-ids/events.sqlite3"
model="/var/lib/yggdrasil-ids/model.json"
notifier="/var/lib/yggdrasil-notifier/delivery.sqlite3"
branch="sprint-4/live-ml-shadow"
stop() { echo "STOP ($phase): $*" >&2; exit 1; }
on_exit() {
  code=$?
  if ((code)); then
    echo "ABORT ($phase): Do not run deployment again blindly." >&2
    [[ -z "$offline" ]] || echo "Offline backup: $offline" >&2
    echo "If installation started, inspect services and use documented rollback." >&2
  fi
}
trap on_exit EXIT
[[ $# == 1 && "$1" =~ ^[0-9a-f]{40}$ ]] || stop "Provide pinned CI-approved SHA."
[[ "$(id -u)" -ne 0 ]] || stop "Run as vidar, not root."
sha="$1"
stage="/var/backups/yggdrasil-ids/sprint4-shadow-prepared-$sha"
wheel="$stage/yggdrasil_ids-0.1.0-py3-none-any.whl"
snapshot="$stage/previous-venv.tar.gz"
candidate="$stage/private-candidate-model.json"

cd "$repo"
[[ -z "$(git status --porcelain)" ]] || stop "Local checkout has changes."
git fetch --no-tags origin "$branch"
[[ "$(git rev-parse "origin/$branch")" == "$sha" ]] || stop "Remote SHA differs from prepared release."
git cat-file -e "$sha^{commit}"
sudo -v
for file in "$wheel" "$snapshot" "$candidate" "$stage/source-sha.txt" \
            "$stage/sha256sums.txt"; do
  sudo test -s "$file" || stop "Missing staged release item."
done
[[ "$(sudo cat "$stage/source-sha.txt")" == "$sha" ]] || stop "Stage source SHA mismatch."
sudo sha256sum --check --status "$stage/sha256sums.txt" || stop "Staged SHA-256 mismatch."
sudo tar -tzf "$snapshot" | grep -Fx 'venv/bin/yggdrasil-ids' >/dev/null \
  || stop "Rollback venv archive invalid."
sudo test ! -e "$model" || stop "Production model already exists."
sudo ufw status verbose | grep -F "Logging: on (low)" >/dev/null \
  || stop "UFW logging differs from accepted state."
for service in yggdrasil-collector.service yggdrasil-web.service yggdrasil-notifier.service; do
  systemctl is-active --quiet "$service" || stop "$service not active."
done
sudo "$venv/bin/python" -m pip check >/dev/null || stop "Current venv deps invalid."
sudo "$venv/bin/python" - "$config" "$candidate" <<'PY'
import sqlite3,sys,tomllib
from pathlib import Path
from yggdrasil_ids.ml import IsolationForestDetector
from yggdrasil_ids.storage import SCHEMA_VERSION
raw=tomllib.loads(Path(sys.argv[1]).read_text())
assert SCHEMA_VERSION == 4
assert raw["app"]["mode"] == "live"
assert raw["network"]["enabled"] is True
assert raw["network"]["distinct_ports_threshold"] == 5
assert raw["web"]["bind"] in ("127.0.0.1", "::1")
assert "alert_mode" not in raw["ml"], "Shadow already configured; stop."
assert not Path(raw["paths"]["model"]).exists()
with sqlite3.connect(Path(raw["paths"]["database"]).as_uri()+"?mode=ro",uri=True) as db:
    db.execute("PRAGMA query_only=ON")
    assert db.execute("PRAGMA user_version").fetchone()[0]==4
    assert db.execute("PRAGMA quick_check").fetchone()[0]=="ok"
m=IsolationForestDetector.load(sys.argv[2])
assert m.metadata["version"]=="ssh-if-7cc1f15288d0c73b"
assert m.metadata["sample_count"]==324
assert "EXPERIMENTAL hybrid bootstrap" in m.metadata["provenance"]
print("PASS: Candidate identity, untouched live model and schema v4.")
PY
sudo -u yggdrasil-worker "$venv/bin/yggdrasil-ids" doctor \
  --config "$config" --role collector --journal >/dev/null || stop "Worker doctor."
sudo -u yggdrasil-web "$venv/bin/yggdrasil-ids" doctor \
  --config "$config" --role web >/dev/null || stop "Web doctor."
before="$(sudo "$venv/bin/yggdrasil-ids" notify \
  --config "$config" --state-file "$notifier" --status)" || stop "Notifier preflight."
printf '%s' "$before" | python3 -c 'import json,sys; x=json.load(sys.stdin); assert x["pending"]>=0 and x["delivered"]>=0'
free_mb="$(df -Pm /var/backups/yggdrasil-ids | awk 'NR==2{print $4}')"
[[ "$free_mb" =~ ^[0-9]+$ && "$free_mb" -ge 512 ]] || stop "Disk space below 512 MB."

phase="stopping"
sudo systemctl stop yggdrasil-notifier.service yggdrasil-web.service yggdrasil-collector.service
for service in yggdrasil-collector.service yggdrasil-web.service yggdrasil-notifier.service; do
  ! systemctl is-active --quiet "$service" || stop "$service is still active."
done
phase="offline-backup"
offline="$(sudo mktemp -d -p /var/backups/yggdrasil-ids sprint4-shadow-offline-XXXXXXXX)"
sudo "$venv/bin/yggdrasil-ids" backup --config "$config" \
  --output "$offline/pre-shadow-v4.sqlite3" || stop "SQLite backup failed."
sudo tar -C /var/lib -czf "$offline/ids-data.tar.gz" yggdrasil-ids
sudo tar -C /var/lib -czf "$offline/notifier-data.tar.gz" yggdrasil-notifier
sudo tar -C /etc -czf "$offline/config.tar.gz" yggdrasil-ids
sudo tar -C /etc/systemd/system -czf "$offline/systemd.tar.gz" \
  yggdrasil-collector.service yggdrasil-web.service yggdrasil-notifier.service
sudo find "$offline" -maxdepth 1 -type f -exec chmod 0600 {} +
sudo "$venv/bin/python" - "$offline/pre-shadow-v4.sqlite3" <<'PY'
import sqlite3,sys
with sqlite3.connect(sys.argv[1]) as db:
    assert db.execute("PRAGMA user_version").fetchone()[0]==4
    assert db.execute("PRAGMA integrity_check").fetchone()[0]=="ok"
    assert not db.execute("PRAGMA foreign_key_check").fetchone()
print("PASS: Offline SQLite schema-v4 backup validated.")
PY
for name in ids-data notifier-data config systemd; do
  sudo tar -tzf "$offline/$name.tar.gz" >/dev/null || stop "Backup tar invalid: $name."
done
sudo sha256sum "$offline"/*.gz "$offline/pre-shadow-v4.sqlite3" |
  sudo tee "$offline/sha256sums.txt" >/dev/null
sudo chmod 0600 "$offline/sha256sums.txt"
sudo sha256sum --check --status "$offline/sha256sums.txt" || stop "Offline backup hash error."
echo "PASS: All offline snapshots verified before software/config changes."

phase="installing-wheel"
sudo /bin/sh -c 'umask 022; exec "$1" -m pip install --no-index --no-deps --force-reinstall "$2"' \
  _ "$venv/bin/python" "$wheel" || stop "Wheel installation failed."
sudo "$venv/bin/python" -m pip check >/dev/null || stop "New venv dependencies failed."
for account in yggdrasil-worker yggdrasil-web yggdrasil-notifier; do
  sudo -u "$account" "$venv/bin/yggdrasil-ids" --version >/dev/null \
    || stop "New package unreadable by $account."
done
sudo "$venv/bin/python" - "$config" <<'PY'
import sys
from pathlib import Path
from yggdrasil_ids.config import load_config
from yggdrasil_ids.storage import SCHEMA_VERSION
assert SCHEMA_VERSION==4
cfg=load_config(Path(sys.argv[1]))
assert cfg.ml.alert_mode=="alert"
assert cfg.network.enabled and cfg.network.distinct_ports_threshold==5
print("PASS: New software works with existing schema and old config.")
PY

phase="configuring-shadow"
# This change is atomic, restricted to the existing [ml] section and preserves
# the original root/group/mode. Never create a second [ml] section.
sudo python3 - "$config" <<'PY'
import os,re,stat,sys,tempfile,tomllib
from pathlib import Path
path=Path(sys.argv[1])
raw=path.read_text()
parsed=tomllib.loads(raw)
assert "alert_mode" not in parsed["ml"]
match=list(re.finditer(r"(?m)^\[ml\]\s*$",raw))
assert len(match)==1
end=re.search(r"(?m)^\[[^\]]+\]\s*$",raw[match[0].end():])
position=match[0].end()+(end.start() if end else len(raw)-match[0].end())
updated=raw[:position]+'alert_mode = "shadow"\n'+raw[position:]
check=tomllib.loads(updated)
assert check["ml"]["alert_mode"]=="shadow"
test=dict(parsed)
test["ml"]=dict(parsed["ml"],alert_mode="shadow")
assert check==test, "Unintended config delta."
old=path.stat()
name=None
try:
    with tempfile.NamedTemporaryFile("w",encoding="utf-8",dir=path.parent,
                                     prefix=".shadow-config-",delete=False) as handle:
        name=handle.name
        handle.write(updated)
        handle.flush()
        os.fsync(handle.fileno())
    os.chown(name,old.st_uid,old.st_gid)
    os.chmod(name,stat.S_IMODE(old.st_mode))
    os.replace(name,path)
    name=None
finally:
    if name is not None:
        Path(name).unlink(missing_ok=True)
print("PASS: Atomic config change sets shadow, preserving all other settings.")
PY
sudo test ! -e "$model" || stop "Model appeared before installation."
sudo install -o yggdrasil-worker -g yggdrasil-data -m 0600 \
  "$candidate" "$model" || stop "Could not install private model as collector-owned file."

phase="model-preflight"
sudo -u yggdrasil-worker "$venv/bin/python" - "$config" <<'PY'
import sys
from pathlib import Path
from yggdrasil_ids.config import load_config
from yggdrasil_ids.ml import IsolationForestDetector
cfg=load_config(Path(sys.argv[1]))
assert cfg.ml.alert_mode=="shadow"
assert cfg.mode=="live"
assert cfg.network.enabled and cfg.network.distinct_ports_threshold==5
assert cfg.web.bind in ("127.0.0.1","::1")
m=IsolationForestDetector.load(cfg.model_path)
assert m.metadata["version"]=="ssh-if-7cc1f15288d0c73b"
assert m.metadata["sample_count"]==324
assert "EXPERIMENTAL" in m.metadata["provenance"]
print("PASS: Worker can load experimental model only with shadow mode.")
PY
sudo -u yggdrasil-web "$venv/bin/python" - "$config" <<'PY'
from pathlib import Path
import sys
from yggdrasil_ids.config import load_config
from yggdrasil_ids.web import create_app
cfg=load_config(Path(sys.argv[1]))
assert cfg.ml.alert_mode=="shadow"
assert cfg.web.bind=="127.0.0.1"
app=create_app(cfg)
assert "/model" in {str(rule) for rule in app.url_map.iter_rules()}
print("PASS: Web user loads shadow-enabled private dashboard.")
PY

phase="starting"
sudo systemctl start yggdrasil-collector.service
sleep 5
systemctl is-active --quiet yggdrasil-collector.service || stop "Collector failed."
sudo -u yggdrasil-worker "$venv/bin/yggdrasil-ids" doctor \
  --config "$config" --role collector --journal >/dev/null || stop "Collector doctor after restart."
sudo "$venv/bin/python" - "$db" <<'PY'
import json,sqlite3,sys
with sqlite3.connect("file:"+sys.argv[1]+"?mode=ro",uri=True) as db:
    state=json.loads(db.execute("SELECT value FROM state WHERE key='model'").fetchone()[0])
    assert state["state"]=="ready"
    assert state["alert_mode"]=="shadow"
    assert state["metadata"]["version"]=="ssh-if-7cc1f15288d0c73b"
print("PASS: Live collector loaded shadow model and persisted correct state.")
PY
sudo systemctl start yggdrasil-web.service
sleep 3
systemctl is-active --quiet yggdrasil-web.service || stop "Web failed."
sudo -u yggdrasil-web "$venv/bin/yggdrasil-ids" doctor \
  --config "$config" --role web >/dev/null || stop "Web doctor."
python3 - <<'PY'
from urllib.request import build_opener,ProxyHandler,HTTPError
open_local=build_opener(ProxyHandler({}))
with open_local.open("http://127.0.0.1:8765/login",timeout=5) as response:
    assert response.status==200
try:
    open_local.open("http://127.0.0.1:8765/api/overview",timeout=5)
except HTTPError as e:
    assert e.code==401
else:
    raise AssertionError("Private API unexpectedly unauthenticated")
print("PASS: Dashboard remains loopback-only and protected by login.")
PY
sudo systemctl start yggdrasil-notifier.service
sleep 3
systemctl is-active --quiet yggdrasil-notifier.service || stop "Notifier failed."
after="$(sudo "$venv/bin/yggdrasil-ids" notify \
  --config "$config" --state-file "$notifier" --status)" || stop "Notifier checkpoint."
BEFORE="$before" AFTER="$after" python3 - <<'PY'
import json,os
a=json.loads(os.environ["BEFORE"])
b=json.loads(os.environ["AFTER"])
assert b["delivered"]>=a["delivered"]
assert b["last_seq"]>=a["last_seq"]
print("PASS: Notifier delivery checkpoint preserved.")
PY
sudo "$venv/bin/python" - "$offline/pre-shadow-v4.sqlite3" "$db" <<'PY'
import sqlite3,sys
with sqlite3.connect(sys.argv[1]) as prior, sqlite3.connect(
    "file:"+sys.argv[2]+"?mode=ro",uri=True
) as live:
    assert live.execute("PRAGMA user_version").fetchone()[0]==4
    assert live.execute("PRAGMA quick_check").fetchone()[0]=="ok"
    for name in ("events","observations","alerts","network_evidence","discord_outbox"):
        previous=prior.execute(f"SELECT count(*) FROM {name}").fetchone()[0]
        current=live.execute(f"SELECT count(*) FROM {name}").fetchone()[0]
        assert current>=previous,(name,previous,current)
    for database in (prior,live):
        count=database.execute(
            "SELECT count(*) FROM findings WHERE detector_id='ssh.isolation_forest'"
        ).fetchone()[0]
        if database is prior:
            old_ml=count
        else:
            assert count==old_ml,"Shadow produced an ML finding!"
print("PASS: Existing incidents/history preserved; no new shadow ML findings.")
PY
sudo ufw status verbose | grep -F "Logging: on (low)" >/dev/null \
  || stop "Unexpected UFW logging change."
phase="complete"
echo "PASS: Experimental hybrid model installed in SSH shadow mode only."
echo "MODEL=ssh-if-7cc1f15288d0c73b"
echo "OFFLINE_BACKUP=$offline"
echo "ROLLBACK_VENV=$snapshot"
echo "Collector, web, notifier active; network/rules/Discord still functional."
echo "Now use normal SSH to generate a new scored observation; NO ML alerts are sent."
