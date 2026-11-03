#!/usr/bin/env bash
# Web-only seen-marker update. No production schema/config/model/notifier changes.
set -Eeuo pipefail
umask 077
sha="${1:-}"
action="${2:-install}"
branch=experiment/sudo-if-v2
base=/opt/yggdrasil-nav-unread-web
previous=/opt/yggdrasil-sudo-integration
dropdir=/etc/systemd/system/yggdrasil-web.service.d
override="$dropdir/70-nav-unread.conf"
backup="/var/backups/yggdrasil-ids/nav-unread-web-before-$sha"
if [[ ! "$sha" =~ ^[0-9a-f]{40}$ || "$(hostname)" != yggdrasil || "$(id -un)" != vidar ]]; then
  echo "STOP: Run as vidar on Yggdrasil with the reviewed full SHA" >&2
  exit 2
fi
[[ "$action" == install || "$action" == rollback ]] ||
  { echo "STOP: Expected install or rollback" >&2; exit 2; }
cd /home/vidar/AI-Intrusion-Detection-System
git fetch --no-tags origin "refs/heads/$branch:refs/remotes/origin/$branch"
if [[ "$action" == install && "$(git rev-parse "origin/$branch")" != "$sha" ]]; then
  echo "STOP: Branch changed; review the new commit" >&2
  exit 2
fi
git cat-file -e "$sha^{commit}"

healthy_login() {
  /usr/bin/python3 - <<'PY'
from urllib.request import urlopen
with urlopen("http://127.0.0.1:8765/login", timeout=5) as response:
    assert response.status == 200 and b"Yggdrasil" in response.read(16384)
PY
}

effective_path() {
  systemctl show yggdrasil-web.service --property=Environment --value |
    /usr/bin/python3 -c 'import shlex,sys; print("\n".join(v for v in shlex.split(sys.stdin.read()) if v.startswith("PYTHONPATH=")))'
}

if [[ "$action" == rollback ]]; then
  [[ "$(cat "$base/COMMIT")" == "$sha" ]] ||
    { echo "STOP: Installed web release SHA differs" >&2; exit 2; }
  [[ "$(sudo cat "$override")" == $'[Service]\nEnvironment=PYTHONPATH=/opt/yggdrasil-nav-unread-web/src\nEnvironment=PYTHONDONTWRITEBYTECODE=1' ]] ||
    { echo "STOP: Web override changed; inspect before rollback" >&2; exit 2; }
  [[ "$(effective_path)" == PYTHONPATH=/opt/yggdrasil-nav-unread-web/src ]] ||
    { echo "STOP: Effective web source changed" >&2; exit 2; }
  sudo rm -- "$override"
  sudo systemctl daemon-reload
  [[ "$(effective_path)" == "PYTHONPATH=$previous/src" ]] ||
    { echo "STOP: Previous web source differs; staged source retained for review" >&2; exit 1; }
  sudo systemctl restart yggdrasil-web.service
  systemctl is-active --quiet yggdrasil-web.service
  healthy_login
  sudo rm -rf -- "$base"
  echo "PASS: Previous schema5 web source restored; alarm history preserved"
  exit 0
fi

[[ "$(cat "$previous/COMMIT")" == 9ced7d60ab7b6776af95a12e83596683e04676ae ]] ||
  { echo "STOP: Expected verified sudo integration release" >&2; exit 2; }
current_path="$(effective_path)"
[[ "$current_path" == PYTHONPATH=/opt/yggdrasil-sudo-integration/src ]] ||
  { echo "STOP: Effective web source differs from reviewed integration" >&2; exit 2; }
for unit in yggdrasil-collector.service yggdrasil-web.service yggdrasil-notifier.service yggdrasil-sudo-shadow.timer yggdrasil-sudo-integration.timer yggdrasil-sudo-ui-export.timer; do
  systemctl is-active --quiet "$unit" ||
    { echo "STOP: Existing component inactive: $unit" >&2; exit 2; }
done
for path in "$base" "$override" "$backup"; do
  if sudo test -e "$path" || sudo test -L "$path"; then
    echo "STOP: Web release path or backup exists; inspect instead of overwriting" >&2
    exit 2
  fi
done

tmp="$(mktemp -d -t yggdrasil-nav-unread-XXXXXX)"
staged=0
changed=0
cleanup() {
  status=$?
  if ((status != 0 && changed == 1)); then
    echo "ERROR: Restoring the previous web override" >&2
    if sudo rm -f -- "$override" && sudo systemctl daemon-reload &&
       sudo systemctl restart yggdrasil-web.service && systemctl is-active --quiet yggdrasil-web.service; then
      changed=0
    else
      echo "ERROR: Web recovery needs review; retaining staged source" >&2
      staged=0
    fi
  fi
  if ((status != 0 && staged == 1 && changed == 0)); then
    sudo rm -rf -- "$base"
  fi
  rm -rf -- "$tmp"
}
trap cleanup EXIT
git archive "$sha" src/yggdrasil_ids | tar -xf - -C "$tmp"
staged=1
sudo install -d -o root -g root -m 0755 "$base"
sudo cp -a "$tmp/src" "$base/src"
sudo chown -R root:root "$base/src"
sudo chmod -R a+rX "$base/src"
printf '%s\n' "$sha" > "$tmp/COMMIT"
sudo install -o root -g root -m 0644 "$tmp/COMMIT" "$base/COMMIT"

echo "=== Verify schema5 web routes and anonymous navigation data as web user ==="
sudo /usr/bin/setpriv --reuid=yggdrasil-web --regid=yggdrasil-web --groups=yggdrasil-data \
  /usr/bin/env PYTHONPATH="$base/src" PYTHONDONTWRITEBYTECODE=1 \
  YGGDRASIL_CONFIG=/etc/yggdrasil-ids/config.toml \
  /opt/yggdrasil-ids/venv/bin/python - <<'PY'
import time
from yggdrasil_ids.config import load_config
from yggdrasil_ids.nav_alerts import snapshot
from yggdrasil_ids.storage import Repository, SCHEMA_VERSION
from yggdrasil_ids.web import create_app
cfg = load_config()
assert SCHEMA_VERSION == 5 and cfg.mode == "live"
assert cfg.web.bind == "127.0.0.1" and cfg.web.port == 8765
repo = Repository(cfg.database_path, readonly=True)
with repo.reader() as db:
    assert db.execute("PRAGMA user_version").fetchone()[0] == 5
data = snapshot(repo)
assert data["meaning"] == "browser_unseen_alert_revisions_v1"
client = create_app(cfg).test_client()
assert client.get("/api/nav-alerts").status_code == 401
with client.session_transaction() as session:
    session["authenticated"] = True
    session["authenticated_at"] = time.time()
assert client.get("/api/nav-alerts").get_json()["meaning"] == data["meaning"]
response = client.get("/sudo")
assert response.status_code == 200 and b'id="nav-alert-view"' in response.data
assert client.get("/static/nav_alerts.js").status_code == 200
assert not __import__("os").access("/var/lib/yggdrasil-sudo-shadow/sudo-shadow.sqlite3", 4)
print("PASS: Authenticated navigation and sudo page validated without database writes")
PY

sudo install -d -o root -g root -m 0700 "$backup"
sudo cp -a "$dropdir/60-sudo-integration.conf" "$backup/60-sudo-integration.conf"
cat > "$tmp/70-nav-unread.conf" <<'CONF'
[Service]
Environment=PYTHONPATH=/opt/yggdrasil-nav-unread-web/src
Environment=PYTHONDONTWRITEBYTECODE=1
CONF
changed=1
sudo install -o root -g root -m 0644 "$tmp/70-nav-unread.conf" "$override"
sudo systemctl daemon-reload
[[ "$(effective_path)" == "PYTHONPATH=$base/src" ]] ||
  { echo "STOP: Another override prevents the new web source from taking effect" >&2; exit 1; }
echo "=== Restart only the web service ==="
sudo systemctl restart yggdrasil-web.service
systemctl is-active --quiet yggdrasil-web.service
for attempt in 1 2 3 4 5; do
  if healthy_login; then break; fi
  ((attempt < 5)) || exit 1
  sleep 1
done
for unit in yggdrasil-collector.service yggdrasil-notifier.service yggdrasil-sudo-shadow.timer yggdrasil-sudo-integration.timer yggdrasil-sudo-ui-export.timer; do
  systemctl is-active --quiet "$unit"
done
echo "PASS: Browser-local seen markers activated on port 8765"
echo "Only web restarted; database, rule alarms, models and notifier delivery state preserved"
echo "Refresh the browser with Ctrl+F5, then open the relevant section"
echo "Web override backup: $backup"
changed=0
staged=0
