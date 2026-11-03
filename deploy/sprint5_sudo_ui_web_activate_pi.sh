#!/usr/bin/env bash
# Rollbackable web-only sudo UI release after separate port-8766 preview.
# Uses a systemd drop-in with PYTHONPATH instead of pip replacement.
# No changes to collector/notifier/sudo-shadow code, database, config, firewall or SSH.
set -Eeuo pipefail
umask 077
sha="${1:-}"
if [[ ! "$sha" =~ ^[0-9a-f]{40}$ ||
      "$(hostname)" != "yggdrasil" || "$(id -un)" != "vidar" ]]; then
  echo "STOP: Run as vidar on Yggdrasil with reviewed full SHA" >&2
  exit 2
fi
cd /home/vidar/AI-Intrusion-Detection-System
base=/opt/yggdrasil-sudo-ui-web
if [[ "$(cat "$base/COMMIT")" != "$sha" ]]; then
  echo "STOP: Installed web preview source SHA differs" >&2
  exit 2
fi
git cat-file -e "$sha^{commit}"
for unit in yggdrasil-collector.service yggdrasil-web.service yggdrasil-notifier.service yggdrasil-sudo-shadow.timer yggdrasil-sudo-ui-export.timer; do
  systemctl is-active --quiet "$unit" ||
    { echo "STOP: Expected IDS component inactive: $unit" >&2; exit 2; }
done
sudo /usr/bin/setpriv --reuid=yggdrasil-web --regid=yggdrasil-web --groups=yggdrasil-data \
  /usr/bin/test -r /var/lib/yggdrasil-sudo-public/sudo-status.json ||
  { echo "STOP: Web has no sanitized sudo status" >&2; exit 2; }
if sudo /usr/bin/setpriv --reuid=yggdrasil-web --regid=yggdrasil-web --groups=yggdrasil-data \
  /usr/bin/test -r /var/lib/yggdrasil-sudo-shadow/sudo-shadow.sqlite3; then
  echo "STOP: Web user unexpectedly reads private sudo DB" >&2
  exit 2
fi
if [[ -n "$(systemctl show yggdrasil-web.service -p Environment --value | grep -o 'PYTHONPATH=[^ ]*' || :)" ]]; then
  echo "STOP: Existing web service has a PYTHONPATH override" >&2
  exit 2
fi

dropdir=/etc/systemd/system/yggdrasil-web.service.d
override="$dropdir/50-sudo-dashboard.conf"
if sudo test -e "$override" || sudo test -L "$override"; then
  echo "STOP: Sudo dashboard override already installed" >&2
  exit 2
fi
tmp="$(mktemp -d -t sudo-ui-web-release-XXXXXX)"
backup=""
changed=0
cleanup() {
  status=$?
  if ((status != 0 && changed == 1)); then
    echo "ERROR: Reverting only web service drop-in after failed release" >&2
    sudo rm -f -- "$override" || :
    sudo systemctl daemon-reload || :
    sudo systemctl restart yggdrasil-web.service || :
  fi
  rm -rf -- "$tmp"
}
trap cleanup EXIT

git archive "$sha" src/yggdrasil_ids | tar -xf - -C "$tmp"
if ! diff -qr "$tmp/src/yggdrasil_ids" "$base/src/yggdrasil_ids" >/dev/null; then
  echo "STOP: Staged web source differs from pinned Git commit" >&2
  exit 2
fi

sudo /usr/bin/setpriv --reuid=yggdrasil-web --regid=yggdrasil-web --groups=yggdrasil-data \
  /usr/bin/env PYTHONPATH="$base/src" YGGDRASIL_CONFIG=/etc/yggdrasil-ids/config.toml \
  /opt/yggdrasil-ids/venv/bin/python - <<'PY'
from yggdrasil_ids.config import load_config
from yggdrasil_ids.sudo_dashboard import read_experiment, read_summary
from yggdrasil_ids.web import create_app
cfg = load_config()
assert cfg.web.bind == "127.0.0.1" and cfg.web.port == 8765 and cfg.mode == "live"
assert read_summary()["state"] in {"ready", "stale"}
assert read_experiment()["synthetic_only"] is True
app = create_app(cfg)
assert "/sudo" in {rule.rule for rule in app.url_map.iter_rules()}
assert app.test_client().get("/sudo").status_code == 302
print("PASS: Web-only overlay is compatible with current config and read-only routes")
PY

# Preserve a root-owned copy of original service metadata even though no
# existing unit or Python package files will be modified.
backup="/var/backups/yggdrasil-ids/sprint5-sudo-web-before-$sha"
if sudo test -e "$backup"; then
  echo "STOP: Release backup already exists; inspect, do not overwrite" >&2
  exit 2
fi
sudo install -d -o root -g root -m 0700 "$backup"
sudo cp -a /etc/systemd/system/yggdrasil-web.service "$backup/yggdrasil-web.service"
sudo chmod 0600 "$backup/yggdrasil-web.service"

cat > "$tmp/50-sudo-dashboard.conf" <<'CONF'
[Service]
# Web-only import overlay. Existing virtualenv, collector and notifier untouched.
Environment=PYTHONPATH=/opt/yggdrasil-sudo-ui-web/src
ReadOnlyPaths=/var/lib/yggdrasil-sudo-public
CONF
sudo install -d -o root -g root -m 0755 "$dropdir"
changed=1
sudo install -o root -g root -m 0644 "$tmp/50-sudo-dashboard.conf" "$override"
sudo systemd-analyze verify /etc/systemd/system/yggdrasil-web.service
sudo systemctl daemon-reload
echo "=== Restart only existing private web dashboard ==="
sudo systemctl restart yggdrasil-web.service
systemctl is-active --quiet yggdrasil-web.service
for unit in yggdrasil-collector.service yggdrasil-notifier.service yggdrasil-sudo-shadow.timer yggdrasil-sudo-ui-export.timer; do
  systemctl is-active --quiet "$unit" ||
    { echo "STOP: Existing component lost active state: $unit" >&2; exit 1; }
done

# No credentials are sent. Login must still require authentication.
for attempt in 1 2 3 4 5; do
  if /usr/bin/python3 - <<'PY'
from urllib.request import urlopen
with urlopen("http://127.0.0.1:8765/login", timeout=3) as response:
    assert response.status == 200
    assert b"Yggdrasil" in response.read(8192)
PY
  then
    break
  fi
  if ((attempt == 5)); then
    echo "STOP: Private login page not healthy after web restart" >&2
    exit 1
  fi
  sleep 1
done
echo "PASS: Web-only sudo UI overlay activated; existing services still active"
echo "Production SQLite, SSH/UFW, installed Python venv and Discord: unchanged"
echo "Rollback: bash deploy/sprint5_sudo_ui_web_rollback_pi.sh $sha"
echo "Original unit metadata copy: $backup"
changed=0
