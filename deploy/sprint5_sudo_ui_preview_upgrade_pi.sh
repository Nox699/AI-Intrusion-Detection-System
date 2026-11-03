#!/usr/bin/env bash
# Replace ONLY the stopped, previously staged port-8766 preview sources.
# Preserve a root-owned snapshot, never touch the running web unit or pip.
set -Eeuo pipefail
umask 077

sha="$1"
old="56c4d4a54c6a1c4a2467a526691a50b7706b1df4"
if [[ ! "$sha" =~ ^[0-9a-f]{40}$ ||
      "$(hostname)" != "yggdrasil" || "$(id -un)" != "vidar" ]]; then
  echo "STOP: Run as vidar on Yggdrasil with reviewed full SHA" >&2
  exit 2
fi
cd /home/vidar/AI-Intrusion-Detection-System
git fetch --no-tags origin integration/sprint5-sudo-clean
[[ "$(git rev-parse origin/integration/sprint5-sudo-clean)" == "$sha" ]] ||
  { echo "STOP: Branch differs from pinned commit" >&2; exit 2; }

base=/opt/yggdrasil-sudo-ui-web
backup="/var/backups/yggdrasil-ids/sprint5-sudo-web-preview-before-$sha"
if [[ "$(cat "$base/COMMIT")" != "$old" ]] ||
   sudo test -e "$backup" || sudo test -L "$backup"; then
  echo "STOP: Original preview SHA unexpected or backup exists; do not overwrite" >&2
  exit 2
fi
if sudo test -e /etc/systemd/system/yggdrasil-web.service.d/50-sudo-dashboard.conf; then
  echo "STOP: Production web has already been overlaid; preview upgrade refused" >&2
  exit 2
fi
for unit in yggdrasil-collector.service yggdrasil-web.service yggdrasil-notifier.service yggdrasil-sudo-shadow.timer yggdrasil-sudo-ui-export.timer; do
  systemctl is-active --quiet "$unit" ||
    { echo "STOP: Existing IDS unit inactive: $unit" >&2; exit 2; }
done
/usr/bin/python3 - <<'PY'
import socket
with socket.socket() as s:
    try:
        s.bind(("127.0.0.1", 8766))
    except OSError:
        raise SystemExit("STOP: Old preview port 8766 is busy. Stop it with Ctrl+C first.")
PY

temporary="$(mktemp -d -t sudo-web-preview-upgrade-XXXXXX)"
changed=0
cleanup() {
  result=$?
  if ((result != 0 && changed == 1)); then
    echo "STOP: Restoring original stopped preview sources after error" >&2
    sudo rm -rf -- "$base/src" || :
    sudo cp -a "$backup/src" "$base/src" || :
    sudo install -o root -g root -m 0644 "$backup/COMMIT" "$base/COMMIT" || :
  fi
  rm -rf -- "$temporary"
}
trap cleanup EXIT

git archive "$old" src/yggdrasil_ids | tar -xf - -C "$temporary"
if ! sudo diff -qr "$temporary/src/yggdrasil_ids" "$base/src/yggdrasil_ids" >/dev/null; then
  echo "STOP: Old preview sources changed since staging; inspect before upgrading" >&2
  exit 2
fi
rm -rf -- "$temporary/src"
git archive "$sha" src/yggdrasil_ids | tar -xf - -C "$temporary"
test -f "$temporary/src/yggdrasil_ids/templates/sudo.html"
test -f "$temporary/src/yggdrasil_ids/sudo_dashboard.py"
test -f "$temporary/src/yggdrasil_ids/sudo_benchmark.json"

sudo install -d -o root -g root -m 0700 "$backup"
sudo cp -a "$base/src" "$backup/src"
sudo install -o root -g root -m 0600 "$base/COMMIT" "$backup/COMMIT"
changed=1

sudo rm -rf -- "$base/src"
sudo cp -a "$temporary/src" "$base/src"
sudo chown -R root:root "$base/src"
sudo chmod -R a+rX "$base/src"
printf '%s\n' "$sha" > "$temporary/COMMIT"
sudo install -o root -g root -m 0644 "$temporary/COMMIT" "$base/COMMIT"

sudo /usr/bin/setpriv --reuid=yggdrasil-web --regid=yggdrasil-web --groups=yggdrasil-data \
  /usr/bin/env PYTHONPATH="$base/src" YGGDRASIL_CONFIG=/etc/yggdrasil-ids/config.toml \
  /opt/yggdrasil-ids/venv/bin/python - <<'PY'
from yggdrasil_ids.config import load_config
from yggdrasil_ids.sudo_dashboard import read_activity, read_summary
from yggdrasil_ids.web import create_app

assert read_summary()["state"] in {"ready", "stale"}
assert read_activity()["state"] in {"ready", "stale"}
config = load_config()
assert config.mode == "live" and config.web.port == 8765
app = create_app(config)
assert app.test_client().get("/sudo").status_code == 302
assert app.test_client().get("/api/nav-alerts").status_code == 401
assert "/sudo" in {rule.rule for rule in app.url_map.iter_rules()}
print("PASS: Revised sudo UI imports with existing web-only permissions")
PY
for unit in yggdrasil-collector.service yggdrasil-web.service yggdrasil-notifier.service yggdrasil-sudo-shadow.timer yggdrasil-sudo-ui-export.timer; do
  systemctl is-active --quiet "$unit" ||
    { echo "STOP: IDS service changed state: $unit" >&2; exit 1; }
done
echo "PASS: New Sudo preview code staged; web port 8765 and all IDS services unchanged"
echo "Previous preview saved privately: $backup"
changed=0
