#!/usr/bin/env bash
# Stage the UI source for authenticated port-8766 preview.
# No pip install, DB/schema migration, systemd modification, port opening, or restarts.
set -Eeuo pipefail
umask 077
sha="${1:-}"
if [[ ! "$sha" =~ ^[0-9a-f]{40}$ ||
      "$(hostname)" != "yggdrasil" || "$(id -un)" != "vidar" ]]; then
  echo "STOP: Run as vidar on Yggdrasil with approved Git SHA" >&2
  exit 2
fi
cd /home/vidar/AI-Intrusion-Detection-System
git fetch --no-tags origin integration/sprint5-sudo-clean
if [[ "$(git rev-parse origin/integration/sprint5-sudo-clean)" != "$sha" ]]; then
  echo "STOP: Branch changed; review new SHA before staging" >&2
  exit 2
fi
for unit in yggdrasil-collector.service yggdrasil-web.service yggdrasil-notifier.service yggdrasil-sudo-shadow.timer yggdrasil-sudo-ui-export.timer; do
  systemctl is-active --quiet "$unit" ||
    { echo "STOP: Existing service inactive: $unit" >&2; exit 2; }
done
base=/opt/yggdrasil-sudo-ui-web
if sudo test -e "$base" || sudo test -L "$base"; then
  echo "STOP: An existing sudo web preview is staged; review before replacing" >&2
  exit 2
fi
python3 - <<'PY'
import socket
with socket.socket() as s:
    try:
        s.bind(("127.0.0.1", 8766))
    except OSError as exc:
        raise SystemExit(f"STOP: Preview port 8766 is busy: {type(exc).__name__}")
PY

temporary="$(mktemp -d -t sudo-ui-web-stage-XXXXXX)"
staged=0
cleanup() {
  status=$?
  if ((status != 0 && staged == 1)); then
    sudo rm -rf -- "$base"
  fi
  rm -rf -- "$temporary"
}
trap cleanup EXIT

git archive "$sha" src/yggdrasil_ids | tar -xf - -C "$temporary"
test -f "$temporary/src/yggdrasil_ids/templates/sudo.html"
test -f "$temporary/src/yggdrasil_ids/sudo_benchmark.json"
test -f "$temporary/src/yggdrasil_ids/sudo_dashboard.py"

staged=1
sudo install -d -o root -g root -m 0755 "$base"
sudo cp -a "$temporary/src" "$base/src"
sudo chown -R root:root "$base/src"
sudo chmod -R a+rX "$base/src"
printf '%s\n' "$sha" > "$temporary/COMMIT"
sudo install -o root -g root -m 0644 "$temporary/COMMIT" "$base/COMMIT"

echo "=== Validate preview code as unprivileged yggdrasil-web ==="
sudo -u yggdrasil-web env \
  PYTHONPATH="$base/src" \
  YGGDRASIL_CONFIG=/etc/yggdrasil-ids/config.toml \
  /opt/yggdrasil-ids/venv/bin/python - <<'PY'
from yggdrasil_ids.config import load_config
from yggdrasil_ids.sudo_dashboard import read_experiment, read_summary
from yggdrasil_ids.web import create_app

cfg = load_config()
assert cfg.web.bind == "127.0.0.1" and cfg.web.port == 8765
assert cfg.mode == "live"
report = read_experiment()
assert not report.get("unavailable")
assert report["synthetic_only"] is True
status = read_summary()
assert status["state"] in {"ready", "stale"}
app = create_app(cfg)
assert "/sudo" in {rule.rule for rule in app.url_map.iter_rules()}
client = app.test_client()
assert client.get("/sudo").status_code == 302  # no login bypass
assert client.get("/api/status").status_code == 401
print("PASS: Sudo UI preview imports as web-only user, protected and isolated")
print("Sudo summary state:", status["state"])
print("Synthetic model:", report["model_version"])
PY

echo "PASS: UI source staged at /opt/yggdrasil-sudo-ui-web (not installed)"
echo "Next: run the separate port-8766 preview before changing the production web service"
staged=0
