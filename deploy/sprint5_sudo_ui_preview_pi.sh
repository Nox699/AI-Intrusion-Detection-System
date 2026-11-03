#!/usr/bin/env bash
# Foreground-only private port-8766 preview. Ctrl-C to exit.
# Uses existing read-only web permissions and existing credentials.
set -Eeuo pipefail
sha="${1:-}"
if [[ ! "$sha" =~ ^[0-9a-f]{40}$ ||
      "$(hostname)" != "yggdrasil" || "$(id -un)" != "vidar" ]]; then
  echo "STOP: Run as vidar on Yggdrasil with reviewed SHA" >&2
  exit 2
fi
if [[ "$(cat /opt/yggdrasil-sudo-ui-web/COMMIT)" != "$sha" ]]; then
  echo "STOP: Preview source commit differs from reviewed SHA" >&2
  exit 2
fi
for unit in yggdrasil-collector.service yggdrasil-web.service yggdrasil-notifier.service yggdrasil-sudo-shadow.timer yggdrasil-sudo-ui-export.timer; do
  systemctl is-active --quiet "$unit" ||
    { echo "STOP: Existing service inactive: $unit" >&2; exit 2; }
done
python3 - <<'PY'
import socket
with socket.socket() as s:
    try:
        s.bind(("127.0.0.1", 8766))
    except OSError as exc:
        raise SystemExit(f"STOP: Port 8766 is already in use: {type(exc).__name__}")
PY
echo "=== Preview accessible ONLY via SSH tunnel: localhost:8766 ==="
echo "=== Foreground process; press Ctrl-C to stop. Production dashboard stays at 8765. ==="
exec sudo /usr/bin/setpriv --reuid=yggdrasil-web --regid=yggdrasil-web --groups=yggdrasil-data \
  /usr/bin/env PYTHONPATH=/opt/yggdrasil-sudo-ui-web/src \
  YGGDRASIL_CONFIG=/etc/yggdrasil-ids/config.toml \
  PYTHONUNBUFFERED=1 \
  OMP_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1 \
  /opt/yggdrasil-ids/venv/bin/python -c '
from dataclasses import replace
from yggdrasil_ids.cli import serve
from yggdrasil_ids.config import load_config

cfg = load_config()
if cfg.mode != "live" or cfg.web.bind != "127.0.0.1" or cfg.web.port != 8765:
    raise SystemExit("STOP: Unexpected production web configuration")
serve(replace(cfg, web=replace(cfg.web, port=8766)))
'
