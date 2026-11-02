#!/usr/bin/env bash
# Ephemeral loopback-only trained AI demo. Does NOT touch the live Pi IDS.
set -Eeuo pipefail
umask 077

repo="/home/vidar/AI-Intrusion-Detection-System"
cli="/opt/yggdrasil-ids/venv/bin/yggdrasil-ids"
py="/opt/yggdrasil-ids/venv/bin/python"
port="8766"
stop() { echo "STOP: $*" >&2; exit 1; }

[[ $# == 1 && "$1" =~ ^[0-9a-f]{40}$ ]] || stop "Angiv den fulde CI-godkendte Sprint 4 SHA."
[[ "$(id -u)" -ne 0 ]] || stop "Kør som vidar, ikke root."
sha="$1"
cd "$repo"
git fetch --no-tags origin sprint-4/ml-evaluation
[[ "$(git rev-parse origin/sprint-4/ml-evaluation)" == "$sha" ]] \
  || stop "Fjernbranchen matcher ikke den valgte SHA."
git cat-file -e "$sha^{commit}"
[[ -x "$cli" && -x "$py" ]] || stop "Den installerede Yggdrasil IDS Python/CLI mangler."
for service in yggdrasil-collector.service yggdrasil-web.service yggdrasil-notifier.service; do
  systemctl is-active --quiet "$service" || stop "$service er ikke aktiv."
done
"$py" - "$port" <<'PY'
import socket
import sys
with socket.socket() as client:
    client.bind(("127.0.0.1", int(sys.argv[1])))
print("PASS: Demo-porten er ledig på loopback")
PY

demo="$(mktemp -d -p "$HOME" yggdrasil-ml-demo-XXXXXXXX)"
echo "=== Opretter separat syntetisk model og database ==="
demo_result="$("$cli" demo --directory "$demo")" || stop "Kunne ikke oprette isoleret demo."
# The standard demo CLI prints a default port 8765 URL before our explicit
# port override. Suppress that misleading URL to avoid opening production.
printf '%s\n' "$demo_result" | "$py" -c '
import json
import sys

result = json.load(sys.stdin)
assert result["mode"] == "demo"
assert result["evaluation"]["events"] > 0
print("PASS: Separate synthetic lab database and model generated.")
print("SYNTHETIC_TEST_EVENTS=" + str(result["evaluation"]["events"]))
' || stop "Demoens metadata kunne ikke verificeres."
cat >> "$demo/config.toml" <<'TOML'

[web]
bind = "127.0.0.1"
port = 8766
TOML
"$py" - "$demo/config.toml" <<'PY'
import sqlite3
import sys
from pathlib import Path
from yggdrasil_ids.config import load_config
cfg = load_config(Path(sys.argv[1]))
assert cfg.mode == "demo"
assert cfg.web.bind == "127.0.0.1" and cfg.web.port == 8766
assert cfg.database_path.is_file() and cfg.model_path.is_file()
with sqlite3.connect(cfg.database_path.as_uri() + "?mode=ro", uri=True) as db:
    state = db.execute(
        "SELECT value FROM state WHERE key='model'"
    ).fetchone()[0]
    import json
    assert json.loads(state)["state"] == "ready"
    count = db.execute(
        "SELECT COUNT(*) FROM observations WHERE state='scored'"
    ).fetchone()[0]
    assert count > 0
print(f"PASS: Isoleret demo-model trained/ready med {count} scorede SSH-hændelser.")
PY

echo "=== Kun SYNTHETISK demo; intet produktions-IDS er ændret ==="
echo "DEMO_DIR=$demo"
echo "DEMO_URL=http://127.0.0.1:8766/model"
echo "DEMO_LOGIN=demo-yggdrasil (offentligt kendt LAB-adgangskode)"
echo "Opret SSH-tunnel fra laptop: ssh -N -L 8766:127.0.0.1:8766 homelab"
echo "Tryk Ctrl+C i denne Pi-terminal for at stoppe demo-webserveren."
exec "$cli" serve --config "$demo/config.toml"
