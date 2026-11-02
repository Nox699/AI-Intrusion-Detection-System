#!/usr/bin/env bash
# Reproducible synthetic SSH ML experiment only. Never installs a production model.
set -Eeuo pipefail
umask 077

repo="/home/vidar/AI-Intrusion-Detection-System"
cli="/opt/yggdrasil-ids/venv/bin/yggdrasil-ids"
lab=""
temp=""
stop() { echo "STOP: $*" >&2; exit 1; }
on_exit() {
  code=$?
  [[ -z "$temp" ]] || rm -f -- "$temp"
  if ((code != 0)); then
    echo "Laboratoriet blev afbrudt; ingen produktionskonfiguration er ændret." >&2
    [[ -z "$lab" ]] || echo "Undersøg den private LAB_DIR: $lab" >&2
  fi
}
trap on_exit EXIT
[[ $# == 1 && "$1" =~ ^[0-9a-f]{40}$ ]] || stop "Angiv fuld, CI-godkendt SHA på sprint-4/ml-evaluation."
[[ "$(id -u)" -ne 0 ]] || stop "Kør som vidar, ikke root."
sha="$1"
[[ -x "$cli" ]] || stop "Yggdrasil IDS CLI mangler."
cd "$repo"
git fetch --no-tags origin sprint-4/ml-evaluation
[[ "$(git rev-parse origin/sprint-4/ml-evaluation)" == "$sha" ]] \
  || stop "Sprint 4-branchen matcher ikke den godkendte SHA."
git cat-file -e "$sha^{commit}"

echo "=== Før: IDS-services ==="
for service in yggdrasil-collector.service yggdrasil-web.service yggdrasil-notifier.service; do
  systemctl is-active --quiet "$service" || stop "$service er ikke aktiv."
  echo "$service: active"
done

lab="$(mktemp -d -p "$HOME" yggdrasil-ml-lab-XXXXXXXX)"
echo "LAB_DIR=$lab"
echo "=== Træner og evaluerer kun en isoleret syntetisk model ==="
"$cli" lab --directory "$lab"

temp="$(mktemp)"
git show "$sha:deploy/sprint4_verify_lab.py" > "$temp"
python3 -m py_compile "$temp" || stop "ML-verifikationsscript har syntaksfejl."
echo "=== Verificerer hold-out-splits, hashes og alle confusion-matricer ==="
/opt/yggdrasil-ids/venv/bin/python "$temp" --directory "$lab" \
  || stop "ML-verifikation fejlede."

echo "=== Gennemført syntetisk forsøgsrapport ==="
sed -n '1,35p' "$lab/report.md"
echo "=== Hashes for syntetiske artefakter ==="
sha256sum "$lab/report.json" "$lab/lab-model.json"

echo "=== Efter: IDS-services (ingen restart/installation) ==="
for service in yggdrasil-collector.service yggdrasil-web.service yggdrasil-notifier.service; do
  systemctl is-active --quiet "$service" || stop "$service er ikke aktiv efter lab."
  echo "$service: active"
done
echo "PASS: Kun isoleret labmodel og evalueringsrapport er genereret."
echo "LAB_DIR=$lab"
echo "Gem report.md/report.json/model-identitet som private eksamensbilag."
echo "Flyt IKKE lab-model.json til /var/lib/yggdrasil-ids/model.json."
