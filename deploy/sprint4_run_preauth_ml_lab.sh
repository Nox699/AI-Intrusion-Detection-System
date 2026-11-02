#!/usr/bin/env bash
# Pinned, offline-only preauth Isolation Forest laboratory on Pi.
# Never touches live SQLite, installed model, sshd, UFW, Fail2ban or services.
set -Eeuo pipefail
umask 077

repository="/home/vidar/AI-Intrusion-Detection-System"
venv="/opt/yggdrasil-ids/venv"
branch="sprint-4/preauth-ml-coverage"
work=""
fail() { echo "STOP: $*" >&2; exit 1; }
cleanup() {
  [[ -z "$work" ]] || rm -rf -- "$work"
}
trap cleanup EXIT
[[ "$#" == 1 && "$1" =~ ^[0-9a-f]{40}$ ]] || fail "Use a full pinned CI-approved commit SHA"
[[ "$(id -u)" -ne 0 ]] || fail "Run as your unprivileged Pi account, not root"
sha="$1"
cd "$repository"
git fetch --no-tags origin "$branch"
[[ "$(git rev-parse "origin/$branch")" == "$sha" ]] \
  || fail "Remote preauth branch does not match approved SHA"
git cat-file -e "$sha^{commit}" || fail "Pinned Git commit unavailable"
for service in yggdrasil-collector.service yggdrasil-web.service yggdrasil-notifier.service; do
  systemctl is-active --quiet "$service" || fail "$service must be running"
done
"$venv/bin/python" -m pip check >/dev/null || fail "Installed ML dependencies are unhealthy"
parent="$HOME/yggdrasil-preauth-ml-private"
mkdir -p "$parent"
chmod 0700 "$parent"
work="$(mktemp -d)"
mkdir -m 0700 "$work/source"
# Only trusted pinned source files, not the current checkout, are evaluated.
git archive "$sha" src deploy/sprint4_preauth_signal_audit.py \
  deploy/sprint4_preauth_ml_lab.py | tar -xf - -C "$work/source"
test -f "$work/source/src/yggdrasil_ids/preauth_ml.py" || fail "New preauth schema missing"
test -f "$work/source/deploy/sprint4_preauth_ml_lab.py" || fail "Lab script missing"
output="$(mktemp -d "$parent/preauth-if-XXXXXXXX")"
chmod 0700 "$output"
echo "PASS: Isolated preauth laboratory created; NO production data is read."
PYTHONPATH="$work/source/src:$work/source/deploy" \
  "$venv/bin/python" "$work/source/deploy/sprint4_preauth_ml_lab.py" \
  --directory "$output" || fail "Isolated model evaluation failed; review private lab directory"
for service in yggdrasil-collector.service yggdrasil-web.service yggdrasil-notifier.service; do
  systemctl is-active --quiet "$service" || fail "$service unexpectedly inactive after lab"
done
echo "PASS: Synthetic preauth ML lab completed; all three production IDS services active."
echo "PRIVATE_OUTPUT=$output"
echo "NO_NEW_LIVE_ML_MODEL=true"
