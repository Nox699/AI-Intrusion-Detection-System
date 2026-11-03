#!/usr/bin/env python3
"""Remove the shadow-model systemd dependency and check the installed sudo pipeline.

Only the reviewed integration unit is replaced. No application source, database,
model, credentials, notifier state or running service is replaced or restarted.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import stat
import subprocess
import tempfile
import time
from pathlib import Path
from urllib.error import URLError
from urllib.request import urlopen

import sudo_integration_deploy as deployment

INTEGRATION_SHA = "9ced7d60ab7b6776af95a12e83596683e04676ae"
WEB_SHA = "614579ca2ab6fb246c363a8a95dc9a15a7135db3"
WEB_CODE = Path("/opt/yggdrasil-nav-unread-web")
OLD_CONDITION = (
    "ConditionPathExists=/var/lib/yggdrasil-sudo-integration-private/mixed_full-model.json\n"
)
OLD_READONLY = (
    "ReadOnlyPaths=/var/lib/yggdrasil-sudo-shadow /var/lib/yggdrasil-sudo-integration-private\n"
)
NEW_READONLY = (
    "# A missing shadow model must not block production rule alarms.\n"
    "ReadOnlyPaths=/var/lib/yggdrasil-sudo-shadow -/var/lib/yggdrasil-sudo-integration-private\n"
)
TIMERS = (
    "yggdrasil-sudo-shadow.timer",
    "yggdrasil-sudo-ui-export.timer",
    deployment.TIMER,
)

# Programs execute as the existing role identities, with the installed source.
# Exceptions and arbitrary child output are never reflected to the terminal.
WORKER_CHECK = """
import hashlib, json, math, sqlite3, time
from contextlib import closing
from pathlib import Path
from yggdrasil_ids.config import load_config
from yggdrasil_ids.storage import Repository
from yggdrasil_ids.sudo_live_bridge import ARM_KEY
from yggdrasil_ids.sudo_live_ml import _private_file
cfg = load_config()
if cfg.mode != 'live' or cfg.database_path != Path('/var/lib/yggdrasil-ids/events.sqlite3'):
    raise RuntimeError('Unexpected live configuration')
with Repository(cfg.database_path, readonly=True).reader() as db:
    if db.execute('PRAGMA user_version').fetchone()[0] != 5:
        raise RuntimeError('Expected schema5')
    for key in ('mode', 'namespace'):
        if Repository.state_in(db, key) != 'live':
            raise RuntimeError('Expected live database')
    activated = Repository.state_in(db, ARM_KEY)
    if type(activated) not in (int, float) or not 1 <= activated <= time.time():
        raise RuntimeError('Missing activation boundary')
    alarms = db.execute('SELECT COUNT(*) FROM sudo_evidence').fetchone()[0]
source = Path('/var/lib/yggdrasil-sudo-shadow/sudo-shadow.sqlite3')
model = Path('/var/lib/yggdrasil-sudo-integration-private/mixed_full-model.json')
_private_file(source, {0o600})
_private_file(model, {0o400, 0o600})
if model.stat().st_size > 5000000 or hashlib.sha256(model.read_bytes()).hexdigest() != MODEL_HASH:
    raise RuntimeError('Frozen model bytes differ')
with closing(sqlite3.connect(source.as_uri()+'?mode=ro', uri=True, timeout=5)) as db:
    db.execute('PRAGMA query_only=ON')
    if db.execute('PRAGMA user_version').fetchone()[0] != 2:
        raise RuntimeError('Unexpected sudo source schema')
    row = db.execute('SELECT last_completed_until FROM shadow_poll_checkpoint WHERE id=1').fetchone()
    if not row or not math.isfinite(row[0]) or not 0 <= time.time()-row[0] <= 180:
        raise RuntimeError('Private sudo checkpoint unavailable')
print(json.dumps({'registered_sudo_evidence': alarms}))
"""

WEB_CHECK = """
import json, os, time
from pathlib import Path
from yggdrasil_ids.config import load_config
from yggdrasil_ids.sudo_dashboard import read_summary, read_activity
from yggdrasil_ids.sudo_integration_dashboard import read_integration
cfg = load_config()
if cfg.mode != 'live' or cfg.web.bind != '127.0.0.1' or cfg.web.port != 8765:
    raise RuntimeError('Unexpected web binding')
for private in ('/var/lib/yggdrasil-sudo-shadow/sudo-shadow.sqlite3',
                '/var/lib/yggdrasil-sudo-integration-private/mixed_full-model.json'):
    if os.access(private, os.R_OK):
        raise RuntimeError('Web can read private sudo data')
summary, activity, current = read_summary(), read_activity(), read_integration()
if summary['state'] != 'ready' or activity['state'] != 'ready':
    raise RuntimeError('Public sudo sensor exports unavailable')
if current['state'] != 'ready' or not current['rules_active']:
    raise RuntimeError('Sudo rule integration unavailable')
ml = current['ml']
if ml['state'] != 'ready' or ml['model_version'] != MODEL_VERSION or ml['threshold'] != THRESHOLD:
    raise RuntimeError('Frozen ML shadow unavailable or changed')
if CHECK_ROUTES:
    from yggdrasil_ids.web import create_app
    client = create_app(cfg).test_client()
    if client.get('/sudo').status_code != 302 or client.get('/api/nav-alerts').status_code != 401:
        raise RuntimeError('Authentication boundary changed')
    with client.session_transaction() as session:
        session['authenticated'] = True
        session['authenticated_at'] = time.time()
    response = client.get('/sudo')
    if response.status_code != 200 or MODEL_VERSION.encode() not in response.data:
        raise RuntimeError('Authenticated sudo view unavailable')
    if client.get('/api/nav-alerts').get_json()['meaning'] != 'browser_unseen_alert_revisions_v1':
        raise RuntimeError('Navigation seen markers unavailable')
print(json.dumps({'generated_at': current['generated_at'],
                  'rules_active': True, 'ml_mode': 'shadow', 'ml_alerts_emitted': False,
                  'model_version': ml['model_version'], 'threshold': ml['threshold']}))
"""

NOTIFIER_CHECK = """
import json, sqlite3
from contextlib import closing
from pathlib import Path
def read(path):
    db = sqlite3.connect(Path(path).as_uri()+'?mode=ro', uri=True, timeout=5)
    db.execute('PRAGMA query_only=ON')
    return db
with closing(read('/var/lib/yggdrasil-ids/events.sqlite3')) as prod, \
     closing(read('/var/lib/yggdrasil-notifier/delivery.sqlite3')) as receipts:
    source = prod.execute('SELECT instance FROM discord_outbox_meta WHERE id=1').fetchone()
    target = receipts.execute('SELECT instance FROM meta').fetchone()
    if not source or not target or source[0] != target[0]:
        raise RuntimeError('Notifier source identity mismatch')
print(json.dumps({'notifier_identity_matches': True}))
"""


def runtime_check() -> None:
    """Refuse an unreviewed installation instead of altering another release."""
    for folder, expected in ((deployment.CODE, INTEGRATION_SHA), (WEB_CODE, WEB_SHA)):
        manifest = folder / "COMMIT"
        if manifest.is_symlink() or manifest.read_text().strip() != expected:
            raise deployment.DeployError(
                "Installed source release differs from reviewed deployment"
            )
    roles = (
        ("yggdrasil-worker", "yggdrasil-data", deployment.CODE),
        ("yggdrasil-web", "yggdrasil-web", WEB_CODE),
        ("yggdrasil-notifier", "yggdrasil-notifier", deployment.CODE),
    )
    for unit, (user, group, source) in zip(deployment.PRODUCTION, roles):
        info = deployment.properties(unit)
        environment = dict(
            item.split("=", 1) for item in shlex.split(info.get("Environment", "")) if "=" in item
        )
        if (
            info.get("ActiveState") != "active"
            or info.get("UnitFileState") != "enabled"
            or info.get("User") != user
            or info.get("Group") != group
            or environment.get("PYTHONPATH") != str(source / "src")
            or environment.get("YGGDRASIL_CONFIG", str(deployment.CONFIG)) != str(deployment.CONFIG)
        ):
            raise deployment.DeployError("Production role needs review: " + unit)
    for timer in TIMERS:
        info = deployment.properties(timer)
        if info.get("ActiveState") != "active" or info.get("UnitFileState") != "enabled":
            raise deployment.DeployError("Sudo timer is not active and enabled: " + timer)
    info = deployment.properties(deployment.SERVICE)
    if (
        info.get("User") != "yggdrasil-worker"
        or info.get("Group") != "yggdrasil-data"
        or info.get("DropInPaths")
    ):
        raise deployment.DeployError("Unexpected sudo integration role or unit override")


def role_check(user: str, code: str, *, routes: bool = False) -> dict:
    source = WEB_CODE if user == "yggdrasil-web" else deployment.CODE
    group = "yggdrasil-data" if user == "yggdrasil-worker" else user
    groups = "yggdrasil-data,systemd-journal" if user == "yggdrasil-worker" else "yggdrasil-data"
    constants = (
        f"MODEL_HASH={deployment.MODEL_HASH!r}; MODEL_VERSION={deployment.MODEL_VERSION!r}; "
        f"THRESHOLD=0.6616139517267046; CHECK_ROUTES={routes!r}\n"
    )
    result = deployment.command(
        [
            "/usr/bin/setpriv",
            f"--reuid={user}",
            f"--regid={group}",
            f"--groups={groups}",
            "/usr/bin/env",
            f"PYTHONPATH={source}/src",
            "PYTHONDONTWRITEBYTECODE=1",
            f"YGGDRASIL_CONFIG={deployment.CONFIG}",
            "OPENBLAS_NUM_THREADS=1",
            "OMP_NUM_THREADS=1",
            deployment.PYTHON,
            "-c",
            constants + code,
        ],
        check=False,
    )
    if result.returncode:
        raise deployment.DeployError("Read-only sudo acceptance failed for " + user)
    return json.loads(result.stdout)


def atomic_unit(path: Path, data: bytes) -> None:
    fd, temporary = tempfile.mkstemp(prefix=".sudo-production-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fchmod(stream.fileno(), 0o644)
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def finish_unit(candidate: Path, sha: str, *, check_only: bool = False) -> bool:
    updated = candidate.read_bytes()
    # Exact two-line runtime change only; refuse other unit edits in this runner.
    if (
        updated.count(NEW_READONLY.encode()) != 1
        or b"Condition" in updated
        or updated.count(b"After=yggdrasil-sudo-shadow.service yggdrasil-collector.service\n") != 1
    ):
        raise deployment.DeployError("Unexpected candidate sudo integration unit")
    old = updated.replace(NEW_READONLY.encode(), OLD_READONLY.encode()).replace(
        b"After=yggdrasil-sudo-shadow.service yggdrasil-collector.service\n",
        b"After=yggdrasil-sudo-shadow.service yggdrasil-collector.service\n"
        + OLD_CONDITION.encode(),
    )
    target = deployment.UNIT_DIR / deployment.SERVICE
    info = target.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o644:
        raise deployment.DeployError("Expected root-owned sudo integration unit")
    current = target.read_bytes()
    if current not in (old, updated):
        raise deployment.DeployError("Installed sudo integration unit changed; inspect it first")
    if check_only and current != updated:
        raise deployment.DeployError("Shadow-model dependency fix has not been installed")
    changed = current != updated
    if changed:
        backup = deployment.BACKUP_ROOT / ("sudo-production-finish-before-" + sha)
        if backup.exists() or backup.is_symlink():
            saved = backup / deployment.SERVICE
            info = backup.lstat()
            if (
                not stat.S_ISDIR(info.st_mode)
                or info.st_uid != 0
                or stat.S_IMODE(info.st_mode) != 0o700
                or saved.is_symlink()
                or saved.read_bytes() != current
            ):
                raise deployment.DeployError("Existing unit backup differs; inspect it first")
        else:
            backup.mkdir(mode=0o700, parents=True, exist_ok=False)
            deployment.write_exclusive(backup / deployment.SERVICE, current, 0o600)
        atomic_unit(target, updated)
    # Reload also recovers the case where a previous invocation was interrupted
    # after atomic replacement but before systemd loaded the new definition.
    if not check_only:
        try:
            deployment.command(["systemctl", "daemon-reload"])
        except BaseException:
            if changed:
                atomic_unit(target, current)
                deployment.command(["systemctl", "daemon-reload"], check=False)
            raise
    conditions = deployment.command(
        ["systemctl", "show", deployment.SERVICE, "--property=Conditions", "--value"]
    ).stdout.strip()
    if conditions:
        raise deployment.DeployError("Effective sudo unit still has a start condition")
    return changed


def verify(*, not_before: float | None = None) -> dict:
    worker = role_check("yggdrasil-worker", WORKER_CHECK)
    notifier = role_check("yggdrasil-notifier", NOTIFIER_CHECK)
    if not_before is not None:
        print(
            "Waiting up to 150 seconds for the normal sudo timer; no forced poll or test alarm.",
            flush=True,
        )
        deadline = time.monotonic() + 150
        next_message = time.monotonic() + 30
        while True:
            try:
                latest = role_check("yggdrasil-web", WEB_CHECK)
                if latest["generated_at"] >= not_before:
                    break
            except deployment.DeployError:
                pass
            if time.monotonic() >= deadline:
                raise deployment.DeployError("No fresh healthy sudo export after unit reload")
            if time.monotonic() >= next_message:
                print(
                    "Still waiting for the existing timer to publish a new healthy snapshot...",
                    flush=True,
                )
                next_message = time.monotonic() + 30
            time.sleep(5)
    web = role_check("yggdrasil-web", WEB_CHECK, routes=True)
    with urlopen("http://127.0.0.1:8765/login", timeout=5) as response:
        if response.status != 200 or b"Yggdrasil" not in response.read(16384):
            raise deployment.DeployError("Production login page unavailable")
    runtime_check()
    return {"status": "ready", **worker, **notifier, **web}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--sha", required=True)
    parser.add_argument("--check-only", action="store_true")
    args = parser.parse_args()
    if os.geteuid() != 0 or not re.fullmatch(r"[0-9a-f]{40}", args.sha):
        raise SystemExit("STOP: Use the pinned Pi wrapper")
    try:
        runtime_check()
        # Check actual role access before touching the reviewed unit.
        role_check("yggdrasil-worker", WORKER_CHECK)
        role_check("yggdrasil-notifier", NOTIFIER_CHECK)
        role_check("yggdrasil-web", WEB_CHECK, routes=True)
        changed = finish_unit(
            args.source / "deploy" / deployment.SERVICE, args.sha, check_only=args.check_only
        )
        report = verify(not_before=None if args.check_only else time.time())
    except (OSError, ValueError, RuntimeError, URLError, subprocess.SubprocessError) as exc:
        if isinstance(exc, deployment.DeployError):
            message = str(exc)
        else:
            message = "Local sudo production check failed; inspect the service state"
        raise SystemExit("STOP: " + message) from None
    print(
        json.dumps(
            {
                "format": "sudo-production-acceptance-v1",
                **report,
                "unit_updated": changed,
                "services_restarted": False,
                "database_migrated": False,
                "new_probe_generated": False,
            },
            indent=2,
        )
    )
    print("PASS: sudo rules active; frozen mixed Isolation Forest in shadow; dashboard port 8765")


if __name__ == "__main__":
    main()
