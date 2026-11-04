"""Explicit local administration commands. No firewall or SSH configuration changes."""

from __future__ import annotations

import argparse
import getpass
import json
import logging
import math
import os
import secrets
import signal
import sqlite3
import sys
import tempfile
import threading
import time
from pathlib import Path

from werkzeug.security import generate_password_hash

from . import __version__
from .config import AppConfig, load_config
from .engine import AnalysisEngine
from .features import FEATURE_NAMES
from .ml import IsolationForestDetector
from .source import CollectorLock, JournalCollector, probe_journal
from .storage import Repository


def write_credentials(path: Path, password: str, replace: bool = False) -> None:
    if not 12 <= len(password) <= 256:
        raise ValueError("Adgangskoden skal være 12 til 256 tegn")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
    data = {
        "password_hash": generate_password_hash(password),
        "secret_key": secrets.token_urlsafe(48),
    }
    fd, temporary = tempfile.mkstemp(prefix=".credentials-", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(data, handle)
            handle.flush()
            os.fsync(handle.fileno())
        if replace:
            os.replace(temporary, path)
        else:
            os.link(temporary, path)  # Atomic create-if-absent; refuses existing credentials.
    finally:
        Path(temporary).unlink(missing_ok=True)


def _json(value: object) -> None:
    print(json.dumps(value, ensure_ascii=False, indent=2, default=str, allow_nan=False))


def serve(config: AppConfig) -> None:
    from gunicorn.app.base import BaseApplication

    from .web import create_app

    application = create_app(config)

    class LocalServer(BaseApplication):
        def load_config(self):
            options = {
                "bind": f"[{config.web.bind}]:{config.web.port}"
                if ":" in config.web.bind
                else f"{config.web.bind}:{config.web.port}",
                "workers": 1,
                "worker_class": "gthread",
                "threads": 4,
                "timeout": 30,
                "accesslog": None,
                "errorlog": "-",
                "limit_request_line": 4094,
                "limit_request_fields": 50,
                "control_socket_disable": True,
                "umask": 0o077,
                "forwarded_allow_ips": "",
            }
            for key, value in options.items():
                self.cfg.set(key, value)

        def load(self):
            return application

    LocalServer().run()


def doctor(
    config: AppConfig, check_journal: bool = False, role: str = "all", require_ready: bool = False
) -> dict:
    if role not in {"all", "collector", "web"}:
        raise ValueError("Ukendt driftsrolle")
    result = {
        "version": __version__,
        "mode": config.mode,
        "role": role,
        "python": sys.version.split()[0],
        "checks": {},
    }
    checks = result["checks"]
    model_metadata = None
    try:
        repo = Repository(config.database_path, readonly=True)
        with repo.reader() as db:
            ok = db.execute("PRAGMA quick_check").fetchone()[0] == "ok"
        checks["database"] = {"ok": ok, "message": "SQLite quick_check"}
        result["status"] = repo.status()
    except (OSError, ValueError, sqlite3.Error) as exc:
        checks["database"] = {"ok": False, "message": str(exc)}
    if role in {"all", "web"}:
        try:
            from .web import create_app

            app = create_app(config)
            checks["web"] = {
                "ok": app is not None,
                "message": "Konfiguration og loginoplysninger kan indlæses",
            }
        except (OSError, ValueError, RuntimeError) as exc:
            checks["web"] = {"ok": False, "message": str(exc)}
    if role in {"all", "collector"}:
        try:
            if config.model_path.exists():
                model = IsolationForestDetector.load(config.model_path)
                if model.metadata["window_seconds"] != config.ml.window_seconds:
                    raise ValueError("Modelvinduet matcher ikke konfigurationen")
                model_metadata = model.metadata
                checks["model"] = {
                    "ok": config.ml.alert_mode == "alert",
                    "message": model.metadata["version"],
                }
            else:
                checks["model"] = {
                    "ok": None,
                    "message": "Ingen model. Regelbaseret overvågning er stadig tilgængelig.",
                }
        except (OSError, ValueError, TypeError) as exc:
            checks["model"] = {"ok": False, "message": str(exc)}
    if check_journal:
        checks["journal"] = probe_journal(config)
    if require_ready:
        status = result.get("status", {})
        collector = status.get("collector", {})
        if not isinstance(collector, dict):
            collector = {}
        heartbeat = collector.get("heartbeat_at")
        current_model = status.get("model", {})
        if not isinstance(current_model, dict):
            current_model = {}
        stored_metadata = current_model.get("metadata", {})
        if not isinstance(stored_metadata, dict):
            stored_metadata = {}
        stored_version = stored_metadata.get("version")
        checks["production"] = {
            "ok": (
                config.mode == "live"
                and config.ml.alert_mode == "alert"
                and status.get("mode") == "live"
                and status.get("namespace") == "live"
                and status.get("database", {}).get("schema_version") == 5
                and current_model.get("state") == "ready"
                and current_model.get("alert_mode") == "alert"
                and isinstance(stored_version, str)
                and (model_metadata is None if role == "web" else model_metadata is not None)
                and (model_metadata is None or model_metadata["version"] == stored_version)
                and config.network.enabled
                and getattr(getattr(config, "sudo", None), "enabled", False)
                and collector.get("state") == "running"
                and type(heartbeat) in (int, float)
                and math.isfinite(heartbeat)
                and 0 <= time.time() - heartbeat <= max(30, 3 * config.collector.heartbeat_seconds)
            ),
            "message": "Samlet drift kræver aktiv SSH-model, netværk, sudo og en frisk collector",
        }
        try:
            from .sudo_integration_dashboard import read_integration

            sudo = read_integration(config.sudo_public_directory / "sudo-integration.json")
            checks["sudo"] = {
                "ok": sudo.get("state") == "ready" and sudo.get("rules_active") is True,
                "message": "Frisk sudo-regelintegration",
            }
        except (OSError, ValueError, TypeError, AttributeError):
            checks["sudo"] = {"ok": False, "message": "Sudo-regelintegrationen er utilgængelig"}
    result["ready"] = require_ready and all(c.get("ok") is True for c in checks.values())
    result["ok"] = all(c.get("ok") is not False for c in checks.values())
    return result


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="yggdrasil-ids", description="Yggdrasil IDS · SSH, portscanning og sudo"
    )
    p.add_argument("--version", action="version", version=__version__)
    commands = p.add_subparsers(dest="command", required=True)
    for name, help_text in [
        ("init", "Opret lokal database"),
        ("credentials", "Opret eller skift dashboardets adgangskode"),
        ("collect", "Læs SSH og UFW fra journalen løbende"),
        ("serve", "Start privat Gunicorn-dashboard"),
        ("doctor", "Kontrollér opsætningen uden at ændre serverindstillinger"),
        ("train", "Træn på udvalgte normale observationer"),
        ("prepare-training", "Beregn observationer fra et gennemgået SSH-JSONL-forløb"),
        ("export-features", "Eksportér gemte observationer fra en udvalgt periode"),
        ("backup", "Tag en konsistent SQLite-backup"),
        ("prune", "Håndhæv retention"),
        ("notify", "Send alarmer fra en separat Discord-tjeneste"),
        ("sudo-arm", "Aktivér sudo-regler fra dette tidspunkt uden historiske alarmer"),
        ("sudo-poll", "Indsaml sudo, registrér regelalarmer og opdatér dashboardet"),
    ]:
        sub = commands.add_parser(name, help=help_text)
        sub.add_argument("--config", type=Path, default=None)
        if name in {"train", "prepare-training"}:
            sub.add_argument("file", type=Path)
        if name == "credentials":
            sub.add_argument(
                "--replace",
                action="store_true",
                help="Udskift eksisterende login og afslut gamle sessioner",
            )
        if name == "notify":
            sub.add_argument("--state-file", type=Path, required=True)
            sub.add_argument("--webhook-file", type=Path)
            sub.add_argument("--status", action="store_true")
            sub.add_argument("--bootstrap", action="store_true")
        if name == "doctor":
            sub.add_argument("--journal", action="store_true")
            sub.add_argument(
                "--require-ready", action="store_true", help="Kræv fuld produktionsparathed"
            )
            sub.add_argument(
                "--role",
                choices=("all", "collector", "web"),
                default="all",
                help="Kontrollér kun de adgangskrav, som denne servicebruger har",
            )
        if name == "train":
            sub.add_argument(
                "--approve-reviewed-normal",
                action="store_true",
                help="Bekræft at alle træningsrækker er gennemgået som normal aktivitet",
            )
            sub.add_argument(
                "--provenance",
                required=True,
                help="Hvorfor dette er et egnet normalt træningsgrundlag",
            )
            sub.add_argument("--replace", action="store_true")
        if name in {"prepare-training", "export-features", "backup"}:
            sub.add_argument("--output", required=True, type=Path)
        if name == "export-features":
            sub.add_argument(
                "--since", required=True, type=float, help="Start som UTC Unix-sekunder"
            )
            sub.add_argument(
                "--until", required=True, type=float, help="Slut som UTC Unix-sekunder"
            )
    return p


def main(argv: list[str] | None = None) -> int:
    os.umask(0o027)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    args = parser().parse_args(argv)
    try:
        config = load_config(args.config)
        if args.command == "init":
            with CollectorLock(config.database_path):
                engine = AnalysisEngine(config)
                engine.heartbeat(
                    "stopped", "Initialiseret. Start collector for løbende overvågning."
                )
            print(
                "Database initialiseret. Opret login med credentials og gennemgå konfigurationen."
            )
        elif args.command == "credentials":
            password = getpass.getpass("Ny dashboard-adgangskode (mindst 12 tegn): ")
            if password != getpass.getpass("Gentag adgangskoden: "):
                raise ValueError("Adgangskoderne er forskellige")
            write_credentials(config.credentials_path, password, args.replace)
            print("Loginoplysninger gemt. Genstart webprocessen ved udskiftning.")
        elif args.command == "collect":
            if config.mode != "live":
                raise ValueError("Collector kræver app.mode='live'")
            stop = threading.Event()
            for sig in (signal.SIGTERM, signal.SIGINT):
                signal.signal(sig, lambda *_: stop.set())
            with CollectorLock(config.database_path):
                engine = AnalysisEngine(config)
                try:
                    JournalCollector(config, engine).run(stop)
                except Exception as exc:
                    engine.heartbeat("error", str(exc)[:500])
                    raise
        elif args.command == "serve":
            serve(config)
        elif args.command == "doctor":
            report = doctor(config, args.journal, args.role, args.require_ready)
            _json(report)
            return 0 if report["ok"] else 1
        elif args.command == "train":
            if not args.approve_reviewed_normal:
                raise ValueError(
                    "Træning kræver --approve-reviewed-normal efter gennemgang af normaldata"
                )
            if config.model_path.exists() and not args.replace:
                raise FileExistsError(
                    "Modellen findes allerede. Brug --replace efter gennemgang af det nye datagrundlag."
                )
            if args.file.stat().st_size > 8 * 1024 * 1024:
                raise ValueError("Træningsfilen er for stor")
            data = json.loads(args.file.read_text(encoding="utf-8"))
            if (
                not isinstance(data, dict)
                or data.get("feature_names") != list(FEATURE_NAMES)
                or data.get("window_seconds") != config.ml.window_seconds
            ):
                raise ValueError("Træningsfilens featuredefinition eller tidsvindue matcher ikke")
            model = IsolationForestDetector.train(data["rows"], config.ml, args.provenance)
            model.save(config.model_path)
            _json(model.metadata)
            print("Genstart collector for bevidst aktivering af den nye model.")
        elif args.command == "prepare-training":
            from .training import prepare_rows

            rows = prepare_rows(args.file, config.ml.window_seconds)
            args.output.parent.mkdir(parents=True, exist_ok=True)
            with args.output.open("x", encoding="utf-8") as handle:
                json.dump(
                    {
                        "feature_names": list(FEATURE_NAMES),
                        "window_seconds": config.ml.window_seconds,
                        "rows": rows,
                    },
                    handle,
                )
            print(f"{len(rows)} observationer gemt. Gennemgå datagrundlaget før train.")
        elif args.command == "export-features":
            if (
                not math.isfinite(args.since)
                or not math.isfinite(args.until)
                or not 0 <= args.since < args.until
            ):
                raise ValueError("--since skal være før --until")
            repo = Repository(config.database_path, readonly=True)
            with repo.reader() as db:
                rows = db.execute(
                    "SELECT features FROM observations WHERE timestamp>=? AND timestamp<? AND state!='late' ORDER BY timestamp,event_id LIMIT 10001",
                    (args.since, args.until),
                ).fetchall()
            if len(rows) > 10000:
                raise ValueError("Vælg en kortere periode; højst 10000 observationer")
            matrix = [[json.loads(row[0])[name] for name in FEATURE_NAMES] for row in rows]
            args.output.parent.mkdir(parents=True, exist_ok=True)
            with args.output.open("x", encoding="utf-8") as handle:
                json.dump(
                    {
                        "feature_names": list(FEATURE_NAMES),
                        "window_seconds": config.ml.window_seconds,
                        "rows": matrix,
                        "range": [args.since, args.until],
                    },
                    handle,
                )
            print(
                f"{len(matrix)} observationer eksporteret. Udvælg normaldata; brug andre forløb til test."
            )
        elif args.command == "backup":
            Repository(config.database_path, readonly=True).backup(args.output)
            print("Backup oprettet.")
        elif args.command == "notify":
            from .notify import DiscordNotifier

            notifier = DiscordNotifier(
                database=config.database_path,
                state_path=args.state_file,
                host_label=config.host_label,
                zone=config.timezone,
                webhook_file=args.webhook_file,
            )
            if args.status:
                _json(notifier.status())
            elif args.bootstrap:
                _json(notifier.bootstrap())
            else:
                stop = threading.Event()
                for sig in (signal.SIGTERM, signal.SIGINT):
                    signal.signal(sig, lambda *_: stop.set())
                notifier.run(stop)
        elif args.command == "sudo-arm":
            from .sudo_service import arm

            _json(arm(config))
        elif args.command == "sudo-poll":
            from .sudo_service import run_once

            _json(run_once(config))
        elif args.command == "prune":
            with CollectorLock(config.database_path):
                _json(
                    Repository(config.database_path).prune(
                        time.time() - config.retention_days * 86400
                    )
                )
        return 0
    except (OSError, ValueError, TypeError, KeyError, RuntimeError, sqlite3.Error) as exc:
        print(f"Fejl: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
