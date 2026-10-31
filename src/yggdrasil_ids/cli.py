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


def demo(directory: Path) -> dict:
    from .lab import evaluate_lab, generate_lab

    directory = directory.resolve()
    if directory.exists() and any(directory.iterdir()):
        raise FileExistsError(
            "Demomappen er ikke tom; vælg en ny mappe for at bevare eksisterende data"
        )
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    config_path = directory / "config.toml"
    config_path.write_text(
        """[app]
mode = "demo"
host_label = "Yggdrasil · demonstration"
timezone = "Europe/Copenhagen"
[paths]
database = "events.sqlite3"
model = "lab/lab-model.json"
credentials = "web-secrets.json"
[rules]
expected_sources = ["192.0.2.10/32", "192.0.2.11/32"]
expected_users = ["labuser", "backup"]
""",
        encoding="utf-8",
    )
    cfg = load_config(config_path)
    fixture_paths = generate_lab(directory / "lab")
    report = evaluate_lab(directory / "lab", rules=cfg.rules, ml=cfg.ml)
    write_credentials(cfg.credentials_path, "demo-yggdrasil")
    with CollectorLock(cfg.database_path):
        engine = AnalysisEngine(cfg, namespace="demo")
        engine.replay(Path(fixture_paths["test_path"]))
    return {
        "mode": "demo",
        "config": str(config_path),
        "password": "demo-yggdrasil",
        "url": "http://127.0.0.1:8765",
        "start": f"yggdrasil-ids serve --config {config_path}",
        "evaluation": {
            "events": report["test"]["event_count"],
            "rule_alert_events": report["test"]["rules"]["predicted_positive"],
            "ml_alert_events": report["test"]["ml"]["predicted_positive"],
            "report": str(directory / "lab" / "report.md"),
        },
        "message": "Syntetisk demonstration. Ingen forbindelse til Pi eller SSH-tjeneste.",
    }


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


def doctor(config: AppConfig, check_journal: bool = False, role: str = "all") -> dict:
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
                checks["model"] = {"ok": True, "message": model.metadata["version"]}
            else:
                checks["model"] = {
                    "ok": None,
                    "message": "Ingen model. Regelbaseret overvågning er stadig tilgængelig.",
                }
        except (OSError, ValueError, TypeError) as exc:
            checks["model"] = {"ok": False, "message": str(exc)}
    if check_journal:
        checks["journal"] = probe_journal(config)
    result["ok"] = all(c.get("ok") is not False for c in checks.values())
    return result


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="yggdrasil-ids", description="Yggdrasil IDS · SSH-overvågning")
    p.add_argument("--version", action="version", version=__version__)
    commands = p.add_subparsers(dest="command", required=True)
    for name, help_text in [
        ("init", "Opret lokal database"),
        ("credentials", "Opret eller skift dashboardets adgangskode"),
        ("collect", "Læs SSH-journalen løbende"),
        ("serve", "Start privat Gunicorn-dashboard"),
        ("doctor", "Kontrollér opsætningen uden at ændre serverindstillinger"),
        ("replay", "Genafspil JSONL i en separat demo-database"),
        ("train", "Træn på udvalgte normale observationer"),
        ("prepare-training", "Beregn observationer fra et gennemgået SSH-JSONL-forløb"),
        ("export-features", "Eksportér gemte observationer fra en udvalgt periode"),
        ("backup", "Tag en konsistent SQLite-backup"),
        ("prune", "Håndhæv retention"),
    ]:
        sub = commands.add_parser(name, help=help_text)
        sub.add_argument("--config", type=Path, default=None)
        if name in {"replay", "train", "prepare-training"}:
            sub.add_argument("file", type=Path)
        if name == "credentials":
            sub.add_argument(
                "--replace",
                action="store_true",
                help="Udskift eksisterende login og afslut gamle sessioner",
            )
        if name == "doctor":
            sub.add_argument("--journal", action="store_true")
            sub.add_argument(
                "--role",
                choices=("all", "collector", "web"),
                default="all",
                help="Kontrollér kun de adgangskrav, som denne servicebruger har",
            )
        if name == "train":
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
    d = commands.add_parser("demo", help="Generér isoleret demonstration og målt labrapport")
    d.add_argument("--directory", type=Path, default=Path(".demo"))
    lab = commands.add_parser("lab", help="Kør det reproducerbare laboratorieforsøg")
    lab.add_argument("--directory", type=Path, default=Path(".lab"))
    return p


def main(argv: list[str] | None = None) -> int:
    os.umask(0o027)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    args = parser().parse_args(argv)
    try:
        if args.command == "demo":
            _json(demo(args.directory))
            return 0
        if args.command == "lab":
            from .lab import evaluate_lab

            report = evaluate_lab(args.directory)
            _json(
                {
                    "kind": report["kind"],
                    "report": str(args.directory.resolve() / "report.md"),
                    "details": str(args.directory.resolve() / "report.json"),
                    "test_events": report["test"]["event_count"],
                    "rules": report["test"]["rules"],
                    "ml": report["test"]["ml"],
                }
            )
            return 0
        config = load_config(args.config)
        if args.command == "init":
            with CollectorLock(config.database_path):
                engine = AnalysisEngine(config, "demo" if config.mode == "demo" else "live")
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
            report = doctor(config, args.journal, args.role)
            _json(report)
            return 0 if report["ok"] else 1
        elif args.command == "replay":
            if config.mode != "demo":
                raise ValueError("Genafspilning kræver app.mode='demo' og en separat database")
            with CollectorLock(config.database_path):
                _json(AnalysisEngine(config, namespace="demo").replay(args.file))
        elif args.command == "train":
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
            from .lab import prepare_rows

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
