"""Bounded journalctl reader with checkpoints and a single-writer process lock."""

from __future__ import annotations

import fcntl
import json
import logging
import os
import selectors
import subprocess
import threading
import time
from contextlib import AbstractContextManager
from pathlib import Path

from .config import AppConfig
from .engine import AnalysisEngine

FIELDS = "MESSAGE,_COMM,_UID,_PID,_HOSTNAME,_SYSTEMD_UNIT,SYSLOG_IDENTIFIER,__CURSOR,__REALTIME_TIMESTAMP,_BOOT_ID,_TRANSPORT"
log = logging.getLogger(__name__)


class CollectorLock(AbstractContextManager):
    def __init__(self, database: Path):
        self.path = Path(str(database) + ".lock")
        self.file = None

    def __enter__(self):
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
        fd = os.open(self.path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o640)
        self.file = os.fdopen(fd, "a+")
        try:
            fcntl.flock(self.file, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            self.file.close()
            raise RuntimeError(
                "En collector eller genafspilning bruger allerede denne database"
            ) from exc
        return self

    def __exit__(self, exc_type, exc, tb):
        if self.file is not None:
            self.file.close()


def probe_journal(config: AppConfig) -> dict:
    result = subprocess.run(
        [
            config.collector.executable,
            "--system",
            "--no-pager",
            "--output=json",
            "--output-fields=__CURSOR",
            "--lines=1",
        ],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
        env={**os.environ, "LC_ALL": "C", "SYSTEMD_COLORS": "0"},
    )
    if (
        result.returncode
        or not result.stdout.strip()
        or "permission" in result.stderr.lower()
        or "not seeing messages" in result.stderr.lower()
    ):
        return {
            "ok": False,
            "message": "Systemjournalen kan ikke læses. Kontrollér journaladgang for collector-brugeren.",
            "detail": result.stderr.strip()[:500],
        }
    try:
        record = json.loads(result.stdout.splitlines()[0])
        if not isinstance(record.get("__CURSOR"), str) or not record["__CURSOR"].strip():
            raise ValueError
    except (ValueError, AttributeError, IndexError):
        return {"ok": False, "message": "Systemjournalens JSON-output kunne ikke verificeres."}
    return {
        "ok": True,
        "message": "Adgang til systemjournalen verificeret; SSH-dækning kontrolleres med et rigtigt login.",
    }


class JournalCollector:
    def __init__(self, config: AppConfig, engine: AnalysisEngine):
        if config.mode != "live":
            raise ValueError("Collector kræver app.mode='live'")
        self.config = config
        self.engine = engine

    def command(self, cursor: str | None = None, since: float | None = None) -> list[str]:
        cmd = [
            self.config.collector.executable,
            "--system",
            "--no-pager",
            "--output=json",
            "--all",
            "--follow",
            "--no-tail",
            "--output-fields=" + FIELDS,
        ]
        if cursor:
            cmd.append("--after-cursor=" + cursor)
        elif since is not None:
            cmd.append(f"--since=@{since:.6f}")
        else:
            cmd.append(f"--since=-{self.config.collector.initial_history_hours}h")
        matches = ["_COMM=sshd", "_COMM=sshd-session", "_COMM=sshd-auth", "_UID=0"]
        if self.config.network.enabled:
            # The "+" separates OR groups. The SSH group retains its UID guard.
            matches.extend(["+", "_TRANSPORT=kernel"])
        return cmd + matches

    def _cursor_exists(self, cursor: str) -> bool:
        # +1 requests the FIRST item at the cursor, not the latest journal item.
        result = subprocess.run(
            [
                self.config.collector.executable,
                "--system",
                "--no-pager",
                "--output=json",
                "--output-fields=__CURSOR",
                "--cursor=" + cursor,
                "--lines=+1",
            ],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
            env={**os.environ, "LC_ALL": "C", "SYSTEMD_COLORS": "0"},
        )
        if result.returncode:
            return False
        try:
            return json.loads(result.stdout.splitlines()[0]).get("__CURSOR") == cursor
        except (ValueError, AttributeError, IndexError):
            return False

    def run(self, stop: threading.Event | None = None) -> None:
        stop = stop or threading.Event()
        self.engine.heartbeat("starting", "Kontrollerer adgang til systemjournalen")
        probe = probe_journal(self.config)
        if not probe["ok"]:
            self.engine.heartbeat("error", probe["message"])
            raise PermissionError(probe["message"])
        cursor = self.engine.repository.get_state("cursor")
        since = None
        if cursor and not self._cursor_exists(cursor):
            previous = self.engine.repository.get_state("cursor_timestamp", time.time())
            since = max(
                0, previous - max(self.config.rules.window_seconds, self.config.ml.window_seconds)
            )
            self.engine.data_gap(
                "Den gemte journalposition findes ikke længere. Genoptaget fra seneste tidspunkt med overlap; manglende historik kan ikke genskabes."
            )
            cursor = None
        child = subprocess.Popen(
            self.command(cursor, since),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=0,
            env={**os.environ, "LC_ALL": "C", "SYSTEMD_COLORS": "0"},
        )
        selector = selectors.DefaultSelector()
        assert child.stdout is not None and child.stderr is not None
        selector.register(child.stdout, selectors.EVENT_READ, "stdout")
        selector.register(child.stderr, selectors.EVENT_READ, "stderr")
        buffer, errors = b"", b""
        dropping = False
        last_heartbeat = 0.0
        last_prune = time.monotonic()
        limit = self.config.collector.max_record_bytes
        failed = False
        try:
            while not stop.is_set():
                for key, _ in selector.select(timeout=1):
                    chunk = os.read(key.fileobj.fileno(), 65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    if key.data == "stderr":
                        errors = (errors + chunk)[-4096:]
                        continue
                    buffer += chunk
                    while b"\n" in buffer:
                        line, buffer = buffer.split(b"\n", 1)
                        if dropping:
                            dropping = False
                            continue
                        if len(line) > limit:
                            self.engine.invalid_line("Journalpost overskred størrelsesgrænsen")
                            continue
                        try:
                            record = json.loads(line)
                        except (ValueError, UnicodeDecodeError, RecursionError):
                            self.engine.invalid_line("Ugyldig JSON fra journalctl")
                            continue
                        self.engine.process(record)
                    if len(buffer) > limit:
                        buffer = b""
                        if not dropping:
                            self.engine.invalid_line("Journalpost overskred størrelsesgrænsen")
                        dropping = True
                clock = time.monotonic()
                if clock - last_heartbeat >= self.config.collector.heartbeat_seconds:
                    if (
                        self.engine.repository.size_bytes()
                        > self.config.max_database_mb * 1024 * 1024
                    ):
                        raise RuntimeError(
                            "Databasens lagerbudget er overskredet; kontrollér retention og diskforbrug"
                        )
                    self.engine.heartbeat(
                        "running",
                        "Læser SSH og UFW fra systemjournalen"
                        if self.config.network.enabled
                        else "Læser SSH-hændelser fra systemjournalen",
                    )
                    last_heartbeat = clock
                if clock - last_prune >= 3600:
                    self.engine.repository.prune(time.time() - self.config.retention_days * 86400)
                    last_prune = clock
                if child.poll() is not None and not selector.get_map():
                    detail = errors.decode("utf-8", errors="replace").strip()[:500]
                    raise RuntimeError(f"journalctl stoppede (kode {child.returncode}). {detail}")
        except BaseException as exc:
            failed = True
            try:
                self.engine.heartbeat("error", "Indsamling stoppet: " + str(exc)[:450])
            except Exception:
                log.error("Collectorens fejlstatus kunne ikke gemmes")
            raise
        finally:
            selector.close()
            if child.poll() is None:
                child.terminate()
                try:
                    child.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait(timeout=3)
            child.stdout.close()
            child.stderr.close()
            if not failed:
                self.engine.heartbeat("stopped", "Collector er stoppet")
