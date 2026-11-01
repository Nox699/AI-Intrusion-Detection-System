"""Independent read-only Discord alarm notifier.

The notifier never reads the journal, mutates the IDS database, or shares raw
log messages or source addresses. It has a private acknowledgement cursor.
A crash between Discord acknowledgement and cursor fsync can cause one repeat;
exactly-once delivery is not guaranteed by webhooks.
"""

from __future__ import annotations

import fcntl
import json
import logging
import math
import os
import re
import sqlite3
import stat
import tempfile
import threading
import time
import urllib.error
import urllib.request
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Callable, Iterator
from urllib.parse import urlsplit
from zoneinfo import ZoneInfo

from .storage import Repository

log = logging.getLogger(__name__)
SEVERITY = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
WEBHOOK_PATH = re.compile(r"/api/webhooks/[0-9]{15,25}/[A-Za-z0-9._-]{20,256}")
MAX_BODY_BYTES = 1024


class NotifyError(RuntimeError):
    """A non-secret operational error."""


class TemporaryNotifyError(NotifyError):
    def __init__(self, message: str, delay: float = 20.0):
        super().__init__(message)
        self.delay = delay


class PermanentNotifyError(NotifyError):
    """A disabled webhook or invalid credentials require manual attention."""


def load_webhook(path: Path) -> str:
    """Accept only a local, private regular file and an official Discord endpoint."""
    if path.is_symlink():
        raise PermanentNotifyError("Webhookfilen må ikke være et symbolsk link")
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o007:
        raise PermanentNotifyError("Webhookfilen skal være privat og almindelig")
    if info.st_size > 1024:
        raise PermanentNotifyError("Webhookfilen er for stor")
    url = path.read_text(encoding="utf-8").strip()
    parts = urlsplit(url)
    if (
        parts.scheme != "https"
        or parts.netloc != "discord.com"
        or parts.query
        or parts.fragment
        or not WEBHOOK_PATH.fullmatch(parts.path)
    ):
        raise PermanentNotifyError("Ugyldigt Discord webhook-endpoint")
    return url


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def send_discord(webhook: str, message: str) -> None:
    """Require Discord's message acknowledgement; never log the secret URL."""
    payload = json.dumps(
        {"content": message[:1900], "allowed_mentions": {"parse": []}},
        ensure_ascii=False,
    ).encode("utf-8")
    request = urllib.request.Request(
        webhook + "?wait=true",
        data=payload,
        headers={"Content-Type": "application/json", "User-Agent": "YggdrasilIDS/0.1"},
        method="POST",
    )
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    try:
        with opener.open(request, timeout=8) as response:
            if response.status != 200:
                raise TemporaryNotifyError("Discord kvitterede ikke for beskeden")
            answer = json.loads(response.read(MAX_BODY_BYTES))
            if not isinstance(answer, dict) or not str(answer.get("id", "")).isdigit():
                raise TemporaryNotifyError("Discord returnerede ingen beskedkvittering")
    except urllib.error.HTTPError as exc:
        if exc.code == 429:
            raw = exc.headers.get("Retry-After", "20")
            try:
                delay = float(raw)
            except ValueError:
                delay = 20.0
            if not math.isfinite(delay):
                delay = 20.0
            raise TemporaryNotifyError(
                "Discord ratebegrænser beskeder", max(1.0, min(delay, 300.0))
            ) from None
        if exc.code in (400, 401, 403, 404):
            raise PermanentNotifyError(
                "Discord afviste webhook-konfigurationen; ret den før ny levering"
            ) from None
        raise TemporaryNotifyError("Discord er midlertidigt utilgængelig") from None
    except (urllib.error.URLError, TimeoutError, OSError):
        raise TemporaryNotifyError("Netværksfejl under Discord-levering") from None
    except (ValueError, TypeError, UnicodeError, json.JSONDecodeError):
        raise TemporaryNotifyError("Ugyldigt Discord-svar") from None


@contextmanager
def notifier_lock(path: Path) -> Iterator[None]:
    """Prevent competing notifier processes from sending the same alert."""
    fd = os.open(str(path) + ".lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise NotifyError("En Discord-notifier kører allerede") from None
        yield
    finally:
        os.close(fd)


class DiscordNotifier:
    def __init__(
        self,
        database: Path,
        webhook_file: Path,
        state_file: Path,
        host: str = "Yggdrasil",
        timezone: str = "Europe/Copenhagen",
        min_severity: str = "medium",
        sender: Callable[[str, str], None] = send_discord,
    ):
        if min_severity not in SEVERITY:
            raise ValueError("Ukendt alarmniveau")
        self.repo = Repository(database, readonly=True)
        self.webhook_file = webhook_file
        self.state_file = state_file
        self.host = host
        self.zone = ZoneInfo(timezone)
        self.min_severity = min_severity
        self.sender = sender

    def _max_id(self) -> int:
        with self.repo.reader() as db:
            return int(db.execute("SELECT COALESCE(MAX(id),0) FROM alerts").fetchone()[0])

    def _state(self) -> dict | None:
        if not self.state_file.exists():
            return None
        if self.state_file.is_symlink():
            raise NotifyError("Notifierstatus må ikke være et symbolsk link")
        info = self.state_file.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
            raise NotifyError("Notifierstatus skal være privat")
        if info.st_size > 4096:
            raise NotifyError("Notifierstatus er for stor")
        data = json.loads(self.state_file.read_text(encoding="utf-8"))
        if (
            not isinstance(data, dict)
            or type(data.get("last_id")) is not int
            or data["last_id"] < 0
            or type(data.get("sent")) is not int
            or data["sent"] < 0
        ):
            raise NotifyError("Ugyldigt notifier-checkpoint")
        return data

    def _write_state(self, state: dict) -> None:
        self.state_file.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        fd, name = tempfile.mkstemp(prefix=".notify-", dir=self.state_file.parent)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(state, handle, ensure_ascii=False)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(name, self.state_file)
            dirfd = os.open(self.state_file.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(dirfd)
            finally:
                os.close(dirfd)
        finally:
            Path(name).unlink(missing_ok=True)

    def _new_alerts(self, last_id: int) -> list[dict]:
        with self.repo.reader() as db:
            rows = db.execute(
                "SELECT id,title,severity,first_seen FROM alerts "
                "WHERE id>? ORDER BY id ASC LIMIT 20",
                (last_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def _message(self, alert: dict) -> str:
        when = datetime.fromtimestamp(alert["first_seen"], self.zone)
        level = alert["severity"]
        title = str(alert["title"])[:120].replace("@", "@\u200b")
        # No IP addresses, usernames, log fragments or local-only dashboard URL.
        return (
            f"🛡️ {self.host} IDS — ny alarm\n"
            f"Alvorlighed: {level}\n"
            f"Type: {title}\n"
            f"Tidspunkt: {when:%d.%m.%Y %H:%M:%S} ({self.zone.key})\n"
            "Se detaljer i det private Yggdrasil-dashboard."
        )

    def run_once(self) -> dict:
        state = self._state()
        if state is None:
            # Opt in only to new alerts; do not flood the channel with history.
            state = {"last_id": self._max_id(), "sent": 0, "last_sent_at": None}
            self._write_state(state)
            log.info("Discord-notifier startet ved alarm-ID %d (ingen historisk replay)", state["last_id"])
            return state

        alerts = self._new_alerts(state["last_id"])
        if not alerts:
            return state
        webhook = None
        for alert in alerts:
            if SEVERITY.get(alert["severity"], -1) >= SEVERITY[self.min_severity]:
                if webhook is None:
                    webhook = load_webhook(self.webhook_file)
                self.sender(webhook, self._message(alert))
                state["sent"] += 1
                state["last_sent_at"] = time.time()
                log.info("Discord-besked kvitteret for alarm-ID %d", alert["id"])
            state["last_id"] = alert["id"]
            self._write_state(state)
        return state

    def test_message(self) -> None:
        self.sender(
            load_webhook(self.webhook_file),
            f"🧪 {self.host} IDS — testbesked. Ingen rigtig sikkerhedsalarm.",
        )

    def loop(self, stop: threading.Event, interval: int = 20) -> None:
        if not 5 <= interval <= 300:
            raise ValueError("Polling skal være mellem 5 og 300 sekunder")
        while not stop.is_set():
            delay = interval
            try:
                self.run_once()
            except PermanentNotifyError:
                log.error("Discord-webhook afvist: kontrollér konfigurationen")
                return
            except TemporaryNotifyError as exc:
                log.warning("%s (nyt forsøg senere)", exc)
                delay = max(interval, exc.delay)
            except (sqlite3.Error, OSError, ValueError, NotifyError) as exc:
                log.warning("Notifier kan ikke læse status eller database: %s", type(exc).__name__)
                delay = max(interval, 60)
            stop.wait(delay)
