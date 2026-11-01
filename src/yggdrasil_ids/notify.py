"""Private, separately privileged Discord alert delivery with durable local state."""

from __future__ import annotations

import fcntl
import json
import logging
import math
import os
import re
import sqlite3
import stat
import threading
import time
import urllib.error
import urllib.request
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from urllib.parse import urlsplit
from zoneinfo import ZoneInfo

from .storage import Repository

log = logging.getLogger(__name__)
LEVELS = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
WEBHOOK = re.compile(r"/api/webhooks/[0-9]{15,25}/[A-Za-z0-9._-]{20,256}")


class DeliveryError(RuntimeError):
    pass


class RetryLater(DeliveryError):
    def __init__(self, delay: float = 30.0):
        self.delay = delay
        super().__init__("Discord midlertidigt utilgængelig")


class InvalidWebhook(DeliveryError):
    pass


def secret_file(path: Path) -> str:
    if path.is_symlink():
        raise InvalidWebhook("Webhookfil er et symbolsk link")
    st = path.stat()
    if not stat.S_ISREG(st.st_mode) or st.st_mode & 0o007 or st.st_size > 1024:
        raise InvalidWebhook("Webhookfil har ugyldige rettigheder eller størrelse")
    value = path.read_text(encoding="utf-8").strip()
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or parsed.netloc not in {"discord.com", "discordapp.com"}
        or parsed.query
        or parsed.fragment
        or not WEBHOOK.fullmatch(parsed.path)
    ):
        raise InvalidWebhook("Ugyldigt webhook-endpoint")
    return value


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def deliver(webhook: str, content: str) -> str:
    body = json.dumps(
        {"content": content, "allowed_mentions": {"parse": []}}, ensure_ascii=False
    ).encode("utf-8")
    request = urllib.request.Request(
        webhook + "?wait=true",
        data=body,
        method="POST",
        headers={"Content-Type": "application/json", "User-Agent": "Yggdrasil-IDS/0.1"},
    )
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    try:
        with opener.open(request, timeout=10) as response:
            if response.status != 200:
                raise RetryLater()
            raw = response.read(65537)
            if len(raw) > 65536:
                raise DeliveryError("Discord-kvittering for stor; levering er usikker")
            reply = json.loads(raw)
            if not isinstance(reply, dict) or not str(reply.get("id", "")).isdigit():
                raise DeliveryError("Discord-kvittering mangler besked-ID")
            return str(reply["id"])
    except urllib.error.HTTPError as exc:
        if exc.code == 429:
            raw = exc.headers.get("Retry-After", "30")
            try:
                delay = float(raw)
            except ValueError:
                delay = 30.0
            if not math.isfinite(delay) or delay <= 0:
                delay = 30.0
            try:
                extra = json.loads(exc.read(4096))
                specified = extra.get("retry_after") if isinstance(extra, dict) else None
                if (
                    isinstance(specified, (int, float))
                    and not isinstance(specified, bool)
                    and math.isfinite(specified)
                ):
                    delay = max(delay, specified)
            except (ValueError, TypeError):
                pass
            raise RetryLater(delay) from None
        if exc.code in {400, 401, 403, 404}:
            raise InvalidWebhook("Webhook afvist; kontrollér Discord-opsætningen") from None
        raise RetryLater() from None
    except (urllib.error.URLError, TimeoutError, OSError):
        raise RetryLater() from None


@contextmanager
def exclusive_notifier(path: Path):
    """Only one process may own the notifier state and perform deliveries."""
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(str(path) + ".lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise DeliveryError("En notifier bruger allerede denne kø") from None
        yield
    finally:
        os.close(fd)


class DiscordNotifier:
    """SQLite outbox reader with a separate per-notifier delivery database."""

    def __init__(
        self,
        database: Path,
        state_path: Path,
        host_label: str = "Yggdrasil",
        zone: str = "Europe/Copenhagen",
        webhook_file: Path | None = None,
        sender=deliver,
    ):
        self.source = Repository(database, readonly=True)
        self.path = Path(state_path)
        self.webhook_file = webhook_file
        self.host = host_label
        self.zone = ZoneInfo(zone)
        self.sender = sender

    def _source(self, after: int | None = None):
        """Return instance, monotonic high watermark and up to 20 events."""
        with self.source.reader() as db:
            row = db.execute("SELECT instance FROM discord_outbox_meta WHERE id=1").fetchone()
            instance = row[0]
            maximum = db.execute("SELECT COALESCE(MAX(seq),0) FROM discord_outbox").fetchone()[0]
            rows = []
            if after is not None:
                rows = [
                    dict(r)
                    for r in db.execute(
                        "SELECT seq,ref,detector_id,severity,happened_at "
                        "FROM discord_outbox WHERE seq>? ORDER BY seq LIMIT 20",
                        (after,),
                    ).fetchall()
                ]
        return instance, maximum, rows

    def _connect(self):
        db = sqlite3.connect(self.path, timeout=5)
        db.execute("PRAGMA busy_timeout=5000")
        return db

    def bootstrap(self):
        """Explicitly skip existing alarms once; never reset on restart."""
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        instance, maximum, _ = self._source()
        with self._connect() as db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS meta(instance TEXT NOT NULL,last_seq INTEGER NOT NULL)"
            )
            db.execute(
                "CREATE TABLE IF NOT EXISTS deliveries("
                "ref TEXT PRIMARY KEY,discord_id TEXT NOT NULL,sent_at REAL NOT NULL)"
            )
            current = db.execute("SELECT instance,last_seq FROM meta").fetchone()
            if current is None:
                last_seq = maximum
                db.execute("INSERT INTO meta VALUES(?,?)", (instance, last_seq))
                log.info("Notifikationer starter efter historisk sekvens %d", last_seq)
            elif current[0] != instance:
                raise DeliveryError("Databasens identitet er ændret; manuel kontrol påkrævet")
            else:
                last_seq = current[1]
        self.path.chmod(0o600)
        return {"last_seq": last_seq}

    def message(self, event):
        label = {
            "ssh.preauth_burst": "Gentagne SSH-afbrud før login",
            "ssh.failed_burst": "Mange fejlede SSH-forsøg",
            "ssh.user_spray": "Forsøg mod flere brugernavne",
            "ssh.unexpected_success": "Uventet SSH-login",
            "ssh.isolation_forest": "Usædvanligt SSH-mønster",
        }.get(event["detector_id"], "Sikkerhedsalarm")
        stamp = datetime.fromtimestamp(event["happened_at"], self.zone)
        return (
            f"🛡️ Yggdrasil IDS — ny alarm\n"
            f"Server: {self.host}\n"
            f"Type: {label}\n"
            f"Niveau: {event['severity']}\n"
            f"Tid: {stamp:%d.%m.%Y %H:%M:%S}\n"
            f"Reference: {event['ref']}\n"
            "Se detaljerne via dit private dashboard."
        )

    def poll(self):
        with self._connect() as db:
            row = db.execute("SELECT instance,last_seq FROM meta").fetchone()
            if row is None:
                raise DeliveryError("Notifieren skal initialiseres med --bootstrap")
            expected_instance, cursor = row
        instance, maximum, events = self._source(cursor)
        if expected_instance != instance:
            raise DeliveryError("Databasens identitet er ændret")
        if maximum < cursor:
            raise DeliveryError("Kildens sekvens er gået baglæns")
        webhook = None
        for event in events:
            if event["seq"] <= cursor:
                continue
            if LEVELS.get(event["severity"], -1) >= LEVELS["medium"]:
                if webhook is None:
                    webhook_path = self.webhook_file
                    if webhook_path is None:
                        folder = os.environ.get("CREDENTIALS_DIRECTORY")
                        if not folder:
                            raise InvalidWebhook("Systemd credential mangler")
                        webhook_path = Path(folder) / "discord-webhook.url"
                    webhook = secret_file(webhook_path)
                discord_id = self.sender(webhook, self.message(event))
            else:
                discord_id = None
            with self._connect() as db:
                if discord_id is not None:
                    db.execute(
                        "INSERT OR IGNORE INTO deliveries(ref,discord_id,sent_at) VALUES(?,?,?)",
                        (event["ref"], discord_id, time.time()),
                    )
                updated = db.execute(
                    "UPDATE meta SET last_seq=? WHERE instance=? AND last_seq=?",
                    (event["seq"], instance, cursor),
                )
                if updated.rowcount != 1:
                    raise DeliveryError("Checkpoint blev ændret samtidig")
            cursor = event["seq"]
        return cursor

    def test(self):
        webhook = self.webhook_file
        if webhook is None:
            folder = os.environ.get("CREDENTIALS_DIRECTORY")
            if not folder:
                raise InvalidWebhook("Systemd credential mangler")
            webhook = Path(folder) / "discord-webhook.url"
        return self.sender(secret_file(webhook), "🧪 Yggdrasil IDS: testbesked, ikke en alarm.")

    def run(self, stop: threading.Event):
        with exclusive_notifier(self.path):
            self.bootstrap()
            while not stop.is_set():
                try:
                    self.poll()
                    stop.wait(20)
                except RetryLater as exc:
                    log.warning("Discord midlertidigt utilgængelig; afventer genforsøg")
                    stop.wait(max(20.0, exc.delay))
                except (InvalidWebhook, DeliveryError, sqlite3.Error):
                    log.error("Notifier er stoppet efter konfigurations-/leveringsfejl")
                    raise
