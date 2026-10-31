"""Transactional SQLite persistence; the web process opens read-only connections."""

from __future__ import annotations

import json
import math
import os
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from .domain import Finding, SSHEvent

SCHEMA_VERSION = 1
SCHEMA = """
CREATE TABLE IF NOT EXISTS records (
 id TEXT PRIMARY KEY, cursor TEXT NOT NULL, timestamp REAL NOT NULL,
 status TEXT NOT NULL, reason TEXT NOT NULL, raw_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS records_time ON records(timestamp);
CREATE TABLE IF NOT EXISTS events (
 event_id TEXT PRIMARY KEY, timestamp REAL NOT NULL, source_ip TEXT NOT NULL,
 username TEXT NOT NULL, outcome TEXT NOT NULL CHECK(outcome IN ('success','failure')),
 auth_method TEXT NOT NULL, host TEXT NOT NULL, message TEXT NOT NULL,
 pid TEXT NOT NULL, cursor TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS events_time ON events(timestamp);
CREATE INDEX IF NOT EXISTS events_source_time ON events(source_ip,timestamp);
CREATE TABLE IF NOT EXISTS observations (
 event_id TEXT PRIMARY KEY REFERENCES events(event_id) ON DELETE CASCADE,
 timestamp REAL NOT NULL, source_ip TEXT NOT NULL, features TEXT NOT NULL,
 score REAL, threshold REAL, is_anomaly INTEGER, model_version TEXT, state TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS observations_time ON observations(timestamp);
CREATE TABLE IF NOT EXISTS alerts (
 id INTEGER PRIMARY KEY, detector_id TEXT NOT NULL, title TEXT NOT NULL,
 severity TEXT NOT NULL, reason TEXT NOT NULL, source_ip TEXT NOT NULL,
 first_seen REAL NOT NULL, last_seen REAL NOT NULL, count INTEGER NOT NULL,
 score REAL, model_version TEXT, details TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS alerts_group ON alerts(detector_id,source_ip,last_seen);
CREATE TABLE IF NOT EXISTS findings (
 id INTEGER PRIMARY KEY,
 alert_id INTEGER NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
 event_id TEXT NOT NULL REFERENCES events(event_id) ON DELETE CASCADE,
 timestamp REAL NOT NULL, detector_id TEXT NOT NULL, reason TEXT NOT NULL,
 details TEXT NOT NULL, score REAL, model_version TEXT,
 UNIQUE(event_id,detector_id)
);
CREATE TABLE IF NOT EXISTS state (key TEXT PRIMARY KEY, value TEXT NOT NULL);
"""


def encode(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False)


class Repository:
    def __init__(self, path: Path | str, readonly: bool = False):
        self.path = Path(path).resolve()
        self.readonly = readonly

    def connect(self) -> sqlite3.Connection:
        if self.readonly:
            db = sqlite3.connect(self.path.as_uri() + "?mode=ro", uri=True, timeout=5)
            db.execute("PRAGMA query_only=ON")
        else:
            db = sqlite3.connect(self.path, timeout=5)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys=ON")
        db.execute("PRAGMA busy_timeout=5000")
        return db

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        if self.readonly:
            raise PermissionError("Repository er åbnet skrivebeskyttet")
        db = self.connect()
        try:
            db.execute("BEGIN IMMEDIATE")
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    @contextmanager
    def reader(self) -> Iterator[sqlite3.Connection]:
        db = self.connect()
        try:
            db.execute("BEGIN")
            yield db
        finally:
            db.close()

    def initialize(self) -> None:
        if self.readonly:
            raise PermissionError("Read-only database cannot be initialized")
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
        db = self.connect()
        try:
            version = db.execute("PRAGMA user_version").fetchone()[0]
            if version not in (0, SCHEMA_VERSION):
                raise ValueError(
                    f"Databaseversion {version} understøttes ikke; tag backup før migration"
                )
            # The separate dashboard user cannot create WAL/SHM files. DELETE
            # keeps committed history readable when the collector is stopped.
            db.execute("PRAGMA journal_mode=DELETE")
            db.execute("PRAGMA synchronous=FULL")
            db.executescript(SCHEMA)
            db.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
            db.commit()
        finally:
            db.close()
        self.path.chmod(0o640)

    @staticmethod
    def state_in(db: sqlite3.Connection, key: str, default: Any = None) -> Any:
        row = db.execute("SELECT value FROM state WHERE key=?", (key,)).fetchone()
        return json.loads(row[0]) if row else default

    @staticmethod
    def put_state(db: sqlite3.Connection, key: str, value: Any) -> None:
        db.execute(
            "INSERT INTO state(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, encode(value)),
        )

    def get_state(self, key: str, default: Any = None) -> Any:
        with self.reader() as db:
            return self.state_in(db, key, default)

    def set_state(self, key: str, value: Any) -> None:
        with self.transaction() as db:
            self.put_state(db, key, value)

    @staticmethod
    def insert_event(db: sqlite3.Connection, event: SSHEvent) -> None:
        data = event.to_dict()
        columns = tuple(SSHEvent.__dataclass_fields__)
        db.execute(
            f"INSERT INTO events ({','.join(columns)}) VALUES ({','.join('?' for _ in columns)})",
            tuple(data[c] for c in columns),
        )

    @staticmethod
    def history(db: sqlite3.Connection, event: SSHEvent, seconds: int) -> list[SSHEvent]:
        rows = db.execute(
            "SELECT * FROM events WHERE source_ip=? AND timestamp>? AND timestamp<=? ORDER BY timestamp,event_id LIMIT 10001",
            (event.source_ip, event.timestamp - seconds, event.timestamp),
        ).fetchall()
        if len(rows) > 10000:
            raise ValueError("Observationsvinduet overstiger 10000 hændelser; analyse er pauset")
        return [SSHEvent(**dict(r)) for r in rows]

    @staticmethod
    def add_finding(db: sqlite3.Connection, finding: Finding, cooldown: int) -> int:
        # Findings are unique per event/detector; incidents group repeated findings.
        existing = db.execute(
            "SELECT alert_id FROM findings WHERE event_id=? AND detector_id=?",
            (finding.event_id, finding.detector_id),
        ).fetchone()
        if existing:
            return existing[0]
        row = db.execute(
            "SELECT id FROM alerts WHERE detector_id=? AND source_ip=? AND last_seen>=? AND last_seen<=? AND COALESCE(model_version,'')=COALESCE(?,'') ORDER BY last_seen DESC LIMIT 1",
            (
                finding.detector_id,
                finding.source_ip,
                finding.timestamp - cooldown,
                finding.timestamp,
                finding.model_version,
            ),
        ).fetchone()
        if row:
            alert_id = row[0]
            db.execute(
                "UPDATE alerts SET last_seen=?,count=count+1,reason=?,severity=?,score=?,details=? WHERE id=?",
                (
                    finding.timestamp,
                    finding.reason,
                    finding.severity,
                    finding.score,
                    encode(finding.details),
                    alert_id,
                ),
            )
        else:
            cur = db.execute(
                "INSERT INTO alerts(detector_id,title,severity,reason,source_ip,first_seen,last_seen,count,score,model_version,details) VALUES(?,?,?,?,?,?,?,1,?,?,?)",
                (
                    finding.detector_id,
                    finding.title,
                    finding.severity,
                    finding.reason,
                    finding.source_ip,
                    finding.timestamp,
                    finding.timestamp,
                    finding.score,
                    finding.model_version,
                    encode(finding.details),
                ),
            )
            alert_id = cur.lastrowid
        db.execute(
            "INSERT INTO findings(alert_id,event_id,timestamp,detector_id,reason,details,score,model_version) VALUES(?,?,?,?,?,?,?,?)",
            (
                alert_id,
                finding.event_id,
                finding.timestamp,
                finding.detector_id,
                finding.reason,
                encode(finding.details),
                finding.score,
                finding.model_version,
            ),
        )
        return int(alert_id)

    @staticmethod
    def _decode(row: sqlite3.Row) -> dict:
        value = dict(row)
        for field in ("features", "details"):
            if field in value:
                value[field] = json.loads(value[field])
        if "is_anomaly" in value and value["is_anomaly"] is not None:
            value["is_anomaly"] = bool(value["is_anomaly"])
        return value

    @staticmethod
    def _period(hours: int) -> tuple[float, float]:
        if type(hours) is not int or not 1 <= hours <= 24 * 90:
            raise ValueError("Tidsperiode skal være 1 til 2160 timer")
        now = time.time()
        return now - hours * 3600, now

    def _page(
        self, table: str, where: str, args: list, page: int, per_page: int, order: str
    ) -> dict:
        if (
            type(page) is not int
            or page < 1
            or type(per_page) is not int
            or not 1 <= per_page <= 100
        ):
            raise ValueError("Ugyldig side eller sidestørrelse")
        with self.reader() as db:
            total = db.execute(f"SELECT COUNT(*) FROM {table} WHERE {where}", args).fetchone()[0]
            pages = max(1, math.ceil(total / per_page))
            page = min(page, pages)
            rows = db.execute(
                f"SELECT * FROM {table} WHERE {where} ORDER BY {order} LIMIT ? OFFSET ?",
                [*args, per_page, (page - 1) * per_page],
            ).fetchall()
        return {
            "items": [self._decode(r) for r in rows],
            "total": total,
            "page": page,
            "pages": pages,
        }

    def list_events(
        self,
        hours: int = 24,
        outcome: str = "",
        source: str = "",
        user: str = "",
        page: int = 1,
        per_page: int = 25,
    ) -> dict:
        start, end = self._period(hours)
        where, args = ["timestamp>=?", "timestamp<=?"], [start, end]
        for field, value in (("outcome", outcome), ("source_ip", source), ("username", user)):
            if value:
                where.append(field + "=?")
                args.append(value)
        return self._page(
            "events", " AND ".join(where), args, page, per_page, "timestamp DESC,event_id"
        )

    def list_alerts(
        self, hours: int = 24, detector: str = "", page: int = 1, per_page: int = 25
    ) -> dict:
        start, end = self._period(hours)
        where, args = "last_seen>=? AND last_seen<=?", [start, end]
        if detector:
            where += " AND detector_id=?"
            args.append(detector)
        return self._page("alerts", where, args, page, per_page, "last_seen DESC,id DESC")

    def list_observations(self, hours: int = 24, page: int = 1, per_page: int = 25) -> dict:
        start, end = self._period(hours)
        return self._page(
            "observations",
            "timestamp>=? AND timestamp<=?",
            [start, end],
            page,
            per_page,
            "timestamp DESC,event_id",
        )

    def alert_detail(self, alert_id: int) -> dict | None:
        with self.reader() as db:
            row = db.execute("SELECT * FROM alerts WHERE id=?", (alert_id,)).fetchone()
            if not row:
                return None
            alert = self._decode(row)
            rows = db.execute(
                "SELECT f.*, e.username, e.outcome, e.message FROM findings f LEFT JOIN events e USING(event_id) WHERE f.alert_id=? ORDER BY f.timestamp DESC LIMIT 100",
                (alert_id,),
            ).fetchall()
            alert["findings"] = [self._decode(r) for r in rows]
            alert["findings_truncated"] = alert["count"] > len(rows)
            return alert

    def dashboard(self, hours: int = 24) -> dict:
        start, end = self._period(hours)
        bucket = 300 if hours <= 24 else 3600
        with self.reader() as db:
            counts = dict(
                db.execute(
                    "SELECT outcome,COUNT(*) FROM events WHERE timestamp>=? AND timestamp<=? GROUP BY outcome",
                    (start, end),
                ).fetchall()
            )
            totals = {"success": counts.get("success", 0), "failure": counts.get("failure", 0)}
            totals["events"] = totals["success"] + totals["failure"]
            totals["alerts"] = db.execute(
                "SELECT COUNT(*) FROM alerts WHERE last_seen>=? AND last_seen<=?", (start, end)
            ).fetchone()[0]
            times = db.execute("SELECT MIN(timestamp),MAX(timestamp) FROM events").fetchone()
            series = [
                dict(r)
                for r in db.execute(
                    "SELECT CAST(timestamp/? AS INTEGER)*? AS timestamp, SUM(outcome='success') AS success,SUM(outcome='failure') AS failure FROM events WHERE timestamp>=? AND timestamp<=? GROUP BY 1 ORDER BY 1",
                    (bucket, bucket, start, end),
                )
            ]
            sources = [
                dict(r)
                for r in db.execute(
                    "SELECT source_ip,COUNT(*) AS count,SUM(outcome='failure') AS failure FROM events WHERE timestamp>=? AND timestamp<=? GROUP BY source_ip ORDER BY count DESC LIMIT 6",
                    (start, end),
                )
            ]
            alerts = [
                self._decode(r)
                for r in db.execute(
                    "SELECT * FROM alerts WHERE last_seen>=? AND last_seen<=? ORDER BY last_seen DESC LIMIT 6",
                    (start, end),
                )
            ]
        return {
            "totals": totals,
            "series": series,
            "top_sources": sources,
            "recent_alerts": alerts,
            "last_event_at": times[1],
            "first_event_at": times[0],
        }

    def status(self) -> dict:
        with self.reader() as db:
            state = {r["key"]: json.loads(r["value"]) for r in db.execute("SELECT * FROM state")}
            state["database"] = {
                "state": "ready",
                "schema_version": db.execute("PRAGMA user_version").fetchone()[0],
                "size_bytes": self.size_bytes(),
            }
        return state

    def size_bytes(self) -> int:
        return sum(
            p.stat().st_size for p in (self.path, Path(str(self.path) + "-wal")) if p.exists()
        )

    def prune(self, cutoff: float) -> dict:
        with self.transaction() as db:
            events = db.execute("DELETE FROM events WHERE timestamp<?", (cutoff,)).rowcount
            records = db.execute("DELETE FROM records WHERE timestamp<?", (cutoff,)).rowcount
            db.execute(
                "DELETE FROM alerts WHERE NOT EXISTS(SELECT 1 FROM findings WHERE alert_id=alerts.id)"
            )
            db.execute(
                "UPDATE alerts SET count=(SELECT COUNT(*) FROM findings WHERE alert_id=alerts.id),first_seen=(SELECT MIN(timestamp) FROM findings WHERE alert_id=alerts.id)"
            )
        # Reuse freed pages; avoids blocking a live collector with a full VACUUM.
        return {"events": events, "records": records}

    def backup(self, destination: Path) -> None:
        if destination.resolve() == self.path:
            raise ValueError("Backup skal have en anden sti end databasen")
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
        fd = os.open(destination, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(fd)
        try:
            with self.reader() as db:
                target = sqlite3.connect(destination)
                try:
                    db.backup(target)
                finally:
                    target.close()
        except BaseException:
            destination.unlink(missing_ok=True)
            raise
