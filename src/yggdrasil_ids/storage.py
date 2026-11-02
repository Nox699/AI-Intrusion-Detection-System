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
from .firewall import FirewallEvent
from .network_rules import NetworkFinding

SCHEMA_VERSION = 4

# Previously ignored trusted journal records remain visible after migration.
# Preauth disconnects are never authentication events, rule inputs or ML features.
PREAUTH_FILTER = """
    timestamp>=? AND timestamp<=? AND status='ignored'
    AND CAST(json_extract(raw_json, '$._UID') AS TEXT)='0'
    AND json_extract(raw_json, '$._COMM') IN ('sshd','sshd-session','sshd-auth')
    AND (
      json_extract(raw_json, '$.MESSAGE') LIKE
        'Connection closed by authenticating user % port % [preauth]'
      OR json_extract(raw_json, '$.MESSAGE') LIKE
        'Connection reset by authenticating user % port % [preauth]'
    )
"""

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
-- Separate packet history: no SSH event, ML or outbox foreign keys.
CREATE TABLE IF NOT EXISTS firewall_events (
 event_id TEXT PRIMARY KEY, namespace TEXT NOT NULL,
 timestamp REAL NOT NULL, cursor TEXT NOT NULL, boot_id TEXT NOT NULL,
 host TEXT NOT NULL, action TEXT NOT NULL, direction TEXT NOT NULL,
 in_interface TEXT NOT NULL, out_interface TEXT NOT NULL,
 source_ip TEXT NOT NULL, destination_ip TEXT NOT NULL,
 ip_version INTEGER NOT NULL, protocol TEXT NOT NULL,
 protocol_number INTEGER NOT NULL, source_port INTEGER,
 destination_port INTEGER, packet_length INTEGER, transport_length INTEGER,
 tcp_flags TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS firewall_events_time ON firewall_events(timestamp);
CREATE INDEX IF NOT EXISTS firewall_events_group
 ON firewall_events(namespace,source_ip,destination_ip,in_interface,timestamp);
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
CREATE TABLE IF NOT EXISTS preauth_disconnects (
 record_id TEXT PRIMARY KEY REFERENCES records(id) ON DELETE CASCADE,
 timestamp REAL NOT NULL, source_ip TEXT NOT NULL,
 kind TEXT NOT NULL CHECK(kind IN ('closed','reset'))
);
CREATE INDEX IF NOT EXISTS preauth_source_time ON preauth_disconnects(source_ip,timestamp);
CREATE TABLE IF NOT EXISTS preauth_evidence (
 record_id TEXT NOT NULL REFERENCES records(id) ON DELETE CASCADE,
 alert_id INTEGER NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
 timestamp REAL NOT NULL, detector_id TEXT NOT NULL,
 reason TEXT NOT NULL, details TEXT NOT NULL,
 PRIMARY KEY (record_id,detector_id)
);
CREATE INDEX IF NOT EXISTS preauth_evidence_alert ON preauth_evidence(alert_id,timestamp);
CREATE TABLE IF NOT EXISTS network_evidence (
 event_id TEXT NOT NULL REFERENCES firewall_events(event_id) ON DELETE CASCADE,
 alert_id INTEGER NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
 timestamp REAL NOT NULL, detector_id TEXT NOT NULL,
 reason TEXT NOT NULL, details TEXT NOT NULL,
 PRIMARY KEY(event_id,detector_id)
);
CREATE INDEX IF NOT EXISTS network_evidence_alert ON network_evidence(alert_id,timestamp);
-- Independent notification identities survive deletion or reuse of alert IDs.
-- Never cascade-delete outbox rows when the alert history is pruned.
CREATE TABLE IF NOT EXISTS discord_outbox (
 seq INTEGER PRIMARY KEY AUTOINCREMENT,
 ref TEXT NOT NULL UNIQUE,
 detector_id TEXT NOT NULL, severity TEXT NOT NULL,
 happened_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS discord_outbox_meta (
 id INTEGER PRIMARY KEY CHECK(id=1), instance TEXT NOT NULL
);
INSERT OR IGNORE INTO discord_outbox_meta(id,instance)
VALUES(1,lower(hex(randomblob(16))));
CREATE TRIGGER IF NOT EXISTS alert_discord_outbox AFTER INSERT ON alerts
BEGIN
 INSERT INTO discord_outbox(ref,detector_id,severity,happened_at)
 VALUES(lower(hex(randomblob(16))),NEW.detector_id,NEW.severity,NEW.first_seen);
END;
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
            if version not in (0, 1, 2, 3, SCHEMA_VERSION):
                raise ValueError(
                    f"Databaseversion {version} understøttes ikke; tag backup før migration"
                )
            # The separate dashboard user cannot create WAL/SHM files. DELETE
            # keeps committed history readable when the collector is stopped.
            db.execute("PRAGMA journal_mode=DELETE")
            db.execute("PRAGMA synchronous=FULL")
            # A single transaction makes upgrades from schema 1 crash-safe.
            # The old authentication tables are untouched; only new tables are added.
            db.executescript(
                "BEGIN IMMEDIATE;\n" + SCHEMA + f"\nPRAGMA user_version={SCHEMA_VERSION};\nCOMMIT;"
            )
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
    def insert_firewall_event(db: sqlite3.Connection, event: FirewallEvent) -> bool:
        """Persist normalized packet metadata, never raw logs or MAC addresses."""
        fields = tuple(FirewallEvent.__dataclass_fields__)
        values = [
            encode(event.tcp_flags) if field == "tcp_flags" else getattr(event, field)
            for field in fields
        ]
        result = db.execute(
            "INSERT OR IGNORE INTO firewall_events ("
            + ",".join(fields)
            + ") VALUES ("
            + ",".join("?" for _ in fields)
            + ")",
            values,
        )
        return result.rowcount == 1

    @staticmethod
    def firewall_history(
        db: sqlite3.Connection, event: FirewallEvent, seconds: int, limit: int = 10000
    ) -> list[FirewallEvent]:
        """Bounded event-time history for one source, destination and sensor."""
        if type(limit) is not int or not 1 <= limit <= 50000:
            raise ValueError("Ugyldig netværkshistorikgrænse")
        rows = db.execute(
            "SELECT * FROM firewall_events WHERE namespace=? AND host=? AND boot_id=? "
            "AND source_ip=? AND destination_ip=? AND in_interface=? "
            "AND timestamp>? AND timestamp<=? ORDER BY timestamp,event_id LIMIT ?",
            (
                event.namespace,
                event.host,
                event.boot_id,
                event.source_ip,
                event.destination_ip,
                event.in_interface,
                event.timestamp - seconds,
                event.timestamp,
                limit + 1,
            ),
        ).fetchall()
        if len(rows) > limit:
            raise ValueError("Netværkshistorikken er for stor til pålidelig analyse")
        return [
            FirewallEvent(**{**dict(row), "tcp_flags": tuple(json.loads(row["tcp_flags"]))})
            for row in rows
        ]

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
    def insert_preauth_disconnect(
        db: sqlite3.Connection, record_id: str, timestamp: float, source_ip: str, kind: str
    ) -> None:
        db.execute(
            "INSERT INTO preauth_disconnects(record_id,timestamp,source_ip,kind) VALUES(?,?,?,?)",
            (record_id, timestamp, source_ip, kind),
        )

    @staticmethod
    def preauth_window_count(
        db: sqlite3.Connection, source_ip: str, timestamp: float, seconds: int
    ) -> int:
        return int(
            db.execute(
                "SELECT COUNT(*) FROM preauth_disconnects "
                "WHERE source_ip=? AND timestamp>? AND timestamp<=?",
                (source_ip, timestamp - seconds, timestamp),
            ).fetchone()[0]
        )

    @staticmethod
    def add_network_alert(db: sqlite3.Connection, finding: NetworkFinding, cooldown: int) -> int:
        """Group by source and sensor/destination. A new alert feeds Discord once."""
        if type(cooldown) is not int or cooldown < 0:
            raise ValueError("Ugyldigt netværksalarm-cooldown")
        previous = db.execute(
            "SELECT alert_id FROM network_evidence WHERE event_id=? AND detector_id=?",
            (finding.event_id, finding.detector_id),
        ).fetchone()
        if previous:
            return int(previous["alert_id"])
        # Never merge different destination hosts, interfaces or sensor boots.
        row = db.execute(
            "SELECT a.id FROM alerts a "
            "JOIN network_evidence ne ON ne.alert_id=a.id "
            "JOIN firewall_events fe ON fe.event_id=ne.event_id "
            "JOIN firewall_events current ON current.event_id=? "
            "WHERE a.detector_id=? AND a.source_ip=? "
            "AND a.last_seen>=? AND a.last_seen<=? "
            "AND fe.namespace=current.namespace AND fe.host=current.host "
            "AND fe.boot_id=current.boot_id "
            "AND fe.destination_ip=current.destination_ip "
            "AND fe.in_interface=current.in_interface "
            "ORDER BY a.last_seen DESC LIMIT 1",
            (
                finding.event_id,
                finding.detector_id,
                finding.source_ip,
                finding.timestamp - cooldown,
                finding.timestamp,
            ),
        ).fetchone()
        details = {
            "destination_ip": finding.destination_ip,
            "in_interface": finding.in_interface,
            "window_seconds": finding.window_seconds,
            "threshold": finding.threshold,
            "distinct_ports": finding.distinct_ports,
            "recorded_packets": finding.recorded_packets,
            "destination_ports": list(finding.destination_ports),
            "evidence_ids": list(finding.evidence_ids),
            "evidence_truncated": finding.evidence_truncated,
        }
        if row:
            alert_id = int(row["id"])
            db.execute(
                "UPDATE alerts SET last_seen=?,count=count+1,reason=?,details=? WHERE id=?",
                (finding.timestamp, finding.reason, encode(details), alert_id),
            )
        else:
            result = db.execute(
                "INSERT INTO alerts(detector_id,title,severity,reason,source_ip,"
                "first_seen,last_seen,count,score,model_version,details) "
                "VALUES(?,?,?,?,?,?,?,1,NULL,NULL,?)",
                (
                    finding.detector_id,
                    finding.title,
                    finding.severity,
                    finding.reason,
                    finding.source_ip,
                    finding.timestamp,
                    finding.timestamp,
                    encode(details),
                ),
            )
            alert_id = int(result.lastrowid)
        db.execute(
            "INSERT INTO network_evidence(event_id,alert_id,timestamp,detector_id,"
            "reason,details) VALUES(?,?,?,?,?,?)",
            (
                finding.event_id,
                alert_id,
                finding.timestamp,
                finding.detector_id,
                finding.reason,
                encode(details),
            ),
        )
        return alert_id

    @staticmethod
    def add_preauth_alert(
        db: sqlite3.Connection,
        *,
        record_id: str,
        timestamp: float,
        source_ip: str,
        observed: int,
        threshold: int,
        window_seconds: int,
        cooldown: int,
    ) -> int:
        """Record one burst finding, retaining source evidence outside events/ML."""
        detector_id = "ssh.preauth_burst"
        existing = db.execute(
            "SELECT alert_id FROM preauth_evidence WHERE record_id=? AND detector_id=?",
            (record_id, detector_id),
        ).fetchone()
        if existing:
            return int(existing[0])
        reason = (
            f"{observed} SSH-forbindelser fra {source_ip} blev afbrudt før login "
            f"inden for {window_seconds} sekunder (grænse: {threshold}). "
            "Dette alene beviser ikke et nøgleangreb."
        )
        details = {
            "window_seconds": window_seconds,
            "observed_disconnects": observed,
            "threshold": threshold,
            "evidence_record_id": record_id,
        }
        row = db.execute(
            "SELECT id FROM alerts WHERE detector_id=? AND source_ip=? "
            "AND last_seen>=? AND last_seen<=? ORDER BY last_seen DESC LIMIT 1",
            (detector_id, source_ip, timestamp - cooldown, timestamp),
        ).fetchone()
        if row:
            alert_id = int(row[0])
            db.execute(
                "UPDATE alerts SET last_seen=?,count=count+1,reason=?,details=? WHERE id=?",
                (timestamp, reason, encode(details), alert_id),
            )
        else:
            result = db.execute(
                "INSERT INTO alerts(detector_id,title,severity,reason,source_ip,"
                "first_seen,last_seen,count,score,model_version,details) "
                "VALUES(?,?,?,?,?,?,?,1,NULL,NULL,?)",
                (
                    detector_id,
                    "Gentagne SSH-afbrud før login",
                    "medium",
                    reason,
                    source_ip,
                    timestamp,
                    timestamp,
                    encode(details),
                ),
            )
            alert_id = int(result.lastrowid)
        db.execute(
            "INSERT INTO preauth_evidence(record_id,alert_id,timestamp,detector_id,"
            "reason,details) VALUES(?,?,?,?,?,?)",
            (record_id, alert_id, timestamp, detector_id, reason, encode(details)),
        )
        return alert_id

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

    def list_preauth(self, hours: int = 24, page: int = 1, per_page: int = 25) -> dict:
        """Show trusted preauth disconnects already saved in raw journal records.

        No schema migration, backfill writing, or alteration of login counts.
        """
        start, end = self._period(hours)
        if (
            type(page) is not int
            or page < 1
            or type(per_page) is not int
            or not 1 <= per_page <= 100
        ):
            raise ValueError("Ugyldig side eller sidestørrelse")
        with self.reader() as db:
            total = db.execute(
                "SELECT COUNT(*) FROM records WHERE " + PREAUTH_FILTER, (start, end)
            ).fetchone()[0]
            pages = max(1, math.ceil(total / per_page))
            page = min(page, pages)
            rows = db.execute(
                """SELECT timestamp,
                          CASE WHEN json_extract(raw_json, '$.MESSAGE')
                                    LIKE 'Connection reset%'
                               THEN 'Nulstillet' ELSE 'Lukket' END AS connection_type,
                          SUBSTR(json_extract(raw_json, '$.MESSAGE'), 1, 4096) AS message
                   FROM records WHERE """
                + PREAUTH_FILTER
                + " ORDER BY timestamp DESC,id DESC LIMIT ? OFFSET ?",
                (start, end, per_page, (page - 1) * per_page),
            ).fetchall()
        return {
            "items": [dict(row) for row in rows],
            "total": total,
            "page": page,
            "pages": pages,
        }

    def list_firewall(
        self,
        hours: int = 24,
        source: str = "",
        protocol: str = "",
        page: int = 1,
        per_page: int = 25,
    ) -> dict:
        start, end = self._period(hours)
        where, args = "timestamp>=? AND timestamp<=?", [start, end]
        if source:
            where += " AND source_ip=?"
            args.append(source)
        if protocol:
            where += " AND protocol=?"
            args.append(protocol)
        return self._page(
            "firewall_events", where, args, page, per_page, "timestamp DESC,event_id DESC"
        )

    def firewall_summary(self, hours: int = 24) -> dict:
        start, end = self._period(hours)
        with self.reader() as db:
            row = db.execute(
                "SELECT COUNT(*) AS recorded, "
                "COUNT(DISTINCT source_ip) AS sources, "
                "SUM(CASE WHEN protocol='TCP' THEN 1 ELSE 0 END) AS tcp, "
                "SUM(CASE WHEN protocol='UDP' THEN 1 ELSE 0 END) AS udp "
                "FROM firewall_events WHERE timestamp>=? AND timestamp<=?",
                (start, end),
            ).fetchone()
        return {
            "recorded": int(row["recorded"]),
            "sources": int(row["sources"]),
            "tcp": int(row["tcp"] or 0),
            "udp": int(row["udp"] or 0),
        }

    def firewall_charts(self, hours: int = 24) -> dict:
        """Read-only aggregate timeline and top-ten blocked TCP SYN destination ports.

        Time buckets include only recorded activity. No IP addresses or raw
        firewall events are returned, regardless of how many ports were hit.
        """
        start, end = self._period(hours)
        bucket = 300 if hours <= 6 else 1800 if hours <= 24 else 7200 if hours <= 168 else 21600
        condition = """
            timestamp>=? AND timestamp<=?
            AND action IN ('BLOCK','REJECT','LIMIT BLOCK')
            AND direction='incoming' AND in_interface!='' AND out_interface=''
            AND protocol_number=6 AND destination_port IS NOT NULL
            AND instr(tcp_flags, '"SYN"')>0
            AND instr(tcp_flags, '"ACK"')=0
            AND instr(tcp_flags, '"FIN"')=0
            AND instr(tcp_flags, '"RST"')=0
        """
        with self.reader() as db:
            timeline = db.execute(
                "SELECT CAST(timestamp / ? AS INTEGER) * ? AS bucket_start, "
                "COUNT(*) AS packets FROM firewall_events WHERE "
                + condition
                + " GROUP BY bucket_start ORDER BY bucket_start",
                (bucket, bucket, start, end),
            ).fetchall()
            top = db.execute(
                "SELECT destination_port AS port, COUNT(*) AS packets "
                "FROM firewall_events WHERE "
                + condition
                + " GROUP BY destination_port ORDER BY packets DESC, port ASC LIMIT 10",
                (start, end),
            ).fetchall()
            totals = db.execute(
                "SELECT COUNT(*) AS packets, "
                "COUNT(DISTINCT destination_port) AS unique_ports "
                "FROM firewall_events WHERE " + condition,
                (start, end),
            ).fetchone()
        top_ports = [
            {"port": int(row["port"]), "packets": int(row["packets"])} for row in top
        ]
        total_packets = int(totals["packets"])
        return {
            "bucket_seconds": bucket,
            "series": [
                {"timestamp": int(row["bucket_start"]), "packets": int(row["packets"])}
                for row in timeline
            ],
            "top_ports": top_ports,
            "other_ports_packets": total_packets - sum(row["packets"] for row in top_ports),
            "total_packets": total_packets,
            "unique_ports": int(totals["unique_ports"]),
        }

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
            evidence = db.execute(
                "SELECT p.record_id AS event_id,p.timestamp,p.detector_id,p.reason,"
                "p.details,NULL AS score,NULL AS model_version,NULL AS username,"
                "'preauth' AS outcome,json_extract(r.raw_json,'$.MESSAGE') AS message "
                "FROM preauth_evidence AS p "
                "JOIN records AS r ON r.id=p.record_id "
                "WHERE p.alert_id=? ORDER BY p.timestamp DESC LIMIT 100",
                (alert_id,),
            ).fetchall()
            network = db.execute(
                "SELECT n.event_id,n.timestamp,n.detector_id,n.reason,n.details,"
                "NULL AS score,NULL AS model_version,NULL AS username,"
                "'firewall' AS outcome,NULL AS message "
                "FROM network_evidence n WHERE n.alert_id=? "
                "ORDER BY n.timestamp DESC LIMIT 100",
                (alert_id,),
            ).fetchall()
            merged = [self._decode(r) for r in rows]
            merged.extend(self._decode(r) for r in evidence)
            merged.extend(self._decode(r) for r in network)
            merged.sort(key=lambda item: (item["timestamp"], item["event_id"]), reverse=True)
            alert["findings"] = merged[:100]
            alert["findings_truncated"] = alert["count"] > len(alert["findings"])
            return alert

    def dashboard(self, hours: int = 24) -> dict:
        start, end = self._period(hours)
        # A five-minute bucket is useful for short views but makes the day
        # chart overly spiky when observations are sparse. These are counts,
        # not continuous samples; preserve exact five-minute detail at <=6h.
        bucket = 300 if hours <= 6 else 1800 if hours <= 24 else 3600
        with self.reader() as db:
            counts = dict(
                db.execute(
                    "SELECT outcome,COUNT(*) FROM events WHERE timestamp>=? AND timestamp<=? GROUP BY outcome",
                    (start, end),
                ).fetchall()
            )
            totals = {"success": counts.get("success", 0), "failure": counts.get("failure", 0)}
            totals["events"] = totals["success"] + totals["failure"]
            preauth_count = db.execute(
                "SELECT COUNT(*) FROM records WHERE " + PREAUTH_FILTER, (start, end)
            ).fetchone()[0]
            totals["alerts"] = db.execute(
                "SELECT COUNT(*) FROM alerts WHERE last_seen>=? AND last_seen<=?", (start, end)
            ).fetchone()[0]
            times = db.execute("SELECT MIN(timestamp),MAX(timestamp) FROM events").fetchone()
            # Authentication results and preauth disconnects are different
            # types of evidence. Merge their time buckets for visualization,
            # without changing authentication totals or ML observations.
            by_time = {
                row["timestamp"]: {**dict(row), "preauth": 0}
                for row in db.execute(
                    "SELECT CAST(timestamp/? AS INTEGER)*? AS timestamp, "
                    "SUM(outcome='success') AS success, SUM(outcome='failure') AS failure "
                    "FROM events WHERE timestamp>=? AND timestamp<=? GROUP BY 1",
                    (bucket, bucket, start, end),
                )
            }
            for row in db.execute(
                "SELECT CAST(timestamp/? AS INTEGER)*? AS timestamp, COUNT(*) AS preauth "
                "FROM records WHERE " + PREAUTH_FILTER + " GROUP BY 1",
                (bucket, bucket, start, end),
            ):
                item = by_time.setdefault(
                    row["timestamp"],
                    {"timestamp": row["timestamp"], "success": 0, "failure": 0, "preauth": 0},
                )
                item["preauth"] = row["preauth"]
            series = [by_time[key] for key in sorted(by_time)]
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
            "preauth_count": preauth_count,
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
            firewall_events = db.execute(
                "DELETE FROM firewall_events WHERE timestamp<?", (cutoff,)
            ).rowcount
            db.execute(
                "DELETE FROM alerts WHERE "
                "NOT EXISTS(SELECT 1 FROM findings WHERE alert_id=alerts.id) "
                "AND NOT EXISTS(SELECT 1 FROM preauth_evidence WHERE alert_id=alerts.id) "
                "AND NOT EXISTS(SELECT 1 FROM network_evidence WHERE alert_id=alerts.id)"
            )
            db.execute(
                "UPDATE alerts SET "
                "count=(SELECT COUNT(*) FROM findings WHERE alert_id=alerts.id)"
                "+(SELECT COUNT(*) FROM preauth_evidence WHERE alert_id=alerts.id)"
                "+(SELECT COUNT(*) FROM network_evidence WHERE alert_id=alerts.id),"
                "first_seen=(SELECT MIN(timestamp) FROM ("
                "SELECT timestamp FROM findings WHERE alert_id=alerts.id UNION ALL "
                "SELECT timestamp FROM preauth_evidence WHERE alert_id=alerts.id UNION ALL "
                "SELECT timestamp FROM network_evidence WHERE alert_id=alerts.id)),"
                "last_seen=(SELECT MAX(timestamp) FROM ("
                "SELECT timestamp FROM findings WHERE alert_id=alerts.id UNION ALL "
                "SELECT timestamp FROM preauth_evidence WHERE alert_id=alerts.id UNION ALL "
                "SELECT timestamp FROM network_evidence WHERE alert_id=alerts.id))"
            )
        # Reuse freed pages; avoids blocking a live collector with a full VACUUM.
        return {"events": events, "records": records, "firewall_events": firewall_events}

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
