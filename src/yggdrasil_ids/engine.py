"""One-record atomic ingestion with event-time detection and durable checkpoints."""

from __future__ import annotations

import hashlib
import json
import logging
import math
import time
from pathlib import Path

from .config import AppConfig
from .domain import Finding
from .features import FEATURE_NAMES, SSHFeatureBuilder
from .firewall import UFWParser
from .ml import IsolationForestDetector
from .preauth import parse_preauth
from .rules import SSHRuleDetector
from .ssh import SSHParser
from .storage import Repository, encode

log = logging.getLogger(__name__)
COUNTERS = ("records", "events", "ignored", "malformed", "duplicates", "late", "analysis_errors")


class AnalysisEngine:
    def __init__(self, config: AppConfig, namespace: str = "live"):
        self.config = config
        self.namespace = namespace
        self.repository = Repository(config.database_path)
        self.repository.initialize()
        with self.repository.transaction() as db:
            old_mode = self.repository.state_in(db, "mode")
            old_namespace = self.repository.state_in(db, "namespace")
            if old_mode is not None and old_mode != config.mode:
                raise ValueError("Demo- og driftsdata må ikke blandes i samme database")
            if old_namespace is not None and old_namespace != namespace:
                raise ValueError(
                    "Databasen tilhører et andet datagrundlag; brug en separat database"
                )
            self.repository.put_state(db, "mode", config.mode)
            self.repository.put_state(db, "namespace", namespace)
            if config.network.enabled and config.mode == "live":
                # The first opt-in must not backfill or alert on old kernel logs.
                if self.repository.state_in(db, "firewall_started_at") is None:
                    self.repository.put_state(db, "firewall_started_at", time.time())
            self.repository.put_state(
                db,
                "settings",
                {
                    "host_label": config.host_label,
                    "rule_window_seconds": config.rules.window_seconds,
                    "ml_window_seconds": config.ml.window_seconds,
                    "failure_threshold": config.rules.failure_threshold,
                    "username_threshold": config.rules.username_threshold,
                    "expected_sources": list(config.rules.expected_sources),
                    "expected_users": list(config.rules.expected_users),
                    "retention_days": config.retention_days,
                },
            )
        self.parser = SSHParser()
        self.firewall_parser = UFWParser()
        self.rules = SSHRuleDetector(config.rules)
        self.features = SSHFeatureBuilder(config.ml.window_seconds)
        self.model = None
        self.load_model()

    def load_model(self) -> None:
        self.model = None
        if not self.config.model_path.exists():
            state = {
                "state": "untrained",
                "message": "Ingen model indlæst. Reglerne er aktive; indsamling af normaldata kan fortsætte.",
            }
        else:
            try:
                candidate = IsolationForestDetector.load(self.config.model_path)
                if candidate.metadata["window_seconds"] != self.config.ml.window_seconds:
                    raise ValueError("Modellens tidsvindue matcher ikke konfigurationen")
                self.model = candidate
                state = {
                    "state": "ready",
                    "metadata": candidate.metadata,
                    "message": "Model indlæst; score viser afvigelse, ikke angrebssandsynlighed.",
                }
            except (OSError, ValueError, TypeError, KeyError) as exc:
                self.model = None
                state = {
                    "state": "error",
                    "message": "Modellen kunne ikke indlæses: " + str(exc)[:300],
                }
        self.repository.set_state("model", state)

    def heartbeat(self, state: str = "running", message: str = "") -> None:
        with self.repository.transaction() as db:
            previous = self.repository.state_in(db, "collector", {})
            self.repository.put_state(
                db,
                "collector",
                {
                    **previous,
                    "state": state,
                    "heartbeat_at": time.time(),
                    "message": message,
                    "namespace": self.namespace,
                },
            )

    def data_gap(self, message: str) -> None:
        self.repository.set_state("data_gap", {"at": time.time(), "message": message})

    def invalid_line(self, reason: str) -> None:
        with self.repository.transaction() as db:
            counters = self.repository.state_in(db, "counters", dict.fromkeys(COUNTERS, 0))
            counters["malformed"] = counters.get("malformed", 0) + 1
            self.repository.put_state(db, "counters", counters)
            self.repository.put_state(
                db, "data_quality", {"at": time.time(), "message": reason[:300]}
            )

    def process(self, record: dict) -> dict:
        received_at = time.time()
        if not isinstance(record, dict):
            self.invalid_line("Journalposten var ikke et JSON-objekt")
            return {"status": "malformed"}
        try:
            raw = encode(record)
            raw_bytes = raw.encode("utf-8")
        except (ValueError, TypeError, UnicodeError, RecursionError):
            self.invalid_line("Journalposten indeholdt ugyldige værdier")
            return {"status": "malformed"}
        if len(raw_bytes) > self.config.collector.max_record_bytes:
            self.invalid_line("Journalpost overskred størrelsesgrænsen")
            return {"status": "malformed"}
        cursor = record.get("__CURSOR", "")
        cursor = cursor if isinstance(cursor, str) and len(cursor) <= 4096 else ""
        record_id = hashlib.sha256((self.namespace + "\0" + (cursor or raw)).encode()).hexdigest()
        if self.config.network.enabled and record.get("_TRANSPORT") == "kernel":
            return self._process_firewall(record, received_at)
        parsed = self.parser.parse(record, namespace=self.namespace)
        stamp = received_at
        try:
            candidate_stamp = int(record.get("__REALTIME_TIMESTAMP", "")) / 1_000_000
            if 0 <= candidate_stamp <= 4_102_444_800 and math.isfinite(candidate_stamp):
                stamp = candidate_stamp
        except (ValueError, TypeError, OverflowError):
            pass
        result = {"status": parsed.status, "findings": 0}
        with self.repository.transaction() as db:
            counters = {
                **dict.fromkeys(COUNTERS, 0),
                **self.repository.state_in(db, "counters", {}),
            }
            inserted = db.execute(
                "INSERT OR IGNORE INTO records(id,cursor,timestamp,status,reason,raw_json) VALUES(?,?,?,?,?,?)",
                (record_id, cursor, stamp, parsed.status, parsed.reason, raw),
            ).rowcount
            if not inserted:
                counters["duplicates"] += 1
                result["status"] = "duplicate"
            else:
                counters["records"] += 1
                if parsed.event is None:
                    counters["malformed" if parsed.status == "malformed" else "ignored"] += 1
                    disconnect = parse_preauth(record) if parsed.status == "ignored" else None
                    if disconnect is not None and 0 <= stamp <= received_at + 60:
                        self.repository.insert_preauth_disconnect(
                            db, record_id, stamp, disconnect.source_ip, disconnect.kind
                        )
                        previous_seen = self.repository.state_in(db, "preauth_max_seen", 0)
                        if stamp >= previous_seen:
                            self.repository.put_state(db, "preauth_max_seen", stamp)
                            count = self.repository.preauth_window_count(
                                db, disconnect.source_ip, stamp, self.config.rules.window_seconds
                            )
                            if count >= self.config.rules.preauth_threshold:
                                self.repository.add_preauth_alert(
                                    db,
                                    record_id=record_id,
                                    timestamp=stamp,
                                    source_ip=disconnect.source_ip,
                                    observed=count,
                                    threshold=self.config.rules.preauth_threshold,
                                    window_seconds=self.config.rules.window_seconds,
                                    cooldown=self.config.rules.cooldown_seconds,
                                )
                                result["findings"] = 1
                    if parsed.status == "malformed":
                        self.repository.put_state(
                            db, "data_quality", {"at": received_at, "message": parsed.reason}
                        )
                else:
                    event = parsed.event
                    self.repository.insert_event(db, event)
                    counters["events"] += 1
                    max_seen = self.repository.state_in(db, "max_seen_timestamp", 0)
                    late = event.timestamp < max_seen
                    future = self.config.mode == "live" and event.timestamp > received_at + 60
                    if late or future:
                        counters["late"] += 1
                        why = (
                            "Hændelse ude af tidsrækkefølge"
                            if late
                            else "Hændelse mere end 60 sekunder foran systemuret"
                        )
                        self.repository.put_state(
                            db,
                            "data_quality",
                            {
                                "at": received_at,
                                "message": why
                                + "; gemt i historik, men ikke analyseret bagudrettet.",
                            },
                        )
                        db.execute(
                            "INSERT INTO observations VALUES(?,?,?,?,NULL,NULL,NULL,NULL,?)",
                            (event.event_id, event.timestamp, event.source_ip, "{}", "late"),
                        )
                    else:
                        self.repository.put_state(db, "max_seen_timestamp", event.timestamp)
                        try:
                            history = self.repository.history(
                                db,
                                event,
                                max(
                                    self.config.rules.window_seconds, self.config.ml.window_seconds
                                ),
                            )
                            findings = self.rules.detect(event, history)
                            values = self.features.build(history, event)
                            scored = None
                            observation_state = "untrained"
                            if self.model is not None:
                                try:
                                    scored = self.model.score(values)
                                    observation_state = "scored"
                                except (ValueError, TypeError, KeyError, RuntimeError) as exc:
                                    self.model = None
                                    counters["analysis_errors"] += 1
                                    observation_state = "error"
                                    self.repository.put_state(
                                        db,
                                        "model",
                                        {
                                            "state": "error",
                                            "message": "ML-vurderingen er stoppet efter en fejl. Reglerne fortsætter: "
                                            + str(exc)[:200],
                                        },
                                    )
                            elif self.repository.state_in(db, "model", {}).get("state") == "error":
                                observation_state = "error"
                            features = dict(zip(FEATURE_NAMES, values, strict=True))
                            db.execute(
                                "INSERT INTO observations VALUES(?,?,?,?,?,?,?,?,?)",
                                (
                                    event.event_id,
                                    event.timestamp,
                                    event.source_ip,
                                    encode(features),
                                    scored["score"] if scored else None,
                                    scored["threshold"] if scored else None,
                                    int(scored["is_anomaly"]) if scored else None,
                                    scored["model_version"] if scored else None,
                                    observation_state,
                                ),
                            )
                            if scored and scored["is_anomaly"]:
                                findings.append(
                                    Finding(
                                        detector_id="ssh.isolation_forest",
                                        title="Usædvanligt SSH-mønster",
                                        severity="medium",
                                        reason=f"Afvigelsesscore {scored['score']:.3f} overstiger modellens grænse {scored['threshold']:.3f}.",
                                        source_ip=event.source_ip,
                                        event_id=event.event_id,
                                        timestamp=event.timestamp,
                                        score=scored["score"],
                                        model_version=scored["model_version"],
                                        details={
                                            "features": features,
                                            "threshold": scored["threshold"],
                                            "window_seconds": self.config.ml.window_seconds,
                                            "evidence_event_ids": [event.event_id],
                                        },
                                    )
                                )
                            for finding in findings:
                                self.repository.add_finding(
                                    db, finding, self.config.rules.cooldown_seconds
                                )
                            result["findings"] = len(findings)
                        except (ValueError, TypeError, KeyError) as exc:
                            counters["analysis_errors"] += 1
                            self.repository.put_state(
                                db,
                                "analysis_error",
                                {
                                    "at": received_at,
                                    "message": str(exc)[:300],
                                    "event_id": event.event_id,
                                },
                            )
                            log.error("Analysefejl: %s", type(exc).__name__)
            # The journal cursor and all resulting data commit in one transaction.
            if cursor:
                self.repository.put_state(db, "cursor", cursor)
                self.repository.put_state(db, "cursor_timestamp", stamp)
            self.repository.put_state(db, "counters", counters)
            collector = self.repository.state_in(db, "collector", {})
            self.repository.put_state(
                db,
                "collector",
                {
                    **collector,
                    "last_record_at": received_at,
                    "heartbeat_at": received_at,
                    "state": "replay" if self.config.mode == "demo" else "running",
                    "namespace": self.namespace,
                },
            )
        return result

    def _process_firewall(self, record: dict, received_at: float) -> dict:
        """Commit normalized kernel data and the shared cursor atomically.

        Unrelated kernel messages are never saved as raw records, and SSH
        counters/authentication/ML features remain unchanged.
        """
        parsed = self.firewall_parser.parse(record, namespace=self.namespace)
        cursor = record.get("__CURSOR")
        if not isinstance(cursor, str) or len(cursor) > 4096:
            cursor = ""
        stamp = parsed.event.timestamp if parsed.event is not None else received_at
        with self.repository.transaction() as db:
            counters = self.repository.state_in(
                db, "firewall_counters", {"events": 0, "duplicates": 0, "malformed": 0}
            )
            status = parsed.status
            if parsed.event is not None:
                activation = self.repository.state_in(db, "firewall_started_at", 0)
                if self.config.mode == "live" and stamp < activation:
                    status = "historical"
                elif self.repository.insert_firewall_event(db, parsed.event):
                    counters["events"] += 1
                else:
                    counters["duplicates"] += 1
                    status = "duplicate"
            elif status == "malformed":
                counters["malformed"] += 1
                self.repository.put_state(
                    db, "network_data_quality", {"at": received_at, "message": parsed.reason}
                )
            self.repository.put_state(db, "firewall_counters", counters)
            if cursor:
                self.repository.put_state(db, "cursor", cursor)
                self.repository.put_state(db, "cursor_timestamp", stamp)
            collector = self.repository.state_in(db, "collector", {})
            self.repository.put_state(
                db,
                "collector",
                {
                    **collector,
                    "last_record_at": received_at,
                    "heartbeat_at": received_at,
                    "state": "replay" if self.config.mode == "demo" else "running",
                    "namespace": self.namespace,
                },
            )
        return {"status": status, "findings": 0}

    def replay(self, path: Path) -> dict:
        if self.config.mode != "demo":
            raise ValueError("Genafspilning kræver app.mode='demo' og en separat database")
        with path.open("rb") as handle:
            while True:
                line = handle.readline(self.config.collector.max_record_bytes + 1)
                if not line:
                    break
                if len(line) > self.config.collector.max_record_bytes:
                    while line and not line.endswith(b"\n"):
                        line = handle.readline(self.config.collector.max_record_bytes + 1)
                    self.invalid_line("En testpost var for stor og blev sprunget over")
                    continue
                if not line.strip():
                    continue
                try:
                    record = json.loads(line)
                except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError):
                    self.invalid_line("Ugyldig JSON i genafspilning")
                    continue
                self.process(record)
        self.heartbeat("replay", "Genafspilning afsluttet. Disse data er ikke live overvågning.")
        return self.repository.get_state("counters", {})
