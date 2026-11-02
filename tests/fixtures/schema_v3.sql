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
