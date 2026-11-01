#!/usr/bin/env python3
"""Read-only, privacy-preserving aggregates for a bounded Sprint 3 scan test."""
import argparse
import json
import sqlite3
import time
from collections import Counter, deque
from pathlib import Path

DB = Path("/var/lib/yggdrasil-ids/events.sqlite3")
DETECTOR = "network.tcp_port_scan"


def peak_distinct(events, window=60):
    active, ports = deque(), Counter()
    highest = 0
    for timestamp, port in sorted(events):
        while active and active[0][0] <= timestamp - window:
            _, expired = active.popleft()
            ports[expired] -= 1
            if ports[expired] == 0:
                del ports[expired]
        active.append((timestamp, port))
        ports[port] += 1
        highest = max(highest, len(ports))
    return highest


def observe(path, now, minutes=10, low=45010, high=45019):
    if not 1 <= minutes <= 60 or not 1 <= low <= high <= 65535 or high - low >= 64:
        raise ValueError("Invalid observation window or port range")
    cutoff = now - 60 * minutes
    with sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True) as db:
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA query_only=ON")
        version = db.execute("PRAGMA user_version").fetchone()[0]
        if version != 4 or db.execute("PRAGMA quick_check").fetchone()[0] != "ok":
            raise ValueError("Expected healthy SQLite schema 4")
        events = db.execute(
            "SELECT timestamp,action,direction,in_interface,out_interface,namespace,"
            "host,boot_id,source_ip,destination_ip,protocol_number,destination_port,"
            "tcp_flags FROM firewall_events WHERE timestamp>=? AND timestamp<=? "
            "ORDER BY timestamp,event_id LIMIT 10001",
            (cutoff, now + 5),
        ).fetchall()
        if len(events) > 10000:
            raise ValueError("Too many events; select a shorter time window")
        grouped = {}
        syn_count = 0
        selected = 0
        for row in events:
            if (row["protocol_number"] != 6
                or row["action"] not in ("BLOCK", "REJECT", "LIMIT BLOCK")
                or row["direction"] != "incoming"
                or not row["in_interface"] or row["out_interface"]
                or row["destination_port"] is None):
                continue
            flags = set(json.loads(row["tcp_flags"]))
            if "SYN" not in flags or flags.intersection(("ACK", "FIN", "RST")):
                continue
            syn_count += 1
            port = row["destination_port"]
            if not low <= port <= high:
                continue
            selected += 1
            key = tuple(row[x] for x in (
                "namespace","host","boot_id","source_ip","destination_ip","in_interface"
            ))
            grouped.setdefault(key, []).append((row["timestamp"], port))
        def count(table, time_col, condition):
            return db.execute(
                "SELECT COUNT(*) FROM " + table + " WHERE detector_id=? AND "
                + time_col + ">=? AND " + time_col + "<=?",
                (DETECTOR, cutoff, now + 5),
            ).fetchone()[0]
        alerts = count("alerts", "last_seen", None)
        evidence = count("network_evidence", "timestamp", None)
        outbox = count("discord_outbox", "happened_at", None)
        def state(key):
            row = db.execute("SELECT value FROM state WHERE key=?", (key,)).fetchone()
            return json.loads(row[0]) if row else None
        collector = state("collector") or {}
        counters = state("firewall_counters") or {}
        started = state("firewall_started_at")
        error = state("network_analysis_error")
        quality = state("network_data_quality")
    heartbeat = collector.get("heartbeat_at")
    return {
        "window_minutes": minutes,
        "selected_ports": f"{low}-{high}",
        "firewall_records_in_window": len(events),
        "blocked_tcp_syn_in_window": syn_count,
        "selected_port_packets_in_window": selected,
        "selected_port_groups_in_window": len(grouped),
        "max_distinct_selected_ports_in_60s_one_group": max(
            (peak_distinct(group) for group in grouped.values()), default=0
        ),
        "scan_alerts_in_window": alerts,
        "network_evidence_in_window": evidence,
        "scan_outbox_in_window": outbox,
        "firewall_events_cumulative": counters.get("events", 0),
        "network_analysis_errors_cumulative": counters.get("analysis_errors", 0),
        "network_error_flag": error is not None,
        "network_quality_flag": quality is not None,
        "first_activation_recorded": started is not None,
        "collector_state": collector.get("state", "unknown"),
        "collector_heartbeat_age_seconds": (
            max(0, round(now - heartbeat)) if isinstance(heartbeat, (int, float))
            else None
        ),
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--minutes", type=int, default=10)
    parser.add_argument("--port-start", type=int, default=45010)
    parser.add_argument("--port-end", type=int, default=45019)
    args = parser.parse_args()
    result = observe(DB, time.time(), args.minutes, args.port_start, args.port_end)
    print(json.dumps(result, indent=2, ensure_ascii=False))
