"""Software acceptance of the combined production pipeline, with no real traffic.

Synthetic records exercise actual parsers, a fitted SSH forest, both collectors,
SQLite/outbox, authenticated pages and local notifier receipts. Journal and
network boundaries are replaced; these are not Raspberry Pi detection metrics.
"""

import hashlib
import json
import math
import sqlite3
import time

from werkzeug.security import generate_password_hash

from tests.sudo_helpers import row as sudo_row
from yggdrasil_ids import sudo_collector, sudo_service
from yggdrasil_ids.config import AppConfig, MLConfig, NetworkConfig, RulesConfig, SudoConfig
from yggdrasil_ids.engine import AnalysisEngine
from yggdrasil_ids.ml import IsolationForestDetector
from yggdrasil_ids.notify import DiscordNotifier
from yggdrasil_ids.web import create_app

NOW = 1_800_000_000.0


def ssh_record(index, stamp, message):
    return {
        "__CURSOR": f"production-ssh-{index}",
        "__REALTIME_TIMESTAMP": str(round(stamp * 1_000_000)),
        "_COMM": "sshd-session",
        "_UID": "0",
        "_PID": str(1000 + index),
        "_HOSTNAME": "software-fixture",
        "MESSAGE": message,
    }


def scan_record(index, stamp):
    return {
        "__CURSOR": f"production-ufw-{index}",
        "__REALTIME_TIMESTAMP": str(round(stamp * 1_000_000)),
        "_TRANSPORT": "kernel",
        "SYSLOG_IDENTIFIER": "kernel",
        "_BOOT_ID": "a" * 32,
        "_HOSTNAME": "software-fixture",
        "MESSAGE": (
            "[UFW BLOCK] IN=wlan0 OUT= SRC=203.0.113.99 DST=192.0.2.92 "
            f"LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID={index + 1} DF PROTO=TCP "
            f"SPT=45000 DPT={45010 + index} WINDOW=64240 RES=0x00 SYN URGP=0"
        ),
    }


def counts(repository):
    with repository.reader() as db:
        return {
            table: db.execute("SELECT COUNT(*) FROM " + table).fetchone()[0]
            for table in (
                "events",
                "observations",
                "preauth_disconnects",
                "firewall_events",
                "alerts",
                "sudo_evidence",
                "discord_outbox",
            )
        }


def test_shared_production_detection_dashboard_and_delivery_survive_replay_and_restart(
    tmp_path, monkeypatch
):
    clock = [NOW]
    monkeypatch.setattr(time, "time", lambda: clock[0])

    def forbidden_boundary(*args, **kwargs):
        raise AssertionError("The software test must not read a real journal or contact a network")

    monkeypatch.setattr(sudo_collector, "journal_records", forbidden_boundary)
    monkeypatch.setattr("urllib.request.OpenerDirector.open", forbidden_boundary)
    # The executor is root and cannot become the worker. Replace only the entry
    # guard, keeping all real file ownership, permissions, locking and DB checks.
    monkeypatch.setattr(sudo_collector, "_require_worker", lambda: None)
    monkeypatch.setattr(sudo_service, "_require_worker", lambda: None)
    public = tmp_path / "sudo-public"
    public.mkdir(mode=0o750)
    cfg = AppConfig(
        database_path=tmp_path / "production" / "events.sqlite3",
        model_path=tmp_path / "production" / "model.json",
        credentials_path=tmp_path / "credentials.json",
        sudo_database_path=tmp_path / "sudo-private" / "sudo.sqlite3",
        sudo_public_directory=public,
        ml=MLConfig(n_estimators=32),
        rules=RulesConfig(failure_threshold=3, username_threshold=3, preauth_threshold=3),
        network=NetworkConfig(enabled=True, distinct_ports_threshold=3),
        sudo=SudoConfig(enabled=True),
    )
    normal_rows = []
    # A fixed-phase software fixture exercises a real positive forest decision;
    # it is not a representative corpus or a recommended production profile.
    phase = 2 * math.pi * ((NOW % 86400) / 86400)
    for index in range(96):
        failed, successful = index % 2, 2 + index % 7
        normal_rows.append(
            [
                failed,
                successful,
                min(failed + successful, 1 + index % 3),
                failed / (failed + successful),
                math.sin(phase),
                math.cos(phase),
            ]
        )
    model = IsolationForestDetector.train(
        normal_rows, cfg.ml, "Synthetic normal software-test fixtures; no real-world rate claim"
    )
    model.save(cfg.model_path)
    frozen_bytes = cfg.model_path.read_bytes()
    frozen_hash = hashlib.sha256(frozen_bytes).hexdigest()
    frozen_metadata = model.metadata
    engine = AnalysisEngine(cfg, namespace="live")
    assert engine.repository.get_state("model")["state"] == "ready"
    assert engine.repository.get_state("model")["alert_mode"] == "alert"
    assert engine.repository.get_state("firewall_started_at") == NOW
    sudo_service.arm(cfg, now=NOW)

    # Bootstrap this new fixture's notifier while its outbox is empty. There is
    # no reset/bootstrap of an existing production stream.
    sent = []
    webhook = tmp_path / "synthetic-webhook"
    webhook.write_text("https://discord.com/api/webhooks/" + "0" * 18 + "/" + "a" * 60)
    webhook.chmod(0o600)
    delivery_path = tmp_path / "notifier-private" / "delivery.sqlite3"

    def sender(url, message):
        assert url == webhook.read_text()
        sent.append(message)
        return str(100000000000000000 + len(sent))

    notifier = DiscordNotifier(
        cfg.database_path, delivery_path, webhook_file=webhook, sender=sender
    )
    assert notifier.bootstrap()["last_seq"] == 0

    authentication = [
        ssh_record(0, NOW + 1, "Accepted publickey for operator from 192.0.2.10 port 54321 ssh2")
    ]
    authentication.extend(
        ssh_record(
            index,
            NOW + 2 + index,
            f"Failed publickey for account{index} from 192.0.2.99 port 54321 ssh2",
        )
        for index in range(1, 13)
    )
    preauth = [
        ssh_record(
            100 + index,
            NOW + 30 + index,
            f"Connection closed by authenticating user visitor 198.51.100.25 port {42000 + index} [preauth]",
        )
        for index in range(3)
    ]
    packets = [scan_record(index, NOW + 40 + index) for index in range(3)]
    for record in authentication:
        clock[0] = int(record["__REALTIME_TIMESTAMP"]) / 1_000_000
        assert engine.process(record)["status"] == "event"
    auth_counts = counts(engine.repository)
    for record in preauth:
        clock[0] = int(record["__REALTIME_TIMESTAMP"]) / 1_000_000
        assert engine.process(record)["status"] == "ignored"
    after_preauth = counts(engine.repository)
    assert after_preauth["events"] == auth_counts["events"] == len(authentication)
    assert after_preauth["observations"] == auth_counts["observations"] == len(authentication)
    assert after_preauth["preauth_disconnects"] == 3
    for record in packets:
        clock[0] = int(record["__REALTIME_TIMESTAMP"]) / 1_000_000
        assert engine.process(record)["status"] == "event"
    assert counts(engine.repository)["observations"] == len(authentication)

    sudo_records = [sudo_row(index, NOW + 70 + index) for index in (1, 2, 3)]
    clock[0] = NOW + 85
    sudo_result = sudo_service.run_once(cfg, now=clock[0], records=sudo_records)
    assert sudo_result["rules"]["state"] == "active"
    assert "ml" not in sudo_result
    with engine.repository.reader() as db:
        detectors = {row[0] for row in db.execute("SELECT detector_id FROM alerts")}
        assert {
            "ssh.failed_burst",
            "ssh.user_spray",
            "ssh.isolation_forest",
            "ssh.preauth_burst",
            "network.tcp_port_scan",
            "sudo.repeated_auth_failure",
        } <= detectors
        outbox = [
            dict(row)
            for row in db.execute("SELECT seq,ref,detector_id,severity FROM discord_outbox")
        ]
        assert {row["detector_id"] for row in outbox} == detectors
        assert all(row["severity"] in {"medium", "high", "critical"} for row in outbox)
        observation_rows = db.execute(
            "SELECT state,model_version,threshold FROM observations"
        ).fetchall()
        assert all(
            tuple(row) == ("scored", frozen_metadata["version"], frozen_metadata["threshold"])
            for row in observation_rows
        )
        assert db.execute("SELECT COUNT(*) FROM observations WHERE is_anomaly=1").fetchone()[0] > 0
    assert counts(engine.repository)["sudo_evidence"] == 1
    assert len({row["ref"] for row in outbox}) == len(outbox)

    engine.heartbeat("running", "Software fixture collection active")
    cfg.credentials_path.write_text(
        json.dumps(
            {
                "secret_key": "production-test-secret-longer-than-thirty-two-characters",
                "password_hash": generate_password_hash("test", method="pbkdf2:sha256:1000"),
            }
        )
    )
    client = create_app(cfg).test_client()
    assert client.get("/sudo").status_code == 302
    assert client.get("/api/nav-alerts").status_code == 401
    with client.session_transaction() as session:
        session["authenticated"] = True
        session["authenticated_at"] = clock[0]
    before_web = cfg.database_path.read_bytes()
    for route in ("/", "/events", "/preauth", "/network", "/sudo", "/alerts", "/model", "/status"):
        assert client.get(route).status_code == 200
    assert "Autentificering mislykkedes" in client.get("/sudo").get_data(as_text=True)
    assert "Sudo-regler opretter alarmer" in client.get("/sudo").get_data(as_text=True)
    assert frozen_metadata["version"] in client.get("/model").get_data(as_text=True)
    assert "Gentagne SSH-afbrud" in client.get("/alerts").get_data(
        as_text=True
    ) or "Gentagne afbrud før login" in client.get("/alerts").get_data(as_text=True)
    nav = client.get("/api/nav-alerts").get_json()["counts"]
    assert all(nav[key] > 0 for key in ("ssh", "preauth", "network", "sudo"))
    assert cfg.database_path.read_bytes() == before_web
    for path in public.iterdir():
        text = path.read_text()
        assert "private-user" not in text and "private-cursor" not in text
        assert "sudo-if-" not in text and "shadow" not in text

    assert notifier.poll() == max(row["seq"] for row in outbox)
    assert len(sent) == len(outbox)
    frozen_counts = counts(engine.repository)
    restarted = AnalysisEngine(cfg, namespace="live")
    for record in authentication + preauth + packets:
        assert restarted.process(record)["status"] == "duplicate"
    clock[0] = NOW + 90
    sudo_service.run_once(cfg, now=clock[0], records=sudo_records)
    assert counts(restarted.repository) == frozen_counts
    restarted_notifier = DiscordNotifier(
        cfg.database_path, delivery_path, webhook_file=webhook, sender=sender
    )
    assert restarted_notifier.poll() == max(row["seq"] for row in outbox)
    assert len(sent) == len(outbox)
    with sqlite3.connect(delivery_path) as receipts:
        actual_refs = {row[0] for row in receipts.execute("SELECT ref FROM deliveries")}
    assert actual_refs == {row["ref"] for row in outbox}
    assert cfg.model_path.read_bytes() == frozen_bytes
    assert hashlib.sha256(cfg.model_path.read_bytes()).hexdigest() == frozen_hash
    assert restarted.model.metadata == frozen_metadata
