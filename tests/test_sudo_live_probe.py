"""Exact controlled-process evidence and read-only receipt verification."""

import importlib.util
import json
import sqlite3
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from yggdrasil_ids.storage import Repository
from yggdrasil_ids.sudo_rules import SudoRuleMatch, SudoSignal
from yggdrasil_ids.sudo_storage import SudoStagingStore, event_id

NOW = 1_800_000_000.0
BOOT = "b" * 32


@pytest.fixture
def probe():
    path = Path(__file__).parents[1] / "deploy/sprint5_sudo_live_probe.py"
    spec = importlib.util.spec_from_file_location("sudo_live_probe_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def evidence(probe, tmp_path, monkeypatch):
    store = SudoStagingStore(tmp_path / "private-source/sudo-shadow.sqlite3")
    store.initialize()
    monkeypatch.setattr(probe, "SOURCE", store.path)
    with sqlite3.connect(store.path) as db:
        db.execute(
            "CREATE TABLE shadow_poll_checkpoint(id INTEGER PRIMARY KEY,last_completed_until REAL)"
        )
        db.execute("INSERT INTO shadow_poll_checkpoint VALUES(1,?)", (NOW - 2,))
    repo = Repository(tmp_path / "prod/events.sqlite3")
    repo.initialize()
    monkeypatch.setattr(probe, "DATABASE", repo.path)
    delivery = tmp_path / "delivery.sqlite3"
    monkeypatch.setattr(probe, "DELIVERY", delivery)
    request = {
        "stage": "watch",
        "boot": BOOT,
        "pids": [1001, 1002, 1003],
        "start": NOW - 30,
        "end": NOW - 20,
    }
    signals = [
        SudoSignal(f"private-cursor-{i}", NOW - 29 + i, BOOT, "997", 1001 + i, "incorrect_password")
        for i in range(3)
    ]
    for i, signal in enumerate(signals):
        candidate = SudoRuleMatch(probe.DETECTOR, "medium", 3, signal.timestamp) if i == 2 else None
        store.append(signal, candidate)
    with repo.transaction() as db:
        alarm_id = repo.add_sudo_alert(
            db,
            event_id=event_id(signals[-1]),
            detector_id=probe.DETECTOR,
            timestamp=signals[-1].timestamp,
            process_count=3,
        )
    with repo.reader() as db:
        instance = db.execute("SELECT instance FROM discord_outbox_meta").fetchone()[0]
        reference = db.execute("SELECT ref FROM discord_outbox").fetchone()[0]
    with sqlite3.connect(delivery) as db:
        db.execute("CREATE TABLE meta(instance TEXT,last_seq INTEGER,not_before REAL)")
        db.execute("INSERT INTO meta VALUES(?,0,0)", (instance,))
        db.execute("CREATE TABLE deliveries(ref TEXT PRIMARY KEY,discord_id TEXT,sent_at REAL)")
    public = {
        "state": "ready",
        "ml": {
            "state": "ready",
            "model_version": probe.MODEL_VERSION,
            "latest": [
                {
                    "timestamp": signal.timestamp,
                    "category": "authentication_failed",
                    "is_anomaly": i == 2,
                }
                for i, signal in enumerate(signals)
            ],
        },
    }
    monkeypatch.setattr(probe, "public_status", lambda: public)
    return SimpleNamespace(
        store=store,
        repo=repo,
        request=request,
        reference=reference,
        alarm_id=alarm_id,
        public=public,
    )


def acknowledge(probe, reference):
    with sqlite3.connect(probe.DELIVERY) as db:
        db.execute("INSERT INTO deliveries VALUES(?,'123456789012345678',?)", (reference, NOW))


def test_exact_candidate_alarm_outbox_receipt_chain_and_private_readonly(probe, evidence):
    pending = probe.inspect(evidence.request, now=NOW)
    assert not probe.complete(pending)
    assert pending["registered_alarms"][0]["discord_acknowledged"] is False
    acknowledge(probe, evidence.reference)
    paths = [probe.SOURCE, probe.DATABASE, probe.DELIVERY]
    before = [path.read_bytes() for path in paths]
    result = probe.inspect(evidence.request, now=NOW)
    assert probe.complete(result)
    assert result["ml_probe_positions_matched"] == 3 and result["ml_probe_flags"] == 1
    assert result["registered_alarms"] == [
        {
            "alarm_id": evidence.alarm_id,
            "process_count": 3,
            "reference": evidence.reference,
            "discord_acknowledged": True,
        }
    ]
    assert [path.read_bytes() for path in paths] == before
    output = json.dumps(result)
    assert BOOT not in output and "private-cursor" not in output
    assert '"uid"' not in output and '"pid"' not in output and '"discord_id"' not in output


def test_unrelated_discord_receipt_is_not_credited_to_probe(probe, evidence):
    acknowledge(probe, "f" * 32)
    assert not probe.complete(probe.inspect(evidence.request, now=NOW))


def test_wrong_probe_pid_cannot_claim_background_detection(probe, evidence):
    acknowledge(probe, evidence.reference)
    request = {**evidence.request, "pids": [1001, 1002, 9999]}
    result = probe.inspect(request, now=NOW)
    assert result["failed_probe_processes"] == 2
    assert result["matching_candidates"] == 0 and not probe.complete(result)


def test_ambiguous_outbox_link_is_not_claimed_as_delivery(probe, evidence):
    acknowledge(probe, evidence.reference)
    with evidence.repo.transaction() as db:
        evidence.repo.add_sudo_alert(
            db, event_id="d" * 64, detector_id=probe.DETECTOR, timestamp=NOW - 27, process_count=3
        )
    result = probe.inspect(evidence.request, now=NOW)
    assert result["outbox_match_ambiguous"] and not probe.complete(result)


def test_real_background_failures_are_reported_as_context_not_isolated_test(probe, evidence):
    evidence.store.append(
        SudoSignal("private-background", NOW - 100, BOOT, "997", 9999, "pam_auth_failure")
    )
    acknowledge(probe, evidence.reference)
    result = probe.inspect(evidence.request, now=NOW)
    assert result["other_failure_processes"] == 1 and not probe.complete(result)


def test_unmatched_ml_positions_are_unknown_instead_of_zero(probe, evidence):
    evidence.public["ml"]["latest"] = []
    acknowledge(probe, evidence.reference)
    result = probe.inspect(evidence.request, now=NOW)
    assert probe.complete(result)  # Rule/delivery evidence is independent of raw ML decisions.
    assert result["ml_probe_flags"] is None and result["ml_probe_positions_matched"] == 0


def test_temporary_shadow_export_failure_does_not_hide_recorded_rule_delivery(probe, evidence):
    acknowledge(probe, evidence.reference)
    evidence.public["ml"] = {"state": "unavailable"}
    result = probe.inspect(evidence.request, now=NOW)
    assert probe.complete(result)
    assert result["ml_state"] == "unavailable" and result["model_version"] is None
    assert result["ml_probe_flags"] is None
    with pytest.raises(ValueError, match="Fresh"):
        probe.inspect({"stage": "preflight"}, now=NOW)


def test_preflight_holds_recent_failures_and_requires_fresh_checkpoint(probe, evidence):
    assert probe.inspect({"stage": "preflight"}, now=NOW)["ready"] is False
    with pytest.raises(ValueError, match="checkpoint"):
        probe.inspect({"stage": "preflight"}, now=NOW + 400)
    with sqlite3.connect(probe.SOURCE) as db:
        db.execute("UPDATE shadow_poll_checkpoint SET last_completed_until=?", (NOW + 398,))
    assert probe.inspect({"stage": "preflight"}, now=NOW + 400)["ready"] is True


def test_receipt_database_must_match_active_outbox_identity(probe, evidence):
    acknowledge(probe, evidence.reference)
    with sqlite3.connect(probe.DELIVERY) as db:
        db.execute("UPDATE meta SET instance='different-source'")
    with pytest.raises(ValueError, match="identity"):
        probe.inspect(evidence.request, now=NOW)
    with pytest.raises(ValueError, match="identity"):
        probe.inspect({"stage": "preflight"}, now=NOW)


@pytest.mark.parametrize(
    "changed",
    [{"pids": [1, 1, 2]}, {"pids": [True, 2, 3]}, {"end": NOW + 301}, {"boot": "not-a-boot"}],
)
def test_invalid_process_manifest_cannot_reach_private_sql(probe, evidence, changed):
    with pytest.raises(ValueError):
        probe.validate_request({**evidence.request, **changed})


@pytest.mark.parametrize("stop_after", [None, 1])
def test_parent_generates_only_three_failures_or_stops_at_first_error(
    probe, tmp_path, monkeypatch, stop_after
):
    code = tmp_path / "installed"
    code.mkdir()
    (code / "COMMIT").write_text(probe.INSTALLED_SHA)
    monkeypatch.setattr(probe, "CODE", code)
    attempts = []
    inspections = []

    def invoke(*, failure):
        assert failure is True
        attempts.append(1)
        if stop_after is not None and len(attempts) == stop_after:
            raise RuntimeError("unexpected sudo success; stopped")
        return 1000 + len(attempts)

    monkeypatch.setitem(sys.modules, "sprint5_sudo_frozen_probe", SimpleNamespace(invoke=invoke))

    def command(args, **kwargs):
        if args[0] == "systemctl":
            return SimpleNamespace(returncode=0, stdout="active\n" * len(probe.UNITS))
        request = json.loads(kwargs["input"])
        inspections.append(request["stage"])
        if request["stage"] == "preflight":
            return SimpleNamespace(returncode=0, stdout=json.dumps({"ready": True}))
        assert request["pids"] == [1001, 1002, 1003]
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(probe.subprocess, "run", command)
    if stop_after is None:
        assert probe.run() and len(attempts) == 3
        assert inspections == ["preflight", "watch"]
    else:
        with pytest.raises(RuntimeError, match="stopped"):
            probe.run()
        assert len(attempts) == 1 and inspections == ["preflight"]


def test_watcher_does_not_generate_retries(probe, evidence, monkeypatch):
    pending = probe.inspect(evidence.request, now=NOW)
    acknowledge(probe, evidence.reference)
    passed = probe.inspect(evidence.request, now=NOW)
    reports = iter([pending, passed])
    monkeypatch.setattr(probe, "inspect", lambda _: next(reports))
    monkeypatch.setattr(probe.time, "sleep", lambda _: None)
    assert probe.watch(evidence.request) is True
