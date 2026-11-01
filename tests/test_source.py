"""Exercise collector boundaries using an isolated fake journalctl process."""

import json
import subprocess
import sys
import threading
from dataclasses import replace

import pytest

from yggdrasil_ids.config import AppConfig, CollectorConfig
from yggdrasil_ids.engine import AnalysisEngine
from yggdrasil_ids.source import CollectorLock, JournalCollector, probe_journal

NOW = 1_800_000_000.0


@pytest.fixture
def config(tmp_path, monkeypatch):
    monkeypatch.setattr("yggdrasil_ids.source.time.time", lambda: NOW)
    return AppConfig(
        database_path=tmp_path / "events.sqlite3",
        model_path=tmp_path / "model.json",
        credentials_path=tmp_path / "credentials.json",
        mode="live",
    )


def record(index):
    return {
        "__CURSOR": f"cursor-{index}",
        "__REALTIME_TIMESTAMP": str(int((NOW - 100 + index) * 1e6)),
        "_COMM": "sshd-session",
        "_UID": "0",
        "_PID": str(100 + index),
        "MESSAGE": "Accepted publickey for labuser from 192.0.2.10 port 54321 ssh2",
    }


def fake_journal(tmp_path, payload, *, linger=True, code=0, stderr=""):
    """No shell, network or host journals: emit exact test bytes from a child."""
    path = tmp_path / "fake-journalctl"
    path.write_text(
        f"#!{sys.executable}\n"
        "import sys,time,json\n"
        "if '--follow' not in sys.argv:\n"
        "    print(json.dumps({'__CURSOR':'probe-cursor'}))\n"
        "    raise SystemExit(0)\n"
        f"sys.stdout.buffer.write({payload!r})\n"
        "sys.stdout.flush()\n"
        f"sys.stderr.write({stderr!r})\n"
        "sys.stderr.flush()\n"
        + ("time.sleep(30)\n" if linger else "")
        + f"raise SystemExit({code})\n"
    )
    path.chmod(0o700)
    return path


def stop_after_records(engine, stop, count):
    original = engine.process
    seen = []

    def process(value):
        result = original(value)
        seen.append(result)
        if len(seen) >= count:
            stop.set()
        return result

    engine.process = process
    return seen


def test_command_requests_trusted_fields_and_complete_catchup_after_cursor(config):
    collector = JournalCollector(config, AnalysisEngine(config))
    command = collector.command("cursor;literal")
    assert "--after-cursor=cursor;literal" in command
    assert "--follow" in command and "--no-tail" in command
    assert not any(
        value.startswith("--lines=") or value.startswith("--since=") for value in command
    )
    fields = next(
        value.split("=", 1)[1].split(",")
        for value in command
        if value.startswith("--output-fields=")
    )
    assert {"_COMM", "_UID", "MESSAGE", "__CURSOR", "__REALTIME_TIMESTAMP"} <= set(fields)
    assert command[-4:] == ["_COMM=sshd", "_COMM=sshd-session", "_COMM=sshd-auth", "_UID=0"]
    assert "--since=@123.500000" in collector.command(since=123.5)


@pytest.mark.parametrize(
    "stdout,stderr,returncode",
    [
        ("", "", 0),
        ('{"__CURSOR":"c"}', "Permission denied", 0),
        ('{"__CURSOR":"c"}', "You are not seeing messages from other users", 0),
        ('{"__CURSOR":"c"}', "failure", 1),
        ("{broken}", "", 0),
        ("[]", "", 0),
        ('{"__CURSOR":""}', "", 0),
    ],
)
def test_probe_does_not_report_access_from_empty_unreadable_or_invalid_output(
    config, monkeypatch, stdout, stderr, returncode
):
    monkeypatch.setattr(
        "yggdrasil_ids.source.subprocess.run",
        lambda *a, **kw: subprocess.CompletedProcess(a[0], returncode, stdout, stderr),
    )
    assert probe_journal(config)["ok"] is False


def test_probe_verifies_system_scope_and_uses_consistent_locale(config, monkeypatch):
    def run(command, **kwargs):
        assert "--system" in command
        assert kwargs["env"]["LC_ALL"] == "C"
        assert kwargs["timeout"] == 10
        return subprocess.CompletedProcess(command, 0, '{"__CURSOR":"verified"}\n', "")

    monkeypatch.setattr("yggdrasil_ids.source.subprocess.run", run)
    assert probe_journal(config)["ok"] is True


def test_cursor_validation_rejects_nearest_entry_instead_of_silently_skipping(config, monkeypatch):
    collector = JournalCollector(config, AnalysisEngine(config))

    def run(command, **kwargs):
        assert "--cursor=missing-cursor" in command
        assert "--lines=+1" in command
        return subprocess.CompletedProcess(command, 0, '{"__CURSOR":"nearest-other-cursor"}', "")

    monkeypatch.setattr("yggdrasil_ids.source.subprocess.run", run)
    assert collector._cursor_exists("missing-cursor") is False


def test_single_writer_lock_blocks_competing_collector_and_releases(config):
    with CollectorLock(config.database_path):
        with pytest.raises(RuntimeError, match="allerede"):
            with CollectorLock(config.database_path):
                pytest.fail("second lock must not be acquired")
    with CollectorLock(config.database_path):
        pass


def test_collector_lock_does_not_follow_symlink(config, tmp_path):
    target = tmp_path / "unrelated"
    target.write_text("preserve")
    config.database_path.with_suffix(config.database_path.suffix + ".lock").symlink_to(target)
    with pytest.raises(OSError):
        with CollectorLock(config.database_path):
            pytest.fail("symlink lock must not be acquired")
    assert target.read_text() == "preserve"


def test_fake_journal_stream_updates_history_heartbeat_and_stops_cleanly(config, tmp_path):
    executable = fake_journal(
        tmp_path, b"\n".join(json.dumps(record(i)).encode() for i in (1, 2)) + b"\n"
    )
    config = replace(config, collector=replace(config.collector, executable=str(executable)))
    engine = AnalysisEngine(config)
    stop = threading.Event()
    seen = stop_after_records(engine, stop, 2)
    states = []
    original = engine.heartbeat

    def heartbeat(state="running", message=""):
        states.append(state)
        original(state, message)

    engine.heartbeat = heartbeat
    JournalCollector(config, engine).run(stop)
    assert len(seen) == 2
    assert engine.repository.list_events()["total"] == 2
    assert engine.repository.get_state("cursor") == "cursor-2"
    assert states[0] == "starting"
    assert "running" in states
    assert states[-1] == "stopped"


def test_stale_cursor_sets_explicit_gap_and_uses_time_overlap(config, tmp_path, monkeypatch):
    executable = fake_journal(tmp_path, json.dumps(record(1)).encode() + b"\n")
    config = replace(config, collector=replace(config.collector, executable=str(executable)))
    engine = AnalysisEngine(config)
    engine.repository.set_state("cursor", "expired-cursor")
    engine.repository.set_state("cursor_timestamp", NOW - 50)
    collector = JournalCollector(config, engine)
    monkeypatch.setattr(collector, "_cursor_exists", lambda cursor: False)
    calls = []
    original_command = collector.command

    def command(cursor=None, since=None):
        calls.append((cursor, since))
        return original_command(cursor, since)

    monkeypatch.setattr(collector, "command", command)
    stop = threading.Event()
    stop_after_records(engine, stop, 1)
    collector.run(stop)
    assert calls == [(None, NOW - 50 - max(config.rules.window_seconds, config.ml.window_seconds))]
    assert engine.repository.get_state("data_gap")["message"]
    assert engine.repository.get_state("cursor") == "cursor-1"


def test_failed_access_probe_is_visible_and_does_not_spawn_reader(config, monkeypatch):
    engine = AnalysisEngine(config)
    monkeypatch.setattr(
        "yggdrasil_ids.source.probe_journal", lambda config: {"ok": False, "message": "no access"}
    )
    with pytest.raises(PermissionError, match="no access"):
        JournalCollector(config, engine).run()
    assert engine.repository.get_state("collector")["state"] == "error"


def test_unexpected_journal_exit_retains_data_and_sets_error_state(config, tmp_path):
    executable = fake_journal(
        tmp_path,
        json.dumps(record(1)).encode() + b"\n",
        linger=False,
        code=7,
        stderr="simulated source error",
    )
    config = replace(config, collector=replace(config.collector, executable=str(executable)))
    engine = AnalysisEngine(config)
    with pytest.raises(RuntimeError, match="7"):
        JournalCollector(config, engine).run()
    assert engine.repository.list_events()["total"] == 1
    assert engine.repository.get_state("collector")["state"] == "error"


def test_stream_discards_one_oversized_record_once_and_recovers_at_next_line(config, tmp_path):
    payload = b"x" * 150_000 + b"\n" + json.dumps(record(1)).encode() + b"\n"
    executable = fake_journal(tmp_path, payload)
    config = replace(
        config, collector=CollectorConfig(max_record_bytes=1024, executable=str(executable))
    )
    engine = AnalysisEngine(config)
    stop = threading.Event()
    stop_after_records(engine, stop, 1)
    JournalCollector(config, engine).run(stop)
    counts = engine.repository.get_state("counters")
    assert counts["malformed"] == 1
    assert counts["events"] == 1


def test_stream_deep_invalid_json_does_not_prevent_next_valid_event(config, tmp_path):
    payload = b"[" * 1500 + b"0" + b"]" * 1500 + b"\n" + json.dumps(record(1)).encode() + b"\n"
    executable = fake_journal(tmp_path, payload)
    config = replace(config, collector=replace(config.collector, executable=str(executable)))
    engine = AnalysisEngine(config)
    stop = threading.Event()
    stop_after_records(engine, stop, 1)
    JournalCollector(config, engine).run(stop)
    counts = engine.repository.get_state("counters")
    assert counts["malformed"] == 1
    assert counts["events"] == 1


def test_network_opt_in_uses_disjoint_kernel_match_without_relaxing_ssh(config):
    from yggdrasil_ids.config import NetworkConfig

    existing = JournalCollector(config, AnalysisEngine(config)).command()
    assert "+" not in existing
    enabled = replace(config, network=NetworkConfig(enabled=True))
    cmd = JournalCollector(enabled, AnalysisEngine(enabled)).command()
    assert cmd[-6:] == [
        "_COMM=sshd",
        "_COMM=sshd-session",
        "_COMM=sshd-auth",
        "_UID=0",
        "+",
        "_TRANSPORT=kernel",
    ]
    assert "_TRANSPORT" in next(
        value for value in cmd if value.startswith("--output-fields=")
    )


def test_mixed_fake_journal_stream_keeps_ssh_and_firewall_separate(config, tmp_path):
    from yggdrasil_ids.config import NetworkConfig

    ufw = {
        "_TRANSPORT": "kernel",
        "__CURSOR": "kernel-1",
        "__REALTIME_TIMESTAMP": str(int(NOW * 1_000_000)),
        "MESSAGE": (
            "[UFW BLOCK] IN=wlan0 OUT= SRC=192.0.2.55 DST=192.0.2.92 "
            "LEN=60 PROTO=TCP SPT=40000 DPT=22 SYN"
        ),
    }
    payload = b"\n".join(json.dumps(item).encode() for item in [record(1), ufw]) + b"\n"
    executable = fake_journal(tmp_path, payload)
    config = replace(
        config,
        network=NetworkConfig(enabled=True),
        collector=replace(config.collector, executable=str(executable)),
    )
    engine = AnalysisEngine(config)
    stop = threading.Event()
    stop_after_records(engine, stop, 2)
    JournalCollector(config, engine).run(stop)
    assert engine.repository.list_events()["total"] == 1
    with engine.repository.reader() as db:
        assert db.execute("SELECT COUNT(*) FROM firewall_events").fetchone()[0] == 1
        assert db.execute("SELECT COUNT(*) FROM records").fetchone()[0] == 1
        assert db.execute("SELECT COUNT(*) FROM observations").fetchone()[0] == 1
    assert engine.repository.get_state("cursor") == "kernel-1"
