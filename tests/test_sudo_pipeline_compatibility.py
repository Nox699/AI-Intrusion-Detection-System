"""Compare raw-journal/export/scoring and synthetic/scoring representations."""

import importlib.util
import sys
from pathlib import Path

import pytest

from yggdrasil_ids.sudo_ml import attempts_from_signals, feature_rows
from yggdrasil_ids.sudo_rules import SudoSignal

MESSAGES = {
    "command_invoked": "test-user : TTY=pts/1 ; PWD=/tmp ; USER=root ; COMMAND=/usr/bin/true",
    "pam_session_opened": "pam_unix(sudo:session): session opened for user root",
    "pam_session_closed": "pam_unix(sudo:session): session closed for user root",
    "pam_auth_failure": "pam_unix(sudo:auth): authentication failure;",
    "incorrect_password": "test-user : 1 incorrect password attempt",
    "not_in_sudoers": "test-user is not in the sudoers file",
}


@pytest.fixture(scope="module")
def modules():
    root = Path(__file__).resolve().parents[1]
    names = (
        "sprint5_sudo_ml_lab",
        "sprint5_sudo_ml_v2_lab",
        "sprint5_sudo_mixed_ml_lab",
        "sudo_real_export",
    )
    for name in names:
        spec = importlib.util.spec_from_file_location(name, root / "deploy" / f"{name}.py")
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
    return sys.modules[names[0]], sys.modules[names[2]], sys.modules[names[3]]


def raw_records(signals):
    return [
        {
            "_EXE": "/usr/bin/sudo",
            "_UID": s.uid,
            "_PID": str(s.pid),
            "_BOOT_ID": s.boot_id,
            "__CURSOR": s.cursor,
            "__REALTIME_TIMESTAMP": str(round(s.timestamp * 1e6)),
            "MESSAGE": MESSAGES[s.kind],
        }
        for s in signals
    ]


def test_all_original_scenarios_have_equivalent_export_and_synthetic_features(modules):
    original, mixed, exporter = modules
    checked = 0
    for cases in original.create_splits():
        for case in cases:
            exported = exporter.aggregate(raw_records(case.signals))
            actual = mixed.real_bundle(exported["processes"])[1]
            assert actual == mixed.scenario_bundle(case)[1]
            # The timestamp alignment does not change the old benchmark's features.
            legacy = [row[:5] for row in feature_rows(attempts_from_signals(case.signals))]
            assert actual == legacy
            checked += 1
    assert checked == 308


def test_success_close_record_does_not_change_window_boundary(modules):
    original, mixed, exporter = modules
    # A failure at t=1000 and success at t=1299.95 must share the 300s window.
    # Counting the close at t=1300.05 instead would incorrectly evict the failure.
    signals = (
        SudoSignal("a", 1000.0, "b" * 32, "1000", 1, "pam_auth_failure"),
        SudoSignal("b", 1299.95, "b" * 32, "1000", 2, "command_invoked"),
        SudoSignal("c", 1300.05, "b" * 32, "1000", 2, "pam_session_closed"),
    )
    case = original.Scenario("boundary", False, 999999, signals)
    exported = exporter.aggregate(raw_records(signals))
    real = mixed.real_bundle(exported["processes"])[1]
    assert mixed.scenario_bundle(case)[1] == real
    assert real[-1] == [2, 1, 0, 1, 0.5]
    legacy = [row[:5] for row in feature_rows(attempts_from_signals(signals))]
    assert legacy[-1] == [1, 0, 0, 1, 0]
