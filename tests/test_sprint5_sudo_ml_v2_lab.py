"""Causality, grouping, calibration boundaries and private research output."""

from __future__ import annotations

import importlib.util
import sys
from dataclasses import replace
from pathlib import Path

import pytest

from yggdrasil_ids.sudo_ml import SudoAttempt


@pytest.fixture(scope="module")
def lab():
    root = Path(__file__).resolve().parents[1]
    # The research tool deliberately imports the unchanged original lab.
    for name in ("sprint5_sudo_ml_lab", "sprint5_sudo_ml_v2_lab"):
        spec = importlib.util.spec_from_file_location(name, root / "deploy" / f"{name}.py")
        obj = importlib.util.module_from_spec(spec)
        sys.modules[name] = obj
        spec.loader.exec_module(obj)
    return sys.modules["sprint5_sudo_ml_v2_lab"]


def attempt(t, pid, uid="1000", outcome="failure"):
    return SudoAttempt(float(t), "b" * 32, uid, pid, outcome)


def test_confirmation_requires_consecutive_same_group_anomalies_and_time_limit(lab):
    rows = [attempt(1, 1), attempt(2, 2), attempt(3, 3)]
    # With score threshold 0.8, an intervening normal process breaks confirmation.
    assert lab.evidence_score(rows, [0.9, 0.2, 0.95], 2) == 0.2
    assert lab.evidence_score(rows, [0.9, 0.85, 0.2], 2) == 0.85
    assert lab.evidence_score([rows[0], replace(rows[1], uid="1001")], [0.9, 0.9], 2) is None
    assert lab.evidence_score([attempt(1, 1), attempt(901, 2)], [0.9, 0.9], 2) is None
    assert lab.evidence_score([attempt(1, 1), attempt(900, 2)], [0.9, 0.9], 2) == 0.9
    with pytest.raises(ValueError):
        lab.evidence_score(rows, [float("nan")] * 3, 2)


def test_features_are_causal_and_900s_window_preserves_spaced_failures(lab):
    case = lab.scenario("slow_auth_failure", 30000)
    first_only = replace(case, signals=case.signals[:2])
    for variant in lab.VARIANTS:
        assert lab.features(first_only, variant)[0] == lab.features(case, variant)[0]
    rows = lab.features(case, "counts_300_900")
    assert rows[-1][1] == 1
    assert rows[-1][6] == 2


def test_feature_grouping_does_not_leak_other_users_or_boots(lab):
    case = lab.scenario("sudo_auth_burst", 30000)
    other_uid = "1001" if case.signals[0].uid == "1000" else "1000"
    changed = replace(
        case,
        signals=tuple(replace(s, uid=other_uid) if s.pid == 10002 else s for s in case.signals),
    )
    rows = lab.features(changed, "counts_300_900")
    assert rows[1][:5] == [1, 1, 0, 0, 1]
    assert rows[-1][0] == len(rows) - 1


def test_all_splits_are_independent_and_holdout_contains_declared_counts(lab):
    training, validation, historical = lab.create_splits()
    holdout = lab.fresh_holdout()
    stress = lab.stress_cases()
    seeds = [s.seed for cases in (training, validation, historical, holdout, stress) for s in cases]
    assert len(seeds) == len(set(seeds))
    assert len(holdout) == 900
    assert sum(s.suspicious for s in holdout) == 400
    assert len(stress) == 100 and not any(s.suspicious for s in stress)


def test_simple_rule_comparator_and_benign_corrections(lab):
    assert lab.simple_long_rule(lab.scenario("slow_auth_failure", 30000))
    assert lab.simple_long_rule(lab.scenario("sudoers_denial", 30100))
    assert not lab.simple_long_rule(lab.stress_cases()[0])


def test_validation_selection_has_no_holdout_input(lab, monkeypatch):
    def forbidden():
        raise AssertionError("Selection must not read the fresh holdout")

    monkeypatch.setattr(lab, "fresh_holdout", forbidden)
    training, validation, _ = lab.create_splits()
    selected, candidates, _ = lab.select_candidate(training, validation)
    assert len(candidates) == 8
    assert selected["validation"]["false_positive_rate"] <= lab.VALIDATION_FPR_BUDGET


def test_output_private_non_deployable_and_existing_directory_not_overwritten(lab, tmp_path):
    import json

    directory = tmp_path / "isolated"
    report = lab.save_research(directory)
    assert report["production_changes"] is False
    assert report["real_journal_rows_read"] == 0
    assert report["discord_messages_sent"] == 0
    assert report["training_normal_only"] is True
    assert report["historical_test_descriptive_only"]["metrics"]["original_if"]["tp"] == 12
    assert report["historical_test_descriptive_only"]["metrics"]["original_if"]["fp"] == 4
    recipe = json.loads((directory / "research-recipe.json").read_text())
    assert recipe["deployable"] is False
    signature = recipe.pop("sha256")
    assert signature == lab.digest(recipe)
    assert directory.stat().st_mode & 0o077 == 0
    assert (directory / "report.json").stat().st_mode & 0o077 == 0
    with pytest.raises(FileExistsError):
        lab.save_research(directory)
