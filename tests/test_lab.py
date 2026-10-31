"""Held-out demonstration data must remain separate from model input."""

import json

import pytest

from yggdrasil_ids.config import MLConfig, RulesConfig
from yggdrasil_ids.lab import _metrics, evaluate_lab, generate_lab, prepare_rows
from yggdrasil_ids.ml import IsolationForestDetector
from yggdrasil_ids.ssh import SSHParser

ANCHOR = 1_793_480_000


def records(path):
    return [json.loads(line) for line in path.read_text().splitlines()]


def auth_events(path):
    parser = SSHParser()
    return [
        parsed.event
        for raw in records(path)
        if (parsed := parser.parse(raw, namespace="lab")).event is not None
    ]


def test_generation_is_reproducible_and_contains_no_label_fields(tmp_path):
    first = generate_lab(tmp_path / "first", anchor=ANCHOR, seed=42)
    second = generate_lab(tmp_path / "second", anchor=ANCHOR, seed=42)
    for key in first:
        assert first[key].read_bytes() == second[key].read_bytes()
    for split in ("train", "validation", "test"):
        for raw in records(first[f"{split}_path"]):
            assert not ({"expected", "label", "scenario", "split"} & set(raw))
            assert raw["_UID"] == "0"
            assert raw["_COMM"] == "sshd-session"
    labels = json.loads(first["labels_path"].read_text())
    assert all(item["expected"] == "normal" for item in labels["splits"]["train"])
    assert labels["kind"] == "synthetic_laboratory"


def test_splits_are_whole_scenarios_with_purged_time_gaps(tmp_path):
    paths = generate_lab(tmp_path, anchor=ANCHOR)
    split_events = {
        split: auth_events(paths[f"{split}_path"]) for split in ("train", "validation", "test")
    }
    for earlier, later in (("train", "validation"), ("validation", "test")):
        assert split_events[later][0].timestamp - split_events[earlier][-1].timestamp > 600
        assert not (
            {event.cursor for event in split_events[earlier]}
            & {event.cursor for event in split_events[later]}
        )
    assert all(ANCHOR - 86400 < event.timestamp < ANCHOR for event in split_events["test"])
    labels = json.loads(paths["labels_path"].read_text())
    scenarios = labels["scenarios"]
    for earlier, later in zip(scenarios, scenarios[1:]):
        assert later["first_timestamp"] - earlier["last_timestamp"] > 600


def test_prepare_ignores_pam_and_exact_duplicates(tmp_path):
    paths = generate_lab(tmp_path, anchor=ANCHOR)
    raw = records(paths["train_path"])
    parsed = auth_events(paths["train_path"])
    expected = prepare_rows(paths["train_path"])
    assert len(expected) == len(parsed) >= 80
    assert len(raw) > len(parsed)
    assert all(len(row) == 6 for row in expected)
    last_auth = next(
        record for record in reversed(raw) if record["MESSAGE"].startswith(("Accepted", "Failed"))
    )
    with paths["train_path"].open("a") as handle:
        handle.write(json.dumps(last_auth) + "\n")
    assert prepare_rows(paths["train_path"]) == expected


def test_labels_have_no_influence_on_prepared_features(tmp_path):
    paths = generate_lab(tmp_path, anchor=ANCHOR)
    before = prepare_rows(paths["test_path"])
    paths["labels_path"].write_text("deliberately not even JSON")
    assert prepare_rows(paths["test_path"]) == before


def test_empty_malformed_or_reversed_input_fails_clearly(tmp_path):
    path = tmp_path / "empty.jsonl"
    path.write_text("")
    with pytest.raises(ValueError, match="ingen gyldige"):
        prepare_rows(path)
    path.write_text("{bad json}\n")
    with pytest.raises(ValueError, match="linje 1"):
        prepare_rows(path)
    paths = generate_lab(tmp_path / "fixture", anchor=ANCHOR)
    path.write_text("\n".join(reversed(paths["test_path"].read_text().splitlines())) + "\n")
    with pytest.raises(ValueError, match="kronologisk"):
        prepare_rows(path)
    raw = records(paths["test_path"])[0]
    raw["__REALTIME_TIMESTAMP"] = "broken"
    path.write_text(json.dumps(raw) + "\n")
    with pytest.raises(ValueError, match="ugyldig SSH-post"):
        prepare_rows(path)


def test_evaluation_counts_denominators_and_saved_artifacts_are_consistent(tmp_path):
    paths = generate_lab(tmp_path, anchor=ANCHOR)
    report = evaluate_lab(tmp_path, ml=MLConfig(n_estimators=16))
    labels = json.loads(paths["labels_path"].read_text())
    assert report["kind"] == "synthetic_laboratory"
    assert report["model"]["sample_count"] == len(labels["splits"]["train"])
    for split in ("validation", "test"):
        positive = sum(
            item["expected"] == "simulated_suspicious" for item in labels["splits"][split]
        )
        total = len(labels["splits"][split])
        assert report[split]["event_count"] == total
        assert sum(scenario["event_count"] for scenario in report[split]["scenarios"]) == total
        for method in ("rules", "ml"):
            item = report[split][method]
            assert item["tp"] + item["fp"] + item["tn"] + item["fn"] == total
            assert item["tp"] + item["fn"] == positive
            assert item["denominators"]["recall"] == positive
            assert item["denominators"]["false_positive_rate"] == total - positive
            assert item["denominators"]["precision"] == item["tp"] + item["fp"]
    assert json.loads((tmp_path / "report.json").read_text()) == json.loads(json.dumps(report))
    assert "Syntetisk softwaretest" in (tmp_path / "report.md").read_text()
    assert IsolationForestDetector.load(tmp_path / "lab-model.json").metadata == report["model"]


def test_only_train_rows_are_passed_to_model_training(tmp_path, monkeypatch):
    paths = generate_lab(tmp_path, anchor=ANCHOR)
    captured = []
    original = IsolationForestDetector.train

    def capture(rows, config, provenance):
        captured.append(rows)
        return original(rows, config, provenance)

    monkeypatch.setattr("yggdrasil_ids.lab.IsolationForestDetector.train", capture)
    evaluate_lab(tmp_path, ml=MLConfig(n_estimators=16))
    assert captured == [prepare_rows(paths["train_path"])]
    assert len(captured[0]) != len(prepare_rows(paths["test_path"]))


def test_scenario_labels_are_independent_of_detector_thresholds(tmp_path):
    generate_lab(tmp_path, anchor=ANCHOR)
    disabled_rules = RulesConfig(failure_threshold=1000, username_threshold=1000)
    report = evaluate_lab(tmp_path, rules=disabled_rules, ml=MLConfig(n_estimators=16))
    assert report["test"]["rules"]["predicted_positive"] == 0
    assert report["test"]["rules"]["expected_positive"] > 0
    assert report["test"]["rules"]["fn"] == report["test"]["rules"]["expected_positive"]
    assert report["test"]["rules"]["precision"] is None


def test_training_sidecar_cannot_silently_contain_attack_labels(tmp_path):
    paths = generate_lab(tmp_path, anchor=ANCHOR)
    labels = json.loads(paths["labels_path"].read_text())
    labels["splits"]["train"][0]["expected"] = "simulated_suspicious"
    paths["labels_path"].write_text(json.dumps(labels))
    with pytest.raises(ValueError, match="Træningsdelen"):
        evaluate_lab(tmp_path, ml=MLConfig(n_estimators=16))


def test_partial_dataset_is_not_overwritten(tmp_path):
    path = tmp_path / "train.jsonl"
    path.write_text("original user input\n")
    with pytest.raises(ValueError, match="mangler inputfiler"):
        evaluate_lab(tmp_path)
    assert path.read_text() == "original user input\n"
    assert not (tmp_path / "test.jsonl").exists()


def test_window_larger_than_split_gap_is_rejected(tmp_path):
    generate_lab(tmp_path, anchor=ANCHOR)
    with pytest.raises(ValueError, match="tidsafstand"):
        evaluate_lab(tmp_path, ml=MLConfig(window_seconds=3600, n_estimators=16))


def test_metrics_keep_undefined_denominators_visible():
    result = _metrics([False, False], [False, False])
    assert result["precision"] is None
    assert result["recall"] is None
    assert result["false_positive_rate"] == 0
    assert result["denominators"] == {"precision": 0, "recall": 0, "false_positive_rate": 2}


@pytest.mark.parametrize(
    "seed,anchor", [(True, ANCHOR), (-1, ANCHOR), (42, float("nan")), (42, True), (42, 0)]
)
def test_invalid_generation_parameters_are_rejected(tmp_path, seed, anchor):
    with pytest.raises(ValueError):
        generate_lab(tmp_path, anchor=anchor, seed=seed)
