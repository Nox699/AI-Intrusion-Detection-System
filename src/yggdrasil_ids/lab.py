"""Reproducible, isolated software demonstrations with held-out scenarios.

Fixtures are synthetic journal records and use documentation-only IP ranges.
Labels are a separate sidecar keyed by journal cursor. They describe scenario
intent, not the output of either detector, and never enter the feature matrix.
Results here are not a benchmark of the real server or of real-world attacks.
"""

from __future__ import annotations

import hashlib
import json
import math
import random
import time
from collections import Counter, defaultdict, deque
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .config import MLConfig, RulesConfig
from .domain import SSHEvent
from .features import SSHFeatureBuilder
from .ml import MAX_TRAINING_ROWS, IsolationForestDetector
from .rules import SSHRuleDetector
from .ssh import SSHParser

NAMES = {
    "train_path": "train.jsonl",
    "validation_path": "validation.jsonl",
    "test_path": "test.jsonl",
    "labels_path": "labels.json",
}
NORMAL_SOURCES = ("192.0.2.10", "192.0.2.11")
SUSPICIOUS_SOURCE = "198.51.100.23"
NEW_NORMAL_SOURCE = "203.0.113.44"
MAX_INPUT_RECORDS = 50_000
MAX_INPUT_BYTES = 64 * 1024 * 1024
MAX_LINE_BYTES = 65_536
LIMITATIONS = [
    "Syntetiske software- og demonstrationsdata; resultaterne er ikke en sikkerhedsbenchmark for Pi’en.",
    "En observation er ét autentificeringsresultat. Overlappende vinduer gør observationerne afhængige.",
    "Scenariernes hensigt er kendt fra forsøget. Logs alene beviser ikke ondsindet hensigt.",
    "Træningen bruger kun den separate normaldel. Validering og sluttest ændrer ikke modellen eller alarmgrænserne.",
    "Første forsøg i et simuleret angrebsforløb kan ligge under reglernes tærskel og tæller derfor som oversete hændelser.",
    "Precision, recall og falsk positiv-rate beskriver kun disse konstruerede forløb og deres valgte fordeling.",
]


def _utc(value: float) -> str:
    return datetime.fromtimestamp(value, timezone.utc).isoformat(timespec="seconds")


def _write_json(path: Path, value: Any) -> None:
    path.write_text(
        json.dumps(value, indent=2, ensure_ascii=False, allow_nan=False) + "\n", encoding="utf-8"
    )


def _normal_actions(index: int, rng: random.Random) -> list[tuple[str, str]]:
    user = "labuser" if index % 3 else "backup"
    result = [("success", user)] * (3 + index % 6)
    if index % 6 == 2:
        result[0] = ("success", "backup" if user == "labuser" else "labuser")
    if index % 4 in {1, 3}:
        result += [("failure", user)] * (1 + index % 2)
    rng.shuffle(result)
    return result


def _held_out_specs(split: str) -> list[tuple[str, str, str, list[tuple[str, str]]]]:
    """Scenario intent is fixed independently of thresholds or model results."""
    extra = 0 if split == "test" else 1
    return [
        ("normal_login", "normal", NORMAL_SOURCES[0], [("success", "labuser")] * (3 + extra)),
        (
            "legitimate_typos",
            "normal",
            NORMAL_SOURCES[1],
            [("failure", "backup")] * 2 + [("success", "backup")],
        ),
        (
            "legitimate_maintenance",
            "normal",
            NORMAL_SOURCES[0],
            [("success", "labuser")] * (10 + extra) + [("failure", "labuser")],
        ),
        ("legitimate_new_source", "normal", NEW_NORMAL_SOURCE, [("success", "labuser")]),
        (
            "simulated_failed_burst",
            "simulated_suspicious",
            SUSPICIOUS_SOURCE,
            [("failure", "labuser")] * (10 + extra),
        ),
        (
            "simulated_user_spray",
            "simulated_suspicious",
            SUSPICIOUS_SOURCE,
            [
                ("failure", name)
                for name in [
                    "admin",
                    "test",
                    "oracle",
                    "guest",
                    "ubuntu",
                    "deploy",
                    "postgres",
                    "support",
                ]
            ],
        ),
        (
            "simulated_unexpected_success",
            "simulated_suspicious",
            SUSPICIOUS_SOURCE,
            [("success", "labuser")],
        ),
        ("legitimate_after_tests", "normal", NORMAL_SOURCES[0], [("success", "backup")] * 4),
    ]


def generate_lab(directory: Path, anchor: float | None = None, seed: int = 42) -> dict[str, Path]:
    """Write deterministic train/validation/test JSONL and independent labels.

    With a fixed anchor and seed all four files are byte-for-byte reproducible.
    Training spans nearly 24 hours. Validation and final test follow, with at
    least 600 seconds of separation between complete scenarios. Final test is
    within the four hours before the anchor. No command is sent to a real host.
    """
    if type(seed) is not int or not 0 <= seed <= 2**32 - 1:
        raise ValueError("seed skal være et ikke-negativt 32-bit heltal.")
    anchor = time.time() if anchor is None else anchor
    if (
        isinstance(anchor, bool)
        or not isinstance(anchor, (int, float))
        or not math.isfinite(anchor)
        or not 200_000 <= anchor < 253402100000
    ):
        raise ValueError("Labdata kræver et gyldigt UTC-ankertidspunkt.")
    anchor = float(int(anchor))
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    paths = {key: directory / name for key, name in NAMES.items()}
    rng = random.Random(seed)
    records: dict[str, list[dict[str, str]]] = {key: [] for key in ("train", "validation", "test")}
    labels: dict[str, Any] = {
        "schema_version": 1,
        "kind": "synthetic_laboratory",
        "seed": seed,
        "anchor": anchor,
        "anchor_utc": _utc(anchor),
        "label_key": "journal_cursor",
        "observation_unit": "one_accepted_or_failed_authentication",
        "splits": {key: [] for key in records},
        "scenarios": [],
        "limitations": list(LIMITATIONS),
    }
    beginning = anchor - (48 * 1800 + 16 * 720)

    def add_scenario(
        split: str,
        index: int,
        start: float,
        name: str,
        expected: str,
        source: str,
        actions: list[tuple[str, str]],
    ) -> None:
        scenario = f"{split}_{name}"
        timestamps = []
        for sequence, (outcome, username) in enumerate(actions):
            timestamp = start + sequence * 4 + rng.randint(0, 2)
            timestamps.append(timestamp)
            cursor = f"lab-{seed}-{split}-{index:03d}-{sequence:03d}-auth"
            pid = str(10_000 + index * 100 + sequence)
            port = rng.randint(40_000, 60_000)
            action = "Accepted" if outcome == "success" else "Failed"
            invalid = "invalid user " if username not in {"labuser", "backup"} else ""
            message = f"{action} publickey for {invalid}{username} from {source} port {port} ssh2"
            record = {
                "__CURSOR": cursor,
                "__REALTIME_TIMESTAMP": str(int(timestamp * 1_000_000)),
                "_UID": "0",
                "_COMM": "sshd-session",
                "SYSLOG_IDENTIFIER": "sshd-session",
                "_SYSTEMD_UNIT": "ssh.service",
                "_HOSTNAME": "lab-yggdrasil",
                "_PID": pid,
                "MESSAGE": message,
            }
            records[split].append(record)
            labels["splits"][split].append(
                {
                    "cursor": cursor,
                    "timestamp": timestamp,
                    "scenario": scenario,
                    "expected": expected,
                }
            )
            # These records are context, not extra authentications or labels.
            if outcome == "success" and sequence % 2 == 0:
                records[split].append(
                    {
                        **record,
                        "__CURSOR": cursor.removesuffix("auth") + "pam",
                        "__REALTIME_TIMESTAMP": str(int((timestamp + 0.125) * 1_000_000)),
                        "MESSAGE": f"pam_unix(sshd:session): session opened for user {username}(uid=1000) by {username}(uid=0)",
                    }
                )
        labels["scenarios"].append(
            {
                "id": scenario,
                "split": split,
                "expected": expected,
                "source_ip": source,
                "event_count": len(actions),
                "first_timestamp": min(timestamps),
                "last_timestamp": max(timestamps),
            }
        )

    for index in range(48):
        add_scenario(
            "train",
            index,
            beginning + index * 1800,
            f"normal_{index:02d}",
            "normal",
            NORMAL_SOURCES[index % 2],
            _normal_actions(index, rng),
        )
    for split_number, split in enumerate(("validation", "test")):
        for index, (name, expected, source, actions) in enumerate(_held_out_specs(split)):
            start = beginning + 48 * 1800 + (split_number * 8 + index) * 720
            add_scenario(split, index, start, name, expected, source, actions)
    for split, items in records.items():
        items.sort(key=lambda item: int(item["__REALTIME_TIMESTAMP"]))
        content = "".join(
            json.dumps(item, sort_keys=True, ensure_ascii=False) + "\n" for item in items
        )
        paths[f"{split}_path"].write_text(content, encoding="utf-8")
    _write_json(paths["labels_path"], labels)
    return paths


def _reject_constant(value: str) -> None:
    raise ValueError(f"Ugyldig numerisk JSON-konstant: {value}")


def _read_events(path: Path) -> list[SSHEvent]:
    parser = SSHParser()
    events: list[SSHEvent] = []
    seen: dict[str, SSHEvent] = {}
    previous = float("-inf")
    consumed_bytes = 0
    with Path(path).open("rb") as handle:
        line_number = 0
        while raw := handle.readline(MAX_LINE_BYTES + 1):
            line_number += 1
            consumed_bytes += len(raw)
            if (
                len(raw) > MAX_LINE_BYTES
                or consumed_bytes > MAX_INPUT_BYTES
                or line_number > MAX_INPUT_RECORDS
            ):
                raise ValueError(f"{path.name}: inputgrænse overskredet ved linje {line_number}.")
            if not raw.strip():
                continue
            try:
                record = json.loads(raw, parse_constant=_reject_constant)
            except (ValueError, UnicodeError, RecursionError) as exc:
                raise ValueError(f"{path.name}: ugyldig JSON ved linje {line_number}.") from exc
            result = parser.parse(record, namespace="lab")
            if result.status == "malformed":
                raise ValueError(
                    f"{path.name}: ugyldig SSH-post ved linje {line_number}: {result.reason}"
                )
            if result.event is None:
                continue
            event = result.event
            if event.event_id in seen:
                if seen[event.event_id] != event:
                    raise ValueError(
                        f"{path.name}: modstridende hændelses-ID ved linje {line_number}."
                    )
                continue
            if event.timestamp < previous:
                raise ValueError(
                    f"{path.name}: hændelserne er ikke i kronologisk rækkefølge ved linje {line_number}."
                )
            previous = event.timestamp
            events.append(event)
            seen[event.event_id] = event
            if len(events) > MAX_TRAINING_ROWS:
                raise ValueError(
                    f"{path.name}: højst {MAX_TRAINING_ROWS} autentificeringshændelser understøttes."
                )
    if not events:
        raise ValueError(f"{path.name}: ingen gyldige SSH-autentificeringer blev fundet.")
    return events


def _feature_rows(events: list[SSHEvent], window_seconds: int) -> list[list[float]]:
    builder = SSHFeatureBuilder(window_seconds)
    history: dict[str, deque[SSHEvent]] = defaultdict(deque)
    rows = []
    for event in events:
        group = history[event.source_ip]
        while group and group[0].timestamp <= event.timestamp - window_seconds:
            group.popleft()
        group.append(event)
        rows.append(builder.build(group, event))
    return rows


def prepare_rows(path: Path, window_seconds: int = 300) -> list[list[float]]:
    """Turn chronologically ordered journal JSONL into bounded feature rows.

    PAM/context rows are ignored and exact duplicate auth rows are deduplicated.
    Malformed authentication records, reversed event times and empty input fail
    with a concrete error. This function does not read labels or train a model.
    """
    return _feature_rows(_read_events(Path(path)), window_seconds)


def _metrics(expected: list[bool], predicted: list[bool]) -> dict[str, Any]:
    tp = sum(actual and result for actual, result in zip(expected, predicted, strict=True))
    fp = sum(not actual and result for actual, result in zip(expected, predicted, strict=True))
    tn = sum(not actual and not result for actual, result in zip(expected, predicted, strict=True))
    fn = sum(actual and not result for actual, result in zip(expected, predicted, strict=True))
    return {
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "total": len(expected),
        "expected_positive": tp + fn,
        "predicted_positive": tp + fp,
        "precision": tp / (tp + fp) if tp + fp else None,
        "recall": tp / (tp + fn) if tp + fn else None,
        "false_positive_rate": fp / (fp + tn) if fp + tn else None,
        "denominators": {"precision": tp + fp, "recall": tp + fn, "false_positive_rate": fp + tn},
    }


def _evaluate_events(
    events: list[SSHEvent],
    labels: dict[str, dict[str, Any]],
    rules: RulesConfig,
    model: IsolationForestDetector,
    window_seconds: int,
) -> dict[str, Any]:
    detector = SSHRuleDetector(rules)
    builder = SSHFeatureBuilder(window_seconds)
    history: dict[str, deque[SSHEvent]] = defaultdict(deque)
    observations: list[dict[str, Any]] = []
    findings = Counter()
    for event in events:
        group = history[event.source_ip]
        cutoff = event.timestamp - max(rules.window_seconds, window_seconds)
        while group and group[0].timestamp <= cutoff:
            group.popleft()
        group.append(event)
        rule_findings = detector.detect(event, group)
        result = model.score(builder.build(group, event))
        expected = labels[event.cursor]
        findings.update(finding.detector_id for finding in rule_findings)
        observations.append(
            {
                "cursor": event.cursor,
                "event_id": event.event_id,
                "timestamp": event.timestamp,
                "source_ip": event.source_ip,
                "username": event.username,
                "outcome": event.outcome,
                "scenario": expected["scenario"],
                "expected": expected["expected"],
                "expected_positive": expected["expected"] == "simulated_suspicious",
                "rule_alarm": bool(rule_findings),
                "rule_ids": [finding.detector_id for finding in rule_findings],
                "ml_alarm": result["is_anomaly"],
                "score": result["score"],
                "threshold": result["threshold"],
            }
        )
    scenarios: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for observation in observations:
        scenarios[observation["scenario"]].append(observation)

    def summarise(items: list[dict[str, Any]]) -> dict[str, Any]:
        actual = [item["expected_positive"] for item in items]
        return {
            "event_count": len(items),
            "rules": _metrics(actual, [item["rule_alarm"] for item in items]),
            "ml": _metrics(actual, [item["ml_alarm"] for item in items]),
        }

    return {
        **summarise(observations),
        "detector_findings": dict(findings),
        "scenarios": [{"name": name, **summarise(items)} for name, items in scenarios.items()],
        "observations": observations,
    }


def _read_labels(path: Path) -> dict[str, Any]:
    with path.open("rb") as handle:
        raw = handle.read(8 * 1024 * 1024 + 1)
    if len(raw) > 8 * 1024 * 1024:
        raise ValueError("Labellisten er for stor.")
    try:
        labels = json.loads(raw, parse_constant=_reject_constant)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise ValueError("Labellisten er ikke gyldig JSON.") from exc
    if (
        not isinstance(labels, dict)
        or type(labels.get("schema_version")) is not int
        or labels.get("schema_version") != 1
        or labels.get("kind") != "synthetic_laboratory"
    ):
        raise ValueError("Labellisten har et ukendt format.")
    if not isinstance(labels.get("splits"), dict) or set(labels["splits"]) != {
        "train",
        "validation",
        "test",
    }:
        raise ValueError("Labellisten skal indeholde train, validation og test.")
    return labels


def evaluate_lab(
    directory: Path, rules: RulesConfig | None = None, ml: MLConfig | None = None
) -> dict[str, Any]:
    """Train only on train.jsonl and report untouched validation/final tests.

    Generates a fixture set only if none of the four input files exists. Partial
    datasets fail explicitly instead of silently replacing existing evidence.
    The caller may select settings beforehand; neither held-out split tunes them.
    """
    directory = Path(directory)
    paths = {key: directory / name for key, name in NAMES.items()}
    present = [path.exists() for path in paths.values()]
    if not any(present):
        generate_lab(directory)
    elif not all(present):
        raise ValueError(
            "Labmappen mangler inputfiler; det eksisterende datasæt er ikke blevet erstattet."
        )
    rules = rules or RulesConfig(
        expected_sources=("192.0.2.10/32", "192.0.2.11/32"), expected_users=("labuser", "backup")
    )
    ml = ml or MLConfig()
    labels = _read_labels(paths["labels_path"])
    events = {
        split: _read_events(paths[f"{split}_path"]) for split in ("train", "validation", "test")
    }
    label_maps: dict[str, dict[str, dict[str, Any]]] = {}
    all_cursors: set[str] = set()
    for split, items in events.items():
        entries = labels["splits"][split]
        if not isinstance(entries, list) or len(entries) > MAX_TRAINING_ROWS:
            raise ValueError(f"Ugyldig labelliste for {split}.")
        label_maps[split] = {}
        for item in entries:
            if (
                not isinstance(item, dict)
                or not isinstance(item.get("cursor"), str)
                or not isinstance(item.get("scenario"), str)
                or not isinstance(item.get("expected"), str)
                or item.get("expected") not in {"normal", "simulated_suspicious"}
            ):
                raise ValueError(f"Ugyldig hændelseslabel i {split}.")
            if item["cursor"] in label_maps[split]:
                raise ValueError(f"Dubleret label i {split}.")
            label_maps[split][item["cursor"]] = item
        cursors = {event.cursor for event in items}
        if "" in cursors or cursors != set(label_maps[split]):
            raise ValueError(f"Labels og autentificeringshændelser stemmer ikke overens i {split}.")
        if cursors & all_cursors:
            raise ValueError("Den samme journalhændelse optræder i flere datasæt.")
        all_cursors.update(cursors)
    if any(item["expected"] != "normal" for item in label_maps["train"].values()):
        raise ValueError("Træningsdelen må kun indeholde dokumenterede normale labforløb.")
    required_gap = 2 * max(rules.window_seconds, ml.window_seconds)
    for earlier, later in (("train", "validation"), ("validation", "test")):
        if events[later][0].timestamp - events[earlier][-1].timestamp <= required_gap:
            raise ValueError("Datasættene kræver en tidsafstand større end to observationsvinduer.")
    training_rows = _feature_rows(events["train"], ml.window_seconds)
    model = IsolationForestDetector.train(
        training_rows,
        ml,
        "Syntetiske normale SSH-labforløb fra train.jsonl; ingen validerings- eller testobservationer i træningen.",
    )
    model_path = directory / "lab-model.json"
    model.save(model_path)
    report = {
        "schema_version": 1,
        "kind": "synthetic_laboratory",
        "observation_unit": "one_accepted_or_failed_authentication",
        "evaluated_at": _utc(time.time()),
        "limitations": list(LIMITATIONS),
        "settings": {"rules": asdict(rules), "ml": asdict(ml)},
        "model": model.metadata,
        "splits": {
            split: {
                "event_count": len(items),
                "first_timestamp": items[0].timestamp,
                "last_timestamp": items[-1].timestamp,
                "first_utc": _utc(items[0].timestamp),
                "last_utc": _utc(items[-1].timestamp),
                "sha256": hashlib.sha256(paths[f"{split}_path"].read_bytes()).hexdigest(),
            }
            for split, items in events.items()
        },
        "labels_sha256": hashlib.sha256(paths["labels_path"].read_bytes()).hexdigest(),
        "validation": _evaluate_events(
            events["validation"], label_maps["validation"], rules, model, ml.window_seconds
        ),
        "test": _evaluate_events(
            events["test"], label_maps["test"], rules, model, ml.window_seconds
        ),
        "artifacts": {
            **NAMES,
            "model_path": model_path.name,
            "report_path": "report.json",
            "markdown_path": "report.md",
        },
    }
    _write_json(directory / "report.json", report)
    lines = [
        "# Laboratorietest af SSH detektion",
        "",
        "**Syntetisk softwaretest. Resultaterne dokumenterer disse konstruerede forløb og er ikke en sikkerhedsbenchmark for Raspberry Pi’en.**",
        "",
        f"Model: `{report['model']['version']}`. Træningsobservationer: {len(training_rows)}. Vindue: {ml.window_seconds} sekunder.",
        "",
        "Træning, validering og sluttest består af adskilte tidsperioder. Modellen trænes kun på normaldelen. Validering og test ændrer ikke indstillingerne.",
        "",
        "| Datasæt | Metode | TP | FP | TN | FN | Precision | Recall | Falsk positiv-rate |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]

    def percentage(value: float | None) -> str:
        return "Ikke defineret" if value is None else f"{100 * value:.1f} %"

    for split, title in (("validation", "Validering"), ("test", "Sluttest")):
        for method, method_title in (("rules", "Regler"), ("ml", "Isolation Forest")):
            item = report[split][method]
            lines.append(
                f"| {title} | {method_title} | {item['tp']} | {item['fp']} | {item['tn']} | {item['fn']} | {percentage(item['precision'])} | {percentage(item['recall'])} | {percentage(item['false_positive_rate'])} |"
            )
    lines += [
        "",
        "TP = opdaget simuleret mistænkelig hændelse; FP = alarm ved legitim aktivitet; TN = legitim aktivitet uden alarm; FN = overset simuleret mistænkelig hændelse.",
        "",
        "Precision = TP/(TP+FP). Recall = TP/(TP+FN). Falsk positiv-rate = FP/(FP+TN). Nævnerne og resultater pr. scenarie findes i report.json. Hændelser tælles før gruppering til alarmforløb.",
        "",
        "## Begrænsninger",
        "",
    ]
    lines += ["- " + limitation for limitation in LIMITATIONS]
    lines += [
        "",
        "Det legitime login fra en ny kilde er bevidst medtaget for at vise, at en afvigelse fra normalprofilen også kan have en legitim forklaring.",
        "",
    ]
    (directory / "report.md").write_text("\n".join(lines), encoding="utf-8")
    return report
