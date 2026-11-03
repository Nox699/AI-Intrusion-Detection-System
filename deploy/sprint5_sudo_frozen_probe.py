#!/usr/bin/env python3
"""Prospective controlled sudo probe against frozen original-format models.

Thirty harmless successes, then three bounded service-account auth failures.
No fit on probe data, threshold change, activation or notification. Original
load() reconstructs forests from their saved normal rows before the probe.
Keep all journal context; exact test PIDs are used only in memory for labels.
"""

import argparse
import hashlib
import json
import os
import pwd
import re
import subprocess
import time
from pathlib import Path

from yggdrasil_ids.sudo_ml import SudoIsolationForest, attempts_from_signals, feature_rows
from yggdrasil_ids.sudo_rules import parse_sudo

MODES = ("synthetic_full", "real_full", "mixed_full")
NORMAL_CALLS = 30
FAILURE_CALLS = 3
TARGET = "yggdrasil-web"
FIELDS = "MESSAGE,_EXE,_UID,_PID,_BOOT_ID,__CURSOR,__REALTIME_TIMESTAMP"
INNER = (
    "import os; print(os.getpid(), flush=True); "
    "os.execv('/usr/bin/sudo', ['sudo','-k','-S','-p','','--','/usr/bin/true'])"
)


def file_hash(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_frozen(folder):
    report_path = folder / "report.json"
    metadata = json.loads(report_path.read_text())
    if metadata.get("kind") != "restored_sprint5_full_data_baseline":
        raise ValueError("Expected restored Sprint5 baseline report")
    frozen = metadata.get("models_frozen_at")
    if type(frozen) not in (int, float) or not frozen < time.time():
        raise ValueError("Models must be frozen before the probe")
    models, hashes = {}, {"report.json": file_hash(report_path)}
    for name in MODES:
        expected = metadata["results"][name]
        filename = expected["model_file"]
        if filename != f"{name}-model.json":
            raise ValueError("Unexpected model filename")
        path = folder / filename
        hashes[filename] = file_hash(path)
        model = SudoIsolationForest.load(path)
        if model.threshold != expected["threshold"]:
            raise ValueError("Model/report thresholds differ")
        if model.payload["features"] != expected["feature_names"]:
            raise ValueError("Model/report feature schemas differ")
        matrix_sha = hashlib.sha256(
            json.dumps(
                model.payload["normal_training_rows"],
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            ).encode()
        ).hexdigest()
        if matrix_sha != expected["matrix_sha256"]:
            raise ValueError("Model/report training matrices differ")
        models[name] = model
    return models, hashes, metadata


def read_journal(since, until):
    result = subprocess.run(
        [
            "/usr/bin/sudo",
            "-n",
            "/usr/bin/setpriv",
            "--reuid=yggdrasil-worker",
            "--regid=yggdrasil-data",
            "--groups=yggdrasil-data,systemd-journal",
            "/usr/bin/journalctl",
            "--quiet",
            "--no-pager",
            "--all",
            "--output=json",
            "--output-fields=" + FIELDS,
            f"--since=@{since:.6f}",
            f"--until=@{until:.6f}",
            "_EXE=/usr/bin/sudo",
        ],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=30,
        cwd="/",
    )
    if result.returncode or len(result.stdout) > 10_000_000:
        raise RuntimeError("Bounded worker journal query failed")
    lines = result.stdout.splitlines()
    if len(lines) > 10000:
        raise ValueError("Journal snapshot exceeds 10000 rows")
    return [json.loads(line) for line in lines]


def invoke(failure=False):
    command = (
        [
            "/usr/bin/sudo",
            "-n",
            "-u",
            TARGET,
            "--",
            "/usr/bin/timeout",
            "--signal=TERM",
            "--kill-after=2s",
            "10s",
            "/usr/bin/python3",
            "-c",
            INNER,
        ]
        if failure
        else ["/usr/bin/sudo", "-n", "--", "/usr/bin/true"]
    )
    child = subprocess.Popen(
        command,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        cwd="/",
        env={**os.environ, "LC_ALL": "C", "LANG": "C"},
    )
    try:
        stdout, stderr = child.communicate(
            "Yggdrasil-frozen-IDS-probe-not-a-password-8766!\n" if failure else "", timeout=15
        )
    except subprocess.TimeoutExpired:
        # A descendant can retain stdout/stderr after its launcher exits. Keep
        # cleanup bounded as well; the inner GNU timeout also limits auth work.
        child.terminate()
        try:
            child.communicate(timeout=2)
        except subprocess.TimeoutExpired:
            child.kill()
            try:
                child.communicate(timeout=2)
            except subprocess.TimeoutExpired:
                for pipe in (child.stdin, child.stdout, child.stderr):
                    if pipe is not None:
                        pipe.close()
        raise RuntimeError("Probe command timed out; no further attempts") from None
    if not failure:
        if child.returncode != 0:
            raise RuntimeError("Harmless passwordless normal command was not permitted")
        return child.pid
    if child.returncode == 0:
        raise RuntimeError(
            "Service-account sudo unexpectedly succeeded; remaining attempts stopped"
        )
    if child.returncode in (124, 137):
        raise RuntimeError("Service-account attempt exceeded its inner time limit")
    output = stdout.strip()
    if not re.fullmatch(r"[0-9]{1,10}", output) or "incorrect password" not in stderr.lower():
        raise RuntimeError("Failure command did not confirm the intended auth-failure path")
    # The helper prints its own PID and execs sudo, preserving that exact PID.
    return int(output)


def observations(records):
    signals = []
    for record in records:
        parsed = parse_sudo(record)
        if parsed.status != "event":
            raise ValueError("Trusted journal record did not pass parsing")
        if parsed.signal.kind != "pam_session_closed":
            signals.append(parsed.signal)
    signals.sort(key=lambda row: (row.timestamp, row.cursor))
    return attempts_from_signals(signals)


def evaluate(models, attempts, boot, normal_pids, failure_pids, start, end):
    if (
        len(normal_pids) != NORMAL_CALLS
        or len(failure_pids) != FAILURE_CALLS
        or len(set(normal_pids)) != NORMAL_CALLS
        or len(set(failure_pids)) != FAILURE_CALLS
        or set(normal_pids) & set(failure_pids)
    ):
        raise ValueError("Invalid or incomplete controlled process manifest")
    normal = [i for i, row in enumerate(attempts) if row.boot_id == boot and row.pid in normal_pids]
    failure = [
        i for i, row in enumerate(attempts) if row.boot_id == boot and row.pid in failure_pids
    ]
    if (
        len(normal) != NORMAL_CALLS
        or len(failure) != FAILURE_CALLS
        or {attempts[i].pid for i in normal} != set(normal_pids)
        or {attempts[i].pid for i in failure} != set(failure_pids)
    ):
        raise ValueError("Journal process identity counts do not match the controlled manifest")
    if any(attempts[i].outcome != "success" for i in normal):
        raise ValueError("A normal probe lacks recognized success evidence")
    if any(attempts[i].outcome != "failure" for i in failure):
        raise ValueError("A failure probe lacks recognized authentication-failure evidence")
    if any(not start <= attempts[i].timestamp <= end for i in normal + failure):
        raise ValueError("Probe evidence falls outside the fixed prospective interval")
    if any(
        max(attempts[i].timestamp for i in phase) - min(attempts[i].timestamp for i in phase) >= 300
        for phase in (normal, failure)
    ):
        raise ValueError("Controlled phase did not fit within its 300-second window")
    normal_groups = {(attempts[i].boot_id, attempts[i].uid) for i in normal}
    failure_groups = {(attempts[i].boot_id, attempts[i].uid) for i in failure}
    if len(failure_groups) != 1:
        raise ValueError("Failed probes did not share one trusted parser group")
    # ALL warm-up/background/wrapper observations participate before labels select outputs.
    matrix = feature_rows(attempts)
    results = {}
    for name, model in models.items():
        scores = model.score_many(matrix)
        normal_flags = sum(scores[i]["is_anomaly"] for i in normal)
        failure_flags = sum(scores[i]["is_anomaly"] for i in failure)
        results[name] = {
            "normal_positions": len(normal),
            "normal_flagged": normal_flags,
            "failure_positions": len(failure),
            "failure_flagged": failure_flags,
            "failure_episode_detected": failure_flags > 0,
            "controlled_criterion_passed": normal_flags == 0 and failure_flags > 0,
            "version": model.version,
            "threshold": model.threshold,
        }
    return {
        "results": results,
        "probe_groups_overlap": bool(normal_groups & failure_groups),
        "failure_group_count": len(failure_groups),
        "context_processes_before_probe": sum(row.timestamp < start for row in attempts),
        "other_processes_during_probe": sum(
            start <= row.timestamp <= end and i not in set(normal + failure)
            for i, row in enumerate(attempts)
        ),
        "first_failure_context": {
            "process_count_300s": matrix[failure[0]][0],
            "failure_count_300s": matrix[failure[0]][1],
            "denied_count_300s": matrix[failure[0]][2],
            "success_count_300s": matrix[failure[0]][3],
            "failure_ratio_300s": matrix[failure[0]][4],
        },
    }


def run(folder, output):
    if output.exists() or output.is_symlink():
        raise FileExistsError("Choose a fresh private probe directory")
    models, hashes, baseline = load_frozen(folder)
    account = pwd.getpwnam(TARGET)
    if account.pw_uid == 0:
        raise ValueError("Service-account test target must be unprivileged")
    boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip().replace("-", "")
    # Verify journal access before generating any labelled probe activity.
    now = time.time()
    read_journal(now - 300, now - 2)
    output.mkdir(parents=True, mode=0o700)
    output.chmod(0o700)
    report = {
        "kind": "prospective_frozen_sudo_probe",
        "status": "incomplete",
        "primary_model": "mixed_full",
        "model_file_sha256": hashes,
        "baseline_frozen_at": baseline["models_frozen_at"],
        "frozen_artifacts_reconstructed_before_probe": True,
        "probe_used_for_fitting": False,
        "thresholds_changed": False,
        "models_activated": False,
        "raw_identities_saved": False,
        "test_type": "one busy normal workflow followed by auth failures in live context",
    }
    normal_pids, failure_pids = [], []
    start = time.time()
    report["probe_started_at"] = start
    try:
        print("Generating 30 harmless successful sudo calls...", flush=True)
        for _ in range(NORMAL_CALLS):
            normal_pids.append(invoke())
            time.sleep(0.2)
        print("Generating 3 bounded service-account authentication failures...", flush=True)
        for _ in range(FAILURE_CALLS):
            failure_pids.append(invoke(failure=True))
        end = time.time()
        time.sleep(2)  # Journal delivery only; fixed snapshot boundary remains end.
        attempts = observations(read_journal(start - 300, end))
        report.update(evaluate(models, attempts, boot, normal_pids, failure_pids, start, end))
        report.update(status="complete", probe_started_at=start, probe_ended_at=end)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
        report["reason"] = str(exc)
        report["probe_ended_at"] = time.time()
    report["completed_normal_commands"] = len(normal_pids)
    report["completed_failure_commands"] = len(failure_pids)
    report["frozen_files_unchanged"] = all(
        file_hash(folder / name) == value for name, value in hashes.items()
    )
    if not report["frozen_files_unchanged"]:
        report.update(status="incomplete", reason="A frozen input file changed during the probe")
    report["interpretation"] = (
        "One prospective workflow and one controlled failure episode, not population FPR/recall. "
        "All observed context retained; a shared parser group may mix successes and failures. "
        "Raw model flags are not sent alerts. Known typo and 60-process limitations remain."
    )
    path = output / "report.json"
    with path.open("x") as file:
        json.dump(report, file, indent=2, sort_keys=True, allow_nan=False)
        file.write("\n")
    path.chmod(0o600)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--run-controlled-probe", action="store_true")
    args = parser.parse_args()
    if os.geteuid() == 0 or not args.run_controlled_probe:
        parser.exit(2, "STOP: Run as vidar with --run-controlled-probe.\n")
    try:
        report = run(args.baseline, args.directory)
    except (OSError, ValueError, RuntimeError, KeyError, subprocess.SubprocessError) as exc:
        parser.exit(1, f"STOP: Frozen probe could not start: {exc}\n")
    print("\nEvidence status:", report["status"])
    for name, values in report.get("results", {}).items():
        print(
            f"{name}: normal flags={values['normal_flagged']}/{values['normal_positions']}; "
            f"failure flags={values['failure_flagged']}/{values['failure_positions']}; "
            f"episode detected={values['failure_episode_detected']}"
        )
    if report["status"] == "complete":
        print(
            "Primary mixed criterion passed:",
            report["results"]["mixed_full"]["controlled_criterion_passed"],
        )
        print("Normal/failure parser groups overlap:", report["probe_groups_overlap"])
        print("First failure's actual rolling context:", report["first_failure_context"])
    else:
        print("Incomplete reason:", report.get("reason", "unknown"))
    print("Frozen files unchanged:", report["frozen_files_unchanged"])
    print("Private probe report:", args.directory / "report.json")
    if report["status"] != "complete":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
