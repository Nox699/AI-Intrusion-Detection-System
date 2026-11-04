"""Small synthetic SSH fixtures for software tests, using documentation addresses."""

import json
from pathlib import Path


def normal_journal_records(count=96, anchor=1_790_000_000):
    result = []
    stamp = anchor
    for index in range(count):
        stamp += 600 if index % 8 == 0 else 3
        source = "192.0.2.10" if index % 3 else "192.0.2.11"
        user = "operator" if index % 4 else "backup"
        outcome = "Failed publickey" if index % 11 == 7 else "Accepted publickey"
        result.append(
            {
                "__CURSOR": f"fixture-{index}",
                "__REALTIME_TIMESTAMP": str(stamp * 1_000_000),
                "_COMM": "sshd-session",
                "_UID": "0",
                "_PID": str(1000 + index),
                "_HOSTNAME": "fixture-server",
                "MESSAGE": f"{outcome} for {user} from {source} port 54321 ssh2",
            }
        )
    return result


def write_normal_journal(path: Path, count=96, anchor=1_790_000_000):
    path.write_text(
        "\n".join(json.dumps(item) for item in normal_journal_records(count, anchor)) + "\n"
    )
    return path
