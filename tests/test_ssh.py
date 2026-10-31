"""Parser regressions grounded in Debian OpenSSH/journal formats."""

from datetime import datetime, timezone

import pytest

from yggdrasil_ids.ssh import MAX_STORED_MESSAGE_LENGTH, SSHParser


def journal(message, **changes):
    record = {
        "__CURSOR": "s=test;i=1;b=boot;m=100;t=200;x=300",
        "__REALTIME_TIMESTAMP": "1793148292000000",
        "_COMM": "sshd-session",
        "_UID": "0",
        "_PID": "55811",
        "_HOSTNAME": "test-server",
        "SYSLOG_IDENTIFIER": "sshd-session",
        "MESSAGE": message,
    }
    record.update(changes)
    return record


ACCEPTED = "Accepted publickey for labuser from 192.0.2.12 port 42962 ssh2: ED25519 SHA256:test"
FAILED = "Failed password for invalid user admin from 192.0.2.8 port 54321 ssh2 [preauth]"


def test_real_accepted_and_pam_are_one_authentication():
    parser = SSHParser()
    records = [
        journal(ACCEPTED),
        journal(
            "pam_unix(sshd:session): session opened for user labuser(uid=1000) by labuser(uid=0)",
            __CURSOR="pam",
        ),
    ]
    events = [result.event for record in records if (result := parser.parse(record)).event]
    assert len(events) == 1
    event = events[0]
    assert event.username == "labuser"  # calling-process uid=0 does not mean a root login
    assert event.outcome == "success"
    assert event.auth_method == "publickey"
    assert event.source_ip == "192.0.2.12"
    assert event.pid == "55811"


def test_invalid_user_notice_is_not_a_second_failure():
    parser = SSHParser()
    assert parser.parse(journal("Invalid user admin from 192.0.2.8 port 54321")).status == "ignored"
    event = parser.parse(journal(FAILED)).event
    assert event.outcome == "failure"
    assert event.username == "admin"


@pytest.mark.parametrize("producer", ["sshd", "sshd-session", "sshd-auth"])
def test_supported_openssh_processes(producer):
    assert SSHParser().parse(journal(FAILED, _COMM=producer)).status == "event"


@pytest.mark.parametrize("method", ["password", "publickey", "keyboard-interactive/pam", "none"])
def test_authentication_methods(method):
    event = (
        SSHParser().parse(journal(f"Failed {method} for root from 192.0.2.8 port 22 ssh2")).event
    )
    assert event.auth_method == method
    assert event.username == "root"


def test_ipv6_is_canonicalised():
    event = (
        SSHParser()
        .parse(journal("Accepted publickey for labuser from 2001:0db8:0000::1 port 2222 ssh2"))
        .event
    )
    assert event.source_ip == "2001:db8::1"


@pytest.mark.parametrize(
    "changes",
    [
        {"_COMM": "logger", "SYSLOG_IDENTIFIER": "sshd"},
        {"_COMM": "sshd", "_UID": "1000"},
        {"_COMM": None},
        {"_COMM": ["sshd"]},
        {"_UID": False},
        {"_UID": None},
        {"_UID": 0.0},
        {"_UID": "00"},
    ],
)
def test_syslog_tag_cannot_establish_trusted_source(changes):
    result = SSHParser().parse(journal(ACCEPTED, **changes))
    assert result.status == "ignored"
    assert result.event is None


def test_source_identifier_is_not_required_when_trusted_fields_are_present():
    record = journal(ACCEPTED)
    record.pop("SYSLOG_IDENTIFIER")
    assert SSHParser().parse(record).status == "event"


@pytest.mark.parametrize(
    "timestamp",
    [
        None,
        "",
        "nan",
        "inf",
        "1.2",
        -1,
        True,
        [],
        {},
        "99999999999999999999999",
        "253402300800000000",
    ],
)
def test_invalid_timestamps_are_visible_as_malformed(timestamp):
    result = SSHParser().parse(journal(FAILED, __REALTIME_TIMESTAMP=timestamp))
    assert result.status == "malformed"
    assert result.event is None


def test_timestamp_is_utc_epoch_without_host_timezone_assumption():
    timestamp = int(datetime(2026, 10, 28, 0, 44, 52, tzinfo=timezone.utc).timestamp() * 1_000_000)
    event = SSHParser().parse(journal(ACCEPTED, __REALTIME_TIMESTAMP=str(timestamp))).event
    assert (
        datetime.fromtimestamp(event.timestamp, timezone.utc).isoformat()
        == "2026-10-28T00:44:52+00:00"
    )


@pytest.mark.parametrize("address", ["999.1.2.3", "example.org", "127.000.0.1", "2001:::1"])
def test_invalid_addresses(address):
    result = SSHParser().parse(journal(FAILED.replace("192.0.2.8", address)))
    assert result.status == "malformed"


@pytest.mark.parametrize("port", ["0", "65536", "999999", "-1", "not-a-port"])
def test_invalid_port(port):
    assert SSHParser().parse(journal(FAILED.replace("54321", port))).status == "malformed"


@pytest.mark.parametrize("record", [None, [], "text", 42, {}, {"_UID": [], "_COMM": {}}])
def test_unexpected_journal_shapes_never_crash(record):
    assert SSHParser().parse(record).event is None


@pytest.mark.parametrize("message", [None, [], {}, 42])
def test_binary_or_non_text_message_is_malformed(message):
    assert SSHParser().parse(journal(message)).status == "malformed"


@pytest.mark.parametrize("character", ["\n", "\r", "\x00", "\x1b", "\u202e", "\ud800"])
def test_authentication_log_control_injection(character):
    assert (
        SSHParser().parse(journal(FAILED.replace("admin", f"ad{character}min"))).status
        == "malformed"
    )


def test_html_in_attempted_username_remains_data():
    event = SSHParser().parse(journal(FAILED.replace("admin", "<script>alert(1)</script>"))).event
    assert event.username == "<script>alert(1)</script>"


def test_stored_message_is_bounded_but_valid_header_is_preserved():
    message = ACCEPTED + "x" * 8_000
    event = SSHParser().parse(journal(message)).event
    assert event.username == "labuser"
    assert len(event.message) == MAX_STORED_MESSAGE_LENGTH
    assert event.message.endswith("…")


def test_oversized_message_and_username_are_rejected():
    assert SSHParser().parse(journal(ACCEPTED + "x" * 20_000)).status == "malformed"
    assert SSHParser().parse(journal(FAILED.replace("admin", "x" * 257))).status == "malformed"


def test_cursor_identity_is_stable_and_namespaced():
    parser = SSHParser()
    record = journal(ACCEPTED)
    first = parser.parse(record).event
    assert parser.parse(record).event.event_id == first.event_id
    assert parser.parse(record, namespace="demo").event.event_id != first.event_id
    assert parser.parse(journal(ACCEPTED, __CURSOR="another")).event.event_id != first.event_id


def test_fallback_identity_is_canonical_full_record():
    parser = SSHParser()
    record = journal(ACCEPTED)
    record.pop("__CURSOR")
    first = parser.parse(record).event
    assert first.cursor == ""
    assert parser.parse(dict(reversed(list(record.items())))).event.event_id == first.event_id
    assert parser.parse({**record, "_PID": "2"}).event.event_id != first.event_id


def test_fallback_rejects_non_json_record_and_nonfinite_metadata():
    for extra in [{"other": object()}, {"other": float("nan")}, {1: "mixed-key-types"}]:
        record = journal(ACCEPTED, **{"__CURSOR": ""})
        record.update(extra)
        assert SSHParser().parse(record).status == "malformed"


@pytest.mark.parametrize("cursor", [[], {}, True, "\u202e", "a" * 5_000])
def test_invalid_cursor_is_not_silently_coerced(cursor):
    assert SSHParser().parse(journal(ACCEPTED, __CURSOR=cursor)).status == "malformed"
