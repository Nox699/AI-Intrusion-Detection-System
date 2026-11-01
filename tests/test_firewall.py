"""UFW boundary tests: sanitized samples, provenance and malformed inputs."""

import json
from dataclasses import asdict
from pathlib import Path

import pytest

from yggdrasil_ids.firewall import MAX_MESSAGE_LENGTH, UFWParser

NOW = 1_800_000_000
MESSAGE = (
    "[UFW BLOCK] IN=wlan0 OUT= MAC=02:00:00:00:00:92:02:00:00:00:00:01:08:00 "
    "SRC=192.0.2.1 DST=192.0.2.92 LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=123 DF "
    "PROTO=TCP SPT=40000 DPT=443 WINDOW=65535 RES=0x00 SYN URGP=0"
)


def record(message=MESSAGE, **fields):
    return {
        "_TRANSPORT": "kernel",
        "SYSLOG_IDENTIFIER": "kernel",
        "_HOSTNAME": "test-sensor",
        "_BOOT_ID": "a" * 32,
        "__CURSOR": "test-cursor-1",
        "__REALTIME_TIMESTAMP": str(NOW * 1_000_000),
        "MESSAGE": message,
        **fields,
    }


def test_tcp_kernel_entry_does_not_require_uid_or_process_name():
    result = UFWParser().parse(record())
    assert result.status == "event"
    event = result.event
    assert event is not None
    assert event.action == "BLOCK"
    assert event.direction == "incoming"
    assert (event.source_ip, event.destination_ip) == ("192.0.2.1", "192.0.2.92")
    assert (event.source_port, event.destination_port) == (40000, 443)
    assert event.protocol == "TCP" and event.protocol_number == 6
    assert event.tcp_flags == ("SYN",)
    assert event.timestamp == NOW
    assert event.packet_length == 60 and event.transport_length is None
    assert "MAC" not in asdict(event) and "message" not in asdict(event)


def test_sanitized_live_format_samples():
    path = Path(__file__).parent / "fixtures" / "ufw_journal.jsonl"
    results = [UFWParser().parse(json.loads(line)) for line in path.read_text().splitlines()]
    assert len(results) == 4
    assert all(result.status == "event" for result in results)
    udp, igmp, tcp, ipv6 = [result.event for result in results]
    assert (udp.packet_length, udp.transport_length) == (491, 471)
    assert udp.protocol == "UDP" and udp.destination_port == 55817
    assert igmp.protocol_number == 2 and igmp.protocol == "IGMP"
    assert igmp.source_port is None and igmp.destination_port is None
    assert igmp.destination_ip == "224.0.0.1"
    assert tcp.tcp_flags == ("SYN",)
    assert ipv6.ip_version == 6 and ipv6.protocol == "TCP"


@pytest.mark.parametrize("transport", [None, "syslog", "stdout", "journal", ["kernel"]])
def test_a_forged_syslog_tag_is_not_kernel_provenance(transport):
    item = record(_TRANSPORT=transport, _UID="0", _COMM="sshd")
    result = UFWParser().parse(item)
    assert result.status == "ignored" and result.event is None


@pytest.mark.parametrize("action", ["BLOCK", "ALLOW", "AUDIT", "REJECT", "LIMIT BLOCK"])
def test_action_labels_are_preserved_without_inference(action):
    result = UFWParser().parse(record(MESSAGE.replace("[UFW BLOCK]", f"[UFW {action}]")))
    assert result.event.action == action


@pytest.mark.parametrize("message", ["ordinary kernel message", "[UFW UNKNOWN] IN=wlan0"])
def test_unrelated_or_unsupported_prefix_is_ignored(message):
    assert UFWParser().parse(record(message)).status == "ignored"


@pytest.mark.parametrize(
    "message",
    [
        None,
        [],
        "x" * (MAX_MESSAGE_LENGTH + 1),
        MESSAGE + "\nSYN",
        MESSAGE + "\x00",
        MESSAGE + "\u202e",
    ],
)
def test_nontext_oversize_and_control_characters_are_rejected(message):
    assert UFWParser().parse(record(message)).status == "malformed"


@pytest.mark.parametrize("value", [None, [], "", "a" * 4097, "cursor\nforged"])
def test_cursor_required_for_stable_packet_identity(value):
    assert UFWParser().parse(record(__CURSOR=value)).status == "malformed"


@pytest.mark.parametrize("value", [None, True, -1, 1.25, "NaN", "1e6", "9" * 19, "１２３", []])
def test_invalid_journal_timestamp_fails_closed(value):
    assert UFWParser().parse(record(__REALTIME_TIMESTAMP=value)).status == "malformed"


@pytest.mark.parametrize("value", ["bad name", "", None, "x" * 129, "live\n"])
def test_bad_namespace_rejected(value):
    assert UFWParser().parse(record(), namespace=value).status == "malformed"


@pytest.mark.parametrize(
    "old,new",
    [
        ("SRC=192.0.2.1", "SRC=not-an-ip"),
        ("DST=192.0.2.92", "DST=2001:db8::1"),
        ("SPT=40000", "SPT=-1"),
        ("DPT=443", "DPT=65536"),
        ("DPT=443", "DPT=abc"),
        ("DPT=443", ""),
        ("PROTO=TCP", "PROTO=256"),
        ("PROTO=TCP", "PROTO=unknown"),
        ("IN=wlan0", "IN=" + "a" * 65),
        ("LEN=60", "LEN=-1"),
        ("LEN=60", "LEN=60 LEN=40"),
        ("IN=wlan0", ""),
    ],
)
def test_malformed_fields_are_not_partially_accepted(old, new):
    result = UFWParser().parse(record(MESSAGE.replace(old, new)))
    assert result.status == "malformed" and result.event is None
    assert "192.0.2.1" not in result.reason


@pytest.mark.parametrize("extra", ["SRC=192.0.2.2", "DPT=22", "PROTO=UDP", "IN=wlan0"])
def test_ambiguous_repeated_identity_fields_are_rejected(extra):
    assert UFWParser().parse(record(MESSAGE + " " + extra)).status == "malformed"


def test_udp_double_length_fields_remain_separate():
    message = MESSAGE.replace("PROTO=TCP", "PROTO=UDP").replace(" SYN", "") + " LEN=40"
    event = UFWParser().parse(record(message)).event
    assert (event.packet_length, event.transport_length) == (60, 40)
    assert event.protocol == "UDP"
    assert UFWParser().parse(record(message + " LEN=40")).status == "malformed"


@pytest.mark.parametrize("protocol,label", [("6", "TCP"), ("17", "UDP"), ("132", "SCTP")])
def test_numeric_transport_protocols(protocol, label):
    message = MESSAGE.replace("PROTO=TCP", f"PROTO={protocol}")
    if protocol != "6":
        message = message.replace(" SYN", "")
    assert UFWParser().parse(record(message)).event.protocol == label


def test_unknown_numeric_protocol_has_no_invented_ports():
    message = "[UFW BLOCK] IN=wlan0 OUT= SRC=192.0.2.1 DST=192.0.2.2 PROTO=253"
    event = UFWParser().parse(record(message)).event
    assert event.protocol == "253" and event.destination_port is None


def test_ipv6_is_canonical_and_icmpv6_needs_no_ports():
    message = "[UFW BLOCK] IN=wlan0 OUT= SRC=fe80::0001 DST=ff02::1 PROTO=ICMPv6 TYPE=130 CODE=0"
    event = UFWParser().parse(record(message)).event
    assert event.source_ip == "fe80::1"
    assert event.protocol == "ICMPV6" and event.protocol_number == 58
    assert event.destination_port is None and event.ip_version == 6


def test_fragment_without_ports_remains_visible_but_has_no_destination_port():
    message = MESSAGE.replace(" SPT=40000 DPT=443", "").replace(" SYN", "")
    event = UFWParser().parse(record(message)).event
    assert event.protocol == "TCP" and event.destination_port is None


def test_nested_icmp_quote_cannot_override_outer_headers():
    message = "[UFW BLOCK] IN=wlan0 OUT= SRC=192.0.2.1 DST=192.0.2.2 PROTO=ICMP [SRC=192.0.2.3]"
    assert UFWParser().parse(record(message)).status == "malformed"


@pytest.mark.parametrize(
    "interfaces,direction",
    [
        ("IN=wlan0 OUT=", "incoming"),
        ("IN= OUT=wlan0", "outgoing"),
        ("IN=wlan0 OUT=eth0", "forwarded"),
        ("IN= OUT=", "unknown"),
    ],
)
def test_direction_is_derived_from_both_interfaces(interfaces, direction):
    message = MESSAGE.replace("IN=wlan0 OUT=", interfaces)
    assert UFWParser().parse(record(message)).event.direction == direction


def test_identity_is_stable_for_a_cursor_but_separates_namespaces():
    parser = UFWParser()
    first = parser.parse(record()).event
    assert parser.parse(record()).event.event_id == first.event_id
    assert parser.parse(record(), namespace="demo").event.event_id != first.event_id
    assert parser.parse(record(__CURSOR="second-cursor")).event.event_id != first.event_id


@pytest.mark.parametrize("item", [None, [], "text", 1])
def test_record_must_be_an_object(item):
    assert UFWParser().parse(item).status == "malformed"
