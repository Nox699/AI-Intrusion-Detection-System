"""Pure TCP scan rule tests, never opening sockets or changing a firewall."""

from dataclasses import replace

import pytest

from yggdrasil_ids.firewall import UFWParser
from yggdrasil_ids.network_rules import (
    NetworkRuleConfig,
    NetworkWindowOverflow,
    TCPPortScanDetector,
)

NOW = 1_800_000_000


def packet(index, port=None, timestamp=None, **changes):
    message = (
        "[UFW BLOCK] IN=wlan0 OUT= SRC=192.0.2.50 DST=192.0.2.92 "
        f"PROTO=TCP SPT={40000 + index % 1000} DPT={2000 + index if port is None else port} SYN"
    )
    stamp = NOW + index if timestamp is None else timestamp
    parsed = UFWParser().parse(
        {
            "_TRANSPORT": "kernel",
            "_BOOT_ID": "a" * 32,
            "_HOSTNAME": "test-sensor",
            "__REALTIME_TIMESTAMP": str(int(stamp * 1_000_000)),
            "__CURSOR": f"test-cursor-{index}",
            "MESSAGE": message,
        },
        namespace="test",
    )
    item = parsed.event
    assert item is not None
    return replace(item, **changes)


def test_six_distinct_ports_are_needed_and_evidence_is_explainable():
    detector = TCPPortScanDetector()
    events = [packet(index) for index in range(6)]
    for count in range(1, 6):
        assert detector.evaluate(events[count - 1], events[:count]) is None
    finding = detector.evaluate(events[-1], events)
    assert finding.detector_id == "network.tcp_port_scan"
    assert finding.severity == "medium"
    assert finding.distinct_ports == 6 and finding.recorded_packets == 6
    assert finding.destination_ports == tuple(range(2000, 2006))
    assert finding.evidence_ids == tuple(event.event_id for event in events)
    assert not finding.evidence_truncated
    assert "ikke bevis for et angreb" in finding.reason
    assert finding.window_seconds == 60 and finding.threshold == 6


def test_local_lan_threshold_five_detects_five_but_default_six_does_not():
    events = [packet(index, port=45010 + index) for index in range(5)]
    assert TCPPortScanDetector().evaluate(events[-1], events) is None
    tuned = TCPPortScanDetector(NetworkRuleConfig(distinct_ports_threshold=5))
    assert tuned.evaluate(events[-2], events[:-1]) is None
    result = tuned.evaluate(events[-1], events)
    assert result is not None
    assert result.distinct_ports == 5
    assert result.threshold == 5
    assert result.recorded_packets == 5


def test_retransmissions_and_changing_source_ports_do_not_count_as_new_ports():
    events = [packet(index, port=443) for index in range(50)]
    assert TCPPortScanDetector().evaluate(events[-1], events) is None


def test_replayed_journal_records_are_deduplicated_and_current_is_included_once():
    events = [packet(index) for index in range(6)]
    detector = TCPPortScanDetector()
    normal = detector.evaluate(events[-1], events)
    repeated = detector.evaluate(events[-1], events * 4)
    assert normal == repeated
    assert detector.evaluate(events[-1], events[:-1]) == normal


def test_window_excludes_exact_start_and_future_events():
    detector = TCPPortScanDetector(NetworkRuleConfig(distinct_ports_threshold=2))
    current = packet(5, timestamp=NOW)
    assert detector.evaluate(current, [packet(1, timestamp=NOW - 60)]) is None
    assert detector.evaluate(current, [packet(1, timestamp=NOW + 1)]) is None
    assert detector.evaluate(current, [packet(1, timestamp=NOW - 59.999)]) is not None
    assert detector.evaluate(current, [packet(1, timestamp=NOW)]) is not None


@pytest.mark.parametrize(
    "changes",
    [
        {"source_ip": "192.0.2.51"},
        {"destination_ip": "192.0.2.93"},
        {"in_interface": "tailscale0"},
        {"namespace": "demo"},
        {"host": "another-sensor"},
        {"boot_id": "b" * 32},
    ],
)
def test_sources_destinations_interfaces_and_sensors_never_mix(changes):
    detector = TCPPortScanDetector(NetworkRuleConfig(distinct_ports_threshold=2))
    assert detector.evaluate(packet(2), [packet(1, **changes)]) is None


@pytest.mark.parametrize("action", ["ALLOW", "AUDIT"])
def test_allowed_or_audited_packets_are_not_called_blocked_scans(action):
    events = [packet(index, action=action) for index in range(6)]
    assert TCPPortScanDetector().evaluate(events[-1], events) is None


@pytest.mark.parametrize("action", ["BLOCK", "REJECT", "LIMIT BLOCK"])
def test_supported_block_labels_can_contribute(action):
    events = [packet(index, action=action) for index in range(6)]
    assert TCPPortScanDetector().evaluate(events[-1], events).distinct_ports == 6


@pytest.mark.parametrize(
    "changes",
    [
        {"protocol": "UDP", "protocol_number": 17, "tcp_flags": ()},
        {"protocol": "IGMP", "protocol_number": 2, "destination_port": None, "tcp_flags": ()},
        {"direction": "outgoing", "in_interface": "", "out_interface": "wlan0"},
        {"direction": "forwarded", "out_interface": "eth0"},
        {"destination_ip": "224.0.0.1"},
        {"destination_ip": "255.255.255.255"},
        {"source_ip": "0.0.0.0"},
        {"source_ip": "127.0.0.1"},
        {"tcp_flags": ("SYN", "ACK")},
        {"tcp_flags": ("SYN", "RST")},
        {"tcp_flags": ("SYN", "FIN")},
        {"tcp_flags": ("ACK",)},
        {"tcp_flags": ("RST",)},
        {"tcp_flags": ()},
        {"destination_port": None},
    ],
)
def test_nonqualifying_traffic_does_not_trigger(changes):
    events = [packet(index, **changes) for index in range(8)]
    assert TCPPortScanDetector().evaluate(events[-1], events) is None


def test_router_udp_to_many_ports_is_not_a_tcp_scan():
    events = [
        packet(index, source_ip="192.0.2.1", protocol="UDP", protocol_number=17, tcp_flags=())
        for index in range(30)
    ]
    assert TCPPortScanDetector().evaluate(events[-1], events) is None


def test_private_sources_are_not_automatically_allowlisted():
    events = [packet(index, source_ip="192.168.50.1") for index in range(6)]
    assert TCPPortScanDetector().evaluate(events[-1], events) is not None


def test_ipv6_unicast_syn_scan_is_detectable():
    events = [
        packet(index, source_ip="2001:db8::50", destination_ip="2001:db8::92", ip_version=6)
        for index in range(6)
    ]
    assert TCPPortScanDetector().evaluate(events[-1], events).distinct_ports == 6


def test_unsorted_input_has_the_same_result():
    events = [packet(index) for index in range(6)]
    detector = TCPPortScanDetector()
    assert detector.evaluate(events[-1], reversed(events)) == detector.evaluate(events[-1], events)


def test_conflicting_duplicate_id_is_a_data_quality_error():
    current = packet(5)
    original = packet(1)
    conflicting = replace(original, destination_port=9000)
    with pytest.raises(ValueError, match="hændelses-ID"):
        TCPPortScanDetector().evaluate(current, [original, conflicting])


def test_empty_history_and_overflow_are_not_silent_false_alarms():
    config = NetworkRuleConfig(distinct_ports_threshold=2, max_history_records=2)
    detector = TCPPortScanDetector(config)
    assert detector.evaluate(packet(5), []) is None
    with pytest.raises(NetworkWindowOverflow):
        detector.evaluate(packet(5), [packet(1), packet(2), packet(3)])


def test_evidence_is_bounded_but_distinct_port_count_is_exact():
    events = [packet(index, timestamp=NOW + index / 10) for index in range(100)]
    result = TCPPortScanDetector().evaluate(events[-1], events)
    assert result.distinct_ports == 100 and result.recorded_packets == 100
    assert len(result.destination_ports) == len(result.evidence_ids) == 64
    assert result.evidence_truncated


@pytest.mark.parametrize(
    "config",
    [
        {"window_seconds": True},
        {"window_seconds": 0},
        {"window_seconds": 3601},
        {"distinct_ports_threshold": 1},
        {"distinct_ports_threshold": 65},
        {"distinct_ports_threshold": 6.0},
        {"max_history_records": 1},
        {"max_history_records": 50001},
    ],
)
def test_config_limits_are_strict(config):
    with pytest.raises(ValueError):
        NetworkRuleConfig(**config)


def test_conflicting_id_is_detected_even_across_different_groups():
    current = packet(5)
    first = packet(1)
    contradictory = replace(first, source_ip="192.0.2.200")
    with pytest.raises(ValueError, match="hændelses-ID"):
        TCPPortScanDetector().evaluate(current, [first, contradictory])


def test_current_id_cannot_conflict_with_history():
    current = packet(5)
    with pytest.raises(ValueError, match="hændelses-ID"):
        TCPPortScanDetector().evaluate(current, [replace(current, destination_port=22)])
