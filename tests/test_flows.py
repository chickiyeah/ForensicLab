"""forensiclab.flows 단위 테스트 (stdlib unittest)."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from forensiclab.flows import (  # noqa: E402
    Flow,
    FlowKey,
    aggregate_flows,
    flow_key,
)
from forensiclab.netdissect import (  # noqa: E402
    IP_PROTO_ICMP,
    IP_PROTO_TCP,
    IP_PROTO_UDP,
    Dissection,
    IPv4,
)


def _diss(src_ip, dst_ip, protocol, src_port=None, dst_port=None):
    """포트/IP 만 채운 가벼운 Dissection (L2 는 흐름에 영향 없음)."""
    ipv4 = IPv4(
        src_ip=src_ip,
        dst_ip=dst_ip,
        protocol=protocol,
        ttl=64,
        total_length=40,
        header_length=20,
        payload_offset=20,
    )
    return Dissection(ethernet=None, ipv4=ipv4, src_port=src_port, dst_port=dst_port)


class FlowKeyTest(unittest.TestCase):
    def test_both_directions_same_key(self):
        fwd = _diss("10.0.0.1", "10.0.0.2", IP_PROTO_TCP, 51000, 443)
        rev = _diss("10.0.0.2", "10.0.0.1", IP_PROTO_TCP, 443, 51000)
        self.assertEqual(flow_key(fwd), flow_key(rev))

    def test_canonical_endpoint_order(self):
        # 더 큰 끝점에서 보낸 패킷이라도 A 는 사전식으로 작은 쪽.
        key = flow_key(_diss("10.0.0.2", "10.0.0.1", IP_PROTO_TCP, 443, 51000))
        self.assertEqual(key.ip_a, "10.0.0.1")
        self.assertEqual(key.port_a, 51000)
        self.assertEqual(key.ip_b, "10.0.0.2")
        self.assertEqual(key.port_b, 443)

    def test_same_ip_orders_by_port(self):
        key = flow_key(_diss("10.0.0.1", "10.0.0.1", IP_PROTO_UDP, 9000, 53))
        self.assertEqual(key.port_a, 53)
        self.assertEqual(key.port_b, 9000)

    def test_protocol_name(self):
        self.assertEqual(flow_key(_diss("1.1.1.1", "2.2.2.2", IP_PROTO_TCP)).protocol_name, "TCP")
        self.assertEqual(flow_key(_diss("1.1.1.1", "2.2.2.2", IP_PROTO_ICMP)).protocol_name, "ICMP")

    def test_no_ipv4_returns_none(self):
        self.assertIsNone(flow_key(Dissection(None, None, None, None)))

    def test_different_protocol_distinct_keys(self):
        tcp = flow_key(_diss("1.1.1.1", "2.2.2.2", IP_PROTO_TCP, 1, 2))
        udp = flow_key(_diss("1.1.1.1", "2.2.2.2", IP_PROTO_UDP, 1, 2))
        self.assertNotEqual(tcp, udp)


class AggregateFlowsTest(unittest.TestCase):
    def test_bidirectional_merge_and_counts(self):
        packets = [
            (_diss("10.0.0.1", "10.0.0.2", IP_PROTO_TCP, 51000, 443), 100, 1.0),
            (_diss("10.0.0.2", "10.0.0.1", IP_PROTO_TCP, 443, 51000), 1400, 2.0),
            (_diss("10.0.0.1", "10.0.0.2", IP_PROTO_TCP, 51000, 443), 60, 3.0),
        ]
        flows = aggregate_flows(packets)
        self.assertEqual(len(flows), 1)
        flow = flows[0]
        self.assertEqual(flow.packets, 3)
        self.assertEqual(flow.bytes_total, 1560)
        # A = (10.0.0.1, 51000) 이므로 A→B 2개, B→A 1개.
        self.assertEqual(flow.a_to_b_packets, 2)
        self.assertEqual(flow.b_to_a_packets, 1)
        self.assertEqual(flow.first_seen, 1.0)
        self.assertEqual(flow.last_seen, 3.0)
        self.assertEqual(flow.duration, 2.0)

    def test_separate_flows_kept_apart(self):
        packets = [
            (_diss("10.0.0.1", "10.0.0.2", IP_PROTO_TCP, 1, 80), 10, None),
            (_diss("10.0.0.1", "10.0.0.3", IP_PROTO_TCP, 2, 80), 10, None),
        ]
        flows = aggregate_flows(packets)
        self.assertEqual(len(flows), 2)

    def test_insertion_order_preserved(self):
        packets = [
            (_diss("10.0.0.9", "10.0.0.2", IP_PROTO_UDP, 5, 53), 1, None),
            (_diss("10.0.0.1", "10.0.0.2", IP_PROTO_UDP, 5, 53), 1, None),
        ]
        flows = aggregate_flows(packets)
        self.assertEqual(flows[0].key.ip_b, "10.0.0.9")  # 9.x 끝점이 먼저 등장
        self.assertEqual(flows[1].key.ip_a, "10.0.0.1")

    def test_non_ipv4_skipped(self):
        packets = [
            (Dissection(None, None, None, None), 64, 1.0),
            (_diss("1.1.1.1", "2.2.2.2", IP_PROTO_TCP, 1, 2), 64, 2.0),
        ]
        flows = aggregate_flows(packets)
        self.assertEqual(len(flows), 1)

    def test_missing_timestamps_leave_duration_none(self):
        flows = aggregate_flows([(_diss("1.1.1.1", "2.2.2.2", IP_PROTO_ICMP), 64, None)])
        self.assertIsNone(flows[0].first_seen)
        self.assertIsNone(flows[0].duration)

    def test_icmp_no_ports_aggregates(self):
        packets = [
            (_diss("1.1.1.1", "2.2.2.2", IP_PROTO_ICMP), 64, 1.0),
            (_diss("2.2.2.2", "1.1.1.1", IP_PROTO_ICMP), 64, 2.0),
        ]
        flows = aggregate_flows(packets)
        self.assertEqual(len(flows), 1)
        self.assertEqual(flows[0].packets, 2)
        self.assertEqual(flows[0].a_to_b_packets, 1)
        self.assertEqual(flows[0].b_to_a_packets, 1)

    def test_empty_input(self):
        self.assertEqual(aggregate_flows([]), [])


if __name__ == "__main__":
    unittest.main()
