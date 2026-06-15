"""forensiclab.netdissect 단위 테스트 (stdlib unittest)."""

import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from forensiclab.netdissect import (  # noqa: E402
    ETHERTYPE_ARP,
    ETHERTYPE_IPV4,
    IP_PROTO_TCP,
    IP_PROTO_UDP,
    Dissection,
    Ethernet,
    IPv4,
    dissect,
    dissect_ethernet,
    dissect_ipv4,
    format_ipv4,
    format_mac,
)

_DST = b"\xaa\xbb\xcc\xdd\xee\xff"
_SRC = b"\x11\x22\x33\x44\x55\x66"


def _ether(ethertype, payload=b"", dst=_DST, src=_SRC):
    return dst + src + struct.pack(">H", ethertype) + payload


def _vlan(vid, inner_ethertype, payload=b""):
    tci = vid & 0x0FFF
    return (
        _DST + _SRC
        + struct.pack(">H", 0x8100)
        + struct.pack(">HH", tci, inner_ethertype)
        + payload
    )


def _ipv4(src_ip, dst_ip, protocol, payload=b"", ttl=64, ihl=5):
    ver_ihl = (4 << 4) | ihl
    header = bytearray(ihl * 4)
    header[0] = ver_ihl
    struct.pack_into(">H", header, 2, ihl * 4 + len(payload))  # total length
    header[8] = ttl
    header[9] = protocol
    header[12:16] = bytes(int(x) for x in src_ip.split("."))
    header[16:20] = bytes(int(x) for x in dst_ip.split("."))
    return bytes(header) + payload


def _l4_ports(src_port, dst_port):
    return struct.pack(">HH", src_port, dst_port)


class FormattingTest(unittest.TestCase):
    def test_format_mac(self):
        self.assertEqual(format_mac(_DST), "aa:bb:cc:dd:ee:ff")

    def test_format_ipv4(self):
        self.assertEqual(format_ipv4(b"\xc0\xa8\x00\x01"), "192.168.0.1")


class EthernetTest(unittest.TestCase):
    def test_basic_frame(self):
        eth = dissect_ethernet(_ether(ETHERTYPE_IPV4))
        assert eth is not None
        self.assertEqual(eth.dst_mac, "aa:bb:cc:dd:ee:ff")
        self.assertEqual(eth.src_mac, "11:22:33:44:55:66")
        self.assertEqual(eth.ethertype, ETHERTYPE_IPV4)
        self.assertIsNone(eth.vlan_id)
        self.assertEqual(eth.payload_offset, 14)

    def test_vlan_tag_stripped(self):
        eth = dissect_ethernet(_vlan(42, ETHERTYPE_IPV4))
        assert eth is not None
        self.assertEqual(eth.vlan_id, 42)
        self.assertEqual(eth.ethertype, ETHERTYPE_IPV4)
        self.assertEqual(eth.payload_offset, 18)

    def test_too_short_returns_none(self):
        self.assertIsNone(dissect_ethernet(b"\x00" * 13))

    def test_truncated_vlan_returns_none(self):
        # ethertype 은 VLAN 이지만 태그 4바이트가 모자람.
        self.assertIsNone(dissect_ethernet(_DST + _SRC + struct.pack(">H", 0x8100) + b"\x00"))


class IPv4Test(unittest.TestCase):
    def test_basic_header(self):
        ip = dissect_ipv4(_ipv4("10.0.0.1", "10.0.0.2", IP_PROTO_TCP, b"xyz"))
        assert ip is not None
        self.assertEqual(ip.src_ip, "10.0.0.1")
        self.assertEqual(ip.dst_ip, "10.0.0.2")
        self.assertEqual(ip.protocol, IP_PROTO_TCP)
        self.assertEqual(ip.ttl, 64)
        self.assertEqual(ip.header_length, 20)
        self.assertEqual(ip.total_length, 23)
        self.assertEqual(ip.payload_offset, 20)

    def test_offset_respected(self):
        packet = b"\x99" * 14 + _ipv4("1.1.1.1", "2.2.2.2", IP_PROTO_UDP)
        ip = dissect_ipv4(packet, offset=14)
        assert ip is not None
        self.assertEqual(ip.src_ip, "1.1.1.1")
        self.assertEqual(ip.payload_offset, 34)

    def test_options_extend_header_length(self):
        # IHL=6 → 24바이트 헤더(옵션 4바이트). payload_offset 가 따라가야 함.
        ip = dissect_ipv4(_ipv4("1.2.3.4", "5.6.7.8", IP_PROTO_TCP, ihl=6))
        assert ip is not None
        self.assertEqual(ip.header_length, 24)
        self.assertEqual(ip.payload_offset, 24)

    def test_non_ipv4_version_returns_none(self):
        bad = bytearray(_ipv4("1.1.1.1", "2.2.2.2", IP_PROTO_TCP))
        bad[0] = (6 << 4) | 5  # version 6
        self.assertIsNone(dissect_ipv4(bytes(bad)))

    def test_too_short_returns_none(self):
        self.assertIsNone(dissect_ipv4(b"\x45" + b"\x00" * 10))

    def test_bad_ihl_returns_none(self):
        bad = bytearray(_ipv4("1.1.1.1", "2.2.2.2", IP_PROTO_TCP))
        bad[0] = (4 << 4) | 4  # IHL=4 → 16바이트 < 최소 20
        self.assertIsNone(dissect_ipv4(bytes(bad)))


class DissectTest(unittest.TestCase):
    def test_full_tcp_stack(self):
        payload = _ipv4("10.0.0.1", "10.0.0.9", IP_PROTO_TCP, _l4_ports(51000, 443))
        d = dissect(_ether(ETHERTYPE_IPV4, payload))
        self.assertIsNotNone(d.ethernet)
        self.assertIsNotNone(d.ipv4)
        self.assertEqual(d.src_port, 51000)
        self.assertEqual(d.dst_port, 443)
        self.assertEqual(d.protocol_name, "TCP")

    def test_full_udp_stack(self):
        payload = _ipv4("192.168.1.5", "8.8.8.8", IP_PROTO_UDP, _l4_ports(5353, 53))
        d = dissect(_ether(ETHERTYPE_IPV4, payload))
        self.assertEqual(d.src_port, 5353)
        self.assertEqual(d.dst_port, 53)
        self.assertEqual(d.protocol_name, "UDP")

    def test_vlan_then_ipv4(self):
        payload = _ipv4("10.0.0.1", "10.0.0.2", IP_PROTO_TCP, _l4_ports(1, 2))
        d = dissect(_vlan(7, ETHERTYPE_IPV4, payload))
        assert d.ethernet is not None
        self.assertEqual(d.ethernet.vlan_id, 7)
        self.assertEqual(d.dst_port, 2)

    def test_raw_ip_linktype_skips_ethernet(self):
        d = dissect(_ipv4("1.1.1.1", "2.2.2.2", IP_PROTO_UDP, _l4_ports(9, 8)), linktype=101)
        self.assertIsNone(d.ethernet)
        self.assertIsNotNone(d.ipv4)
        self.assertEqual(d.src_port, 9)

    def test_non_ip_ethertype_stops_at_l2(self):
        d = dissect(_ether(ETHERTYPE_ARP, b"\x00" * 28))
        self.assertIsNotNone(d.ethernet)
        self.assertIsNone(d.ipv4)
        self.assertEqual(d.protocol_name, "?")

    def test_icmp_has_no_ports(self):
        d = dissect(_ether(ETHERTYPE_IPV4, _ipv4("1.1.1.1", "2.2.2.2", 1)))
        self.assertEqual(d.protocol_name, "ICMP")
        self.assertIsNone(d.src_port)
        self.assertIsNone(d.dst_port)

    def test_truncated_l4_leaves_ports_none(self):
        # TCP 인데 포트 바이트가 부족(잘린 캡처).
        payload = _ipv4("1.1.1.1", "2.2.2.2", IP_PROTO_TCP, b"\x01")
        d = dissect(_ether(ETHERTYPE_IPV4, payload))
        self.assertIsNotNone(d.ipv4)
        self.assertIsNone(d.src_port)

    def test_unknown_linktype_returns_empty(self):
        d = dissect(_ether(ETHERTYPE_IPV4), linktype=999)
        self.assertEqual(d, Dissection(None, None, None, None))

    def test_does_not_mutate_input(self):
        buf = _ether(ETHERTYPE_IPV4, _ipv4("1.1.1.1", "2.2.2.2", IP_PROTO_TCP, _l4_ports(1, 2)))
        snapshot = bytes(buf)
        dissect(buf)
        self.assertEqual(buf, snapshot)


if __name__ == "__main__":
    unittest.main()
