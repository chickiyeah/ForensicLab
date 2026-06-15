"""forensiclab.arp 단위 테스트 (stdlib unittest)."""

import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from forensiclab.arp import (  # noqa: E402
    ARP_REPLY,
    ARP_REQUEST,
    Arp,
    format_ipv4,
    format_mac,
    parse_arp,
)


def _arp(oper, sha, spa, tha, tpa, htype=1, ptype=0x0800, hlen=6, plen=4):
    """Ethernet+IPv4 ARP 패킷 바이트를 짠다."""
    return (
        struct.pack(">HHBBH", htype, ptype, hlen, plen, oper)
        + sha + spa + tha + tpa
    )


# 테스트용 주소 상수.
MAC_A = b"\xaa\xbb\xcc\x00\x00\x01"
MAC_B = b"\xaa\xbb\xcc\x00\x00\x02"
IP_A = bytes([192, 168, 0, 1])
IP_B = bytes([192, 168, 0, 2])
ZERO_MAC = b"\x00" * 6


class FormatTests(unittest.TestCase):
    def test_format_mac(self):
        self.assertEqual(format_mac(MAC_A), "aa:bb:cc:00:00:01")

    def test_format_ipv4(self):
        self.assertEqual(format_ipv4(IP_A), "192.168.0.1")

    def test_format_ipv4_nonstandard_length(self):
        self.assertEqual(format_ipv4(b"\x01\x02"), "0102")


class ParseArpTests(unittest.TestCase):
    def test_request_round_trip(self):
        # 누가 192.168.0.2 의 MAC 을 아느냐 (target MAC 미상 → 0).
        pkt = _arp(ARP_REQUEST, MAC_A, IP_A, ZERO_MAC, IP_B)
        arp = parse_arp(pkt)
        self.assertIsNotNone(arp)
        self.assertEqual(arp.oper, ARP_REQUEST)
        self.assertEqual(arp.oper_name, "request")
        self.assertTrue(arp.is_ethernet_ipv4)
        self.assertEqual(arp.sender_mac, "aa:bb:cc:00:00:01")
        self.assertEqual(arp.sender_ip, "192.168.0.1")
        self.assertEqual(arp.target_mac, "00:00:00:00:00:00")
        self.assertEqual(arp.target_ip, "192.168.0.2")
        self.assertFalse(arp.is_gratuitous)

    def test_reply_round_trip(self):
        pkt = _arp(ARP_REPLY, MAC_B, IP_B, MAC_A, IP_A)
        arp = parse_arp(pkt)
        self.assertEqual(arp.oper, ARP_REPLY)
        self.assertEqual(arp.oper_name, "reply")
        self.assertEqual(arp.sender_mac, "aa:bb:cc:00:00:02")

    def test_gratuitous_arp(self):
        # sender 와 target 프로토콜 주소가 동일.
        pkt = _arp(ARP_REPLY, MAC_A, IP_A, ZERO_MAC, IP_A)
        arp = parse_arp(pkt)
        self.assertTrue(arp.is_gratuitous)

    def test_unknown_oper_name(self):
        pkt = _arp(99, MAC_A, IP_A, MAC_B, IP_B)
        self.assertEqual(parse_arp(pkt).oper_name, "oper-99")

    def test_non_ethernet_ipv4_preserved(self):
        # htype 0, hlen/plen 2 짜리 가상 조합 — 원시 바이트로 보존.
        pkt = _arp(1, b"\x11\x22", b"\x33\x44", b"\x55\x66", b"\x77\x88",
                   htype=0, ptype=0x1234, hlen=2, plen=2)
        arp = parse_arp(pkt)
        self.assertFalse(arp.is_ethernet_ipv4)
        self.assertEqual(arp.sha, b"\x11\x22")
        self.assertEqual(arp.spa, b"\x33\x44")

    def test_offset(self):
        prefix = b"\xde\xad\xbe\xef"
        pkt = _arp(ARP_REQUEST, MAC_A, IP_A, ZERO_MAC, IP_B)
        arp = parse_arp(prefix + pkt, offset=len(prefix))
        self.assertEqual(arp.sender_ip, "192.168.0.1")

    def test_too_short_fixed_header_returns_none(self):
        self.assertIsNone(parse_arp(b"\x00" * 7))
        self.assertIsNone(parse_arp(b""))

    def test_truncated_addresses_returns_none(self):
        # 고정 헤더는 있으나 주소 4쌍이 모자람.
        pkt = _arp(ARP_REQUEST, MAC_A, IP_A, ZERO_MAC, IP_B)[:-1]
        self.assertIsNone(parse_arp(pkt))

    def test_negative_offset_returns_none(self):
        self.assertIsNone(parse_arp(b"\x00" * 28, offset=-1))

    def test_input_not_mutated(self):
        pkt = _arp(ARP_REQUEST, MAC_A, IP_A, ZERO_MAC, IP_B)
        before = bytes(pkt)
        parse_arp(pkt)
        self.assertEqual(pkt, before)


if __name__ == "__main__":
    unittest.main()
