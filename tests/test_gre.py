"""forensiclab.gre 단위 테스트 (stdlib unittest)."""

import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from forensiclab.gre import (  # noqa: E402
    GreHeader,
    looks_like_gre,
    parse_gre,
)


def _gre_v0(proto, *, checksum=None, key=None, sequence=None, routing=False):
    """버전0 GRE 헤더 조립(필요 플래그만 켬)."""
    flags0 = 0
    if checksum is not None:
        flags0 |= 0x80
    if routing:
        flags0 |= 0x40
    if key is not None:
        flags0 |= 0x20
    if sequence is not None:
        flags0 |= 0x10
    out = bytes([flags0, 0x00]) + struct.pack(">H", proto)
    if checksum is not None:
        out += struct.pack(">HH", checksum, 0)
    if key is not None:
        out += struct.pack(">I", key)
    if sequence is not None:
        out += struct.pack(">I", sequence)
    return out


def _gre_v1(payload_len, call_id, *, sequence=None, ack=None):
    """버전1(Enhanced GRE/PPTP) 헤더 조립."""
    flags0 = 0x20  # K 항상
    if sequence is not None:
        flags0 |= 0x10
    flags1 = 0x01  # Version=1
    if ack is not None:
        flags1 |= 0x80
    out = bytes([flags0, flags1]) + struct.pack(">H", 0x880B)
    out += struct.pack(">HH", payload_len, call_id)
    if sequence is not None:
        out += struct.pack(">I", sequence)
    if ack is not None:
        out += struct.pack(">I", ack)
    return out


class GuardTests(unittest.TestCase):
    def test_non_bytes(self):
        self.assertIsNone(parse_gre(None))
        self.assertIsNone(parse_gre(42))

    def test_too_short(self):
        self.assertIsNone(parse_gre(b"\x00\x00"))
        self.assertIsNone(parse_gre(b""))

    def test_bad_version(self):
        # 버전 필드(byte1 하위 3비트)=2 는 GRE 아님.
        self.assertIsNone(parse_gre(bytes([0x00, 0x02, 0x08, 0x00])))

    def test_v1_must_be_ppp(self):
        # 버전1 인데 protocol 이 PPP(0x880B)가 아니면 거부.
        data = bytes([0x20, 0x01]) + struct.pack(">H", 0x0800) + b"\x00" * 4
        self.assertIsNone(parse_gre(data))

    def test_truncated_optional_field(self):
        # K 비트는 켰는데 Key 4바이트가 없으면 None.
        data = bytes([0x20, 0x00]) + struct.pack(">H", 0x0800) + b"\x00\x00"
        self.assertIsNone(parse_gre(data))


class V0Tests(unittest.TestCase):
    def test_minimal_ipv4(self):
        h = parse_gre(_gre_v0(0x0800))
        self.assertIsInstance(h, GreHeader)
        self.assertEqual(h.version, 0)
        self.assertEqual(h.protocol, "IPv4")
        self.assertTrue(h.carries_ipv4)
        self.assertFalse(h.carries_ipv6)
        self.assertEqual(h.header_length, 4)
        self.assertEqual(h.payload_offset, 4)
        self.assertIsNone(h.key)

    def test_ipv6_carrier(self):
        h = parse_gre(_gre_v0(0x86DD))
        self.assertEqual(h.protocol, "IPv6")
        self.assertTrue(h.carries_ipv6)

    def test_key_field(self):
        h = parse_gre(_gre_v0(0x0800, key=0xDEADBEEF))
        self.assertTrue(h.has_key)
        self.assertEqual(h.key, 0xDEADBEEF)
        self.assertEqual(h.header_length, 8)
        self.assertEqual(h.payload_offset, 8)

    def test_checksum_and_sequence(self):
        h = parse_gre(_gre_v0(0x0800, checksum=0x1234, sequence=7))
        self.assertTrue(h.has_checksum)
        self.assertEqual(h.checksum, 0x1234)
        self.assertTrue(h.has_sequence)
        self.assertEqual(h.sequence, 7)
        # 4(기본)+4(cksum+rsv)+4(seq)=12.
        self.assertEqual(h.header_length, 12)

    def test_all_fields_order(self):
        # C+K+S 모두: Checksum → Key → Sequence 순서·오프셋 누적.
        h = parse_gre(_gre_v0(0x0800, checksum=1, key=2, sequence=3))
        self.assertEqual(h.checksum, 1)
        self.assertEqual(h.key, 2)
        self.assertEqual(h.sequence, 3)
        self.assertEqual(h.header_length, 16)

    def test_unknown_protocol_hex(self):
        h = parse_gre(_gre_v0(0x1234))
        self.assertEqual(h.protocol, "0x1234")

    def test_payload_offset_with_inner_data(self):
        inner = b"INNERPKT"
        h = parse_gre(_gre_v0(0x0800, key=1) + inner)
        self.assertEqual(h.payload_offset, 8)


class TunnelTypeTests(unittest.TestCase):
    def test_erspan_ii(self):
        h = parse_gre(_gre_v0(0x88BE, sequence=1))
        self.assertTrue(h.is_erspan)
        self.assertEqual(h.protocol, "ERSPAN_II")

    def test_erspan_iii(self):
        h = parse_gre(_gre_v0(0x22EB, sequence=1))
        self.assertTrue(h.is_erspan)
        self.assertEqual(h.protocol, "ERSPAN_III")

    def test_nvgre_teb(self):
        h = parse_gre(_gre_v0(0x6558, key=0x010203))
        self.assertTrue(h.is_nvgre)
        self.assertEqual(h.protocol, "TEB")

    def test_plain_ipv4_not_special(self):
        h = parse_gre(_gre_v0(0x0800))
        self.assertFalse(h.is_erspan)
        self.assertFalse(h.is_nvgre)
        self.assertFalse(h.is_pptp)


class PptpTests(unittest.TestCase):
    def test_basic_pptp(self):
        h = parse_gre(_gre_v1(1500, 0xABCD))
        self.assertEqual(h.version, 1)
        self.assertTrue(h.is_pptp)
        self.assertEqual(h.protocol, "PPP")
        self.assertEqual(h.payload_length, 1500)
        self.assertEqual(h.call_id, 0xABCD)
        self.assertEqual(h.header_length, 8)

    def test_pptp_with_sequence(self):
        h = parse_gre(_gre_v1(1000, 0x0001, sequence=42))
        self.assertTrue(h.is_pptp)
        self.assertEqual(h.sequence, 42)
        self.assertEqual(h.header_length, 12)

    def test_pptp_with_ack(self):
        h = parse_gre(_gre_v1(0, 0x0001, ack=99))
        self.assertTrue(h.has_ack)
        self.assertEqual(h.ack, 99)
        # Payload Length 0 = Ack-only(데이터 없는 ACK) 패킷.
        self.assertEqual(h.payload_length, 0)

    def test_pptp_seq_and_ack(self):
        h = parse_gre(_gre_v1(500, 0x0002, sequence=10, ack=9))
        self.assertEqual(h.sequence, 10)
        self.assertEqual(h.ack, 9)
        self.assertEqual(h.header_length, 16)


class HelperTests(unittest.TestCase):
    def test_looks_like_gre(self):
        self.assertTrue(looks_like_gre(_gre_v0(0x0800)))
        self.assertFalse(looks_like_gre(b"\x00\x02\x08\x00"))

    def test_offset(self):
        prefix = b"\xff\xff"
        h = parse_gre(prefix + _gre_v0(0x0800, key=5), offset=2)
        self.assertEqual(h.key, 5)
        self.assertEqual(h.payload_offset, 2 + 8)


if __name__ == "__main__":
    unittest.main()
