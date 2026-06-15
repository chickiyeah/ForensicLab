"""forensiclab.vxlan 단위 테스트 (stdlib unittest)."""

import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from forensiclab.vxlan import (  # noqa: E402
    VXLAN_GPE_PROTOCOLS,
    VXLAN_PORTS,
    VxlanHeader,
    looks_like_vxlan,
    parse_vxlan,
)


def _vxlan(vni, *, flags=0x08, last=0x00):
    """표준 VXLAN 헤더(8바이트) 조립: Flags·Reserved(3)·VNI(3)·last(1)."""
    return (
        bytes([flags, 0, 0, 0])
        + bytes([(vni >> 16) & 0xFF, (vni >> 8) & 0xFF, vni & 0xFF])
        + bytes([last])
    )


def _vxlan_gpe(vni, next_proto):
    """VXLAN-GPE 헤더(P 비트 + 마지막 바이트 Next Protocol)."""
    return _vxlan(vni, flags=0x08 | 0x04, last=next_proto)


class ParseStandardVxlanTests(unittest.TestCase):
    def test_basic_vni(self):
        h = parse_vxlan(_vxlan(0x123456))
        self.assertIsInstance(h, VxlanHeader)
        self.assertEqual(h.vni, 0x123456)
        self.assertTrue(h.valid_vni)
        self.assertFalse(h.is_gpe)
        self.assertEqual(h.header_length, 8)
        self.assertEqual(h.payload_offset, 8)

    def test_vni_zero(self):
        h = parse_vxlan(_vxlan(0))
        self.assertIsNotNone(h)
        self.assertEqual(h.vni, 0)

    def test_vni_max(self):
        h = parse_vxlan(_vxlan(0xFFFFFF))
        self.assertEqual(h.vni, 0xFFFFFF)

    def test_carries_ethernet(self):
        h = parse_vxlan(_vxlan(100))
        self.assertTrue(h.carries_ethernet)
        self.assertFalse(h.carries_ipv4)
        self.assertFalse(h.carries_ipv6)
        self.assertIsNone(h.next_protocol)

    def test_payload_offset_with_offset_arg(self):
        data = b"\xaa\xbb" + _vxlan(7) + b"INNERFRAME"
        h = parse_vxlan(data, offset=2)
        self.assertEqual(h.vni, 7)
        self.assertEqual(h.payload_offset, 10)

    def test_bum_and_oam_flags(self):
        h = parse_vxlan(_vxlan(5, flags=0x08 | 0x02 | 0x01))
        self.assertTrue(h.is_bum)
        self.assertTrue(h.is_oam)


class ParseGpeVxlanTests(unittest.TestCase):
    def test_gpe_ipv4(self):
        h = parse_vxlan(_vxlan_gpe(0x010203, 1))
        self.assertTrue(h.is_gpe)
        self.assertEqual(h.next_protocol, 1)
        self.assertEqual(h.next_protocol_name, "IPv4")
        self.assertTrue(h.carries_ipv4)
        self.assertFalse(h.carries_ethernet)

    def test_gpe_ipv6(self):
        h = parse_vxlan(_vxlan_gpe(1, 2))
        self.assertTrue(h.carries_ipv6)
        self.assertEqual(h.next_protocol_name, "IPv6")

    def test_gpe_ethernet(self):
        h = parse_vxlan(_vxlan_gpe(1, 3))
        self.assertTrue(h.carries_ethernet)
        self.assertEqual(h.next_protocol_name, "Ethernet")

    def test_gpe_nsh(self):
        h = parse_vxlan(_vxlan_gpe(1, 4))
        self.assertEqual(h.next_protocol_name, "NSH")

    def test_gpe_unknown_next_proto(self):
        h = parse_vxlan(_vxlan_gpe(1, 0x99))
        self.assertEqual(h.next_protocol, 0x99)
        self.assertEqual(h.next_protocol_name, "0x99")

    def test_gpe_allows_nonzero_last_byte(self):
        # GPE 는 마지막 바이트가 Next Protocol 이므로 0 이 아니어도 정상.
        self.assertIsNotNone(parse_vxlan(_vxlan_gpe(1, 1)))


class GuardTests(unittest.TestCase):
    def test_missing_i_bit_rejected(self):
        self.assertIsNone(parse_vxlan(_vxlan(1, flags=0x00)))

    def test_standard_nonzero_reserved_rejected(self):
        # 표준 VXLAN(I 만) 인데 마지막 Reserved 바이트가 0 이 아니면 거부.
        self.assertIsNone(parse_vxlan(_vxlan(1, last=0x05)))

    def test_too_short(self):
        self.assertIsNone(parse_vxlan(_vxlan(1)[:7]))

    def test_empty(self):
        self.assertIsNone(parse_vxlan(b""))

    def test_non_bytes(self):
        self.assertIsNone(parse_vxlan(None))
        self.assertIsNone(parse_vxlan(12345))

    def test_offset_past_end(self):
        self.assertIsNone(parse_vxlan(_vxlan(1), offset=4))


class LooksLikeTests(unittest.TestCase):
    def test_positive(self):
        self.assertTrue(looks_like_vxlan(_vxlan(99)))
        self.assertTrue(looks_like_vxlan(_vxlan_gpe(99, 1)))

    def test_negative(self):
        self.assertFalse(looks_like_vxlan(b"\x00" * 8))
        self.assertFalse(looks_like_vxlan(b"short"))


class ConstantsTests(unittest.TestCase):
    def test_ports(self):
        self.assertIn(4789, VXLAN_PORTS)

    def test_gpe_protocol_table(self):
        self.assertEqual(VXLAN_GPE_PROTOCOLS[3], "Ethernet")


if __name__ == "__main__":
    unittest.main()
