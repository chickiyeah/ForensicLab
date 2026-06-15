"""forensiclab.geneve 단위 테스트 (stdlib unittest)."""

import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from forensiclab.geneve import (  # noqa: E402
    GENEVE_PORT,
    GENEVE_PROTOCOLS,
    GeneveHeader,
    GeneveOption,
    looks_like_geneve,
    parse_geneve,
)


def _geneve(vni, *, version=0, opt_len_words=0, proto=0x6558, oam=False,
            critical=False, options=b""):
    """GENEVE 기본 헤더(8바이트) + 옵션 영역 조립."""
    ver_optlen = (version << 6) | (opt_len_words & 0x3F)
    flags = (0x80 if oam else 0) | (0x40 if critical else 0)
    return (
        bytes([ver_optlen, flags])
        + struct.pack(">H", proto)
        + bytes([(vni >> 16) & 0xFF, (vni >> 8) & 0xFF, vni & 0xFF, 0])
        + options
    )


def _option(option_class, option_type, data=b""):
    """GENEVE 옵션 TLV 한 개 조립(데이터는 4바이트 정렬 가정)."""
    assert len(data) % 4 == 0
    length_words = len(data) // 4
    return struct.pack(">H", option_class) + bytes([option_type, length_words]) + data


class ParseBasicTests(unittest.TestCase):
    def test_basic_vni(self):
        h = parse_geneve(_geneve(0x123456))
        self.assertIsInstance(h, GeneveHeader)
        self.assertEqual(h.vni, 0x123456)
        self.assertEqual(h.version, 0)
        self.assertEqual(h.header_length, 8)
        self.assertEqual(h.payload_offset, 8)
        self.assertEqual(h.opt_len, 0)
        self.assertEqual(h.options, ())

    def test_vni_zero_and_max(self):
        self.assertEqual(parse_geneve(_geneve(0)).vni, 0)
        self.assertEqual(parse_geneve(_geneve(0xFFFFFF)).vni, 0xFFFFFF)

    def test_carries_ethernet(self):
        h = parse_geneve(_geneve(1, proto=0x6558))
        self.assertTrue(h.carries_ethernet)
        self.assertFalse(h.carries_ipv4)
        self.assertFalse(h.carries_ipv6)
        self.assertEqual(h.protocol_name, "Ethernet")

    def test_carries_ipv4(self):
        h = parse_geneve(_geneve(1, proto=0x0800))
        self.assertTrue(h.carries_ipv4)
        self.assertFalse(h.carries_ethernet)
        self.assertEqual(h.protocol_name, "IPv4")

    def test_carries_ipv6(self):
        h = parse_geneve(_geneve(1, proto=0x86DD))
        self.assertTrue(h.carries_ipv6)
        self.assertEqual(h.protocol_name, "IPv6")

    def test_unknown_protocol_name(self):
        h = parse_geneve(_geneve(1, proto=0x1234))
        self.assertEqual(h.protocol_name, "0x1234")
        self.assertFalse(h.carries_ethernet)

    def test_oam_and_critical_flags(self):
        h = parse_geneve(_geneve(1, oam=True, critical=True))
        self.assertTrue(h.is_oam)
        self.assertTrue(h.is_critical)

    def test_offset_arg(self):
        data = b"\xaa\xbb" + _geneve(7) + b"INNERFRAME"
        h = parse_geneve(data, offset=2)
        self.assertEqual(h.vni, 7)
        self.assertEqual(h.payload_offset, 2 + 8)


class OptionsTests(unittest.TestCase):
    def test_single_option(self):
        opt = _option(0x0104, 0x01, data=b"\xde\xad\xbe\xef")
        h = parse_geneve(_geneve(1, opt_len_words=2, options=opt))
        self.assertEqual(h.opt_len, 8)
        self.assertEqual(h.header_length, 16)
        self.assertEqual(h.payload_offset, 16)
        self.assertEqual(len(h.options), 1)
        o = h.options[0]
        self.assertEqual(o.option_class, 0x0104)
        self.assertEqual(o.option_type, 0x01)
        self.assertFalse(o.is_critical)
        self.assertEqual(o.length, 4)
        self.assertEqual(o.data, b"\xde\xad\xbe\xef")

    def test_multiple_options(self):
        opts = _option(0x0001, 0x01, b"\x00\x00\x00\x01") + _option(0x0002, 0x02, b"")
        # 8(첫 옵션) + 4(둘째 헤더만) = 12바이트 = 3워드.
        h = parse_geneve(_geneve(9, opt_len_words=3, options=opts))
        self.assertEqual(len(h.options), 2)
        self.assertEqual(h.options[0].option_class, 0x0001)
        self.assertEqual(h.options[1].option_class, 0x0002)
        self.assertEqual(h.options[1].length, 0)

    def test_critical_option(self):
        opt = _option(0x0123, 0x80, b"\x01\x02\x03\x04")  # type 최상위=critical.
        h = parse_geneve(_geneve(1, opt_len_words=2, options=opt))
        self.assertTrue(h.options[0].is_critical)
        self.assertTrue(h.has_critical_option)

    def test_no_critical_option(self):
        opt = _option(0x0123, 0x01, b"\x01\x02\x03\x04")
        h = parse_geneve(_geneve(1, opt_len_words=2, options=opt))
        self.assertFalse(h.has_critical_option)

    def test_truncated_option_data_stops(self):
        # Opt Len 은 2워드(8바이트)인데 옵션이 length=2워드라 데이터가 영역 초과 →
        # 옵션 영역 자체는 채워졌으나 옵션 데이터가 넘쳐 멈춤(읽은 데까지).
        bad_opt = struct.pack(">H", 0x0001) + bytes([0x01, 0x03])  # length=3워드=12B
        h = parse_geneve(_geneve(1, opt_len_words=2, options=bad_opt + b"\x00\x00\x00\x00"))
        self.assertEqual(h.opt_len, 8)
        self.assertEqual(h.options, ())  # 데이터가 영역 넘어 파싱 중단.


class GuardTests(unittest.TestCase):
    def test_nonzero_version_rejected(self):
        self.assertIsNone(parse_geneve(_geneve(1, version=1)))

    def test_too_short(self):
        self.assertIsNone(parse_geneve(_geneve(1)[:7]))

    def test_empty(self):
        self.assertIsNone(parse_geneve(b""))

    def test_non_bytes(self):
        self.assertIsNone(parse_geneve(None))
        self.assertIsNone(parse_geneve(12345))

    def test_offset_past_end(self):
        self.assertIsNone(parse_geneve(_geneve(1), offset=4))

    def test_truncated_option_region_rejected(self):
        # Opt Len 은 2워드(8바이트)를 선언했지만 실제 옵션 바이트가 없음 → None.
        self.assertIsNone(parse_geneve(_geneve(1, opt_len_words=2, options=b"")))


class LooksLikeTests(unittest.TestCase):
    def test_positive(self):
        self.assertTrue(looks_like_geneve(_geneve(99)))

    def test_negative(self):
        self.assertFalse(looks_like_geneve(_geneve(1, version=2)))
        self.assertFalse(looks_like_geneve(b"short"))


class ConstantsTests(unittest.TestCase):
    def test_port(self):
        self.assertEqual(GENEVE_PORT, 6081)

    def test_protocol_table(self):
        self.assertEqual(GENEVE_PROTOCOLS[0x6558], "Ethernet")
        self.assertEqual(GENEVE_PROTOCOLS[0x0800], "IPv4")


if __name__ == "__main__":
    unittest.main()
