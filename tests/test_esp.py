"""forensiclab.esp 단위 테스트 (stdlib unittest)."""

import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from forensiclab.esp import (  # noqa: E402
    ESP_IP_PROTO,
    ESP_NAT_T_PORT,
    EspHeader,
    looks_like_esp,
    parse_esp,
)


def _esp(spi, sequence, payload=b""):
    """ESP 헤더(8바이트 SPI+Sequence) + (선택)암호화된 페이로드 자리 조립."""
    return struct.pack(">II", spi, sequence) + payload


class ParseBasicTests(unittest.TestCase):
    def test_basic(self):
        h = parse_esp(_esp(0x12345678, 1))
        self.assertIsInstance(h, EspHeader)
        self.assertEqual(h.spi, 0x12345678)
        self.assertEqual(h.sequence, 1)
        self.assertEqual(h.header_length, 8)
        self.assertEqual(h.payload_offset, 8)

    def test_spi_and_sequence_max(self):
        h = parse_esp(_esp(0xFFFFFFFF, 0xFFFFFFFF))
        self.assertEqual(h.spi, 0xFFFFFFFF)
        self.assertEqual(h.sequence, 0xFFFFFFFF)

    def test_payload_offset_with_ciphertext(self):
        h = parse_esp(_esp(0xAABBCCDD, 42, payload=b"\x01\x02\x03\x04\x05"))
        # 암호화된 본문은 풀지 않고 시작 오프셋만 노출.
        self.assertEqual(h.payload_offset, 8)
        self.assertEqual(h.spi, 0xAABBCCDD)
        self.assertEqual(h.sequence, 42)

    def test_is_initial_true(self):
        self.assertTrue(parse_esp(_esp(0x10, 1)).is_initial)

    def test_is_initial_false(self):
        self.assertFalse(parse_esp(_esp(0x10, 0)).is_initial)
        self.assertFalse(parse_esp(_esp(0x10, 2)).is_initial)
        self.assertFalse(parse_esp(_esp(0x10, 1000)).is_initial)

    def test_offset_arg(self):
        data = b"\xde\xad" + _esp(0x99, 7) + b"CIPHER"
        h = parse_esp(data, offset=2)
        self.assertEqual(h.spi, 0x99)
        self.assertEqual(h.sequence, 7)
        self.assertEqual(h.payload_offset, 2 + 8)


class GuardTests(unittest.TestCase):
    def test_spi_zero_rejected(self):
        # SPI 0 은 예약값 — 거부. UDP 4500 비-ESP 마커(=IKE) 오인 방지.
        self.assertIsNone(parse_esp(_esp(0, 1)))

    def test_non_esp_marker_rejected(self):
        # IKE-over-4500 의 4바이트-0 비-ESP 마커는 SPI 0 으로 읽혀 거부돼야 한다.
        self.assertIsNone(parse_esp(b"\x00\x00\x00\x00" + b"\x21\x20\x22\x08"))

    def test_too_short(self):
        self.assertIsNone(parse_esp(_esp(0x10, 1)[:7]))

    def test_empty(self):
        self.assertIsNone(parse_esp(b""))

    def test_non_bytes(self):
        self.assertIsNone(parse_esp(None))
        self.assertIsNone(parse_esp(12345))

    def test_offset_past_end(self):
        self.assertIsNone(parse_esp(_esp(0x10, 1), offset=4))


class LooksLikeTests(unittest.TestCase):
    def test_positive(self):
        self.assertTrue(looks_like_esp(_esp(0xABCDEF, 5)))

    def test_negative(self):
        self.assertFalse(looks_like_esp(_esp(0, 1)))
        self.assertFalse(looks_like_esp(b"short"))


class ConstantsTests(unittest.TestCase):
    def test_ip_proto(self):
        self.assertEqual(ESP_IP_PROTO, 50)

    def test_nat_t_port(self):
        self.assertEqual(ESP_NAT_T_PORT, 4500)


if __name__ == "__main__":
    unittest.main()
