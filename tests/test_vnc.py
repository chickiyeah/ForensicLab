"""forensiclab.vnc 단위 테스트 (stdlib unittest)."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from forensiclab.vnc import (  # noqa: E402
    RFB_HANDSHAKE_LEN,
    RfbVersion,
    parse_rfb_version,
)


class ParseRfbVersionTest(unittest.TestCase):
    def test_standard_3_8(self):
        v = parse_rfb_version(b"RFB 003.008\n")
        self.assertIsInstance(v, RfbVersion)
        self.assertEqual(v.major, 3)
        self.assertEqual(v.minor, 8)
        self.assertEqual(v.version, "3.8")
        self.assertEqual(v.raw, "RFB 003.008")
        self.assertTrue(v.is_standard)
        self.assertFalse(v.is_legacy_3_3)

    def test_standard_3_7(self):
        v = parse_rfb_version(b"RFB 003.007\n")
        self.assertEqual((v.major, v.minor), (3, 7))
        self.assertTrue(v.is_standard)

    def test_legacy_3_3_weak_auth(self):
        v = parse_rfb_version(b"RFB 003.003\n")
        self.assertEqual(v.version, "3.3")
        self.assertTrue(v.is_legacy_3_3)
        self.assertTrue(v.is_standard)

    def test_handshake_len_constant(self):
        self.assertEqual(len(b"RFB 003.008\n"), RFB_HANDSHAKE_LEN)

    def test_missing_trailing_lf_still_parses(self):
        # 트레일링 LF 가 없어도 11바이트 핵심으로 판별.
        v = parse_rfb_version(b"RFB 003.008")
        self.assertEqual(v.version, "3.8")
        self.assertEqual(v.raw, "RFB 003.008")

    def test_nonstandard_version_fingerprint(self):
        # Apple Remote Desktop 류 비표준 버전 — 구현 핑거프린트.
        v = parse_rfb_version(b"RFB 003.889\n")
        self.assertEqual((v.major, v.minor), (3, 889))
        self.assertFalse(v.is_standard)
        self.assertFalse(v.is_legacy_3_3)

    def test_nonstandard_major(self):
        v = parse_rfb_version(b"RFB 004.001\n")
        self.assertEqual((v.major, v.minor), (4, 1))
        self.assertFalse(v.is_standard)

    def test_trailing_bytes_after_handshake_ignored(self):
        # 12바이트 뒤 자투리(다음 메시지 등)는 무시.
        v = parse_rfb_version(b"RFB 003.008\n\x01extra")
        self.assertEqual(v.version, "3.8")

    def test_offset(self):
        v = parse_rfb_version(b"\x00\x00RFB 003.008\n", offset=2)
        self.assertEqual(v.version, "3.8")

    def test_not_rfb_returns_none(self):
        self.assertIsNone(parse_rfb_version(b"SSH-2.0-OpenSSH_9.6\r\n"))

    def test_wrong_prefix_returns_none(self):
        self.assertIsNone(parse_rfb_version(b"XFB 003.008\n"))

    def test_missing_dot_returns_none(self):
        self.assertIsNone(parse_rfb_version(b"RFB 003x008\n"))

    def test_nondigit_field_returns_none(self):
        self.assertIsNone(parse_rfb_version(b"RFB 0a3.008\n"))

    def test_too_short_returns_none(self):
        self.assertIsNone(parse_rfb_version(b"RFB 003.0"))

    def test_empty_returns_none(self):
        self.assertIsNone(parse_rfb_version(b""))

    def test_negative_offset_returns_none(self):
        self.assertIsNone(parse_rfb_version(b"RFB 003.008\n", offset=-1))

    def test_raw_not_mutated(self):
        data = bytearray(b"RFB 003.008\n")
        parse_rfb_version(bytes(data))
        self.assertEqual(data, bytearray(b"RFB 003.008\n"))


if __name__ == "__main__":
    unittest.main()
