"""forensiclab.rtp 단위 테스트 (stdlib unittest)."""

import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from forensiclab.rtp import (  # noqa: E402
    PT_H263,
    PT_PCMA,
    PT_PCMU,
    RTP_HEADER_SIZE,
    RTP_VERSION,
    Rtp,
    is_audio_payload,
    is_rtcp_packet,
    is_video_payload,
    parse_rtp,
    payload_type_name,
)


def _rtp(b0: int, b1: int, seq: int, ts: int, ssrc: int, rest: bytes = b"") -> bytes:
    return struct.pack(">BBHII", b0, b1, seq, ts, ssrc) + rest


# V=2 -> 0x80, P/X/CC=0. PT=PCMU, M=0.
_BASE = _rtp(0x80, PT_PCMU, 1000, 0xDEADBEEF, 0x11223344, b"audio-bytes")


class ParseRtpTest(unittest.TestCase):
    def test_basic_header(self):
        r = parse_rtp(_BASE)
        self.assertIsNotNone(r)
        self.assertEqual(r.version, RTP_VERSION)
        self.assertFalse(r.padding)
        self.assertFalse(r.extension)
        self.assertEqual(r.csrc_count, 0)
        self.assertFalse(r.marker)
        self.assertEqual(r.payload_type, PT_PCMU)
        self.assertEqual(r.sequence, 1000)
        self.assertEqual(r.timestamp, 0xDEADBEEF)
        self.assertEqual(r.ssrc, 0x11223344)
        self.assertEqual(r.csrc, ())
        self.assertEqual(r.payload_offset, RTP_HEADER_SIZE)

    def test_payload_after_header(self):
        r = parse_rtp(_BASE)
        self.assertEqual(_BASE[r.payload_offset:], b"audio-bytes")

    def test_too_short(self):
        self.assertIsNone(parse_rtp(_BASE[:11]))

    def test_wrong_version(self):
        # 상위 2비트 = 1(0x40) — RTP 버전 2 아님.
        self.assertIsNone(parse_rtp(_rtp(0x40, PT_PCMU, 1, 2, 3)))
        # 상위 2비트 = 0 (고전/비-RTP).
        self.assertIsNone(parse_rtp(_rtp(0x00, PT_PCMU, 1, 2, 3)))

    def test_marker_bit(self):
        r = parse_rtp(_rtp(0x80, 0x80 | PT_PCMA, 1, 2, 3))
        self.assertTrue(r.marker)
        self.assertEqual(r.payload_type, PT_PCMA)


class FlagsTest(unittest.TestCase):
    def test_padding_extension_bits(self):
        # P=0x20, X=0x10 둘 다 켜고 확장 헤더 1워드 첨부.
        ext = struct.pack(">HH", 0xBEDE, 1) + b"\x01\x02\x03\x04"
        r = parse_rtp(_rtp(0x80 | 0x20 | 0x10, PT_PCMU, 1, 2, 3, ext))
        self.assertTrue(r.padding)
        self.assertTrue(r.extension)
        self.assertEqual(r.ext_profile, 0xBEDE)
        self.assertEqual(r.ext_data, b"\x01\x02\x03\x04")
        self.assertEqual(r.payload_offset, RTP_HEADER_SIZE + 8)

    def test_extension_truncated(self):
        # X 비트지만 확장 헤더 4바이트도 없음 -> None.
        self.assertIsNone(parse_rtp(_rtp(0x80 | 0x10, PT_PCMU, 1, 2, 3)))

    def test_extension_length_overflow(self):
        # 확장 길이 5워드(20바이트) 알리지만 데이터 없음 -> None.
        bad = _rtp(0x80 | 0x10, PT_PCMU, 1, 2, 3, struct.pack(">HH", 0xBEDE, 5))
        self.assertIsNone(parse_rtp(bad))


class CsrcTest(unittest.TestCase):
    def test_csrc_list(self):
        # CC=2, 두 기여 소스.
        body = struct.pack(">II", 0xAAAAAAAA, 0xBBBBBBBB) + b"payload"
        r = parse_rtp(_rtp(0x82, PT_PCMU, 1, 2, 0xCCCCCCCC, body))
        self.assertEqual(r.csrc_count, 2)
        self.assertEqual(r.csrc, (0xAAAAAAAA, 0xBBBBBBBB))
        self.assertTrue(r.has_contributors)
        self.assertEqual(r.payload_offset, RTP_HEADER_SIZE + 8)
        self.assertEqual(_rtp(0x82, PT_PCMU, 1, 2, 0xCCCCCCCC, body)[r.payload_offset:], b"payload")

    def test_csrc_overflow(self):
        # CC=3 알리지만 CSRC 바이트 부족 -> None.
        self.assertIsNone(parse_rtp(_rtp(0x83, PT_PCMU, 1, 2, 3, b"\x00\x00\x00\x00")))

    def test_no_contributors(self):
        self.assertFalse(parse_rtp(_BASE).has_contributors)


class PayloadTypeTest(unittest.TestCase):
    def test_names(self):
        self.assertEqual(payload_type_name(PT_PCMU), "PCMU")
        self.assertEqual(payload_type_name(PT_PCMA), "PCMA")
        self.assertEqual(payload_type_name(PT_H263), "H263")
        self.assertEqual(payload_type_name(96), "dynamic-96")
        self.assertEqual(payload_type_name(127), "dynamic-127")
        self.assertEqual(payload_type_name(50), "PT-50")

    def test_audio_video_classification(self):
        self.assertTrue(is_audio_payload(PT_PCMU))
        self.assertTrue(is_audio_payload(PT_PCMA))
        self.assertFalse(is_audio_payload(PT_H263))
        self.assertTrue(is_video_payload(PT_H263))
        self.assertFalse(is_video_payload(PT_PCMU))

    def test_dynamic_property(self):
        r = parse_rtp(_rtp(0x80, 96, 1, 2, 3))
        self.assertTrue(r.is_dynamic_payload)
        self.assertFalse(r.is_audio)
        self.assertFalse(r.is_video)
        self.assertEqual(r.payload_type_name, "dynamic-96")

    def test_audio_property(self):
        self.assertTrue(parse_rtp(_BASE).is_audio)
        self.assertFalse(parse_rtp(_BASE).is_video)


class RtcpDemuxTest(unittest.TestCase):
    def test_rtcp_rejected_by_parse(self):
        # PT=200(SR), V=2 -> RTCP 다중화 -> parse_rtp None.
        rtcp = _rtp(0x80, 200, 0, 0, 0x12345678)
        self.assertTrue(is_rtcp_packet(rtcp))
        self.assertIsNone(parse_rtp(rtcp))

    def test_rtcp_range(self):
        for pt in (200, 201, 202, 203, 204):
            self.assertTrue(is_rtcp_packet(_rtp(0x80, pt, 0, 0, 0)))
        # 경계 밖.
        self.assertFalse(is_rtcp_packet(_rtp(0x80, 199, 0, 0, 0)))
        self.assertFalse(is_rtcp_packet(_rtp(0x80, 205, 0, 0, 0)))
        # RTP 정상 PT 는 RTCP 아님.
        self.assertFalse(is_rtcp_packet(_BASE))

    def test_rtcp_wrong_version_not_flagged(self):
        self.assertFalse(is_rtcp_packet(_rtp(0x00, 200, 0, 0, 0)))


class OffsetTest(unittest.TestCase):
    def test_offset(self):
        framed = b"\xff\xff" + _BASE
        r = parse_rtp(framed, offset=2)
        self.assertEqual(r.ssrc, 0x11223344)
        self.assertEqual(r.payload_offset, 2 + RTP_HEADER_SIZE)

    def test_negative_offset(self):
        self.assertIsNone(parse_rtp(_BASE, offset=-1))


if __name__ == "__main__":
    unittest.main()
