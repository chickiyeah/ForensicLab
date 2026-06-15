"""forensiclab.quic 단위 테스트 (stdlib unittest)."""

import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from forensiclab.quic import (  # noqa: E402
    MAX_CID_LEN,
    PKT_HANDSHAKE,
    PKT_INITIAL,
    PKT_RETRY,
    QUIC_PORT,
    QUIC_V1,
    QUIC_V2,
    VERSION_NEGOTIATION,
    QuicLongHeader,
    is_short_header,
    looks_like_quic,
    parse_quic,
)


def _long(version, dcid, scid, *, type_bits=0, fixed=True, form=True):
    """롱 헤더(헤더까지) 조립."""
    b0 = 0
    if form:
        b0 |= 0x80
    if fixed:
        b0 |= 0x40
    b0 |= (type_bits & 0x03) << 4
    return (
        bytes([b0])
        + struct.pack(">I", version)
        + bytes([len(dcid)]) + dcid
        + bytes([len(scid)]) + scid
    )


def _version_negotiation(dcid, scid, versions):
    body = (
        bytes([0xC0])  # Form 1 + 임의 비트
        + struct.pack(">I", VERSION_NEGOTIATION)
        + bytes([len(dcid)]) + dcid
        + bytes([len(scid)]) + scid
    )
    for v in versions:
        body += struct.pack(">I", v)
    return body


class LongHeaderTests(unittest.TestCase):
    def test_initial_v1(self):
        h = parse_quic(_long(QUIC_V1, b"\x01\x02\x03\x04", b"\xaa\xbb", type_bits=0)
                       + b"\xff" * 50)
        self.assertIsInstance(h, QuicLongHeader)
        self.assertEqual(h.version, QUIC_V1)
        self.assertEqual(h.version_name, "quic_v1")
        self.assertEqual(h.dcid, b"\x01\x02\x03\x04")
        self.assertEqual(h.scid, b"\xaa\xbb")
        self.assertEqual(h.dcid_hex, "01020304")
        self.assertEqual(h.scid_hex, "aabb")
        self.assertTrue(h.is_initial)
        self.assertEqual(h.type_name, PKT_INITIAL)
        self.assertTrue(h.fixed_bit)
        self.assertFalse(h.is_version_negotiation)
        # payload_offset = 1 + 4 + (1+4) + (1+2) = 13.
        self.assertEqual(h.payload_offset, 13)

    def test_handshake_v1(self):
        h = parse_quic(_long(QUIC_V1, b"\x00", b"\x00", type_bits=2))
        self.assertTrue(h.is_handshake)
        self.assertEqual(h.type_name, PKT_HANDSHAKE)
        self.assertFalse(h.is_initial)

    def test_retry_v1(self):
        h = parse_quic(_long(QUIC_V1, b"abc", b"de", type_bits=3) + b"token")
        self.assertTrue(h.is_retry)
        self.assertEqual(h.type_name, PKT_RETRY)

    def test_v2_type_remap(self):
        # v2 에서 코드 1 = Initial, 코드 0 = Retry.
        h_init = parse_quic(_long(QUIC_V2, b"\x01", b"\x02", type_bits=1))
        self.assertTrue(h_init.is_initial)
        self.assertEqual(h_init.version_name, "quic_v2")
        h_retry = parse_quic(_long(QUIC_V2, b"\x01", b"\x02", type_bits=0))
        self.assertTrue(h_retry.is_retry)

    def test_empty_connection_ids(self):
        h = parse_quic(_long(QUIC_V1, b"", b"", type_bits=0))
        self.assertEqual(h.dcid, b"")
        self.assertEqual(h.scid, b"")
        self.assertEqual(h.dcid_hex, "")
        self.assertEqual(h.payload_offset, 7)

    def test_max_length_cid(self):
        dcid = bytes(range(MAX_CID_LEN))
        h = parse_quic(_long(QUIC_V1, dcid, b"\x09"))
        self.assertEqual(h.dcid, dcid)


class VersionTests(unittest.TestCase):
    def test_draft_version(self):
        h = parse_quic(_long(0xFF00001D, b"\x01", b"\x02"))
        self.assertEqual(h.version_name, "draft-29")

    def test_grease_version(self):
        h = parse_quic(_long(0x0A0A0A0A, b"\x01", b"\x02"))
        self.assertTrue(h.is_grease_version)
        self.assertEqual(h.version_name, "grease")

    def test_unknown_version(self):
        h = parse_quic(_long(0x12345678, b"\x01", b"\x02"))
        self.assertEqual(h.version_name, "unknown_0x12345678")
        self.assertFalse(h.is_grease_version)


class VersionNegotiationTests(unittest.TestCase):
    def test_basic(self):
        h = parse_quic(_version_negotiation(b"\xde\xad", b"\xbe\xef",
                                            [QUIC_V1, QUIC_V2]))
        self.assertTrue(h.is_version_negotiation)
        self.assertIsNone(h.long_packet_type)
        self.assertEqual(h.type_name, "version_negotiation")
        self.assertEqual(h.version, VERSION_NEGOTIATION)
        self.assertEqual(h.supported_versions, (QUIC_V1, QUIC_V2))
        self.assertEqual(h.dcid, b"\xde\xad")

    def test_no_fixed_bit_allowed(self):
        # Version Negotiation 은 Fixed 비트 검사 안 함.
        blob = bytes([0x80]) + struct.pack(">I", 0) + b"\x00" + b"\x00"
        h = parse_quic(blob)
        self.assertTrue(h.is_version_negotiation)
        self.assertEqual(h.supported_versions, ())

    def test_truncated_version_list(self):
        # 지원 버전 목록이 4의 배수가 아니면 None.
        base = _version_negotiation(b"\x01", b"\x02", [QUIC_V1])
        self.assertIsNone(parse_quic(base[:-1]))


class GuardTests(unittest.TestCase):
    def test_short_header_rejected(self):
        # Form 비트 0 → 롱 헤더 아님.
        self.assertIsNone(parse_quic(_long(QUIC_V1, b"\x01", b"\x02", form=False)))

    def test_missing_fixed_bit_rejected(self):
        self.assertIsNone(parse_quic(_long(QUIC_V1, b"\x01", b"\x02", fixed=False)))

    def test_cid_too_long_rejected(self):
        # DCID 길이 21 > 20.
        blob = bytes([0xC0]) + struct.pack(">I", QUIC_V1) + bytes([21]) + b"\x00" * 21
        self.assertIsNone(parse_quic(blob))

    def test_truncated_dcid(self):
        blob = bytes([0xC0]) + struct.pack(">I", QUIC_V1) + bytes([10]) + b"\x00" * 3
        self.assertIsNone(parse_quic(blob))

    def test_missing_scid_length(self):
        blob = bytes([0xC0]) + struct.pack(">I", QUIC_V1) + bytes([2]) + b"\x00\x00"
        self.assertIsNone(parse_quic(blob))

    def test_too_short(self):
        self.assertIsNone(parse_quic(b"\xc0\x00\x00"))

    def test_not_bytes(self):
        self.assertIsNone(parse_quic(None))
        self.assertIsNone(parse_quic(12345))

    def test_offset(self):
        blob = b"\xff\xff" + _long(QUIC_V1, b"\x07", b"\x08", type_bits=0)
        h = parse_quic(blob, offset=2)
        self.assertEqual(h.dcid, b"\x07")
        self.assertEqual(h.scid, b"\x08")
        self.assertEqual(h.payload_offset, 2 + 9)

    def test_looks_like(self):
        self.assertTrue(looks_like_quic(_long(QUIC_V1, b"\x01", b"\x02")))
        self.assertFalse(looks_like_quic(b"GET / HTTP/1.1\r\n"))


class ShortHeaderTests(unittest.TestCase):
    def test_is_short_header(self):
        # Form 0 + Fixed 1.
        self.assertTrue(is_short_header(b"\x40\xaa\xbb"))

    def test_long_header_not_short(self):
        self.assertFalse(is_short_header(_long(QUIC_V1, b"\x01", b"\x02")))

    def test_empty(self):
        self.assertFalse(is_short_header(b""))
        self.assertFalse(is_short_header(None))


class ConstantTests(unittest.TestCase):
    def test_port(self):
        self.assertEqual(QUIC_PORT, 443)

    def test_versions(self):
        self.assertEqual(QUIC_V1, 0x00000001)
        self.assertEqual(QUIC_V2, 0x6B3343CF)
        self.assertEqual(MAX_CID_LEN, 20)


if __name__ == "__main__":
    unittest.main()
