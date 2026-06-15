"""forensiclab.gtp 단위 테스트 (stdlib unittest)."""

import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from forensiclab.gtp import (  # noqa: E402
    CREATE_PDP_CONTEXT_REQUEST,
    CREATE_SESSION_REQUEST,
    DELETE_PDP_CONTEXT_REQUEST,
    ECHO_REQUEST,
    ERROR_INDICATION,
    G_PDU,
    GTP_C_PORT,
    GTP_U_PORT,
    GTP_VERSION_1,
    GTP_VERSION_2,
    GTPMessage,
    looks_like_gtp,
    parse_gtp,
)


def _v1(message_type, teid=0x11223344, length=0, flags_low=0,
        seq=None, npdu=None, next_ext=None):
    """GTPv1 헤더 조립. flags_low 는 E/S/PN 하위 3비트(상위는 version=1·PT=1)."""
    flags = (1 << 5) | (1 << 4) | (flags_low & 0x07)
    hdr = struct.pack(">BBHI", flags, message_type, length, teid)
    if flags_low:
        hdr += struct.pack(">H", seq if seq is not None else 0)
        hdr += bytes([npdu if npdu is not None else 0])
        hdr += bytes([next_ext if next_ext is not None else 0])
    return hdr


def _v2(message_type, teid=0xAABBCCDD, length=0, seq=0x010203, t=True):
    """GTPv2-C 헤더 조립."""
    flags = (2 << 5) | ((1 << 3) if t else 0)
    hdr = struct.pack(">BBH", flags, message_type, length)
    if t:
        hdr += struct.pack(">I", teid)
    hdr += bytes([(seq >> 16) & 0xFF, (seq >> 8) & 0xFF, seq & 0xFF, 0])
    return hdr


class GTPConstantsTests(unittest.TestCase):
    def test_ports(self):
        self.assertEqual(GTP_C_PORT, 2123)
        self.assertEqual(GTP_U_PORT, 2152)


class GTPGuardTests(unittest.TestCase):
    def test_rejects_short(self):
        self.assertIsNone(parse_gtp(b"\x00" * 7))

    def test_rejects_non_bytes(self):
        self.assertIsNone(parse_gtp(42))

    def test_rejects_bad_version(self):
        # Version=0 (GTP') → None.
        flags = (0 << 5) | (1 << 4)
        self.assertIsNone(parse_gtp(struct.pack(">BBHI", flags, 1, 0, 0)))

    def test_rejects_v1_pt_zero(self):
        # GTPv1 인데 PT=0(GTP') → None.
        flags = (1 << 5) | (0 << 4)
        self.assertIsNone(parse_gtp(struct.pack(">BBHI", flags, 1, 0, 0)))

    def test_rejects_v1_reserved_set(self):
        flags = (1 << 5) | (1 << 4) | (1 << 3)
        self.assertIsNone(parse_gtp(struct.pack(">BBHI", flags, 1, 0, 0)))

    def test_rejects_unknown_message_type(self):
        self.assertIsNone(parse_gtp(_v1(200)))  # v1 미정의 타입.
        self.assertIsNone(parse_gtp(_v2(99)))   # v2 미정의 타입.

    def test_looks_like(self):
        self.assertTrue(looks_like_gtp(_v1(ECHO_REQUEST)))
        self.assertFalse(looks_like_gtp(b"GET / HTTP/1.1\r\n\r\n"))


class GTPv1Tests(unittest.TestCase):
    def test_minimal_echo(self):
        msg = parse_gtp(_v1(ECHO_REQUEST))
        self.assertIsInstance(msg, GTPMessage)
        self.assertEqual(msg.version, GTP_VERSION_1)
        self.assertEqual(msg.message_name, "Echo-Request")
        self.assertTrue(msg.is_echo)
        self.assertEqual(msg.protocol_type, 1)
        self.assertEqual(msg.payload_offset, 8)  # 선택 필드 없음.

    def test_teid_extracted(self):
        msg = parse_gtp(_v1(G_PDU, teid=0xDEADBEEF))
        self.assertEqual(msg.teid, 0xDEADBEEF)
        self.assertTrue(msg.is_user_data)

    def test_gpdu_payload_offset_points_to_inner(self):
        # G-PDU(255) + length=4 캡슐 IP 4바이트 → payload_offset=8.
        inner = b"\x45\x00\x00\x14"  # 가짜 IPv4 시작.
        pkt = _v1(G_PDU, length=len(inner)) + inner
        msg = parse_gtp(pkt)
        self.assertEqual(msg.payload_offset, 8)
        self.assertEqual(pkt[msg.payload_offset:], inner)

    def test_optional_sequence_field(self):
        msg = parse_gtp(_v1(ECHO_REQUEST, flags_low=0x02, seq=0x1234))
        self.assertEqual(msg.sequence_number, 0x1234)
        self.assertEqual(msg.payload_offset, 12)

    def test_optional_npdu_and_ext(self):
        msg = parse_gtp(_v1(G_PDU, flags_low=0x05, npdu=0x07, next_ext=0xC0))
        self.assertEqual(msg.npdu_number, 0x07)
        self.assertEqual(msg.next_extension_header_type, 0xC0)

    def test_create_and_delete_context(self):
        c = parse_gtp(_v1(CREATE_PDP_CONTEXT_REQUEST))
        self.assertTrue(c.is_session_create)
        d = parse_gtp(_v1(DELETE_PDP_CONTEXT_REQUEST))
        self.assertTrue(d.is_session_delete)

    def test_error_indication(self):
        msg = parse_gtp(_v1(ERROR_INDICATION))
        self.assertTrue(msg.is_error_indication)


class GTPv2Tests(unittest.TestCase):
    def test_create_session_with_teid(self):
        msg = parse_gtp(_v2(CREATE_SESSION_REQUEST, teid=0xAABBCCDD, seq=0x000123))
        self.assertEqual(msg.version, GTP_VERSION_2)
        self.assertEqual(msg.message_name, "Create-Session-Request")
        self.assertTrue(msg.is_session_create)
        self.assertTrue(msg.has_teid)
        self.assertEqual(msg.teid, 0xAABBCCDD)
        self.assertEqual(msg.sequence_number, 0x000123)
        self.assertEqual(msg.payload_offset, 12)

    def test_without_teid(self):
        msg = parse_gtp(_v2(ECHO_REQUEST, t=False, seq=0x000042))
        self.assertFalse(msg.has_teid)
        self.assertIsNone(msg.teid)
        self.assertEqual(msg.sequence_number, 0x000042)
        self.assertEqual(msg.payload_offset, 8)

    def test_delete_session(self):
        msg = parse_gtp(_v2(36))
        self.assertTrue(msg.is_session_delete)


class GTPOffsetTests(unittest.TestCase):
    def test_offset_parsing(self):
        prefix = b"\xaa\xbb"
        msg = parse_gtp(prefix + _v1(ECHO_REQUEST), offset=2)
        self.assertIsNotNone(msg)
        self.assertEqual(msg.message_type, ECHO_REQUEST)

    def test_inner_packet_recoverable_at_offset(self):
        # GTP-U G-PDU 안의 단말 IP 패킷을 payload_offset 으로 그대로 복원.
        inner = b"\x45\x00\x00\x14\x00\x00\x40\x00"
        pkt = _v1(G_PDU, length=len(inner)) + inner
        msg = parse_gtp(pkt)
        self.assertEqual(pkt[msg.payload_offset:], inner)


if __name__ == "__main__":
    unittest.main()
