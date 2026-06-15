"""forensiclab.rdp 단위 테스트 (stdlib unittest)."""

import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from forensiclab.rdp import (  # noqa: E402
    PROTOCOL_NAMES,
    RDP_PORTS,
    RdpConnectionRequest,
    parse_rdp_connection_request,
)


def _neg_req(protocols: int, flags: int = 0) -> bytes:
    """rdpNegReq 8바이트: type(0x01) flags length(LE 0x0008) protocols(LE)."""
    return struct.pack("<BBHI", 0x01, flags, 0x0008, protocols)


def _cr(user_data: bytes) -> bytes:
    """TPKT + X.224 CR 고정부 + 가변부(user_data) 로 연결 요청 바이트 조립."""
    x224 = bytes([6 + len(user_data)])      # LI = 이후 헤더 길이
    x224 += b"\xe0"                          # CR|CDT
    x224 += b"\x00\x00"                      # DST-REF
    x224 += b"\x00\x00"                      # SRC-REF
    x224 += b"\x00"                          # CLASS
    x224 += user_data
    tpkt = b"\x03\x00" + struct.pack(">H", 4 + len(x224))
    return tpkt + x224


def _cookie(name: str, value: str) -> bytes:
    return b"Cookie: " + name.encode() + b"=" + value.encode() + b"\r\n"


class CookieTests(unittest.TestCase):
    def test_mstshash_username(self):
        data = _cr(_cookie("mstshash", "ADMIN") + _neg_req(0x00000003))
        m = parse_rdp_connection_request(data)
        self.assertIsInstance(m, RdpConnectionRequest)
        self.assertEqual(m.cookie_type, "mstshash")
        self.assertEqual(m.cookie_value, "ADMIN")
        self.assertTrue(m.has_username)
        self.assertEqual(m.username, "ADMIN")
        self.assertFalse(m.has_routing_token)
        self.assertIsNone(m.routing_token)

    def test_mstshash_with_domain(self):
        m = parse_rdp_connection_request(_cr(_cookie("mstshash", "CORP\\jdoe")))
        self.assertEqual(m.username, "CORP\\jdoe")
        self.assertFalse(m.neg_present)

    def test_routing_token(self):
        m = parse_rdp_connection_request(
            _cr(_cookie("msts", "3640205228.15629.0000"))
        )
        self.assertEqual(m.cookie_type, "msts")
        self.assertTrue(m.has_routing_token)
        self.assertEqual(m.routing_token, "3640205228.15629.0000")
        self.assertFalse(m.has_username)
        self.assertIsNone(m.username)

    def test_no_cookie(self):
        m = parse_rdp_connection_request(_cr(_neg_req(0x00000002)))
        self.assertIsNone(m.cookie_type)
        self.assertIsNone(m.cookie_value)
        self.assertFalse(m.has_username)
        self.assertTrue(m.neg_present)


class ProtocolTests(unittest.TestCase):
    def test_standard_rdp_security_is_weak(self):
        m = parse_rdp_connection_request(_cr(_neg_req(0x00000000)))
        self.assertEqual(m.requested_protocols, 0)
        self.assertTrue(m.is_standard_rdp_security)
        self.assertFalse(m.requests_nla)
        self.assertFalse(m.requests_tls)
        self.assertEqual(m.protocols, ("PROTOCOL_RDP",))

    def test_nla_hybrid(self):
        m = parse_rdp_connection_request(_cr(_neg_req(0x00000002)))
        self.assertTrue(m.requests_nla)
        self.assertFalse(m.is_standard_rdp_security)
        self.assertIn("PROTOCOL_HYBRID", m.protocols)

    def test_tls_plus_nla(self):
        m = parse_rdp_connection_request(_cr(_neg_req(0x00000003)))
        self.assertTrue(m.requests_tls)
        self.assertTrue(m.requests_nla)
        self.assertEqual(set(m.protocols), {"PROTOCOL_SSL", "PROTOCOL_HYBRID"})

    def test_hybrid_ex(self):
        m = parse_rdp_connection_request(_cr(_neg_req(0x00000008)))
        self.assertTrue(m.requests_nla)
        self.assertIn("PROTOCOL_HYBRID_EX", m.protocols)

    def test_no_negreq_means_no_protocols(self):
        m = parse_rdp_connection_request(_cr(_cookie("mstshash", "x")))
        self.assertIsNone(m.requested_protocols)
        self.assertEqual(m.protocols, ())
        self.assertFalse(m.requests_nla)
        self.assertFalse(m.is_standard_rdp_security)


class FlagTests(unittest.TestCase):
    def test_restricted_admin(self):
        m = parse_rdp_connection_request(_cr(_neg_req(0x00000002, flags=0x01)))
        self.assertEqual(m.neg_flags, 0x01)
        self.assertTrue(m.restricted_admin)

    def test_no_restricted_admin(self):
        m = parse_rdp_connection_request(_cr(_neg_req(0x00000002, flags=0x00)))
        self.assertFalse(m.restricted_admin)


class FramingTests(unittest.TestCase):
    def test_tpkt_length(self):
        data = _cr(_cookie("mstshash", "ADMIN") + _neg_req(0x3))
        m = parse_rdp_connection_request(data)
        self.assertEqual(m.tpkt_length, len(data))

    def test_offset(self):
        data = b"\xff\xff" + _cr(_neg_req(0x2))
        m = parse_rdp_connection_request(data, offset=2)
        self.assertTrue(m.requests_nla)

    def test_raw_preserved(self):
        data = _cr(_neg_req(0x2))
        m = parse_rdp_connection_request(data)
        self.assertEqual(m.raw, data)

    def test_cookie_without_crlf(self):
        # CRLF 없는 망가진 쿠키도 끝까지 한 줄로 관대 처리.
        ud = b"Cookie: mstshash=trailing"
        m = parse_rdp_connection_request(_cr(ud))
        self.assertEqual(m.username, "trailing")


class RobustnessTests(unittest.TestCase):
    def test_empty_returns_none(self):
        self.assertIsNone(parse_rdp_connection_request(b""))

    def test_negative_offset_returns_none(self):
        self.assertIsNone(parse_rdp_connection_request(_cr(_neg_req(0x2)), offset=-1))

    def test_offset_beyond_returns_none(self):
        self.assertIsNone(parse_rdp_connection_request(b"\x03\x00\x00\x0b", offset=99))

    def test_not_tpkt_returns_none(self):
        self.assertIsNone(parse_rdp_connection_request(b"GET / HTTP/1.1\r\n"))

    def test_not_connection_request_returns_none(self):
        # X.224 PDU 타입이 CR(0xE0)이 아니면(예: DT 0xF0) None.
        bad = b"\x03\x00\x00\x0b\x06\xf0\x00\x00\x00\x00\x00"
        self.assertIsNone(parse_rdp_connection_request(bad))

    def test_truncated_negreq_ignored(self):
        # 8바이트 미만 negReq 는 무시(부분 파싱) — 쿠키만 남는다.
        m = parse_rdp_connection_request(_cr(_cookie("mstshash", "x") + b"\x01\x00"))
        self.assertEqual(m.username, "x")
        self.assertFalse(m.neg_present)

    def test_ports_constant(self):
        self.assertIn(3389, RDP_PORTS)

    def test_protocol_names_table(self):
        names = {n for _, n in PROTOCOL_NAMES}
        self.assertIn("PROTOCOL_HYBRID", names)
        self.assertIn("PROTOCOL_SSL", names)


if __name__ == "__main__":
    unittest.main()
