"""forensiclab.openvpn 단위 테스트 (stdlib unittest)."""

import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from forensiclab.openvpn import (  # noqa: E402
    OPENVPN_PORT,
    P_ACK_V1,
    P_CONTROL_HARD_RESET_CLIENT_V1,
    P_CONTROL_HARD_RESET_CLIENT_V2,
    P_CONTROL_HARD_RESET_SERVER_V2,
    P_CONTROL_SOFT_RESET_V1,
    P_CONTROL_V1,
    P_DATA_V1,
    P_DATA_V2,
    OpenVPNHeader,
    looks_like_openvpn,
    parse_openvpn,
)


def _first(opcode, key_id=0):
    """opcode<<3 | key_id 첫 바이트."""
    return bytes([(opcode << 3) | (key_id & 0x07)])


def _control(opcode, session_id=b"\x01\x02\x03\x04\x05\x06\x07\x08", key_id=0, rest=b""):
    """제어 패킷(첫 바이트 + 8B 세션 ID + 나머지) 조립."""
    return _first(opcode, key_id) + session_id + rest


class OpenVPNHeaderTests(unittest.TestCase):
    def test_port_constant(self):
        self.assertEqual(OPENVPN_PORT, 1194)

    def test_hard_reset_client_v2(self):
        sid = b"\xaa" * 8
        hdr = parse_openvpn(_control(P_CONTROL_HARD_RESET_CLIENT_V2, sid))
        self.assertIsInstance(hdr, OpenVPNHeader)
        self.assertEqual(hdr.opcode, P_CONTROL_HARD_RESET_CLIENT_V2)
        self.assertEqual(hdr.session_id, sid)
        self.assertEqual(hdr.session_id_hex, "aa" * 8)
        self.assertTrue(hdr.is_control)
        self.assertTrue(hdr.is_hard_reset)
        self.assertTrue(hdr.is_client_reset)
        self.assertFalse(hdr.is_server_reset)
        self.assertFalse(hdr.is_data)
        self.assertEqual(hdr.payload_offset, 9)

    def test_hard_reset_server_v2_direction(self):
        hdr = parse_openvpn(_control(P_CONTROL_HARD_RESET_SERVER_V2))
        self.assertTrue(hdr.is_hard_reset)
        self.assertTrue(hdr.is_server_reset)
        self.assertFalse(hdr.is_client_reset)

    def test_hard_reset_client_v1_legacy(self):
        hdr = parse_openvpn(_control(P_CONTROL_HARD_RESET_CLIENT_V1))
        self.assertTrue(hdr.is_hard_reset)
        self.assertTrue(hdr.is_client_reset)
        self.assertEqual(hdr.opcode_name, "P_CONTROL_HARD_RESET_CLIENT_V1")

    def test_soft_reset_is_rekey(self):
        hdr = parse_openvpn(_control(P_CONTROL_SOFT_RESET_V1))
        self.assertTrue(hdr.is_soft_reset)
        self.assertFalse(hdr.is_hard_reset)
        self.assertTrue(hdr.is_control)

    def test_control_v1(self):
        hdr = parse_openvpn(_control(P_CONTROL_V1))
        self.assertTrue(hdr.is_control)
        self.assertFalse(hdr.is_hard_reset)
        self.assertFalse(hdr.is_ack)
        self.assertEqual(hdr.opcode_name, "P_CONTROL_V1")

    def test_ack(self):
        hdr = parse_openvpn(_control(P_ACK_V1))
        self.assertTrue(hdr.is_ack)
        self.assertTrue(hdr.is_control)
        self.assertFalse(hdr.is_data)

    def test_key_id_extraction(self):
        hdr = parse_openvpn(_control(P_CONTROL_V1, key_id=5))
        self.assertEqual(hdr.key_id, 5)
        self.assertEqual(hdr.opcode, P_CONTROL_V1)

    def test_key_id_max(self):
        hdr = parse_openvpn(_control(P_CONTROL_V1, key_id=7))
        self.assertEqual(hdr.key_id, 7)

    def test_data_v1_payload_only(self):
        pkt = _first(P_DATA_V1) + b"\xde\xad\xbe\xef" * 4
        hdr = parse_openvpn(pkt)
        self.assertTrue(hdr.is_data)
        self.assertFalse(hdr.is_control)
        self.assertIsNone(hdr.session_id)
        self.assertIsNone(hdr.session_id_hex)
        self.assertIsNone(hdr.peer_id)
        self.assertEqual(hdr.payload_offset, 1)

    def test_data_v2_peer_id(self):
        pkt = _first(P_DATA_V2) + bytes([0x00, 0x12, 0x34]) + b"\xff" * 8
        hdr = parse_openvpn(pkt)
        self.assertTrue(hdr.is_data)
        self.assertEqual(hdr.peer_id, 0x001234)
        self.assertIsNone(hdr.session_id)
        self.assertEqual(hdr.payload_offset, 4)

    def test_data_v2_peer_id_max(self):
        pkt = _first(P_DATA_V2) + bytes([0xFF, 0xFF, 0xFF]) + b"\x00" * 4
        hdr = parse_openvpn(pkt)
        self.assertEqual(hdr.peer_id, 0xFFFFFF)

    def test_data_v2_truncated_peer_id(self):
        pkt = _first(P_DATA_V2) + b"\x00\x12"  # peer-id 2바이트뿐
        self.assertIsNone(parse_openvpn(pkt))

    def test_control_truncated_session_id(self):
        pkt = _first(P_CONTROL_V1) + b"\x01\x02\x03"  # 세션 ID 3바이트뿐
        self.assertIsNone(parse_openvpn(pkt))

    def test_empty(self):
        self.assertIsNone(parse_openvpn(b""))

    def test_invalid_opcode_zero(self):
        # opcode 0 은 미정의.
        self.assertIsNone(parse_openvpn(_first(0) + b"\x00" * 8))

    def test_invalid_opcode_high(self):
        # opcode 12 이상 미정의.
        self.assertIsNone(parse_openvpn(_first(12) + b"\x00" * 8))

    def test_opcode_31_rejected(self):
        # 0xFF -> opcode 31, key_id 7: 미정의 opcode.
        self.assertIsNone(parse_openvpn(b"\xff" + b"\x00" * 8))

    def test_not_bytes(self):
        self.assertIsNone(parse_openvpn(None))
        self.assertIsNone(parse_openvpn(12345))

    def test_offset(self):
        prefix = b"\x99\x88"
        sid = b"\x77" * 8
        pkt = prefix + _control(P_CONTROL_HARD_RESET_CLIENT_V2, sid)
        hdr = parse_openvpn(pkt, offset=2)
        self.assertEqual(hdr.session_id, sid)
        self.assertEqual(hdr.payload_offset, 2 + 9)

    def test_tcp_length_prefix_offset(self):
        # TCP 전송: 2바이트 big-endian 길이 접두사 뒤 패킷.
        body = _control(P_CONTROL_HARD_RESET_CLIENT_V2)
        framed = struct.pack(">H", len(body)) + body
        hdr = parse_openvpn(framed, offset=2)
        self.assertIsNotNone(hdr)
        self.assertTrue(hdr.is_client_reset)

    def test_bytearray_accepted(self):
        hdr = parse_openvpn(bytearray(_control(P_ACK_V1)))
        self.assertTrue(hdr.is_ack)

    def test_unknown_opcode_name(self):
        hdr = OpenVPNHeader(opcode=99, key_id=0)
        self.assertEqual(hdr.opcode_name, "opcode_99")

    def test_looks_like_openvpn(self):
        self.assertTrue(looks_like_openvpn(_control(P_CONTROL_HARD_RESET_CLIENT_V2)))
        self.assertTrue(looks_like_openvpn(_first(P_DATA_V1) + b"\x00" * 16))
        self.assertFalse(looks_like_openvpn(b""))
        self.assertFalse(looks_like_openvpn(_first(0) + b"\x00" * 8))


if __name__ == "__main__":
    unittest.main()
