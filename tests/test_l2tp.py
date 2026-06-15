"""forensiclab.l2tp 단위 테스트 (stdlib unittest)."""

import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from forensiclab.l2tp import (  # noqa: E402
    L2TP_PORT,
    L2TP_VERSION,
    L2tpHeader,
    looks_like_l2tp,
    parse_l2tp,
)

_T = 0x8000
_L = 0x4000
_S = 0x0800
_O = 0x0200
_P = 0x0100


def _ctrl(tunnel_id, session_id, ns, nr, length=None, payload=b""):
    """제어 메시지(T=L=S=1) 헤더 조립."""
    flags = _T | _L | _S | L2TP_VERSION
    if length is None:
        length = 12 + len(payload)
    return (
        struct.pack(">HH", flags, length)
        + struct.pack(">HH", tunnel_id, session_id)
        + struct.pack(">HH", ns, nr)
        + payload
    )


def _data(tunnel_id, session_id, payload=b""):
    """데이터 메시지(T=0, 시퀀스/길이 없음) 헤더 조립."""
    flags = L2TP_VERSION  # T=0, 모든 옵션 비트 0
    return struct.pack(">HH", flags, tunnel_id) + struct.pack(">H", session_id) + payload


class ControlMessageTests(unittest.TestCase):
    def test_basic_control(self):
        h = parse_l2tp(_ctrl(0x1234, 0x5678, 1, 2))
        self.assertIsInstance(h, L2tpHeader)
        self.assertTrue(h.is_control)
        self.assertFalse(h.is_data)
        self.assertTrue(h.has_length)
        self.assertTrue(h.has_sequence)
        self.assertEqual(h.version, 2)
        self.assertEqual(h.tunnel_id, 0x1234)
        self.assertEqual(h.session_id, 0x5678)
        self.assertEqual(h.ns, 1)
        self.assertEqual(h.nr, 2)

    def test_payload_offset_control(self):
        # Flags+Len(4) + Tunnel+Session(4) + Ns+Nr(4) = 12.
        h = parse_l2tp(_ctrl(1, 0, 0, 0, payload=b"\x00\x00AVP"))
        self.assertEqual(h.payload_offset, 12)

    def test_length_field(self):
        h = parse_l2tp(_ctrl(1, 1, 5, 6, length=20))
        self.assertEqual(h.length, 20)

    def test_setup_tunnel_zero(self):
        # SCCRQ: 터널 ID 아직 미배정.
        h = parse_l2tp(_ctrl(0, 0, 0, 0))
        self.assertTrue(h.is_setup)

    def test_control_requires_length_bit(self):
        # 제어(T=1)인데 L 비트 없음 → 거부.
        flags = _T | _S | L2TP_VERSION
        data = struct.pack(">H", flags) + struct.pack(">HHHH", 1, 1, 0, 0)
        self.assertIsNone(parse_l2tp(data))

    def test_control_requires_sequence_bit(self):
        # 제어(T=1)인데 S 비트 없음 → 거부.
        flags = _T | _L | L2TP_VERSION
        data = struct.pack(">H", flags) + struct.pack(">HHH", 12, 1, 1)
        self.assertIsNone(parse_l2tp(data))


class DataMessageTests(unittest.TestCase):
    def test_basic_data(self):
        h = parse_l2tp(_data(0xAAAA, 0xBBBB, payload=b"\xff\x03PPP"))
        self.assertIsInstance(h, L2tpHeader)
        self.assertTrue(h.is_data)
        self.assertFalse(h.is_control)
        self.assertFalse(h.has_length)
        self.assertFalse(h.has_sequence)
        self.assertEqual(h.tunnel_id, 0xAAAA)
        self.assertEqual(h.session_id, 0xBBBB)
        self.assertIsNone(h.ns)
        self.assertIsNone(h.nr)
        self.assertIsNone(h.length)
        # Flags(2) + Tunnel(2) + Session(2) = 6.
        self.assertEqual(h.payload_offset, 6)

    def test_data_with_length_and_sequence(self):
        flags = _L | _S | L2TP_VERSION  # 데이터지만 L+S 켜짐(합법)
        data = (
            struct.pack(">HH", flags, 16)
            + struct.pack(">HH", 3, 4)
            + struct.pack(">HH", 7, 8)
        )
        h = parse_l2tp(data)
        self.assertTrue(h.is_data)
        self.assertEqual(h.length, 16)
        self.assertEqual(h.ns, 7)
        self.assertEqual(h.nr, 8)


class OffsetBitTests(unittest.TestCase):
    def test_offset_pad_skipped(self):
        flags = _O | L2TP_VERSION  # 데이터 + Offset
        data = (
            struct.pack(">H", flags)
            + struct.pack(">HH", 1, 2)   # tunnel, session
            + struct.pack(">H", 3)        # offset size = 3
            + b"PAD"                       # 3바이트 패드
            + b"PPP"
        )
        h = parse_l2tp(data)
        self.assertEqual(h.offset_size, 3)
        # Flags(2)+Tunnel(2)+Session(2)+OffSize(2)+Pad(3) = 11.
        self.assertEqual(h.payload_offset, 11)
        self.assertEqual(data[h.payload_offset:], b"PPP")

    def test_offset_pad_truncated(self):
        flags = _O | L2TP_VERSION
        data = struct.pack(">H", flags) + struct.pack(">HH", 1, 2) + struct.pack(">H", 10) + b"xx"
        self.assertIsNone(parse_l2tp(data))


class GuardTests(unittest.TestCase):
    def test_wrong_version(self):
        flags = _T | _L | _S | 3  # version 3
        data = struct.pack(">H", flags) + struct.pack(">HHHHH", 12, 1, 1, 0, 0)
        self.assertIsNone(parse_l2tp(data))

    def test_too_short_flags(self):
        self.assertIsNone(parse_l2tp(b"\x00"))

    def test_truncated_tunnel_session(self):
        h = struct.pack(">H", L2TP_VERSION) + b"\x00"  # 데이터, tunnel/session 부족
        self.assertIsNone(parse_l2tp(h))

    def test_not_bytes(self):
        self.assertIsNone(parse_l2tp(None))
        self.assertIsNone(parse_l2tp(1234))

    def test_offset_into_buffer(self):
        blob = b"\xaa\xbb" + _data(1, 2, payload=b"X")
        h = parse_l2tp(blob, offset=2)
        self.assertEqual(h.tunnel_id, 1)
        self.assertEqual(h.payload_offset, 2 + 6)


class HelperTests(unittest.TestCase):
    def test_looks_like(self):
        self.assertTrue(looks_like_l2tp(_ctrl(1, 1, 0, 0)))
        self.assertFalse(looks_like_l2tp(b"random non-l2tp"))

    def test_constants(self):
        self.assertEqual(L2TP_PORT, 1701)
        self.assertEqual(L2TP_VERSION, 2)


if __name__ == "__main__":
    unittest.main()
