"""forensiclab.wireguard 단위 테스트 (stdlib unittest)."""

import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from forensiclab.wireguard import (  # noqa: E402
    MSG_COOKIE_REPLY,
    MSG_HANDSHAKE_INITIATION,
    MSG_HANDSHAKE_RESPONSE,
    MSG_TRANSPORT_DATA,
    WIREGUARD_PORT,
    WireGuardHeader,
    looks_like_wireguard,
    parse_wireguard,
)


def _initiation(sender, *, mac2=b"\x00" * 16, reserved=b"\x00\x00\x00"):
    """Handshake Initiation(148B) 조립."""
    body = (
        bytes([MSG_HANDSHAKE_INITIATION]) + reserved
        + struct.pack("<I", sender)
        + b"\xee" * 32  # ephemeral
        + b"\x11" * 48  # encrypted_static
        + b"\x22" * 28  # encrypted_timestamp
        + b"\x33" * 16  # mac1
        + mac2          # mac2
    )
    assert len(body) == 148, len(body)
    return body


def _response(sender, receiver, *, mac2=b"\x00" * 16):
    """Handshake Response(92B) 조립."""
    body = (
        bytes([MSG_HANDSHAKE_RESPONSE]) + b"\x00\x00\x00"
        + struct.pack("<II", sender, receiver)
        + b"\xee" * 32  # ephemeral
        + b"\x44" * 16  # encrypted_nothing
        + b"\x33" * 16  # mac1
        + mac2          # mac2
    )
    assert len(body) == 92, len(body)
    return body


def _cookie(receiver):
    """Cookie Reply(64B) 조립."""
    body = (
        bytes([MSG_COOKIE_REPLY]) + b"\x00\x00\x00"
        + struct.pack("<I", receiver)
        + b"\x55" * 24  # nonce
        + b"\x66" * 32  # encrypted_cookie
    )
    assert len(body) == 64, len(body)
    return body


def _transport(receiver, counter, payload=b"\x00" * 16):
    """Transport Data(가변) 조립."""
    return (
        bytes([MSG_TRANSPORT_DATA]) + b"\x00\x00\x00"
        + struct.pack("<IQ", receiver, counter)
        + payload
    )


class HandshakeInitiationTests(unittest.TestCase):
    def test_basic(self):
        h = parse_wireguard(_initiation(0xAABBCCDD))
        self.assertIsInstance(h, WireGuardHeader)
        self.assertTrue(h.is_handshake_initiation)
        self.assertTrue(h.is_handshake)
        self.assertEqual(h.message_type, MSG_HANDSHAKE_INITIATION)
        self.assertEqual(h.type_name, "handshake_initiation")
        self.assertEqual(h.sender_index, 0xAABBCCDD)
        self.assertIsNone(h.receiver_index)
        self.assertIsNone(h.counter)
        self.assertEqual(h.payload_offset, 148)

    def test_mac2_zero_default(self):
        h = parse_wireguard(_initiation(1))
        self.assertFalse(h.mac2_present)

    def test_mac2_present_under_load(self):
        h = parse_wireguard(_initiation(1, mac2=b"\x99" * 16))
        self.assertTrue(h.mac2_present)

    def test_truncated(self):
        self.assertIsNone(parse_wireguard(_initiation(1)[:147]))

    def test_nonzero_reserved_rejected(self):
        self.assertIsNone(parse_wireguard(_initiation(1, reserved=b"\x00\x01\x00")))


class HandshakeResponseTests(unittest.TestCase):
    def test_basic(self):
        h = parse_wireguard(_response(0x11112222, 0x33334444))
        self.assertTrue(h.is_handshake_response)
        self.assertTrue(h.is_handshake)
        self.assertEqual(h.sender_index, 0x11112222)
        self.assertEqual(h.receiver_index, 0x33334444)
        self.assertEqual(h.payload_offset, 92)

    def test_mac2_present(self):
        h = parse_wireguard(_response(1, 2, mac2=b"\xab" * 16))
        self.assertTrue(h.mac2_present)

    def test_truncated(self):
        self.assertIsNone(parse_wireguard(_response(1, 2)[:91]))


class CookieReplyTests(unittest.TestCase):
    def test_basic(self):
        h = parse_wireguard(_cookie(0xDEADBEEF))
        self.assertTrue(h.is_cookie_reply)
        self.assertFalse(h.is_handshake)
        self.assertEqual(h.receiver_index, 0xDEADBEEF)
        self.assertIsNone(h.sender_index)
        self.assertEqual(h.payload_offset, 64)

    def test_truncated(self):
        self.assertIsNone(parse_wireguard(_cookie(1)[:63]))


class TransportDataTests(unittest.TestCase):
    def test_basic(self):
        h = parse_wireguard(_transport(0x01020304, 42, payload=b"\xaa" * 80))
        self.assertTrue(h.is_transport_data)
        self.assertEqual(h.receiver_index, 0x01020304)
        self.assertEqual(h.counter, 42)
        self.assertIsNone(h.sender_index)
        self.assertEqual(h.payload_offset, 16)
        self.assertFalse(h.is_initial_transport)

    def test_initial_transport_counter_zero(self):
        h = parse_wireguard(_transport(1, 0))
        self.assertTrue(h.is_initial_transport)

    def test_large_counter(self):
        h = parse_wireguard(_transport(1, 2**48))
        self.assertEqual(h.counter, 2**48)

    def test_minimum_length(self):
        # 4(type)+4(receiver)+8(counter)+16(tag) = 32.
        self.assertIsNotNone(parse_wireguard(_transport(1, 0, payload=b"\x00" * 16)))

    def test_below_minimum_rejected(self):
        self.assertIsNone(parse_wireguard(_transport(1, 0, payload=b"\x00" * 15)))


class GuardTests(unittest.TestCase):
    def test_unknown_message_type(self):
        self.assertIsNone(parse_wireguard(b"\x05\x00\x00\x00" + b"\x00" * 200))

    def test_zero_type_rejected(self):
        self.assertIsNone(parse_wireguard(b"\x00\x00\x00\x00" + b"\x00" * 200))

    def test_too_short(self):
        self.assertIsNone(parse_wireguard(b"\x01\x00\x00"))

    def test_not_bytes(self):
        self.assertIsNone(parse_wireguard(None))
        self.assertIsNone(parse_wireguard(12345))

    def test_offset(self):
        blob = b"\xff\xff" + _transport(7, 3)
        h = parse_wireguard(blob, offset=2)
        self.assertEqual(h.receiver_index, 7)
        self.assertEqual(h.counter, 3)
        self.assertEqual(h.payload_offset, 2 + 16)

    def test_looks_like(self):
        self.assertTrue(looks_like_wireguard(_initiation(1)))
        self.assertTrue(looks_like_wireguard(_cookie(1)))
        self.assertFalse(looks_like_wireguard(b"GET / HTTP/1.1\r\n"))

    def test_port_constant(self):
        self.assertEqual(WIREGUARD_PORT, 51820)


if __name__ == "__main__":
    unittest.main()
