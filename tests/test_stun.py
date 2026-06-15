"""forensiclab.stun 단위 테스트 (stdlib unittest)."""

import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from forensiclab.stun import (  # noqa: E402
    ATTR_MAPPED_ADDRESS,
    ATTR_SOFTWARE,
    ATTR_USERNAME,
    ATTR_XOR_MAPPED_ADDRESS,
    ATTR_XOR_RELAYED_ADDRESS,
    CLASS_REQUEST,
    CLASS_SUCCESS,
    METHOD_ALLOCATE,
    METHOD_BINDING,
    STUN_HEADER_SIZE,
    STUN_MAGIC_COOKIE,
    Stun,
    StunAttribute,
    parse_stun,
)

_TXID = bytes(range(12))  # 0x000102...0b


def _attr(atype: int, value: bytes) -> bytes:
    pad = (4 - (len(value) % 4)) % 4
    return struct.pack(">HH", atype, len(value)) + value + b"\x00" * pad


def _msg(mtype: int, attrs: bytes = b"", txid: bytes = _TXID) -> bytes:
    return struct.pack(">HHI", mtype, len(attrs), STUN_MAGIC_COOKIE) + txid + attrs


def _xor_mapped_ipv4(ip: str, port: int) -> bytes:
    xport = port ^ (STUN_MAGIC_COOKIE >> 16)
    cookie = struct.pack(">I", STUN_MAGIC_COOKIE)
    octets = bytes(o ^ c for o, c in zip((int(p) for p in ip.split(".")), cookie))
    return b"\x00\x01" + struct.pack(">H", xport) + octets


class ParseHeaderTests(unittest.TestCase):
    def test_binding_request(self):
        msg = _msg(0x0001)  # Binding request.
        s = parse_stun(msg)
        self.assertIsNotNone(s)
        self.assertEqual(s.method, METHOD_BINDING)
        self.assertEqual(s.msg_class, CLASS_REQUEST)
        self.assertEqual(s.method_name, "Binding")
        self.assertEqual(s.class_name, "request")
        self.assertEqual(s.transaction_id, _TXID)
        self.assertTrue(s.is_request)
        self.assertTrue(s.is_amplification_request)

    def test_binding_success_response_class(self):
        # 0x0101 = Binding success response.
        s = parse_stun(_msg(0x0101))
        self.assertEqual(s.method, METHOD_BINDING)
        self.assertEqual(s.msg_class, CLASS_SUCCESS)
        self.assertTrue(s.is_response)
        self.assertFalse(s.is_request)
        self.assertFalse(s.is_amplification_request)

    def test_allocate_is_turn(self):
        # 0x0003 = Allocate request (TURN).
        s = parse_stun(_msg(0x0003))
        self.assertEqual(s.method, METHOD_ALLOCATE)
        self.assertTrue(s.is_turn)
        self.assertFalse(s.is_amplification_request)

    def test_method_class_bit_interleave(self):
        # 0x0112 응답 클래스의 method 비트가 올바로 풀리는지(C 비트 사이 비트).
        s = parse_stun(_msg(0x0112))
        # class bits at 0x100|0x010 -> 0b11 = error response.
        self.assertEqual(s.msg_class, 0b11)


class RejectTests(unittest.TestCase):
    def test_too_short(self):
        self.assertIsNone(parse_stun(b"\x00" * 19))

    def test_bad_magic_cookie(self):
        msg = bytearray(_msg(0x0001))
        msg[4:8] = b"\xde\xad\xbe\xef"
        self.assertIsNone(parse_stun(bytes(msg)))

    def test_high_bits_set(self):
        # 상위 2비트가 0이 아니면 STUN 아님.
        msg = _msg(0xC001)
        self.assertIsNone(parse_stun(msg))

    def test_negative_offset(self):
        self.assertIsNone(parse_stun(_msg(0x0001), offset=-1))


class AttributeTests(unittest.TestCase):
    def test_xor_mapped_address_ipv4(self):
        attr = _attr(ATTR_XOR_MAPPED_ADDRESS, _xor_mapped_ipv4("203.0.113.7", 51234))
        s = parse_stun(_msg(0x0101, attr))
        self.assertEqual(s.mapped_address, ("203.0.113.7", 51234))

    def test_plain_mapped_address_ipv4(self):
        val = b"\x00\x01" + struct.pack(">H", 8080) + bytes([192, 168, 1, 50])
        attr = _attr(ATTR_MAPPED_ADDRESS, val)
        s = parse_stun(_msg(0x0101, attr))
        self.assertEqual(s.mapped_address, ("192.168.1.50", 8080))

    def test_xor_preferred_over_plain(self):
        plain = _attr(ATTR_MAPPED_ADDRESS,
                      b"\x00\x01" + struct.pack(">H", 1) + bytes([10, 0, 0, 1]))
        xor = _attr(ATTR_XOR_MAPPED_ADDRESS, _xor_mapped_ipv4("8.8.8.8", 443))
        s = parse_stun(_msg(0x0101, plain + xor))
        self.assertEqual(s.mapped_address, ("8.8.8.8", 443))

    def test_software_and_username(self):
        attrs = (_attr(ATTR_SOFTWARE, b"coturn 4.5") +
                 _attr(ATTR_USERNAME, b"alice:1700000000"))
        s = parse_stun(_msg(0x0001, attrs))
        self.assertEqual(s.software, "coturn 4.5")
        self.assertEqual(s.username, "alice:1700000000")

    def test_attribute_names_and_find(self):
        attr = _attr(ATTR_SOFTWARE, b"x")
        s = parse_stun(_msg(0x0001, attr))
        found = s.find(ATTR_SOFTWARE)
        self.assertIsNotNone(found)
        self.assertEqual(found.type_name, "SOFTWARE")
        self.assertIsNone(s.find(ATTR_MAPPED_ADDRESS))

    def test_unknown_attribute_name_hex(self):
        a = StunAttribute(type=0x9999, value=b"")
        self.assertEqual(a.type_name, "0x9999")

    def test_relayed_address(self):
        attr = _attr(ATTR_XOR_RELAYED_ADDRESS, _xor_mapped_ipv4("198.51.100.9", 49152))
        s = parse_stun(_msg(0x0103, attr))  # Allocate success response.
        self.assertEqual(s.relayed_address, ("198.51.100.9", 49152))

    def test_no_address_returns_none(self):
        s = parse_stun(_msg(0x0001))
        self.assertIsNone(s.mapped_address)
        self.assertIsNone(s.relayed_address)
        self.assertIsNone(s.software)


class RobustnessTests(unittest.TestCase):
    def test_offset_in_buffer(self):
        msg = b"\xaa\xbb\xcc" + _msg(0x0001)
        s = parse_stun(msg, offset=3)
        self.assertEqual(s.method, METHOD_BINDING)

    def test_truncated_attribute_value(self):
        # 길이 8을 알리지만 4바이트만 존재 — 가용분까지 담고 None 아님.
        body = struct.pack(">HH", ATTR_SOFTWARE, 8) + b"abcd"
        msg = struct.pack(">HHI", 0x0001, len(body), STUN_MAGIC_COOKIE) + _TXID + body
        s = parse_stun(msg)
        self.assertIsNotNone(s)
        self.assertEqual(s.attributes[0].value, b"abcd")

    def test_xor_mapped_ipv6_roundtrip(self):
        # IPv6 XOR: 매직쿠키+txid 키로 역XOR.
        key = struct.pack(">I", STUN_MAGIC_COOKIE) + _TXID
        addr = bytes(range(16))
        xored = bytes(a ^ b for a, b in zip(addr, key))
        val = b"\x00\x02" + struct.pack(">H", 1234 ^ (STUN_MAGIC_COOKIE >> 16)) + xored
        attr = _attr(ATTR_XOR_MAPPED_ADDRESS, val)
        s = parse_stun(_msg(0x0101, attr))
        ip, port = s.mapped_address
        self.assertEqual(port, 1234)
        # 원본 addr = 0x0001:0203:...:0e0f.
        self.assertEqual(ip, "1:203:405:607:809:a0b:c0d:e0f")

    def test_empty_attributes(self):
        s = parse_stun(_msg(0x0001))
        self.assertEqual(s.attributes, ())
        self.assertEqual(s.length, 0)
        self.assertEqual(STUN_HEADER_SIZE, 20)


if __name__ == "__main__":
    unittest.main()
