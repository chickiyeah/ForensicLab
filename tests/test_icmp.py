"""forensiclab.icmp 단위 테스트 (stdlib unittest)."""

import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from forensiclab.icmp import (  # noqa: E402
    ICMP_DEST_UNREACHABLE,
    ICMP_ECHO_REPLY,
    ICMP_ECHO_REQUEST,
    Icmp,
    parse_icmp,
    verify_checksum,
)


def _checksum(segment):
    """주어진 바이트의 ICMP 체크섬(1의 보수 합의 보수)을 계산."""
    total = 0
    for i in range(0, len(segment) - 1, 2):
        total += (segment[i] << 8) | segment[i + 1]
    if len(segment) % 2 == 1:
        total += segment[-1] << 8
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _icmp(type_, code, rest, payload=b"", checksum=None):
    """체크섬 필드 0 으로 ICMP 메시지를 짜고, checksum 지정 시 채워 넣는다."""
    head_no_cksum = struct.pack(">BBH", type_, code, 0) + rest
    msg = head_no_cksum + payload
    if checksum is None:
        return msg
    return struct.pack(">BBH", type_, code, checksum) + rest + payload


class ParseIcmpTests(unittest.TestCase):
    def test_echo_request_round_trip(self):
        rest = struct.pack(">HH", 0x1234, 7)
        msg = _icmp(ICMP_ECHO_REQUEST, 0, rest, payload=b"abcdefgh")
        icmp = parse_icmp(msg)
        self.assertIsNotNone(icmp)
        self.assertEqual(icmp.type, ICMP_ECHO_REQUEST)
        self.assertEqual(icmp.code, 0)
        self.assertEqual(icmp.type_name, "echo-request")
        self.assertTrue(icmp.is_echo)
        self.assertFalse(icmp.is_error)
        self.assertEqual(icmp.echo, (0x1234, 7))
        self.assertEqual(icmp.payload, b"abcdefgh")

    def test_echo_reply_echo_fields(self):
        rest = struct.pack(">HH", 1, 2)
        icmp = parse_icmp(_icmp(ICMP_ECHO_REPLY, 0, rest))
        self.assertEqual(icmp.type_name, "echo-reply")
        self.assertEqual(icmp.echo, (1, 2))

    def test_error_message_carries_payload(self):
        # dest unreachable: rest of header 미사용 4바이트 + 원본 IP 헤더 일부.
        original = b"\x45\x00\x00\x28" + b"\x00" * 24
        icmp = parse_icmp(_icmp(ICMP_DEST_UNREACHABLE, 3, b"\x00" * 4, payload=original))
        self.assertEqual(icmp.code, 3)  # port unreachable.
        self.assertEqual(icmp.type_name, "dest-unreachable")
        self.assertTrue(icmp.is_error)
        self.assertFalse(icmp.is_echo)
        self.assertIsNone(icmp.echo)  # echo 계열 아님.
        self.assertEqual(icmp.payload, original)

    def test_unknown_type_name(self):
        icmp = parse_icmp(_icmp(99, 0, b"\x00" * 4))
        self.assertEqual(icmp.type_name, "type-99")

    def test_offset(self):
        rest = struct.pack(">HH", 5, 6)
        prefix = b"\xde\xad\xbe\xef"
        icmp = parse_icmp(prefix + _icmp(ICMP_ECHO_REQUEST, 0, rest), offset=len(prefix))
        self.assertEqual(icmp.echo, (5, 6))

    def test_too_short_returns_none(self):
        self.assertIsNone(parse_icmp(b"\x08\x00\x00"))   # 헤더 8바이트 미만.
        self.assertIsNone(parse_icmp(b""))
        self.assertIsNone(parse_icmp(b"\x08\x00\x00\x00\x00\x00\x00\x00", offset=4))

    def test_negative_offset_returns_none(self):
        self.assertIsNone(parse_icmp(b"\x00" * 8, offset=-1))

    def test_input_not_mutated(self):
        rest = struct.pack(">HH", 1, 1)
        msg = _icmp(ICMP_ECHO_REQUEST, 0, rest, payload=b"data")
        before = bytes(msg)
        parse_icmp(msg)
        self.assertEqual(msg, before)


class ChecksumTests(unittest.TestCase):
    def test_valid_checksum(self):
        rest = struct.pack(">HH", 0x1234, 1)
        body = struct.pack(">BBH", ICMP_ECHO_REQUEST, 0, 0) + rest + b"payload!"
        cksum = _checksum(body)
        msg = _icmp(ICMP_ECHO_REQUEST, 0, rest, payload=b"payload!", checksum=cksum)
        self.assertIs(verify_checksum(msg), True)

    def test_odd_length_payload_checksum(self):
        rest = struct.pack(">HH", 9, 9)
        body = struct.pack(">BBH", ICMP_ECHO_REQUEST, 0, 0) + rest + b"odd"
        cksum = _checksum(body)
        msg = _icmp(ICMP_ECHO_REQUEST, 0, rest, payload=b"odd", checksum=cksum)
        self.assertIs(verify_checksum(msg), True)

    def test_corrupted_checksum_fails(self):
        rest = struct.pack(">HH", 1, 1)
        msg = _icmp(ICMP_ECHO_REQUEST, 0, rest, payload=b"x", checksum=0x0000)
        self.assertIs(verify_checksum(msg), False)

    def test_checksum_too_short_returns_none(self):
        self.assertIsNone(verify_checksum(b"\x08\x00\x00"))


if __name__ == "__main__":
    unittest.main()
