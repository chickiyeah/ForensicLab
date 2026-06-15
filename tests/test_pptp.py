"""forensiclab.pptp 단위 테스트 (stdlib unittest)."""

import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from forensiclab.pptp import (  # noqa: E402
    ICCN,
    ICRQ,
    OCRP,
    OCRQ,
    PPTP_MAGIC_COOKIE,
    PPTP_MESSAGE_CONTROL,
    PPTP_PORT,
    SCCRP,
    SCCRQ,
    STOP_CCRQ,
    WAN_ERROR_NOTIFY,
    PPTPControlMessage,
    looks_like_pptp,
    parse_pptp,
)


def _common(control_type, length=None, message_type=PPTP_MESSAGE_CONTROL,
            magic=PPTP_MAGIC_COOKIE):
    """12바이트 공통 헤더 조립."""
    if length is None:
        length = 12
    return struct.pack(">HHIHH", length, message_type, magic, control_type, 0)


def _padded(text, width):
    raw = text.encode("latin-1")
    return raw + b"\x00" * (width - len(raw))


def _sccrq(hostname="WS-01", vendor="Microsoft", version=0x0100):
    body = struct.pack(">H", version)  # Protocol Version
    body += b"\x00\x00"  # Reserved1
    body += b"\x00\x00\x00\x01"  # Framing Capabilities
    body += b"\x00\x00\x00\x01"  # Bearer Capabilities
    body += b"\xff\xff"  # Maximum Channels
    body += b"\x00\x01"  # Firmware Revision
    body += _padded(hostname, 64)
    body += _padded(vendor, 64)
    length = 12 + len(body)
    return _common(SCCRQ, length) + body


class PPTPConstantsTests(unittest.TestCase):
    def test_port_and_cookie(self):
        self.assertEqual(PPTP_PORT, 1723)
        self.assertEqual(PPTP_MAGIC_COOKIE, 0x1A2B3C4D)


class PPTPCommonHeaderTests(unittest.TestCase):
    def test_rejects_short(self):
        self.assertIsNone(parse_pptp(b"\x00" * 11))

    def test_rejects_bad_magic(self):
        self.assertIsNone(parse_pptp(_common(SCCRQ, magic=0xDEADBEEF)))

    def test_rejects_bad_message_type(self):
        self.assertIsNone(parse_pptp(_common(SCCRQ, message_type=9)))

    def test_rejects_bad_control_type(self):
        self.assertIsNone(parse_pptp(_common(99)))
        self.assertIsNone(parse_pptp(_common(0)))

    def test_rejects_non_bytes(self):
        self.assertIsNone(parse_pptp(12345))

    def test_minimal_echo_request(self):
        msg = parse_pptp(_common(5))
        self.assertIsNotNone(msg)
        self.assertEqual(msg.control_message_type, 5)
        self.assertEqual(msg.control_message_name, "Echo-Request")
        self.assertEqual(msg.message_type, PPTP_MESSAGE_CONTROL)


class PPTPSccrqTests(unittest.TestCase):
    def test_hostname_and_vendor(self):
        msg = parse_pptp(_sccrq("WS-01", "Microsoft", 0x0100))
        self.assertIsInstance(msg, PPTPControlMessage)
        self.assertTrue(msg.is_start_request)
        self.assertEqual(msg.hostname, "WS-01")
        self.assertEqual(msg.vendor_string, "Microsoft")
        self.assertEqual(msg.protocol_version, 0x0100)

    def test_looks_like(self):
        self.assertTrue(looks_like_pptp(_sccrq()))
        self.assertFalse(looks_like_pptp(b"GET / HTTP/1.1\r\n"))

    def test_sccrp_result_error(self):
        body = struct.pack(">H", 0x0100)  # Protocol Version
        body += bytes([1, 0])  # Result Code=1(OK), Error Code=0
        body += b"\x00\x00\x00\x01"  # Framing
        body += b"\x00\x00\x00\x01"  # Bearer
        body += b"\xff\xff\x00\x01"  # Max Channels + Firmware
        body += _padded("SERVER", 64)
        body += _padded("linux", 64)
        msg = parse_pptp(_common(SCCRP, 12 + len(body)) + body)
        self.assertTrue(msg.is_start_reply)
        self.assertEqual(msg.result_code, 1)
        self.assertEqual(msg.error_code, 0)
        self.assertEqual(msg.hostname, "SERVER")
        self.assertEqual(msg.vendor_string, "linux")

    def test_truncated_hostname_field_is_none(self):
        # 공통 헤더 + 짧은 본문(호스트명 64B 미달) → 헤더는 살고 hostname=None.
        msg = parse_pptp(_common(SCCRQ, 20) + b"\x01\x00" + b"\x00" * 6)
        self.assertIsNotNone(msg)
        self.assertEqual(msg.protocol_version, 0x0100)
        self.assertIsNone(msg.hostname)


class PPTPCallTests(unittest.TestCase):
    def test_ocrq_call_id(self):
        body = struct.pack(">H", 0x1234) + b"\x00" * 30
        msg = parse_pptp(_common(OCRQ, 12 + len(body)) + body)
        self.assertTrue(msg.is_call_request)
        self.assertEqual(msg.call_id, 0x1234)

    def test_icrq_call_id(self):
        body = struct.pack(">H", 0xABCD) + b"\x00" * 12
        msg = parse_pptp(_common(ICRQ, 12 + len(body)) + body)
        self.assertTrue(msg.is_call_request)
        self.assertEqual(msg.call_id, 0xABCD)

    def test_ocrp_call_pair_and_result(self):
        body = struct.pack(">HH", 0x0002, 0x1234)  # Call ID + Peer's Call ID
        body += bytes([1, 0])  # Result=1, Error=0
        body += b"\x00" * 10
        msg = parse_pptp(_common(OCRP, 12 + len(body)) + body)
        self.assertTrue(msg.is_call_reply)
        self.assertEqual(msg.call_id, 0x0002)
        self.assertEqual(msg.peer_call_id, 0x1234)
        self.assertEqual(msg.result_code, 1)
        self.assertEqual(msg.error_code, 0)

    def test_iccn_peer_call_id(self):
        body = struct.pack(">H", 0x0042) + b"\x00" * 10
        msg = parse_pptp(_common(ICCN, 12 + len(body)) + body)
        self.assertEqual(msg.peer_call_id, 0x0042)

    def test_wan_error_is_teardown(self):
        body = struct.pack(">H", 0x0042) + b"\x00" * 26
        msg = parse_pptp(_common(WAN_ERROR_NOTIFY, 12 + len(body)) + body)
        self.assertTrue(msg.is_teardown)
        self.assertEqual(msg.peer_call_id, 0x0042)

    def test_stop_ccrq_teardown(self):
        msg = parse_pptp(_common(STOP_CCRQ, 16) + b"\x01\x00\x00\x00")
        self.assertTrue(msg.is_teardown)


class PPTPOffsetTests(unittest.TestCase):
    def test_two_messages_in_one_segment(self):
        seg = _sccrq("A", "X")
        first_len = len(seg)
        seg += _common(5)  # Echo-Request 뒤이어
        first = parse_pptp(seg)
        self.assertEqual(first.payload_offset, first_len)
        second = parse_pptp(seg, first.payload_offset)
        self.assertEqual(second.control_message_type, 5)

    def test_offset_parsing(self):
        prefix = b"\xaa\xbb\xcc"
        msg = parse_pptp(prefix + _common(5), offset=3)
        self.assertIsNotNone(msg)
        self.assertEqual(msg.control_message_type, 5)


if __name__ == "__main__":
    unittest.main()
