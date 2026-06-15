"""forensiclab.tacacs 단위 테스트 (stdlib unittest)."""

import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from forensiclab.tacacs import (  # noqa: E402
    TACACS_FLAG_SINGLE_CONNECT,
    TACACS_FLAG_UNENCRYPTED,
    TACACS_HEADER_LEN,
    TACACS_MAJOR_VERSION,
    TACACS_TYPE_ACCOUNTING,
    TACACS_TYPE_AUTHENTICATION,
    TACACS_TYPE_AUTHORIZATION,
    Tacacs,
    parse_tacacs,
)


def _header(
    major=TACACS_MAJOR_VERSION,
    minor=0,
    ptype=TACACS_TYPE_AUTHENTICATION,
    seq_no=1,
    flags=0,
    session_id=0x11223344,
    length=0,
    body=b"",
):
    """TACACS+ 12바이트 헤더(+선택 본문) 바이트를 짠다."""
    version = ((major & 0x0F) << 4) | (minor & 0x0F)
    return (
        struct.pack(">BBBBII", version, ptype, seq_no, flags, session_id, length)
        + body
    )


class HeaderTests(unittest.TestCase):
    def test_parses_minimal_header(self):
        pkt = _header()
        t = parse_tacacs(pkt)
        self.assertIsInstance(t, Tacacs)
        self.assertEqual(t.major_version, TACACS_MAJOR_VERSION)
        self.assertEqual(t.minor_version, 0)
        self.assertEqual(t.type, TACACS_TYPE_AUTHENTICATION)
        self.assertEqual(t.seq_no, 1)
        self.assertEqual(t.session_id, 0x11223344)
        self.assertEqual(t.length, 0)
        self.assertEqual(t.payload_offset, TACACS_HEADER_LEN)

    def test_minor_version_extracted(self):
        t = parse_tacacs(_header(minor=1))
        self.assertEqual(t.minor_version, 1)
        self.assertEqual(t.major_version, TACACS_MAJOR_VERSION)

    def test_length_and_payload_offset(self):
        body = b"\xde\xad\xbe\xef\x00\x01"
        t = parse_tacacs(_header(length=len(body), body=body))
        self.assertEqual(t.length, len(body))
        self.assertEqual(t.payload_offset, TACACS_HEADER_LEN)

    def test_offset_arg(self):
        prefix = b"\x99\x88\x77"
        t = parse_tacacs(prefix + _header(session_id=0xCAFEBABE), offset=3)
        self.assertEqual(t.session_id, 0xCAFEBABE)
        self.assertEqual(t.payload_offset, 3 + TACACS_HEADER_LEN)


class TypeTests(unittest.TestCase):
    def test_authentication(self):
        t = parse_tacacs(_header(ptype=TACACS_TYPE_AUTHENTICATION))
        self.assertTrue(t.is_authentication)
        self.assertFalse(t.is_authorization)
        self.assertFalse(t.is_accounting)
        self.assertEqual(t.type_name, "Authentication")

    def test_authorization(self):
        t = parse_tacacs(_header(ptype=TACACS_TYPE_AUTHORIZATION))
        self.assertTrue(t.is_authorization)
        self.assertEqual(t.type_name, "Authorization")

    def test_accounting(self):
        t = parse_tacacs(_header(ptype=TACACS_TYPE_ACCOUNTING))
        self.assertTrue(t.is_accounting)
        self.assertEqual(t.type_name, "Accounting")


class SessionAndFlagTests(unittest.TestCase):
    def test_session_start(self):
        self.assertTrue(parse_tacacs(_header(seq_no=1)).is_session_start)
        self.assertFalse(parse_tacacs(_header(seq_no=2)).is_session_start)

    def test_unencrypted_flag(self):
        t = parse_tacacs(_header(flags=TACACS_FLAG_UNENCRYPTED))
        self.assertTrue(t.is_unencrypted)
        self.assertFalse(t.is_single_connect)

    def test_single_connect_flag(self):
        t = parse_tacacs(_header(flags=TACACS_FLAG_SINGLE_CONNECT))
        self.assertTrue(t.is_single_connect)
        self.assertFalse(t.is_unencrypted)

    def test_both_flags(self):
        t = parse_tacacs(
            _header(flags=TACACS_FLAG_UNENCRYPTED | TACACS_FLAG_SINGLE_CONNECT)
        )
        self.assertTrue(t.is_unencrypted)
        self.assertTrue(t.is_single_connect)

    def test_no_flags(self):
        t = parse_tacacs(_header(flags=0))
        self.assertFalse(t.is_unencrypted)
        self.assertFalse(t.is_single_connect)


class RejectionTests(unittest.TestCase):
    def test_too_short(self):
        self.assertIsNone(parse_tacacs(_header()[:TACACS_HEADER_LEN - 1]))

    def test_empty(self):
        self.assertIsNone(parse_tacacs(b""))

    def test_wrong_major_version(self):
        # major 0xd 는 TACACS+ 가 아니다.
        self.assertIsNone(parse_tacacs(_header(major=0xD)))

    def test_undefined_type(self):
        self.assertIsNone(parse_tacacs(_header(ptype=0x09)))

    def test_type_zero(self):
        self.assertIsNone(parse_tacacs(_header(ptype=0x00)))

    def test_negative_offset(self):
        self.assertIsNone(parse_tacacs(_header(), offset=-1))

    def test_offset_past_end(self):
        self.assertIsNone(parse_tacacs(_header(), offset=5))

    def test_unknown_type_name_for_valid_but_other(self):
        # 정의된 type 만 통과하므로 type_name 의 fallback 은 직접 구성으로 확인.
        t = Tacacs(
            major_version=0xC,
            minor_version=0,
            type=0x42,
            seq_no=1,
            flags=0,
            session_id=0,
            length=0,
            payload_offset=12,
        )
        self.assertEqual(t.type_name, "type-66")


if __name__ == "__main__":
    unittest.main()
