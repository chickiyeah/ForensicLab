"""forensiclab.ident 단위 테스트 (stdlib unittest)."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from forensiclab.ident import (  # noqa: E402
    IDENT_PORTS,
    IDENT_ERROR_TYPES,
    IdentMessage,
    parse_ident,
)


def _line(text: str) -> bytes:
    """CRLF 종단을 붙여 바이트로(UTF-8)."""
    return (text + "\r\n").encode("utf-8")


class QueryTests(unittest.TestCase):
    def test_basic_query(self):
        m = parse_ident(_line("6191, 23"))
        self.assertIsInstance(m, IdentMessage)
        self.assertTrue(m.is_query)
        self.assertFalse(m.is_reply)
        self.assertEqual(m.server_port, 6191)
        self.assertEqual(m.client_port, 23)
        self.assertEqual(m.port_pair, (6191, 23))
        self.assertIsNone(m.resp_type)
        self.assertFalse(m.is_userid)
        self.assertFalse(m.has_attribution)

    def test_query_no_spaces(self):
        m = parse_ident(_line("12345,80"))
        self.assertTrue(m.is_query)
        self.assertEqual(m.server_port, 12345)
        self.assertEqual(m.client_port, 80)

    def test_query_nonnumeric_port(self):
        m = parse_ident(_line("foo, 23"))
        self.assertTrue(m.is_query)
        self.assertIsNone(m.server_port)
        self.assertEqual(m.client_port, 23)
        self.assertIsNone(m.port_pair)


class UseridReplyTests(unittest.TestCase):
    def test_userid_reply(self):
        m = parse_ident(_line("6191, 23 : USERID : UNIX : alice"))
        self.assertTrue(m.is_reply)
        self.assertTrue(m.is_userid)
        self.assertEqual(m.opsys, "UNIX")
        self.assertIsNone(m.charset)
        self.assertEqual(m.username, "alice")
        self.assertTrue(m.has_attribution)
        self.assertEqual(m.port_pair, (6191, 23))

    def test_userid_with_charset(self):
        m = parse_ident(_line("6191, 23 : USERID : UNIX,US-ASCII : root"))
        self.assertEqual(m.opsys, "UNIX")
        self.assertEqual(m.charset, "US-ASCII")
        self.assertEqual(m.username, "root")
        self.assertTrue(m.has_attribution)

    def test_username_with_colon_rejoined(self):
        # 사용자명에 콜론이 있어도 마지막 필드를 다시 이어 붙인다.
        m = parse_ident(_line("6191, 23 : USERID : OTHER : do:main\\user"))
        self.assertEqual(m.username, "do:main\\user")

    def test_userid_no_attribution_when_missing(self):
        m = parse_ident(_line("6191, 23 : USERID : UNIX"))
        self.assertTrue(m.is_userid)
        self.assertIsNone(m.username)
        self.assertFalse(m.has_attribution)


class ErrorReplyTests(unittest.TestCase):
    def test_hidden_user(self):
        m = parse_ident(_line("6191, 23 : ERROR : HIDDEN-USER"))
        self.assertTrue(m.is_error)
        self.assertEqual(m.error_type, "HIDDEN-USER")
        self.assertTrue(m.is_hidden_user)
        self.assertFalse(m.is_invalid_port)
        self.assertFalse(m.has_attribution)

    def test_invalid_port(self):
        m = parse_ident(_line("6191, 23 : ERROR : INVALID-PORT"))
        self.assertTrue(m.is_error)
        self.assertTrue(m.is_invalid_port)
        self.assertFalse(m.is_hidden_user)

    def test_no_user(self):
        m = parse_ident(_line("6191, 23 : ERROR : NO-USER"))
        self.assertEqual(m.error_type, "NO-USER")
        self.assertIn(m.error_type, IDENT_ERROR_TYPES)

    def test_error_lowercase_normalized(self):
        m = parse_ident(_line("6191, 23 : error : hidden-user"))
        self.assertTrue(m.is_error)
        self.assertTrue(m.is_hidden_user)


class RobustnessTests(unittest.TestCase):
    def test_lf_only_line_ending(self):
        m = parse_ident(b"6191, 23\n")
        self.assertTrue(m.is_query)
        self.assertEqual(m.server_port, 6191)

    def test_only_first_line_parsed(self):
        m = parse_ident(_line("6191, 23") + _line("70, 80"))
        self.assertEqual(m.port_pair, (6191, 23))

    def test_offset(self):
        raw = b"\x00\x00" + _line("6191, 23")
        m = parse_ident(raw, offset=2)
        self.assertEqual(m.server_port, 6191)

    def test_empty_bytes_returns_none(self):
        self.assertIsNone(parse_ident(b""))

    def test_negative_offset_returns_none(self):
        self.assertIsNone(parse_ident(_line("6191, 23"), offset=-1))

    def test_raw_preserved(self):
        m = parse_ident(_line("6191, 23 : USERID : UNIX : alice"))
        self.assertEqual(m.raw, "6191, 23 : USERID : UNIX : alice")

    def test_unknown_resp_type_kept(self):
        m = parse_ident(_line("6191, 23 : WEIRD : stuff"))
        self.assertTrue(m.is_reply)
        self.assertEqual(m.resp_type, "WEIRD")
        self.assertFalse(m.is_userid)
        self.assertFalse(m.is_error)

    def test_ports_constant(self):
        self.assertIn(113, IDENT_PORTS)


if __name__ == "__main__":
    unittest.main()
