"""forensiclab.pop3 단위 테스트 (stdlib unittest)."""

import base64
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from forensiclab.pop3 import (  # noqa: E402
    POP3_PORTS,
    Pop3Command,
    Pop3Reply,
    decode_auth_plain,
    parse_apop_argument,
    parse_apop_banner,
    parse_pop3,
)


def _line(text: str) -> bytes:
    """CRLF 종단을 붙여 바이트로."""
    return (text + "\r\n").encode("ascii")


class CommandTests(unittest.TestCase):
    def test_user_command(self):
        msg = parse_pop3(_line("USER alice"))
        self.assertIsInstance(msg, Pop3Command)
        self.assertEqual(msg.verb, "USER")
        self.assertEqual(msg.arg, "alice")

    def test_verb_uppercased(self):
        msg = parse_pop3(_line("pass s3cret"))
        self.assertEqual(msg.verb, "PASS")
        self.assertEqual(msg.arg, "s3cret")

    def test_command_without_arg(self):
        msg = parse_pop3(_line("STAT"))
        self.assertIsInstance(msg, Pop3Command)
        self.assertEqual(msg.verb, "STAT")
        self.assertEqual(msg.arg, "")

    def test_is_credential(self):
        self.assertTrue(parse_pop3(_line("USER alice")).is_credential)
        self.assertTrue(parse_pop3(_line("PASS s3cret")).is_credential)
        self.assertTrue(parse_pop3(_line("APOP alice deadbeef")).is_credential)
        self.assertFalse(parse_pop3(_line("STAT")).is_credential)

    def test_is_retrieval(self):
        self.assertTrue(parse_pop3(_line("RETR 1")).is_retrieval)
        self.assertTrue(parse_pop3(_line("TOP 1 10")).is_retrieval)
        self.assertFalse(parse_pop3(_line("LIST")).is_retrieval)

    def test_is_delete(self):
        self.assertTrue(parse_pop3(_line("DELE 1")).is_delete)
        self.assertFalse(parse_pop3(_line("RETR 1")).is_delete)


class ApopTests(unittest.TestCase):
    def test_apop_credentials(self):
        digest = "c4c9334bac560ecc979e58001b3e22fb"
        msg = parse_pop3(_line("APOP alice " + digest))
        self.assertEqual(msg.apop_credentials, ("alice", digest))

    def test_non_apop_no_credentials(self):
        self.assertIsNone(parse_pop3(_line("USER alice")).apop_credentials)

    def test_parse_apop_argument_bad_token_count(self):
        self.assertIsNone(parse_apop_argument("alice"))
        self.assertIsNone(parse_apop_argument("alice digest extra"))

    def test_parse_apop_banner_from_greeting(self):
        banner = parse_apop_banner("POP3 ready <1896.697170952@mail.corp.example>")
        self.assertEqual(banner, "<1896.697170952@mail.corp.example>")

    def test_parse_apop_banner_absent(self):
        self.assertIsNone(parse_apop_banner("POP3 ready, no timestamp"))

    def test_reply_apop_banner(self):
        msg = parse_pop3(_line("+OK ready <1896.697@host>"))
        self.assertEqual(msg.apop_banner, "<1896.697@host>")


class AuthCredentialTests(unittest.TestCase):
    def test_auth_plain_inline_credentials(self):
        token = base64.b64encode(b"\x00alice\x00s3cret").decode("ascii")
        msg = parse_pop3(_line("AUTH PLAIN " + token))
        self.assertEqual(msg.auth_credentials, ("", "alice", "s3cret"))

    def test_auth_without_initial_response(self):
        # AUTH PLAIN 초기 응답이 없으면 자격증명을 즉시 노출하지 않는다.
        self.assertIsNone(parse_pop3(_line("AUTH PLAIN")).auth_credentials)

    def test_non_auth_no_credentials(self):
        self.assertIsNone(parse_pop3(_line("USER alice")).auth_credentials)

    def test_decode_auth_plain_with_authzid(self):
        token = base64.b64encode(b"admin\x00alice\x00pw").decode("ascii")
        self.assertEqual(decode_auth_plain(token), ("admin", "alice", "pw"))

    def test_decode_auth_plain_bad_base64(self):
        self.assertIsNone(decode_auth_plain("not!base64!"))

    def test_decode_auth_plain_wrong_field_count(self):
        token = base64.b64encode(b"only\x00two").decode("ascii")
        self.assertIsNone(decode_auth_plain(token))


class ReplyTests(unittest.TestCase):
    def test_ok_reply(self):
        msg = parse_pop3(_line("+OK 2 messages"))
        self.assertIsInstance(msg, Pop3Reply)
        self.assertEqual(msg.status, "+OK")
        self.assertEqual(msg.text, "2 messages")
        self.assertTrue(msg.is_ok)
        self.assertFalse(msg.is_error)

    def test_err_reply(self):
        msg = parse_pop3(_line("-ERR invalid password"))
        self.assertIsInstance(msg, Pop3Reply)
        self.assertEqual(msg.status, "-ERR")
        self.assertTrue(msg.is_error)
        self.assertFalse(msg.is_ok)

    def test_indicator_only_reply(self):
        msg = parse_pop3(_line("+OK"))
        self.assertIsInstance(msg, Pop3Reply)
        self.assertEqual(msg.status, "+OK")
        self.assertEqual(msg.text, "")


class DisambiguationTests(unittest.TestCase):
    def test_plus_without_ok_is_command(self):
        # '+something' 이지만 +OK 가 아니면 명령으로 취급.
        msg = parse_pop3(_line("+FOO bar"))
        self.assertIsInstance(msg, Pop3Command)

    def test_command_resembling_status_text(self):
        # 본문에 OK 가 들어가도 첫 토큰이 표시자가 아니면 명령.
        msg = parse_pop3(_line("RETR +OK"))
        self.assertIsInstance(msg, Pop3Command)
        self.assertEqual(msg.verb, "RETR")


class RobustnessTests(unittest.TestCase):
    def test_lf_only_line_ending(self):
        msg = parse_pop3(b"USER alice\n")
        self.assertEqual(msg.verb, "USER")

    def test_only_first_line_parsed(self):
        msg = parse_pop3(_line("USER alice") + _line("PASS s3cret"))
        self.assertEqual(msg.verb, "USER")

    def test_offset(self):
        raw = b"\x00\x00" + _line("STAT")
        msg = parse_pop3(raw, offset=2)
        self.assertEqual(msg.verb, "STAT")

    def test_empty_returns_none(self):
        self.assertIsNone(parse_pop3(b""))

    def test_blank_line_returns_none(self):
        self.assertIsNone(parse_pop3(b"   \r\n"))

    def test_negative_offset_returns_none(self):
        self.assertIsNone(parse_pop3(_line("USER x"), offset=-1))

    def test_ports_constant(self):
        self.assertEqual(POP3_PORTS, (110, 995))


if __name__ == "__main__":
    unittest.main()
