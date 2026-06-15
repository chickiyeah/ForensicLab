"""forensiclab.ftp 단위 테스트 (stdlib unittest)."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from forensiclab.ftp import (  # noqa: E402
    FTP_CONTROL_PORT,
    FtpCommand,
    FtpReply,
    parse_ftp,
    parse_passive_reply,
    parse_port_argument,
)


def _line(text: str) -> bytes:
    """CRLF 종단을 붙여 바이트로."""
    return (text + "\r\n").encode("ascii")


class CommandTests(unittest.TestCase):
    def test_user_command(self):
        msg = parse_ftp(_line("USER anonymous"))
        self.assertIsInstance(msg, FtpCommand)
        self.assertEqual(msg.verb, "USER")
        self.assertEqual(msg.arg, "anonymous")

    def test_verb_uppercased(self):
        msg = parse_ftp(_line("retr /pub/secret.zip"))
        self.assertEqual(msg.verb, "RETR")
        self.assertEqual(msg.arg, "/pub/secret.zip")

    def test_command_without_arg(self):
        msg = parse_ftp(_line("PASV"))
        self.assertIsInstance(msg, FtpCommand)
        self.assertEqual(msg.verb, "PASV")
        self.assertEqual(msg.arg, "")

    def test_is_credential(self):
        self.assertTrue(parse_ftp(_line("USER bob")).is_credential)
        self.assertTrue(parse_ftp(_line("PASS hunter2")).is_credential)
        self.assertTrue(parse_ftp(_line("ACCT dept")).is_credential)
        self.assertFalse(parse_ftp(_line("CWD /pub")).is_credential)

    def test_password_in_arg(self):
        # 평문 자격증명 노출 — 인자에 비밀번호가 그대로 담긴다.
        msg = parse_ftp(_line("PASS guest@example.com"))
        self.assertEqual(msg.arg, "guest@example.com")

    def test_is_transfer(self):
        for verb in ("RETR", "STOR", "STOU", "APPE"):
            self.assertTrue(parse_ftp(_line(verb + " f")).is_transfer, verb)
        self.assertFalse(parse_ftp(_line("LIST")).is_transfer)

    def test_anonymous_login(self):
        self.assertTrue(parse_ftp(_line("USER anonymous")).is_anonymous_login)
        self.assertTrue(parse_ftp(_line("USER FTP")).is_anonymous_login)
        self.assertFalse(parse_ftp(_line("USER alice")).is_anonymous_login)
        self.assertFalse(parse_ftp(_line("PASS anonymous")).is_anonymous_login)


class DataEndpointTests(unittest.TestCase):
    def test_port_command_endpoint(self):
        msg = parse_ftp(_line("PORT 192,168,0,10,7,138"))
        self.assertEqual(msg.data_endpoint, ("192.168.0.10", 7 * 256 + 138))

    def test_eprt_command_endpoint(self):
        msg = parse_ftp(_line("EPRT |1|192.168.0.10|50000|"))
        self.assertEqual(msg.data_endpoint, ("192.168.0.10", 50000))

    def test_non_port_command_no_endpoint(self):
        self.assertIsNone(parse_ftp(_line("RETR x")).data_endpoint)

    def test_parse_port_argument_classic(self):
        self.assertEqual(parse_port_argument("10,0,0,1,4,1"), ("10.0.0.1", 1025))

    def test_parse_port_argument_rejects_bad_octet(self):
        self.assertIsNone(parse_port_argument("10,0,0,300,4,1"))

    def test_parse_port_argument_wrong_count(self):
        self.assertIsNone(parse_port_argument("10,0,0,1,4"))

    def test_parse_port_argument_eprt_no_addr(self):
        self.assertEqual(parse_port_argument("|||50000|"), ("", 50000))

    def test_parse_port_argument_rejects_bad_port(self):
        self.assertIsNone(parse_port_argument("|1|::1|notaport|"))
        self.assertIsNone(parse_port_argument("0,0,0,0,999,0"))


class ReplyTests(unittest.TestCase):
    def test_simple_reply(self):
        msg = parse_ftp(_line("230 Login successful."))
        self.assertIsInstance(msg, FtpReply)
        self.assertEqual(msg.code, 230)
        self.assertEqual(msg.text, "Login successful.")
        self.assertFalse(msg.is_intermediate)

    def test_intermediate_multiline_marker(self):
        msg = parse_ftp(_line("220-Welcome banner line 1"))
        self.assertIsInstance(msg, FtpReply)
        self.assertEqual(msg.code, 220)
        self.assertTrue(msg.is_intermediate)

    def test_category_and_completion(self):
        self.assertTrue(parse_ftp(_line("226 Transfer complete.")).is_positive_completion)
        self.assertEqual(parse_ftp(_line("226 done")).category, 2)
        self.assertFalse(parse_ftp(_line("530 Login incorrect.")).is_positive_completion)

    def test_auth_failure(self):
        self.assertTrue(parse_ftp(_line("530 Login incorrect.")).is_auth_failure)
        self.assertFalse(parse_ftp(_line("230 ok")).is_auth_failure)

    def test_passive_endpoint_227(self):
        msg = parse_ftp(_line("227 Entering Passive Mode (192,168,0,10,7,138)."))
        self.assertEqual(msg.passive_endpoint, ("192.168.0.10", 7 * 256 + 138))

    def test_passive_endpoint_229(self):
        msg = parse_ftp(_line("229 Entering Extended Passive Mode (|||50000|)."))
        self.assertEqual(msg.passive_endpoint, ("", 50000))

    def test_non_passive_reply_no_endpoint(self):
        self.assertIsNone(parse_ftp(_line("230 Login successful.")).passive_endpoint)

    def test_code_only_reply(self):
        msg = parse_ftp(_line("200"))
        self.assertIsInstance(msg, FtpReply)
        self.assertEqual(msg.code, 200)
        self.assertEqual(msg.text, "")


class DisambiguationTests(unittest.TestCase):
    def test_three_digit_verb_not_misread_as_reply(self):
        # 4자리 숫자나 숫자+문자는 명령으로 본다(코드는 정확히 3자리+구분자).
        msg = parse_ftp(_line("2300 weird"))
        self.assertIsInstance(msg, FtpCommand)

    def test_digit_run_without_separator_is_command(self):
        msg = parse_ftp(_line("123abc"))
        self.assertIsInstance(msg, FtpCommand)
        self.assertEqual(msg.verb, "123ABC")

    def test_parse_passive_reply_no_parens(self):
        self.assertIsNone(parse_passive_reply("no parens here"))


class RobustnessTests(unittest.TestCase):
    def test_lf_only_line_ending(self):
        msg = parse_ftp(b"USER bob\n")
        self.assertEqual(msg.verb, "USER")

    def test_only_first_line_parsed(self):
        msg = parse_ftp(_line("USER bob") + _line("PASS secret"))
        self.assertEqual(msg.verb, "USER")
        self.assertEqual(msg.arg, "bob")

    def test_offset(self):
        raw = b"\x00\x00" + _line("RETR x")
        msg = parse_ftp(raw, offset=2)
        self.assertEqual(msg.verb, "RETR")

    def test_empty_returns_none(self):
        self.assertIsNone(parse_ftp(b""))

    def test_blank_line_returns_none(self):
        self.assertIsNone(parse_ftp(b"   \r\n"))

    def test_negative_offset_returns_none(self):
        self.assertIsNone(parse_ftp(_line("USER bob"), offset=-1))

    def test_control_port_constant(self):
        self.assertEqual(FTP_CONTROL_PORT, 21)


if __name__ == "__main__":
    unittest.main()
