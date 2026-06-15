"""forensiclab.smtp 단위 테스트 (stdlib unittest)."""

import base64
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from forensiclab.smtp import (  # noqa: E402
    SMTP_PORTS,
    SmtpCommand,
    SmtpReply,
    decode_auth_plain,
    parse_mail_path,
    parse_smtp,
)


def _line(text: str) -> bytes:
    """CRLF 종단을 붙여 바이트로."""
    return (text + "\r\n").encode("ascii")


class CommandTests(unittest.TestCase):
    def test_ehlo_command(self):
        msg = parse_smtp(_line("EHLO mail.evil.example"))
        self.assertIsInstance(msg, SmtpCommand)
        self.assertEqual(msg.verb, "EHLO")
        self.assertEqual(msg.arg, "mail.evil.example")

    def test_verb_uppercased(self):
        msg = parse_smtp(_line("mail from:<a@b>"))
        self.assertEqual(msg.verb, "MAIL")
        self.assertEqual(msg.arg, "from:<a@b>")

    def test_command_without_arg(self):
        msg = parse_smtp(_line("DATA"))
        self.assertIsInstance(msg, SmtpCommand)
        self.assertEqual(msg.verb, "DATA")
        self.assertEqual(msg.arg, "")

    def test_is_auth(self):
        self.assertTrue(parse_smtp(_line("AUTH LOGIN")).is_auth)
        self.assertFalse(parse_smtp(_line("EHLO x")).is_auth)

    def test_is_envelope(self):
        self.assertTrue(parse_smtp(_line("MAIL FROM:<a@b>")).is_envelope)
        self.assertTrue(parse_smtp(_line("RCPT TO:<c@d>")).is_envelope)
        self.assertFalse(parse_smtp(_line("DATA")).is_envelope)

    def test_is_recon(self):
        self.assertTrue(parse_smtp(_line("VRFY admin")).is_recon)
        self.assertTrue(parse_smtp(_line("EXPN staff")).is_recon)
        self.assertFalse(parse_smtp(_line("NOOP")).is_recon)

    def test_is_starttls(self):
        self.assertTrue(parse_smtp(_line("STARTTLS")).is_starttls)
        self.assertFalse(parse_smtp(_line("HELO x")).is_starttls)


class MailAddressTests(unittest.TestCase):
    def test_mail_from_address(self):
        msg = parse_smtp(_line("MAIL FROM:<attacker@evil.example>"))
        self.assertEqual(msg.mail_address, "attacker@evil.example")

    def test_rcpt_to_with_params(self):
        msg = parse_smtp(_line("RCPT TO:<victim@corp.example> NOTIFY=NEVER"))
        self.assertEqual(msg.mail_address, "victim@corp.example")

    def test_null_sender(self):
        # 빈 발신자(반송/DSN) — 빈 문자열.
        msg = parse_smtp(_line("MAIL FROM:<>"))
        self.assertEqual(msg.mail_address, "")

    def test_non_envelope_no_address(self):
        self.assertIsNone(parse_smtp(_line("EHLO host")).mail_address)

    def test_parse_mail_path_no_brackets(self):
        # 관대 처리: 꺾쇠 없는 형식도 첫 토큰을 환원.
        self.assertEqual(parse_mail_path("FROM:alice@x SIZE=10"), "alice@x")

    def test_parse_mail_path_empty(self):
        self.assertIsNone(parse_mail_path(""))


class AuthCredentialTests(unittest.TestCase):
    def test_auth_plain_inline_credentials(self):
        token = base64.b64encode(b"\x00alice\x00s3cret").decode("ascii")
        msg = parse_smtp(_line("AUTH PLAIN " + token))
        self.assertEqual(msg.auth_credentials, ("", "alice", "s3cret"))

    def test_auth_login_has_no_inline_credentials(self):
        # AUTH LOGIN 은 초기 응답이 없어 자격증명을 즉시 노출하지 않는다.
        self.assertIsNone(parse_smtp(_line("AUTH LOGIN")).auth_credentials)

    def test_non_auth_no_credentials(self):
        self.assertIsNone(parse_smtp(_line("MAIL FROM:<a@b>")).auth_credentials)

    def test_decode_auth_plain_with_authzid(self):
        token = base64.b64encode(b"admin\x00alice\x00pw").decode("ascii")
        self.assertEqual(decode_auth_plain(token), ("admin", "alice", "pw"))

    def test_decode_auth_plain_bad_base64(self):
        self.assertIsNone(decode_auth_plain("not!base64!"))

    def test_decode_auth_plain_wrong_field_count(self):
        token = base64.b64encode(b"only\x00two").decode("ascii")
        self.assertIsNone(decode_auth_plain(token))


class ReplyTests(unittest.TestCase):
    def test_simple_reply(self):
        msg = parse_smtp(_line("250 OK"))
        self.assertIsInstance(msg, SmtpReply)
        self.assertEqual(msg.code, 250)
        self.assertEqual(msg.text, "OK")
        self.assertFalse(msg.is_intermediate)

    def test_intermediate_multiline_marker(self):
        msg = parse_smtp(_line("250-mail.corp.example"))
        self.assertIsInstance(msg, SmtpReply)
        self.assertEqual(msg.code, 250)
        self.assertTrue(msg.is_intermediate)

    def test_category_and_completion(self):
        self.assertTrue(parse_smtp(_line("220 ESMTP ready")).is_positive_completion)
        self.assertEqual(parse_smtp(_line("354 go ahead")).category, 3)
        self.assertFalse(parse_smtp(_line("535 bad creds")).is_positive_completion)

    def test_auth_failure(self):
        self.assertTrue(parse_smtp(_line("535 5.7.8 Authentication failed")).is_auth_failure)
        self.assertFalse(parse_smtp(_line("235 Authentication successful")).is_auth_failure)

    def test_code_only_reply(self):
        msg = parse_smtp(_line("250"))
        self.assertIsInstance(msg, SmtpReply)
        self.assertEqual(msg.code, 250)
        self.assertEqual(msg.text, "")


class DisambiguationTests(unittest.TestCase):
    def test_four_digit_run_is_command(self):
        msg = parse_smtp(_line("2500 weird"))
        self.assertIsInstance(msg, SmtpCommand)

    def test_digit_run_without_separator_is_command(self):
        msg = parse_smtp(_line("250x"))
        self.assertIsInstance(msg, SmtpCommand)


class RobustnessTests(unittest.TestCase):
    def test_lf_only_line_ending(self):
        msg = parse_smtp(b"EHLO host\n")
        self.assertEqual(msg.verb, "EHLO")

    def test_only_first_line_parsed(self):
        msg = parse_smtp(_line("MAIL FROM:<a@b>") + _line("RCPT TO:<c@d>"))
        self.assertEqual(msg.verb, "MAIL")

    def test_offset(self):
        raw = b"\x00\x00" + _line("DATA")
        msg = parse_smtp(raw, offset=2)
        self.assertEqual(msg.verb, "DATA")

    def test_empty_returns_none(self):
        self.assertIsNone(parse_smtp(b""))

    def test_blank_line_returns_none(self):
        self.assertIsNone(parse_smtp(b"   \r\n"))

    def test_negative_offset_returns_none(self):
        self.assertIsNone(parse_smtp(_line("EHLO x"), offset=-1))

    def test_ports_constant(self):
        self.assertEqual(SMTP_PORTS, (25, 587, 465))


if __name__ == "__main__":
    unittest.main()
