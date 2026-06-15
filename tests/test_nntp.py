"""forensiclab.nntp 단위 테스트 (stdlib unittest)."""

import base64
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from forensiclab.nntp import (  # noqa: E402
    NNTP_PORTS,
    NntpCommand,
    NntpReply,
    decode_sasl_plain,
    parse_nntp,
)


def _line(text: str) -> bytes:
    """CRLF 종단을 붙여 바이트로(ASCII)."""
    return (text + "\r\n").encode("ascii")


class CommandTests(unittest.TestCase):
    def test_group_select(self):
        c = parse_nntp(_line("GROUP alt.binaries.warez"))
        self.assertIsInstance(c, NntpCommand)
        self.assertEqual(c.verb, "GROUP")
        self.assertTrue(c.is_group_select)
        self.assertEqual(c.newsgroup, "alt.binaries.warez")

    def test_verb_normalized_uppercase(self):
        c = parse_nntp(_line("group news.test"))
        self.assertEqual(c.verb, "GROUP")
        self.assertEqual(c.newsgroup, "news.test")

    def test_retrieve_article(self):
        c = parse_nntp(_line("ARTICLE <msg-id@host>"))
        self.assertTrue(c.is_retrieve)
        self.assertFalse(c.is_post)
        self.assertEqual(c.arg, "<msg-id@host>")

    def test_body_is_retrieve(self):
        self.assertTrue(parse_nntp(_line("BODY 12345")).is_retrieve)

    def test_post_is_post(self):
        c = parse_nntp(_line("POST"))
        self.assertTrue(c.is_post)
        self.assertEqual(c.arg, "")

    def test_ihave_is_post(self):
        self.assertTrue(parse_nntp(_line("IHAVE <leak@evil.example>")).is_post)

    def test_enumeration(self):
        self.assertTrue(parse_nntp(_line("LIST")).is_enumeration)
        self.assertTrue(parse_nntp(_line("NEWGROUPS 20260101 000000")).is_enumeration)
        self.assertTrue(parse_nntp(_line("NEWNEWS * 20260101 000000")).is_enumeration)

    def test_non_group_newsgroup_none(self):
        self.assertIsNone(parse_nntp(_line("ARTICLE 5")).newsgroup)


class CredentialTests(unittest.TestCase):
    def test_authinfo_user_cleartext(self):
        c = parse_nntp(_line("AUTHINFO USER attacker"))
        self.assertTrue(c.is_auth)
        self.assertEqual(c.cleartext_credential, ("USER", "attacker"))

    def test_authinfo_pass_cleartext(self):
        c = parse_nntp(_line("AUTHINFO PASS s3cret"))
        self.assertEqual(c.cleartext_credential, ("PASS", "s3cret"))

    def test_authinfo_sub_normalized(self):
        c = parse_nntp(_line("AUTHINFO user alice"))
        self.assertEqual(c.cleartext_credential, ("USER", "alice"))

    def test_authinfo_other_sub_not_credential(self):
        # GENERIC 등 USER/PASS 가 아닌 부명령은 평문 자격증명이 아니다.
        c = parse_nntp(_line("AUTHINFO GENERIC PLAIN"))
        self.assertTrue(c.is_auth)
        self.assertIsNone(c.cleartext_credential)

    def test_non_auth_credential_none(self):
        self.assertIsNone(parse_nntp(_line("GROUP x")).cleartext_credential)

    def test_sasl_plain_credentials(self):
        token = base64.b64encode(b"\x00alice\x00s3cret").decode("ascii")
        c = parse_nntp(_line(f"AUTHINFO SASL PLAIN {token}"))
        self.assertEqual(c.sasl_credentials, ("", "alice", "s3cret"))
        # SASL 은 USER/PASS 평문 경로와 구분된다.
        self.assertIsNone(c.cleartext_credential)

    def test_sasl_non_plain_none(self):
        self.assertIsNone(parse_nntp(_line("AUTHINFO SASL CRAM-MD5")).sasl_credentials)

    def test_decode_sasl_plain_helper(self):
        token = base64.b64encode(b"authz\x00bob\x00pw").decode("ascii")
        self.assertEqual(decode_sasl_plain(token), ("authz", "bob", "pw"))

    def test_decode_sasl_plain_bad_base64(self):
        self.assertIsNone(decode_sasl_plain("!!!notb64!!!"))

    def test_decode_sasl_plain_wrong_field_count(self):
        token = base64.b64encode(b"onlyone").decode("ascii")
        self.assertIsNone(decode_sasl_plain(token))


class ReplyTests(unittest.TestCase):
    def test_greeting_positive(self):
        r = parse_nntp(_line("200 news.corp.example ready"))
        self.assertIsInstance(r, NntpReply)
        self.assertEqual(r.code, 200)
        self.assertEqual(r.category, 2)
        self.assertTrue(r.is_positive_completion)
        self.assertEqual(r.text, "news.corp.example ready")

    def test_auth_accepted(self):
        r = parse_nntp(_line("281 Authentication accepted"))
        self.assertTrue(r.is_auth_accepted)
        self.assertFalse(r.is_auth_failure)

    def test_password_required(self):
        r = parse_nntp(_line("381 PASS required"))
        self.assertTrue(r.is_password_required)
        self.assertEqual(r.category, 3)

    def test_auth_failure_481(self):
        r = parse_nntp(_line("481 Authentication failed"))
        self.assertTrue(r.is_auth_failure)

    def test_auth_failure_482_out_of_sequence(self):
        self.assertTrue(parse_nntp(_line("482 out of sequence")).is_auth_failure)

    def test_code_only_no_text(self):
        r = parse_nntp(_line("205"))
        self.assertIsInstance(r, NntpReply)
        self.assertEqual(r.code, 205)
        self.assertEqual(r.text, "")


class DisambiguationTests(unittest.TestCase):
    def test_three_digit_glued_is_command(self):
        # 3자리 뒤 공백/줄 끝이 아니면 응답이 아니라 명령으로 본다.
        c = parse_nntp(_line("200OK"))
        self.assertIsInstance(c, NntpCommand)
        self.assertEqual(c.verb, "200OK")

    def test_numeric_arg_command_not_reply(self):
        # ARTICLE 12345 는 명령이지 응답이 아니다(첫 토큰이 숫자 아님).
        c = parse_nntp(_line("ARTICLE 12345"))
        self.assertIsInstance(c, NntpCommand)


class RobustnessTests(unittest.TestCase):
    def test_lf_only_line_ending(self):
        c = parse_nntp(b"POST\n")
        self.assertEqual(c.verb, "POST")

    def test_only_first_line_parsed(self):
        c = parse_nntp(_line("GROUP a.b") + _line("ARTICLE 1"))
        self.assertEqual(c.verb, "GROUP")

    def test_offset(self):
        raw = b"\x00\x00" + _line("LIST")
        c = parse_nntp(raw, offset=2)
        self.assertEqual(c.verb, "LIST")

    def test_empty_bytes_returns_none(self):
        self.assertIsNone(parse_nntp(b""))

    def test_whitespace_only_returns_none(self):
        self.assertIsNone(parse_nntp(_line("   ")))

    def test_negative_offset_returns_none(self):
        self.assertIsNone(parse_nntp(_line("LIST"), offset=-1))

    def test_raw_preserved(self):
        c = parse_nntp(_line("AUTHINFO USER bob"))
        self.assertEqual(c.raw, "AUTHINFO USER bob")

    def test_ports_constant(self):
        self.assertIn(119, NNTP_PORTS)
        self.assertIn(563, NNTP_PORTS)


if __name__ == "__main__":
    unittest.main()
