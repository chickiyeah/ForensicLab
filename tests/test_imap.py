"""forensiclab.imap 단위 테스트 (stdlib unittest)."""

import base64
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from forensiclab.imap import (  # noqa: E402
    IMAP_PORTS,
    ImapCommand,
    ImapResponse,
    decode_auth_plain,
    parse_imap,
    parse_login_argument,
)


def _line(text: str) -> bytes:
    """CRLF 종단을 붙여 바이트로."""
    return (text + "\r\n").encode("ascii")


class CommandTests(unittest.TestCase):
    def test_login_command(self):
        msg = parse_imap(_line("a001 LOGIN alice s3cret"))
        self.assertIsInstance(msg, ImapCommand)
        self.assertEqual(msg.tag, "a001")
        self.assertEqual(msg.verb, "LOGIN")
        self.assertEqual(msg.arg, "alice s3cret")

    def test_verb_uppercased(self):
        msg = parse_imap(_line("a002 select INBOX"))
        self.assertEqual(msg.verb, "SELECT")
        self.assertEqual(msg.arg, "INBOX")

    def test_command_without_arg(self):
        msg = parse_imap(_line("a003 NOOP"))
        self.assertIsInstance(msg, ImapCommand)
        self.assertEqual(msg.verb, "NOOP")
        self.assertEqual(msg.arg, "")

    def test_is_credential(self):
        self.assertTrue(parse_imap(_line("a001 LOGIN a b")).is_credential)
        self.assertFalse(parse_imap(_line("a002 SELECT INBOX")).is_credential)

    def test_is_select(self):
        self.assertTrue(parse_imap(_line("a002 SELECT INBOX")).is_select)
        self.assertTrue(parse_imap(_line("a002 EXAMINE Drafts")).is_select)
        self.assertFalse(parse_imap(_line("a003 FETCH 1 BODY[]")).is_select)

    def test_is_retrieval(self):
        self.assertTrue(parse_imap(_line("a004 FETCH 1 (BODY[])")).is_retrieval)
        self.assertFalse(parse_imap(_line("a002 SELECT INBOX")).is_retrieval)

    def test_is_delete_expunge(self):
        self.assertTrue(parse_imap(_line("a005 EXPUNGE")).is_delete)

    def test_is_delete_store_deleted_flag(self):
        msg = parse_imap(_line("a006 STORE 1 +FLAGS (\\Deleted)"))
        self.assertTrue(msg.is_delete)

    def test_store_without_deleted_flag_not_delete(self):
        msg = parse_imap(_line("a006 STORE 1 +FLAGS (\\Seen)"))
        self.assertFalse(msg.is_delete)


class UidPrefixTests(unittest.TestCase):
    def test_effective_verb_strips_uid(self):
        msg = parse_imap(_line("a007 UID FETCH 1:* (BODY[])"))
        self.assertEqual(msg.verb, "UID")
        self.assertEqual(msg.effective_verb, "FETCH")
        self.assertTrue(msg.is_retrieval)

    def test_uid_store_delete(self):
        msg = parse_imap(_line("a008 UID STORE 5 +FLAGS (\\Deleted)"))
        self.assertEqual(msg.effective_verb, "STORE")
        self.assertTrue(msg.is_delete)

    def test_non_uid_effective_verb_unchanged(self):
        msg = parse_imap(_line("a009 FETCH 1 BODY[]"))
        self.assertEqual(msg.effective_verb, "FETCH")


class MailboxTests(unittest.TestCase):
    def test_select_mailbox(self):
        msg = parse_imap(_line("a002 SELECT INBOX"))
        self.assertEqual(msg.mailbox, "INBOX")

    def test_quoted_mailbox(self):
        msg = parse_imap(_line('a002 EXAMINE "Sent Items"'))
        self.assertEqual(msg.mailbox, "Sent Items")

    def test_non_select_mailbox_none(self):
        self.assertIsNone(parse_imap(_line("a003 FETCH 1 BODY[]")).mailbox)


class LoginCredentialTests(unittest.TestCase):
    def test_plain_login_credentials(self):
        msg = parse_imap(_line("a001 LOGIN alice s3cret"))
        self.assertEqual(msg.login_credentials, ("alice", "s3cret"))

    def test_quoted_login_credentials(self):
        msg = parse_imap(_line('a001 LOGIN "alice" "s3 cret"'))
        self.assertEqual(msg.login_credentials, ("alice", "s3 cret"))

    def test_escaped_quote_in_password(self):
        msg = parse_imap(_line('a001 LOGIN alice "p\\"w"'))
        self.assertEqual(msg.login_credentials, ("alice", 'p"w'))

    def test_non_login_no_credentials(self):
        self.assertIsNone(parse_imap(_line("a002 SELECT INBOX")).login_credentials)

    def test_parse_login_argument_too_few_tokens(self):
        self.assertIsNone(parse_login_argument("alice"))

    def test_parse_login_argument_none(self):
        self.assertIsNone(parse_login_argument(None))


class AuthCredentialTests(unittest.TestCase):
    def test_authenticate_plain_inline(self):
        token = base64.b64encode(b"\x00alice\x00s3cret").decode("ascii")
        msg = parse_imap(_line("a002 AUTHENTICATE PLAIN " + token))
        self.assertEqual(msg.auth_credentials, ("", "alice", "s3cret"))

    def test_authenticate_without_initial_response(self):
        self.assertIsNone(parse_imap(_line("a002 AUTHENTICATE PLAIN")).auth_credentials)

    def test_authenticate_login_mechanism_not_decoded(self):
        # LOGIN 메커니즘은 자격증명을 한 줄에 담지 않는다.
        msg = parse_imap(_line("a002 AUTHENTICATE LOGIN"))
        self.assertIsNone(msg.auth_credentials)

    def test_non_authenticate_no_credentials(self):
        self.assertIsNone(parse_imap(_line("a001 LOGIN a b")).auth_credentials)

    def test_decode_auth_plain_with_authzid(self):
        token = base64.b64encode(b"admin\x00alice\x00pw").decode("ascii")
        self.assertEqual(decode_auth_plain(token), ("admin", "alice", "pw"))

    def test_decode_auth_plain_bad_base64(self):
        self.assertIsNone(decode_auth_plain("not!base64!"))

    def test_decode_auth_plain_wrong_field_count(self):
        token = base64.b64encode(b"only\x00two").decode("ascii")
        self.assertIsNone(decode_auth_plain(token))


class ResponseTests(unittest.TestCase):
    def test_tagged_ok(self):
        msg = parse_imap(_line("a001 OK [CAPABILITY IMAP4rev1] LOGIN completed"))
        self.assertIsInstance(msg, ImapResponse)
        self.assertEqual(msg.tag, "a001")
        self.assertEqual(msg.status, "OK")
        self.assertTrue(msg.is_tagged)
        self.assertTrue(msg.is_ok)
        self.assertFalse(msg.is_error)

    def test_tagged_no_is_error(self):
        msg = parse_imap(_line("a005 NO [AUTHENTICATIONFAILED] invalid credentials"))
        self.assertEqual(msg.status, "NO")
        self.assertTrue(msg.is_error)
        self.assertFalse(msg.is_ok)

    def test_tagged_bad_is_error(self):
        self.assertTrue(parse_imap(_line("a006 BAD command unknown")).is_error)

    def test_untagged_status_response(self):
        msg = parse_imap(_line("* OK [CAPABILITY IMAP4rev1] ready"))
        self.assertIsInstance(msg, ImapResponse)
        self.assertTrue(msg.is_untagged)
        self.assertEqual(msg.status, "OK")

    def test_untagged_data_response(self):
        msg = parse_imap(_line("* 18 EXISTS"))
        self.assertIsInstance(msg, ImapResponse)
        self.assertTrue(msg.is_untagged)
        self.assertEqual(msg.status, "")
        self.assertEqual(msg.text, "18 EXISTS")

    def test_continuation_request(self):
        msg = parse_imap(_line("+ Ready for additional input"))
        self.assertIsInstance(msg, ImapResponse)
        self.assertTrue(msg.is_continuation)
        self.assertFalse(msg.is_tagged)
        self.assertEqual(msg.text, "Ready for additional input")

    def test_bye_response(self):
        msg = parse_imap(_line("* BYE server shutting down"))
        self.assertTrue(msg.is_bye)


class DisambiguationTests(unittest.TestCase):
    def test_tag_followed_by_status_word_is_response(self):
        msg = parse_imap(_line("a001 OK done"))
        self.assertIsInstance(msg, ImapResponse)

    def test_tag_followed_by_verb_is_command(self):
        msg = parse_imap(_line("a001 LOGIN a b"))
        self.assertIsInstance(msg, ImapCommand)

    def test_untagged_status_word_case_insensitive(self):
        msg = parse_imap(_line("* ok lowercase status"))
        self.assertEqual(msg.status, "OK")


class RobustnessTests(unittest.TestCase):
    def test_lf_only_line_ending(self):
        msg = parse_imap(b"a001 LOGIN alice s3cret\n")
        self.assertEqual(msg.verb, "LOGIN")

    def test_only_first_line_parsed(self):
        msg = parse_imap(_line("a002 SELECT INBOX") + _line("a003 FETCH 1 BODY[]"))
        self.assertEqual(msg.verb, "SELECT")

    def test_offset(self):
        raw = b"\x00\x00" + _line("a003 NOOP")
        msg = parse_imap(raw, offset=2)
        self.assertEqual(msg.verb, "NOOP")

    def test_empty_returns_none(self):
        self.assertIsNone(parse_imap(b""))

    def test_blank_line_returns_none(self):
        self.assertIsNone(parse_imap(b"   \r\n"))

    def test_tag_only_returns_none(self):
        self.assertIsNone(parse_imap(_line("a001")))

    def test_negative_offset_returns_none(self):
        self.assertIsNone(parse_imap(_line("a001 NOOP"), offset=-1))

    def test_ports_constant(self):
        self.assertEqual(IMAP_PORTS, (143, 993))


if __name__ == "__main__":
    unittest.main()
