"""forensiclab.irc 단위 테스트 (stdlib unittest)."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from forensiclab.irc import (  # noqa: E402
    IRC_PORTS,
    IrcMessage,
    IrcPrefix,
    parse_irc,
    parse_prefix,
)


def _line(text: str) -> bytes:
    """CRLF 종단을 붙여 바이트로(UTF-8)."""
    return (text + "\r\n").encode("utf-8")


class PrefixTests(unittest.TestCase):
    def test_full_prefix(self):
        p = parse_prefix("nick!user@host")
        self.assertEqual(p.nick, "nick")
        self.assertEqual(p.user, "user")
        self.assertEqual(p.host, "host")
        self.assertFalse(p.is_server)

    def test_server_prefix(self):
        p = parse_prefix("irc.evil.net")
        self.assertEqual(p.nick, "irc.evil.net")
        self.assertIsNone(p.user)
        self.assertIsNone(p.host)
        self.assertTrue(p.is_server)

    def test_leading_colon_stripped(self):
        p = parse_prefix(":[USA|XP]98213!bot@1.2.3.4")
        self.assertEqual(p.nick, "[USA|XP]98213")
        self.assertEqual(p.user, "bot")
        self.assertEqual(p.host, "1.2.3.4")

    def test_nick_with_host_only(self):
        # @ 만 있고 ! 없는 형태.
        p = parse_prefix("nick@host")
        self.assertEqual(p.nick, "nick")
        self.assertIsNone(p.user)
        self.assertEqual(p.host, "host")

    def test_empty_returns_none(self):
        self.assertIsNone(parse_prefix(""))
        self.assertIsNone(parse_prefix(":"))


class CommandTests(unittest.TestCase):
    def test_simple_command_uppercased(self):
        msg = parse_irc(_line("join #botnet"))
        self.assertIsInstance(msg, IrcMessage)
        self.assertEqual(msg.command, "JOIN")
        self.assertEqual(msg.params, ("#botnet",))
        self.assertIsNone(msg.prefix)

    def test_pass_is_credential(self):
        msg = parse_irc(_line("PASS s3cr3t"))
        self.assertTrue(msg.is_credential)
        self.assertEqual(msg.params, ("s3cr3t",))

    def test_oper_is_credential(self):
        self.assertTrue(parse_irc(_line("OPER root toor")).is_credential)

    def test_registration_commands(self):
        self.assertTrue(parse_irc(_line("NICK [USA|XP]98213")).is_registration)
        self.assertTrue(parse_irc(_line("USER bot 0 0 :infected")).is_registration)
        self.assertFalse(parse_irc(_line("JOIN #x")).is_registration)

    def test_user_command_trailing(self):
        msg = parse_irc(_line("USER bot 0 0 :infected host"))
        self.assertEqual(msg.command, "USER")
        self.assertEqual(msg.params, ("bot", "0", "0", "infected host"))
        self.assertEqual(msg.trailing, "infected host")


class MessageTests(unittest.TestCase):
    def test_privmsg_with_prefix_and_trailing(self):
        msg = parse_irc(
            _line(":[USA|XP]98213!bot@1.2.3.4 PRIVMSG #botnet :.ddos 9.9.9.9 80")
        )
        self.assertEqual(msg.command, "PRIVMSG")
        self.assertTrue(msg.is_message)
        self.assertEqual(msg.target, "#botnet")
        self.assertTrue(msg.is_channel_target)
        self.assertEqual(msg.trailing, ".ddos 9.9.9.9 80")
        self.assertEqual(msg.prefix.nick, "[USA|XP]98213")
        self.assertEqual(msg.prefix.host, "1.2.3.4")

    def test_notice_is_message(self):
        self.assertTrue(parse_irc(_line("NOTICE #c :hi")).is_message)

    def test_target_for_join(self):
        self.assertEqual(parse_irc(_line("JOIN #botnet")).target, "#botnet")

    def test_non_message_no_target(self):
        self.assertIsNone(parse_irc(_line("PING :server")).target)

    def test_privmsg_to_nick_not_channel(self):
        msg = parse_irc(_line("PRIVMSG someone :hello"))
        self.assertEqual(msg.target, "someone")
        self.assertFalse(msg.is_channel_target)

    def test_trailing_preserves_internal_colons(self):
        msg = parse_irc(_line("PRIVMSG #c :time is 12:30:00"))
        self.assertEqual(msg.trailing, "time is 12:30:00")


class NumericTests(unittest.TestCase):
    def test_welcome_numeric(self):
        msg = parse_irc(_line(":irc.evil.net 001 botnick :Welcome"))
        self.assertEqual(msg.command, "001")
        self.assertEqual(msg.numeric, 1)
        self.assertEqual(msg.trailing, "Welcome")
        self.assertTrue(msg.prefix.is_server)

    def test_auth_failure_numerics(self):
        self.assertTrue(parse_irc(_line(":s 464 x :Password incorrect")).is_auth_failure)
        self.assertTrue(parse_irc(_line(":s 465 x :You are banned")).is_auth_failure)
        self.assertTrue(parse_irc(_line(":s 433 * nick :in use")).is_auth_failure)

    def test_non_failure_numeric(self):
        self.assertFalse(parse_irc(_line(":s 001 x :Welcome")).is_auth_failure)

    def test_command_not_numeric(self):
        self.assertIsNone(parse_irc(_line("JOIN #x")).numeric)


class RobustnessTests(unittest.TestCase):
    def test_lf_only_line_ending(self):
        msg = parse_irc(b"NICK bot\n")
        self.assertEqual(msg.command, "NICK")

    def test_only_first_line_parsed(self):
        msg = parse_irc(_line("NICK bot") + _line("USER x"))
        self.assertEqual(msg.command, "NICK")
        self.assertEqual(msg.params, ("bot",))

    def test_offset(self):
        raw = b"\x00\x00" + _line("JOIN #x")
        msg = parse_irc(raw, offset=2)
        self.assertEqual(msg.command, "JOIN")

    def test_empty_returns_none(self):
        self.assertIsNone(parse_irc(b""))

    def test_blank_line_returns_none(self):
        self.assertIsNone(parse_irc(b"   \r\n"))

    def test_negative_offset_returns_none(self):
        self.assertIsNone(parse_irc(_line("NICK bot"), offset=-1))

    def test_prefix_only_no_command_returns_none(self):
        self.assertIsNone(parse_irc(_line(":irc.evil.net")))

    def test_prefix_with_trailing_space_no_command(self):
        self.assertIsNone(parse_irc(_line(":irc.evil.net ")))

    def test_ports_constant(self):
        self.assertIn(6667, IRC_PORTS)
        self.assertIn(6697, IRC_PORTS)


if __name__ == "__main__":
    unittest.main()
