"""forensiclab.telnet 단위 테스트 (stdlib unittest)."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from forensiclab.telnet import (  # noqa: E402
    DO,
    DONT,
    IAC,
    IP,
    SB,
    SE,
    TELNET_PORTS,
    WILL,
    WONT,
    TelnetCommand,
    TelnetStream,
    decode_environ,
    decode_terminal_type,
    parse_telnet,
)


def _b(*vals) -> bytes:
    """정수/바이트열을 이어붙여 바이트로."""
    out = bytearray()
    for v in vals:
        if isinstance(v, int):
            out.append(v)
        elif isinstance(v, (bytes, bytearray)):
            out.extend(v)
        elif isinstance(v, str):
            out.extend(v.encode("ascii"))
        else:
            raise TypeError(type(v))
    return bytes(out)


class DataSeparationTests(unittest.TestCase):
    def test_plain_data_no_commands(self):
        s = parse_telnet(b"login: alice\r\n")
        self.assertIsInstance(s, TelnetStream)
        self.assertEqual(s.data, b"login: alice\r\n")
        self.assertEqual(s.commands, ())
        self.assertTrue(s.has_data)

    def test_data_around_negotiation(self):
        # "ab" + IAC DO ECHO + "cd"
        s = parse_telnet(_b("ab", IAC, DO, 1, "cd"))
        self.assertEqual(s.data, b"abcd")
        self.assertEqual(len(s.commands), 1)
        self.assertEqual(s.commands[0].command_name, "DO")
        self.assertEqual(s.commands[0].option, 1)
        self.assertEqual(s.commands[0].option_name, "ECHO")

    def test_iac_iac_is_literal_ff(self):
        s = parse_telnet(_b("x", IAC, IAC, "y"))
        self.assertEqual(s.data, b"x\xffy")
        self.assertEqual(s.commands, ())

    def test_text_helper(self):
        s = parse_telnet(b"Password: s3cret\r\n")
        self.assertEqual(s.text().strip(), "Password: s3cret")


class NegotiationTests(unittest.TestCase):
    def test_all_negotiate_verbs(self):
        s = parse_telnet(_b(IAC, WILL, 3, IAC, WONT, 1, IAC, DO, 24, IAC, DONT, 31))
        names = [c.command_name for c in s.negotiations]
        self.assertEqual(names, ["WILL", "WONT", "DO", "DONT"])
        self.assertEqual(s.negotiations[0].option_name, "SUPPRESS-GO-AHEAD")
        self.assertEqual(s.negotiations[2].option_name, "TERMINAL-TYPE")
        self.assertTrue(all(c.is_negotiation for c in s.negotiations))

    def test_unknown_option_name(self):
        s = parse_telnet(_b(IAC, WILL, 200))
        self.assertEqual(s.negotiations[0].option, 200)
        self.assertEqual(s.negotiations[0].option_name, "OPT_200")

    def test_simple_command(self):
        s = parse_telnet(_b("a", IAC, IP, "b"))
        self.assertEqual(s.data, b"ab")
        self.assertEqual(len(s.commands), 1)
        cmd = s.commands[0]
        self.assertEqual(cmd.command_name, "IP")
        self.assertEqual(cmd.kind, "command")
        self.assertIsNone(cmd.option)
        self.assertFalse(cmd.is_negotiation)


class SubnegotiationTests(unittest.TestCase):
    def test_terminal_type_subneg(self):
        # IAC SB TERMINAL-TYPE IS "xterm" IAC SE
        s = parse_telnet(_b(IAC, SB, 24, 0, "xterm", IAC, SE))
        self.assertEqual(len(s.subnegotiations), 1)
        sub = s.subnegotiations[0]
        self.assertTrue(sub.is_subnegotiation)
        self.assertEqual(sub.option_name, "TERMINAL-TYPE")
        self.assertEqual(decode_terminal_type(sub), "xterm")

    def test_terminal_type_wrong_option(self):
        s = parse_telnet(_b(IAC, SB, 31, 0, 80, 0, 24, IAC, SE))  # NAWS
        self.assertIsNone(decode_terminal_type(s.subnegotiations[0]))

    def test_subneg_iac_iac_in_payload(self):
        # 페이로드 안의 리터럴 0xFF (IAC IAC) 는 단일 0xFF 로 환원.
        s = parse_telnet(_b(IAC, SB, 0, 0x01, IAC, IAC, 0x02, IAC, SE))
        self.assertEqual(s.subnegotiations[0].data, b"\x01\xff\x02")

    def test_new_environ_subneg(self):
        # IAC SB NEW-ENVIRON IS VAR "USER" VALUE "alice" IAC SE
        s = parse_telnet(_b(IAC, SB, 39, 0, 0, "USER", 1, "alice", IAC, SE))
        pairs = decode_environ(s.subnegotiations[0])
        self.assertEqual(pairs, [("USER", "alice")])

    def test_new_environ_multiple(self):
        s = parse_telnet(
            _b(IAC, SB, 39, 0, 0, "USER", 1, "bob", 0, "TERM", 1, "vt100", IAC, SE)
        )
        pairs = decode_environ(s.subnegotiations[0])
        self.assertEqual(pairs, [("USER", "bob"), ("TERM", "vt100")])

    def test_new_environ_value_none_for_send(self):
        # VAR "USER" 만 있고 VALUE 없음(SEND 요청 형태).
        s = parse_telnet(_b(IAC, SB, 39, 1, 0, "USER", IAC, SE))
        pairs = decode_environ(s.subnegotiations[0])
        self.assertEqual(pairs, [("USER", None)])

    def test_decode_environ_wrong_option(self):
        s = parse_telnet(_b(IAC, SB, 24, 0, "xterm", IAC, SE))
        self.assertIsNone(decode_environ(s.subnegotiations[0]))


class RobustnessTests(unittest.TestCase):
    def test_empty_input_none(self):
        self.assertIsNone(parse_telnet(b""))

    def test_bad_offset_none(self):
        self.assertIsNone(parse_telnet(b"abc", offset=99))
        self.assertIsNone(parse_telnet(b"abc", offset=-1))

    def test_offset_applied(self):
        s = parse_telnet(b"\x00\x00login", offset=2)
        self.assertEqual(s.data, b"login")

    def test_dangling_iac_dropped(self):
        s = parse_telnet(_b("data", IAC))
        self.assertEqual(s.data, b"data")
        self.assertEqual(s.commands, ())

    def test_incomplete_negotiation_dropped(self):
        # IAC DO 뒤 옵션 바이트가 잘림.
        s = parse_telnet(_b("hi", IAC, DO))
        self.assertEqual(s.data, b"hi")
        self.assertEqual(s.commands, ())

    def test_unterminated_subneg_dropped(self):
        # IAC SB … 에 종단 IAC SE 가 없음.
        s = parse_telnet(_b("hi", IAC, SB, 24, 0, "xterm"))
        self.assertEqual(s.data, b"hi")
        self.assertEqual(s.subnegotiations, ())

    def test_has_data_false_for_negotiation_only(self):
        s = parse_telnet(_b(IAC, WILL, 1))
        self.assertFalse(s.has_data)
        self.assertEqual(s.data, b"")


class ConstantsTests(unittest.TestCase):
    def test_ports_and_iac(self):
        self.assertEqual(TELNET_PORTS, (23,))
        self.assertEqual(IAC, 0xFF)

    def test_command_dataclass_frozen(self):
        c = TelnetCommand(kind="command", command=IP, command_name="IP")
        with self.assertRaises(Exception):
            c.command = 0  # type: ignore[misc]


if __name__ == "__main__":
    unittest.main()
