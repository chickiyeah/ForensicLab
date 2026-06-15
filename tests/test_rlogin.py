"""forensiclab.rlogin 단위 테스트 (stdlib unittest)."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from forensiclab.rlogin import (  # noqa: E402
    RLOGIN_PORTS,
    RloginStart,
    parse_rlogin,
)


def _start(client: str, server: str, term: str = "xterm/38400") -> bytes:
    """rlogin 시작 문자열 바이트(선두 NUL + 3개 NUL 종단 필드)."""
    return (
        b"\x00"
        + client.encode() + b"\x00"
        + server.encode() + b"\x00"
        + term.encode() + b"\x00"
    )


class StartRecordTests(unittest.TestCase):
    def test_basic_start(self):
        m = parse_rlogin(_start("alice", "bob"))
        self.assertIsInstance(m, RloginStart)
        self.assertFalse(m.is_server_ack)
        self.assertEqual(m.client_user, "alice")
        self.assertEqual(m.server_user, "bob")
        self.assertEqual(m.terminal_type, "xterm")
        self.assertEqual(m.terminal_speed, 38400)
        self.assertTrue(m.has_attribution)

    def test_same_account_not_cross(self):
        m = parse_rlogin(_start("alice", "alice"))
        self.assertTrue(m.has_attribution)
        self.assertFalse(m.is_cross_account)
        self.assertFalse(m.targets_root)

    def test_cross_account(self):
        m = parse_rlogin(_start("alice", "bob"))
        self.assertTrue(m.is_cross_account)

    def test_targets_root(self):
        m = parse_rlogin(_start("operator", "root"))
        self.assertTrue(m.targets_root)
        self.assertTrue(m.is_cross_account)

    def test_terminal_without_speed(self):
        m = parse_rlogin(_start("alice", "bob", term="vt100"))
        self.assertEqual(m.terminal_type, "vt100")
        self.assertIsNone(m.terminal_speed)

    def test_terminal_nonnumeric_speed(self):
        m = parse_rlogin(_start("alice", "bob", term="xterm/fast"))
        self.assertEqual(m.terminal_type, "xterm")
        self.assertIsNone(m.terminal_speed)


class ServerAckTests(unittest.TestCase):
    def test_single_null_is_ack(self):
        m = parse_rlogin(b"\x00")
        self.assertTrue(m.is_server_ack)
        self.assertIsNone(m.client_user)
        self.assertIsNone(m.server_user)
        self.assertFalse(m.has_attribution)


class PartialTests(unittest.TestCase):
    def test_only_client_user(self):
        m = parse_rlogin(b"\x00alice\x00")
        self.assertEqual(m.client_user, "alice")
        self.assertIsNone(m.server_user)
        self.assertFalse(m.has_attribution)
        self.assertFalse(m.is_cross_account)

    def test_no_terminal(self):
        m = parse_rlogin(b"\x00alice\x00bob\x00")
        self.assertEqual(m.client_user, "alice")
        self.assertEqual(m.server_user, "bob")
        self.assertIsNone(m.terminal_type)
        self.assertTrue(m.has_attribution)


class RobustnessTests(unittest.TestCase):
    def test_no_leading_null_returns_none(self):
        self.assertIsNone(parse_rlogin(b"alice\x00bob\x00"))

    def test_empty_bytes_returns_none(self):
        self.assertIsNone(parse_rlogin(b""))

    def test_negative_offset_returns_none(self):
        self.assertIsNone(parse_rlogin(_start("a", "b"), offset=-1))

    def test_offset_beyond_returns_none(self):
        self.assertIsNone(parse_rlogin(b"\x00", offset=5))

    def test_offset(self):
        raw = b"\xff\xff" + _start("alice", "bob")
        m = parse_rlogin(raw, offset=2)
        self.assertEqual(m.client_user, "alice")
        self.assertEqual(m.server_user, "bob")

    def test_raw_preserved(self):
        data = _start("alice", "bob")
        m = parse_rlogin(data)
        self.assertEqual(m.raw, data)

    def test_ports_constant(self):
        self.assertIn(513, RLOGIN_PORTS)


if __name__ == "__main__":
    unittest.main()
