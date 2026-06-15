"""forensiclab.finger 단위 테스트 (stdlib unittest)."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from forensiclab.finger import (  # noqa: E402
    FINGER_PORTS,
    FingerQuery,
    parse_finger,
)


def _line(text: str) -> bytes:
    """CRLF 종단을 붙여 바이트로(UTF-8)."""
    return (text + "\r\n").encode("utf-8")


class BasicQueryTests(unittest.TestCase):
    def test_simple_username(self):
        q = parse_finger(_line("root"))
        self.assertIsInstance(q, FingerQuery)
        self.assertEqual(q.username, "root")
        self.assertEqual(q.hosts, ())
        self.assertFalse(q.verbose)
        self.assertFalse(q.is_list_all)
        self.assertFalse(q.is_forwarding)
        self.assertIsNone(q.target_host)

    def test_empty_query_is_list_all(self):
        # CRLF 만 — 로그인 전원 목록 질의(유효).
        q = parse_finger(_line(""))
        self.assertIsInstance(q, FingerQuery)
        self.assertIsNone(q.username)
        self.assertTrue(q.is_list_all)
        self.assertEqual(q.hosts, ())

    def test_whitespace_only_is_list_all(self):
        q = parse_finger(_line("   "))
        self.assertTrue(q.is_list_all)


class VerboseTests(unittest.TestCase):
    def test_verbose_switch(self):
        q = parse_finger(_line("/W admin"))
        self.assertTrue(q.verbose)
        self.assertEqual(q.username, "admin")

    def test_verbose_lowercase(self):
        q = parse_finger(_line("/w admin"))
        self.assertTrue(q.verbose)
        self.assertEqual(q.username, "admin")

    def test_verbose_alone_is_list_all(self):
        q = parse_finger(_line("/W"))
        self.assertTrue(q.verbose)
        self.assertTrue(q.is_list_all)

    def test_slash_w_glued_not_switch(self):
        # /Wfoo 는 공백이 없으니 스위치가 아니라 일반 토큰(사용자명).
        q = parse_finger(_line("/Wfoo"))
        self.assertFalse(q.verbose)
        self.assertEqual(q.username, "/Wfoo")


class ForwardingTests(unittest.TestCase):
    def test_user_at_host(self):
        q = parse_finger(_line("user@victim.net"))
        self.assertEqual(q.username, "user")
        self.assertEqual(q.hosts, ("victim.net",))
        self.assertTrue(q.is_forwarding)
        self.assertFalse(q.is_relay_chain)
        self.assertEqual(q.target_host, "victim.net")

    def test_at_host_list_all_forwarded(self):
        # @host — 사용자명 없이 원격 전원 목록 전달.
        q = parse_finger(_line("@internal"))
        self.assertIsNone(q.username)
        self.assertTrue(q.is_list_all)
        self.assertTrue(q.is_forwarding)
        self.assertEqual(q.hosts, ("internal",))

    def test_relay_chain(self):
        q = parse_finger(_line("user@a@b@c"))
        self.assertEqual(q.username, "user")
        self.assertEqual(q.hosts, ("a", "b", "c"))
        self.assertTrue(q.is_relay_chain)
        self.assertEqual(q.target_host, "a")

    def test_verbose_with_forwarding(self):
        q = parse_finger(_line("/W root@gateway"))
        self.assertTrue(q.verbose)
        self.assertEqual(q.username, "root")
        self.assertEqual(q.hosts, ("gateway",))

    def test_empty_host_segments_filtered(self):
        # 망가진 user@@host — 빈 호스트 조각은 버린다.
        q = parse_finger(_line("user@@host"))
        self.assertEqual(q.hosts, ("host",))


class RobustnessTests(unittest.TestCase):
    def test_lf_only_line_ending(self):
        q = parse_finger(b"root\n")
        self.assertEqual(q.username, "root")

    def test_only_first_line_parsed(self):
        q = parse_finger(_line("root") + _line("admin"))
        self.assertEqual(q.username, "root")

    def test_offset(self):
        raw = b"\x00\x00" + _line("root")
        q = parse_finger(raw, offset=2)
        self.assertEqual(q.username, "root")

    def test_empty_bytes_returns_none(self):
        self.assertIsNone(parse_finger(b""))

    def test_negative_offset_returns_none(self):
        self.assertIsNone(parse_finger(_line("root"), offset=-1))

    def test_internal_spaces_take_first_token(self):
        q = parse_finger(_line("root extra junk"))
        self.assertEqual(q.username, "root")

    def test_raw_preserved(self):
        q = parse_finger(_line("/W user@host"))
        self.assertEqual(q.raw, "/W user@host")

    def test_ports_constant(self):
        self.assertIn(79, FINGER_PORTS)


if __name__ == "__main__":
    unittest.main()
