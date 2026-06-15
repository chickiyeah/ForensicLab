"""forensiclab.rcmd 단위 테스트 (stdlib unittest)."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from forensiclab.rcmd import (  # noqa: E402
    RCMD_PORTS,
    REXEC_PORTS,
    RSH_PORTS,
    RcmdRequest,
    RcmdResponse,
    parse_rcmd,
    parse_rcmd_response,
)


def _rsh(local: str, remote: str, cmd: str, port: str = "0") -> bytes:
    """rsh 요청 바이트: stderr-port NUL local NUL remote NUL command NUL."""
    return (
        port.encode() + b"\x00"
        + local.encode() + b"\x00"
        + remote.encode() + b"\x00"
        + cmd.encode() + b"\x00"
    )


def _rexec(remote: str, password: str, cmd: str, port: str = "0") -> bytes:
    """rexec 요청 바이트: stderr-port NUL remote NUL password NUL command NUL."""
    return (
        port.encode() + b"\x00"
        + remote.encode() + b"\x00"
        + password.encode() + b"\x00"
        + cmd.encode() + b"\x00"
    )


class RshTests(unittest.TestCase):
    def test_basic_rsh(self):
        m = parse_rcmd(_rsh("alice", "bob", "uname -a"), service="rsh")
        self.assertIsInstance(m, RcmdRequest)
        self.assertEqual(m.service, "rsh")
        self.assertEqual(m.stderr_port, 0)
        self.assertEqual(m.client_user, "alice")
        self.assertEqual(m.server_user, "bob")
        self.assertIsNone(m.password)
        self.assertEqual(m.command, "uname -a")
        self.assertTrue(m.has_command)
        self.assertFalse(m.has_cleartext_password)
        self.assertTrue(m.has_attribution)
        self.assertTrue(m.is_cross_account)

    def test_same_account_not_cross(self):
        m = parse_rcmd(_rsh("alice", "alice", "id"), service="rsh")
        self.assertTrue(m.has_attribution)
        self.assertFalse(m.is_cross_account)
        self.assertFalse(m.targets_root)

    def test_targets_root(self):
        m = parse_rcmd(_rsh("operator", "root", "cat /etc/shadow"), service="rsh")
        self.assertTrue(m.targets_root)
        self.assertTrue(m.is_cross_account)

    def test_shell_alias(self):
        m = parse_rcmd(_rsh("a", "b", "ls"), service="shell")
        self.assertEqual(m.service, "rsh")

    def test_separate_stderr_port(self):
        m = parse_rcmd(_rsh("a", "b", "ls", port="1023"), service="rsh")
        self.assertEqual(m.stderr_port, 1023)
        self.assertTrue(m.has_separate_stderr)

    def test_no_separate_stderr(self):
        m = parse_rcmd(_rsh("a", "b", "ls"), service="rsh")
        self.assertFalse(m.has_separate_stderr)


class RexecTests(unittest.TestCase):
    def test_basic_rexec(self):
        m = parse_rcmd(_rexec("bob", "s3cret", "whoami"), service="rexec")
        self.assertEqual(m.service, "rexec")
        self.assertIsNone(m.client_user)
        self.assertEqual(m.server_user, "bob")
        self.assertEqual(m.password, "s3cret")
        self.assertEqual(m.command, "whoami")
        self.assertTrue(m.has_cleartext_password)
        self.assertTrue(m.has_command)

    def test_exec_alias(self):
        m = parse_rcmd(_rexec("bob", "pw", "id"), service="exec")
        self.assertEqual(m.service, "rexec")

    def test_rexec_no_dual_attribution(self):
        # rexec 에는 로컬 계정 필드가 없어 이중 귀속/계정 교차 개념 없음.
        m = parse_rcmd(_rexec("bob", "pw", "id"), service="rexec")
        self.assertFalse(m.has_attribution)
        self.assertFalse(m.is_cross_account)

    def test_rexec_targets_root(self):
        m = parse_rcmd(_rexec("root", "toor", "id"), service="rexec")
        self.assertTrue(m.targets_root)


class ResponseTests(unittest.TestCase):
    def test_success_ack(self):
        r = parse_rcmd_response(b"\x00")
        self.assertIsInstance(r, RcmdResponse)
        self.assertTrue(r.is_success)
        self.assertFalse(r.is_error)
        self.assertIsNone(r.error_message)

    def test_error_with_message(self):
        r = parse_rcmd_response(b"\x01Permission denied.\n")
        self.assertTrue(r.is_error)
        self.assertFalse(r.is_success)
        self.assertEqual(r.error_message, "Permission denied.")

    def test_error_without_message(self):
        r = parse_rcmd_response(b"\x01")
        self.assertTrue(r.is_error)
        self.assertIsNone(r.error_message)

    def test_unknown_first_byte(self):
        r = parse_rcmd_response(b"Xfoo")
        self.assertFalse(r.is_success)
        self.assertFalse(r.is_error)


class PartialTests(unittest.TestCase):
    def test_only_port_and_user(self):
        m = parse_rcmd(b"0\x00alice\x00", service="rsh")
        self.assertEqual(m.stderr_port, 0)
        self.assertEqual(m.client_user, "alice")
        self.assertIsNone(m.server_user)
        self.assertIsNone(m.command)
        self.assertFalse(m.has_attribution)

    def test_nonnumeric_port(self):
        m = parse_rcmd(b"abc\x00alice\x00bob\x00ls\x00", service="rsh")
        self.assertIsNone(m.stderr_port)
        self.assertEqual(m.client_user, "alice")


class RobustnessTests(unittest.TestCase):
    def test_empty_bytes_returns_none(self):
        self.assertIsNone(parse_rcmd(b"", service="rsh"))

    def test_unknown_service_returns_none(self):
        self.assertIsNone(parse_rcmd(_rsh("a", "b", "ls"), service="bogus"))

    def test_negative_offset_returns_none(self):
        self.assertIsNone(parse_rcmd(_rsh("a", "b", "ls"), offset=-1))

    def test_offset_beyond_returns_none(self):
        self.assertIsNone(parse_rcmd(b"0\x00", offset=5))

    def test_offset(self):
        raw = b"\xff\xff" + _rsh("alice", "bob", "ls")
        m = parse_rcmd(raw, service="rsh", offset=2)
        self.assertEqual(m.client_user, "alice")
        self.assertEqual(m.server_user, "bob")

    def test_raw_preserved(self):
        data = _rsh("alice", "bob", "ls")
        m = parse_rcmd(data, service="rsh")
        self.assertEqual(m.raw, data)

    def test_response_empty_returns_none(self):
        self.assertIsNone(parse_rcmd_response(b""))

    def test_ports_constants(self):
        self.assertIn(514, RSH_PORTS)
        self.assertIn(512, REXEC_PORTS)
        self.assertEqual(set(RCMD_PORTS), {512, 514})


if __name__ == "__main__":
    unittest.main()
