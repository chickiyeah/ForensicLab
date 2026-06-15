"""forensiclab.ssh 단위 테스트 (stdlib unittest)."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from forensiclab.ssh import (  # noqa: E402
    SshBanner,
    parse_banner,
)


class ParseBannerTest(unittest.TestCase):
    def test_full_banner_with_comments(self):
        data = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n"
        b = parse_banner(data)
        self.assertIsInstance(b, SshBanner)
        self.assertEqual(b.protoversion, "2.0")
        self.assertEqual(b.software, "OpenSSH_8.9p1")
        self.assertEqual(b.comments, "Ubuntu-3ubuntu0.1")
        self.assertEqual(b.raw, "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1")

    def test_banner_without_comments(self):
        b = parse_banner(b"SSH-2.0-OpenSSH_9.6\r\n")
        self.assertEqual(b.protoversion, "2.0")
        self.assertEqual(b.software, "OpenSSH_9.6")
        self.assertEqual(b.comments, "")

    def test_lf_only_terminator(self):
        # 일부 구현은 CR 없이 LF 만 보낸다 — 둘 다 허용.
        b = parse_banner(b"SSH-2.0-paramiko_3.4.0\n")
        self.assertEqual(b.software, "paramiko_3.4.0")
        self.assertEqual(b.raw, "SSH-2.0-paramiko_3.4.0")

    def test_no_terminator_still_parses(self):
        b = parse_banner(b"SSH-2.0-libssh_0.10.6")
        self.assertEqual(b.protoversion, "2.0")
        self.assertEqual(b.software, "libssh_0.10.6")

    def test_protoversion_1_99(self):
        b = parse_banner(b"SSH-1.99-OpenSSH_3.9p1\r\n")
        self.assertEqual(b.protoversion, "1.99")
        self.assertEqual(b.software, "OpenSSH_3.9p1")

    def test_comments_may_contain_spaces(self):
        b = parse_banner(b"SSH-2.0-MyServer some comment here\r\n")
        self.assertEqual(b.software, "MyServer")
        self.assertEqual(b.comments, "some comment here")

    def test_skips_pre_banner_lines(self):
        # 서버는 SSH- 줄 앞에 안내 줄을 보낼 수 있다(RFC 4253 §4.2).
        data = b"Welcome to host\r\nAuthorized use only\r\nSSH-2.0-OpenSSH_8.9\r\n"
        b = parse_banner(data)
        self.assertIsNotNone(b)
        self.assertEqual(b.software, "OpenSSH_8.9")

    def test_non_ssh_returns_none(self):
        self.assertIsNone(parse_banner(b"GET / HTTP/1.1\r\n\r\n"))
        self.assertIsNone(parse_banner(b"220 vsftpd ready\r\n"))

    def test_empty_returns_none(self):
        self.assertIsNone(parse_banner(b""))

    def test_missing_software_dash_returns_none(self):
        # protoversion 과 softwareversion 구분자(-) 가 없으면 무효.
        self.assertIsNone(parse_banner(b"SSH-2.0\r\n"))

    def test_empty_protoversion_returns_none(self):
        self.assertIsNone(parse_banner(b"SSH--OpenSSH_8.9\r\n"))

    def test_does_not_mutate_input(self):
        data = bytearray(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu\r\n")
        snapshot = bytes(data)
        parse_banner(bytes(data))
        self.assertEqual(bytes(data), snapshot)


if __name__ == "__main__":
    unittest.main()
