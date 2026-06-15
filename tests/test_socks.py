"""forensiclab.socks 단위 테스트 (stdlib unittest)."""

import os
import socket
import struct
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from forensiclab.socks import (  # noqa: E402
    SocksMessage,
    looks_like_socks,
    parse_socks,
)


def _socks4(cd, ip, port, userid=b"root", trailer=b""):
    return (
        bytes([4, cd])
        + struct.pack(">H", port)
        + ip
        + userid
        + b"\x00"
        + trailer
    )


def _socks5_greeting(methods):
    return bytes([5, len(methods)]) + bytes(methods)


def _socks5_req_ipv4(cmd, ip, port):
    return bytes([5, cmd, 0, 1]) + ip + struct.pack(">H", port)


def _socks5_req_domain(cmd, domain, port):
    d = domain.encode("ascii")
    return bytes([5, cmd, 0, 3, len(d)]) + d + struct.pack(">H", port)


def _socks5_req_ipv6(cmd, raw16, port):
    return bytes([5, cmd, 0, 4]) + raw16 + struct.pack(">H", port)


class GuardTests(unittest.TestCase):
    def test_non_bytes(self):
        self.assertIsNone(parse_socks(None))
        self.assertIsNone(parse_socks(123))

    def test_too_short(self):
        self.assertIsNone(parse_socks(b"\x05"))
        self.assertIsNone(parse_socks(b""))

    def test_unknown_version(self):
        self.assertIsNone(parse_socks(b"\x09\x01\x00\x01"))

    def test_socks4_bad_command(self):
        # CD=9 는 SOCKS4 명령 아님.
        self.assertIsNone(parse_socks(_socks4(9, b"\x01\x02\x03\x04", 80)))

    def test_looks_like_socks(self):
        self.assertTrue(looks_like_socks(_socks5_greeting([0])))
        self.assertFalse(looks_like_socks(b"\xff\xff"))


class Socks4Tests(unittest.TestCase):
    def test_connect_request(self):
        ip = socket.inet_aton("93.184.216.34")
        pkt = parse_socks(_socks4(1, ip, 443, userid=b"alice"))
        self.assertIsInstance(pkt, SocksMessage)
        self.assertEqual(pkt.version, 4)
        self.assertTrue(pkt.is_request)
        self.assertTrue(pkt.is_connect)
        self.assertEqual(pkt.dst_host, "93.184.216.34")
        self.assertEqual(pkt.dst_port, 443)
        self.assertEqual(pkt.userid, "alice")
        self.assertFalse(pkt.is_socks4a)
        self.assertEqual(pkt.target, "93.184.216.34:443")

    def test_bind_command(self):
        pkt = parse_socks(_socks4(2, b"\x0a\x00\x00\x01", 21))
        self.assertTrue(pkt.is_bind)

    def test_socks4a_domain(self):
        # DSTIP=0.0.0.x → 도메인이 USERID NUL 다음에 동봉(SOCKS4a).
        pkt = parse_socks(
            _socks4(1, b"\x00\x00\x00\x07", 8080, userid=b"u", trailer=b"evil.example.com\x00")
        )
        self.assertTrue(pkt.is_socks4a)
        self.assertTrue(pkt.is_hostname_target)
        self.assertEqual(pkt.dst_host, "evil.example.com")
        self.assertEqual(pkt.address_type, "domain")

    def test_socks4_reply(self):
        reply = bytes([0, 90]) + struct.pack(">H", 443) + b"\x00\x00\x00\x00"
        pkt = parse_socks(reply)
        self.assertEqual(pkt.kind, "reply")
        self.assertEqual(pkt.reply_status, "GRANTED")
        self.assertEqual(pkt.reply_code, 90)

    def test_socks4_reply_rejected(self):
        reply = bytes([0, 91]) + struct.pack(">H", 0) + b"\x00\x00\x00\x00"
        self.assertEqual(parse_socks(reply).reply_status, "REJECTED")

    def test_truncated_userid(self):
        # USERID 에 NUL 이 없으면 받은 데까지.
        pkt = parse_socks(bytes([4, 1]) + struct.pack(">H", 80) + b"\x01\x02\x03\x04" + b"bob")
        self.assertEqual(pkt.userid, "bob")


class Socks5GreetingTests(unittest.TestCase):
    def test_no_auth_greeting(self):
        pkt = parse_socks(_socks5_greeting([0]))
        self.assertTrue(pkt.is_greeting)
        self.assertTrue(pkt.offers_no_auth)
        self.assertEqual(pkt.auth_methods, ["NO_AUTH"])

    def test_userpass_greeting(self):
        pkt = parse_socks(_socks5_greeting([0, 2]))
        self.assertTrue(pkt.offers_no_auth)
        self.assertTrue(pkt.offers_userpass)
        self.assertEqual(pkt.auth_methods, ["NO_AUTH", "USERNAME_PASSWORD"])

    def test_unknown_method_hex(self):
        pkt = parse_socks(_socks5_greeting([0x80]))
        self.assertEqual(pkt.auth_methods, ["0x80"])

    def test_zero_methods_rejected(self):
        self.assertIsNone(parse_socks(bytes([5, 0])))

    def test_truncated_methods(self):
        # NMETHODS=3 인데 1개만 — 가용분까지.
        pkt = parse_socks(bytes([5, 3, 0]))
        self.assertEqual(pkt.auth_method_codes, [0])


class Socks5RequestTests(unittest.TestCase):
    def test_connect_ipv4(self):
        ip = socket.inet_aton("10.1.2.3")
        pkt = parse_socks(_socks5_req_ipv4(1, ip, 22))
        self.assertTrue(pkt.is_request)
        self.assertEqual(pkt.version, 5)
        self.assertTrue(pkt.is_connect)
        self.assertEqual(pkt.dst_host, "10.1.2.3")
        self.assertEqual(pkt.dst_port, 22)
        self.assertEqual(pkt.address_type, "ipv4")

    def test_connect_domain(self):
        pkt = parse_socks(_socks5_req_domain(1, "c2.evil.net", 443))
        self.assertTrue(pkt.is_hostname_target)
        self.assertEqual(pkt.dst_host, "c2.evil.net")
        self.assertEqual(pkt.dst_port, 443)
        self.assertEqual(pkt.target, "c2.evil.net:443")

    def test_connect_ipv6(self):
        raw = socket.inet_pton(socket.AF_INET6, "2001:db8::1")
        pkt = parse_socks(_socks5_req_ipv6(1, raw, 8443))
        self.assertEqual(pkt.address_type, "ipv6")
        self.assertEqual(pkt.dst_host, "2001:db8::1")
        self.assertEqual(pkt.target, "[2001:db8::1]:8443")

    def test_udp_associate(self):
        pkt = parse_socks(_socks5_req_ipv4(3, b"\x00\x00\x00\x00", 0))
        self.assertTrue(pkt.is_udp_associate)

    def test_greeting_not_misread_as_request(self):
        # 05 03 00 01 02 — 요청 구조처럼 보이나 짧아(5<10) 그리팅으로.
        pkt = parse_socks(bytes([5, 3, 0, 1, 2]))
        self.assertTrue(pkt.is_greeting)
        self.assertEqual(pkt.auth_method_codes, [0, 1, 2])

    def test_request_with_offset(self):
        pre = b"\xde\xad"
        pkt = parse_socks(pre + _socks5_req_domain(1, "x.io", 80), offset=2)
        self.assertEqual(pkt.dst_host, "x.io")


if __name__ == "__main__":
    unittest.main()
