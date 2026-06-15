"""forensiclab.mysql 단위 테스트 (stdlib unittest)."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from forensiclab.mysql import (  # noqa: E402
    CLIENT_PLUGIN_AUTH,
    CLIENT_PROTOCOL_41,
    CLIENT_SECURE_CONNECTION,
    CLIENT_SSL,
    MysqlHandshake,
    parse_mysql_handshake,
)


def _build_greeting(
    server_version=b"8.0.32",
    thread_id=12345,
    capabilities=(
        CLIENT_PROTOCOL_41 | CLIENT_SSL | CLIENT_SECURE_CONNECTION | CLIENT_PLUGIN_AUTH
    ),
    charset=255,
    status_flags=0x0002,
    auth_plugin_name=b"caching_sha2_password",
    with_header=True,
):
    """완전한 HandshakeV10 페이로드(옵션으로 4바이트 패킷 헤더 포함)를 만든다."""
    body = bytearray()
    body.append(0x0A)  # protocol_version 10
    body += server_version + b"\x00"
    body += thread_id.to_bytes(4, "little")
    body += b"\x11\x22\x33\x44\x55\x66\x77\x88"  # auth-plugin-data-part-1 (8)
    body.append(0x00)  # filler
    body += (capabilities & 0xFFFF).to_bytes(2, "little")  # cap_lo
    body.append(charset)
    body += status_flags.to_bytes(2, "little")
    body += ((capabilities >> 16) & 0xFFFF).to_bytes(2, "little")  # cap_hi
    apd2 = b"\xaa" * 12 + b"\x00"  # 13바이트 part2
    apd_len = 8 + len(apd2) if (capabilities & CLIENT_PLUGIN_AUTH) else 0
    body.append(apd_len)
    body += b"\x00" * 10  # reserved
    if capabilities & CLIENT_SECURE_CONNECTION:
        body += apd2
    if capabilities & CLIENT_PLUGIN_AUTH:
        body += auth_plugin_name + b"\x00"
    if not with_header:
        return bytes(body)
    header = len(body).to_bytes(3, "little") + b"\x00"  # seq_id 0
    return header + bytes(body)


class ParseMysqlHandshakeTest(unittest.TestCase):
    def test_full_greeting_with_header(self):
        h = parse_mysql_handshake(_build_greeting())
        self.assertIsInstance(h, MysqlHandshake)
        self.assertTrue(h.has_packet_header)
        self.assertEqual(h.protocol_version, 10)
        self.assertEqual(h.server_version, "8.0.32")
        self.assertEqual(h.thread_id, 12345)
        self.assertEqual(h.charset, 255)
        self.assertEqual(h.auth_plugin_name, "caching_sha2_password")
        self.assertTrue(h.supports_ssl)
        self.assertTrue(h.supports_plugin_auth)
        self.assertTrue(h.protocol_41)
        self.assertFalse(h.is_weak_auth_plugin)
        self.assertFalse(h.is_mariadb)

    def test_greeting_without_packet_header(self):
        h = parse_mysql_handshake(_build_greeting(with_header=False))
        self.assertFalse(h.has_packet_header)
        self.assertEqual(h.server_version, "8.0.32")
        self.assertEqual(h.thread_id, 12345)

    def test_no_ssl_flag(self):
        caps = CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONNECTION | CLIENT_PLUGIN_AUTH
        h = parse_mysql_handshake(_build_greeting(capabilities=caps))
        self.assertFalse(h.supports_ssl)
        self.assertTrue(h.supports_plugin_auth)

    def test_weak_clear_password_plugin(self):
        h = parse_mysql_handshake(
            _build_greeting(auth_plugin_name=b"mysql_clear_password")
        )
        self.assertEqual(h.auth_plugin_name, "mysql_clear_password")
        self.assertTrue(h.is_weak_auth_plugin)

    def test_weak_old_password_plugin(self):
        h = parse_mysql_handshake(
            _build_greeting(auth_plugin_name=b"mysql_old_password")
        )
        self.assertTrue(h.is_weak_auth_plugin)

    def test_native_password_not_flagged_weak(self):
        # native_password 는 deprecated 이지만 WEAK 집합엔 없음(docstring 참조).
        h = parse_mysql_handshake(
            _build_greeting(auth_plugin_name=b"mysql_native_password")
        )
        self.assertFalse(h.is_weak_auth_plugin)

    def test_mariadb_fingerprint_string(self):
        h = parse_mysql_handshake(
            _build_greeting(server_version=b"5.5.5-10.5.8-MariaDB-1:10.5.8+maria")
        )
        self.assertTrue(h.is_mariadb)

    def test_combined_capabilities_high_bits(self):
        # cap_hi 의 CLIENT_PLUGIN_AUTH 비트(0x80000)가 결합돼야 보인다.
        h = parse_mysql_handshake(_build_greeting())
        self.assertEqual(h.capabilities & CLIENT_PLUGIN_AUTH, CLIENT_PLUGIN_AUTH)
        self.assertEqual(h.capabilities & CLIENT_SSL, CLIENT_SSL)

    def test_offset(self):
        data = b"\x00\x00" + _build_greeting()
        h = parse_mysql_handshake(data, offset=2)
        self.assertEqual(h.server_version, "8.0.32")

    def test_truncated_after_version_returns_none(self):
        # thread_id(4바이트)가 모자라면 None.
        self.assertIsNone(parse_mysql_handshake(b"\x0a8.0.32\x00\x01\x02"))

    def test_truncated_before_capabilities_degrades(self):
        # version+thread_id 까지만 있고 확장부가 없으면 거기까지만 채운다.
        data = b"\x0a8.0.32\x00" + (99).to_bytes(4, "little")
        h = parse_mysql_handshake(data)
        self.assertEqual(h.thread_id, 99)
        self.assertIsNone(h.capabilities)
        self.assertIsNone(h.charset)
        self.assertIsNone(h.auth_plugin_name)
        self.assertFalse(h.supports_ssl)
        self.assertFalse(h.is_weak_auth_plugin)

    def test_not_mysql_returns_none(self):
        self.assertIsNone(parse_mysql_handshake(b"SSH-2.0-OpenSSH_9.6\r\n"))

    def test_no_version_nul_returns_none(self):
        self.assertIsNone(parse_mysql_handshake(b"\x0a8.0.32nonull"))

    def test_empty_version_returns_none(self):
        self.assertIsNone(parse_mysql_handshake(b"\x0a\x00\x01\x02\x03\x04"))

    def test_empty_returns_none(self):
        self.assertIsNone(parse_mysql_handshake(b""))

    def test_negative_offset_returns_none(self):
        self.assertIsNone(parse_mysql_handshake(_build_greeting(), offset=-1))

    def test_offset_past_end_returns_none(self):
        self.assertIsNone(parse_mysql_handshake(b"\x0a", offset=10))

    def test_input_not_mutated(self):
        data = _build_greeting()
        snapshot = bytes(data)
        parse_mysql_handshake(data)
        self.assertEqual(data, snapshot)


if __name__ == "__main__":
    unittest.main()
