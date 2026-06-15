"""forensiclab.tls 단위 테스트 (stdlib unittest)."""

import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from forensiclab.tls import (  # noqa: E402
    ClientHello,
    ContentType,
    ExtensionType,
    HandshakeType,
    parse_client_hello,
)


def _sni_ext(host: bytes) -> bytes:
    """SNI 확장 한 개를 만든다(type 0x0000)."""
    entry = struct.pack(">BH", 0x00, len(host)) + host  # name_type + len + name
    server_name_list = struct.pack(">H", len(entry)) + entry
    return struct.pack(">HH", ExtensionType.SERVER_NAME, len(server_name_list)) \
        + server_name_list


def _alpn_ext(protos) -> bytes:
    """ALPN 확장 한 개를 만든다(type 0x0010)."""
    body = b"".join(struct.pack(">B", len(p)) + p for p in protos)
    proto_list = struct.pack(">H", len(body)) + body
    return struct.pack(">HH", ExtensionType.ALPN, len(proto_list)) + proto_list


def _client_hello(
    cipher_suites=(0x1301, 0x1302),
    extensions=b"",
    version=0x0303,
    include_ext_block=True,
):
    """ClientHello 를 담은 완전한 TLS handshake record 바이트를 만든다."""
    cs = b"".join(struct.pack(">H", c) for c in cipher_suites)
    body = struct.pack(">H", version)  # client_version
    body += b"\x00" * 32  # random
    body += b"\x00"  # session_id length = 0
    body += struct.pack(">H", len(cs)) + cs  # cipher_suites
    body += b"\x01\x00"  # compression_methods: len=1, null
    if include_ext_block:
        body += struct.pack(">H", len(extensions)) + extensions

    handshake = struct.pack(">B", HandshakeType.CLIENT_HELLO)
    handshake += struct.pack(">I", len(body))[1:]  # 3바이트 길이
    handshake += body

    record = struct.pack(">B", ContentType.HANDSHAKE)
    record += b"\x03\x01"  # record version (TLS 1.0, 흔한 값)
    record += struct.pack(">H", len(handshake))
    record += handshake
    return record


class ParseBasicTest(unittest.TestCase):
    def test_minimal_no_extensions(self):
        hello = parse_client_hello(_client_hello())
        self.assertIsInstance(hello, ClientHello)
        self.assertEqual(hello.legacy_version, 0x0303)
        self.assertEqual(hello.legacy_version_str, "TLS 1.2")
        self.assertEqual(hello.cipher_suites, [0x1301, 0x1302])
        self.assertIsNone(hello.server_name)
        self.assertEqual(hello.alpn, [])
        self.assertEqual(hello.extensions, [])

    def test_legacy_without_extension_block(self):
        # 확장 섹션 자체가 없는 구형 ClientHello.
        hello = parse_client_hello(_client_hello(include_ext_block=False))
        self.assertIsInstance(hello, ClientHello)
        self.assertIsNone(hello.server_name)


class SniTest(unittest.TestCase):
    def test_extracts_sni(self):
        data = _client_hello(extensions=_sni_ext(b"c2.evil.example"))
        hello = parse_client_hello(data)
        self.assertEqual(hello.server_name, "c2.evil.example")
        self.assertIn(ExtensionType.SERVER_NAME, hello.extensions)

    def test_sni_and_alpn_together(self):
        ext = _sni_ext(b"cdn.example.com") + _alpn_ext([b"h2", b"http/1.1"])
        hello = parse_client_hello(_client_hello(extensions=ext))
        self.assertEqual(hello.server_name, "cdn.example.com")
        self.assertEqual(hello.alpn, ["h2", "http/1.1"])
        self.assertEqual(
            hello.extensions, [ExtensionType.SERVER_NAME, ExtensionType.ALPN]
        )

    def test_unknown_extension_collected_by_type(self):
        # type 0x002b(supported_versions) 더미 — 의미 해석 없이 type 만 수집.
        unknown = struct.pack(">HH", 0x002B, 1) + b"\x00"
        hello = parse_client_hello(_client_hello(extensions=unknown))
        self.assertEqual(hello.extensions, [0x002B])
        self.assertIsNone(hello.server_name)


class RobustnessTest(unittest.TestCase):
    def test_empty_returns_none(self):
        self.assertIsNone(parse_client_hello(b""))

    def test_non_handshake_record_returns_none(self):
        data = bytearray(_client_hello())
        data[0] = ContentType.APPLICATION_DATA
        self.assertIsNone(parse_client_hello(bytes(data)))

    def test_server_hello_returns_none(self):
        data = bytearray(_client_hello())
        data[5] = HandshakeType.SERVER_HELLO  # handshake msg_type
        self.assertIsNone(parse_client_hello(bytes(data)))

    def test_truncated_body_returns_none(self):
        data = _client_hello(extensions=_sni_ext(b"host.example"))
        # random 도 다 못 받은 잘린 입력.
        self.assertIsNone(parse_client_hello(data[:20]))

    def test_lying_cipher_length_returns_none(self):
        # cipher_suites 길이가 실제보다 크다고 우기는 입력 → None.
        data = bytearray(_client_hello(cipher_suites=(0x1301,)))
        # cipher_suites length 필드 위치: record(5) + hs_hdr(4) + ver(2)
        # + random(32) + sid_len(1) = 44.
        struct.pack_into(">H", data, 44, 0xFFFF)
        self.assertIsNone(parse_client_hello(bytes(data)))


if __name__ == "__main__":
    unittest.main()
