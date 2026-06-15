"""forensiclab.tls ServerHello 파싱 단위 테스트 (stdlib unittest)."""

import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from forensiclab.tls import (  # noqa: E402
    ContentType,
    ExtensionType,
    HandshakeType,
    ServerHello,
    parse_server_hello,
)


def _alpn_ext(protos) -> bytes:
    """ALPN 확장 한 개를 만든다(type 0x0010). 서버는 보통 1개를 고른다."""
    body = b"".join(struct.pack(">B", len(p)) + p for p in protos)
    proto_list = struct.pack(">H", len(body)) + body
    return struct.pack(">HH", ExtensionType.ALPN, len(proto_list)) + proto_list


def _supported_versions_ext(version: int) -> bytes:
    """ServerHello 의 supported_versions 확장 — 선택된 단일 버전 2바이트."""
    body = struct.pack(">H", version)
    return struct.pack(">HH", ExtensionType.SUPPORTED_VERSIONS, len(body)) + body


def _server_hello(
    cipher_suite=0x1301,
    extensions=b"",
    version=0x0303,
    include_ext_block=True,
):
    """ServerHello 를 담은 완전한 TLS handshake record 바이트를 만든다."""
    body = struct.pack(">H", version)  # server_version
    body += b"\x00" * 32  # random
    body += b"\x00"  # session_id length = 0
    body += struct.pack(">H", cipher_suite)  # 단일 cipher_suite
    body += b"\x00"  # compression_method: null
    if include_ext_block:
        body += struct.pack(">H", len(extensions)) + extensions

    handshake = struct.pack(">B", HandshakeType.SERVER_HELLO)
    handshake += struct.pack(">I", len(body))[1:]  # 3바이트 길이
    handshake += body

    record = struct.pack(">B", ContentType.HANDSHAKE)
    record += b"\x03\x03"  # record version
    record += struct.pack(">H", len(handshake))
    record += handshake
    return record


class ParseBasicTest(unittest.TestCase):
    def test_minimal_no_extensions(self):
        hello = parse_server_hello(_server_hello())
        self.assertIsInstance(hello, ServerHello)
        self.assertEqual(hello.legacy_version, 0x0303)
        self.assertEqual(hello.legacy_version_str, "TLS 1.2")
        self.assertEqual(hello.cipher_suite, 0x1301)
        self.assertEqual(hello.extensions, [])
        self.assertEqual(hello.alpn, [])
        self.assertIsNone(hello.selected_version)

    def test_legacy_without_extension_block(self):
        hello = parse_server_hello(_server_hello(include_ext_block=False))
        self.assertIsInstance(hello, ServerHello)
        self.assertEqual(hello.cipher_suite, 0x1301)
        self.assertEqual(hello.extensions, [])

    def test_negotiated_version_falls_back_to_legacy(self):
        # supported_versions 가 없으면 협상 버전 = legacy.
        hello = parse_server_hello(_server_hello(version=0x0303))
        self.assertEqual(hello.negotiated_version, 0x0303)
        self.assertEqual(hello.negotiated_version_str, "TLS 1.2")


class ExtensionTest(unittest.TestCase):
    def test_extracts_alpn(self):
        hello = parse_server_hello(_server_hello(extensions=_alpn_ext([b"h2"])))
        self.assertEqual(hello.alpn, ["h2"])
        self.assertIn(ExtensionType.ALPN, hello.extensions)

    def test_tls13_negotiated_via_supported_versions(self):
        # legacy 는 1.2 라고 적지만 supported_versions 가 실제 1.3 을 알려준다.
        ext = _supported_versions_ext(0x0304)
        hello = parse_server_hello(_server_hello(version=0x0303, extensions=ext))
        self.assertEqual(hello.legacy_version, 0x0303)
        self.assertEqual(hello.selected_version, 0x0304)
        self.assertEqual(hello.negotiated_version, 0x0304)
        self.assertEqual(hello.negotiated_version_str, "TLS 1.3")

    def test_unknown_extension_collected_by_type(self):
        unknown = struct.pack(">HH", 0xFF01, 1) + b"\x00"  # renegotiation_info 류
        hello = parse_server_hello(_server_hello(extensions=unknown))
        self.assertEqual(hello.extensions, [0xFF01])
        self.assertEqual(hello.alpn, [])


class RobustnessTest(unittest.TestCase):
    def test_empty_returns_none(self):
        self.assertIsNone(parse_server_hello(b""))

    def test_non_handshake_record_returns_none(self):
        data = bytearray(_server_hello())
        data[0] = ContentType.APPLICATION_DATA
        self.assertIsNone(parse_server_hello(bytes(data)))

    def test_client_hello_returns_none(self):
        data = bytearray(_server_hello())
        data[5] = HandshakeType.CLIENT_HELLO  # handshake msg_type
        self.assertIsNone(parse_server_hello(bytes(data)))

    def test_truncated_body_returns_none(self):
        data = _server_hello(extensions=_alpn_ext([b"h2"]))
        self.assertIsNone(parse_server_hello(data[:20]))


if __name__ == "__main__":
    unittest.main()
