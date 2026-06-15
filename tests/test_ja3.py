"""forensiclab.ja3 단위 테스트 (stdlib unittest)."""

import hashlib
import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from forensiclab.ja3 import (  # noqa: E402
    Ja3,
    is_grease,
    ja3,
    ja3_hash,
    ja3_string,
)
from forensiclab.tls import (  # noqa: E402
    ClientHello,
    ContentType,
    ExtensionType,
    HandshakeType,
    parse_client_hello,
)


class GreaseTest(unittest.TestCase):
    def test_known_grease_values(self):
        for v in (0x0A0A, 0x1A1A, 0x2A2A, 0xAAAA, 0xFAFA):
            self.assertTrue(is_grease(v), f"0x{v:04x}")

    def test_non_grease_values(self):
        for v in (0x0000, 0x1301, 29, 0x000A, 0x0A0B, 0x0B0A, 0xAAAB):
            self.assertFalse(is_grease(v), f"0x{v:04x}")


class Ja3StringTest(unittest.TestCase):
    def test_string_field_order_and_format(self):
        hello = ClientHello(
            legacy_version=0x0303,  # 771
            cipher_suites=[0x1301, 0x1302, 0x1303],
            extensions=[0x0000, 0x000A, 0x000B, 0x0010],
            supported_groups=[29, 23, 24],
            ec_point_formats=[0],
        )
        self.assertEqual(
            ja3_string(hello),
            "771,4865-4866-4867,0-10-11-16,29-23-24,0",
        )

    def test_hash_matches_independent_oracle(self):
        hello = ClientHello(
            legacy_version=0x0303,
            cipher_suites=[0x1301, 0x1302, 0x1303],
            extensions=[0x0000, 0x000A, 0x000B, 0x0010],
            supported_groups=[29, 23, 24],
            ec_point_formats=[0],
        )
        # 독립 계산한 기준값(test 본문 밖 python -c 로 확인).
        self.assertEqual(ja3_hash(hello), "3f26ac59384c58df3ec716bf24deb901")

    def test_empty_lists_leave_empty_fields(self):
        hello = ClientHello(legacy_version=0x0301, cipher_suites=[4, 5])
        self.assertEqual(ja3_string(hello), "769,4-5,,,")

    def test_grease_stripped_from_all_lists(self):
        hello = ClientHello(
            legacy_version=0x0303,
            cipher_suites=[0x0A0A, 0x1301, 0x1A1A, 0x1302],
            extensions=[0x2A2A, 0x0000, 0x0010],
            supported_groups=[0xFAFA, 29],
            ec_point_formats=[0],
        )
        self.assertEqual(
            ja3_string(hello),
            "771,4865-4866,0-16,29,0",
        )

    def test_ja3_returns_string_and_hash_together(self):
        hello = ClientHello(legacy_version=0x0303, cipher_suites=[4865])
        result = ja3(hello)
        self.assertIsInstance(result, Ja3)
        self.assertEqual(result.string, ja3_string(hello))
        self.assertEqual(
            result.hash, hashlib.md5(result.string.encode()).hexdigest()
        )


def _ext(ext_type, body):
    return struct.pack(">HH", ext_type, len(body)) + body


def _supported_groups_ext(groups):
    body = b"".join(struct.pack(">H", g) for g in groups)
    return _ext(ExtensionType.SUPPORTED_GROUPS, struct.pack(">H", len(body)) + body)


def _ec_point_formats_ext(formats):
    body = bytes(formats)
    return _ext(ExtensionType.EC_POINT_FORMATS, struct.pack(">B", len(body)) + body)


def _client_hello(extensions):
    body = struct.pack(">H", 0x0303)  # client_version
    body += b"\x00" * 32  # random
    body += b"\x00"  # session_id length = 0
    cs = struct.pack(">H", 0x1301)
    body += struct.pack(">H", len(cs)) + cs  # cipher_suites
    body += b"\x01\x00"  # compression_methods
    body += struct.pack(">H", len(extensions)) + extensions

    handshake = struct.pack(">B", HandshakeType.CLIENT_HELLO)
    handshake += struct.pack(">I", len(body))[1:]
    handshake += body

    record = struct.pack(">B", ContentType.HANDSHAKE) + b"\x03\x01"
    record += struct.pack(">H", len(handshake)) + handshake
    return record


class ParseIntegrationTest(unittest.TestCase):
    """parse_client_hello 가 JA3 입력 필드를 채우는지 확인."""

    def test_parse_populates_groups_and_point_formats(self):
        ext = _supported_groups_ext([29, 23, 24]) + _ec_point_formats_ext([0, 1])
        hello = parse_client_hello(_client_hello(ext))
        self.assertIsNotNone(hello)
        self.assertEqual(hello.supported_groups, [29, 23, 24])
        self.assertEqual(hello.ec_point_formats, [0, 1])

    def test_parsed_hello_produces_stable_ja3(self):
        ext = _supported_groups_ext([29]) + _ec_point_formats_ext([0])
        hello = parse_client_hello(_client_hello(ext))
        # 같은 핸드셰이크를 두 번 파싱하면 같은 JA3.
        self.assertEqual(ja3_hash(hello), ja3_hash(parse_client_hello(_client_hello(ext))))

    def test_missing_extensions_default_to_empty(self):
        hello = parse_client_hello(_client_hello(b""))
        self.assertEqual(hello.supported_groups, [])
        self.assertEqual(hello.ec_point_formats, [])


if __name__ == "__main__":
    unittest.main()
