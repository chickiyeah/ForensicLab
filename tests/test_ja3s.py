"""forensiclab.ja3s 단위 테스트 (stdlib unittest)."""

import hashlib
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from forensiclab.ja3s import (  # noqa: E402
    Ja3s,
    ja3s,
    ja3s_hash,
    ja3s_string,
)
from forensiclab.tls import ServerHello  # noqa: E402


class Ja3sStringTest(unittest.TestCase):
    def test_string_field_order_and_format(self):
        hello = ServerHello(
            legacy_version=0x0303,  # 771
            cipher_suite=0xC02B,  # 49195
            extensions=[0x0000, 0x000B, 0x0023, 0x0010],
        )
        self.assertEqual(ja3s_string(hello), "771,49195,0-11-35-16")

    def test_hash_matches_independent_oracle(self):
        hello = ServerHello(
            legacy_version=0x0303,
            cipher_suite=0xC02B,
            extensions=[0x0000, 0x000B, 0x0023, 0x0010],
        )
        self.assertEqual(ja3s_hash(hello), "69f3ac67fc140ef221a855a41529d8d3")

    def test_empty_extensions_leave_trailing_empty_field(self):
        hello = ServerHello(legacy_version=0x0303, cipher_suite=0xC02B)
        self.assertEqual(ja3s_string(hello), "771,49195,")
        self.assertEqual(ja3s_hash(hello), "ec9fdb7b766d47dd56948c6a5d580ddd")

    def test_grease_stripped_from_extensions(self):
        hello = ServerHello(
            legacy_version=0x0303,
            cipher_suite=0xC02B,
            extensions=[0x2A2A, 0x0000, 0xFAFA, 0x0010],
        )
        self.assertEqual(ja3s_string(hello), "771,49195,0-16")

    def test_grease_cipher_leaves_empty_field(self):
        # 정상 트래픽엔 없지만 방어적으로: cipher 가 GREASE 면 비운다.
        hello = ServerHello(legacy_version=0x0303, cipher_suite=0x0A0A)
        self.assertEqual(ja3s_string(hello), "771,,")

    def test_cipher_is_single_value_not_list(self):
        # JA3(클라이언트)와 달리 cipher 필드엔 '-' 가 없다.
        hello = ServerHello(
            legacy_version=0x0301, cipher_suite=0x009C, extensions=[0x0017]
        )
        self.assertNotIn("-", ja3s_string(hello).split(",")[1])
        self.assertEqual(ja3s_string(hello), "769,156,23")

    def test_ja3s_returns_string_and_hash_together(self):
        hello = ServerHello(legacy_version=0x0303, cipher_suite=0x1301)
        result = ja3s(hello)
        self.assertIsInstance(result, Ja3s)
        self.assertEqual(result.string, ja3s_string(hello))
        self.assertEqual(
            result.hash, hashlib.md5(result.string.encode()).hexdigest()
        )

    def test_input_servrhello_not_mutated(self):
        exts = [0x0000, 0x2A2A, 0x0010]
        hello = ServerHello(
            legacy_version=0x0303, cipher_suite=0xC02B, extensions=exts
        )
        ja3s(hello)
        self.assertEqual(hello.extensions, [0x0000, 0x2A2A, 0x0010])
        self.assertEqual(exts, [0x0000, 0x2A2A, 0x0010])


if __name__ == "__main__":
    unittest.main()
