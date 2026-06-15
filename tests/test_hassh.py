"""forensiclab.hassh 단위 테스트 (stdlib unittest)."""

import hashlib
import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from forensiclab.hassh import (  # noqa: E402
    SSH_MSG_KEXINIT,
    Hassh,
    KexInit,
    hassh,
    hassh_server,
    hassh_server_string,
    hassh_string,
    parse_kexinit,
)


def _namelist(names):
    """이름 리스트를 SSH name-list 바이트(uint32 길이 + ASCII)로."""
    raw = ",".join(names).encode("ascii")
    return struct.pack(">I", len(raw)) + raw


def _kexinit_payload(
    kex=("curve25519-sha256",),
    hostkey=("ssh-ed25519",),
    enc_c2s=("aes128-ctr",),
    enc_s2c=("aes256-ctr",),
    mac_c2s=("hmac-sha2-256",),
    mac_s2c=("hmac-sha2-512",),
    comp_c2s=("none",),
    comp_s2c=("none",),
    lang_c2s=(),
    lang_s2c=(),
):
    """KEXINIT 페이로드(코드 20 + 쿠키 + 10 name-list + 꼬리)를 만든다."""
    body = bytes([SSH_MSG_KEXINIT]) + b"\x00" * 16
    for lst in (
        kex, hostkey, enc_c2s, enc_s2c, mac_c2s, mac_s2c,
        comp_c2s, comp_s2c, lang_c2s, lang_s2c,
    ):
        body += _namelist(lst)
    body += b"\x00"  # first_kex_packet_follows
    body += struct.pack(">I", 0)  # reserved
    return body


def _wrap_binary_packet(payload):
    """페이로드를 SSH 바이너리 패킷(packet_length + padding)으로 감싼다."""
    padding_length = 8 - ((len(payload) + 5) % 8)
    if padding_length < 4:
        padding_length += 8
    packet_length = 1 + len(payload) + padding_length
    return (
        struct.pack(">I", packet_length)
        + bytes([padding_length])
        + payload
        + b"\x00" * padding_length
    )


class ParseKexInitTest(unittest.TestCase):
    def test_parse_payload_only(self):
        kex = parse_kexinit(_kexinit_payload())
        self.assertIsInstance(kex, KexInit)
        self.assertEqual(kex.kex_algorithms, ["curve25519-sha256"])
        self.assertEqual(kex.server_host_key_algorithms, ["ssh-ed25519"])
        self.assertEqual(kex.encryption_algorithms_c2s, ["aes128-ctr"])
        self.assertEqual(kex.encryption_algorithms_s2c, ["aes256-ctr"])
        self.assertEqual(kex.mac_algorithms_c2s, ["hmac-sha2-256"])
        self.assertEqual(kex.compression_algorithms_c2s, ["none"])
        self.assertEqual(len(kex.cookie), 16)

    def test_parse_binary_packet_framing(self):
        # 바이너리 패킷으로 감싸도 같은 결과여야 한다.
        payload = _kexinit_payload()
        wrapped = _wrap_binary_packet(payload)
        self.assertNotEqual(wrapped[0], SSH_MSG_KEXINIT)  # 길이로 시작.
        kex = parse_kexinit(wrapped)
        self.assertIsNotNone(kex)
        self.assertEqual(kex.kex_algorithms, ["curve25519-sha256"])

    def test_multi_name_lists_preserve_order(self):
        kex = parse_kexinit(
            _kexinit_payload(kex=("a", "b", "c"), enc_c2s=("x", "y"))
        )
        self.assertEqual(kex.kex_algorithms, ["a", "b", "c"])
        self.assertEqual(kex.encryption_algorithms_c2s, ["x", "y"])

    def test_empty_namelist_becomes_empty_list(self):
        kex = parse_kexinit(_kexinit_payload(lang_c2s=(), lang_s2c=()))
        self.assertEqual(kex.languages_c2s, [])
        self.assertEqual(kex.languages_s2c, [])

    def test_truncated_namelist_returns_none(self):
        payload = _kexinit_payload()
        self.assertIsNone(parse_kexinit(payload[:20]))

    def test_non_kexinit_code_returns_none(self):
        payload = bytearray(_kexinit_payload())
        payload[0] = 21  # SSH_MSG_NEWKEYS, KEXINIT 아님.
        self.assertIsNone(parse_kexinit(bytes(payload)))

    def test_empty_input_returns_none(self):
        self.assertIsNone(parse_kexinit(b""))

    def test_length_overrun_returns_none(self):
        # name-list 길이가 버퍼를 넘어서면 손상으로 본다.
        bad = bytes([SSH_MSG_KEXINIT]) + b"\x00" * 16 + struct.pack(">I", 9999)
        self.assertIsNone(parse_kexinit(bad))


class HasshStringTest(unittest.TestCase):
    def test_client_string_uses_c2s_lists(self):
        kex = parse_kexinit(_kexinit_payload())
        self.assertEqual(
            hassh_string(kex),
            "curve25519-sha256;aes128-ctr;hmac-sha2-256;none",
        )

    def test_server_string_uses_s2c_lists(self):
        kex = parse_kexinit(_kexinit_payload())
        self.assertEqual(
            hassh_server_string(kex),
            "curve25519-sha256;aes256-ctr;hmac-sha2-512;none",
        )

    def test_string_omits_hostkey_and_languages(self):
        # HASSH 는 kex;enc;mac;comp 네 필드뿐 — 호스트키·언어는 들어가지 않는다.
        kex = parse_kexinit(_kexinit_payload(hostkey=("ssh-rsa",), lang_c2s=("en",)))
        self.assertEqual(hassh_string(kex).count(";"), 3)
        self.assertNotIn("ssh-rsa", hassh_string(kex))
        self.assertNotIn("en", hassh_string(kex))

    def test_empty_lists_yield_empty_fields(self):
        kex = parse_kexinit(
            _kexinit_payload(mac_c2s=(), comp_c2s=())
        )
        self.assertEqual(hassh_string(kex), "curve25519-sha256;aes128-ctr;;")


class HasshHashTest(unittest.TestCase):
    def test_hash_is_md5_of_string(self):
        kex = parse_kexinit(_kexinit_payload())
        result = hassh(kex)
        self.assertIsInstance(result, Hassh)
        expected = hashlib.md5(result.string.encode("ascii")).hexdigest()
        self.assertEqual(result.hash, expected)
        self.assertEqual(len(result.hash), 32)

    def test_known_vector(self):
        # 고정 입력 → 안정적인 MD5(회귀 방지용 골든 값).
        kex = parse_kexinit(_kexinit_payload())
        s = "curve25519-sha256;aes128-ctr;hmac-sha2-256;none"
        self.assertEqual(hassh(kex).string, s)
        self.assertEqual(hassh(kex).hash, hashlib.md5(s.encode()).hexdigest())

    def test_client_and_server_differ(self):
        kex = parse_kexinit(_kexinit_payload())
        self.assertNotEqual(hassh(kex).hash, hassh_server(kex).hash)

    def test_order_changes_fingerprint(self):
        # 같은 알고리즘이라도 제시 순서가 다르면 다른 HASSH (순서는 지문의 일부).
        a = parse_kexinit(_kexinit_payload(enc_c2s=("aes128-ctr", "aes256-ctr")))
        b = parse_kexinit(_kexinit_payload(enc_c2s=("aes256-ctr", "aes128-ctr")))
        self.assertNotEqual(hassh(a).hash, hassh(b).hash)


if __name__ == "__main__":
    unittest.main()
