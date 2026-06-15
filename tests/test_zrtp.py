"""forensiclab.zrtp 단위 테스트 (stdlib unittest)."""

import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from forensiclab.zrtp import (  # noqa: E402
    ZRTP_MAGIC,
    ZRTP_MESSAGE_PREAMBLE,
    ZrtpPacket,
    looks_like_zrtp,
    parse_zrtp,
)


def _header(seq: int, ssrc: int) -> bytes:
    """12바이트 ZRTP 헤더(0x10 프리앰블+seq·매직 쿠키·SSRC)."""
    return struct.pack(">I", 0x10000000 | (seq & 0xFFFF)) + struct.pack(
        ">I", ZRTP_MAGIC
    ) + struct.pack(">I", ssrc)


def _message(mtype: str, body: bytes) -> bytes:
    """ZRTP 메시지(프리앰블+length 워드+8바이트 타입 블록+본문)."""
    type_block = mtype.encode("ascii").ljust(8, b" ")
    total = 4 + len(type_block) + len(body)  # 프리앰블/length + 타입 + 본문
    length_words = total // 4
    return struct.pack(">HH", ZRTP_MESSAGE_PREAMBLE, length_words) + type_block + body


def _hello_body(
    version="1.10",
    client_id="GNU ZRTP4J 2.1",
    zid=bytes(range(12)),
    hashes=("S256",),
    ciphers=("AES1",),
    auths=("HS32",),
    kas=("DH3k",),
    sas=("B32 ",),
    p=False,
    m=False,
    s=False,
):
    """Hello 본문(타입 블록 다음): version·client_id·H3·ZID·플래그/카운트·알고리즘."""
    out = version.encode("ascii").ljust(4, b" ")[:4]
    out += client_id.encode("ascii").ljust(16, b" ")[:16]
    out += b"\x00" * 32  # H3 해시 이미지.
    out += zid  # 12바이트 ZID.
    word = 0
    if s:
        word |= 1 << 27
    if m:
        word |= 1 << 26
    if p:
        word |= 1 << 25
    word |= (len(hashes) & 0xF) << 16
    word |= (len(ciphers) & 0xF) << 12
    word |= (len(auths) & 0xF) << 8
    word |= (len(kas) & 0xF) << 4
    word |= len(sas) & 0xF
    out += struct.pack(">I", word)
    for grp in (hashes, ciphers, auths, kas, sas):
        for tok in grp:
            out += tok.encode("ascii").ljust(4, b" ")[:4]
    out += b"\x00" * 8  # MAC.
    return out


def _hello_packet(**kw):
    return _header(1, 0xDEADBEEF) + _message("Hello", _hello_body(**kw))


class GuardTests(unittest.TestCase):
    def test_non_zrtp_returns_none(self):
        self.assertIsNone(parse_zrtp(b"\x80\x00" + b"\x00" * 20))

    def test_too_short_returns_none(self):
        self.assertIsNone(parse_zrtp(b"\x10\x00\x00\x01"))

    def test_non_bytes_returns_none(self):
        self.assertIsNone(parse_zrtp(None))
        self.assertIsNone(parse_zrtp(12345))

    def test_looks_like_zrtp(self):
        self.assertTrue(looks_like_zrtp(_header(5, 1)))
        self.assertFalse(looks_like_zrtp(b"\x80" + b"\x00" * 20))
        self.assertFalse(looks_like_zrtp(b"short"))


class HeaderTests(unittest.TestCase):
    def test_sequence_and_ssrc(self):
        pkt = parse_zrtp(_header(0x1234, 0xABCD1234) + _message("HelloACK", b""))
        self.assertIsInstance(pkt, ZrtpPacket)
        self.assertEqual(pkt.sequence, 0x1234)
        self.assertEqual(pkt.ssrc, 0xABCD1234)
        self.assertEqual(pkt.message_type, "HelloACK")

    def test_offset_parsing(self):
        pre = b"\xaa\xbb\xcc"
        pkt = parse_zrtp(pre + _header(1, 7) + _message("Commit", b""), offset=3)
        self.assertEqual(pkt.message_type, "Commit")
        self.assertEqual(pkt.ssrc, 7)


class HelloTests(unittest.TestCase):
    def test_identity_fields(self):
        pkt = parse_zrtp(_hello_packet())
        self.assertTrue(pkt.is_hello)
        self.assertEqual(pkt.version, "1.10")
        self.assertEqual(pkt.client_id, "GNU ZRTP4J 2.1")
        self.assertEqual(pkt.zid, bytes(range(12)).hex())

    def test_algorithm_lists(self):
        pkt = parse_zrtp(
            _hello_packet(
                hashes=("S256", "S384"),
                ciphers=("AES1", "AES3"),
                auths=("HS32",),
                kas=("DH3k", "EC25"),
                sas=("B32 ",),
            )
        )
        self.assertEqual(pkt.hash_algos, ["S256", "S384"])
        self.assertEqual(pkt.cipher_algos, ["AES1", "AES3"])
        self.assertEqual(pkt.auth_tags, ["HS32"])
        self.assertEqual(pkt.key_agreements, ["DH3k", "EC25"])
        self.assertEqual(pkt.sas_types, ["B32"])

    def test_flags(self):
        pkt = parse_zrtp(_hello_packet(p=True, m=True, s=False))
        self.assertTrue(pkt.passive)
        self.assertTrue(pkt.mitm)
        self.assertFalse(pkt.sign_capable)

    def test_zid_correlation_value(self):
        # 같은 ZID 가 SSRC 가 달라도 같은 단말로 묶이는지(호스트 귀속).
        zid = bytes([0xAA] * 12)
        a = parse_zrtp(_header(1, 111) + _message("Hello", _hello_body(zid=zid)))
        b = parse_zrtp(_header(1, 222) + _message("Hello", _hello_body(zid=zid)))
        self.assertEqual(a.zid, b.zid)
        self.assertNotEqual(a.ssrc, b.ssrc)


class MessageTypeTests(unittest.TestCase):
    def test_goclear_is_downgrade(self):
        pkt = parse_zrtp(_header(1, 1) + _message("GoClear", b"\x00" * 8))
        self.assertTrue(pkt.is_clear_downgrade)
        self.assertTrue(pkt.is_known_type)

    def test_clearack_is_downgrade(self):
        pkt = parse_zrtp(_header(1, 1) + _message("ClearACK", b""))
        self.assertTrue(pkt.is_clear_downgrade)

    def test_hello_not_downgrade(self):
        pkt = parse_zrtp(_hello_packet())
        self.assertFalse(pkt.is_clear_downgrade)

    def test_error_code(self):
        body = struct.pack(">I", 0x10)  # 오류 코드.
        pkt = parse_zrtp(_header(1, 1) + _message("Error", body))
        self.assertTrue(pkt.is_error)
        self.assertEqual(pkt.error_code, 0x10)

    def test_unknown_type_flagged(self):
        pkt = parse_zrtp(_header(1, 1) + _message("Bogus", b""))
        self.assertFalse(pkt.is_known_type)
        self.assertEqual(pkt.message_type, "Bogus")


class TruncationTests(unittest.TestCase):
    def test_header_only(self):
        # 메시지 없이 헤더만 — 헤더 필드는 채우고 타입은 비운다.
        pkt = parse_zrtp(_header(9, 42))
        self.assertEqual(pkt.ssrc, 42)
        self.assertEqual(pkt.message_type, "")

    def test_truncated_hello_body(self):
        # Hello 본문이 ZID 까지만(플래그/알고리즘 없음) — version·client_id 만.
        body = _hello_body()[:64]
        pkt = parse_zrtp(_header(1, 1) + _message("Hello", body))
        self.assertEqual(pkt.version, "1.10")
        self.assertEqual(pkt.zid, bytes(range(12)).hex())
        self.assertEqual(pkt.hash_algos, [])

    def test_bad_message_preamble(self):
        # 매직 쿠키는 맞지만 메시지 프리앰블이 틀리면 헤더만.
        bad = _header(1, 1) + struct.pack(">HH", 0x0000, 0) + b"Hello   "
        pkt = parse_zrtp(bad)
        self.assertIsInstance(pkt, ZrtpPacket)
        self.assertEqual(pkt.message_type, "")


if __name__ == "__main__":
    unittest.main()
