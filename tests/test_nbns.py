"""forensiclab.nbns 단위 테스트 (stdlib unittest)."""

import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from forensiclab.nbns import (  # noqa: E402
    NBNS_OP_QUERY,
    NBNS_OP_REGISTRATION,
    NBNS_TYPE_NB,
    NBNS_TYPE_NBSTAT,
    Nbns,
    NbnsQuestion,
    decode_netbios_name,
    parse_nbns,
)


def _encode_netbios_name(name: str, suffix: int) -> bytes:
    """이름(≤15자)+suffix 를 NetBIOS 1차 인코딩(32바이트)으로."""
    raw = name.upper().encode("latin-1")[:15].ljust(15, b" ") + bytes([suffix])
    out = bytearray()
    for b in raw:
        out.append(0x41 + (b >> 4))
        out.append(0x41 + (b & 0x0F))
    return bytes(out)


def _build(trn_id, flags, questions):
    """헤더 + 질문들로 NBNS 패킷을 짠다.

    questions: (name, suffix, qtype) 튜플 목록.
    """
    pkt = struct.pack(">HHHHHH", trn_id, flags, len(questions), 0, 0, 0)
    for name, suffix, qtype in questions:
        enc = _encode_netbios_name(name, suffix)
        pkt += bytes([0x20]) + enc + b"\x00"        # len + 32 + scope NUL
        pkt += struct.pack(">HH", qtype, 0x0001)    # QTYPE + QCLASS(IN)
    return pkt


class DecodeNameTests(unittest.TestCase):
    def test_roundtrip(self):
        enc = _encode_netbios_name("WORKSTATION1", 0x00)
        decoded = decode_netbios_name(enc)
        self.assertEqual(decoded, ("WORKSTATION1", 0x00))

    def test_file_server_suffix(self):
        enc = _encode_netbios_name("FILESRV", 0x20)
        name, suffix = decode_netbios_name(enc)
        self.assertEqual(name, "FILESRV")
        self.assertEqual(suffix, 0x20)

    def test_wrong_length_returns_none(self):
        self.assertIsNone(decode_netbios_name(b"AB"))

    def test_out_of_range_nibble_returns_none(self):
        # 0x40 은 0x41 미만 → 잘못된 인코딩.
        self.assertIsNone(decode_netbios_name(b"\x40" * 32))


class QueryTests(unittest.TestCase):
    def test_name_query(self):
        pkt = _build(0x1234, 0x0110, [("FILESRV", 0x20, NBNS_TYPE_NB)])
        msg = parse_nbns(pkt)
        self.assertIsInstance(msg, Nbns)
        self.assertEqual(msg.transaction_id, 0x1234)
        self.assertFalse(msg.is_response)
        self.assertEqual(msg.opcode, NBNS_OP_QUERY)
        self.assertEqual(msg.opcode_name, "query")
        self.assertTrue(msg.broadcast)
        self.assertEqual(msg.qdcount, 1)
        self.assertEqual(len(msg.questions), 1)
        q = msg.questions[0]
        self.assertEqual(q.name, "FILESRV")
        self.assertEqual(q.suffix, 0x20)
        self.assertEqual(q.suffix_name, "File Server")
        self.assertEqual(q.qtype, NBNS_TYPE_NB)
        self.assertEqual(q.qtype_name, "NB")
        self.assertFalse(q.is_wildcard)

    def test_response_bit(self):
        # R=1 (0x8000) | OPCODE query.
        pkt = _build(0x0001, 0x8500, [("HOST", 0x00, NBNS_TYPE_NB)])
        msg = parse_nbns(pkt)
        self.assertTrue(msg.is_response)
        self.assertEqual(msg.questions[0].suffix_name, "Workstation")


class NbstatTests(unittest.TestCase):
    def test_wildcard_node_status(self):
        pkt = _build(0xABCD, 0x0000, [("*", 0x00, NBNS_TYPE_NBSTAT)])
        msg = parse_nbns(pkt)
        self.assertTrue(msg.is_nbstat)
        q = msg.questions[0]
        self.assertEqual(q.name, "*")
        self.assertTrue(q.is_wildcard)
        self.assertEqual(q.qtype_name, "NBSTAT")


class RobustnessTests(unittest.TestCase):
    def test_too_short_returns_none(self):
        self.assertIsNone(parse_nbns(b"\x00" * 11))

    def test_unknown_opcode_returns_none(self):
        # OPCODE 1 (응답 전용 자리, 정의 안 됨).
        flags = (1 << 11)
        pkt = struct.pack(">HHHHHH", 1, flags, 0, 0, 0, 0)
        self.assertIsNone(parse_nbns(pkt))

    def test_truncated_question_keeps_header(self):
        # QD=1 이라 주장하지만 질문 본문이 없다 → 헤더는 반환, 질문은 빈 목록.
        pkt = struct.pack(">HHHHHH", 0x0007, 0x0000, 1, 0, 0, 0)
        msg = parse_nbns(pkt)
        self.assertIsNotNone(msg)
        self.assertEqual(msg.qdcount, 1)
        self.assertEqual(msg.questions, [])

    def test_registration_opcode(self):
        pkt = _build(0x0042, (NBNS_OP_REGISTRATION << 11) | 0x0010,
                     [("EVILHOST", 0x20, NBNS_TYPE_NB)])
        msg = parse_nbns(pkt)
        self.assertEqual(msg.opcode, NBNS_OP_REGISTRATION)
        self.assertEqual(msg.opcode_name, "registration")

    def test_negative_offset_returns_none(self):
        self.assertIsNone(parse_nbns(b"\x00" * 32, offset=-1))

    def test_offset_parsing(self):
        pkt = _build(0x1111, 0x0000, [("PC1", 0x00, NBNS_TYPE_NB)])
        framed = b"\xde\xad\xbe\xef" + pkt
        msg = parse_nbns(framed, offset=4)
        self.assertEqual(msg.transaction_id, 0x1111)
        self.assertEqual(msg.questions[0].name, "PC1")


if __name__ == "__main__":
    unittest.main()
