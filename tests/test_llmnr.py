"""forensiclab.llmnr 단위 테스트 (stdlib unittest)."""

import os
import socket
import struct
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from forensiclab.llmnr import (  # noqa: E402
    LLMNR_PORT,
    LlmnrMessage,
    LlmnrQuestion,
    ResourceRecord,
    parse_message,
    qtype_name,
)


def _encode_name(name: str) -> bytes:
    """이름을 DNS 라벨 형식(각 라벨 len+bytes, NUL 종단)으로."""
    out = bytearray()
    for label in name.split("."):
        b = label.encode("ascii")
        out.append(len(b))
        out += b
    out.append(0)
    return bytes(out)


def _header(txn_id, flags, qd=0, an=0, ns=0, ar=0):
    return struct.pack(">HHHHHH", txn_id, flags, qd, an, ns, ar)


def _query(name, qtype=1, txn_id=0x1234, flags=0x0000):
    pkt = _header(txn_id, flags, qd=1)
    pkt += _encode_name(name) + struct.pack(">HH", qtype, 1)
    return pkt


def _a_rr(name, ip):
    return _encode_name(name) + struct.pack(">HHIH", 1, 1, 30, 4) + socket.inet_aton(ip)


class ParseQueryTest(unittest.TestCase):
    def test_basic_query(self):
        msg = parse_message(_query("FILESERVER"))
        self.assertIsInstance(msg, LlmnrMessage)
        self.assertEqual(msg.id, 0x1234)
        self.assertTrue(msg.is_query)
        self.assertFalse(msg.is_response)
        self.assertEqual(msg.opcode, 0)
        self.assertEqual(msg.queried_names, ["FILESERVER"])
        self.assertEqual(len(msg.questions), 1)
        self.assertEqual(msg.questions[0].qtype_name, "A")

    def test_aaaa_qtype(self):
        msg = parse_message(_query("host1", qtype=28))
        self.assertEqual(msg.questions[0].qtype_name, "AAAA")

    def test_flags_query_clear(self):
        msg = parse_message(_query("x"))
        self.assertFalse(msg.conflict)
        self.assertFalse(msg.truncated)
        self.assertFalse(msg.tentative)
        self.assertEqual(msg.rcode, 0)


class WpadTest(unittest.TestCase):
    def test_wpad_query_detected(self):
        msg = parse_message(_query("wpad"))
        self.assertTrue(msg.has_wpad_query)
        self.assertTrue(msg.questions[0].is_wpad)

    def test_wpad_case_insensitive_with_domain(self):
        msg = parse_message(_query("WPAD.corp.local"))
        self.assertTrue(msg.questions[0].is_wpad)

    def test_non_wpad(self):
        msg = parse_message(_query("printer"))
        self.assertFalse(msg.has_wpad_query)


class PoisonResponseTest(unittest.TestCase):
    def test_response_with_a_record(self):
        # 공격자가 임의 이름을 자기 IP 로 답하는 포이즈닝 응답.
        pkt = _header(0xABCD, 0x8000, qd=1, an=1)
        pkt += _encode_name("fileshare") + struct.pack(">HH", 1, 1)
        pkt += _a_rr("fileshare", "10.0.0.66")
        msg = parse_message(pkt)
        self.assertTrue(msg.is_response)
        self.assertEqual(msg.answer_count, 1)
        self.assertEqual(len(msg.answers), 1)
        self.assertEqual(msg.answers[0].address, "10.0.0.66")
        self.assertEqual(msg.answers[0].rtype_name, "A")
        self.assertEqual(msg.answer_addresses, ["10.0.0.66"])

    def test_aaaa_answer(self):
        rdata = socket.inet_pton(socket.AF_INET6, "fe80::dead:beef")
        pkt = _header(1, 0x8000, an=1)
        pkt += _encode_name("h") + struct.pack(">HHIH", 28, 1, 30, 16) + rdata
        msg = parse_message(pkt)
        self.assertEqual(msg.answers[0].address, "fe80::dead:beef")

    def test_conflict_and_tentative_flags(self):
        # C(0x0400) + T(0x0100) + QR.
        msg = parse_message(_header(1, 0x8000 | 0x0400 | 0x0100))
        self.assertTrue(msg.conflict)
        self.assertTrue(msg.tentative)

    def test_non_address_answer_address_none(self):
        # TXT 레코드는 주소 추출 안 함.
        pkt = _header(1, 0x8000, an=1)
        pkt += _encode_name("h") + struct.pack(">HHIH", 16, 1, 30, 3) + b"abc"
        msg = parse_message(pkt)
        self.assertIsNone(msg.answers[0].address)
        self.assertEqual(msg.answer_addresses, [])


class RobustnessTest(unittest.TestCase):
    def test_too_short(self):
        self.assertIsNone(parse_message(b"\x00\x01\x00\x00"))

    def test_empty(self):
        self.assertIsNone(parse_message(b""))

    def test_nonzero_opcode_rejected(self):
        # Opcode 5 — LLMNR 아님(오탐 가드).
        flags = (5 << 11)
        self.assertIsNone(parse_message(_header(1, flags, qd=0)))

    def test_truncated_question_keeps_header(self):
        # qd=2 선언했지만 질문 하나만 온전. 헤더+읽은 만큼 반환.
        pkt = _header(1, 0x0000, qd=2)
        pkt += _encode_name("only") + struct.pack(">HH", 1, 1)
        msg = parse_message(pkt)
        self.assertIsNotNone(msg)
        self.assertEqual(len(msg.questions), 1)

    def test_truncated_rdata_drops_record(self):
        # an=1 이지만 RDATA 가 잘림 — 레코드 버리고 나머지 반환.
        pkt = _header(1, 0x8000, an=1)
        pkt += _encode_name("h") + struct.pack(">HHIH", 1, 1, 30, 4) + b"\x0a\x00"
        msg = parse_message(pkt)
        self.assertIsNotNone(msg)
        self.assertEqual(len(msg.answers), 0)

    def test_offset_support(self):
        prefix = b"\xff\xee"
        msg = parse_message(prefix + _query("HOST"), offset=2)
        self.assertEqual(msg.queried_names, ["HOST"])

    def test_negative_offset(self):
        self.assertIsNone(parse_message(_query("x"), offset=-1))


class MiscTest(unittest.TestCase):
    def test_port_constant(self):
        self.assertEqual(LLMNR_PORT, 5355)

    def test_qtype_name_unknown(self):
        self.assertEqual(qtype_name(99), "99")

    def test_resourcerecord_dataclass(self):
        rr = ResourceRecord(name="h", rtype=1, rclass=1, ttl=30, address="1.2.3.4")
        self.assertEqual(rr.rtype_name, "A")

    def test_question_dataclass(self):
        q = LlmnrQuestion(name="h", qtype=1, qclass=1)
        self.assertFalse(q.is_wpad)


if __name__ == "__main__":
    unittest.main()
