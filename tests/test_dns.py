"""forensiclab.dns 단위 테스트 (stdlib unittest)."""

import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from forensiclab.dns import (  # noqa: E402
    DnsMessage,
    Question,
    parse_message,
    qtype_name,
)


def _encode_name(name):
    """도메인 이름을 라벨 시퀀스(+종료 0바이트)로 인코딩."""
    out = b""
    if name:
        for label in name.split("."):
            out += bytes([len(label)]) + label.encode("ascii")
    return out + b"\x00"


def _header(txn_id=0x1234, flags=0x0100, qd=0, an=0, ns=0, ar=0):
    return struct.pack(">HHHHHH", txn_id, flags, qd, an, ns, ar)


def _query(name, qtype=1, qclass=1, txn_id=0x1234, flags=0x0100):
    return (
        _header(txn_id=txn_id, flags=flags, qd=1)
        + _encode_name(name)
        + struct.pack(">HH", qtype, qclass)
    )


class QtypeNameTest(unittest.TestCase):
    def test_known(self):
        self.assertEqual(qtype_name(1), "A")
        self.assertEqual(qtype_name(28), "AAAA")
        self.assertEqual(qtype_name(16), "TXT")

    def test_unknown_falls_back_to_number(self):
        self.assertEqual(qtype_name(9999), "9999")


class ParseHeaderTest(unittest.TestCase):
    def test_too_short_returns_none(self):
        self.assertIsNone(parse_message(b"\x00" * 11))

    def test_empty_question_header(self):
        msg = parse_message(_header(txn_id=0xABCD, flags=0x8180, an=2, ns=1, ar=3))
        self.assertIsInstance(msg, DnsMessage)
        self.assertEqual(msg.id, 0xABCD)
        self.assertTrue(msg.is_response)
        self.assertEqual(msg.rcode, 0)
        self.assertEqual(msg.questions, [])
        self.assertEqual(msg.answer_count, 2)
        self.assertEqual(msg.authority_count, 1)
        self.assertEqual(msg.additional_count, 3)

    def test_flag_bits(self):
        # QR=0, opcode=0, TC=1(0x0200), RD=1(0x0100), rcode=3.
        msg = parse_message(_header(flags=0x0303))
        self.assertFalse(msg.is_response)
        self.assertTrue(msg.truncated)
        self.assertTrue(msg.recursion_desired)
        self.assertEqual(msg.rcode, 3)
        self.assertEqual(msg.opcode, 0)


class ParseQuestionTest(unittest.TestCase):
    def test_standard_query(self):
        msg = parse_message(_query("www.example.com", qtype=1, qclass=1))
        self.assertEqual(len(msg.questions), 1)
        q = msg.questions[0]
        self.assertEqual(q, Question(name="www.example.com", qtype=1, qclass=1))
        self.assertEqual(q.qtype_name, "A")

    def test_root_name(self):
        msg = parse_message(_query("", qtype=2))
        self.assertEqual(msg.questions[0].name, "")

    def test_multiple_questions(self):
        data = (
            _header(qd=2)
            + _encode_name("a.test") + struct.pack(">HH", 1, 1)
            + _encode_name("b.test") + struct.pack(">HH", 28, 1)
        )
        msg = parse_message(data)
        self.assertEqual([q.name for q in msg.questions], ["a.test", "b.test"])
        self.assertEqual(msg.questions[1].qtype_name, "AAAA")

    def test_truncated_question_returns_none(self):
        # qd=1 을 선언했지만 질문 바이트가 없음.
        self.assertIsNone(parse_message(_header(qd=1)))

    def test_missing_qtype_returns_none(self):
        data = _header(qd=1) + _encode_name("x.test")  # QTYPE/QCLASS 누락.
        self.assertIsNone(parse_message(data))


class CompressionPointerTest(unittest.TestCase):
    def test_pointer_resolves_name(self):
        # 바이트 배치:
        #   0..11   헤더(qd=1)
        #   12..15  질문 이름: 라벨 "www"(\x03www)
        #   16..17  오프셋 22 로의 압축 포인터
        #   18..21  QTYPE(A)/QCLASS(IN)
        #   22..    포인터 대상 이름 "example.com\x00"
        # 결과 이름은 "www" + "example.com" = "www.example.com".
        name_field = b"\x03www" + struct.pack(">H", 0xC000 | 22)
        data = (
            _header(qd=1)
            + name_field
            + struct.pack(">HH", 1, 1)
            + _encode_name("example.com")
        )
        msg = parse_message(data)
        self.assertEqual(msg.questions[0].name, "www.example.com")
        self.assertEqual(msg.questions[0].qtype_name, "A")

    def test_pointer_loop_returns_none(self):
        # 오프셋 12 가 자기 자신(12)을 가리키는 포인터 → 무한 루프 방지로 None.
        data = _header(qd=1) + struct.pack(">H", 0xC000 | 12) + struct.pack(">HH", 1, 1)
        self.assertIsNone(parse_message(data))


class ImmutabilityTest(unittest.TestCase):
    def test_input_not_mutated(self):
        data = _query("host.local")
        original = bytes(data)
        parse_message(data)
        self.assertEqual(data, original)


if __name__ == "__main__":
    unittest.main()
