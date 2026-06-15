"""forensiclab.isup 단위 테스트 (stdlib unittest)."""

import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from forensiclab.isup import (  # noqa: E402
    ISUP_MESSAGE_TYPES,
    Isup,
    parse_isup,
)


def _cic(value):
    """CIC(2바이트 little-endian, 하위 12비트)."""
    return struct.pack("<H", value & 0x0FFF)


def _party_number(digits, odd_even_nai=0x83, octet2=0x10):
    """당사자 번호 파라미터 내용(octet1+octet2+BCD)을 짠다.

    odd_even_nai: octet1(bit8 odd/even + nature of address). 자릿수가 홀수면
    bit8(0x80)을 세팅해 마지막 high nibble 을 filler 로 표시한다.
    """
    odd = len(digits) % 2 == 1
    o1 = (odd_even_nai | 0x80) if odd else (odd_even_nai & 0x7F)
    body = bytes([o1, octet2])
    vals = [int(c, 16) for c in digits]
    if odd:
        vals.append(0x0)  # filler nibble.
    for i in range(0, len(vals), 2):
        body += bytes([vals[i] | (vals[i + 1] << 4)])
    return body


def _len_prefixed(content):
    return bytes([len(content)]) + content


def _iam(cic, called, calling=None, calling_octet2=0x10):
    """IAM(0x01): CIC + type + fixed(5) + 포인터 2 + Called(+optional Calling)."""
    header = _cic(cic) + b"\x01"
    fixed = b"\x00\x00\x00\x0a\x00"  # NCI+FCI(2)+CPC+TMR (값 무의미).

    called_param = _len_prefixed(_party_number(called))

    if calling is not None:
        calling_content = _party_number(calling, octet2=calling_octet2)
        optional = bytes([0x0A, len(calling_content)]) + calling_content + b"\x00"
    else:
        optional = b""

    # mandatory variable: ptr_called, ptr_optional (자기 위치 기준 상대).
    # 포인터부 다음 = Called Party Number, 그 다음 = optional part.
    ptr_called = 2          # ptr_called_pos 에서 Called 까지(자기+1 옥텟 건너뛰면 2).
    ptr_optional = 1 + len(called_param) if optional else 0
    var = bytes([ptr_called, ptr_optional]) + called_param + optional
    return header + fixed + var


def _rel(cic, cause_value):
    """REL(0x0C): CIC + type + ptr_cause + ptr_optional + Cause Indicators."""
    header = _cic(cic) + b"\x0c"
    cause_content = bytes([0x80, 0x80 | (cause_value & 0x7F)])  # octet1 location, octet2 cause.
    cause_param = _len_prefixed(cause_content)
    ptr_cause = 2
    ptr_optional = 0
    return header + bytes([ptr_cause, ptr_optional]) + cause_param


class MessageTypeTests(unittest.TestCase):
    def test_message_type_set(self):
        self.assertIn(0x01, ISUP_MESSAGE_TYPES)
        self.assertIn(0x0C, ISUP_MESSAGE_TYPES)
        self.assertNotIn(0x99, ISUP_MESSAGE_TYPES)

    def test_simple_acm(self):
        msg = _cic(0x123) + b"\x06" + b"\x00\x00"
        m = parse_isup(msg)
        self.assertIsInstance(m, Isup)
        self.assertEqual(m.message_type, 0x06)
        self.assertEqual(m.message_type_name, "ACM")
        self.assertTrue(m.is_address_complete)
        self.assertFalse(m.is_setup)
        self.assertEqual(m.cic, 0x123)
        self.assertEqual(m.payload_offset, 3)

    def test_answer(self):
        m = parse_isup(_cic(7) + b"\x09" + b"\x00")
        self.assertTrue(m.is_answer)
        self.assertEqual(m.message_type_name, "ANM")

    def test_unknown_type_name(self):
        # 0x2A CFN 은 알려진 타입.
        m = parse_isup(_cic(1) + b"\x2a" + b"\x00")
        self.assertEqual(m.message_type_name, "CFN")


class CicTests(unittest.TestCase):
    def test_cic_little_endian_12bit(self):
        # 0x0FFF 보다 큰 상위 비트는 마스크됨.
        m = parse_isup(struct.pack("<H", 0xF456) + b"\x06\x00")
        self.assertEqual(m.cic, 0x456)

    def test_cic_correlation_same_call(self):
        a = parse_isup(_iam(0x321, "1234"))
        b = parse_isup(_rel(0x321, 16))
        self.assertEqual(a.cic, b.cic)  # 한 호의 상관 키.


class IamTests(unittest.TestCase):
    def test_called_number_even(self):
        m = parse_isup(_iam(0x100, "20212345"))
        self.assertTrue(m.is_setup)
        self.assertEqual(m.called_number, "20212345")
        self.assertIsNone(m.calling_number)

    def test_called_number_odd(self):
        m = parse_isup(_iam(0x100, "8210099"))  # 7자리(홀수) filler 처리.
        self.assertEqual(m.called_number, "8210099")

    def test_calling_number_optional(self):
        m = parse_isup(_iam(0x100, "5551212", calling="01055667788"))
        self.assertEqual(m.called_number, "5551212")
        self.assertEqual(m.calling_number, "01055667788")

    def test_calling_presentation_allowed(self):
        m = parse_isup(_iam(0x100, "5551212", calling="01099", calling_octet2=0x10))
        # octet2 bits4-3 = 0 → allowed.
        self.assertEqual(m.calling_presentation, 0)
        self.assertEqual(m.calling_presentation_name, "allowed")
        self.assertFalse(m.is_calling_number_restricted)

    def test_calling_presentation_restricted(self):
        # octet2 bits4-3 = 01 → restricted (0x04).
        m = parse_isup(_iam(0x100, "5551212", calling="01099", calling_octet2=0x14))
        self.assertEqual(m.calling_presentation, 1)
        self.assertEqual(m.calling_presentation_name, "restricted")
        self.assertTrue(m.is_calling_number_restricted)


class RelTests(unittest.TestCase):
    def test_cause_normal_clearing(self):
        m = parse_isup(_rel(0x55, 16))
        self.assertTrue(m.is_release)
        self.assertEqual(m.cause_value, 16)
        self.assertEqual(m.cause_name, "normalCallClearing")

    def test_cause_unallocated_number(self):
        m = parse_isup(_rel(0x55, 1))
        self.assertEqual(m.cause_name, "unallocatedNumber")

    def test_cause_unknown(self):
        m = parse_isup(_rel(0x55, 99))
        self.assertEqual(m.cause_name, "cause-99")

    def test_non_rel_has_no_cause(self):
        m = parse_isup(_iam(0x100, "1234"))
        self.assertIsNone(m.cause_value)
        self.assertIsNone(m.cause_name)


class GuardTests(unittest.TestCase):
    def test_empty(self):
        self.assertIsNone(parse_isup(b""))

    def test_too_short(self):
        self.assertIsNone(parse_isup(b"\x01\x02"))  # CIC만, 타입 없음.

    def test_undefined_message_type(self):
        self.assertIsNone(parse_isup(_cic(1) + b"\x99" + b"\x00"))

    def test_offset(self):
        blob = b"\xde\xad" + _iam(0x100, "1234")
        m = parse_isup(blob, offset=2)
        self.assertEqual(m.called_number, "1234")
        self.assertEqual(m.payload_offset, 5)

    def test_negative_offset(self):
        self.assertIsNone(parse_isup(_iam(0x100, "1234"), offset=-1))

    def test_truncated_iam_called_pointer(self):
        # 포인터가 데이터를 넘어가면 번호는 None, 그래도 메시지는 파싱됨.
        m = parse_isup(_cic(1) + b"\x01" + b"\x00\x00\x00\x0a\x00" + b"\x7f\x00")
        self.assertIsInstance(m, Isup)
        self.assertTrue(m.is_setup)
        self.assertIsNone(m.called_number)


if __name__ == "__main__":
    unittest.main()
