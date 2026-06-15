"""forensiclab.cap 단위 테스트 (stdlib unittest)."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from forensiclab.cap import (  # noqa: E402
    CAP_FRAUD_OPERATIONS,
    CAP_OPERATION_NAMES,
    CapArgument,
    CapNumber,
    decode_cap_number,
    decode_isup_bcd,
    parse_cap,
)


def _tlv(tag, content):
    """짧은 형식(길이<128) BER TLV 하나를 짠다."""
    assert len(content) < 0x80, "테스트 헬퍼는 짧은 형식만"
    return bytes([tag, len(content)]) + content


def _isup_bcd(digits):
    """숫자열을 ISUP BCD(하위 nibble 먼저, 홀수면 마지막 상위 nibble=0 filler)로 인코드."""
    out = bytearray()
    for i in range(0, len(digits), 2):
        lo = int(digits[i])
        hi = int(digits[i + 1]) if i + 1 < len(digits) else 0
        out.append((hi << 4) | lo)
    return bytes(out)


def _num(digits, nai=4, plan=1):
    """CAP/ISUP 형 당사자 번호 OCTET STRING 내용(octet1+octet2+BCD)을 짠다."""
    odd = len(digits) % 2 == 1
    octet1 = (0x80 if odd else 0x00) | nai
    octet2 = (plan & 0x07) << 4
    return bytes([octet1, octet2]) + _isup_bcd(digits)


# 국제 착신 번호(국가코드 포함).
_CALLED = "821012345678"
# 발신 번호(국내·홀수 자릿수).
_CALLING = "01098765432"


class IsupBcdTests(unittest.TestCase):
    def test_even_length(self):
        self.assertEqual(decode_isup_bcd(_isup_bcd("1234"), odd=False), "1234")

    def test_odd_length_drops_filler(self):
        # 홀수 자릿수: 마지막 옥텟 상위 nibble(0 filler)은 odd 플래그로 버린다.
        self.assertEqual(decode_isup_bcd(_isup_bcd("12345"), odd=True), "12345")

    def test_even_keeps_all(self):
        self.assertEqual(decode_isup_bcd(_isup_bcd("1234"), odd=True), "123")


class DecodeCapNumberTests(unittest.TestCase):
    def test_international_isdn(self):
        out = decode_cap_number(_num(_CALLED, nai=4, plan=1))
        self.assertEqual(out, (_CALLED, 4, 1))

    def test_national_odd(self):
        out = decode_cap_number(_num(_CALLING, nai=3, plan=1))
        self.assertEqual(out, (_CALLING, 3, 1))

    def test_too_short_header_only(self):
        self.assertIsNone(decode_cap_number(b"\x84\x10"))

    def test_empty(self):
        self.assertIsNone(decode_cap_number(b""))


class CapNumberTests(unittest.TestCase):
    def test_names(self):
        n = CapNumber("12345", 4, 1, 0)
        self.assertEqual(n.nature_name, "international")
        self.assertEqual(n.numbering_plan_name, "ISDN-E.164")
        self.assertTrue(n.is_international)

    def test_unknown_name_fallback(self):
        n = CapNumber("12345", 7, 5, 0)
        self.assertEqual(n.nature_name, "nai-7")
        self.assertEqual(n.numbering_plan_name, "plan-5")
        self.assertFalse(n.is_international)


class OperationTableTests(unittest.TestCase):
    def test_core_names(self):
        self.assertEqual(CAP_OPERATION_NAMES[0], "initialDP")
        self.assertEqual(CAP_OPERATION_NAMES[20], "connect")
        self.assertEqual(CAP_OPERATION_NAMES[22], "releaseCall")

    def test_fraud_set(self):
        # connect·initiateCallAttempt·과금 조작 연산은 사기 집합에 포함.
        for op in (20, 32, 34, 35, 46):
            self.assertIn(op, CAP_FRAUD_OPERATIONS)
        # initialDP·activityTest 는 사기 집합 밖.
        self.assertNotIn(0, CAP_FRAUD_OPERATIONS)
        self.assertNotIn(55, CAP_FRAUD_OPERATIONS)


class ParseInitialDpTests(unittest.TestCase):
    def setUp(self):
        # InitialDP SEQUENCE { calledPartyNumber [2], callingPartyNumber [3] }.
        arg = _tlv(0x82, _num(_CALLED)) + _tlv(0x83, _num(_CALLING, nai=3))
        self.data = _tlv(0x30, arg)

    def test_extracts_both_numbers(self):
        res = parse_cap(self.data, operation_code=0)
        self.assertIsNotNone(res)
        self.assertEqual(res.all_digits, [_CALLED, _CALLING])

    def test_target_is_first(self):
        res = parse_cap(self.data, operation_code=0)
        self.assertEqual(res.target_number, _CALLED)
        self.assertTrue(res.has_number)

    def test_operation_metadata(self):
        res = parse_cap(self.data, operation_code=0)
        self.assertEqual(res.operation_name, "initialDP")
        self.assertFalse(res.is_fraud_operation)

    def test_payload_offset(self):
        res = parse_cap(self.data, operation_code=0)
        # SEQUENCE 내용은 태그(1)+길이(1) 다음.
        self.assertEqual(res.payload_offset, 2)


class ParseConnectTests(unittest.TestCase):
    def test_nested_destination_routing_address(self):
        # Connect SEQUENCE { destinationRoutingAddress [0] SEQUENCE OF CalledPartyNumber }.
        called = _tlv(0x04, _num(_CALLED))
        dra = _tlv(0xA0, _tlv(0x30, called))
        data = _tlv(0x30, dra)
        res = parse_cap(data, operation_code=20)
        self.assertEqual(res.target_number, _CALLED)
        self.assertEqual(res.operation_name, "connect")
        self.assertTrue(res.is_fraud_operation)


class ParseEdgeCaseTests(unittest.TestCase):
    def test_single_primitive_argument(self):
        # 구성형이 아닌 단일 번호 인자.
        data = _tlv(0x04, _num(_CALLED))
        res = parse_cap(data)
        self.assertEqual(res.target_number, _CALLED)

    def test_no_operation_code(self):
        data = _tlv(0x30, _tlv(0x82, _num(_CALLED)))
        res = parse_cap(data)
        self.assertIsNone(res.operation_name)
        self.assertFalse(res.is_fraud_operation)
        self.assertEqual(res.target_number, _CALLED)

    def test_unknown_nai_rejected(self):
        # nature of address 6(미정의 ISUP)·plan 1 → 번호로 채택 안 함.
        data = _tlv(0x30, _tlv(0x82, _num(_CALLED, nai=6, plan=1)))
        res = parse_cap(data)
        self.assertFalse(res.has_number)

    def test_unknown_plan_rejected(self):
        # plan 5(미정의 ISUP) → 채택 안 함.
        data = _tlv(0x30, _tlv(0x82, _num(_CALLED, nai=4, plan=5)))
        res = parse_cap(data)
        self.assertFalse(res.has_number)

    def test_empty_input(self):
        self.assertIsNone(parse_cap(b""))

    def test_offset_past_end(self):
        self.assertIsNone(parse_cap(_tlv(0x04, _num(_CALLED)), offset=99))

    def test_truncated_top_length(self):
        # 길이 옥텟만 있고 내용 없음 → 첫 TLV 읽되 내용 비어 번호 없음.
        res = parse_cap(b"\x30\x00")
        self.assertIsNotNone(res)
        self.assertFalse(res.has_number)

    def test_offset_support(self):
        prefix = b"\xff\xff"
        data = prefix + _tlv(0x04, _num(_CALLED))
        res = parse_cap(data, offset=len(prefix))
        self.assertEqual(res.target_number, _CALLED)
        # offset 이 번호 내용 절대 위치에 반영된다.
        self.assertEqual(res.numbers[0].offset, len(prefix) + 2)


if __name__ == "__main__":
    unittest.main()
