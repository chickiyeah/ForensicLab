"""forensiclab.map 단위 테스트 (stdlib unittest)."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from forensiclab.map import (  # noqa: E402
    MapArgument,
    MapIdentity,
    decode_address_string,
    decode_tbcd,
    parse_map,
)


def _tlv(tag, content):
    """짧은 형식(길이<128) BER TLV 하나를 짠다."""
    assert len(content) < 0x80, "테스트 헬퍼는 짧은 형식만"
    return bytes([tag, len(content)]) + content


def _tbcd(digits):
    """숫자열을 TBCD(하위 nibble 먼저, 홀수면 후행 0xF filler)로 인코드."""
    out = bytearray()
    pairs = [digits[i:i + 2] for i in range(0, len(digits), 2)]
    for pair in pairs:
        lo = int(pair[0])
        hi = int(pair[1]) if len(pair) == 2 else 0x0F
        out.append((hi << 4) | lo)
    return bytes(out)


# 국제 MSISDN: octet1 0x91(ext|international|ISDN) + TBCD 숫자.
_MSISDN = "821012345678"
_MSISDN_ADDR = b"\x91" + _tbcd(_MSISDN)
# IMSI(15자리): 선두 plan 옥텟 없는 맨 TBCD.
_IMSI = "450050123456789"
_IMSI_TBCD = _tbcd(_IMSI)


class TbcdTests(unittest.TestCase):
    def test_even_length(self):
        self.assertEqual(decode_tbcd(_tbcd("1234")), "1234")

    def test_odd_length_filler(self):
        self.assertEqual(decode_tbcd(_tbcd("12345")), "12345")

    def test_star_hash(self):
        # nibble 0xA=* , 0xB=#.
        self.assertEqual(decode_tbcd(b"\xba"), "*#")

    def test_imsi_roundtrip(self):
        self.assertEqual(decode_tbcd(_IMSI_TBCD), _IMSI)


class AddressStringTests(unittest.TestCase):
    def test_international_isdn(self):
        out = decode_address_string(_MSISDN_ADDR)
        self.assertIsNotNone(out)
        digits, nature, plan = out
        self.assertEqual(digits, _MSISDN)
        self.assertEqual(nature, 1)  # international.
        self.assertEqual(plan, 1)    # ISDN.

    def test_too_short(self):
        self.assertIsNone(decode_address_string(b"\x91"))
        self.assertIsNone(decode_address_string(b""))


class IdentityFormTests(unittest.TestCase):
    def test_address_form_from_sequence(self):
        # SRI-SM 류: SEQUENCE { msisdn [0] IMPLICIT AddressString }.
        arg = _tlv(0x30, _tlv(0x80, _MSISDN_ADDR))
        m = parse_map(arg, operation_code=45)
        self.assertIsInstance(m, MapArgument)
        self.assertTrue(m.has_identity)
        self.assertEqual(len(m.identities), 1)
        ident = m.identities[0]
        self.assertIsInstance(ident, MapIdentity)
        self.assertEqual(ident.form, "address")
        self.assertTrue(ident.is_address)
        self.assertEqual(ident.digits, _MSISDN)
        self.assertEqual(ident.nature_name, "international")
        self.assertEqual(ident.numbering_plan_name, "ISDN-telephony")
        self.assertEqual(m.target_digits, _MSISDN)

    def test_digits_form_bare_imsi(self):
        # sendAuthenticationInfo v2: 인자 자체가 IMSI(OCTET STRING).
        arg = _tlv(0x04, _IMSI_TBCD)
        m = parse_map(arg, operation_code=56)
        self.assertTrue(m.has_identity)
        ident = m.identities[0]
        self.assertEqual(ident.form, "digits")
        self.assertFalse(ident.is_address)
        self.assertEqual(ident.digits, _IMSI)
        self.assertIsNone(ident.nature_of_address)
        self.assertIsNone(ident.nature_name)
        self.assertIsNone(ident.numbering_plan_name)

    def test_nested_subscriber_identity(self):
        # ATI 류: SEQUENCE { subscriberIdentity [0] { msisdn [1] AddressString } }.
        inner = _tlv(0xA0, _tlv(0x81, _MSISDN_ADDR))
        arg = _tlv(0x30, inner)
        m = parse_map(arg, operation_code=71)
        self.assertTrue(m.has_identity)
        self.assertEqual(m.target_digits, _MSISDN)
        self.assertEqual(m.identities[0].form, "address")

    def test_multiple_identities(self):
        # SEQUENCE { msisdn [0] address, serviceCentre [2] address }.
        sc = "447700900123"
        arg = _tlv(0x30, _tlv(0x80, _MSISDN_ADDR) + _tlv(0x82, b"\x91" + _tbcd(sc)))
        m = parse_map(arg, operation_code=45)
        self.assertEqual(len(m.identities), 2)
        self.assertEqual(m.all_digits, [_MSISDN, sc])


class OperationTests(unittest.TestCase):
    def test_attack_operation_name(self):
        m = parse_map(_tlv(0x04, _IMSI_TBCD), operation_code=45)
        self.assertEqual(m.operation_name, "sendRoutingInfoForSM")
        self.assertTrue(m.is_attack_operation)

    def test_non_attack_operation(self):
        m = parse_map(_tlv(0x04, _IMSI_TBCD), operation_code=2)  # updateLocation.
        self.assertEqual(m.operation_name, "updateLocation")
        self.assertFalse(m.is_attack_operation)

    def test_unknown_operation(self):
        m = parse_map(_tlv(0x04, _IMSI_TBCD), operation_code=200)
        self.assertEqual(m.operation_name, "op-200")

    def test_no_operation_code(self):
        # operationCode 없이도 신원 추출은 동작.
        m = parse_map(_tlv(0x04, _IMSI_TBCD))
        self.assertIsNone(m.operation_name)
        self.assertFalse(m.is_attack_operation)
        self.assertEqual(m.target_digits, _IMSI)


class GuardTests(unittest.TestCase):
    def test_empty(self):
        self.assertIsNone(parse_map(b""))

    def test_negative_offset(self):
        self.assertIsNone(parse_map(_tlv(0x04, _IMSI_TBCD), offset=-1))

    def test_offset_past_end(self):
        self.assertIsNone(parse_map(b"\x04\x02\x12\x34", offset=10))

    def test_unreadable_first_tlv(self):
        # 태그만 있고 길이 옥텟 없음.
        self.assertIsNone(parse_map(b"\x30"))

    def test_no_identity_found(self):
        # 너무 짧아 신원 자격(자릿수) 미달 → 빈 신원, None 아님.
        m = parse_map(_tlv(0x04, b"\x12"))
        self.assertIsNotNone(m)
        self.assertFalse(m.has_identity)
        self.assertIsNone(m.target_digits)
        self.assertEqual(m.all_digits, [])

    def test_offset_support(self):
        blob = b"\xde\xad" + _tlv(0x04, _IMSI_TBCD)
        m = parse_map(blob, operation_code=56, offset=2)
        self.assertEqual(m.target_digits, _IMSI)
        self.assertEqual(m.operation_name, "sendAuthenticationInfo")

    def test_end_bound(self):
        # end 로 인자 경계를 제한해도 동작.
        arg = _tlv(0x04, _IMSI_TBCD)
        m = parse_map(arg + b"\xff\xff", operation_code=56, end=len(arg))
        self.assertEqual(m.target_digits, _IMSI)

    def test_truncated_sequence(self):
        # SEQUENCE 길이는 길게 주장하나 내용 모자람 → 담을 수 있는 신원까지.
        body = _tlv(0x80, _MSISDN_ADDR)
        raw = bytes([0x30, 0x40]) + body  # 선언 길이 0x40 > 실제.
        m = parse_map(raw, operation_code=45)
        self.assertIsNotNone(m)
        self.assertEqual(m.target_digits, _MSISDN)


if __name__ == "__main__":
    unittest.main()
