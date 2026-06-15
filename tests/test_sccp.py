"""forensiclab.sccp 단위 테스트 (stdlib unittest)."""

import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from forensiclab.sccp import (  # noqa: E402
    SCCP_CONNECTIONLESS_TYPES,
    Sccp,
    SccpAddress,
    parse_sccp,
)


def _address(ai, point_code=None, ssn=None, gt_body=b""):
    """주소 파라미터(length + AI + [PC] + [SSN] + GT)를 짠다."""
    content = bytes([ai])
    if point_code is not None:
        content += struct.pack("<H", point_code & 0x3FFF)
    if ssn is not None:
        content += bytes([ssn])
    content += gt_body
    return bytes([len(content)]) + content


def _bcd(digits):
    """E.164 숫자 문자열을 BCD(low nibble first, 홀수면 0xF filler)로 인코드."""
    nibbles = [int(d) for d in digits]
    if len(nibbles) % 2:
        nibbles.append(0x0F)
    out = bytearray()
    for i in range(0, len(nibbles), 2):
        out.append(nibbles[i] | (nibbles[i + 1] << 4))
    return bytes(out)


def _udt(protocol_class=0, called=b"", calling=b"", user_data=b"tcap"):
    """UDT(0x09) 메시지를 1옥텟 포인터로 짠다."""
    # 포인터는 자기 위치 기준 상대 오프셋. 고정부: type+class+ptr*3 = 5 옥텟.
    # 가변부: called, calling, data(앞에 length 1옥텟).
    p_called = 3                       # ptr_called(인덱스2) → 가변부 시작.
    p_calling = 2 + len(called)        # ptr_calling(인덱스3) 기준.
    p_data = 1 + len(called) + len(calling)  # ptr_data(인덱스4) 기준.
    data_field = bytes([len(user_data)]) + user_data
    return (
        bytes([0x09, protocol_class, p_called, p_calling, p_data])
        + called + calling + data_field
    )


class MessageTypeTests(unittest.TestCase):
    def test_unitdata_name(self):
        m = parse_sccp(_udt())
        self.assertIsInstance(m, Sccp)
        self.assertEqual(m.message_type, 0x09)
        self.assertEqual(m.message_type_name, "UDT")
        self.assertTrue(m.is_connectionless)
        self.assertTrue(m.is_unitdata)
        self.assertFalse(m.is_unitdata_service)

    def test_connection_oriented_type_only(self):
        # CR(0x01): 타입만 식별, 주소 없음.
        m = parse_sccp(bytes([0x01, 0x00, 0x00, 0x00]))
        self.assertEqual(m.message_type_name, "CR")
        self.assertFalse(m.is_connectionless)
        self.assertIsNone(m.called_party)
        self.assertIsNone(m.calling_party)

    def test_connectionless_set(self):
        self.assertEqual(
            SCCP_CONNECTIONLESS_TYPES,
            frozenset({0x09, 0x0A, 0x11, 0x12, 0x13, 0x14}),
        )


class AddressTests(unittest.TestCase):
    def test_called_party_ssn_and_gt(self):
        # AI: PC 없음(0x00) + SSN(0x02) + GTI 4(0x10) + route on GT(bit7=0).
        ai = 0x02 | (4 << 2)
        gt_header = bytes([0x00, 0x11, 0x04])  # TT, NP/ES, NAI(임의).
        called = _address(ai, ssn=6, gt_body=gt_header + _bcd("821012345678"))
        m = parse_sccp(_udt(called=called))
        addr = m.called_party
        self.assertIsInstance(addr, SccpAddress)
        self.assertTrue(addr.has_ssn)
        self.assertFalse(addr.has_point_code)
        self.assertEqual(addr.ssn, 6)
        self.assertEqual(addr.ssn_name, "HLR")
        self.assertEqual(addr.gti, 4)
        self.assertEqual(addr.routing_indicator, "GT")
        self.assertEqual(addr.global_title_digits, "821012345678")

    def test_point_code_present(self):
        ai = 0x01 | 0x02  # PC + SSN, GTI 0.
        called = _address(ai, point_code=0x1234, ssn=8)
        m = parse_sccp(_udt(called=called))
        addr = m.called_party
        self.assertTrue(addr.has_point_code)
        self.assertEqual(addr.point_code, 0x1234 & 0x3FFF)
        self.assertEqual(addr.ssn, 8)
        self.assertEqual(addr.ssn_name, "MSC")

    def test_route_on_ssn_indicator(self):
        ai = 0x02 | 0x40  # SSN + RI bit7.
        called = _address(ai, ssn=5)
        m = parse_sccp(_udt(called=called))
        self.assertTrue(m.called_party.route_on_ssn)
        self.assertEqual(m.called_party.routing_indicator, "SSN")
        self.assertEqual(m.called_party.ssn_name, "MAP")

    def test_calling_party_distinct(self):
        called = _address(0x02, ssn=6, gt_body=b"")
        calling = _address(0x02, ssn=8)
        m = parse_sccp(_udt(called=called, calling=calling))
        self.assertEqual(m.called_party.ssn, 6)
        self.assertEqual(m.calling_party.ssn, 8)

    def test_odd_length_gt_digits(self):
        ai = 0x02 | (4 << 2)
        gt = bytes([0x00, 0x11, 0x04]) + _bcd("12345")  # 홀수 → filler.
        called = _address(ai, ssn=6, gt_body=gt)
        m = parse_sccp(_udt(called=called))
        self.assertEqual(m.called_party.global_title_digits, "12345")

    def test_unknown_ssn_name(self):
        called = _address(0x02, ssn=200)
        m = parse_sccp(_udt(called=called))
        self.assertEqual(m.called_party.ssn_name, "ssn-200")


class DataPointerTests(unittest.TestCase):
    def test_data_offset_points_to_user_data(self):
        m = parse_sccp(_udt(user_data=b"TCAPDATA"))
        self.assertIsNotNone(m.data_offset)
        # data_offset 은 length 옥텟; 그 다음이 user_data.
        raw = _udt(user_data=b"TCAPDATA")
        self.assertEqual(raw[m.data_offset], len(b"TCAPDATA"))

    def test_protocol_class_value(self):
        m = parse_sccp(_udt(protocol_class=0x80 | 0x01))
        self.assertEqual(m.protocol_class, 0x81)
        self.assertEqual(m.protocol_class_value, 1)


class XudtTests(unittest.TestCase):
    def test_xudt_hop_counter(self):
        # XUDT(0x11): type+class+hop+ptr*4. 포인터 base 인덱스 = 3.
        hop = 15
        called = _address(0x02, ssn=6)
        calling = _address(0x02, ssn=8)
        data_field = b"\x04tcap"
        p_called = 4                          # 인덱스3.
        p_calling = 3 + len(called)           # 인덱스4.
        p_data = 2 + len(called) + len(calling)  # 인덱스5.
        p_opt = 0                             # 인덱스6: optional 없음.
        raw = (
            bytes([0x11, 0x01, hop, p_called, p_calling, p_data, p_opt])
            + called + calling + data_field
        )
        m = parse_sccp(raw)
        self.assertEqual(m.message_type_name, "XUDT")
        self.assertEqual(m.hop_counter, hop)
        self.assertEqual(m.protocol_class, 0x01)
        self.assertEqual(m.called_party.ssn, 6)
        self.assertEqual(m.calling_party.ssn, 8)

    def test_xudts_return_cause(self):
        # XUDTS(0x12): 두 번째 옥텟이 return_cause.
        called = _address(0x02, ssn=6)
        calling = _address(0x02, ssn=8)
        p_called = 4
        p_calling = 3 + len(called)
        p_data = 2 + len(called) + len(calling)
        raw = (
            bytes([0x12, 0x07, 0, p_called, p_calling, p_data, 0])
            + called + calling + b"\x00"
        )
        m = parse_sccp(raw)
        self.assertEqual(m.message_type_name, "XUDTS")
        self.assertTrue(m.is_unitdata_service)
        self.assertEqual(m.return_cause, 0x07)
        self.assertIsNone(m.protocol_class)


class GuardTests(unittest.TestCase):
    def test_empty(self):
        self.assertIsNone(parse_sccp(b""))

    def test_negative_offset(self):
        self.assertIsNone(parse_sccp(_udt(), offset=-1))

    def test_offset_past_end(self):
        self.assertIsNone(parse_sccp(b"\x09", offset=5))

    def test_undefined_message_type(self):
        # 0x00·0xFF 등은 Q.713 정의 밖 → 오탐 가드.
        self.assertIsNone(parse_sccp(b"\x00\x00\x00"))
        self.assertIsNone(parse_sccp(b"\xff\x00\x00"))

    def test_offset_support(self):
        blob = b"\xde\xad" + _udt(called=_address(0x02, ssn=6))
        m = parse_sccp(blob, offset=2)
        self.assertEqual(m.message_type_name, "UDT")
        self.assertEqual(m.called_party.ssn, 6)


class TruncationTests(unittest.TestCase):
    def test_truncated_fixed_part(self):
        # UDT 인데 포인터 일부만 존재 → 주소 None, 클래스만.
        m = parse_sccp(bytes([0x09, 0x02, 0x03]))
        self.assertIsNotNone(m)
        self.assertEqual(m.protocol_class, 0x02)
        self.assertIsNone(m.called_party)
        self.assertIsNone(m.data_offset)

    def test_truncated_address(self):
        # length 는 10 을 주장하나 내용이 모자람 → 풀 수 있는 만큼만.
        ai = 0x02 | (4 << 2)
        broken_called = bytes([10, ai, 6])  # length 10 주장, 실제 2바이트.
        raw = (
            bytes([0x09, 0x00, 3, 2 + len(broken_called),
                   1 + len(broken_called)])
            + broken_called + b"\x01x"
        )
        m = parse_sccp(raw)
        self.assertIsNotNone(m.called_party)
        self.assertEqual(m.called_party.ssn, 6)
        self.assertIsNone(m.called_party.global_title_digits)

    def test_zero_pointer_means_absent(self):
        # ptr_data = 0 → data_offset None.
        raw = bytes([0x09, 0x00, 3, 2, 0]) + _address(0x02, ssn=6)
        m = parse_sccp(raw)
        self.assertIsNone(m.data_offset)
        self.assertIsNotNone(m.called_party)


if __name__ == "__main__":
    unittest.main()
