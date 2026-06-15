"""forensiclab.dnp3 단위 테스트 (stdlib unittest)."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from forensiclab.dnp3 import (  # noqa: E402
    DNP3,
    DNP3_PRIMARY_FUNCTIONS,
    DNP3_SECONDARY_FUNCTIONS,
    DNP3_APPLICATION_FUNCTIONS,
    application_function_name,
    link_function_name,
    parse_dnp3,
)


def _frame(control, dest=0x0004, src=0x0001, user_data=b""):
    """DNP3 데이터 링크 프레임을 만든다(CRC 는 0으로 채움 — 미검증).

    헤더(8) + 헤더 CRC(2) + 사용자 데이터(16바이트 블록마다 CRC 2바이트)."""
    length = 5 + len(user_data)
    header = bytes([0x05, 0x64, length, control,
                    dest & 0xFF, (dest >> 8) & 0xFF,
                    src & 0xFF, (src >> 8) & 0xFF])
    out = bytearray(header)
    out += b"\x00\x00"  # 헤더 CRC.
    # 사용자 데이터 16바이트 블록 + CRC.
    i = 0
    while i < len(user_data):
        block = user_data[i:i + 16]
        out += block
        out += b"\x00\x00"
        i += 16
    return bytes(out)


# Control = DIR|PRM|func.  마스터 UNCONFIRMED_USER_DATA = 0xC4.
def _userdata(app_func, app_control=0xC0, transport=0xC0):
    return bytes([transport, app_control, app_func])


class LinkHeaderTest(unittest.TestCase):
    def test_request_link_status(self):
        # PRM=1, func=9 (REQUEST_LINK_STATUS), DIR=1 → 0xC9.
        f = parse_dnp3(_frame(0xC9, dest=0x000A, src=0x0003))
        self.assertIsNotNone(f)
        self.assertTrue(f.prm)
        self.assertTrue(f.dir)
        self.assertTrue(f.is_master)
        self.assertEqual(f.link_function, 9)
        self.assertEqual(f.link_function_name, "REQUEST_LINK_STATUS")
        self.assertEqual(f.destination, 0x000A)
        self.assertEqual(f.source, 0x0003)
        self.assertFalse(f.carries_user_data)
        self.assertIsNone(f.application_function)
        self.assertEqual(f.length, 5)
        self.assertEqual(f.user_data_length, 0)
        self.assertFalse(f.truncated)

    def test_secondary_ack(self):
        # PRM=0, func=0 (ACK), DIR=0 → 0x00.
        f = parse_dnp3(_frame(0x00))
        self.assertIsNotNone(f)
        self.assertFalse(f.prm)
        self.assertFalse(f.is_master)
        self.assertEqual(f.link_function_name, "ACK")
        self.assertFalse(f.carries_user_data)

    def test_link_status_response(self):
        # PRM=0, func=11 (LINK_STATUS) → 0x0B.
        f = parse_dnp3(_frame(0x0B))
        self.assertIsNotNone(f)
        self.assertEqual(f.link_function_name, "LINK_STATUS")

    def test_little_endian_addresses(self):
        f = parse_dnp3(_frame(0xC4, dest=0x1234, src=0xABCD))
        self.assertEqual(f.destination, 0x1234)
        self.assertEqual(f.source, 0xABCD)


class ApplicationTest(unittest.TestCase):
    def test_operate_breaker(self):
        # 마스터 CONFIRMED_USER_DATA(0xC3) + 응용 OPERATE(4) = 물리 조작.
        f = parse_dnp3(_frame(0xC3, user_data=_userdata(4)))
        self.assertIsNotNone(f)
        self.assertTrue(f.carries_user_data)
        self.assertEqual(f.link_function_name, "CONFIRMED_USER_DATA")
        self.assertEqual(f.application_function, 4)
        self.assertEqual(f.application_function_name, "OPERATE")
        self.assertTrue(f.is_control)
        self.assertTrue(f.is_request)
        self.assertFalse(f.is_response)
        self.assertEqual(f.transport_header, 0xC0)
        self.assertEqual(f.application_control, 0xC0)
        self.assertEqual(f.payload_offset, 10)

    def test_read_recon(self):
        # UNCONFIRMED_USER_DATA(0xC4) + READ(1) = 정찰, 조작 아님.
        f = parse_dnp3(_frame(0xC4, user_data=_userdata(1)))
        self.assertIsNotNone(f)
        self.assertEqual(f.application_function_name, "READ")
        self.assertFalse(f.is_control)
        self.assertTrue(f.is_request)

    def test_direct_operate(self):
        f = parse_dnp3(_frame(0xC3, user_data=_userdata(5)))
        self.assertEqual(f.application_function_name, "DIRECT_OPERATE")
        self.assertTrue(f.is_control)

    def test_unsolicited_response(self):
        # 아웃스테이션→마스터 비요청 보고: 응용 함수 130.
        f = parse_dnp3(_frame(0x44, user_data=_userdata(130)))  # PRM=1, DIR=0.
        self.assertIsNotNone(f)
        self.assertEqual(f.application_function_name, "UNSOLICITED_RESPONSE")
        self.assertTrue(f.is_response)
        self.assertFalse(f.is_request)
        self.assertFalse(f.is_control)

    def test_response(self):
        f = parse_dnp3(_frame(0xC3, user_data=_userdata(129)))
        self.assertEqual(f.application_function_name, "RESPONSE")
        self.assertTrue(f.is_response)


class GuardTest(unittest.TestCase):
    def test_too_short(self):
        self.assertIsNone(parse_dnp3(b"\x05\x64\x05\xc9\x04\x00\x01"))  # 7바이트.
        self.assertIsNone(parse_dnp3(b""))

    def test_bad_sync(self):
        f = _frame(0xC9)
        bad = b"\x05\x65" + f[2:]
        self.assertIsNone(parse_dnp3(bad))
        bad = b"\x06\x64" + f[2:]
        self.assertIsNone(parse_dnp3(bad))

    def test_bad_length(self):
        # Length < 5 거부.
        buf = bytes([0x05, 0x64, 0x04, 0xC9, 0x04, 0x00, 0x01, 0x00])
        self.assertIsNone(parse_dnp3(buf))

    def test_reserved_link_function(self):
        # PRM=1, func=5 (예약) 거부.
        self.assertIsNone(parse_dnp3(_frame(0xC5)))
        # PRM=0, func=9 (2차에 미정의) 거부.
        self.assertIsNone(parse_dnp3(_frame(0x09)))

    def test_negative_offset(self):
        self.assertIsNone(parse_dnp3(_frame(0xC9), offset=-1))


class OffsetTest(unittest.TestCase):
    def test_offset(self):
        prefix = b"\xde\xad\xbe\xef"
        buf = prefix + _frame(0xC3, dest=7, user_data=_userdata(2))
        f = parse_dnp3(buf, offset=len(prefix))
        self.assertIsNotNone(f)
        self.assertEqual(f.destination, 7)
        self.assertEqual(f.application_function_name, "WRITE")
        self.assertTrue(f.is_control)
        self.assertEqual(f.payload_offset, len(prefix) + 10)


class TruncationTest(unittest.TestCase):
    def test_truncated_user_data(self):
        # Length 가 사용자 데이터 10바이트를 선언하지만 일부만 존재.
        buf = bytes([0x05, 0x64, 5 + 10, 0xC3, 0x04, 0x00, 0x01, 0x00]) + b"\x00\x00" + b"\xc0\xc0\x04"
        f = parse_dnp3(buf)
        self.assertIsNotNone(f)
        self.assertTrue(f.truncated)
        self.assertEqual(f.user_data_length, 10)
        # 응용 함수는 가용분(첫 3바이트)으로 디코드됨.
        self.assertEqual(f.application_function_name, "OPERATE")

    def test_truncated_app_header(self):
        # 사용자 데이터를 선언하지만 전송 헤더만 존재(응용 함수 미디코드).
        buf = bytes([0x05, 0x64, 5 + 3, 0xC3, 0x04, 0x00, 0x01, 0x00]) + b"\x00\x00" + b"\xc0"
        f = parse_dnp3(buf)
        self.assertIsNotNone(f)
        self.assertEqual(f.transport_header, 0xC0)
        self.assertIsNone(f.application_function)

    def test_packet_length_two_blocks(self):
        # 사용자 데이터 20바이트 → 블록 2개 → CRC 4바이트.
        f = parse_dnp3(_frame(0xC3, user_data=bytes(20)))
        self.assertEqual(f.user_data_length, 20)
        # 10(헤더+CRC) + 20 + 2*2 = 34.
        self.assertEqual(f.packet_length, 34)


class HelperTest(unittest.TestCase):
    def test_link_function_name_helper(self):
        self.assertEqual(link_function_name(0xC3), "CONFIRMED_USER_DATA")  # PRM=1.
        self.assertEqual(link_function_name(0x03), "reserved-3")  # PRM=0 에 미정의.
        self.assertEqual(link_function_name(0x0B), "LINK_STATUS")

    def test_application_function_name_helper(self):
        self.assertEqual(application_function_name(4), "OPERATE")
        self.assertEqual(application_function_name(200), "app-200")

    def test_tables_present(self):
        self.assertIn(3, DNP3_PRIMARY_FUNCTIONS)
        self.assertIn(0, DNP3_SECONDARY_FUNCTIONS)
        self.assertIn(4, DNP3_APPLICATION_FUNCTIONS)

    def test_frozen_dataclass(self):
        f = parse_dnp3(_frame(0xC9))
        with self.assertRaises(Exception):
            f.source = 9  # type: ignore[misc]


if __name__ == "__main__":
    unittest.main()
