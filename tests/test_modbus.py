"""forensiclab.modbus 단위 테스트 (stdlib unittest)."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from forensiclab.modbus import (  # noqa: E402
    Modbus,
    MODBUS_FUNCTION_NAMES,
    MODBUS_EXCEPTION_NAMES,
    exception_name,
    function_name,
    parse_modbus,
)


def _adu(tid=0x0001, pid=0x0000, unit=0x01, pdu=b"\x03\x00\x00\x00\x0a"):
    """MBAP 헤더 + PDU 로 Modbus/TCP ADU 한 개를 만든다."""
    length = 1 + len(pdu)  # Unit ID + PDU.
    return (
        bytes([(tid >> 8) & 0xFF, tid & 0xFF, (pid >> 8) & 0xFF, pid & 0xFF,
               (length >> 8) & 0xFF, length & 0xFF, unit & 0xFF])
        + pdu
    )


class HeaderTest(unittest.TestCase):
    def test_read_holding_registers(self):
        # FC 3, 시작 주소 0x0000, 개수 10.
        m = parse_modbus(_adu(tid=0x1234, unit=5, pdu=b"\x03\x00\x00\x00\x0a"))
        self.assertIsNotNone(m)
        self.assertEqual(m.transaction_id, 0x1234)
        self.assertEqual(m.protocol_id, 0)
        self.assertEqual(m.unit_id, 5)
        self.assertEqual(m.function_code, 3)
        self.assertEqual(m.base_function, 3)
        self.assertEqual(m.function_name, "Read Holding Registers")
        self.assertFalse(m.is_exception)
        self.assertTrue(m.is_read)
        self.assertFalse(m.is_write)
        self.assertEqual(m.address, 0x0000)
        self.assertEqual(m.count, 10)
        self.assertEqual(m.length, 6)
        self.assertEqual(m.pdu_offset, 7)
        self.assertEqual(m.pdu_length, 5)
        self.assertFalse(m.truncated)
        self.assertEqual(m.packet_length, len(_adu(pdu=b"\x03\x00\x00\x00\x0a")))

    def test_offset(self):
        prefix = b"\xde\xad\xbe\xef"
        buf = prefix + _adu(tid=0x0007, pdu=b"\x04\x00\x10\x00\x02")
        m = parse_modbus(buf, offset=len(prefix))
        self.assertIsNotNone(m)
        self.assertEqual(m.transaction_id, 7)
        self.assertEqual(m.function_name, "Read Input Registers")
        self.assertEqual(m.address, 0x10)
        self.assertEqual(m.count, 2)


class WriteTest(unittest.TestCase):
    def test_write_single_coil(self):
        # FC 5: 주소 0x00AC, 값 0xFF00(ON).
        m = parse_modbus(_adu(pdu=b"\x05\x00\xac\xff\x00"))
        self.assertIsNotNone(m)
        self.assertEqual(m.function_name, "Write Single Coil")
        self.assertTrue(m.is_write)
        self.assertFalse(m.is_read)
        self.assertEqual(m.address, 0x00AC)
        self.assertEqual(m.count, 0xFF00)  # 단일 쓰기는 count 에 쓰인 값.

    def test_write_single_register(self):
        m = parse_modbus(_adu(pdu=b"\x06\x00\x01\x00\x03"))
        self.assertIsNotNone(m)
        self.assertEqual(m.function_name, "Write Single Register")
        self.assertTrue(m.is_write)
        self.assertEqual(m.address, 1)
        self.assertEqual(m.count, 3)

    def test_write_multiple_registers(self):
        # FC 16: 주소 0x0001, 개수 2, 바이트수 4, 데이터.
        pdu = b"\x10\x00\x01\x00\x02\x04\x00\x0a\x01\x02"
        m = parse_modbus(_adu(pdu=pdu))
        self.assertIsNotNone(m)
        self.assertEqual(m.function_name, "Write Multiple Registers")
        self.assertTrue(m.is_write)
        self.assertEqual(m.address, 1)
        self.assertEqual(m.count, 2)


class ExceptionTest(unittest.TestCase):
    def test_illegal_data_address(self):
        # FC 3 예외 응답: 0x83, 예외 코드 2.
        m = parse_modbus(_adu(pdu=b"\x83\x02"))
        self.assertIsNotNone(m)
        self.assertTrue(m.is_exception)
        self.assertEqual(m.function_code, 0x83)
        self.assertEqual(m.base_function, 3)
        self.assertEqual(m.function_name, "Read Holding Registers")
        self.assertEqual(m.exception_code, 2)
        self.assertEqual(m.exception_name, "Illegal Data Address")
        self.assertFalse(m.is_read)  # 예외는 읽기/쓰기로 분류하지 않음.
        self.assertFalse(m.is_write)
        self.assertIsNone(m.address)

    def test_illegal_function(self):
        m = parse_modbus(_adu(pdu=b"\x81\x01"))
        self.assertIsNotNone(m)
        self.assertTrue(m.is_exception)
        self.assertEqual(m.exception_name, "Illegal Function")


class GuardTest(unittest.TestCase):
    def test_too_short(self):
        self.assertIsNone(parse_modbus(b"\x00\x01\x00\x00\x00\x06\x01"))  # 7바이트.
        self.assertIsNone(parse_modbus(b""))

    def test_nonzero_protocol_id(self):
        self.assertIsNone(parse_modbus(_adu(pid=0x0001)))

    def test_bad_length(self):
        # Length = 1 (Unit ID 만, 함수 코드 없음) → 거부.
        buf = bytes([0, 1, 0, 0, 0, 1, 1, 3])
        self.assertIsNone(parse_modbus(buf))
        # Length 초과(255).
        buf = bytes([0, 1, 0, 0, 0, 255, 1, 3, 0, 0, 0, 10])
        self.assertIsNone(parse_modbus(buf))

    def test_unknown_function(self):
        # 함수 코드 0 과 미정의(예: 50) 거부.
        self.assertIsNone(parse_modbus(_adu(pdu=b"\x00\x00")))
        self.assertIsNone(parse_modbus(_adu(pdu=b"\x32\x00\x00")))

    def test_negative_offset(self):
        self.assertIsNone(parse_modbus(_adu(), offset=-1))

    def test_user_defined_function(self):
        m = parse_modbus(_adu(pdu=b"\x65\x00\x00"))  # 0x65 = 101, 사용자 정의.
        self.assertIsNotNone(m)
        self.assertEqual(m.base_function, 101)
        self.assertTrue(m.function_name.startswith("User-Defined"))


class TruncationTest(unittest.TestCase):
    def test_truncated_pdu(self):
        # Length 가 13(=12바이트 PDU) 라 선언하지만 PDU 4바이트만 존재.
        buf = bytes([0, 1, 0, 0, 0, 13, 1]) + b"\x10\x00\x01"
        m = parse_modbus(buf)
        self.assertIsNotNone(m)
        self.assertTrue(m.truncated)
        self.assertEqual(m.length, 13)
        self.assertEqual(m.pdu_length, 3)  # 가용분만.
        self.assertEqual(m.base_function, 16)
        self.assertIsNone(m.count)  # 5바이트 미만이라 개수 미디코드.

    def test_exact_min_message(self):
        # MBAP 7 + 함수 코드 1 = 8바이트(데이터 없는 함수, 예: FC 7).
        buf = bytes([0, 1, 0, 0, 0, 2, 1, 7])
        m = parse_modbus(buf)
        self.assertIsNotNone(m)
        self.assertEqual(m.function_name, "Read Exception Status")
        self.assertTrue(m.is_read)
        self.assertIsNone(m.address)
        self.assertFalse(m.truncated)


class HelperTest(unittest.TestCase):
    def test_function_name_helper(self):
        self.assertEqual(function_name(3), "Read Holding Registers")
        self.assertEqual(function_name(0x83), "Read Holding Registers")  # 예외 비트 제거.
        self.assertTrue(function_name(50).startswith("function-"))

    def test_exception_name_helper(self):
        self.assertEqual(exception_name(1), "Illegal Function")
        self.assertEqual(exception_name(99), "exception-99")

    def test_tables_present(self):
        self.assertIn(16, MODBUS_FUNCTION_NAMES)
        self.assertIn(2, MODBUS_EXCEPTION_NAMES)

    def test_frozen_dataclass(self):
        m = parse_modbus(_adu())
        with self.assertRaises(Exception):
            m.unit_id = 9  # type: ignore[misc]


if __name__ == "__main__":
    unittest.main()
