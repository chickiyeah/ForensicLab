"""forensiclab.iec104 단위 테스트 (stdlib unittest)."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from forensiclab.iec104 import (  # noqa: E402
    IEC104,
    IEC104_TYPES,
    IEC104_CAUSES,
    IEC104_U_FUNCTIONS,
    cause_name,
    type_name,
    u_function_name,
    parse_iec104,
)


def _apci(cf1, cf2=0, cf3=0, cf4=0, asdu=b""):
    """IEC 104 APDU 를 만든다(시작 0x68 + 길이 + 제어 4옥텟 + ASDU)."""
    length = 4 + len(asdu)
    return bytes([0x68, length, cf1, cf2, cf3, cf4]) + asdu


def _i_cf(ns, nr):
    """I-format 제어 4옥텟(N(S)·N(R) 15비트)."""
    cf1 = (ns << 1) & 0xFE
    cf2 = (ns >> 7) & 0xFF
    cf3 = (nr << 1) & 0xFE
    cf4 = (nr >> 7) & 0xFF
    return cf1, cf2, cf3, cf4


def _asdu(type_id, vsq=1, cot=6, orig=0, ca=1, objects=b""):
    """ASDU 헤더 6바이트 + 정보객체."""
    return bytes([type_id, vsq, cot, orig, ca & 0xFF, (ca >> 8) & 0xFF]) + objects


class FrameFormatTest(unittest.TestCase):
    def test_u_startdt_act(self):
        f = parse_iec104(_apci(0x07))
        self.assertIsNotNone(f)
        self.assertTrue(f.is_u_format)
        self.assertEqual(f.frame_format, "U")
        self.assertEqual(f.u_function, 0x07)
        self.assertEqual(f.u_function_name, "STARTDT_ACT")
        self.assertEqual(f.apdu_length, 4)
        self.assertIsNone(f.type_id)

    def test_u_testfr_con(self):
        f = parse_iec104(_apci(0x83))
        self.assertEqual(f.u_function_name, "TESTFR_CON")
        self.assertTrue(f.is_u_format)

    def test_s_format(self):
        f = parse_iec104(_apci(0x01, 0, 0x18, 0x00))
        self.assertTrue(f.is_s_format)
        self.assertEqual(f.frame_format, "S")
        self.assertEqual(f.recv_seq, 0x0C)  # 0x18 >> 1.
        self.assertIsNone(f.send_seq)
        self.assertIsNone(f.type_id)

    def test_i_format_sequence_numbers(self):
        cf1, cf2, cf3, cf4 = _i_cf(ns=300, nr=42)
        f = parse_iec104(_apci(cf1, cf2, cf3, cf4, _asdu(1)))
        self.assertTrue(f.is_i_format)
        self.assertEqual(f.send_seq, 300)
        self.assertEqual(f.recv_seq, 42)


class AsduTest(unittest.TestCase):
    def test_single_command_is_control(self):
        cf1, cf2, cf3, cf4 = _i_cf(0, 0)
        # C_SC_NA_1 (45), COT act(6).
        f = parse_iec104(_apci(cf1, cf2, cf3, cf4, _asdu(45, vsq=1, cot=6, ca=0x000A)))
        self.assertEqual(f.type_id, 45)
        self.assertEqual(f.type_name, "C_SC_NA_1")
        self.assertTrue(f.is_control)
        self.assertTrue(f.is_command)
        self.assertFalse(f.is_interrogation)
        self.assertEqual(f.cause, 6)
        self.assertEqual(f.cause_name, "act")
        self.assertEqual(f.common_address, 0x000A)
        self.assertEqual(f.num_objects, 1)

    def test_double_command_with_time(self):
        cf1, cf2, cf3, cf4 = _i_cf(1, 1)
        f = parse_iec104(_apci(cf1, cf2, cf3, cf4, _asdu(59, cot=6)))
        self.assertEqual(f.type_name, "C_DC_TA_1")
        self.assertTrue(f.is_control)

    def test_interrogation_is_recon(self):
        cf1, cf2, cf3, cf4 = _i_cf(0, 0)
        f = parse_iec104(_apci(cf1, cf2, cf3, cf4, _asdu(100, cot=6)))
        self.assertEqual(f.type_name, "C_IC_NA_1")
        self.assertTrue(f.is_interrogation)
        self.assertTrue(f.is_command)
        self.assertFalse(f.is_control)

    def test_monitoring_not_control(self):
        cf1, cf2, cf3, cf4 = _i_cf(0, 0)
        # M_SP_NA_1 (1), spontaneous(3).
        f = parse_iec104(_apci(cf1, cf2, cf3, cf4, _asdu(1, cot=3)))
        self.assertEqual(f.type_name, "M_SP_NA_1")
        self.assertFalse(f.is_control)
        self.assertFalse(f.is_command)
        self.assertEqual(f.cause_name, "spont")

    def test_negative_confirm(self):
        cf1, cf2, cf3, cf4 = _i_cf(0, 0)
        # COT act(6) | P/N(0x40) → 거부된 명령.
        f = parse_iec104(_apci(cf1, cf2, cf3, cf4, _asdu(45, cot=6 | 0x40)))
        self.assertTrue(f.negative)
        self.assertFalse(f.test)
        self.assertEqual(f.cause, 6)

    def test_test_bit(self):
        cf1, cf2, cf3, cf4 = _i_cf(0, 0)
        f = parse_iec104(_apci(cf1, cf2, cf3, cf4, _asdu(45, cot=6 | 0x80)))
        self.assertTrue(f.test)
        self.assertFalse(f.negative)

    def test_sq_bit_and_object_count(self):
        cf1, cf2, cf3, cf4 = _i_cf(0, 0)
        f = parse_iec104(_apci(cf1, cf2, cf3, cf4, _asdu(9, vsq=0x80 | 5)))
        self.assertTrue(f.sq)
        self.assertEqual(f.num_objects, 5)

    def test_originator_and_actterm(self):
        cf1, cf2, cf3, cf4 = _i_cf(0, 0)
        f = parse_iec104(_apci(cf1, cf2, cf3, cf4, _asdu(45, cot=10, orig=7)))
        self.assertEqual(f.originator_address, 7)
        self.assertEqual(f.cause_name, "actterm")

    def test_payload_offset(self):
        cf1, cf2, cf3, cf4 = _i_cf(0, 0)
        objects = b"\x01\x00\x00\x01"
        f = parse_iec104(_apci(cf1, cf2, cf3, cf4, _asdu(45, objects=objects)))
        # 시작 2 + 제어 4 + ASDU 헤더 6 = 12.
        self.assertEqual(f.payload_offset, 12)


class GuardTest(unittest.TestCase):
    def test_too_short(self):
        self.assertIsNone(parse_iec104(b"\x68\x04\x07"))

    def test_bad_start_byte(self):
        self.assertIsNone(parse_iec104(b"\x00\x04\x07\x00\x00\x00"))

    def test_length_too_small(self):
        self.assertIsNone(parse_iec104(b"\x68\x03\x07\x00\x00\x00"))

    def test_length_too_large(self):
        self.assertIsNone(parse_iec104(b"\x68\xFE\x07\x00\x00\x00"))

    def test_empty(self):
        self.assertIsNone(parse_iec104(b""))

    def test_negative_offset(self):
        self.assertIsNone(parse_iec104(_apci(0x07), offset=-1))


class TruncationTest(unittest.TestCase):
    def test_truncated_asdu(self):
        cf1, cf2, cf3, cf4 = _i_cf(0, 0)
        full = _apci(cf1, cf2, cf3, cf4, _asdu(45, objects=b"\x01\x02\x03\x04"))
        f = parse_iec104(full[:9])  # ASDU 잘림.
        self.assertIsNotNone(f)
        self.assertTrue(f.truncated)
        self.assertEqual(f.type_id, 45)  # 헤더 일부는 디코드.

    def test_not_truncated(self):
        cf1, cf2, cf3, cf4 = _i_cf(0, 0)
        f = parse_iec104(_apci(cf1, cf2, cf3, cf4, _asdu(45)))
        self.assertFalse(f.truncated)


class OffsetTest(unittest.TestCase):
    def test_offset_parsing(self):
        prefix = b"\xAA\xBB\xCC"
        frame = _apci(0x07)
        f = parse_iec104(prefix + frame, offset=3)
        self.assertIsNotNone(f)
        self.assertEqual(f.u_function_name, "STARTDT_ACT")


class HelperTest(unittest.TestCase):
    def test_type_name_known(self):
        self.assertEqual(type_name(45), "C_SC_NA_1")
        self.assertIn(100, IEC104_TYPES)

    def test_type_name_unknown(self):
        self.assertEqual(type_name(200), "type-200")

    def test_cause_name_masks_flags(self):
        # P/N·T 비트가 섞여도 하위 6비트만.
        self.assertEqual(cause_name(6 | 0x40 | 0x80), "act")

    def test_cause_name_unknown(self):
        self.assertEqual(cause_name(63), "cause-63")

    def test_u_function_name_unknown(self):
        self.assertEqual(u_function_name(0x00), "u-0x00")
        self.assertIn(0x07, IEC104_U_FUNCTIONS)

    def test_causes_table_nonempty(self):
        self.assertIn(20, IEC104_CAUSES)


class FrozenTest(unittest.TestCase):
    def test_frozen_dataclass(self):
        f = parse_iec104(_apci(0x07))
        with self.assertRaises(Exception):
            f.frame_format = "X"  # type: ignore[misc]


if __name__ == "__main__":
    unittest.main()
