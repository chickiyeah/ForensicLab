"""forensiclab.s7comm 단위 테스트 (stdlib unittest)."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from forensiclab.s7comm import (  # noqa: E402
    S7comm,
    S7_FUNCTION_NAMES,
    S7_ROSCTR_NAMES,
    function_name,
    parse_s7comm,
    rosctr_name,
)


def _s7(rosctr=0x01, pdu_ref=0x0001, parameter=b"\x04\x01\x12\x0a", data=b"",
        error_class=None, error_code=None):
    """TPKT + COTP(DT Data) + S7comm 메시지 한 개를 만든다."""
    param_len = len(parameter)
    data_len = len(data)
    s7 = bytes([0x32, rosctr, 0x00, 0x00,
                (pdu_ref >> 8) & 0xFF, pdu_ref & 0xFF,
                (param_len >> 8) & 0xFF, param_len & 0xFF,
                (data_len >> 8) & 0xFF, data_len & 0xFF])
    if error_class is not None:
        s7 += bytes([error_class, error_code or 0])
    s7 += parameter + data
    cotp = bytes([0x02, 0xF0, 0x80])  # LI=2, DT Data, TPDU-NR/EOT.
    body = cotp + s7
    total = 4 + len(body)
    tpkt = bytes([0x03, 0x00, (total >> 8) & 0xFF, total & 0xFF])
    return tpkt + body


class HeaderTest(unittest.TestCase):
    def test_read_var_job(self):
        m = parse_s7comm(_s7(rosctr=0x01, pdu_ref=0x1234, parameter=b"\x04\x01\x12\x0a"))
        self.assertIsNotNone(m)
        self.assertEqual(m.protocol_id, 0x32)
        self.assertEqual(m.cotp_pdu_type, 0xF0)
        self.assertEqual(m.rosctr, 0x01)
        self.assertEqual(m.rosctr_name, "Job")
        self.assertEqual(m.pdu_reference, 0x1234)
        self.assertEqual(m.parameter_length, 4)
        self.assertEqual(m.function_code, 0x04)
        self.assertEqual(m.function_name, "Read Var")
        self.assertTrue(m.is_request)
        self.assertTrue(m.is_read)
        self.assertFalse(m.is_write)
        self.assertFalse(m.has_error)
        self.assertEqual(m.parameter_offset, 4 + 3 + 10)  # TPKT+COTP+S7헤더.
        self.assertFalse(m.truncated)

    def test_offset(self):
        prefix = b"\xde\xad\xbe\xef"
        buf = prefix + _s7(pdu_ref=7, parameter=b"\x05\x01\x12\x0a")
        m = parse_s7comm(buf, offset=len(prefix))
        self.assertIsNotNone(m)
        self.assertEqual(m.pdu_reference, 7)
        self.assertEqual(m.function_name, "Write Var")
        self.assertTrue(m.is_write)


class FunctionTest(unittest.TestCase):
    def test_write_var(self):
        m = parse_s7comm(_s7(parameter=b"\x05\x01\x12\x0a"))
        self.assertTrue(m.is_write)
        self.assertFalse(m.is_read)

    def test_plc_control(self):
        m = parse_s7comm(_s7(parameter=b"\x28\x00"))
        self.assertEqual(m.function_name, "PLC Control")
        self.assertTrue(m.is_control)

    def test_plc_stop(self):
        m = parse_s7comm(_s7(parameter=b"\x29\x00"))
        self.assertEqual(m.function_name, "PLC Stop")
        self.assertTrue(m.is_stop)

    def test_download_is_injection(self):
        # 블록 다운로드 = Stuxnet 식 PLC 로직 주입.
        m = parse_s7comm(_s7(parameter=b"\x1a\x00"))
        self.assertEqual(m.function_name, "Request Download")
        self.assertTrue(m.is_download)
        self.assertFalse(m.is_upload)

    def test_upload(self):
        m = parse_s7comm(_s7(parameter=b"\x1d\x00"))
        self.assertTrue(m.is_upload)

    def test_setup_communication(self):
        m = parse_s7comm(_s7(parameter=b"\xf0\x00\x00\x01\x00\x01\x01\xe0"))
        self.assertEqual(m.function_name, "Setup Communication")


class ResponseTest(unittest.TestCase):
    def test_ack_data_with_error(self):
        # Ack_Data(0x03): 오류 클래스/코드 2바이트가 헤더에 추가.
        m = parse_s7comm(_s7(rosctr=0x03, parameter=b"\x04\x01",
                             error_class=0x85, error_code=0x00))
        self.assertIsNotNone(m)
        self.assertEqual(m.rosctr_name, "Ack_Data")
        self.assertTrue(m.is_response)
        self.assertFalse(m.is_request)
        self.assertEqual(m.error_class, 0x85)
        self.assertTrue(m.has_error)
        # 오류 2바이트만큼 파라미터 오프셋이 밀린다.
        self.assertEqual(m.parameter_offset, 4 + 3 + 12)

    def test_ack_no_error(self):
        m = parse_s7comm(_s7(rosctr=0x02, parameter=b"", error_class=0x00,
                             error_code=0x00))
        self.assertIsNotNone(m)
        self.assertEqual(m.rosctr_name, "Ack")
        self.assertFalse(m.has_error)
        self.assertIsNone(m.function_code)  # 파라미터 없음.

    def test_userdata(self):
        m = parse_s7comm(_s7(rosctr=0x07, parameter=b"\x00\x01\x12\x04"))
        self.assertTrue(m.is_userdata)
        self.assertFalse(m.is_request)


class GuardTest(unittest.TestCase):
    def test_too_short(self):
        self.assertIsNone(parse_s7comm(b""))
        self.assertIsNone(parse_s7comm(b"\x03\x00\x00\x16"))

    def test_bad_tpkt_version(self):
        buf = bytearray(_s7())
        buf[0] = 0x04
        self.assertIsNone(parse_s7comm(bytes(buf)))

    def test_not_dt_data(self):
        # COTP CR(0xE0) 연결 요청 — S7 페이로드 없음 → 거부.
        buf = bytearray(_s7())
        buf[5] = 0xE0  # COTP PDU type (TPKT 4 + LI 1 = index 5).
        self.assertIsNone(parse_s7comm(bytes(buf)))

    def test_bad_protocol_id(self):
        buf = bytearray(_s7())
        buf[7] = 0x33  # S7 protocol id at TPKT4+COTP3 = index 7.
        self.assertIsNone(parse_s7comm(bytes(buf)))

    def test_unknown_rosctr(self):
        buf = bytearray(_s7())
        buf[8] = 0x09  # ROSCTR.
        self.assertIsNone(parse_s7comm(bytes(buf)))

    def test_negative_offset(self):
        self.assertIsNone(parse_s7comm(_s7(), offset=-1))


class TruncationTest(unittest.TestCase):
    def test_truncated_data(self):
        # data_length 를 크게 선언하지만 본문은 짧게.
        full = _s7(parameter=b"\x05\x01\x12\x0a", data=b"\x00\x00")
        truncated = full[:-1]  # 데이터 1바이트 잘림.
        m = parse_s7comm(truncated)
        self.assertIsNotNone(m)
        self.assertTrue(m.truncated)
        self.assertEqual(m.data_length, 2)
        self.assertEqual(m.function_name, "Write Var")

    def test_truncated_header_rejected(self):
        # S7 헤더 자체가 잘리면 거부.
        full = _s7()
        self.assertIsNone(parse_s7comm(full[:4 + 3 + 5]))


class HelperTest(unittest.TestCase):
    def test_rosctr_name_helper(self):
        self.assertEqual(rosctr_name(0x01), "Job")
        self.assertTrue(rosctr_name(0x99).startswith("rosctr-"))

    def test_function_name_helper(self):
        self.assertEqual(function_name(0x05), "Write Var")
        self.assertTrue(function_name(0x77).startswith("function-0x"))

    def test_tables_present(self):
        self.assertIn(0x03, S7_ROSCTR_NAMES)
        self.assertIn(0x05, S7_FUNCTION_NAMES)

    def test_frozen_dataclass(self):
        m = parse_s7comm(_s7())
        with self.assertRaises(Exception):
            m.rosctr = 9  # type: ignore[misc]


if __name__ == "__main__":
    unittest.main()
