"""forensiclab.cimd2 단위 테스트 (stdlib unittest)."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from forensiclab.cimd2 import (  # noqa: E402
    Cimd2,
    CIMD2_OPERATION_NAMES,
    CIMD2_PARAMETER_NAMES,
    operation_name,
    parameter_name,
    parse_cimd2,
)

_STX = 0x02
_ETX = 0x03
_TAB = "\t"


def _frame(oc, pn, params, checksum=True):
    """STX..ETX CIMD2 프레임을 짠다(체크섬 자동 계산).

    params: (code:int, value:str) 목록.
    """
    header = "{:02d}:{:03d}".format(oc, pn)
    body = header + _TAB
    for code, value in params:
        body += "{:03d}:{}{}".format(code, value, _TAB)
    region = chr(_STX) + body  # STX 부터 마지막 TAB 까지(체크섬 직전).
    if checksum:
        cc = sum(ord(c) for c in region) & 0xFF
        body += "{:02X}".format(cc)
    return bytes([_STX]) + body.encode("latin-1") + bytes([_ETX])


class ParseLoginTest(unittest.TestCase):
    def test_login_credentials(self):
        frame = _frame(1, 1, [(10, "esmeuser"), (11, "s3cret")])
        c = parse_cimd2(frame)
        self.assertIsInstance(c, Cimd2)
        self.assertEqual(c.operation_code, 1)
        self.assertEqual(c.operation_name, "login")
        self.assertTrue(c.is_login)
        self.assertTrue(c.is_request)
        self.assertFalse(c.is_response)
        self.assertEqual(c.user_identity, "esmeuser")
        self.assertEqual(c.password, "s3cret")
        self.assertTrue(c.checksum_ok)

    def test_login_has_no_recipient(self):
        frame = _frame(1, 1, [(10, "acct"), (11, "pw")])
        c = parse_cimd2(frame)
        self.assertIsNone(c.recipient)
        self.assertIsNone(c.originator)
        self.assertIsNone(c.message)


class ParseMessageTest(unittest.TestCase):
    def test_submit_message_parties_and_body(self):
        frame = _frame(
            3,
            42,
            [(21, "447700900123"), (23, "ACME"), (33, "Your code is 4815")],
        )
        c = parse_cimd2(frame)
        self.assertEqual(c.operation_code, 3)
        self.assertEqual(c.operation_name, "submit_message")
        self.assertEqual(c.recipient, "447700900123")
        self.assertEqual(c.originator, "ACME")
        self.assertEqual(c.message, "Your code is 4815")
        self.assertEqual(c.target_number, "447700900123")

    def test_deliver_message_mo(self):
        frame = _frame(10, 7, [(21, "12345"), (23, "447711111111"), (33, "STOP")])
        c = parse_cimd2(frame)
        self.assertEqual(c.operation_name, "deliver_message")
        self.assertEqual(c.recipient, "12345")
        self.assertEqual(c.message, "STOP")

    def test_alphanumeric_originator_fallback(self):
        # 023 없고 027(alphanumeric)만 있으면 그쪽을 발신자로 채택.
        frame = _frame(3, 1, [(21, "999"), (27, "PAYPAL"), (33, "verify")])
        c = parse_cimd2(frame)
        self.assertEqual(c.originator, "PAYPAL")


class ParseResponseTest(unittest.TestCase):
    def test_login_response_error(self):
        # 응답(51) = login + 50, 인증 실패 오류 코드/텍스트.
        frame = _frame(51, 1, [(900, "100"), (901, "invalid login")])
        c = parse_cimd2(frame)
        self.assertTrue(c.is_response)
        self.assertFalse(c.is_request)
        self.assertTrue(c.is_error)
        self.assertEqual(c.error_code, "100")
        self.assertEqual(c.error_text, "invalid login")

    def test_nack(self):
        frame = _frame(98, 5, [])
        c = parse_cimd2(frame)
        self.assertTrue(c.is_nack)
        self.assertTrue(c.is_error)

    def test_general_error(self):
        frame = _frame(99, 0, [(900, "9")])
        c = parse_cimd2(frame)
        self.assertTrue(c.is_general_error)
        self.assertTrue(c.is_error)

    def test_submit_response_ack_no_error(self):
        frame = _frame(53, 42, [(21, "447700900123"), (60, "")])
        c = parse_cimd2(frame)
        self.assertTrue(c.is_response)
        self.assertIsNone(c.error_code)
        self.assertFalse(c.is_error)


class HeaderTest(unittest.TestCase):
    def test_packet_number(self):
        frame = _frame(3, 255, [(21, "1")])
        c = parse_cimd2(frame)
        self.assertEqual(c.packet_number, 255)
        self.assertEqual(c.frame_length, len(frame))

    def test_payload_offset_points_at_first_param(self):
        frame = _frame(3, 1, [(21, "RCPT")])
        c = parse_cimd2(frame)
        self.assertTrue(frame[c.payload_offset:].startswith(b"021:RCPT"))

    def test_parameters_tuple_and_get(self):
        frame = _frame(3, 1, [(21, "999"), (23, "ABC"), (33, "hi")])
        c = parse_cimd2(frame)
        self.assertEqual(c.parameters, ((21, "999"), (23, "ABC"), (33, "hi")))
        self.assertEqual(c.get(23), "ABC")
        self.assertIsNone(c.get(999))


class ChecksumTest(unittest.TestCase):
    def test_corrupt_checksum_detected(self):
        frame = bytearray(_frame(1, 1, [(10, "acct"), (11, "pw")]))
        idx = len(frame) - 2  # 체크섬 첫 글자(ETX 직전 2바이트).
        frame[idx] = ord("0") if frame[idx] != ord("0") else ord("1")
        c = parse_cimd2(bytes(frame))
        self.assertFalse(c.checksum_ok)

    def test_no_checksum_is_none(self):
        frame = _frame(1, 1, [(10, "acct"), (11, "pw")], checksum=False)
        c = parse_cimd2(frame)
        self.assertEqual(c.checksum, "")
        self.assertIsNone(c.checksum_ok)
        self.assertEqual(c.password, "pw")


class GuardTest(unittest.TestCase):
    def test_no_stx_returns_none(self):
        self.assertIsNone(parse_cimd2(b"01:001\t010:x\t"))

    def test_bad_header_no_colon(self):
        bad = bytes([_STX]) + b"0100\t010:x\t" + bytes([_ETX])
        self.assertIsNone(parse_cimd2(bad))

    def test_non_numeric_operation(self):
        bad = bytes([_STX]) + b"XX:001\t010:x\t" + bytes([_ETX])
        self.assertIsNone(parse_cimd2(bad))

    def test_unknown_operation_code(self):
        # 77 은 CIMD2 연산 열거에 없음 → 오탐 가드.
        bad = bytes([_STX]) + b"77:001\t010:x\t" + bytes([_ETX])
        self.assertIsNone(parse_cimd2(bad))

    def test_too_few_segments(self):
        bad = bytes([_STX]) + b"01:001" + bytes([_ETX])
        self.assertIsNone(parse_cimd2(bad))

    def test_empty(self):
        self.assertIsNone(parse_cimd2(b""))


class TruncatedTest(unittest.TestCase):
    def test_no_etx_best_effort(self):
        frame = _frame(1, 1, [(10, "acct"), (11, "pw")])
        truncated = frame[:-1]  # ETX 제거.
        c = parse_cimd2(truncated)
        self.assertIsNotNone(c)
        self.assertEqual(c.user_identity, "acct")
        self.assertEqual(c.password, "pw")
        self.assertIsNone(c.checksum_ok)  # 절단이면 검증 불가.


class OffsetTest(unittest.TestCase):
    def test_offset(self):
        frame = _frame(3, 1, [(21, "12345"), (33, "Hi")])
        buf = b"\xff\xff\xff" + frame
        c = parse_cimd2(buf, offset=3)
        self.assertEqual(c.recipient, "12345")
        self.assertEqual(c.message, "Hi")


class HelperTest(unittest.TestCase):
    def test_operation_name_known_and_unknown(self):
        self.assertEqual(operation_name(1), "login")
        self.assertEqual(operation_name(53), "submit_message_response")
        self.assertEqual(operation_name(77), "operation-77")
        self.assertIn(98, CIMD2_OPERATION_NAMES)

    def test_parameter_name_known_and_unknown(self):
        self.assertEqual(parameter_name(11), "password")
        self.assertEqual(parameter_name(33), "user_data")
        self.assertEqual(parameter_name(555), "parameter-555")
        self.assertIn(900, CIMD2_PARAMETER_NAMES)


if __name__ == "__main__":
    unittest.main()
