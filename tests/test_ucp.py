"""forensiclab.ucp 단위 테스트 (stdlib unittest)."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from forensiclab.ucp import (  # noqa: E402
    Ucp,
    UCP_OPERATION_NAMES,
    decode_ucp_ira,
    operation_name,
    parse_ucp,
)

_STX = 0x02
_ETX = 0x03


def _frame(oand_r, ot, fields, trn=0):
    """STX..ETX UCP 프레임을 짠다(LEN·CHECKSUM 자동 계산)."""
    body = "/".join(fields)
    tmpl = "{trn:02d}/{ln:05d}/{oar}/{ot}/" + body + "/"
    sample = tmpl.format(trn=trn, ln=0, oar=oand_r, ot=ot)
    frame_len = 1 + len(sample) + 2 + 1  # STX + (summable + checksum2) + ETX.
    summable = tmpl.format(trn=trn, ln=frame_len, oar=oand_r, ot=ot)
    cksum = sum(ord(c) for c in summable) & 0xFF
    content = summable + "{:02X}".format(cksum)
    return bytes([_STX]) + content.encode("latin-1") + bytes([_ETX])


class ParseSessionTest(unittest.TestCase):
    def test_session_credentials(self):
        # 60 session: [OAdC, OTON, ONPI, STYP, PWD, NPWD, VERS].
        frame = _frame("O", "60", ["esmeuser", "", "", "1", "s3cret", "", "0100"])
        u = parse_ucp(frame)
        self.assertIsInstance(u, Ucp)
        self.assertEqual(u.operation_type, 60)
        self.assertEqual(u.operation_name, "session_management")
        self.assertTrue(u.is_session)
        self.assertTrue(u.is_operation)
        self.assertFalse(u.is_result)
        self.assertEqual(u.account, "esmeuser")
        self.assertEqual(u.password, "s3cret")
        self.assertTrue(u.checksum_ok)

    def test_session_has_no_recipient(self):
        frame = _frame("O", "60", ["acct", "", "", "1", "pw", "", "0100"])
        u = parse_ucp(frame)
        self.assertIsNone(u.recipient)
        self.assertIsNone(u.originator)
        self.assertIsNone(u.message)


class ParseMessageTest(unittest.TestCase):
    def test_call_input_decodes_message(self):
        # 01 call input: [AdC, OAdC, AC, MT, Msg]; MT=3 → IRA hex.
        frame = _frame("O", "01", ["12345", "Sender", "", "3", "48656C6C6F"])
        u = parse_ucp(frame)
        self.assertEqual(u.operation_type, 1)
        self.assertEqual(u.operation_name, "call_input")
        self.assertEqual(u.recipient, "12345")
        self.assertEqual(u.originator, "Sender")
        self.assertEqual(u.message_type, "3")
        self.assertEqual(u.message, "Hello")
        self.assertEqual(u.target_number, "12345")

    def test_submit_short_message_shallow(self):
        # 51 submit: 첫 두 필드(착·발신)만 보수적으로, 본문은 풀지 않음.
        frame = _frame(
            "O", "51", ["999", "800123", "", "", "", "", "", "", "", "", ""]
        )
        u = parse_ucp(frame)
        self.assertEqual(u.operation_type, 51)
        self.assertEqual(u.recipient, "999")
        self.assertEqual(u.originator, "800123")
        self.assertIsNone(u.message)
        self.assertIsNone(u.message_type)


class ParseResultTest(unittest.TestCase):
    def test_nack_carries_error_code(self):
        frame = _frame("R", "60", ["N", "04", "authentication failure"])
        u = parse_ucp(frame)
        self.assertTrue(u.is_result)
        self.assertFalse(u.is_operation)
        self.assertTrue(u.is_nack)
        self.assertFalse(u.is_ack)
        self.assertEqual(u.result_ack, "N")
        self.assertEqual(u.error_code, "04")

    def test_ack(self):
        frame = _frame("R", "51", ["A", "", "012345:090531123456"])
        u = parse_ucp(frame)
        self.assertTrue(u.is_ack)
        self.assertFalse(u.is_nack)
        self.assertIsNone(u.error_code)


class HeaderTest(unittest.TestCase):
    def test_trn_and_length(self):
        frame = _frame("O", "01", ["1", "2", "", "3", "41"], trn=42)
        u = parse_ucp(frame)
        self.assertEqual(u.trn, 42)
        self.assertEqual(u.length, len(frame))
        self.assertEqual(u.frame_length, len(frame))

    def test_payload_offset_points_at_first_field(self):
        frame = _frame("O", "01", ["RCPT", "ORIG", "", "3", "41"])
        u = parse_ucp(frame)
        self.assertTrue(frame[u.payload_offset:].startswith(b"RCPT"))

    def test_fields_tuple(self):
        frame = _frame("O", "01", ["a", "b", "c", "3", "41"])
        u = parse_ucp(frame)
        self.assertEqual(u.fields, ("a", "b", "c", "3", "41"))


class ChecksumTest(unittest.TestCase):
    def test_corrupt_checksum_detected(self):
        frame = bytearray(_frame("O", "60", ["acct", "", "", "1", "pw", "", "0100"]))
        # 체크섬은 ETX 직전 2바이트. 한 글자를 다른 16진으로 바꾼다.
        idx = len(frame) - 2  # 체크섬 첫 글자.
        frame[idx] = ord("0") if frame[idx] != ord("0") else ord("1")
        u = parse_ucp(bytes(frame))
        self.assertFalse(u.checksum_ok)


class GuardTest(unittest.TestCase):
    def test_no_stx_returns_none(self):
        self.assertIsNone(parse_ucp(b"00/00041/O/01/x/41/"))

    def test_too_few_fields(self):
        self.assertIsNone(parse_ucp(bytes([_STX]) + b"00/01/O" + bytes([_ETX])))

    def test_bad_operation_or_result(self):
        frame = bytearray(_frame("O", "01", ["x", "y", "", "3", "41"]))
        # 'O' 위치(3번째 필드)를 'X' 로 바꾼다 — content[..] "00/LLLLL/O/..".
        content = frame[1:-1].decode("latin-1").replace("/O/", "/X/", 1)
        bad = bytes([_STX]) + content.encode("latin-1") + bytes([_ETX])
        self.assertIsNone(parse_ucp(bad))

    def test_bad_operation_type(self):
        # OT 가 2자리 숫자가 아님.
        bad = bytes([_STX]) + b"00/00012/O/ZZ/x/41/" + bytes([_ETX])
        self.assertIsNone(parse_ucp(bad))

    def test_empty(self):
        self.assertIsNone(parse_ucp(b""))


class TruncatedTest(unittest.TestCase):
    def test_no_etx_best_effort(self):
        frame = _frame("O", "60", ["acct", "", "", "1", "pw", "", "0100"])
        truncated = frame[:-1]  # ETX 제거.
        u = parse_ucp(truncated)
        self.assertIsNotNone(u)
        self.assertEqual(u.account, "acct")
        self.assertEqual(u.password, "pw")
        self.assertIsNone(u.checksum_ok)  # 절단이면 검증 불가.


class OffsetTest(unittest.TestCase):
    def test_offset(self):
        frame = _frame("O", "01", ["12345", "Sender", "", "3", "4869"])
        buf = b"\xff\xff\xff" + frame
        u = parse_ucp(buf, offset=3)
        self.assertEqual(u.recipient, "12345")
        self.assertEqual(u.message, "Hi")


class HelperTest(unittest.TestCase):
    def test_operation_name_known_and_unknown(self):
        self.assertEqual(operation_name(60), "session_management")
        self.assertEqual(operation_name(99), "operation-99")
        self.assertIn(51, UCP_OPERATION_NAMES)

    def test_decode_ira(self):
        self.assertEqual(decode_ucp_ira("48656C6C6F"), "Hello")
        # 홀수 길이/비-16진은 원본 그대로.
        self.assertEqual(decode_ucp_ira("XYZ"), "XYZ")
        self.assertEqual(decode_ucp_ira("486"), "486")
        self.assertEqual(decode_ucp_ira(""), "")


if __name__ == "__main__":
    unittest.main()
