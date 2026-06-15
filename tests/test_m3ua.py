"""forensiclab.m3ua 단위 테스트 (stdlib unittest)."""

import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from forensiclab.m3ua import (  # noqa: E402
    M3UA_HEADER_LEN,
    M3UA_PARAM_HEADER_LEN,
    M3UA_PROTOCOL_DATA_TAG,
    M3ua,
    M3uaParam,
    parse_m3ua,
)


def _param(tag, value=b""):
    """파라미터 하나(헤더+값+4바이트 패딩) 바이트를 짠다."""
    length = M3UA_PARAM_HEADER_LEN + len(value)
    raw = struct.pack(">HH", tag, length) + value
    raw += b"\x00" * (-length % 4)  # 4바이트 경계 패딩.
    return raw


def _message(
    version=1,
    reserved=0,
    message_class=1,
    message_type=1,
    params=b"",
    message_length=None,
):
    """M3UA 공통 헤더(+파라미터들) 바이트를 짠다."""
    body = params
    if message_length is None:
        message_length = M3UA_HEADER_LEN + len(body)
    return (
        struct.pack(">BBBBI", version, reserved, message_class,
                    message_type, message_length)
        + body
    )


class ParseBasicTests(unittest.TestCase):
    def test_common_header_fields(self):
        m = parse_m3ua(_message(message_class=3, message_type=1))
        self.assertIsInstance(m, M3ua)
        self.assertEqual(m.version, 1)
        self.assertEqual(m.reserved, 0)
        self.assertEqual(m.message_class, 3)
        self.assertEqual(m.message_type, 1)
        self.assertEqual(m.message_length, M3UA_HEADER_LEN)
        self.assertEqual(m.payload_offset, M3UA_HEADER_LEN)

    def test_no_params_is_valid(self):
        # M3UA 는 파라미터가 없을 수 있다(예: 단순 ASPUP).
        m = parse_m3ua(_message(message_class=3, message_type=1))
        self.assertEqual(m.params, ())
        self.assertIsNone(m.first_param)

    def test_message_length_preserved(self):
        m = parse_m3ua(_message(params=_param(0x0006, b"\x00\x00\x00\x01")))
        self.assertEqual(m.message_length, M3UA_HEADER_LEN + 8)

    def test_offset(self):
        blob = b"\xde\xad" + _message(message_class=4, message_type=1)
        m = parse_m3ua(blob, offset=2)
        self.assertEqual(m.payload_offset, 2 + M3UA_HEADER_LEN)
        self.assertEqual(m.message_class, 4)


class MessageNameTests(unittest.TestCase):
    def test_class_names(self):
        self.assertEqual(parse_m3ua(_message(message_class=0)).class_name, "MGMT")
        self.assertEqual(parse_m3ua(_message(message_class=1)).class_name, "TFER")
        self.assertEqual(parse_m3ua(_message(message_class=2)).class_name, "SSNM")
        self.assertEqual(parse_m3ua(_message(message_class=3)).class_name, "ASPSM")
        self.assertEqual(parse_m3ua(_message(message_class=4)).class_name, "ASPTM")

    def test_known_message_names(self):
        for cls, typ, name in [
            (1, 1, "DATA"), (0, 0, "ERR"), (0, 1, "NTFY"),
            (2, 1, "DUNA"), (2, 5, "DUPU"),
            (3, 1, "ASPUP"), (3, 3, "BEAT"), (3, 6, "BEAT-ACK"),
            (4, 1, "ASPAC"), (9, 1, "REG-REQ"),
        ]:
            m = parse_m3ua(_message(message_class=cls, message_type=typ))
            self.assertEqual(m.message_name, name)

    def test_unknown_message_name(self):
        m = parse_m3ua(_message(message_class=1, message_type=99))
        self.assertEqual(m.message_name, "TFER/type-99")

    def test_unknown_class_name(self):
        m = parse_m3ua(_message(message_class=200, message_type=1))
        self.assertEqual(m.class_name, "class-200")
        self.assertEqual(m.message_name, "class-200/type-1")


class ParamTests(unittest.TestCase):
    def test_single_param(self):
        m = parse_m3ua(_message(params=_param(0x0006, b"\x00\x00\x00\x05")))
        self.assertEqual(len(m.params), 1)
        p = m.first_param
        self.assertIsInstance(p, M3uaParam)
        self.assertEqual(p.tag, 0x0006)
        self.assertEqual(p.param_name, "Routing Context")
        self.assertEqual(p.length, M3UA_PARAM_HEADER_LEN + 4)
        self.assertEqual(p.value_offset, M3UA_HEADER_LEN + M3UA_PARAM_HEADER_LEN)

    def test_multiple_params_order(self):
        body = _param(0x0006, b"\x00\x00\x00\x01") + _param(0x0210, b"ss7data")
        m = parse_m3ua(_message(message_class=1, message_type=1, params=body))
        self.assertEqual(m.param_tags, (0x0006, 0x0210))
        self.assertEqual(m.param_names, ("Routing Context", "Protocol Data"))

    def test_padding_between_params(self):
        # 첫 값 7바이트 → 길이 11 → 12 로 패딩, 둘째 파라미터가 경계에 옴.
        body = _param(0x0210, b"abcdefg") + _param(0x0006, b"\x00\x00\x00\x01")
        m = parse_m3ua(_message(params=body))
        self.assertEqual(m.params[1].value_offset,
                         M3UA_HEADER_LEN + 12 + M3UA_PARAM_HEADER_LEN)

    def test_unknown_param_name(self):
        m = parse_m3ua(_message(params=_param(0x9999)))
        self.assertEqual(m.first_param.param_name, "param-0x9999")

    def test_has_param(self):
        m = parse_m3ua(_message(params=_param(0x0006) + _param(0x0210, b"x")))
        self.assertTrue(m.has_param(0x0006))
        self.assertTrue(m.has_param(0x0210))
        self.assertFalse(m.has_param(0x000C))


class SemanticTests(unittest.TestCase):
    def test_is_data(self):
        self.assertTrue(parse_m3ua(_message(message_class=1)).is_data)
        self.assertFalse(parse_m3ua(_message(message_class=3)).is_data)

    def test_has_protocol_data(self):
        m = parse_m3ua(_message(message_class=1, message_type=1,
                                params=_param(M3UA_PROTOCOL_DATA_TAG, b"ss7")))
        self.assertTrue(m.has_protocol_data)
        self.assertTrue(m.is_data)
        m2 = parse_m3ua(_message(message_class=1, message_type=1,
                                 params=_param(0x0006)))
        self.assertFalse(m2.has_protocol_data)

    def test_is_management_error_notify(self):
        self.assertTrue(parse_m3ua(_message(message_class=0, message_type=0)).is_error)
        self.assertTrue(parse_m3ua(_message(message_class=0, message_type=1)).is_notify)
        self.assertTrue(parse_m3ua(_message(message_class=0, message_type=0)).is_management)
        self.assertFalse(parse_m3ua(_message(message_class=0, message_type=1)).is_error)

    def test_is_ssnm(self):
        self.assertTrue(parse_m3ua(_message(message_class=2, message_type=1)).is_ssnm)
        self.assertFalse(parse_m3ua(_message(message_class=1)).is_ssnm)

    def test_is_aspsm_asptm(self):
        self.assertTrue(parse_m3ua(_message(message_class=3, message_type=1)).is_aspsm)
        self.assertTrue(parse_m3ua(_message(message_class=4, message_type=1)).is_asptm)

    def test_is_heartbeat(self):
        self.assertTrue(parse_m3ua(_message(message_class=3, message_type=3)).is_heartbeat)
        self.assertTrue(parse_m3ua(_message(message_class=3, message_type=6)).is_heartbeat)
        self.assertFalse(parse_m3ua(_message(message_class=3, message_type=1)).is_heartbeat)


class GuardTests(unittest.TestCase):
    def test_too_short(self):
        self.assertIsNone(parse_m3ua(b"\x00" * 7))

    def test_bad_version(self):
        blob = struct.pack(">BBBBI", 2, 0, 1, 1, M3UA_HEADER_LEN)
        self.assertIsNone(parse_m3ua(blob))

    def test_bad_reserved(self):
        blob = struct.pack(">BBBBI", 1, 0xFF, 1, 1, M3UA_HEADER_LEN)
        self.assertIsNone(parse_m3ua(blob))

    def test_message_length_too_small(self):
        blob = struct.pack(">BBBBI", 1, 0, 1, 1, 7)
        self.assertIsNone(parse_m3ua(blob))

    def test_negative_offset(self):
        self.assertIsNone(parse_m3ua(_message(), offset=-1))

    def test_empty(self):
        self.assertIsNone(parse_m3ua(b""))


class TruncationTests(unittest.TestCase):
    def test_param_length_exceeds_data(self):
        # 길이 250 주장하지만 값 절단 — 첫 파라미터는 담고 멈춤.
        body = struct.pack(">HH", 0x0210, 250)
        blob = _message(message_class=1, message_type=1, params=body,
                        message_length=M3UA_HEADER_LEN + 250)
        m = parse_m3ua(blob)
        self.assertIsNotNone(m)
        self.assertEqual(len(m.params), 1)
        self.assertEqual(m.first_param.length, 250)

    def test_second_param_truncated(self):
        # 정상 첫 파라미터 + 망가진 둘째(길이 1) → 첫 파라미터만 유지.
        body = _param(0x0006, b"\x00\x00\x00\x01") + struct.pack(">HH", 0x0210, 1)
        m = parse_m3ua(_message(params=body))
        self.assertEqual(m.param_tags, (0x0006,))

    def test_message_length_clamps_params(self):
        # message_length 가 첫 파라미터까지만 포함하면 그 뒤는 무시.
        body = _param(0x0006, b"\x00\x00\x00\x01") + _param(0x0210, b"x")
        blob = _message(params=body, message_length=M3UA_HEADER_LEN + 8)
        m = parse_m3ua(blob)
        self.assertEqual(m.param_tags, (0x0006,))


if __name__ == "__main__":
    unittest.main()
