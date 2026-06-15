"""forensiclab.coap 단위 테스트 (stdlib unittest)."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from forensiclab.coap import (  # noqa: E402
    Coap,
    CoapOption,
    COAP_TYPE_NAMES,
    COAP_OPTION_NAMES,
    COAP_CONTENT_FORMAT_NAMES,
    coap_code_name,
    coap_type_name,
    content_format_name,
    option_name,
    parse_coap,
)


def _header(type_code=0, tkl=0, code=0x01, mid=0x1234):
    """CoAP 4바이트 고정 헤더."""
    b0 = (1 << 6) | ((type_code & 0x03) << 4) | (tkl & 0x0F)
    return bytes([b0, code, (mid >> 8) & 0xFF, mid & 0xFF])


def _opt(delta, value):
    """단일 옵션 인코딩(델타·길이 < 13 인 단순 경우)."""
    if isinstance(value, str):
        value = value.encode("utf-8")
    length = len(value)
    assert delta < 13 and length < 13, "테스트 헬퍼는 단순 옵션만 지원"
    return bytes([(delta << 4) | length]) + value


class FixedHeaderTest(unittest.TestCase):
    def test_minimal_get(self):
        m = parse_coap(_header(type_code=0, tkl=0, code=0x01, mid=0xBEEF))
        self.assertIsNotNone(m)
        self.assertEqual(m.version, 1)
        self.assertEqual(m.type_name, "CON")
        self.assertTrue(m.is_confirmable)
        self.assertTrue(m.is_request)
        self.assertEqual(m.code_name, "0.01 GET")
        self.assertEqual(m.message_id, 0xBEEF)
        self.assertEqual(m.token, "")
        self.assertIsNone(m.payload_offset)
        self.assertFalse(m.has_payload)

    def test_token_extracted(self):
        m = parse_coap(_header(tkl=4, code=0x02) + b"\xde\xad\xbe\xef")
        self.assertEqual(m.token_length, 4)
        self.assertEqual(m.token, "deadbeef")
        self.assertEqual(m.code_name, "0.02 POST")

    def test_response_code(self):
        m = parse_coap(_header(type_code=2, code=0x45, mid=0xBEEF))  # 2.05 Content, ACK
        self.assertEqual(m.type_name, "ACK")
        self.assertTrue(m.is_ack)
        self.assertEqual(m.code_class, 2)
        self.assertEqual(m.code_detail, 5)
        self.assertEqual(m.code_name, "2.05 Content")
        self.assertTrue(m.is_response)
        self.assertFalse(m.is_request)

    def test_not_found_response(self):
        m = parse_coap(_header(type_code=2, code=(4 << 5) | 4))  # 4.04
        self.assertEqual(m.code_name, "4.04 Not Found")
        self.assertTrue(m.is_response)

    def test_empty_message(self):
        m = parse_coap(_header(type_code=3, code=0x00, mid=1))  # RST ping
        self.assertTrue(m.is_empty)
        self.assertTrue(m.is_reset)
        self.assertEqual(m.code_name, "0.00 Empty")

    def test_non_type(self):
        m = parse_coap(_header(type_code=1, code=0x01))
        self.assertEqual(m.type_name, "NON")

    def test_packet_length(self):
        raw = _header(tkl=2, code=0x01) + b"\x01\x02"
        m = parse_coap(raw)
        self.assertEqual(m.packet_length, len(raw))


class OptionTest(unittest.TestCase):
    def test_uri_path(self):
        # Uri-Path(11) "sensors", 다음 델타 0 "temp".
        body = _opt(11, "sensors") + _opt(0, "temp")
        m = parse_coap(_header(code=0x01) + body)
        self.assertEqual(m.uri_path, "/sensors/temp")
        self.assertEqual(len(m.options), 2)
        self.assertEqual(m.options[0].name, "Uri-Path")
        self.assertEqual(m.options[0].as_text, "sensors")

    def test_uri_query(self):
        # Uri-Path(11) "a", 그다음 Uri-Query(15, 델타 4) "q=1".
        body = _opt(11, "a") + _opt(4, "q=1")
        m = parse_coap(_header(code=0x01) + body)
        self.assertEqual(m.uri_path, "/a")
        self.assertEqual(m.uri_query, "q=1")

    def test_uri_host(self):
        body = _opt(3, "iot.local")  # Uri-Host(3)
        m = parse_coap(_header(code=0x01) + body)
        self.assertEqual(m.uri_host, "iot.local")

    def test_content_format_uint(self):
        # Content-Format(12) = 50 (application/json), 단일 바이트 값.
        body = _opt(12, bytes([50]))
        m = parse_coap(_header(type_code=2, code=0x45) + body)
        self.assertEqual(m.content_format, 50)
        self.assertEqual(m.content_format_name, "application/json")

    def test_content_format_empty_value_is_zero(self):
        # 길이 0 값 = 0(text/plain).
        body = _opt(12, b"")
        m = parse_coap(_header(type_code=2, code=0x45) + body)
        self.assertEqual(m.content_format, 0)
        self.assertEqual(m.content_format_name, "text/plain")

    def test_observe_option(self):
        body = _opt(6, bytes([0]))  # Observe(6) 등록.
        m = parse_coap(_header(code=0x01) + body)
        self.assertEqual(m.observe, 0)

    def test_extended_delta_13(self):
        # 델타 니블 13 → 확장 1바이트(델타 = ext + 13). Uri-Path(11) 후
        # 델타 19(=ext 6 + 13)면 옵션 번호 11 + 19 = 30.
        body = _opt(11, "a") + bytes([(13 << 4) | 1, 6]) + b"\x05"
        m = parse_coap(_header(code=0x01) + body)
        self.assertEqual(m.options[1].number, 30)

    def test_get_option_helper(self):
        body = _opt(11, "x")
        m = parse_coap(_header(code=0x01) + body)
        self.assertIsNotNone(m.get_option(11))
        self.assertIsNone(m.get_option(99))

    def test_payload_after_marker(self):
        body = _opt(11, "temp") + b"\xff" + b"23.5C"
        raw = _header(code=0x01) + body
        m = parse_coap(raw)
        self.assertTrue(m.has_payload)
        self.assertEqual(raw[m.payload_offset:], b"23.5C")
        self.assertEqual(m.uri_path, "/temp")


class GuardTest(unittest.TestCase):
    def test_too_short(self):
        self.assertIsNone(parse_coap(b"\x40\x01\x12"))  # 3바이트.

    def test_empty(self):
        self.assertIsNone(parse_coap(b""))

    def test_wrong_version(self):
        # Version 2 (상위 2비트 = 10).
        self.assertIsNone(parse_coap(bytes([0x80, 0x01, 0x00, 0x00])))

    def test_bad_token_length(self):
        # TKL 9 (예약).
        self.assertIsNone(parse_coap(bytes([0x49, 0x01, 0x00, 0x00]) + b"x" * 9))

    def test_reserved_code_class(self):
        # Code class 1 (예약): 1.00 = 0x20.
        self.assertIsNone(parse_coap(_header(code=0x20)))
        # class 7: 7.00 = 0xE0.
        self.assertIsNone(parse_coap(_header(code=0xE0)))

    def test_token_truncated(self):
        # TKL 5 인데 토큰 바이트 부족.
        self.assertIsNone(parse_coap(_header(tkl=5, code=0x01) + b"ab"))

    def test_reserved_option_nibble(self):
        # 델타 니블 15 인데 전체 바이트가 0xFF 가 아님(0xF0).
        body = bytes([0xF0])
        self.assertIsNone(parse_coap(_header(code=0x01) + body))

    def test_offset_out_of_range(self):
        self.assertIsNone(parse_coap(_header(code=0x01), offset=100))


class TruncationTest(unittest.TestCase):
    def test_option_value_truncated(self):
        # 옵션 길이 5 선언인데 값 2바이트만.
        body = bytes([(11 << 4) | 5]) + b"ab"
        m = parse_coap(_header(code=0x01) + body)
        self.assertIsNotNone(m)
        self.assertTrue(m.truncated)
        self.assertEqual(m.options[0].value, b"ab")


class OffsetTest(unittest.TestCase):
    def test_offset_parsing(self):
        raw = b"\x99\x99" + _header(code=0x01) + _opt(11, "x")
        m = parse_coap(raw, offset=2)
        self.assertIsNotNone(m)
        self.assertEqual(m.uri_path, "/x")
        self.assertEqual(m.packet_length, len(raw) - 2)


class HelperTest(unittest.TestCase):
    def test_type_name(self):
        self.assertEqual(coap_type_name(0), "CON")
        self.assertEqual(coap_type_name(99), "type-99")

    def test_code_name_unknown_detail(self):
        self.assertEqual(coap_code_name(0x1F), "0.31")  # class 0, detail 31 미정의.
        self.assertEqual(coap_code_name((2 << 5) | 7), "2.07")  # 2.07 미정의.

    def test_option_name(self):
        self.assertEqual(option_name(11), "Uri-Path")
        self.assertEqual(option_name(999), "option-999")

    def test_content_format_name(self):
        self.assertEqual(content_format_name(60), "application/cbor")
        self.assertEqual(content_format_name(999), "format-999")

    def test_tables_present(self):
        self.assertEqual(COAP_TYPE_NAMES[2], "ACK")
        self.assertEqual(COAP_OPTION_NAMES[15], "Uri-Query")
        self.assertEqual(COAP_CONTENT_FORMAT_NAMES[50], "application/json")


if __name__ == "__main__":
    unittest.main()
