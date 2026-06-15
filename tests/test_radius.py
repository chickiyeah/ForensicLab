"""forensiclab.radius 단위 테스트 (stdlib unittest)."""

import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from forensiclab.radius import (  # noqa: E402
    RADIUS_ATTR_ACCT_STATUS_TYPE,
    RADIUS_ATTR_CALLING_STATION_ID,
    RADIUS_ATTR_FRAMED_IP_ADDRESS,
    RADIUS_ATTR_NAS_IP_ADDRESS,
    RADIUS_ATTR_USER_NAME,
    RADIUS_CODE_ACCESS_ACCEPT,
    RADIUS_CODE_ACCESS_REJECT,
    RADIUS_CODE_ACCESS_REQUEST,
    RADIUS_CODE_ACCOUNTING_REQUEST,
    Radius,
    RadiusAttr,
    parse_radius,
)


def _attr(attr_type, value):
    """TLV 속성 바이트를 짠다(value 는 bytes)."""
    return struct.pack(">BB", attr_type, len(value) + 2) + value


def _packet(code, identifier, attrs=b"", authenticator=None, length=None):
    """RADIUS 패킷 바이트를 짠다."""
    if authenticator is None:
        authenticator = bytes(range(16))
    body = attrs
    total = length if length is not None else 20 + len(body)
    return struct.pack(">BBH", code, identifier, total) + authenticator + body


class HeaderTests(unittest.TestCase):
    def test_access_request_header(self):
        attrs = _attr(RADIUS_ATTR_USER_NAME, b"alice")
        pkt = _packet(RADIUS_CODE_ACCESS_REQUEST, 7, attrs)
        r = parse_radius(pkt)
        self.assertIsNotNone(r)
        self.assertEqual(r.code, RADIUS_CODE_ACCESS_REQUEST)
        self.assertEqual(r.code_name, "Access-Request")
        self.assertEqual(r.identifier, 7)
        self.assertEqual(r.length, len(pkt))
        self.assertEqual(r.authenticator, bytes(range(16)))
        self.assertTrue(r.is_request)
        self.assertFalse(r.is_accept)
        self.assertFalse(r.is_reject)

    def test_accept_and_reject_flags(self):
        accept = parse_radius(_packet(RADIUS_CODE_ACCESS_ACCEPT, 1))
        self.assertTrue(accept.is_accept)
        self.assertFalse(accept.is_reject)
        reject = parse_radius(_packet(RADIUS_CODE_ACCESS_REJECT, 1))
        self.assertTrue(reject.is_reject)
        self.assertEqual(reject.code_name, "Access-Reject")

    def test_unknown_code_name(self):
        # Status-Server(12) 는 알려진 이름이지만 임의 미상 code 는 fallback.
        pkt = bytearray(_packet(RADIUS_CODE_ACCESS_REQUEST, 1))
        pkt[0] = 99
        self.assertIsNone(parse_radius(bytes(pkt)))


class AttributeTests(unittest.TestCase):
    def test_user_name_decoded(self):
        attrs = _attr(RADIUS_ATTR_USER_NAME, b"admin")
        r = parse_radius(_packet(RADIUS_CODE_ACCESS_REQUEST, 1, attrs))
        self.assertEqual(r.user_name, "admin")

    def test_calling_station_id(self):
        attrs = _attr(RADIUS_ATTR_CALLING_STATION_ID, b"00-11-22-33-44-55")
        r = parse_radius(_packet(RADIUS_CODE_ACCESS_REQUEST, 1, attrs))
        self.assertEqual(r.calling_station_id, "00-11-22-33-44-55")

    def test_nas_ip_address_decoded(self):
        attrs = _attr(RADIUS_ATTR_NAS_IP_ADDRESS, bytes([10, 8, 0, 17]))
        r = parse_radius(_packet(RADIUS_CODE_ACCESS_REQUEST, 1, attrs))
        self.assertEqual(r.nas_ip_address, "10.8.0.17")

    def test_framed_ip_as_ipv4(self):
        attrs = _attr(RADIUS_ATTR_FRAMED_IP_ADDRESS, bytes([192, 168, 1, 50]))
        r = parse_radius(_packet(RADIUS_CODE_ACCOUNTING_REQUEST, 1, attrs))
        framed = r.get(RADIUS_ATTR_FRAMED_IP_ADDRESS)
        self.assertEqual(framed.as_ipv4(), "192.168.1.50")

    def test_acct_status_type_name(self):
        attrs = _attr(RADIUS_ATTR_ACCT_STATUS_TYPE, struct.pack(">I", 1))
        r = parse_radius(_packet(RADIUS_CODE_ACCOUNTING_REQUEST, 1, attrs))
        self.assertEqual(r.acct_status, "Start")

    def test_acct_status_unknown_value(self):
        attrs = _attr(RADIUS_ATTR_ACCT_STATUS_TYPE, struct.pack(">I", 99))
        r = parse_radius(_packet(RADIUS_CODE_ACCOUNTING_REQUEST, 1, attrs))
        self.assertEqual(r.acct_status, "status-99")

    def test_multiple_attributes_order_preserved(self):
        attrs = (
            _attr(RADIUS_ATTR_USER_NAME, b"bob")
            + _attr(RADIUS_ATTR_NAS_IP_ADDRESS, bytes([1, 2, 3, 4]))
            + _attr(RADIUS_ATTR_USER_NAME, b"second")
        )
        r = parse_radius(_packet(RADIUS_CODE_ACCESS_REQUEST, 1, attrs))
        self.assertEqual(len(r.attributes), 3)
        names = r.get_all(RADIUS_ATTR_USER_NAME)
        self.assertEqual([a.as_text() for a in names], ["bob", "second"])
        # get() 은 첫 번째.
        self.assertEqual(r.user_name, "bob")

    def test_missing_attribute_returns_none(self):
        r = parse_radius(_packet(RADIUS_CODE_ACCESS_REJECT, 1))
        self.assertIsNone(r.user_name)
        self.assertIsNone(r.calling_station_id)
        self.assertIsNone(r.nas_ip_address)
        self.assertIsNone(r.acct_status)
        self.assertEqual(r.attributes, [])


class RobustnessTests(unittest.TestCase):
    def test_too_short_header(self):
        self.assertIsNone(parse_radius(b"\x01\x02\x00"))
        self.assertIsNone(parse_radius(b""))

    def test_negative_offset(self):
        self.assertIsNone(parse_radius(_packet(RADIUS_CODE_ACCESS_REQUEST, 1), offset=-1))

    def test_offset_parsing(self):
        attrs = _attr(RADIUS_ATTR_USER_NAME, b"carol")
        pkt = _packet(RADIUS_CODE_ACCESS_REQUEST, 1, attrs)
        framed = b"\xaa\xbb" + pkt
        r = parse_radius(framed, offset=2)
        self.assertEqual(r.user_name, "carol")

    def test_truncated_attribute_stops(self):
        # 마지막 속성이 length 만큼의 value 를 못 채우면 거기서 멈춘다.
        good = _attr(RADIUS_ATTR_USER_NAME, b"dave")
        truncated = struct.pack(">BB", RADIUS_ATTR_NAS_IP_ADDRESS, 6) + b"\x0a\x08"  # 4 필요한데 2뿐.
        pkt = _packet(RADIUS_CODE_ACCESS_REQUEST, 1, good + truncated)
        r = parse_radius(pkt)
        self.assertEqual(len(r.attributes), 1)
        self.assertEqual(r.user_name, "dave")

    def test_zero_length_attr_stops(self):
        # length<2 인 속성은 무한 루프 위험 — 멈춰야 한다.
        bad = struct.pack(">BB", RADIUS_ATTR_USER_NAME, 0)
        pkt = _packet(RADIUS_CODE_ACCESS_REQUEST, 1, bad)
        r = parse_radius(pkt)
        self.assertEqual(r.attributes, [])

    def test_declared_length_shorter_than_data(self):
        # length 가 일부 속성만 포함하면 그만큼만 파싱한다.
        attrs = _attr(RADIUS_ATTR_USER_NAME, b"eve") + _attr(RADIUS_ATTR_USER_NAME, b"extra")
        # 첫 속성(5바이트)까지만 선언: 20 + 5 = 25.
        pkt = _packet(RADIUS_CODE_ACCESS_REQUEST, 1, attrs, length=25)
        r = parse_radius(pkt)
        self.assertEqual(len(r.attributes), 1)
        self.assertEqual(r.user_name, "eve")

    def test_attr_helpers_on_wrong_size(self):
        attr = RadiusAttr(type=RADIUS_ATTR_USER_NAME, value=b"abc")
        self.assertIsNone(attr.as_ipv4())
        self.assertIsNone(attr.as_uint32())
        self.assertEqual(attr.as_text(), "abc")

    def test_frozen_dataclass(self):
        r = parse_radius(_packet(RADIUS_CODE_ACCESS_REQUEST, 1))
        with self.assertRaises(Exception):
            r.code = 2  # type: ignore[misc]


if __name__ == "__main__":
    unittest.main()
