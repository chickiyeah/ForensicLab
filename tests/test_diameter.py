"""forensiclab.diameter 단위 테스트 (stdlib unittest)."""

import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from forensiclab.diameter import (  # noqa: E402
    DIAMETER_FLAG_ERROR,
    DIAMETER_FLAG_PROXIABLE,
    DIAMETER_FLAG_REQUEST,
    DIAMETER_FLAG_RETRANSMIT,
    DIAMETER_HEADER_LEN,
    DIAMETER_VERSION,
    Diameter,
    parse_diameter,
)


def _header(
    version=DIAMETER_VERSION,
    message_length=DIAMETER_HEADER_LEN,
    command_flags=DIAMETER_FLAG_REQUEST,
    command_code=257,
    application_id=0,
    hop_by_hop_id=0xAABBCCDD,
    end_to_end_id=0x11223344,
    body=b"",
):
    """Diameter 20바이트 헤더(+선택 AVP 본문) 바이트를 짠다."""
    return (
        struct.pack(">B", version)
        + struct.pack(">I", message_length)[1:]   # 3바이트 길이.
        + struct.pack(">B", command_flags)
        + struct.pack(">I", command_code)[1:]      # 3바이트 명령 코드.
        + struct.pack(">III", application_id, hop_by_hop_id, end_to_end_id)
        + body
    )


class ParseBasicTests(unittest.TestCase):
    def test_minimal_cer_request(self):
        d = parse_diameter(_header())
        self.assertIsInstance(d, Diameter)
        self.assertEqual(d.version, 1)
        self.assertEqual(d.message_length, DIAMETER_HEADER_LEN)
        self.assertEqual(d.command_code, 257)
        self.assertEqual(d.command_name, "Capabilities-Exchange")
        self.assertEqual(d.application_id, 0)
        self.assertEqual(d.application_name, "Diameter Common Messages")
        self.assertEqual(d.payload_offset, DIAMETER_HEADER_LEN)

    def test_identifiers_roundtrip(self):
        d = parse_diameter(_header(hop_by_hop_id=0x01020304,
                                   end_to_end_id=0x0A0B0C0D))
        self.assertEqual(d.hop_by_hop_id, 0x01020304)
        self.assertEqual(d.end_to_end_id, 0x0A0B0C0D)

    def test_24bit_fields_max(self):
        d = parse_diameter(_header(message_length=0xFFFFFC, command_code=0xFFFFFF,
                                   body=b""))
        # message_length 가 실제 본문보다 커도 헤더 파싱은 길이만 신뢰.
        self.assertEqual(d.message_length, 0xFFFFFC)
        self.assertEqual(d.command_code, 0xFFFFFF)

    def test_payload_offset_with_body(self):
        d = parse_diameter(_header(message_length=DIAMETER_HEADER_LEN + 4,
                                   body=b"\xde\xad\xbe\xef"))
        self.assertEqual(d.payload_offset, DIAMETER_HEADER_LEN)
        self.assertEqual(d.message_length, DIAMETER_HEADER_LEN + 4)


class FlagTests(unittest.TestCase):
    def test_request(self):
        d = parse_diameter(_header(command_flags=DIAMETER_FLAG_REQUEST))
        self.assertTrue(d.is_request)
        self.assertFalse(d.is_answer)

    def test_answer(self):
        d = parse_diameter(_header(command_flags=0))
        self.assertFalse(d.is_request)
        self.assertTrue(d.is_answer)

    def test_proxiable(self):
        d = parse_diameter(_header(
            command_flags=DIAMETER_FLAG_REQUEST | DIAMETER_FLAG_PROXIABLE))
        self.assertTrue(d.is_proxiable)
        self.assertTrue(d.is_request)

    def test_error(self):
        d = parse_diameter(_header(command_flags=DIAMETER_FLAG_ERROR))
        self.assertTrue(d.is_error)
        self.assertTrue(d.is_answer)

    def test_retransmit(self):
        d = parse_diameter(_header(
            command_flags=DIAMETER_FLAG_REQUEST | DIAMETER_FLAG_RETRANSMIT))
        self.assertTrue(d.is_retransmit)

    def test_all_defined_flags(self):
        flags = (DIAMETER_FLAG_REQUEST | DIAMETER_FLAG_PROXIABLE
                 | DIAMETER_FLAG_ERROR | DIAMETER_FLAG_RETRANSMIT)
        d = parse_diameter(_header(command_flags=flags))
        self.assertTrue(d.is_request)
        self.assertTrue(d.is_proxiable)
        self.assertTrue(d.is_error)
        self.assertTrue(d.is_retransmit)


class CommandAndAppNameTests(unittest.TestCase):
    def test_device_watchdog(self):
        d = parse_diameter(_header(command_code=280))
        self.assertEqual(d.command_name, "Device-Watchdog")

    def test_s6a_update_location(self):
        d = parse_diameter(_header(command_code=316, application_id=16777251))
        self.assertEqual(d.command_name, "Update-Location")
        self.assertEqual(d.application_name, "3GPP S6a/S6d")

    def test_authentication_information(self):
        d = parse_diameter(_header(command_code=318, application_id=16777251))
        self.assertEqual(d.command_name, "Authentication-Information")

    def test_credit_control(self):
        d = parse_diameter(_header(command_code=272, application_id=4))
        self.assertEqual(d.command_name, "Credit-Control")
        self.assertEqual(d.application_name, "Diameter Credit-Control")

    def test_unknown_command(self):
        d = parse_diameter(_header(command_code=9999))
        self.assertEqual(d.command_name, "cmd-9999")

    def test_unknown_application(self):
        d = parse_diameter(_header(application_id=424242))
        self.assertEqual(d.application_name, "app-424242")


class GuardTests(unittest.TestCase):
    def test_too_short(self):
        self.assertIsNone(parse_diameter(_header()[:DIAMETER_HEADER_LEN - 1]))

    def test_empty(self):
        self.assertIsNone(parse_diameter(b""))

    def test_bad_version(self):
        self.assertIsNone(parse_diameter(_header(version=2)))

    def test_length_below_header(self):
        self.assertIsNone(parse_diameter(_header(message_length=16)))

    def test_length_not_multiple_of_four(self):
        self.assertIsNone(parse_diameter(_header(message_length=22)))

    def test_reserved_flag_bits_set(self):
        # 하위 4비트 예약 — 켜져 있으면 거부.
        self.assertIsNone(parse_diameter(_header(command_flags=0x81)))

    def test_negative_offset(self):
        self.assertIsNone(parse_diameter(_header(), offset=-1))

    def test_offset_past_end(self):
        self.assertIsNone(parse_diameter(_header(), offset=100))


class OffsetTests(unittest.TestCase):
    def test_parse_at_offset(self):
        prefix = b"\xff\xff\xff"
        d = parse_diameter(prefix + _header(command_code=280),
                           offset=len(prefix))
        self.assertIsNotNone(d)
        self.assertEqual(d.command_name, "Device-Watchdog")
        self.assertEqual(d.payload_offset, len(prefix) + DIAMETER_HEADER_LEN)

    def test_reserved_bits_each(self):
        for bit in (0x01, 0x02, 0x04, 0x08):
            self.assertIsNone(
                parse_diameter(_header(command_flags=DIAMETER_FLAG_REQUEST | bit)),
                msg=f"reserved bit {bit:#x} should be rejected",
            )


if __name__ == "__main__":
    unittest.main()
