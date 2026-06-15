"""forensiclab.smpp 단위 테스트 (stdlib unittest)."""

import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from forensiclab.smpp import (  # noqa: E402
    Smpp,
    SMPP_COMMAND_NAMES,
    SMPP_STATUS_NAMES,
    command_name,
    parse_smpp,
    status_name,
)


def _pdu(command_id, body=b"", command_status=0, sequence_number=1):
    """헤더(16) + 본문으로 SMPP PDU 를 짠다(command_length 자동)."""
    command_length = 16 + len(body)
    header = struct.pack(
        ">IIII", command_length, command_id, command_status, sequence_number
    )
    return header + body


def _cstr(s):
    """C-octet string(NUL 종단)."""
    return s.encode("latin-1") + b"\x00"


def _bind_body(system_id, password, system_type="", interface_version=0x34):
    return (
        _cstr(system_id)
        + _cstr(password)
        + _cstr(system_type)
        + bytes([interface_version])
        + bytes([0x00, 0x00])  # addr_ton, addr_npi.
        + _cstr("")            # address_range.
    )


def _submit_body(source, dest, message, data_coding=0x00, service_type=""):
    return (
        _cstr(service_type)
        + bytes([0x00, 0x00])          # source_addr_ton/npi.
        + _cstr(source)
        + bytes([0x00, 0x01])          # dest_addr_ton/npi.
        + _cstr(dest)
        + bytes([0x00, 0x00, 0x00])    # esm_class, protocol_id, priority.
        + _cstr("")                    # schedule_delivery_time.
        + _cstr("")                    # validity_period.
        + bytes([0x00, 0x00, data_coding, 0x00])  # reg_del, replace, dcs, default.
        + bytes([len(message)])        # sm_length.
        + message
    )


class TestHelpers(unittest.TestCase):
    def test_command_name_known(self):
        self.assertEqual(command_name(0x00000004), "submit_sm")
        self.assertEqual(command_name(0x80000004), "submit_sm_resp")

    def test_command_name_unknown(self):
        self.assertEqual(command_name(0x00ABCDEF), "unknown-0x00abcdef")

    def test_status_name_known(self):
        self.assertEqual(status_name(0x0E), "ESME_RINVPASWD")

    def test_status_name_unknown(self):
        self.assertEqual(status_name(0x12345678), "status-0x12345678")

    def test_command_tables_consistent(self):
        # 응답 id 는 요청 id 에 0x80000000 OR.
        self.assertIn(0x80000004, SMPP_COMMAND_NAMES)
        self.assertIn(0x00000000, SMPP_STATUS_NAMES)


class TestHeader(unittest.TestCase):
    def test_enquire_link_header_only(self):
        pdu = _pdu(0x00000015, sequence_number=42)
        r = parse_smpp(pdu)
        self.assertIsInstance(r, Smpp)
        self.assertEqual(r.command_name, "enquire_link")
        self.assertEqual(r.sequence_number, 42)
        self.assertTrue(r.is_request)
        self.assertFalse(r.is_response)
        self.assertIsNone(r.system_id)
        self.assertIsNone(r.short_message)
        self.assertEqual(r.payload_offset, 16)

    def test_response_flag(self):
        pdu = _pdu(0x80000015, command_status=0)
        r = parse_smpp(pdu)
        self.assertTrue(r.is_response)
        self.assertFalse(r.is_request)
        self.assertFalse(r.is_error)

    def test_response_error(self):
        pdu = _pdu(0x80000002, command_status=0x0E)
        r = parse_smpp(pdu)
        self.assertTrue(r.is_response)
        self.assertTrue(r.is_error)
        self.assertEqual(r.command_status_name, "ESME_RINVPASWD")


class TestBind(unittest.TestCase):
    def test_bind_transmitter_credentials(self):
        body = _bind_body("smppclient1", "s3cr3t", "SMPP")
        pdu = _pdu(0x00000002, body)
        r = parse_smpp(pdu)
        self.assertEqual(r.command_name, "bind_transmitter")
        self.assertTrue(r.is_bind)
        self.assertEqual(r.system_id, "smppclient1")
        self.assertEqual(r.password, "s3cr3t")
        self.assertEqual(r.system_type, "SMPP")
        self.assertEqual(r.interface_version, 0x34)

    def test_bind_transceiver_is_bind(self):
        pdu = _pdu(0x00000009, _bind_body("acct", "pw"))
        r = parse_smpp(pdu)
        self.assertTrue(r.is_bind)
        self.assertEqual(r.system_id, "acct")
        self.assertEqual(r.password, "pw")

    def test_bind_resp_not_decoded_as_bind(self):
        # 응답(0x80000009)은 _BIND_COMMANDS 가 아니므로 자격증명 미파싱.
        pdu = _pdu(0x80000009, _cstr("smscid"))
        r = parse_smpp(pdu)
        self.assertFalse(r.is_bind)
        self.assertIsNone(r.password)


class TestSubmitDeliver(unittest.TestCase):
    def test_submit_sm_smishing(self):
        msg = b"Your bank: verify at http://evil.example/login"
        body = _submit_body("BANK", "821012345678", msg)
        pdu = _pdu(0x00000004, body)
        r = parse_smpp(pdu)
        self.assertEqual(r.command_name, "submit_sm")
        self.assertEqual(r.source_addr, "BANK")
        self.assertEqual(r.dest_addr, "821012345678")
        self.assertEqual(r.target_number, "821012345678")
        self.assertEqual(r.short_message, msg.decode("latin-1"))
        self.assertEqual(r.data_coding, 0x00)

    def test_deliver_sm_same_structure(self):
        body = _submit_body("12345", "999", b"hi")
        pdu = _pdu(0x00000005, body)
        r = parse_smpp(pdu)
        self.assertEqual(r.command_name, "deliver_sm")
        self.assertEqual(r.source_addr, "12345")
        self.assertEqual(r.short_message, "hi")

    def test_submit_sm_ucs2(self):
        msg = "안녕".encode("utf-16-be")
        body = _submit_body("S", "D", msg, data_coding=0x08)
        pdu = _pdu(0x00000004, body)
        r = parse_smpp(pdu)
        self.assertEqual(r.data_coding, 0x08)
        self.assertEqual(r.short_message, "안녕")

    def test_submit_sm_invalid_ucs2_returns_none_text(self):
        # 홀수 길이 → UTF-16BE 디코드 실패 → short_message None.
        body = _submit_body("S", "D", b"\x00", data_coding=0x08)
        pdu = _pdu(0x00000004, body)
        r = parse_smpp(pdu)
        self.assertIsNone(r.short_message)


class TestGuards(unittest.TestCase):
    def test_empty(self):
        self.assertIsNone(parse_smpp(b""))

    def test_short_header(self):
        self.assertIsNone(parse_smpp(b"\x00" * 15))

    def test_unknown_command_id(self):
        pdu = _pdu(0x00ABCDEF)
        self.assertIsNone(parse_smpp(pdu))

    def test_command_length_too_small(self):
        # command_length < 16 → 오탐 가드.
        bad = struct.pack(">IIII", 8, 0x00000015, 0, 1)
        self.assertIsNone(parse_smpp(bad))

    def test_offset_out_of_range(self):
        pdu = _pdu(0x00000015)
        self.assertIsNone(parse_smpp(pdu, offset=len(pdu)))

    def test_offset_support(self):
        prefix = b"\xaa\xbb\xcc"
        pdu = _pdu(0x00000015, sequence_number=7)
        r = parse_smpp(prefix + pdu, offset=len(prefix))
        self.assertEqual(r.sequence_number, 7)
        self.assertEqual(r.payload_offset, len(prefix) + 16)

    def test_truncated_body_partial(self):
        # bind 본문이 password 중간에 끊김 — system_id 만 채워지고 password 가용분.
        body = _cstr("user") + b"pa"  # password NUL 없음.
        pdu = _pdu(0x00000002, body)
        r = parse_smpp(pdu)
        self.assertEqual(r.system_id, "user")
        self.assertEqual(r.password, "pa")  # 가용분까지.

    def test_truncated_message_partial(self):
        # sm_length 가 실제 데이터보다 큼 — 가용분까지만.
        body = _submit_body("S", "D", b"hello")
        body = body[:-2]  # short_message 끝 2바이트 절단.
        pdu = struct.pack(">IIII", 16 + len(body) + 2, 0x00000004, 0, 1) + body
        r = parse_smpp(pdu)
        self.assertEqual(r.source_addr, "S")
        self.assertEqual(r.short_message, "hel")


if __name__ == "__main__":
    unittest.main()
