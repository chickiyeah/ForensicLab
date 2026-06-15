"""forensiclab.tftp 단위 테스트 (stdlib unittest)."""

import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from forensiclab.tftp import (  # noqa: E402
    TFTP_ERROR_CODES,
    TFTP_OP_ACK,
    TFTP_OP_DATA,
    TFTP_OP_ERROR,
    TFTP_OP_OACK,
    TFTP_OP_RRQ,
    TFTP_OP_WRQ,
    Tftp,
    parse_tftp,
)


def _rq(opcode, filename, mode, options=None):
    """RRQ/WRQ 바이트를 짠다(옵션은 (key, val) 튜플 목록)."""
    out = struct.pack(">H", opcode) + filename.encode() + b"\x00" + mode.encode() + b"\x00"
    for key, val in (options or []):
        out += key.encode() + b"\x00" + val.encode() + b"\x00"
    return out


class RequestTests(unittest.TestCase):
    def test_rrq_filename_mode(self):
        pkt = _rq(TFTP_OP_RRQ, "startup-config", "octet")
        t = parse_tftp(pkt)
        self.assertEqual(t.opcode, TFTP_OP_RRQ)
        self.assertEqual(t.opcode_name, "RRQ")
        self.assertEqual(t.filename, "startup-config")
        self.assertEqual(t.mode, "octet")
        self.assertTrue(t.is_request)
        self.assertFalse(t.is_write)
        self.assertTrue(t.is_binary)

    def test_wrq_is_write(self):
        pkt = _rq(TFTP_OP_WRQ, "payload.exe", "octet")
        t = parse_tftp(pkt)
        self.assertEqual(t.opcode_name, "WRQ")
        self.assertTrue(t.is_write)
        self.assertTrue(t.is_request)

    def test_netascii_not_binary(self):
        t = parse_tftp(_rq(TFTP_OP_RRQ, "notes.txt", "netascii"))
        self.assertFalse(t.is_binary)

    def test_mode_case_insensitive_binary(self):
        t = parse_tftp(_rq(TFTP_OP_RRQ, "fw.bin", "OCTET"))
        self.assertTrue(t.is_binary)

    def test_rrq_with_options(self):
        pkt = _rq(TFTP_OP_RRQ, "fw.bin", "octet",
                  [("blksize", "1468"), ("tsize", "1048576")])
        t = parse_tftp(pkt)
        self.assertEqual(t.options, {"blksize": "1468", "tsize": "1048576"})
        self.assertEqual(t.filename, "fw.bin")

    def test_option_keys_lowercased(self):
        pkt = _rq(TFTP_OP_RRQ, "x", "octet", [("BlkSize", "512")])
        t = parse_tftp(pkt)
        self.assertEqual(t.options, {"blksize": "512"})


class DataAckTests(unittest.TestCase):
    def test_data_block_and_payload(self):
        pkt = struct.pack(">HH", TFTP_OP_DATA, 1) + b"MZ\x90\x00"
        t = parse_tftp(pkt)
        self.assertEqual(t.opcode_name, "DATA")
        self.assertEqual(t.block, 1)
        self.assertEqual(t.data, b"MZ\x90\x00")

    def test_data_empty_payload(self):
        # 마지막 블록(< 512)·빈 블록 모두 유효.
        pkt = struct.pack(">HH", TFTP_OP_DATA, 7)
        t = parse_tftp(pkt)
        self.assertEqual(t.block, 7)
        self.assertEqual(t.data, b"")

    def test_ack_block_no_data(self):
        pkt = struct.pack(">HH", TFTP_OP_ACK, 0)
        t = parse_tftp(pkt)
        self.assertEqual(t.opcode_name, "ACK")
        self.assertEqual(t.block, 0)
        self.assertIsNone(t.data)

    def test_data_truncated_block(self):
        pkt = struct.pack(">H", TFTP_OP_DATA) + b"\x00"  # block 1바이트뿐.
        self.assertIsNone(parse_tftp(pkt))


class ErrorTests(unittest.TestCase):
    def test_error_with_message(self):
        pkt = struct.pack(">HH", TFTP_OP_ERROR, 2) + b"Access violation\x00"
        t = parse_tftp(pkt)
        self.assertEqual(t.opcode_name, "ERROR")
        self.assertEqual(t.error_code, 2)
        self.assertEqual(t.error_message, "Access violation")

    def test_error_empty_message_falls_back_to_code_table(self):
        pkt = struct.pack(">HH", TFTP_OP_ERROR, 1) + b"\x00"
        t = parse_tftp(pkt)
        self.assertEqual(t.error_code, 1)
        self.assertEqual(t.error_message, TFTP_ERROR_CODES[1])

    def test_error_truncated(self):
        pkt = struct.pack(">H", TFTP_OP_ERROR) + b"\x05"
        self.assertIsNone(parse_tftp(pkt))


class OackTests(unittest.TestCase):
    def test_oack_options(self):
        body = struct.pack(">H", TFTP_OP_OACK)
        body += b"blksize\x001468\x00tsize\x001048576\x00"
        t = parse_tftp(body)
        self.assertEqual(t.opcode_name, "OACK")
        self.assertEqual(t.options, {"blksize": "1468", "tsize": "1048576"})


class RobustnessTests(unittest.TestCase):
    def test_empty_is_none(self):
        self.assertIsNone(parse_tftp(b""))

    def test_one_byte_is_none(self):
        self.assertIsNone(parse_tftp(b"\x00"))

    def test_unknown_opcode_is_none(self):
        self.assertIsNone(parse_tftp(struct.pack(">H", 99)))

    def test_zero_opcode_is_none(self):
        self.assertIsNone(parse_tftp(struct.pack(">H", 0)))

    def test_negative_offset_is_none(self):
        self.assertIsNone(parse_tftp(_rq(TFTP_OP_RRQ, "x", "octet"), offset=-1))

    def test_offset_parsing(self):
        pkt = b"\xff\xff" + _rq(TFTP_OP_RRQ, "boot.cfg", "octet")
        t = parse_tftp(pkt, offset=2)
        self.assertEqual(t.filename, "boot.cfg")

    def test_frozen_immutable(self):
        t = parse_tftp(_rq(TFTP_OP_RRQ, "x", "octet"))
        with self.assertRaises(Exception):
            t.opcode = 9  # type: ignore[misc]


if __name__ == "__main__":
    unittest.main()
