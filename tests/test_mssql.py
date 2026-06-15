"""forensiclab.mssql 단위 테스트 (stdlib unittest)."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from forensiclab.mssql import (  # noqa: E402
    ENCRYPTION_MODES,
    TDS_TYPE_PRELOGIN,
    MSSQLPrelogin,
    parse_mssql_prelogin,
)


def _build_prelogin(options=(("VERSION", b"\x10\x00\x07\xd0\x00\x00"),
                              ("ENCRYPTION", b"\x02")),
                    ptype=TDS_TYPE_PRELOGIN, status=0x01, spid=0):
    """옵션 이름→데이터 목록으로 완전한 TDS PRELOGIN 패킷을 만든다."""
    name_to_token = {
        "VERSION": 0x00, "ENCRYPTION": 0x01, "INSTOPT": 0x02,
        "THREADID": 0x03, "MARS": 0x04, "TRACEID": 0x05,
        "FEDAUTHREQUIRED": 0x06, "NONCEOPT": 0x07,
    }
    # 테이블: 항목 5바이트 * N + 종단 1바이트. 데이터는 그 뒤.
    table_len = len(options) * 5 + 1
    table = bytearray()
    blobs = bytearray()
    for name, data in options:
        off = table_len + len(blobs)
        table += bytes([name_to_token[name]])
        table += off.to_bytes(2, "big")
        table += len(data).to_bytes(2, "big")
        blobs += data
    table += b"\xff"  # 종단
    payload = bytes(table) + bytes(blobs)

    length = 8 + len(payload)
    hdr = bytearray()
    hdr.append(ptype)
    hdr.append(status)
    hdr += length.to_bytes(2, "big")
    hdr += spid.to_bytes(2, "big")
    hdr.append(0)  # packet_id
    hdr.append(0)  # window
    return bytes(hdr) + payload


class ParsePreloginTest(unittest.TestCase):
    def test_basic_version_and_encryption(self):
        r = parse_mssql_prelogin(_build_prelogin())
        self.assertIsInstance(r, MSSQLPrelogin)
        self.assertTrue(r.is_eom)
        self.assertEqual(r.encryption, 0x02)
        self.assertEqual(r.encryption_mode, "ENCRYPT_NOT_SUP")
        self.assertEqual(r.version, (16, 0, 2000, 0))
        self.assertEqual(r.version_str, "16.0.2000")

    def test_plaintext_credentials_likely_not_sup(self):
        r = parse_mssql_prelogin(_build_prelogin(
            options=(("ENCRYPTION", b"\x02"),)))
        self.assertTrue(r.plaintext_credentials_likely)

    def test_plaintext_credentials_likely_off(self):
        r = parse_mssql_prelogin(_build_prelogin(
            options=(("ENCRYPTION", b"\x00"),)))
        self.assertTrue(r.plaintext_credentials_likely)

    def test_encryption_on_not_plaintext(self):
        r = parse_mssql_prelogin(_build_prelogin(
            options=(("ENCRYPTION", b"\x01"),)))
        self.assertEqual(r.encryption_mode, "ENCRYPT_ON")
        self.assertFalse(r.plaintext_credentials_likely)

    def test_encryption_required_not_plaintext(self):
        r = parse_mssql_prelogin(_build_prelogin(
            options=(("ENCRYPTION", b"\x03"),)))
        self.assertEqual(r.encryption_mode, "ENCRYPT_REQ")
        self.assertFalse(r.plaintext_credentials_likely)

    def test_instance_name(self):
        r = parse_mssql_prelogin(_build_prelogin(
            options=(("INSTOPT", b"MSSQLSERVER\x00"),)))
        self.assertEqual(r.instance, "MSSQLSERVER")

    def test_fed_auth_required(self):
        r = parse_mssql_prelogin(_build_prelogin(
            options=(("FEDAUTHREQUIRED", b"\x01"),)))
        self.assertEqual(r.fed_auth_required, 1)

    def test_spid_preserved(self):
        r = parse_mssql_prelogin(_build_prelogin(spid=0x0035))
        self.assertEqual(r.spid, 0x35)

    def test_options_dict_named(self):
        r = parse_mssql_prelogin(_build_prelogin())
        self.assertIn("VERSION", r.options)
        self.assertIn("ENCRYPTION", r.options)

    def test_not_eom_status(self):
        r = parse_mssql_prelogin(_build_prelogin(status=0x00))
        self.assertFalse(r.is_eom)

    def test_no_encryption_option(self):
        r = parse_mssql_prelogin(_build_prelogin(
            options=(("VERSION", b"\x10\x00\x07\xd0\x00\x00"),)))
        self.assertIsNone(r.encryption)
        self.assertIsNone(r.encryption_mode)
        self.assertFalse(r.plaintext_credentials_likely)


class RejectionTest(unittest.TestCase):
    def test_wrong_packet_type(self):
        # LOGIN7(0x10) 등 PRELOGIN 이 아니면 None.
        pkt = bytearray(_build_prelogin())
        pkt[0] = 0x10
        self.assertIsNone(parse_mssql_prelogin(bytes(pkt)))

    def test_empty(self):
        self.assertIsNone(parse_mssql_prelogin(b""))

    def test_too_short_header(self):
        self.assertIsNone(parse_mssql_prelogin(b"\x12\x01\x00"))

    def test_negative_offset(self):
        self.assertIsNone(parse_mssql_prelogin(_build_prelogin(), offset=-1))

    def test_declared_length_too_small(self):
        pkt = bytearray(_build_prelogin())
        pkt[2:4] = (4).to_bytes(2, "big")  # length < _MIN_PRELOGIN
        self.assertIsNone(parse_mssql_prelogin(bytes(pkt)))


class RobustnessTest(unittest.TestCase):
    def test_truncated_body_keeps_available_options(self):
        # 전체 패킷을 옵션 데이터 중간에서 자른다 — VERSION 은 테이블 직후라
        # 살아있고, 잘려나간 옵션은 건너뛴다.
        full = _build_prelogin(options=(
            ("ENCRYPTION", b"\x02"),
            ("VERSION", b"\x10\x00\x07\xd0\x00\x00"),
            ("INSTOPT", b"NAMEDINSTANCE\x00"),
        ))
        truncated = full[:len(full) - 8]  # INSTOPT 꼬리 절단
        r = parse_mssql_prelogin(truncated)
        self.assertIsNotNone(r)
        self.assertEqual(r.encryption, 0x02)

    def test_offset_parsing(self):
        prefix = b"\xde\xad\xbe\xef"
        r = parse_mssql_prelogin(prefix + _build_prelogin(), offset=len(prefix))
        self.assertEqual(r.encryption, 0x02)

    def test_option_pointing_out_of_range_skipped(self):
        # offset/length 가 페이로드 밖을 가리키는 옵션은 조용히 건너뛴다.
        # 종단만 있는 페이로드 + 거짓 항목 수동 구성.
        payload = bytes([0x01]) + (999).to_bytes(2, "big") + (4).to_bytes(2, "big") + b"\xff"
        length = 8 + len(payload)
        hdr = bytes([0x12, 0x01]) + length.to_bytes(2, "big") + b"\x00\x00\x00\x00"
        r = parse_mssql_prelogin(hdr + payload)
        self.assertIsNotNone(r)
        self.assertIsNone(r.encryption)


class TablesTest(unittest.TestCase):
    def test_encryption_modes_complete(self):
        self.assertEqual(ENCRYPTION_MODES[0x02], "ENCRYPT_NOT_SUP")
        self.assertEqual(ENCRYPTION_MODES[0x03], "ENCRYPT_REQ")


if __name__ == "__main__":
    unittest.main()
