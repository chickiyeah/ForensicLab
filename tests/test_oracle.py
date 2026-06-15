"""forensiclab.oracle 단위 테스트 (stdlib unittest)."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from forensiclab.oracle import (  # noqa: E402
    TNS_TYPE_CONNECT,
    TNS_TYPE_REDIRECT,
    OracleConnect,
    parse_oracle_connect,
)


def _build_connect(descriptor=b"(DESCRIPTION=(CONNECT_DATA=(SERVICE_NAME=orcl)"
                              b"(CID=(PROGRAM=sqlplus)(HOST=ws01)(USER=oracle)))"
                              b"(ADDRESS=(PROTOCOL=TCP)(HOST=10.0.0.5)(PORT=1521)))",
                   version=0x013A, version_compatible=0x012C,
                   ptype=TNS_TYPE_CONNECT, flags=0x00):
    """descriptor 문자열로 완전한 TNS CONNECT 패킷을 만든다."""
    # 본문 고정 필드(8 UInt16 = 16바이트) 다음에 connect_data_length(2)+offset(2)
    # +connect_data_max(4) … 이어서 descriptor.
    body = bytearray()
    body += version.to_bytes(2, "big")
    body += version_compatible.to_bytes(2, "big")
    body += (0).to_bytes(2, "big")   # service_options
    body += (8192).to_bytes(2, "big")  # sdu
    body += (32767).to_bytes(2, "big")  # max_tdu
    body += (0).to_bytes(2, "big")   # nt_protocol_chars
    body += (0).to_bytes(2, "big")   # line_turnaround
    body += (1).to_bytes(2, "big")   # value_of_1
    body += len(descriptor).to_bytes(2, "big")  # connect_data_length
    # connect_data_offset: 패킷 선두 기준. 헤더8 + 본문 고정부.
    fixed_after = 4  # connect_data_max(4)
    cd_off = 8 + len(body) + 2 + fixed_after  # +2 for the offset field itself
    body += cd_off.to_bytes(2, "big")  # connect_data_offset
    body += (0).to_bytes(4, "big")   # connect_data_max
    body += descriptor

    length = 8 + len(body)
    hdr = bytearray()
    hdr += length.to_bytes(2, "big")  # packet_length
    hdr += (0).to_bytes(2, "big")     # packet_checksum
    hdr.append(ptype)                 # packet_type
    hdr.append(flags)                 # reserved/flags
    hdr += (0).to_bytes(2, "big")     # header_checksum
    return bytes(hdr) + bytes(body)


class ParseConnectTest(unittest.TestCase):
    def test_basic(self):
        r = parse_oracle_connect(_build_connect())
        self.assertIsInstance(r, OracleConnect)
        self.assertEqual(r.version, 0x013A)
        self.assertEqual(r.version_compatible, 0x012C)
        self.assertEqual(r.version_hex, "0x013a")

    def test_service_name(self):
        r = parse_oracle_connect(_build_connect())
        self.assertEqual(r.service_name, "orcl")
        self.assertEqual(r.attributes.get("SERVICE_NAME"), "orcl")

    def test_cid_attribution(self):
        r = parse_oracle_connect(_build_connect())
        self.assertEqual(r.program, "sqlplus")
        self.assertEqual(r.os_user, "oracle")
        # ADDRESS·CID 양쪽 HOST 중 첫 값(CID 의 ws01) 유지.
        self.assertEqual(r.attributes.get("HOST"), "ws01")

    def test_address_port_protocol(self):
        r = parse_oracle_connect(_build_connect())
        self.assertEqual(r.attributes.get("PORT"), "1521")
        self.assertEqual(r.attributes.get("PROTOCOL"), "TCP")

    def test_connect_data_roundtrip(self):
        r = parse_oracle_connect(_build_connect())
        self.assertIn("SERVICE_NAME=orcl", r.connect_data)

    def test_sid_fallback(self):
        d = b"(DESCRIPTION=(CONNECT_DATA=(SID=XE)))"
        r = parse_oracle_connect(_build_connect(descriptor=d))
        self.assertEqual(r.service_name, "XE")

    def test_global_name(self):
        d = b"(DESCRIPTION=(CONNECT_DATA=(GLOBAL_NAME=db.example.com)))"
        r = parse_oracle_connect(_build_connect(descriptor=d))
        self.assertEqual(r.attributes.get("GLOBAL_NAME"), "db.example.com")


class RejectsTest(unittest.TestCase):
    def test_empty(self):
        self.assertIsNone(parse_oracle_connect(b""))

    def test_negative_offset(self):
        self.assertIsNone(parse_oracle_connect(_build_connect(), offset=-1))

    def test_short_header(self):
        self.assertIsNone(parse_oracle_connect(b"\x00\x10\x00"))

    def test_wrong_type_redirect(self):
        # REDIRECT(5) 는 CONNECT 가 아니므로 None.
        self.assertIsNone(parse_oracle_connect(_build_connect(ptype=TNS_TYPE_REDIRECT)))

    def test_wrong_type_data(self):
        self.assertIsNone(parse_oracle_connect(_build_connect(ptype=0x06)))

    def test_length_too_small(self):
        # length 필드를 비합리적으로 작게 위조.
        pkt = bytearray(_build_connect())
        pkt[0:2] = (5).to_bytes(2, "big")
        self.assertIsNone(parse_oracle_connect(bytes(pkt)))


class RobustnessTest(unittest.TestCase):
    def test_offset_support(self):
        pkt = _build_connect()
        framed = b"\xde\xad\xbe\xef" + pkt
        r = parse_oracle_connect(framed, offset=4)
        self.assertIsNotNone(r)
        self.assertEqual(r.service_name, "orcl")

    def test_truncated_descriptor(self):
        # descriptor 가 잘려도 예외 없이 가용분까지(또는 None) — 크래시 금지.
        pkt = _build_connect()
        r = parse_oracle_connect(pkt[:len(pkt) - 20])
        # 본문 메타까지는 읽혔을 수 있으니 OracleConnect 또는 None 둘 다 허용,
        # 단 예외는 나지 않아야 한다.
        self.assertTrue(r is None or isinstance(r, OracleConnect))

    def test_no_descriptor_still_parses_header(self):
        # connect_data_offset=0 이면 descriptor 없이 헤더/버전만.
        pkt = bytearray(_build_connect())
        # connect_data_offset 위치를 0 으로 — body_start(8) + _CD_OFF_AT(18).
        off_pos = 8 + 18
        pkt[off_pos:off_pos + 2] = (0).to_bytes(2, "big")
        r = parse_oracle_connect(bytes(pkt))
        self.assertIsNotNone(r)
        self.assertEqual(r.version, 0x013A)
        self.assertIsNone(r.connect_data)


if __name__ == "__main__":
    unittest.main()
