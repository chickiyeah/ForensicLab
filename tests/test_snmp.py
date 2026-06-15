"""forensiclab.snmp 단위 테스트 (stdlib unittest)."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from forensiclab.snmp import (  # noqa: E402
    DEFAULT_COMMUNITIES,
    PDU_GET_BULK_REQUEST,
    PDU_GET_NEXT_REQUEST,
    PDU_GET_REQUEST,
    PDU_RESPONSE,
    PDU_SET_REQUEST,
    PDU_TRAP_V1,
    PDU_TRAP_V2,
    SNMP_V1,
    SNMP_V2C,
    Snmp,
    VarBind,
    parse_snmp,
)


# --- 최소 BER 인코더(테스트 픽스처 생성용) ---------------------------------

def _ber_len(n):
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def _tlv(tag, value):
    return bytes([tag]) + _ber_len(len(value)) + value


def _int(n):
    if n == 0:
        body = b"\x00"
    else:
        nbytes = (n.bit_length() + 8) // 8
        body = n.to_bytes(nbytes, "big", signed=True)
    return _tlv(0x02, body)


def _octet(s):
    return _tlv(0x04, s.encode("latin-1"))


def _null():
    return _tlv(0x05, b"")


def _seq(payload):
    return _tlv(0x30, payload)


def _oid(dotted):
    parts = [int(p) for p in dotted.split(".")]
    body = bytes([parts[0] * 40 + parts[1]])
    for sub in parts[2:]:
        if sub == 0:
            body += b"\x00"
            continue
        chunk = []
        while sub:
            chunk.insert(0, sub & 0x7F)
            sub >>= 7
        for i in range(len(chunk) - 1):
            chunk[i] |= 0x80
        body += bytes(chunk)
    return _tlv(0x06, body)


def _ipaddr(ip):
    return _tlv(0x40, bytes(int(o) for o in ip.split(".")))


def _varbind(oid, value_tlv):
    return _seq(_oid(oid) + value_tlv)


def _pdu(tag_num, request_id, varbinds, error_status=0, error_index=0):
    body = (_int(request_id) + _int(error_status) + _int(error_index)
            + _seq(b"".join(varbinds)))
    return _tlv(0xA0 | tag_num, body)


def _message(version, community, pdu):
    return _seq(_int(version) + _octet(community) + pdu)


# --- 테스트 ---------------------------------------------------------------

class GetRequestTests(unittest.TestCase):
    def test_get_request_recon(self):
        pkt = _message(SNMP_V2C, "public",
                       _pdu(PDU_GET_REQUEST, 1234,
                            [_varbind("1.3.6.1.2.1.1.1.0", _null())]))
        m = parse_snmp(pkt)
        self.assertEqual(m.version, SNMP_V2C)
        self.assertEqual(m.version_name, "v2c")
        self.assertEqual(m.community, "public")
        self.assertEqual(m.pdu_type, PDU_GET_REQUEST)
        self.assertEqual(m.pdu_name, "GetRequest")
        self.assertEqual(m.request_id, 1234)
        self.assertTrue(m.is_recon)
        self.assertFalse(m.is_write)
        self.assertFalse(m.is_trap)
        self.assertTrue(m.is_default_community)
        self.assertEqual(m.oids, ["1.3.6.1.2.1.1.1.0"])

    def test_get_next_and_bulk_are_recon(self):
        for tag in (PDU_GET_NEXT_REQUEST, PDU_GET_BULK_REQUEST):
            pkt = _message(SNMP_V2C, "public",
                           _pdu(tag, 1, [_varbind("1.3.6.1.2.1", _null())]))
            self.assertTrue(parse_snmp(pkt).is_recon)

    def test_non_default_community(self):
        pkt = _message(SNMP_V2C, "s3cr3t",
                       _pdu(PDU_GET_REQUEST, 1, [_varbind("1.3.6.1", _null())]))
        self.assertFalse(parse_snmp(pkt).is_default_community)


class SetRequestTests(unittest.TestCase):
    def test_set_request_is_write(self):
        pkt = _message(SNMP_V2C, "private",
                       _pdu(PDU_SET_REQUEST, 99,
                            [_varbind("1.3.6.1.2.1.1.5.0", _octet("evil"))]))
        m = parse_snmp(pkt)
        self.assertEqual(m.pdu_name, "SetRequest")
        self.assertTrue(m.is_write)
        self.assertFalse(m.is_recon)
        self.assertTrue(m.is_default_community)
        self.assertIn("private", DEFAULT_COMMUNITIES)


class ValueDecodingTests(unittest.TestCase):
    def test_response_with_typed_values(self):
        vbs = [
            _varbind("1.3.6.1.2.1.1.1.0", _octet("Linux router 5.10")),
            _varbind("1.3.6.1.2.1.1.3.0", _tlv(0x43, (123456).to_bytes(3, "big"))),
            _varbind("1.3.6.1.2.1.4.20.1.1", _ipaddr("10.8.0.17")),
        ]
        pkt = _message(SNMP_V2C, "public", _pdu(PDU_RESPONSE, 7, vbs))
        m = parse_snmp(pkt)
        self.assertEqual(m.pdu_name, "Response")
        self.assertEqual(m.varbinds[0].value, "Linux router 5.10")
        self.assertEqual(m.varbinds[1].value, 123456)        # TimeTicks → int.
        self.assertEqual(m.varbinds[2].value, "10.8.0.17")   # IpAddress.
        self.assertEqual(len(m.varbinds), 3)

    def test_error_status_carried(self):
        pkt = _message(SNMP_V2C, "public",
                       _pdu(PDU_RESPONSE, 7, [_varbind("1.3.6.1", _null())],
                            error_status=2, error_index=1))
        m = parse_snmp(pkt)
        self.assertEqual(m.error_status, 2)
        self.assertEqual(m.error_index, 1)


class TrapTests(unittest.TestCase):
    def test_v1_trap(self):
        trap_body = (_oid("1.3.6.1.4.1.9") + _ipaddr("10.8.0.17")
                     + _int(6) + _int(42) + _tlv(0x43, (5000).to_bytes(2, "big"))
                     + _seq(_varbind("1.3.6.1.2.1.1.1.0", _octet("alert"))))
        pkt = _message(SNMP_V1, "public", _tlv(0xA4, trap_body))
        m = parse_snmp(pkt)
        self.assertEqual(m.version, SNMP_V1)
        self.assertEqual(m.pdu_type, PDU_TRAP_V1)
        self.assertEqual(m.pdu_name, "Trap")
        self.assertTrue(m.is_trap)
        self.assertEqual(m.enterprise, "1.3.6.1.4.1.9")
        self.assertEqual(m.agent_addr, "10.8.0.17")
        self.assertEqual(m.generic_trap, 6)
        self.assertEqual(m.specific_trap, 42)
        self.assertEqual(m.oids, ["1.3.6.1.2.1.1.1.0"])

    def test_v2_trap_is_trap(self):
        pkt = _message(SNMP_V2C, "public",
                       _pdu(PDU_TRAP_V2, 5, [_varbind("1.3.6.1.6.3.1.1.4.1.0",
                                                       _oid("1.3.6.1.6.3.1.1.5.1"))]))
        m = parse_snmp(pkt)
        self.assertEqual(m.pdu_name, "SNMPv2-Trap")
        self.assertTrue(m.is_trap)
        self.assertEqual(m.varbinds[0].value, "1.3.6.1.6.3.1.1.5.1")


class RobustnessTests(unittest.TestCase):
    def test_empty_and_short(self):
        self.assertIsNone(parse_snmp(b""))
        self.assertIsNone(parse_snmp(b"\x30"))
        self.assertIsNone(parse_snmp(b"\x30\x05\x02\x01"))

    def test_not_a_sequence(self):
        self.assertIsNone(parse_snmp(_int(1)))

    def test_v3_rejected(self):
        # version=3 은 헤더 구조가 달라 미지원 → None.
        pkt = _message(3, "public",
                       _pdu(PDU_GET_REQUEST, 1, [_varbind("1.3.6.1", _null())]))
        self.assertIsNone(parse_snmp(pkt))

    def test_truncated_length_returns_none(self):
        # 길이가 실제 데이터보다 큼 → None.
        self.assertIsNone(parse_snmp(b"\x30\x82\xff\xff\x02\x01\x01"))

    def test_negative_offset(self):
        pkt = _message(SNMP_V2C, "public",
                       _pdu(PDU_GET_REQUEST, 1, [_varbind("1.3.6.1", _null())]))
        self.assertIsNone(parse_snmp(pkt, offset=-1))

    def test_offset_into_buffer(self):
        pkt = _message(SNMP_V2C, "public",
                       _pdu(PDU_GET_REQUEST, 1, [_varbind("1.3.6.1", _null())]))
        m = parse_snmp(b"\xff\xff\xff" + pkt, offset=3)
        self.assertEqual(m.community, "public")


class DataclassTests(unittest.TestCase):
    def test_varbind_and_snmp_are_frozen(self):
        vb = VarBind(oid="1.3.6.1", value=1)
        with self.assertRaises(Exception):
            vb.value = 2  # type: ignore[misc]
        m = Snmp(version=SNMP_V1, community="x", pdu_type=PDU_GET_REQUEST)
        with self.assertRaises(Exception):
            m.community = "y"  # type: ignore[misc]


if __name__ == "__main__":
    unittest.main()
