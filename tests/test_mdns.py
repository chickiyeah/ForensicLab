"""forensiclab.mdns 단위 테스트 (stdlib unittest)."""

import os
import socket
import struct
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from forensiclab.mdns import (  # noqa: E402
    MDNS_PORT,
    MdnsMessage,
    MdnsQuestion,
    ResourceRecord,
    parse_message,
    qtype_name,
    service_label,
)


def _encode_name(name: str) -> bytes:
    """이름을 DNS 라벨 형식(각 라벨 len+bytes, NUL 종단)으로."""
    out = bytearray()
    for label in name.split("."):
        b = label.encode("utf-8")
        out.append(len(b))
        out += b
    out.append(0)
    return bytes(out)


def _header(txn_id, flags, qd=0, an=0, ns=0, ar=0):
    return struct.pack(">HHHHHH", txn_id, flags, qd, an, ns, ar)


def _query(name, qtype=1, txn_id=0x0000, flags=0x0000, qclass=1):
    pkt = _header(txn_id, flags, qd=1)
    pkt += _encode_name(name) + struct.pack(">HH", qtype, qclass)
    return pkt


def _a_rr(name, ip, rclass=1):
    return _encode_name(name) + struct.pack(">HHIH", 1, rclass, 120, 4) + socket.inet_aton(ip)


class ParseQueryTest(unittest.TestCase):
    def test_basic_query(self):
        msg = parse_message(_query("macbook.local"))
        self.assertIsInstance(msg, MdnsMessage)
        self.assertEqual(msg.id, 0)
        self.assertTrue(msg.is_query)
        self.assertFalse(msg.is_response)
        self.assertEqual(msg.opcode, 0)
        self.assertEqual(msg.queried_names, ["macbook.local"])
        self.assertEqual(msg.questions[0].qtype_name, "A")
        self.assertEqual(msg.questions[0].qclass, 1)

    def test_aaaa_qtype(self):
        msg = parse_message(_query("host1.local", qtype=28))
        self.assertEqual(msg.questions[0].qtype_name, "AAAA")

    def test_flags_query_clear(self):
        msg = parse_message(_query("x.local"))
        self.assertFalse(msg.authoritative)
        self.assertFalse(msg.truncated)
        self.assertEqual(msg.rcode, 0)


class UnicastBitTest(unittest.TestCase):
    def test_qu_bit_set(self):
        # QU 비트(0x8000) + IN(1) → qclass=1, unicast_response=True.
        msg = parse_message(_query("h.local", qclass=0x8001))
        self.assertTrue(msg.questions[0].unicast_response)
        self.assertEqual(msg.questions[0].qclass, 1)
        self.assertTrue(msg.unicast_requested)

    def test_qu_bit_clear(self):
        msg = parse_message(_query("h.local", qclass=1))
        self.assertFalse(msg.questions[0].unicast_response)
        self.assertFalse(msg.unicast_requested)


class ServiceDiscoveryTest(unittest.TestCase):
    def test_service_enumeration_meta_query(self):
        msg = parse_message(_query("_services._dns-sd._udp.local", qtype=12))
        self.assertTrue(msg.has_service_enumeration)
        self.assertTrue(msg.questions[0].is_service_enumeration)

    def test_service_enumeration_case_insensitive(self):
        msg = parse_message(_query("_SERVICES._DNS-SD._UDP.LOCAL", qtype=12))
        self.assertTrue(msg.has_service_enumeration)

    def test_non_enumeration_query(self):
        msg = parse_message(_query("printer.local"))
        self.assertFalse(msg.has_service_enumeration)

    def test_queried_service_type(self):
        msg = parse_message(_query("_airplay._tcp.local", qtype=12))
        self.assertEqual(msg.questions[0].service_type, "_airplay._tcp")
        self.assertEqual(msg.queried_service_types, ["_airplay._tcp"])

    def test_service_label_helper(self):
        self.assertEqual(service_label("Living Room._googlecast._tcp.local"),
                         "_googlecast._tcp")
        self.assertEqual(service_label("_ipp._tcp.local"), "_ipp._tcp")
        self.assertIsNone(service_label("plain.local"))


class PoisonResponseTest(unittest.TestCase):
    def test_response_with_a_record(self):
        # 공격자가 .local 이름을 자기 IP 로 답하는 포이즈닝 응답.
        pkt = _header(0x0000, 0x8400, qd=0, an=1)  # QR + AA
        pkt += _a_rr("victim.local", "10.0.0.66")
        msg = parse_message(pkt)
        self.assertTrue(msg.is_response)
        self.assertTrue(msg.authoritative)
        self.assertEqual(msg.answer_count, 1)
        self.assertEqual(msg.answers[0].address, "10.0.0.66")
        self.assertEqual(msg.answer_addresses, ["10.0.0.66"])

    def test_cache_flush_bit(self):
        # rclass 0x8001 = cache-flush + IN.
        pkt = _header(0, 0x8400, an=1) + _a_rr("h.local", "1.2.3.4", rclass=0x8001)
        msg = parse_message(pkt)
        self.assertTrue(msg.answers[0].cache_flush)
        self.assertEqual(msg.answers[0].rclass, 1)

    def test_aaaa_answer(self):
        rdata = socket.inet_pton(socket.AF_INET6, "fe80::dead:beef")
        pkt = _header(0, 0x8400, an=1)
        pkt += _encode_name("h.local") + struct.pack(">HHIH", 28, 1, 120, 16) + rdata
        msg = parse_message(pkt)
        self.assertEqual(msg.answers[0].address, "fe80::dead:beef")


class RecordTypeTest(unittest.TestCase):
    def test_ptr_target_extracted(self):
        # PTR: 서비스 타입 → 인스턴스 이름.
        instance = "Office Printer._ipp._tcp.local"
        rdata = _encode_name(instance)
        pkt = _header(0, 0x8400, an=1)
        pkt += _encode_name("_ipp._tcp.local")
        pkt += struct.pack(">HHIH", 12, 1, 120, len(rdata)) + rdata
        msg = parse_message(pkt)
        rr = msg.answers[0]
        self.assertEqual(rr.rtype_name, "PTR")
        self.assertEqual(rr.target, instance)
        self.assertEqual(rr.service_type, "_ipp._tcp")
        self.assertEqual(msg.advertised_service_types, ["_ipp._tcp"])

    def test_srv_target_and_port(self):
        target = _encode_name("macbook.local")
        rdata = struct.pack(">HHH", 0, 0, 631) + target
        pkt = _header(0, 0x8400, an=1)
        pkt += _encode_name("inst._ipp._tcp.local")
        pkt += struct.pack(">HHIH", 33, 1, 120, len(rdata)) + rdata
        msg = parse_message(pkt)
        rr = msg.answers[0]
        self.assertEqual(rr.rtype_name, "SRV")
        self.assertEqual(rr.port, 631)
        self.assertEqual(rr.target, "macbook.local")

    def test_txt_records(self):
        kv = b"\x09model=J96\x08rp=ipp/p"
        pkt = _header(0, 0x8400, an=1)
        pkt += _encode_name("inst._ipp._tcp.local")
        pkt += struct.pack(">HHIH", 16, 1, 120, len(kv)) + kv
        msg = parse_message(pkt)
        self.assertEqual(msg.answers[0].txt, ["model=J96", "rp=ipp/p"])

    def test_non_address_answer_address_none(self):
        pkt = _header(0, 0x8400, an=1)
        pkt += _encode_name("h.local") + struct.pack(">HHIH", 16, 1, 120, 3) + b"abc"
        msg = parse_message(pkt)
        self.assertIsNone(msg.answers[0].address)
        self.assertEqual(msg.answer_addresses, [])


class RobustnessTest(unittest.TestCase):
    def test_too_short(self):
        self.assertIsNone(parse_message(b"\x00\x01\x00\x00"))

    def test_empty(self):
        self.assertIsNone(parse_message(b""))

    def test_nonzero_opcode_rejected(self):
        flags = (5 << 11)
        self.assertIsNone(parse_message(_header(0, flags, qd=0)))

    def test_truncated_question_keeps_header(self):
        pkt = _header(0, 0x0000, qd=2)
        pkt += _encode_name("only.local") + struct.pack(">HH", 1, 1)
        msg = parse_message(pkt)
        self.assertIsNotNone(msg)
        self.assertEqual(len(msg.questions), 1)

    def test_truncated_rdata_drops_record(self):
        pkt = _header(0, 0x8400, an=1)
        pkt += _encode_name("h.local") + struct.pack(">HHIH", 1, 1, 120, 4) + b"\x0a\x00"
        msg = parse_message(pkt)
        self.assertIsNotNone(msg)
        self.assertEqual(len(msg.answers), 0)

    def test_offset_support(self):
        prefix = b"\xff\xee"
        msg = parse_message(prefix + _query("HOST.local"), offset=2)
        self.assertEqual(msg.queried_names, ["HOST.local"])

    def test_negative_offset(self):
        self.assertIsNone(parse_message(_query("x.local"), offset=-1))


class MiscTest(unittest.TestCase):
    def test_port_constant(self):
        self.assertEqual(MDNS_PORT, 5353)

    def test_qtype_name_unknown(self):
        self.assertEqual(qtype_name(99), "99")

    def test_resourcerecord_dataclass(self):
        rr = ResourceRecord(name="h.local", rtype=1, rclass=1, ttl=120, address="1.2.3.4")
        self.assertEqual(rr.rtype_name, "A")
        self.assertFalse(rr.cache_flush)

    def test_question_dataclass(self):
        q = MdnsQuestion(name="h.local", qtype=1, qclass=1)
        self.assertFalse(q.unicast_response)
        self.assertFalse(q.is_service_enumeration)


if __name__ == "__main__":
    unittest.main()
