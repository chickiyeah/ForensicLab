"""forensiclab.wsd 단위 테스트 (stdlib unittest)."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from forensiclab.wsd import (  # noqa: E402
    WSD_MULTICAST,
    WSD_MESSAGE_TYPES,
    WsdMessage,
    parse_wsd,
)

_NS = (
    'xmlns:soap="http://www.w3.org/2003/05/soap-envelope" '
    'xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" '
    'xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery"'
)


def _env(header: str, body: str) -> bytes:
    return (
        '<?xml version="1.0" encoding="utf-8"?>'
        f"<soap:Envelope {_NS}>"
        f"<soap:Header>{header}</soap:Header>"
        f"<soap:Body>{body}</soap:Body>"
        "</soap:Envelope>"
    ).encode("utf-8")


# ONVIF 카메라를 노린 전형적 Probe.
PROBE_ONVIF = _env(
    "<wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</wsa:Action>"
    "<wsa:MessageID>urn:uuid:11111111-1111-1111-1111-111111111111</wsa:MessageID>"
    "<wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To>",
    "<wsd:Probe>"
    "<wsd:Types>dn:NetworkVideoTransmitter</wsd:Types>"
    "<wsd:Scopes>onvif://www.onvif.org/type/video_encoder</wsd:Scopes>"
    "</wsd:Probe>",
)

# Types/Scopes 없는 와일드카드 Probe — 증폭 표적.
PROBE_WILDCARD = _env(
    "<wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</wsa:Action>"
    "<wsa:MessageID>urn:uuid:22222222-2222-2222-2222-222222222222</wsa:MessageID>",
    "<wsd:Probe></wsd:Probe>",
)

# Probe 에 대한 ProbeMatches 응답(장치가 XAddrs 노출).
PROBE_MATCHES = _env(
    "<wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/ProbeMatches</wsa:Action>"
    "<wsa:MessageID>urn:uuid:33333333-3333-3333-3333-333333333333</wsa:MessageID>"
    "<wsa:RelatesTo>urn:uuid:11111111-1111-1111-1111-111111111111</wsa:RelatesTo>",
    "<wsd:ProbeMatches><wsd:ProbeMatch>"
    "<wsa:EndpointReference><wsa:Address>urn:uuid:cam-aaaa</wsa:Address></wsa:EndpointReference>"
    "<wsd:Types>dn:NetworkVideoTransmitter</wsd:Types>"
    "<wsd:Scopes>onvif://www.onvif.org/name/ACME onvif://www.onvif.org/hardware/IPC</wsd:Scopes>"
    "<wsd:XAddrs>http://192.168.1.50/onvif/device_service</wsd:XAddrs>"
    "<wsd:MetadataVersion>1</wsd:MetadataVersion>"
    "</wsd:ProbeMatch></wsd:ProbeMatches>",
)

# 장치 가입 광고 Hello.
HELLO = _env(
    "<wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Hello</wsa:Action>"
    "<wsa:MessageID>urn:uuid:44444444-4444-4444-4444-444444444444</wsa:MessageID>",
    "<wsd:Hello>"
    "<wsa:EndpointReference><wsa:Address>urn:uuid:printer-bbbb</wsa:Address></wsa:EndpointReference>"
    "<wsd:Types>wsdp:Device PrintDeviceType</wsd:Types>"
    "<wsd:XAddrs>http://10.0.0.5:3911/ http://[fe80::1]:3911/</wsd:XAddrs>"
    "<wsd:MetadataVersion>2</wsd:MetadataVersion>"
    "</wsd:Hello>",
)


class ProbeTests(unittest.TestCase):
    def test_probe_basic(self):
        msg = parse_wsd(PROBE_ONVIF)
        self.assertIsNotNone(msg)
        self.assertEqual(msg.message_type, "Probe")
        self.assertTrue(msg.is_request)
        self.assertFalse(msg.is_response)
        self.assertTrue(msg.is_probe)
        self.assertEqual(
            msg.action,
            "http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe",
        )

    def test_probe_types_scopes(self):
        msg = parse_wsd(PROBE_ONVIF)
        self.assertEqual(msg.types, ["dn:NetworkVideoTransmitter"])
        self.assertEqual(msg.scopes, ["onvif://www.onvif.org/type/video_encoder"])
        self.assertFalse(msg.is_amplification_probe)

    def test_probe_message_id_to(self):
        msg = parse_wsd(PROBE_ONVIF)
        self.assertEqual(
            msg.message_id, "urn:uuid:11111111-1111-1111-1111-111111111111"
        )
        self.assertEqual(msg.to, "urn:schemas-xmlsoap-org:ws:2005:04:discovery")
        self.assertIsNone(msg.relates_to)


class AmplificationTests(unittest.TestCase):
    def test_wildcard_probe_is_amplification(self):
        msg = parse_wsd(PROBE_WILDCARD)
        self.assertEqual(msg.message_type, "Probe")
        self.assertEqual(msg.types, [])
        self.assertEqual(msg.scopes, [])
        self.assertTrue(msg.is_amplification_probe)

    def test_typed_probe_not_amplification(self):
        self.assertFalse(parse_wsd(PROBE_ONVIF).is_amplification_probe)

    def test_response_not_amplification(self):
        self.assertFalse(parse_wsd(PROBE_MATCHES).is_amplification_probe)


class ProbeMatchesTests(unittest.TestCase):
    def test_probe_matches_type_and_relation(self):
        msg = parse_wsd(PROBE_MATCHES)
        self.assertEqual(msg.message_type, "ProbeMatches")
        self.assertTrue(msg.is_response)
        self.assertFalse(msg.is_request)
        self.assertEqual(
            msg.relates_to, "urn:uuid:11111111-1111-1111-1111-111111111111"
        )

    def test_probe_matches_xaddrs_recon(self):
        msg = parse_wsd(PROBE_MATCHES)
        self.assertEqual(
            msg.xaddrs, ["http://192.168.1.50/onvif/device_service"]
        )
        self.assertEqual(msg.device_addresses, msg.xaddrs)
        self.assertEqual(msg.endpoint_reference, "urn:uuid:cam-aaaa")
        self.assertEqual(msg.metadata_version, 1)

    def test_probe_matches_scopes(self):
        msg = parse_wsd(PROBE_MATCHES)
        self.assertIn("onvif://www.onvif.org/name/ACME", msg.scopes)
        self.assertIn("onvif://www.onvif.org/hardware/IPC", msg.scopes)


class HelloTests(unittest.TestCase):
    def test_hello_type(self):
        msg = parse_wsd(HELLO)
        self.assertEqual(msg.message_type, "Hello")
        self.assertTrue(msg.is_response)

    def test_hello_multiple_xaddrs(self):
        msg = parse_wsd(HELLO)
        self.assertEqual(
            msg.xaddrs, ["http://10.0.0.5:3911/", "http://[fe80::1]:3911/"]
        )
        self.assertEqual(msg.endpoint_reference, "urn:uuid:printer-bbbb")
        self.assertEqual(msg.metadata_version, 2)
        self.assertIn("PrintDeviceType", msg.types)


class InferenceTests(unittest.TestCase):
    def test_type_inferred_from_body_without_action(self):
        # Action 헤더가 없어도 body 요소 localname 으로 판별.
        data = _env(
            "<wsa:MessageID>urn:uuid:noact</wsa:MessageID>",
            "<wsd:Resolve>"
            "<wsa:EndpointReference><wsa:Address>urn:uuid:x</wsa:Address>"
            "</wsa:EndpointReference></wsd:Resolve>",
        )
        msg = parse_wsd(data)
        self.assertIsNotNone(msg)
        self.assertEqual(msg.message_type, "Resolve")
        self.assertTrue(msg.is_request)

    def test_offset(self):
        prefix = b"\x00\x00garbage"
        msg = parse_wsd(prefix + PROBE_ONVIF, offset=len(prefix))
        self.assertIsNotNone(msg)
        self.assertEqual(msg.message_type, "Probe")


class RobustnessTests(unittest.TestCase):
    def test_empty(self):
        self.assertIsNone(parse_wsd(b""))

    def test_not_xml(self):
        self.assertIsNone(parse_wsd(b"NOTIFY * HTTP/1.1\r\n\r\n"))

    def test_non_soap_xml(self):
        self.assertIsNone(parse_wsd(b"<root><child/></root>"))

    def test_soap_but_not_wsd(self):
        # SOAP 봉투지만 WS-Discovery 가 아니면 None.
        data = _env(
            "<wsa:Action>http://example.com/SomethingElse</wsa:Action>",
            "<foo:Bar xmlns:foo='http://example.com/foo'/>",
        )
        self.assertIsNone(parse_wsd(data))

    def test_malformed_xml(self):
        self.assertIsNone(parse_wsd(b"<soap:Envelope><soap:Header>"))

    def test_doctype_rejected(self):
        # 엔티티 폭탄 방어: DOCTYPE/ENTITY 선언이 있으면 거부.
        bomb = (
            b'<?xml version="1.0"?>'
            b'<!DOCTYPE Envelope [<!ENTITY lol "lol">]>'
            b"<soap:Envelope " + _NS.encode() + b"></soap:Envelope>"
        )
        self.assertIsNone(parse_wsd(bomb))

    def test_bad_offset(self):
        self.assertIsNone(parse_wsd(PROBE_ONVIF, offset=-1))
        self.assertIsNone(parse_wsd(PROBE_ONVIF, offset=len(PROBE_ONVIF) + 5))

    def test_offset_at_end(self):
        self.assertIsNone(parse_wsd(PROBE_ONVIF, offset=len(PROBE_ONVIF)))


class ConstantsTests(unittest.TestCase):
    def test_multicast(self):
        self.assertEqual(WSD_MULTICAST, "239.255.255.250:3702")

    def test_message_types_complete(self):
        for t in ("Hello", "Bye", "Probe", "ProbeMatches", "Resolve", "ResolveMatches"):
            self.assertIn(t, WSD_MESSAGE_TYPES)

    def test_dataclass_frozen(self):
        msg = parse_wsd(PROBE_ONVIF)
        self.assertIsInstance(msg, WsdMessage)
        with self.assertRaises(Exception):
            msg.action = "x"  # type: ignore[misc]


if __name__ == "__main__":
    unittest.main()
