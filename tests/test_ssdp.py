"""forensiclab.ssdp 단위 테스트 (stdlib unittest)."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from forensiclab.ssdp import (  # noqa: E402
    SSDP_MULTICAST,
    SsdpMessage,
    parse_ssdp,
)


def _crlf(*lines: str) -> bytes:
    """CRLF 로 줄을 잇고 헤더 블록 종단(빈 줄)을 붙여 바이트로."""
    return ("\r\n".join(lines) + "\r\n\r\n").encode("ascii")


M_SEARCH_ALL = _crlf(
    "M-SEARCH * HTTP/1.1",
    "HOST: 239.255.255.250:1900",
    'MAN: "ssdp:discover"',
    "MX: 2",
    "ST: ssdp:all",
)

NOTIFY_ALIVE = _crlf(
    "NOTIFY * HTTP/1.1",
    "HOST: 239.255.255.250:1900",
    "CACHE-CONTROL: max-age=1800",
    "LOCATION: http://192.168.0.1:5000/rootDesc.xml",
    "NT: upnp:rootdevice",
    "NTS: ssdp:alive",
    "SERVER: Linux/3.14 UPnP/1.0 MiniUPnPd/1.9",
    "USN: uuid:abcd-1234::upnp:rootdevice",
)

RESPONSE_200 = _crlf(
    "HTTP/1.1 200 OK",
    "CACHE-CONTROL: max-age=1800",
    "LOCATION: http://192.168.0.42:80/desc.xml",
    "SERVER: Custom/1.0 UPnP/1.1 IoTCam/2.3",
    "ST: urn:schemas-upnp-org:device:Basic:1",
    "USN: uuid:cam-99",
)


class StartLineTests(unittest.TestCase):
    def test_m_search_request(self):
        msg = parse_ssdp(M_SEARCH_ALL)
        self.assertIsNotNone(msg)
        self.assertFalse(msg.is_response)
        self.assertEqual(msg.method, "M-SEARCH")
        self.assertIsNone(msg.status_code)
        self.assertEqual(msg.http_version, "HTTP/1.1")

    def test_notify_request(self):
        msg = parse_ssdp(NOTIFY_ALIVE)
        self.assertEqual(msg.method, "NOTIFY")
        self.assertFalse(msg.is_response)

    def test_http_response(self):
        msg = parse_ssdp(RESPONSE_200)
        self.assertTrue(msg.is_response)
        self.assertIsNone(msg.method)
        self.assertEqual(msg.status_code, 200)

    def test_lowercase_method_normalized(self):
        msg = parse_ssdp(_crlf("m-search * HTTP/1.1", "ST: ssdp:all"))
        self.assertEqual(msg.method, "M-SEARCH")


class HeaderTests(unittest.TestCase):
    def test_case_insensitive_lookup(self):
        msg = parse_ssdp(NOTIFY_ALIVE)
        self.assertEqual(msg.header("Location"), "http://192.168.0.1:5000/rootDesc.xml")
        self.assertEqual(msg.header("LOCATION"), msg.header("location"))

    def test_convenience_accessors(self):
        msg = parse_ssdp(NOTIFY_ALIVE)
        self.assertEqual(msg.location, "http://192.168.0.1:5000/rootDesc.xml")
        self.assertEqual(msg.server, "Linux/3.14 UPnP/1.0 MiniUPnPd/1.9")
        self.assertEqual(msg.usn, "uuid:abcd-1234::upnp:rootdevice")
        self.assertEqual(msg.notification_subtype, "ssdp:alive")

    def test_search_target_prefers_st_then_nt(self):
        # 응답/질의는 ST, 광고는 NT 에서 가져온다.
        self.assertEqual(parse_ssdp(RESPONSE_200).search_target,
                         "urn:schemas-upnp-org:device:Basic:1")
        self.assertEqual(parse_ssdp(NOTIFY_ALIVE).search_target, "upnp:rootdevice")

    def test_colonless_line_skipped(self):
        msg = parse_ssdp(_crlf("M-SEARCH * HTTP/1.1", "garbage line", "ST: ssdp:all"))
        self.assertEqual(msg.header("st"), "ssdp:all")
        self.assertEqual(len(msg.headers), 1)


class ClueTests(unittest.TestCase):
    def test_is_discovery(self):
        self.assertTrue(parse_ssdp(M_SEARCH_ALL).is_discovery)
        self.assertFalse(parse_ssdp(NOTIFY_ALIVE).is_discovery)

    def test_amplification_probe(self):
        self.assertTrue(parse_ssdp(M_SEARCH_ALL).is_amplification_probe)

    def test_targeted_search_is_not_amplification(self):
        msg = parse_ssdp(_crlf(
            "M-SEARCH * HTTP/1.1",
            "ST: urn:schemas-upnp-org:device:Basic:1",
        ))
        self.assertFalse(msg.is_amplification_probe)

    def test_notify_is_not_amplification(self):
        self.assertFalse(parse_ssdp(NOTIFY_ALIVE).is_amplification_probe)

    def test_multicast_constant(self):
        self.assertEqual(SSDP_MULTICAST, "239.255.255.250:1900")


class RobustnessTests(unittest.TestCase):
    def test_lf_only_line_endings(self):
        raw = ("M-SEARCH * HTTP/1.1\nST: ssdp:all\n\n").encode("ascii")
        msg = parse_ssdp(raw)
        self.assertIsNotNone(msg)
        self.assertTrue(msg.is_amplification_probe)

    def test_body_after_blank_line_ignored(self):
        raw = RESPONSE_200 + b"<xml>device body should be ignored</xml>"
        msg = parse_ssdp(raw)
        self.assertEqual(msg.status_code, 200)
        self.assertIsNone(msg.header("xml"))

    def test_offset(self):
        raw = b"\x00\x00" + M_SEARCH_ALL
        msg = parse_ssdp(raw, offset=2)
        self.assertEqual(msg.method, "M-SEARCH")

    def test_empty_returns_none(self):
        self.assertIsNone(parse_ssdp(b""))

    def test_non_ssdp_start_line_returns_none(self):
        self.assertIsNone(parse_ssdp(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
        self.assertIsNone(parse_ssdp(b"random udp payload"))

    def test_bad_status_code_returns_none(self):
        self.assertIsNone(parse_ssdp(b"HTTP/1.1 OK NotANumber\r\n\r\n"))

    def test_request_without_version_returns_none(self):
        self.assertIsNone(parse_ssdp(b"M-SEARCH *\r\n\r\n"))

    def test_negative_offset_returns_none(self):
        self.assertIsNone(parse_ssdp(M_SEARCH_ALL, offset=-1))


if __name__ == "__main__":
    unittest.main()
