"""forensiclab.whois 단위 테스트 (stdlib unittest)."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from forensiclab.whois import (  # noqa: E402
    WHOIS_PORTS,
    WhoisQuery,
    parse_whois,
)


def _line(text: str) -> bytes:
    """CRLF 종단을 붙여 바이트로(UTF-8)."""
    return (text + "\r\n").encode("utf-8")


class TargetClassificationTests(unittest.TestCase):
    def test_domain(self):
        q = parse_whois(_line("example.com"))
        self.assertIsInstance(q, WhoisQuery)
        self.assertEqual(q.target, "example.com")
        self.assertEqual(q.target_type, "domain")
        self.assertTrue(q.is_domain_query)
        self.assertFalse(q.is_ip_query)

    def test_ipv4(self):
        q = parse_whois(_line("8.8.8.8"))
        self.assertEqual(q.target_type, "ipv4")
        self.assertTrue(q.is_ip_query)

    def test_ipv6(self):
        q = parse_whois(_line("2001:4860:4860::8888"))
        self.assertEqual(q.target_type, "ipv6")
        self.assertTrue(q.is_ip_query)

    def test_ipv4_cidr(self):
        q = parse_whois(_line("192.0.2.0/24"))
        self.assertEqual(q.target_type, "ipv4")

    def test_asn_prefixed(self):
        q = parse_whois(_line("AS15169"))
        self.assertEqual(q.target_type, "asn")
        self.assertTrue(q.is_asn_query)

    def test_asn_numeric(self):
        q = parse_whois(_line("15169"))
        self.assertEqual(q.target_type, "asn")

    def test_handle(self):
        q = parse_whois(_line("ABC123-ARIN"))
        self.assertEqual(q.target_type, "handle")

    def test_subdomain_domain(self):
        q = parse_whois(_line("mail.victim.org"))
        self.assertEqual(q.target_type, "domain")


class KeywordTests(unittest.TestCase):
    def test_object_keyword(self):
        q = parse_whois(_line("domain example.com"))
        self.assertEqual(q.keyword, "domain")
        self.assertEqual(q.target, "example.com")
        self.assertEqual(q.target_type, "domain")

    def test_inetnum_keyword(self):
        q = parse_whois(_line("inetnum 8.8.8.8"))
        self.assertEqual(q.keyword, "inetnum")
        self.assertEqual(q.target, "8.8.8.8")

    def test_keyword_case_insensitive(self):
        q = parse_whois(_line("DOMAIN example.com"))
        self.assertEqual(q.keyword, "domain")


class RedirectTests(unittest.TestCase):
    def test_dash_h_redirect(self):
        q = parse_whois(_line("-h whois.arin.net 8.8.8.8"))
        self.assertEqual(q.redirect_host, "whois.arin.net")
        self.assertEqual(q.target, "8.8.8.8")
        self.assertTrue(q.has_redirect)
        self.assertIn("-h", q.flags)

    def test_at_host_redirect(self):
        q = parse_whois(_line("@whois.ripe.net 193.0.0.1"))
        self.assertEqual(q.redirect_host, "whois.ripe.net")
        self.assertEqual(q.target, "193.0.0.1")
        self.assertTrue(q.has_redirect)

    def test_no_redirect(self):
        q = parse_whois(_line("example.com"))
        self.assertIsNone(q.redirect_host)
        self.assertFalse(q.has_redirect)


class FlagTests(unittest.TestCase):
    def test_type_flag_absorbs_value(self):
        # RIPE -T person ABC — 타입 플래그가 값 토큰을 흡수.
        q = parse_whois(_line("-T person ABC-RIPE"))
        self.assertIn("-T", q.flags)
        self.assertIn("person", q.flags)
        self.assertEqual(q.target, "ABC-RIPE")

    def test_flag_does_not_absorb_domain(self):
        # 점 있는 다음 토큰은 대상으로 보고 흡수 안 함.
        q = parse_whois(_line("-r example.com"))
        self.assertIn("-r", q.flags)
        self.assertEqual(q.target, "example.com")

    def test_port_flag(self):
        q = parse_whois(_line("-p 4343 example.com"))
        self.assertIn("-p", q.flags)
        self.assertEqual(q.target, "example.com")


class WildcardTests(unittest.TestCase):
    def test_wildcard_detected(self):
        q = parse_whois(_line("example*"))
        self.assertTrue(q.is_wildcard)

    def test_no_wildcard(self):
        q = parse_whois(_line("example.com"))
        self.assertFalse(q.is_wildcard)


class RobustnessTests(unittest.TestCase):
    def test_empty_line(self):
        q = parse_whois(_line(""))
        self.assertIsInstance(q, WhoisQuery)
        self.assertIsNone(q.target)
        self.assertTrue(q.is_empty)
        self.assertEqual(q.target_type, "unknown")

    def test_lf_only_line_ending(self):
        q = parse_whois(b"example.com\n")
        self.assertEqual(q.target, "example.com")

    def test_only_first_line_parsed(self):
        q = parse_whois(_line("example.com") + _line("other.net"))
        self.assertEqual(q.target, "example.com")

    def test_offset(self):
        raw = b"\x00\x00" + _line("example.com")
        q = parse_whois(raw, offset=2)
        self.assertEqual(q.target, "example.com")

    def test_empty_bytes_returns_none(self):
        self.assertIsNone(parse_whois(b""))

    def test_negative_offset_returns_none(self):
        self.assertIsNone(parse_whois(_line("example.com"), offset=-1))

    def test_raw_preserved(self):
        q = parse_whois(_line("-h whois.arin.net 8.8.8.8"))
        self.assertEqual(q.raw, "-h whois.arin.net 8.8.8.8")

    def test_flags_only_no_target(self):
        q = parse_whois(_line("-h whois.arin.net"))
        self.assertEqual(q.redirect_host, "whois.arin.net")
        self.assertIsNone(q.target)
        self.assertTrue(q.is_empty)

    def test_ports_constant(self):
        self.assertIn(43, WHOIS_PORTS)


if __name__ == "__main__":
    unittest.main()
