"""forensiclab.cldap 단위 테스트 (stdlib unittest)."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from forensiclab.cldap import (  # noqa: E402
    NETLOGON_ATTRIBUTES,
    CldapMessage,
    parse_cldap,
)
from forensiclab.ldap import (  # noqa: E402
    OP_SEARCH_REQUEST,
    OP_SEARCH_RESULT_DONE,
    SCOPE_BASE,
    SCOPE_SUBTREE,
)


# --- 최소 BER 인코더(테스트 픽스처 전용) ---------------------------------

def _ber_len(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def _tlv(tag, value):
    return bytes([tag]) + _ber_len(len(value)) + value


def _int(n, tag=0x02):
    if n == 0:
        body = b"\x00"
    else:
        length = (n.bit_length() + 8) // 8
        body = n.to_bytes(length, "big", signed=True)
    return _tlv(tag, body)


def _octstr(s, tag=0x04):
    if isinstance(s, str):
        s = s.encode("utf-8")
    return _tlv(tag, s)


def _seq(*parts, tag=0x30):
    return _tlv(tag, b"".join(parts))


def _msg(message_id, protocol_op):
    return _seq(_int(message_id), protocol_op)


def _equality(attr, value):
    """equalityMatch [3] SEQUENCE { attributeDesc, assertionValue }."""
    if isinstance(value, str):
        value = value.encode("utf-8")
    return _tlv(0xA3, _octstr(attr) + _octstr(value))


def _and(*subs):
    """and [0] SET OF Filter."""
    return _tlv(0xA0, b"".join(subs))


def _present(attr):
    """present [7] AttributeDescription — 단순 leaf 필터."""
    return _octstr(attr, tag=0x87)


def _search_request(base, scope, attrs, filt=None):
    if filt is None:
        filt = _present("objectClass")
    parts = [
        _octstr(base),
        _int(scope, tag=0x0A),     # scope ENUMERATED.
        _int(0, tag=0x0A),         # derefAliases.
        _int(0),                   # sizeLimit.
        _int(0),                   # timeLimit.
        _tlv(0x01, b"\x00"),       # typesOnly BOOLEAN.
        filt,                      # filter.
        _seq(*[_octstr(a) for a in attrs]),  # attributes.
    ]
    return _tlv(0x63, b"".join(parts))  # [APPLICATION 3].


def _search_done(code=0):
    body = _int(code, tag=0x0A) + _octstr("") + _octstr("")
    return _tlv(0x65, body)  # [APPLICATION 5] SearchResultDone.


# --- 테스트 ----------------------------------------------------------------

class StructureTest(unittest.TestCase):
    def test_returns_none_for_garbage(self):
        self.assertIsNone(parse_cldap(b"not ldap at all"))
        self.assertIsNone(parse_cldap(b""))

    def test_delegates_basic_fields(self):
        pkt = _msg(7, _search_request("", SCOPE_BASE, []))
        r = parse_cldap(pkt)
        self.assertIsInstance(r, CldapMessage)
        self.assertEqual(r.message_id, 7)
        self.assertEqual(r.op_type, OP_SEARCH_REQUEST)
        self.assertEqual(r.op_name, "SearchRequest")
        self.assertTrue(r.is_search_request)
        self.assertFalse(r.is_search_response)


class AmplificationTest(unittest.TestCase):
    def test_rootdse_probe_is_amplification(self):
        # baseObject="" + scope=base + 속성 미지정 = 전형적 반사 탐침.
        pkt = _msg(1, _search_request("", SCOPE_BASE, []))
        r = parse_cldap(pkt)
        self.assertTrue(r.is_rootdse_query)
        self.assertTrue(r.is_amplification_probe)
        self.assertFalse(r.is_netlogon_query)

    def test_wildcard_attrs_is_amplification(self):
        pkt = _msg(1, _search_request("", SCOPE_BASE, ["*", "+"]))
        r = parse_cldap(pkt)
        self.assertTrue(r.is_amplification_probe)

    def test_subtree_search_is_not_rootdse(self):
        pkt = _msg(1, _search_request("dc=corp,dc=local", SCOPE_SUBTREE, []))
        r = parse_cldap(pkt)
        self.assertFalse(r.is_rootdse_query)
        self.assertFalse(r.is_amplification_probe)

    def test_response_side_flag(self):
        pkt = _msg(1, _search_done(0))
        r = parse_cldap(pkt)
        self.assertEqual(r.op_type, OP_SEARCH_RESULT_DONE)
        self.assertTrue(r.is_search_response)
        self.assertEqual(r.result_code, 0)


class NetlogonTest(unittest.TestCase):
    def test_dc_locator_ldap_ping(self):
        filt = _and(
            _equality("DnsDomain", "corp.local"),
            _equality("Host", "CLIENT01"),
            _equality("NtVer", b"\x06\x00\x00\x00"),
        )
        pkt = _msg(2, _search_request("", SCOPE_BASE, ["Netlogon"], filt=filt))
        r = parse_cldap(pkt)
        self.assertTrue(r.is_netlogon_query)
        self.assertFalse(r.is_amplification_probe)  # 목적이 분명 — 반사 아님.
        self.assertEqual(r.dns_domain, "corp.local")
        self.assertEqual(r.queried_host, "CLIENT01")
        # NtVer 바이너리 값도 assertion 으로 보존.
        attrs = dict(r.filter_assertions)
        self.assertIn("NtVer", attrs)

    def test_netlogon_attribute_constant(self):
        self.assertIn("netlogon", NETLOGON_ATTRIBUTES)

    def test_non_netlogon_search_has_no_domain(self):
        pkt = _msg(3, _search_request("", SCOPE_BASE, ["defaultNamingContext"]))
        r = parse_cldap(pkt)
        self.assertFalse(r.is_netlogon_query)
        self.assertIsNone(r.dns_domain)
        self.assertEqual(r.recon_attributes, ["defaultNamingContext"])


class FilterTest(unittest.TestCase):
    def test_simple_present_filter_yields_no_assertions(self):
        pkt = _msg(1, _search_request("", SCOPE_BASE, []))
        r = parse_cldap(pkt)
        self.assertEqual(r.filter_assertions, [])

    def test_top_level_equality_filter(self):
        filt = _equality("DnsDomain", "evil.example")
        pkt = _msg(1, _search_request("", SCOPE_BASE, ["Netlogon"], filt=filt))
        r = parse_cldap(pkt)
        self.assertEqual(r.dns_domain, "evil.example")

    def test_offset_parsing(self):
        pkt = _msg(9, _search_request("", SCOPE_BASE, []))
        r = parse_cldap(b"\xff\xff" + pkt, offset=2)
        self.assertIsNotNone(r)
        self.assertEqual(r.message_id, 9)


if __name__ == "__main__":
    unittest.main()
