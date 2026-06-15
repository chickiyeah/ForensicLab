"""forensiclab.ldap 단위 테스트 (stdlib unittest)."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from forensiclab.ldap import (  # noqa: E402
    AUTH_SASL,
    AUTH_SIMPLE,
    OP_BIND_REQUEST,
    OP_BIND_RESPONSE,
    OP_DEL_REQUEST,
    OP_EXTENDED_REQUEST,
    OP_MODIFY_REQUEST,
    OP_SEARCH_REQUEST,
    RESULT_INVALID_CREDENTIALS,
    RESULT_SUCCESS,
    SCOPE_SUBTREE,
    LdapMessage,
    parse_ldap,
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
    """LDAPMessage = SEQUENCE { messageID INTEGER, protocolOp }."""
    return _seq(_int(message_id), protocol_op)


def _bind_request(version, name, simple_pw=None, sasl_mech=None):
    parts = [_int(version), _octstr(name)]
    if simple_pw is not None:
        parts.append(_octstr(simple_pw, tag=0x80))  # [0] context primitive.
    elif sasl_mech is not None:
        parts.append(_tlv(0xA3, _octstr(sasl_mech)))  # [3] constructed SEQ.
    return _tlv(0x60, b"".join(parts))  # [APPLICATION 0] constructed.


def _search_request(base, scope, attrs):
    parts = [
        _octstr(base),
        _int(scope, tag=0x0A),     # scope ENUMERATED.
        _int(0, tag=0x0A),         # derefAliases.
        _int(0),                   # sizeLimit.
        _int(0),                   # timeLimit.
        _tlv(0x01, b"\x00"),       # typesOnly BOOLEAN.
        _octstr("objectClass", tag=0x87),  # filter present [7] -> 단순 leaf.
        _seq(*[_octstr(a) for a in attrs]),  # attributes.
    ]
    return _tlv(0x63, b"".join(parts))  # [APPLICATION 3].


def _ldap_result(code, matched_dn="", tag=0x61):
    body = _int(code, tag=0x0A) + _octstr(matched_dn) + _octstr("")
    return _tlv(tag, body)  # default [APPLICATION 1] BindResponse.


# --- 테스트 ----------------------------------------------------------------

class BindRequestTest(unittest.TestCase):
    def test_simple_bind_plaintext_password(self):
        pkt = _msg(1, _bind_request(3, "CN=admin,DC=corp,DC=local", simple_pw="S3cr3t!"))
        r = parse_ldap(pkt)
        self.assertIsInstance(r, LdapMessage)
        self.assertEqual(r.op_type, OP_BIND_REQUEST)
        self.assertEqual(r.op_name, "BindRequest")
        self.assertEqual(r.message_id, 1)
        self.assertEqual(r.bind_version, 3)
        self.assertEqual(r.bind_dn, "CN=admin,DC=corp,DC=local")
        self.assertEqual(r.auth_type, AUTH_SIMPLE)
        self.assertEqual(r.simple_password, "S3cr3t!")
        self.assertTrue(r.is_simple_bind)
        self.assertTrue(r.has_plaintext_password)
        self.assertFalse(r.is_anonymous_bind)

    def test_anonymous_bind(self):
        pkt = _msg(1, _bind_request(3, "", simple_pw=""))
        r = parse_ldap(pkt)
        self.assertTrue(r.is_anonymous_bind)
        self.assertFalse(r.has_plaintext_password)
        self.assertEqual(r.bind_dn, "")

    def test_sasl_bind_mechanism(self):
        pkt = _msg(2, _bind_request(3, "", sasl_mech="GSSAPI"))
        r = parse_ldap(pkt)
        self.assertEqual(r.auth_type, AUTH_SASL)
        self.assertEqual(r.sasl_mechanism, "GSSAPI")
        self.assertFalse(r.is_simple_bind)
        self.assertIsNone(r.simple_password)

    def test_utf8_dn(self):
        pkt = _msg(1, _bind_request(3, "CN=관리자,DC=corp", simple_pw="pw"))
        r = parse_ldap(pkt)
        self.assertEqual(r.bind_dn, "CN=관리자,DC=corp")


class SearchRequestTest(unittest.TestCase):
    def test_subtree_search_with_sensitive_attrs(self):
        pkt = _msg(3, _search_request(
            "DC=corp,DC=local", SCOPE_SUBTREE,
            ["cn", "userPassword", "memberOf"]))
        r = parse_ldap(pkt)
        self.assertEqual(r.op_type, OP_SEARCH_REQUEST)
        self.assertTrue(r.is_search)
        self.assertEqual(r.base_object, "DC=corp,DC=local")
        self.assertEqual(r.scope, SCOPE_SUBTREE)
        self.assertEqual(r.scope_name, "wholeSubtree")
        self.assertTrue(r.is_subtree_search)
        self.assertEqual(r.attributes, ["cn", "userPassword", "memberOf"])
        self.assertEqual(r.sensitive_attributes, ["userPassword"])

    def test_base_search_no_sensitive(self):
        pkt = _msg(4, _search_request("CN=x", 0, ["cn", "sn"]))
        r = parse_ldap(pkt)
        self.assertEqual(r.scope_name, "baseObject")
        self.assertFalse(r.is_subtree_search)
        self.assertEqual(r.sensitive_attributes, [])


class BindResponseTest(unittest.TestCase):
    def test_success(self):
        pkt = _msg(1, _ldap_result(RESULT_SUCCESS, "CN=admin"))
        r = parse_ldap(pkt)
        self.assertEqual(r.op_type, OP_BIND_RESPONSE)
        self.assertEqual(r.result_code, RESULT_SUCCESS)
        self.assertEqual(r.matched_dn, "CN=admin")
        self.assertFalse(r.is_failed_bind)

    def test_invalid_credentials_bruteforce(self):
        pkt = _msg(1, _ldap_result(RESULT_INVALID_CREDENTIALS))
        r = parse_ldap(pkt)
        self.assertEqual(r.result_code, RESULT_INVALID_CREDENTIALS)
        self.assertTrue(r.is_failed_bind)


class WriteOpsTest(unittest.TestCase):
    def test_modify_request_target_dn(self):
        body = _octstr("CN=svc,DC=corp") + _seq()  # name + changes SEQ.
        pkt = _msg(5, _tlv(0x66, body))  # [APPLICATION 6] ModifyRequest.
        r = parse_ldap(pkt)
        self.assertEqual(r.op_type, OP_MODIFY_REQUEST)
        self.assertTrue(r.is_write)
        self.assertEqual(r.target_dn, "CN=svc,DC=corp")

    def test_del_request_primitive_dn(self):
        # DelRequest [APPLICATION 10] primitive — 본문이 곧 DN.
        pkt = _msg(6, _tlv(0x4A, b"CN=old,DC=corp"))
        r = parse_ldap(pkt)
        self.assertEqual(r.op_type, OP_DEL_REQUEST)
        self.assertTrue(r.is_write)
        self.assertEqual(r.target_dn, "CN=old,DC=corp")


class ExtendedRequestTest(unittest.TestCase):
    def test_starttls_oid(self):
        oid = "1.3.6.1.4.1.1466.20037"
        # ExtendedRequest [APPLICATION 23], requestName [0] primitive.
        pkt = _msg(1, _tlv(0x77, _octstr(oid, tag=0x80)))
        r = parse_ldap(pkt)
        self.assertEqual(r.op_type, OP_EXTENDED_REQUEST)
        self.assertEqual(r.request_name, oid)


class RobustnessTest(unittest.TestCase):
    def test_too_short(self):
        self.assertIsNone(parse_ldap(b""))
        self.assertIsNone(parse_ldap(b"\x30"))

    def test_not_a_sequence(self):
        self.assertIsNone(parse_ldap(_int(5)))

    def test_negative_offset(self):
        pkt = _msg(1, _bind_request(3, "x", simple_pw="y"))
        self.assertIsNone(parse_ldap(pkt, offset=-1))

    def test_not_application_op(self):
        # protocolOp 자리에 universal INTEGER → LDAP 아님.
        pkt = _seq(_int(1), _int(99))
        self.assertIsNone(parse_ldap(pkt))

    def test_negative_message_id_rejected(self):
        pkt = _seq(_int(-1), _bind_request(3, "x", simple_pw="y"))
        self.assertIsNone(parse_ldap(pkt))

    def test_offset_second_message(self):
        m1 = _msg(1, _bind_request(3, "a", simple_pw="p1"))
        m2 = _msg(2, _bind_request(3, "b", simple_pw="p2"))
        buf = m1 + m2
        r2 = parse_ldap(buf, offset=len(m1))
        self.assertEqual(r2.message_id, 2)
        self.assertEqual(r2.bind_dn, "b")
        self.assertEqual(r2.simple_password, "p2")

    def test_truncated_body_returns_none(self):
        pkt = _msg(1, _bind_request(3, "x", simple_pw="y"))
        self.assertIsNone(parse_ldap(pkt[:-3]))


if __name__ == "__main__":
    unittest.main()
