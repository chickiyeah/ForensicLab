"""forensiclab.kerberos 단위 테스트 (stdlib unittest)."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from forensiclab.kerberos import (  # noqa: E402
    ERR_C_PRINCIPAL_UNKNOWN,
    ERR_PREAUTH_FAILED,
    ERR_PREAUTH_REQUIRED,
    ETYPE_AES256,
    ETYPE_RC4_HMAC,
    KRB_AS_REQ,
    KRB_ERROR,
    KRB_TGS_REP,
    KRB_TGS_REQ,
    PA_ENC_TIMESTAMP,
    KerberosMessage,
    parse_kerberos,
)


# --- 최소 DER 인코더(테스트 픽스처 전용) ---------------------------------

def _der_len(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def _tlv(tag, value):
    return bytes([tag]) + _der_len(len(value)) + value


def _int(n):
    if n == 0:
        body = b"\x00"
    else:
        length = (n.bit_length() + 8) // 8
        body = n.to_bytes(length, "big", signed=True)
    return _tlv(0x02, body)


def _gstr(s):
    return _tlv(0x1B, s.encode("utf-8"))  # GeneralString = KerberosString.


def _seq(*parts):
    return _tlv(0x30, b"".join(parts))


def _ctx(k, content):
    """EXPLICIT context [k] (constructed)."""
    return _tlv(0xA0 | k, content)


def _app(n, content):
    """[APPLICATION n] (constructed)."""
    return _tlv(0x60 | n, content)


def _principal(name_type, parts):
    """PrincipalName ::= SEQ { [0] Int32, [1] SEQ OF KerberosString }."""
    namestr = _seq(*[_gstr(p) for p in parts])
    return _seq(_ctx(0, _int(name_type)), _ctx(1, namestr))


def _padata(*types):
    items = [_seq(_ctx(1, _int(t)), _ctx(2, _tlv(0x04, b"x"))) for t in types]
    return _seq(*items)


def _kdc_req_body(realm, cname=None, sname=None, etypes=()):
    parts = [_ctx(0, _tlv(0x03, b"\x00\x00\x00\x00\x00"))]  # kdc-options
    if cname is not None:
        parts.append(_ctx(1, _principal(1, cname)))
    parts.append(_ctx(2, _gstr(realm)))
    if sname is not None:
        parts.append(_ctx(3, _principal(2, sname)))
    parts.append(_ctx(7, _int(12345)))  # nonce
    parts.append(_ctx(8, _seq(*[_int(e) for e in etypes])))
    return _seq(*parts)


def _kdc_req(app_tag, realm, cname=None, sname=None, etypes=(), padata=None):
    parts = [_ctx(1, _int(5)), _ctx(2, _int(app_tag))]
    if padata is not None:
        parts.append(_ctx(3, padata))
    parts.append(_ctx(4, _kdc_req_body(realm, cname, sname, etypes)))
    return _app(app_tag, _seq(*parts))


def _encrypted_data(etype):
    return _seq(_ctx(0, _int(etype)), _ctx(2, _tlv(0x04, b"cipher")))


def _ticket(realm, sname, etype):
    inner = _seq(
        _ctx(0, _int(5)),               # tkt-vno
        _ctx(1, _gstr(realm)),          # realm
        _ctx(2, _principal(2, sname)),  # sname
        _ctx(3, _encrypted_data(etype)),  # enc-part
    )
    return _app(1, inner)


def _kdc_rep(app_tag, realm, cname, ticket):
    inner = _seq(
        _ctx(0, _int(5)),
        _ctx(1, _int(app_tag)),
        _ctx(3, _gstr(realm)),
        _ctx(4, _principal(1, cname)),
        _ctx(5, ticket),
        _ctx(6, _encrypted_data(ETYPE_AES256)),
    )
    return _app(app_tag, inner)


def _krb_error(error_code, crealm=None, cname=None, srealm=None, sname=None):
    parts = [_ctx(0, _int(5)), _ctx(1, _int(KRB_ERROR)),
             _ctx(4, _gstr("20260614000000Z")), _ctx(5, _int(0)),
             _ctx(6, _int(error_code))]
    if crealm is not None:
        parts.append(_ctx(7, _gstr(crealm)))
    if cname is not None:
        parts.append(_ctx(8, _principal(1, cname)))
    if srealm is not None:
        parts.append(_ctx(9, _gstr(srealm)))
    if sname is not None:
        parts.append(_ctx(10, _principal(2, sname)))
    return _app(KRB_ERROR, _seq(*parts))


# --- 테스트 ---------------------------------------------------------------

class ParseGuardTests(unittest.TestCase):
    def test_empty(self):
        self.assertIsNone(parse_kerberos(b""))

    def test_negative_offset(self):
        self.assertIsNone(parse_kerberos(_kdc_req(KRB_AS_REQ, "CORP"), offset=-1))

    def test_not_application_tag(self):
        # 평범한 SEQUENCE 는 Kerberos 가 아니다.
        self.assertIsNone(parse_kerberos(_seq(_int(5))))

    def test_unknown_app_tag(self):
        # [APPLICATION 22] KRB-CRED 는 미지원 → None.
        self.assertIsNone(parse_kerberos(_app(22, _seq(_ctx(0, _int(5))))))

    def test_truncated_inner(self):
        msg = _kdc_req(KRB_AS_REQ, "CORP")
        self.assertIsNone(parse_kerberos(msg[:6]))

    def test_app_tag_not_wrapping_sequence(self):
        self.assertIsNone(parse_kerberos(_app(KRB_AS_REQ, _int(5))))


class AsReqTests(unittest.TestCase):
    def test_basic_fields(self):
        msg = _kdc_req(
            KRB_AS_REQ, "CORP.LOCAL", cname=["alice"],
            sname=["krbtgt", "CORP.LOCAL"], etypes=[ETYPE_AES256],
        )
        m = parse_kerberos(msg)
        self.assertIsInstance(m, KerberosMessage)
        self.assertEqual(m.msg_type, KRB_AS_REQ)
        self.assertEqual(m.msg_name, "AS-REQ")
        self.assertTrue(m.is_as_req)
        self.assertEqual(m.realm, "CORP.LOCAL")
        self.assertEqual(m.cname, "alice")
        self.assertEqual(m.sname, "krbtgt/CORP.LOCAL")
        self.assertEqual(m.etypes, [ETYPE_AES256])
        self.assertTrue(m.service_is_krbtgt)

    def test_asreproast_no_preauth(self):
        # 사전인증(padata) 없는 AS-REQ → ASREProast 정황.
        msg = _kdc_req(KRB_AS_REQ, "CORP", cname=["svc"], etypes=[ETYPE_RC4_HMAC])
        m = parse_kerberos(msg)
        self.assertFalse(m.preauth_supplied)
        self.assertTrue(m.is_asreproast_attempt)

    def test_preauth_supplied_not_roast(self):
        msg = _kdc_req(
            KRB_AS_REQ, "CORP", cname=["alice"], etypes=[ETYPE_AES256],
            padata=_padata(PA_ENC_TIMESTAMP),
        )
        m = parse_kerberos(msg)
        self.assertTrue(m.preauth_supplied)
        self.assertIn(PA_ENC_TIMESTAMP, m.padata_types)
        self.assertFalse(m.is_asreproast_attempt)

    def test_weak_etype_downgrade(self):
        msg = _kdc_req(KRB_AS_REQ, "CORP", cname=["alice"],
                       etypes=[ETYPE_RC4_HMAC, ETYPE_AES256])
        m = parse_kerberos(msg)
        self.assertTrue(m.requests_rc4)
        self.assertEqual(m.weak_etypes, [ETYPE_RC4_HMAC])
        self.assertIn("rc4-hmac", m.etype_names)


class TgsReqTests(unittest.TestCase):
    def test_kerberoast_request(self):
        # krbtgt 아닌 SPN 을 RC4 로 요청 → Kerberoasting.
        msg = _kdc_req(
            KRB_TGS_REQ, "CORP", sname=["MSSQLSvc", "db.corp.local"],
            etypes=[ETYPE_RC4_HMAC],
        )
        m = parse_kerberos(msg)
        self.assertTrue(m.is_tgs_req)
        self.assertEqual(m.sname, "MSSQLSvc/db.corp.local")
        self.assertFalse(m.service_is_krbtgt)
        self.assertTrue(m.is_kerberoast_request)

    def test_tgs_for_krbtgt_not_roast(self):
        msg = _kdc_req(KRB_TGS_REQ, "CORP", sname=["krbtgt", "CORP"],
                       etypes=[ETYPE_RC4_HMAC])
        m = parse_kerberos(msg)
        self.assertTrue(m.service_is_krbtgt)
        self.assertFalse(m.is_kerberoast_request)

    def test_aes_request_not_roast(self):
        msg = _kdc_req(KRB_TGS_REQ, "CORP", sname=["HTTP", "web"],
                       etypes=[ETYPE_AES256])
        m = parse_kerberos(msg)
        self.assertFalse(m.requests_rc4)
        self.assertFalse(m.is_kerberoast_request)


class KdcRepTests(unittest.TestCase):
    def test_tgs_rep_rc4_ticket(self):
        tkt = _ticket("CORP", ["MSSQLSvc", "db"], ETYPE_RC4_HMAC)
        msg = _kdc_rep(KRB_TGS_REP, "CORP", ["alice"], tkt)
        m = parse_kerberos(msg)
        self.assertTrue(m.is_tgs_rep)
        self.assertEqual(m.realm, "CORP")
        self.assertEqual(m.cname, "alice")
        self.assertEqual(m.sname, "MSSQLSvc/db")
        self.assertEqual(m.ticket_etype, ETYPE_RC4_HMAC)
        self.assertTrue(m.is_kerberoastable_reply)

    def test_tgs_rep_aes_ticket_not_roastable(self):
        tkt = _ticket("CORP", ["HTTP", "web"], ETYPE_AES256)
        msg = _kdc_rep(KRB_TGS_REP, "CORP", ["alice"], tkt)
        m = parse_kerberos(msg)
        self.assertEqual(m.ticket_etype, ETYPE_AES256)
        self.assertFalse(m.is_kerberoastable_reply)

    def test_tgs_rep_krbtgt_not_roastable(self):
        tkt = _ticket("CORP", ["krbtgt", "CORP"], ETYPE_RC4_HMAC)
        msg = _kdc_rep(KRB_TGS_REP, "CORP", ["alice"], tkt)
        m = parse_kerberos(msg)
        self.assertTrue(m.service_is_krbtgt)
        self.assertFalse(m.is_kerberoastable_reply)


class KrbErrorTests(unittest.TestCase):
    def test_principal_unknown_enumeration(self):
        msg = _krb_error(ERR_C_PRINCIPAL_UNKNOWN, srealm="CORP",
                         cname=["nonexistent"])
        m = parse_kerberos(msg)
        self.assertTrue(m.is_error)
        self.assertEqual(m.error_code, ERR_C_PRINCIPAL_UNKNOWN)
        self.assertEqual(m.error_name, "KDC_ERR_C_PRINCIPAL_UNKNOWN")
        self.assertTrue(m.is_principal_unknown)
        self.assertEqual(m.cname, "nonexistent")
        self.assertEqual(m.realm, "CORP")

    def test_preauth_failed_bruteforce(self):
        msg = _krb_error(ERR_PREAUTH_FAILED, crealm="CORP", cname=["admin"])
        m = parse_kerberos(msg)
        self.assertTrue(m.is_preauth_failed)
        self.assertEqual(m.realm, "CORP")  # crealm fallback

    def test_preauth_required_normal(self):
        msg = _krb_error(ERR_PREAUTH_REQUIRED, srealm="CORP")
        m = parse_kerberos(msg)
        self.assertFalse(m.is_preauth_failed)
        self.assertFalse(m.is_principal_unknown)
        self.assertEqual(m.error_name, "KDC_ERR_PREAUTH_REQUIRED")


class MiscTests(unittest.TestCase):
    def test_tcp_length_prefix_offset(self):
        # TCP 전송은 앞 4바이트 길이 접두사를 둔다 → offset=4 로 건너뛴다.
        msg = _kdc_req(KRB_AS_REQ, "CORP", cname=["bob"])
        framed = len(msg).to_bytes(4, "big") + msg
        m = parse_kerberos(framed, offset=4)
        self.assertIsNotNone(m)
        self.assertEqual(m.cname, "bob")

    def test_unknown_etype_name(self):
        msg = _kdc_req(KRB_AS_REQ, "CORP", cname=["a"], etypes=[99])
        m = parse_kerberos(msg)
        self.assertEqual(m.etype_names, ["etype-99"])


if __name__ == "__main__":
    unittest.main()
