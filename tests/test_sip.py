"""forensiclab.sip 단위 테스트 (stdlib unittest)."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from forensiclab.sip import (  # noqa: E402
    SIP_METHODS,
    SIP_VERSION,
    SipRequest,
    SipResponse,
    parse_request,
    parse_response,
)


def _msg(*lines: str, body: str = "") -> bytes:
    """CRLF 로 줄을 잇고 헤더 종료 빈 줄 + 선택 바디를 붙여 바이트로."""
    head = "\r\n".join(lines)
    return (head + "\r\n\r\n" + body).encode("utf-8")


_INVITE = _msg(
    "INVITE sip:bob@biloxi.com SIP/2.0",
    "Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds",
    "From: Alice <sip:alice@atlanta.com>;tag=1928301774",
    "To: Bob <sip:bob@biloxi.com>",
    "Call-ID: a84b4c76e66710@pc33.atlanta.com",
    "CSeq: 314159 INVITE",
    "Contact: <sip:alice@pc33.atlanta.com>",
    "User-Agent: Asterisk PBX 16.2.1",
    "Content-Type: application/sdp",
    "Content-Length: 0",
)


class ParseRequestTests(unittest.TestCase):
    def test_basic_invite(self):
        r = parse_request(_INVITE)
        self.assertIsInstance(r, SipRequest)
        self.assertEqual(r.method, "INVITE")
        self.assertEqual(r.uri, "sip:bob@biloxi.com")
        self.assertEqual(r.version, SIP_VERSION)
        self.assertTrue(r.is_invite)
        self.assertFalse(r.is_register)

    def test_call_metadata(self):
        r = parse_request(_INVITE)
        self.assertEqual(r.from_uri, "Alice <sip:alice@atlanta.com>;tag=1928301774")
        self.assertEqual(r.to_uri, "Bob <sip:bob@biloxi.com>")
        self.assertEqual(r.call_id, "a84b4c76e66710@pc33.atlanta.com")
        self.assertEqual(r.cseq, "314159 INVITE")
        self.assertEqual(r.contact, "<sip:alice@pc33.atlanta.com>")
        self.assertEqual(r.user_agent, "Asterisk PBX 16.2.1")
        self.assertTrue(r.via.startswith("SIP/2.0/UDP pc33.atlanta.com"))

    def test_body_offset_points_after_headers(self):
        raw = _msg("OPTIONS sip:x SIP/2.0", "To: x", body="payload")
        r = parse_request(raw)
        self.assertEqual(r.method, "OPTIONS")
        self.assertEqual(raw[r.body_offset:], b"payload")

    def test_all_methods_recognized(self):
        for m in SIP_METHODS:
            raw = _msg(f"{m} sip:x@y SIP/2.0", "To: x")
            self.assertIsNotNone(parse_request(raw), m)


class CompactHeaderTests(unittest.TestCase):
    def test_compact_forms_normalized(self):
        raw = _msg(
            "INVITE sip:bob@biloxi.com SIP/2.0",
            "v: SIP/2.0/UDP pc.example.com",
            "f: <sip:alice@a.com>;tag=1",
            "t: <sip:bob@b.com>",
            "i: callid-123@host",
            "m: <sip:alice@pc.example.com>",
        )
        r = parse_request(raw)
        self.assertEqual(r.call_id, "callid-123@host")
        self.assertEqual(r.from_uri, "<sip:alice@a.com>;tag=1")
        self.assertEqual(r.to_uri, "<sip:bob@b.com>")
        self.assertEqual(r.contact, "<sip:alice@pc.example.com>")
        self.assertTrue(r.via.startswith("SIP/2.0/UDP"))


class ScannerAndAuthTests(unittest.TestCase):
    def test_scanner_user_agent_detected(self):
        raw = _msg(
            "REGISTER sip:1000@target SIP/2.0",
            "User-Agent: friendly-scanner",
            "To: <sip:1000@target>",
        )
        r = parse_request(raw)
        self.assertTrue(r.is_scanner)
        self.assertTrue(r.is_register)

    def test_benign_user_agent_not_scanner(self):
        r = parse_request(_INVITE)
        self.assertFalse(r.is_scanner)

    def test_digest_credentials_extracted(self):
        raw = _msg(
            "REGISTER sip:asterisk SIP/2.0",
            'Authorization: Digest username="alice", realm="asterisk", '
            'nonce="abc", uri="sip:asterisk", response="deadbeef"',
            "To: <sip:alice@asterisk>",
        )
        r = parse_request(raw)
        self.assertEqual(r.auth_username, "alice")
        self.assertEqual(r.auth_realm, "asterisk")

    def test_proxy_authorization_fallback(self):
        raw = _msg(
            "INVITE sip:bob SIP/2.0",
            'Proxy-Authorization: Digest username="bob", realm="pbx"',
            "To: <sip:bob>",
        )
        r = parse_request(raw)
        self.assertEqual(r.auth_username, "bob")
        self.assertEqual(r.auth_realm, "pbx")

    def test_no_auth_returns_none(self):
        r = parse_request(_INVITE)
        self.assertIsNone(r.authorization)
        self.assertIsNone(r.auth_username)


class ParseResponseTests(unittest.TestCase):
    def test_200_ok(self):
        raw = _msg(
            "SIP/2.0 200 OK",
            "Via: SIP/2.0/UDP pc33.atlanta.com",
            "From: Alice <sip:alice@atlanta.com>;tag=1928301774",
            "To: Bob <sip:bob@biloxi.com>;tag=a6c85cf",
            "Call-ID: a84b4c76e66710@pc33.atlanta.com",
            "CSeq: 314159 INVITE",
            "Server: FreeSWITCH-mod_sofia/1.10",
        )
        r = parse_response(raw)
        self.assertIsInstance(r, SipResponse)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.reason, "OK")
        self.assertEqual(r.server, "FreeSWITCH-mod_sofia/1.10")
        self.assertFalse(r.is_auth_required)

    def test_401_unauthorized(self):
        raw = _msg("SIP/2.0 401 Unauthorized", "To: <sip:x>")
        r = parse_response(raw)
        self.assertEqual(r.status_code, 401)
        self.assertTrue(r.is_auth_required)

    def test_407_proxy_auth(self):
        r = parse_response(_msg("SIP/2.0 407 Proxy Authentication Required", "To: x"))
        self.assertEqual(r.status_code, 407)
        self.assertEqual(r.reason, "Proxy Authentication Required")
        self.assertTrue(r.is_auth_required)


class RejectionTests(unittest.TestCase):
    def test_empty(self):
        self.assertIsNone(parse_request(b""))
        self.assertIsNone(parse_response(b""))

    def test_http_request_rejected(self):
        # HTTP 요청 라인은 SIP 가 아니다(버전 가드).
        raw = _msg("GET / HTTP/1.1", "Host: x")
        self.assertIsNone(parse_request(raw))

    def test_unknown_method_rejected(self):
        raw = _msg("FROBNICATE sip:x SIP/2.0", "To: x")
        self.assertIsNone(parse_request(raw))

    def test_wrong_version_rejected(self):
        raw = _msg("INVITE sip:x SIP/1.0", "To: x")
        self.assertIsNone(parse_request(raw))

    def test_malformed_request_line(self):
        self.assertIsNone(parse_request(_msg("INVITE sip:x", "To: x")))

    def test_response_bad_status_code(self):
        self.assertIsNone(parse_response(_msg("SIP/2.0 OK", "To: x")))
        self.assertIsNone(parse_response(_msg("SIP/2.0 20 OK", "To: x")))

    def test_partial_headers_no_terminator(self):
        # 헤더 종료 CRLFCRLF 가 없어도 받은 데까지 채운다.
        raw = b"REGISTER sip:x SIP/2.0\r\nTo: <sip:x>"
        r = parse_request(raw)
        self.assertIsNotNone(r)
        self.assertEqual(r.to_uri, "<sip:x>")
        self.assertEqual(r.body_offset, len(raw))


if __name__ == "__main__":
    unittest.main()
