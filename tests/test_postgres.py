"""forensiclab.postgres 단위 테스트 (stdlib unittest)."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from forensiclab.postgres import (  # noqa: E402
    CANCEL_REQUEST_CODE,
    GSSENC_REQUEST_CODE,
    PROTOCOL_VERSION_3_0,
    SSL_REQUEST_CODE,
    PostgresStartup,
    parse_postgres_startup,
)


def _build_startup(params=(("user", "alice"), ("database", "payroll")),
                   code=PROTOCOL_VERSION_3_0):
    """key/value 파라미터로 완전한 StartupMessage 를 만든다."""
    body = bytearray()
    for k, v in params:
        body += k.encode() + b"\x00" + v.encode() + b"\x00"
    body += b"\x00"  # 종단 빈 키
    length = 4 + 4 + len(body)
    msg = bytearray()
    msg += length.to_bytes(4, "big")
    msg += code.to_bytes(4, "big")
    msg += body
    return bytes(msg)


def _build_special(code):
    """length=8 고정 특수 요청(SSLRequest/GSSENCRequest)을 만든다."""
    return (8).to_bytes(4, "big") + code.to_bytes(4, "big")


def _build_cancel(pid=4242, secret=0xDEADBEEF):
    msg = bytearray()
    msg += (16).to_bytes(4, "big")
    msg += CANCEL_REQUEST_CODE.to_bytes(4, "big")
    msg += pid.to_bytes(4, "big")
    msg += secret.to_bytes(4, "big")
    return bytes(msg)


class ParseStartupTest(unittest.TestCase):
    def test_basic_startup_user_and_database(self):
        r = parse_postgres_startup(_build_startup())
        self.assertIsInstance(r, PostgresStartup)
        self.assertEqual(r.kind, "startup")
        self.assertTrue(r.is_startup)
        self.assertEqual(r.protocol_major, 3)
        self.assertEqual(r.protocol_minor, 0)
        self.assertEqual(r.user, "alice")
        self.assertEqual(r.database, "payroll")
        self.assertFalse(r.requests_tls)
        self.assertFalse(r.is_cancel_request)

    def test_database_defaults_to_user(self):
        r = parse_postgres_startup(_build_startup(params=(("user", "bob"),)))
        self.assertEqual(r.user, "bob")
        self.assertEqual(r.database, "bob")  # database 미지정 → user

    def test_application_name_fingerprint(self):
        r = parse_postgres_startup(_build_startup(
            params=(("user", "svc"), ("application_name", "sqlmap"))))
        self.assertEqual(r.application_name, "sqlmap")

    def test_legacy_protocol_2(self):
        code = (2 << 16) | 0
        r = parse_postgres_startup(_build_startup(code=code))
        self.assertEqual(r.protocol_major, 2)

    def test_length_field_reported(self):
        msg = _build_startup()
        r = parse_postgres_startup(msg)
        self.assertEqual(r.length, len(msg))


class SpecialRequestTest(unittest.TestCase):
    def test_ssl_request(self):
        r = parse_postgres_startup(_build_special(SSL_REQUEST_CODE))
        self.assertEqual(r.kind, "ssl_request")
        self.assertTrue(r.requests_tls)
        self.assertFalse(r.is_startup)
        self.assertIsNone(r.user)

    def test_gssenc_request(self):
        r = parse_postgres_startup(_build_special(GSSENC_REQUEST_CODE))
        self.assertEqual(r.kind, "gssenc_request")
        self.assertFalse(r.requests_tls)

    def test_cancel_request_exposes_pid_secret(self):
        r = parse_postgres_startup(_build_cancel(pid=4242, secret=0xDEADBEEF))
        self.assertEqual(r.kind, "cancel_request")
        self.assertTrue(r.is_cancel_request)
        self.assertEqual(r.pid, 4242)
        self.assertEqual(r.secret_key, 0xDEADBEEF)

    def test_special_wrong_length_rejected(self):
        # SSLRequest 코드인데 length 가 8 이 아니면 거부.
        bad = (9).to_bytes(4, "big") + SSL_REQUEST_CODE.to_bytes(4, "big") + b"\x00"
        self.assertIsNone(parse_postgres_startup(bad))

    def test_cancel_truncated_rejected(self):
        full = _build_cancel()
        self.assertIsNone(parse_postgres_startup(full[:12]))


class RobustnessTest(unittest.TestCase):
    def test_empty_and_short(self):
        self.assertIsNone(parse_postgres_startup(b""))
        self.assertIsNone(parse_postgres_startup(b"\x00\x00\x00"))

    def test_negative_offset(self):
        self.assertIsNone(parse_postgres_startup(_build_startup(), offset=-1))

    def test_offset_past_end(self):
        msg = _build_startup()
        self.assertIsNone(parse_postgres_startup(msg, offset=len(msg)))

    def test_garbage_protocol_major_rejected(self):
        # major 가 2/3 가 아닌 임의 code → None.
        bad = (12).to_bytes(4, "big") + (99 << 16).to_bytes(4, "big") + b"x\x00\x00\x00"
        self.assertIsNone(parse_postgres_startup(bad))

    def test_absurd_length_rejected(self):
        bad = (10 ** 9).to_bytes(4, "big") + PROTOCOL_VERSION_3_0.to_bytes(4, "big")
        self.assertIsNone(parse_postgres_startup(bad))

    def test_truncated_body_partial_params(self):
        # 선언 길이는 정상인데 본문이 잘린 경우: 파싱 가능한 만큼만.
        full = _build_startup(params=(("user", "carol"), ("database", "hr")))
        truncated = full[:-5]  # database 값 일부 손실
        r = parse_postgres_startup(truncated)
        self.assertEqual(r.kind, "startup")
        self.assertEqual(r.user, "carol")

    def test_offset_parsing(self):
        msg = _build_startup()
        padded = b"\xff\xff" + msg
        r = parse_postgres_startup(padded, offset=2)
        self.assertEqual(r.user, "alice")


if __name__ == "__main__":
    unittest.main()
