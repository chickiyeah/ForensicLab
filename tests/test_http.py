"""forensiclab.http 단위 테스트 (stdlib unittest)."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from forensiclab.http import (  # noqa: E402
    HTTP_METHODS,
    HttpRequest,
    HttpResponse,
    parse_request,
    parse_response,
)


def _req(*lines, body=b""):
    """헤더 줄 목록을 CRLF 로 잇고 헤더 종료 CRLFCRLF + 바디를 붙인다."""
    return ("\r\n".join(lines) + "\r\n\r\n").encode("ascii") + body


class RequestLineTest(unittest.TestCase):
    def test_simple_get(self):
        req = parse_request(_req("GET /index.html HTTP/1.1", "Host: example.com"))
        self.assertIsInstance(req, HttpRequest)
        self.assertEqual(req.method, "GET")
        self.assertEqual(req.target, "/index.html")
        self.assertEqual(req.version, "HTTP/1.1")
        self.assertEqual(req.host, "example.com")

    def test_post_with_body_offset(self):
        data = _req("POST /upload HTTP/1.1", "Host: c2.bad", body=b"secret-bytes")
        req = parse_request(data)
        self.assertEqual(req.method, "POST")
        self.assertEqual(data[req.body_offset:], b"secret-bytes")

    def test_empty_returns_none(self):
        self.assertIsNone(parse_request(b""))

    def test_non_http_method_returns_none(self):
        # TLS 핸드셰이크 류 바이트는 메서드 화이트리스트에서 걸러진다.
        self.assertIsNone(parse_request(b"\x16\x03\x01\x00\x05hello\r\n\r\n"))

    def test_malformed_request_line_returns_none(self):
        self.assertIsNone(parse_request(b"GET /only-two-parts\r\n\r\n"))

    def test_non_http_version_returns_none(self):
        self.assertIsNone(parse_request(b"GET / SPDY/3\r\n\r\n"))

    def test_all_methods_recognized(self):
        for m in HTTP_METHODS:
            req = parse_request((f"{m} / HTTP/1.0\r\n\r\n").encode("ascii"))
            self.assertEqual(req.method, m)


class HeaderTest(unittest.TestCase):
    def test_header_names_lowercased(self):
        req = parse_request(_req("GET / HTTP/1.1", "Host: a", "User-Agent: curl/8"))
        self.assertEqual(req.headers["host"], "a")
        self.assertEqual(req.user_agent, "curl/8")

    def test_value_whitespace_stripped(self):
        req = parse_request(_req("GET / HTTP/1.1", "X-Tag:   spaced   "))
        self.assertEqual(req.headers["x-tag"], "spaced")

    def test_duplicate_headers_joined(self):
        req = parse_request(_req("GET / HTTP/1.1", "X-F: a", "X-F: b"))
        self.assertEqual(req.headers["x-f"], "a, b")

    def test_colonless_line_skipped(self):
        req = parse_request(_req("GET / HTTP/1.1", "Host: x", "garbage-no-colon"))
        self.assertEqual(req.host, "x")
        self.assertNotIn("garbage-no-colon", req.headers)

    def test_missing_headers_are_none(self):
        req = parse_request(b"GET / HTTP/1.1\r\n\r\n")
        self.assertIsNone(req.host)
        self.assertIsNone(req.user_agent)
        self.assertEqual(req.headers, {})

    def test_partial_headers_without_terminator(self):
        # 헤더 종료 CRLFCRLF 가 아직 안 옴(부분 수신): 받은 데까지 파싱.
        req = parse_request(b"GET / HTTP/1.1\r\nHost: partial.example")
        self.assertEqual(req.host, "partial.example")
        self.assertEqual(req.body_offset, len(b"GET / HTTP/1.1\r\nHost: partial.example"))


class ImmutabilityTest(unittest.TestCase):
    def test_input_not_mutated(self):
        data = _req("GET / HTTP/1.1", "Host: h", body=b"abc")
        original = bytes(data)
        parse_request(data)
        self.assertEqual(data, original)


class ResponseStatusLineTest(unittest.TestCase):
    def test_simple_200(self):
        resp = parse_response(_req("HTTP/1.1 200 OK", "Content-Type: text/html"))
        self.assertIsInstance(resp, HttpResponse)
        self.assertEqual(resp.version, "HTTP/1.1")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.reason, "OK")
        self.assertEqual(resp.content_type, "text/html")

    def test_reason_with_spaces(self):
        resp = parse_response(b"HTTP/1.1 404 Not Found\r\n\r\n")
        self.assertEqual(resp.status_code, 404)
        self.assertEqual(resp.reason, "Not Found")

    def test_missing_reason_phrase(self):
        resp = parse_response(b"HTTP/1.0 204\r\n\r\n")
        self.assertEqual(resp.status_code, 204)
        self.assertEqual(resp.reason, "")

    def test_body_offset_points_past_headers(self):
        body = b"\x4d\x5a\x90\x00"  # PE 헤더 — 실행파일 다운로드 모사.
        data = _req("HTTP/1.1 200 OK", "Content-Type: application/octet-stream",
                    body=body)
        resp = parse_response(data)
        self.assertEqual(data[resp.body_offset:], body)

    def test_empty_returns_none(self):
        self.assertIsNone(parse_response(b""))

    def test_request_is_not_a_response(self):
        self.assertIsNone(parse_response(b"GET / HTTP/1.1\r\n\r\n"))

    def test_non_http_version_returns_none(self):
        self.assertIsNone(parse_response(b"ICY 200 OK\r\n\r\n"))

    def test_non_numeric_status_returns_none(self):
        self.assertIsNone(parse_response(b"HTTP/1.1 OK fine\r\n\r\n"))

    def test_wrong_length_status_returns_none(self):
        self.assertIsNone(parse_response(b"HTTP/1.1 20 Short\r\n\r\n"))
        self.assertIsNone(parse_response(b"HTTP/1.1 2000 Long\r\n\r\n"))


class ResponseHeaderTest(unittest.TestCase):
    def test_content_length_parsed(self):
        resp = parse_response(_req("HTTP/1.1 200 OK", "Content-Length: 1024"))
        self.assertEqual(resp.content_length, 1024)

    def test_content_length_absent_is_none(self):
        resp = parse_response(b"HTTP/1.1 200 OK\r\n\r\n")
        self.assertIsNone(resp.content_length)
        self.assertIsNone(resp.content_type)

    def test_content_length_non_numeric_is_none(self):
        resp = parse_response(_req("HTTP/1.1 200 OK", "Content-Length: chunked?"))
        self.assertIsNone(resp.content_length)

    def test_header_names_lowercased(self):
        resp = parse_response(_req("HTTP/1.1 301 Moved", "Location: http://x/"))
        self.assertEqual(resp.headers["location"], "http://x/")

    def test_partial_headers_without_terminator(self):
        resp = parse_response(b"HTTP/1.1 200 OK\r\nServer: nginx")
        self.assertEqual(resp.headers["server"], "nginx")
        self.assertEqual(resp.body_offset, len(b"HTTP/1.1 200 OK\r\nServer: nginx"))


class ResponseImmutabilityTest(unittest.TestCase):
    def test_input_not_mutated(self):
        data = _req("HTTP/1.1 200 OK", "Content-Type: text/html", body=b"<html>")
        original = bytes(data)
        parse_response(data)
        self.assertEqual(data, original)


if __name__ == "__main__":
    unittest.main()
