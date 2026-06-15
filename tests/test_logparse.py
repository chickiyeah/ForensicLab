"""forensiclab.logparse 단위 테스트 (stdlib unittest)."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from forensiclab.logparse import (  # noqa: E402
    ATTACK_SIGNATURES,
    AccessLogEntry,
    AttackHit,
    detect_attacks,
    parse_access_line,
    parse_access_log,
)

_COMMON = '127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /index.html HTTP/1.0" 200 2326'
_COMBINED = (
    '192.168.0.5 - - [12/Jun/2026:09:01:02 +0000] "POST /login HTTP/1.1" 302 0 '
    '"http://example.com/" "Mozilla/5.0 (X11; Linux)"'
)


class ParseAccessLineTest(unittest.TestCase):
    def test_common_log_format(self):
        e = parse_access_line(_COMMON)
        self.assertIsInstance(e, AccessLogEntry)
        self.assertEqual(e.host, "127.0.0.1")
        self.assertEqual(e.user, "frank")
        self.assertEqual(e.method, "GET")
        self.assertEqual(e.path, "/index.html")
        self.assertEqual(e.protocol, "HTTP/1.0")
        self.assertEqual(e.status, 200)
        self.assertEqual(e.size, 2326)
        self.assertEqual(e.referer, "")
        self.assertEqual(e.agent, "")

    def test_combined_log_format(self):
        e = parse_access_line(_COMBINED)
        self.assertEqual(e.method, "POST")
        self.assertEqual(e.path, "/login")
        self.assertEqual(e.status, 302)
        self.assertEqual(e.referer, "http://example.com/")
        self.assertEqual(e.agent, "Mozilla/5.0 (X11; Linux)")

    def test_dash_size_becomes_zero(self):
        e = parse_access_line('1.1.1.1 - - [x] "GET / HTTP/1.1" 404 -')
        self.assertEqual(e.size, 0)

    def test_malformed_request_preserves_path(self):
        e = parse_access_line('1.1.1.1 - - [x] "GARBAGE" 400 0')
        self.assertEqual(e.method, "")
        self.assertEqual(e.path, "GARBAGE")
        self.assertEqual(e.protocol, "")

    def test_non_matching_line_returns_none(self):
        self.assertIsNone(parse_access_line("this is not a log line"))

    def test_trailing_newline_tolerated(self):
        self.assertIsNotNone(parse_access_line(_COMMON + "\n"))


class ParseAccessLogTest(unittest.TestCase):
    def test_skips_blank_and_bad_lines(self):
        lines = [_COMMON, "", "   ", "junk", _COMBINED]
        out = parse_access_log(lines)
        self.assertEqual(len(out), 2)
        self.assertEqual([e.method for e in out], ["GET", "POST"])

    def test_empty_input(self):
        self.assertEqual(parse_access_log([]), [])


class DetectAttacksTest(unittest.TestCase):
    def _entry(self, path, referer=""):
        return AccessLogEntry(
            host="1.1.1.1",
            ident="-",
            user="-",
            time="x",
            method="GET",
            path=path,
            protocol="HTTP/1.1",
            status=200,
            size=0,
            referer=referer,
        )

    def test_path_traversal(self):
        hits = detect_attacks([self._entry("/files/../../etc/passwd")])
        self.assertEqual(len(hits), 1)
        self.assertIn("path_traversal", hits[0].categories)

    def test_sql_injection(self):
        hits = detect_attacks([self._entry("/item?id=1 UNION SELECT pw")])
        self.assertIn("sql_injection", hits[0].categories)

    def test_xss(self):
        hits = detect_attacks([self._entry("/q?s=<script>alert(1)</script>")])
        self.assertIn("xss", hits[0].categories)

    def test_referer_is_scanned(self):
        hits = detect_attacks([self._entry("/", referer="javascript:evil()")])
        self.assertIn("xss", hits[0].categories)

    def test_clean_request_no_hit(self):
        self.assertEqual(detect_attacks([self._entry("/index.html")]), [])

    def test_categories_sorted_and_multiple(self):
        hit = detect_attacks(
            [self._entry("/../x?id=1 OR 1=1 <script>")]
        )[0]
        self.assertEqual(list(hit.categories), sorted(hit.categories))
        self.assertGreaterEqual(len(hit.categories), 2)

    def test_returns_attackhit_instances(self):
        hits = detect_attacks([self._entry("/../etc")])
        self.assertIsInstance(hits[0], AttackHit)

    def test_preserves_input_order(self):
        entries = [
            self._entry("/../a"),
            self._entry("/clean"),
            self._entry("/q?<script>"),
        ]
        hits = detect_attacks(entries)
        self.assertEqual([h.entry.path for h in hits], ["/../a", "/q?<script>"])


class SignatureTableTest(unittest.TestCase):
    def test_expected_categories_present(self):
        names = {sig.name for sig in ATTACK_SIGNATURES}
        self.assertEqual(names, {"path_traversal", "sql_injection", "xss"})


if __name__ == "__main__":
    unittest.main()
