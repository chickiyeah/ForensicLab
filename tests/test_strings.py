"""forensiclab.strings 단위 테스트 (stdlib unittest)."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from forensiclab.strings import (  # noqa: E402
    DEFAULT_MIN_LENGTH,
    ExtractedString,
    extract_ascii,
    extract_strings,
    extract_utf16le,
    filter_by_keyword,
)


def _u16(text):
    """ASCII 문자열을 UTF-16LE 바이트로."""
    return text.encode("utf-16le")


class ExtractAsciiTest(unittest.TestCase):
    def test_simple_extraction(self):
        data = b"\x00\x01hello\x00\xffworld!\x00"
        out = extract_ascii(data)
        self.assertEqual([s.text for s in out], ["hello", "world!"])

    def test_offsets_correct(self):
        data = b"\x00\x01hello\x00world\x00"
        out = extract_ascii(data)
        self.assertEqual(out[0].offset, 2)
        self.assertEqual(out[1].offset, 8)

    def test_min_length_filters_short_runs(self):
        data = b"ab\x00abcd\x00xyz"
        out = extract_ascii(data, min_length=4)
        self.assertEqual([s.text for s in out], ["abcd"])

    def test_custom_min_length(self):
        data = b"ab\x00cd"
        out = extract_ascii(data, min_length=2)
        self.assertEqual([s.text for s in out], ["ab", "cd"])

    def test_string_at_end_of_buffer(self):
        data = b"\x00trailing"
        out = extract_ascii(data)
        self.assertEqual(out[0].text, "trailing")
        self.assertEqual(out[0].offset, 1)

    def test_tab_is_printable(self):
        data = b"\x00a\tb c\x00"
        out = extract_ascii(data)
        self.assertEqual(out[0].text, "a\tb c")

    def test_encoding_label(self):
        out = extract_ascii(b"hello")
        self.assertEqual(out[0].encoding, "ascii")

    def test_len_dunder(self):
        out = extract_ascii(b"hello")
        self.assertEqual(len(out[0]), 5)

    def test_empty_buffer(self):
        self.assertEqual(extract_ascii(b""), [])

    def test_min_length_zero_raises(self):
        with self.assertRaises(ValueError):
            extract_ascii(b"abc", min_length=0)

    def test_default_min_length_is_four(self):
        self.assertEqual(DEFAULT_MIN_LENGTH, 4)
        self.assertEqual(extract_ascii(b"abc"), [])


class ExtractUtf16Test(unittest.TestCase):
    def test_simple_utf16(self):
        data = b"\xff" + _u16("Secret") + b"\xff"
        out = extract_utf16le(data)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].text, "Secret")
        self.assertEqual(out[0].encoding, "utf-16le")
        self.assertEqual(out[0].offset, 1)

    def test_min_length_filters(self):
        data = _u16("ab") + b"\xff\xff" + _u16("abcd")
        out = extract_utf16le(data, min_length=4)
        self.assertEqual([s.text for s in out], ["abcd"])

    def test_no_false_positive_on_pure_ascii(self):
        # NUL 이 끼지 않은 순수 ASCII 는 utf-16le 로 잡히지 않아야 한다.
        self.assertEqual(extract_utf16le(b"plainascii"), [])

    def test_run_at_end(self):
        out = extract_utf16le(_u16("trailing"))
        self.assertEqual(out[0].text, "trailing")


class ExtractStringsTest(unittest.TestCase):
    def test_merges_and_sorts_by_offset(self):
        data = b"plaintext\xff\xff" + _u16("widetext")
        out = extract_strings(data)
        texts = [s.text for s in out]
        self.assertIn("plaintext", texts)
        self.assertIn("widetext", texts)
        offsets = [s.offset for s in out]
        self.assertEqual(offsets, sorted(offsets))

    def test_ascii_only_skips_utf16(self):
        data = b"plaintext\x00" + _u16("widetext")
        out = extract_strings(data, ascii_only=True)
        self.assertTrue(all(s.encoding == "ascii" for s in out))

    def test_both_encodings_present_and_distinct_offsets(self):
        # ASCII 와 UTF-16LE 는 시작 오프셋이 절대 겹치지 않아야 한다.
        data = b"plainword\xff\xff" + _u16("widebody")
        out = extract_strings(data)
        encodings = {s.encoding for s in out}
        self.assertEqual(encodings, {"ascii", "utf-16le"})
        offsets = [s.offset for s in out]
        self.assertEqual(len(offsets), len(set(offsets)))


class FilterByKeywordTest(unittest.TestCase):
    def setUp(self):
        self.items = [
            ExtractedString(0, "ascii", "password=1234"),
            ExtractedString(20, "ascii", "Normal line"),
            ExtractedString(40, "ascii", "PASSWORD field"),
        ]

    def test_case_insensitive_default(self):
        out = filter_by_keyword(self.items, "password")
        self.assertEqual(len(out), 2)

    def test_case_sensitive(self):
        out = filter_by_keyword(self.items, "password", case_sensitive=True)
        self.assertEqual([s.text for s in out], ["password=1234"])

    def test_no_match(self):
        self.assertEqual(filter_by_keyword(self.items, "zzz"), [])

    def test_preserves_order(self):
        out = filter_by_keyword(self.items, "a")
        self.assertEqual([s.offset for s in out], [0, 20, 40])


if __name__ == "__main__":
    unittest.main()
