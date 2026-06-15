"""forensiclab.filetype 단위 테스트 (stdlib unittest)."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from forensiclab.filetype import (  # noqa: E402
    DEFAULT_MAGICS,
    Magic,
    extension_mismatch,
    identify,
    identify_all,
)

PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 16
JPEG = b"\xff\xd8\xff\xe0" + b"\x00" * 16
ZIP = b"PK\x03\x04" + b"\x00" * 16
PE = b"MZ" + b"\x90" * 16
ELF = b"\x7fELF" + b"\x00" * 16


class MagicDataclassTest(unittest.TestCase):
    def test_matches_at_offset_zero(self):
        m = Magic("png", ("png",), b"\x89PNG")
        self.assertTrue(m.matches(PNG))
        self.assertFalse(m.matches(JPEG))

    def test_matches_at_nonzero_offset(self):
        m = Magic("avi", ("avi",), b"AVI ", offset=8)
        self.assertTrue(m.matches(b"RIFF\x00\x00\x00\x00AVI LIST"))
        self.assertFalse(m.matches(b"RIFFAVI "))  # 오프셋 안 맞음

    def test_too_short_buffer_no_match(self):
        m = Magic("png", ("png",), b"\x89PNG\r\n\x1a\n")
        self.assertFalse(m.matches(b"\x89PNG"))  # 시그니처보다 짧음

    def test_empty_signature_rejected(self):
        with self.assertRaises(ValueError):
            Magic("bad", ("x",), b"")

    def test_negative_offset_rejected(self):
        with self.assertRaises(ValueError):
            Magic("bad", ("x",), b"AB", offset=-1)


class IdentifyTest(unittest.TestCase):
    def test_identifies_png(self):
        m = identify(PNG)
        self.assertIsNotNone(m)
        self.assertEqual(m.name, "png")

    def test_identifies_jpeg(self):
        self.assertEqual(identify(JPEG).name, "jpeg")

    def test_identifies_zip(self):
        self.assertEqual(identify(ZIP).name, "zip")

    def test_unknown_returns_none(self):
        self.assertIsNone(identify(b"not a known header at all"))

    def test_empty_returns_none(self):
        self.assertIsNone(identify(b""))

    def test_prefers_longer_signature(self):
        # 짧은 'AB' 와 긴 'ABCDEF' 가 동시에 맞으면 긴 쪽.
        magics = (
            Magic("short", ("s",), b"AB"),
            Magic("long", ("l",), b"ABCDEF"),
        )
        self.assertEqual(identify(b"ABCDEF...", magics).name, "long")

    def test_does_not_mutate_input(self):
        data = bytearray(PNG)
        snapshot = bytes(data)
        identify(bytes(data))
        self.assertEqual(bytes(data), snapshot)


class IdentifyAllTest(unittest.TestCase):
    def test_returns_all_matches_sorted_by_specificity(self):
        magics = (
            Magic("short", ("s",), b"AB"),
            Magic("long", ("l",), b"ABCDEF"),
        )
        names = [m.name for m in identify_all(b"ABCDEF", magics)]
        self.assertEqual(names, ["long", "short"])

    def test_no_match_returns_empty(self):
        self.assertEqual(identify_all(b"zzzz"), [])

    def test_default_magics_nonempty(self):
        self.assertGreater(len(DEFAULT_MAGICS), 0)


class ExtensionMismatchTest(unittest.TestCase):
    def test_correct_extension_no_mismatch(self):
        self.assertFalse(extension_mismatch("photo.png", PNG))
        self.assertFalse(extension_mismatch("doc.PDF", b"%PDF-1.4"))  # 대소문자 무시

    def test_spoofed_extension_flagged(self):
        # PE 실행 파일을 .jpg 로 둔갑.
        self.assertTrue(extension_mismatch("invoice.jpg", PE))

    def test_zip_family_extensions_allowed(self):
        # docx 는 ZIP 매직을 가지므로 어긋나지 않아야 한다.
        self.assertFalse(extension_mismatch("report.docx", ZIP))

    def test_unknown_type_not_flagged(self):
        self.assertFalse(extension_mismatch("mystery.jpg", b"unknown bytes"))

    def test_no_extension_not_flagged(self):
        self.assertFalse(extension_mismatch("README", ELF))

    def test_path_with_directories(self):
        self.assertTrue(extension_mismatch("/var/tmp/x.jpg", PE))


if __name__ == "__main__":
    unittest.main()
