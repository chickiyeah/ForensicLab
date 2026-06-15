"""forensiclab.carving 단위 테스트 (stdlib unittest)."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from forensiclab.carving import (  # noqa: E402
    DEFAULT_SIGNATURES,
    CarvedFile,
    FileSignature,
    carve_buffer,
)


# 테스트용 최소 파일 본문 (헤더 + 본문 + 푸터).
GIF = b"GIF89a" + b"\x01\x02\x03" + b"\x00\x3b"
PNG = b"\x89PNG\r\n\x1a\n" + b"body" + b"\x49\x45\x4e\x44\xae\x42\x60\x82"
JPEG = b"\xff\xd8\xff" + b"\xaa\xbb" + b"\xff\xd9"


class CarveBufferTest(unittest.TestCase):
    def test_carves_single_gif(self):
        data = b"\x00" * 10 + GIF + b"\xff" * 5
        carved = carve_buffer(data)
        gifs = [c for c in carved if c.name == "gif"]
        self.assertEqual(len(gifs), 1)
        self.assertEqual(gifs[0].offset, 10)
        self.assertEqual(gifs[0].data, GIF)
        self.assertEqual(gifs[0].size, len(GIF))

    def test_carves_multiple_formats_sorted_by_offset(self):
        data = PNG + b"junk" + JPEG + b"pad" + GIF
        carved = carve_buffer(data)
        names = [c.name for c in carved]
        # 오프셋 오름차순: PNG(0) → JPEG → GIF
        self.assertEqual(names, ["png", "jpeg", "gif"])
        offsets = [c.offset for c in carved]
        self.assertEqual(offsets, sorted(offsets))

    def test_extracted_data_is_exact(self):
        data = b"prefix" + JPEG + b"suffix"
        carved = carve_buffer(data)
        jpg = next(c for c in carved if c.name == "jpeg")
        self.assertEqual(jpg.data, JPEG)
        self.assertTrue(jpg.data.startswith(b"\xff\xd8\xff"))
        self.assertTrue(jpg.data.endswith(b"\xff\xd9"))

    def test_two_gifs_do_not_overlap(self):
        data = GIF + b"gap" + GIF
        carved = [c for c in carve_buffer(data) if c.name == "gif"]
        self.assertEqual(len(carved), 2)
        self.assertEqual(carved[0].offset, 0)
        self.assertEqual(carved[1].offset, len(GIF) + len(b"gap"))

    def test_header_without_footer_is_skipped(self):
        data = b"GIF89a" + b"no footer here"  # 푸터 없음
        carved = [c for c in carve_buffer(data) if c.name == "gif"]
        self.assertEqual(carved, [])

    def test_empty_buffer_returns_empty(self):
        self.assertEqual(carve_buffer(b""), [])

    def test_sector_property(self):
        data = b"\x00" * 1024 + GIF
        gif = next(c for c in carve_buffer(data) if c.name == "gif")
        self.assertEqual(gif.offset, 1024)
        self.assertEqual(gif.sector, 2)  # 1024 / 512

    def test_suggested_filename(self):
        cf = CarvedFile("gif", "gif", 0, 3, b"abc")
        self.assertEqual(cf.suggested_filename(7), "recovered_7.gif")

    def test_custom_signature_with_max_size(self):
        sig = FileSignature(
            name="raw", extension="bin", headers=(b"MAGIC",), max_size=8
        )
        data = b"....MAGIC1234567890"
        carved = carve_buffer(data, signatures=[sig])
        self.assertEqual(len(carved), 1)
        self.assertEqual(carved[0].size, 8)
        self.assertEqual(carved[0].data, b"MAGIC123")


class SignatureValidationTest(unittest.TestCase):
    def test_requires_at_least_one_header(self):
        with self.assertRaises(ValueError):
            FileSignature(name="x", extension="x", headers=(), footer=b"END")

    def test_requires_footer_or_max_size(self):
        with self.assertRaises(ValueError):
            FileSignature(name="x", extension="x", headers=(b"H",))

    def test_default_signatures_are_valid(self):
        names = {s.name for s in DEFAULT_SIGNATURES}
        self.assertEqual(names, {"gif", "jpeg", "png", "pdf", "zip"})


if __name__ == "__main__":
    unittest.main()
