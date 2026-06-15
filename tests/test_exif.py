"""forensiclab.exif 단위 테스트 (stdlib unittest).

외부 이미지 파일 없이, 위·경도를 담은 최소 EXIF/TIFF 바이트를 직접
조립해 GPS 추출 경로를 검증한다.
"""

import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from forensiclab.exif import (  # noqa: E402
    CameraMetadata,
    GpsCoordinate,
    dms_to_decimal,
    extract_gps,
    extract_metadata,
    find_exif_tiff,
)


def _rational(num, den=1):
    return struct.pack("<II", num, den)


def build_tiff(lat_dms, lat_ref, lon_dms, lon_ref):
    """위·경도를 담은 little-endian TIFF 페이로드를 만든다.

    레이아웃: header(8) + IFD0(18, GPS 포인터 1개) + GPS IFD(54) + 유리수 데이터.
    """
    gps_ifd_off = 8 + 18  # IFD0 = count(2)+entry(12)+next(4) = 18
    data_off = gps_ifd_off + 2 + 4 * 12 + 4  # GPS IFD 헤더 뒤 데이터 영역
    lat_off = data_off
    lon_off = data_off + 24

    # TIFF 헤더: byte order + magic 42 + IFD0 offset.
    out = b"II" + struct.pack("<HI", 42, 8)

    # IFD0: GPSInfo 포인터 1개.
    out += struct.pack("<H", 1)
    out += struct.pack("<HHII", 0x8825, 4, 1, gps_ifd_off)  # LONG, count 1
    out += struct.pack("<I", 0)  # next IFD = 0

    # GPS IFD: 4개 엔트리.
    out += struct.pack("<H", 4)
    # LatRef (ASCII, count 2, 4바이트 inline "N\0\0\0").
    out += struct.pack("<HHI", 1, 2, 2) + (lat_ref.encode() + b"\x00\x00\x00\x00")[:4]
    # Latitude (RATIONAL, count 3, offset).
    out += struct.pack("<HHII", 2, 5, 3, lat_off)
    # LonRef (ASCII, count 2, inline).
    out += struct.pack("<HHI", 3, 2, 2)
    out += (lon_ref.encode() + b"\x00\x00\x00\x00")[:4]
    # Longitude (RATIONAL, count 3, offset).
    out += struct.pack("<HHII", 4, 5, 3, lon_off)
    out += struct.pack("<I", 0)  # next IFD = 0

    # 데이터 영역: 위도/경도 유리수.
    for d in lat_dms:
        out += _rational(d)
    for d in lon_dms:
        out += _rational(d)
    return out


def wrap_jpeg(tiff):
    """TIFF 페이로드를 JPEG APP1(Exif) 세그먼트로 감싼다."""
    payload = b"Exif\x00\x00" + tiff
    app1 = b"\xff\xe1" + struct.pack(">H", len(payload) + 2) + payload
    # SOI + APP1 + (가짜 SOS 로 마무리) — 추출엔 APP1 만 있으면 충분.
    return b"\xff\xd8" + app1 + b"\xff\xd9"


class DmsToDecimalTest(unittest.TestCase):
    def test_north_east_positive(self):
        self.assertAlmostEqual(dms_to_decimal(37, 30, 0, "N"), 37.5)
        self.assertAlmostEqual(dms_to_decimal(127, 15, 0, "E"), 127.25)

    def test_south_west_negative(self):
        self.assertAlmostEqual(dms_to_decimal(33, 0, 0, "S"), -33.0)
        self.assertAlmostEqual(dms_to_decimal(70, 30, 0, "W"), -70.5)

    def test_ref_case_insensitive(self):
        self.assertLess(dms_to_decimal(10, 0, 0, "s"), 0)


class FindExifTiffTest(unittest.TestCase):
    def test_raw_tiff_passthrough(self):
        tiff = build_tiff((37, 30, 0), "N", (127, 15, 0), "E")
        self.assertEqual(find_exif_tiff(tiff), tiff)

    def test_locates_app1_in_jpeg(self):
        tiff = build_tiff((1, 0, 0), "N", (2, 0, 0), "E")
        found = find_exif_tiff(wrap_jpeg(tiff))
        self.assertEqual(found, tiff)

    def test_non_jpeg_returns_none(self):
        self.assertIsNone(find_exif_tiff(b"not an image at all"))

    def test_jpeg_without_exif_returns_none(self):
        self.assertIsNone(find_exif_tiff(b"\xff\xd8\xff\xd9"))


class ExtractGpsTest(unittest.TestCase):
    def test_extract_from_jpeg(self):
        tiff = build_tiff((37, 30, 0), "N", (127, 15, 0), "E")
        coord = extract_gps(wrap_jpeg(tiff))
        self.assertIsInstance(coord, GpsCoordinate)
        self.assertAlmostEqual(coord.latitude, 37.5)
        self.assertAlmostEqual(coord.longitude, 127.25)

    def test_extract_from_raw_tiff(self):
        tiff = build_tiff((10, 6, 0), "N", (20, 0, 36), "E")
        coord = extract_gps(tiff)
        self.assertAlmostEqual(coord.latitude, 10.1)
        self.assertAlmostEqual(coord.longitude, 20.01)

    def test_southern_western_hemisphere(self):
        tiff = build_tiff((33, 51, 0), "S", (151, 12, 0), "W")
        coord = extract_gps(tiff)
        self.assertLess(coord.latitude, 0)
        self.assertLess(coord.longitude, 0)

    def test_no_gps_returns_none(self):
        # GPS 포인터 없는 최소 TIFF: IFD0 엔트리 0개.
        tiff = b"II" + struct.pack("<HI", 42, 8) + struct.pack("<H", 0) + struct.pack("<I", 0)
        self.assertIsNone(extract_gps(tiff))

    def test_garbage_returns_none(self):
        self.assertIsNone(extract_gps(b"\x00\x01\x02\x03"))


def _ascii(s):
    return s.encode("ascii") + b"\x00"


def build_meta_tiff(
    make="Apple",
    model="iPhone 12",
    software="16.1",
    dt="2026:01:01 12:00:00",
    orientation=6,
    iso=200,
    exposure=(1, 120),
    fnumber=(16, 10),
    focal=(52, 10),
    lens="iPhone 12 back camera",
):
    """카메라/촬영 설정 태그를 담은 little-endian TIFF 페이로드를 만든다.

    레이아웃: header(8) + IFD0(6 엔트리) + Exif SubIFD(6 엔트리) + 데이터 영역.
    값이 4바이트를 넘는 항목(문자열·유리수)은 데이터 영역으로 오프셋 참조한다.
    """
    ifd0_off = 8
    ifd0_size = 2 + 6 * 12 + 4
    exif_off = ifd0_off + ifd0_size
    exif_size = 2 + 6 * 12 + 4
    data_off = exif_off + exif_size

    data = bytearray()

    def add(b):
        off = data_off + len(data)
        data.extend(b)
        return off

    make_o = add(_ascii(make))
    model_o = add(_ascii(model))
    soft_o = add(_ascii(software))
    dt_o = add(_ascii(dt))
    exp_o = add(struct.pack("<II", *exposure))
    fn_o = add(struct.pack("<II", *fnumber))
    foc_o = add(struct.pack("<II", *focal))
    lens_o = add(_ascii(lens))

    def off_entry(tag, typ, count, offset):
        return struct.pack("<HHII", tag, typ, count, offset)

    def short_entry(tag, value):
        return struct.pack("<HHI", tag, 3, 1) + struct.pack("<H", value) + b"\x00\x00"

    ifd0 = struct.pack("<H", 6)
    ifd0 += off_entry(0x010F, 2, len(_ascii(make)), make_o)
    ifd0 += off_entry(0x0110, 2, len(_ascii(model)), model_o)
    ifd0 += short_entry(0x0112, orientation)
    ifd0 += off_entry(0x0131, 2, len(_ascii(software)), soft_o)
    ifd0 += off_entry(0x0132, 2, len(_ascii(dt)), dt_o)
    ifd0 += off_entry(0x8769, 4, 1, exif_off)  # Exif SubIFD 포인터
    ifd0 += struct.pack("<I", 0)

    sub = struct.pack("<H", 6)
    sub += off_entry(0x829A, 5, 1, exp_o)
    sub += off_entry(0x829D, 5, 1, fn_o)
    sub += short_entry(0x8827, iso)
    sub += off_entry(0x9003, 2, len(_ascii(dt)), dt_o)
    sub += off_entry(0x920A, 5, 1, foc_o)
    sub += off_entry(0xA434, 2, len(_ascii(lens)), lens_o)
    sub += struct.pack("<I", 0)

    return b"II" + struct.pack("<HI", 42, 8) + ifd0 + sub + bytes(data)


class ExtractMetadataTest(unittest.TestCase):
    def test_full_metadata_from_jpeg(self):
        meta = extract_metadata(wrap_jpeg(build_meta_tiff()))
        self.assertIsInstance(meta, CameraMetadata)
        self.assertEqual(meta.make, "Apple")
        self.assertEqual(meta.model, "iPhone 12")
        self.assertEqual(meta.orientation, 6)
        self.assertEqual(meta.software, "16.1")
        self.assertEqual(meta.datetime_original, "2026:01:01 12:00:00")
        self.assertEqual(meta.iso, 200)
        self.assertAlmostEqual(meta.exposure_time, 1 / 120)
        self.assertAlmostEqual(meta.f_number, 1.6)
        self.assertAlmostEqual(meta.focal_length, 5.2)
        self.assertEqual(meta.lens_model, "iPhone 12 back camera")
        self.assertFalse(meta.is_empty())

    def test_from_raw_tiff(self):
        meta = extract_metadata(build_meta_tiff(make="Canon", model="EOS 5D"))
        self.assertEqual(meta.make, "Canon")
        self.assertEqual(meta.model, "EOS 5D")

    def test_no_subifd_keeps_ifd0_fields(self):
        # GPS 전용 builder 에는 Exif SubIFD 가 없다 → 촬영 설정은 None.
        tiff = build_tiff((37, 30, 0), "N", (127, 15, 0), "E")
        meta = extract_metadata(tiff)
        self.assertIsInstance(meta, CameraMetadata)
        self.assertIsNone(meta.iso)
        self.assertIsNone(meta.make)
        self.assertTrue(meta.is_empty())

    def test_non_image_returns_none(self):
        self.assertIsNone(extract_metadata(b"not an image at all"))

    def test_jpeg_without_exif_returns_none(self):
        self.assertIsNone(extract_metadata(b"\xff\xd8\xff\xd9"))


if __name__ == "__main__":
    unittest.main()
