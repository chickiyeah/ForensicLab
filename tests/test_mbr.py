"""forensiclab.mbr 단위 테스트 (stdlib unittest)."""

import io
import os
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from forensiclab.mbr import (  # noqa: E402
    MBR_SIGNATURE,
    SECTOR_SIZE,
    MasterBootRecord,
    PartitionEntry,
    parse_mbr,
    read_mbr,
)


def _entry(boot_flag, type_code, lba_start, sector_count):
    """16바이트 파티션 엔트리 바이트 생성 (CHS 는 0 으로 채움)."""
    return struct.pack(
        "<B3sB3sII",
        boot_flag,
        b"\x00\x00\x00",
        type_code,
        b"\x00\x00\x00",
        lba_start,
        sector_count,
    )


def _build_mbr(entries, signature=MBR_SIGNATURE):
    """446 바이트 부트코드 + 엔트리들 + 패딩 + 시그니처로 512바이트 구성."""
    buf = bytearray(b"\xeb" + b"\x90" * 445)  # 그럴듯한 부트코드 채움(446B)
    for e in entries:
        buf += e
    buf += b"\x00" * (SECTOR_SIZE - len(buf) - 2)
    buf += signature
    assert len(buf) == SECTOR_SIZE, len(buf)
    return bytes(buf)


# NTFS 활성 파티션 1개를 가진 전형적 MBR.
NTFS_PART = _entry(0x80, 0x07, lba_start=2048, sector_count=204800)
SAMPLE_MBR = _build_mbr([NTFS_PART])


class ParseMbrTest(unittest.TestCase):
    def test_signature_valid(self):
        mbr = parse_mbr(SAMPLE_MBR)
        self.assertTrue(mbr.is_valid)
        self.assertEqual(mbr.signature, MBR_SIGNATURE)

    def test_invalid_signature_detected(self):
        mbr = parse_mbr(_build_mbr([NTFS_PART], signature=b"\x00\x00"))
        self.assertFalse(mbr.is_valid)

    def test_always_four_entries(self):
        self.assertEqual(len(parse_mbr(SAMPLE_MBR).partitions), 4)

    def test_first_partition_fields(self):
        p = parse_mbr(SAMPLE_MBR).partitions[0]
        self.assertEqual(p.index, 0)
        self.assertEqual(p.boot_flag, 0x80)
        self.assertEqual(p.type_code, 0x07)
        self.assertEqual(p.lba_start, 2048)
        self.assertEqual(p.sector_count, 204800)

    def test_bootable_and_type_name(self):
        p = parse_mbr(SAMPLE_MBR).partitions[0]
        self.assertTrue(p.is_bootable)
        self.assertFalse(p.is_empty)
        self.assertEqual(p.type_name, "NTFS / exFAT")

    def test_byte_offset_and_size(self):
        p = parse_mbr(SAMPLE_MBR).partitions[0]
        self.assertEqual(p.byte_offset, 2048 * SECTOR_SIZE)
        self.assertEqual(p.byte_size, 204800 * SECTOR_SIZE)

    def test_empty_entries_recognized(self):
        mbr = parse_mbr(SAMPLE_MBR)
        self.assertTrue(all(p.is_empty for p in mbr.partitions[1:]))
        self.assertEqual(len(mbr.used_partitions), 1)

    def test_unknown_type_name(self):
        mbr = parse_mbr(_build_mbr([_entry(0x00, 0xAB, 1, 1)]))
        self.assertEqual(mbr.partitions[0].type_name, "Unknown (0xAB)")

    def test_multiple_partitions(self):
        parts = [
            _entry(0x80, 0x83, 2048, 1000),
            _entry(0x00, 0x82, 4096, 500),
        ]
        mbr = parse_mbr(_build_mbr(parts))
        self.assertEqual(len(mbr.used_partitions), 2)
        self.assertEqual(mbr.partitions[1].type_name, "Linux swap")

    def test_short_buffer_raises(self):
        with self.assertRaises(ValueError):
            parse_mbr(b"\x00" * 100)

    def test_oversized_buffer_uses_first_sector(self):
        padded = SAMPLE_MBR + b"\xff" * 4096
        self.assertEqual(parse_mbr(padded), parse_mbr(SAMPLE_MBR))

    def test_returns_dataclass_types(self):
        mbr = parse_mbr(SAMPLE_MBR)
        self.assertIsInstance(mbr, MasterBootRecord)
        self.assertIsInstance(mbr.partitions[0], PartitionEntry)


class ReadMbrTest(unittest.TestCase):
    def test_read_from_stream(self):
        mbr = read_mbr(io.BytesIO(SAMPLE_MBR))
        self.assertTrue(mbr.is_valid)
        self.assertEqual(mbr.partitions[0].type_code, 0x07)

    def test_read_from_path(self):
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(SAMPLE_MBR)
            path = tmp.name
        try:
            self.assertEqual(read_mbr(path), parse_mbr(SAMPLE_MBR))
        finally:
            os.unlink(path)

    def test_read_missing_path_raises(self):
        with self.assertRaises(FileNotFoundError):
            read_mbr(os.path.join(tempfile.gettempdir(), "no_such_mbr_image_xyz"))


if __name__ == "__main__":
    unittest.main()
