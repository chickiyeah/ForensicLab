"""forensiclab.pcap 단위 테스트 (stdlib unittest)."""

import os
import struct
import sys
import unittest
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from forensiclab.pcap import (  # noqa: E402
    GLOBAL_HEADER_SIZE,
    RECORD_HEADER_SIZE,
    Packet,
    PcapError,
    PcapHeader,
    iter_packets,
    parse,
    parse_header,
)

# 마이크로초/리틀 엔디안 매직.
_MAGIC_LE_US = b"\xd4\xc3\xb2\xa1"
_MAGIC_LE_NS = b"\x4d\x3c\xb2\xa1"
_MAGIC_BE_US = b"\xa1\xb2\xc3\xd4"


def _global_header(magic=_MAGIC_LE_US, endian="<", snaplen=65535, linktype=1):
    return magic + struct.pack(endian + "HHiIII", 2, 4, 0, 0, snaplen, linktype)


def _record(endian, ts_sec, ts_frac, data, orig_len=None):
    if orig_len is None:
        orig_len = len(data)
    return struct.pack(endian + "IIII", ts_sec, ts_frac, len(data), orig_len) + data


class ParseHeaderTest(unittest.TestCase):
    def test_little_endian_microsecond(self):
        h = parse_header(_global_header())
        self.assertEqual(h.byte_order, "<")
        self.assertFalse(h.nanosecond)
        self.assertEqual(h.version_major, 2)
        self.assertEqual(h.version_minor, 4)
        self.assertEqual(h.snaplen, 65535)
        self.assertEqual(h.linktype, 1)

    def test_big_endian_magic(self):
        h = parse_header(_global_header(magic=_MAGIC_BE_US, endian=">"))
        self.assertEqual(h.byte_order, ">")
        self.assertFalse(h.nanosecond)

    def test_nanosecond_magic(self):
        h = parse_header(_global_header(magic=_MAGIC_LE_NS))
        self.assertTrue(h.nanosecond)

    def test_bad_magic_raises(self):
        with self.assertRaises(PcapError):
            parse_header(b"\x00\x01\x02\x03" + b"\x00" * 20)

    def test_short_buffer_raises(self):
        with self.assertRaises(PcapError):
            parse_header(_MAGIC_LE_US + b"\x00" * 4)

    def test_header_is_frozen(self):
        h = parse_header(_global_header())
        with self.assertRaises(Exception):
            h.snaplen = 1  # type: ignore[misc]


class IterPacketsTest(unittest.TestCase):
    def test_single_packet(self):
        buf = _global_header() + _record("<", 1000, 500, b"\xde\xad\xbe\xef")
        packets = list(iter_packets(buf))
        self.assertEqual(len(packets), 1)
        p = packets[0]
        self.assertEqual(p.index, 0)
        self.assertEqual(p.data, b"\xde\xad\xbe\xef")
        self.assertEqual(p.captured_len, 4)
        self.assertEqual(p.original_len, 4)
        self.assertFalse(p.truncated)

    def test_timestamp_microseconds(self):
        buf = _global_header() + _record("<", 1_700_000_000, 123_456, b"x")
        p = next(iter(iter_packets(buf)))
        expected = datetime.fromtimestamp(1_700_000_000, tz=timezone.utc).replace(
            microsecond=123_456
        )
        self.assertEqual(p.timestamp, expected)
        self.assertEqual(p.timestamp.tzinfo, timezone.utc)

    def test_timestamp_nanoseconds_scaled_to_micros(self):
        # 나노초 해상도: 소수부 123_456_789ns → 123_456us.
        buf = _global_header(magic=_MAGIC_LE_NS) + _record(
            "<", 1_700_000_000, 123_456_789, b"x"
        )
        p = next(iter(iter_packets(buf)))
        self.assertEqual(p.timestamp.microsecond, 123_456)

    def test_multiple_packets_indexed_in_order(self):
        buf = (
            _global_header()
            + _record("<", 10, 0, b"a")
            + _record("<", 20, 0, b"bb")
            + _record("<", 30, 0, b"ccc")
        )
        packets = list(iter_packets(buf))
        self.assertEqual([p.index for p in packets], [0, 1, 2])
        self.assertEqual([p.captured_len for p in packets], [1, 2, 3])

    def test_truncated_packet_flag(self):
        # 회선상 1500바이트였으나 4바이트만 캡처됨.
        buf = _global_header() + _record("<", 1, 0, b"\x00\x00\x00\x00", orig_len=1500)
        p = next(iter(iter_packets(buf)))
        self.assertTrue(p.truncated)
        self.assertEqual(p.original_len, 1500)
        self.assertEqual(p.captured_len, 4)

    def test_empty_capture_yields_nothing(self):
        self.assertEqual(list(iter_packets(_global_header())), [])

    def test_truncated_record_header_raises(self):
        buf = _global_header() + b"\x00" * (RECORD_HEADER_SIZE - 1)
        with self.assertRaises(PcapError):
            list(iter_packets(buf))

    def test_truncated_payload_raises(self):
        # incl_len=10 이라 선언하지만 실제 데이터는 3바이트뿐.
        bad = _global_header() + struct.pack("<IIII", 1, 0, 10, 10) + b"abc"
        with self.assertRaises(PcapError):
            list(iter_packets(bad))

    def test_accepts_explicit_header_and_packet_region(self):
        header = parse_header(_global_header())
        region = _record("<", 5, 0, b"zz")
        packets = list(iter_packets(region, header))
        self.assertEqual(len(packets), 1)
        self.assertEqual(packets[0].data, b"zz")


class ParseTest(unittest.TestCase):
    def test_returns_header_and_packets(self):
        buf = (
            _global_header()
            + _record("<", 1, 0, b"a")
            + _record("<", 2, 0, b"b")
        )
        header, packets = parse(buf)
        self.assertIsInstance(header, PcapHeader)
        self.assertEqual(len(packets), 2)
        self.assertTrue(all(isinstance(p, Packet) for p in packets))

    def test_does_not_mutate_input(self):
        buf = _global_header() + _record("<", 1, 0, b"a")
        snapshot = bytes(buf)
        parse(buf)
        self.assertEqual(buf, snapshot)

    def test_constants(self):
        self.assertEqual(GLOBAL_HEADER_SIZE, 24)
        self.assertEqual(RECORD_HEADER_SIZE, 16)


if __name__ == "__main__":
    unittest.main()
