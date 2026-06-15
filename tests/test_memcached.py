"""forensiclab.memcached 단위 테스트 (stdlib unittest)."""

import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from forensiclab.memcached import (  # noqa: E402
    MEMCACHED_PORTS,
    MemcachedCommand,
    MemcachedFrame,
    parse_memcached_command,
)


def _udp(payload: bytes, request_id=0x1234, seq=0, total=1, reserved=0):
    return struct.pack(">HHHH", request_id, seq, total, reserved) + payload


class ParseBasicTest(unittest.TestCase):
    def test_get(self):
        c = parse_memcached_command(b"get session:42\r\n")
        self.assertIsInstance(c, MemcachedCommand)
        self.assertEqual(c.verb, "get")
        self.assertEqual(c.args, ["session:42"])
        self.assertTrue(c.is_retrieval)
        self.assertEqual(c.keys, ["session:42"])
        self.assertFalse(c.is_udp)

    def test_multi_key_get(self):
        c = parse_memcached_command(b"get a b c\r\n")
        self.assertEqual(c.keys, ["a", "b", "c"])

    def test_verb_lowercased(self):
        c = parse_memcached_command(b"GET k\r\n")
        self.assertEqual(c.verb, "get")

    def test_no_trailing_crlf(self):
        c = parse_memcached_command(b"version")
        self.assertEqual(c.verb, "version")
        self.assertEqual(c.args, [])

    def test_ports(self):
        self.assertEqual(MEMCACHED_PORTS, (11211,))


class StorageTest(unittest.TestCase):
    def test_set_with_data_block(self):
        c = parse_memcached_command(b"set foo 0 3600 5\r\nhello\r\n")
        self.assertEqual(c.verb, "set")
        self.assertTrue(c.is_storage)
        self.assertEqual(c.keys, ["foo"])
        self.assertEqual(c.bytes_declared, 5)
        self.assertEqual(c.data, b"hello")

    def test_set_truncated_data(self):
        c = parse_memcached_command(b"set foo 0 0 100\r\nhel")
        self.assertEqual(c.bytes_declared, 100)
        self.assertEqual(c.data, b"hel")  # 가용분까지만

    def test_noreply(self):
        c = parse_memcached_command(b"set k 0 0 1 noreply\r\nx\r\n")
        self.assertTrue(c.noreply)

    def test_add_is_storage(self):
        self.assertTrue(parse_memcached_command(b"add k 0 0 0\r\n\r\n").is_storage)


class ForensicClueTest(unittest.TestCase):
    def test_flush_all_destructive(self):
        c = parse_memcached_command(b"flush_all\r\n")
        self.assertTrue(c.is_destructive)

    def test_stats_is_stats(self):
        self.assertTrue(parse_memcached_command(b"stats\r\n").is_stats)

    def test_stats_arg(self):
        c = parse_memcached_command(b"stats slabs\r\n")
        self.assertEqual(c.args, ["slabs"])

    def test_gat_keys_skip_exptime(self):
        c = parse_memcached_command(b"gat 60 k1 k2\r\n")
        self.assertEqual(c.keys, ["k1", "k2"])


class UdpFrameTest(unittest.TestCase):
    def test_udp_stats_amplification(self):
        c = parse_memcached_command(_udp(b"stats\r\n"))
        self.assertTrue(c.is_udp)
        self.assertIsInstance(c.frame, MemcachedFrame)
        self.assertEqual(c.frame.request_id, 0x1234)
        self.assertEqual(c.verb, "stats")
        self.assertTrue(c.is_amplification_probe)

    def test_udp_get_amplification(self):
        c = parse_memcached_command(_udp(b"get bigkey\r\n"))
        self.assertTrue(c.is_amplification_probe)

    def test_tcp_not_amplification(self):
        c = parse_memcached_command(b"stats\r\n")
        self.assertFalse(c.is_amplification_probe)

    def test_udp_reserved_nonzero_rejected_as_frame(self):
        # reserved != 0 → 프레임으로 인정 안 함 → 동사 아님 → None
        c = parse_memcached_command(_udp(b"stats\r\n", reserved=5))
        self.assertIsNone(c)

    def test_frame_fields(self):
        c = parse_memcached_command(_udp(b"version\r\n", request_id=7, seq=0, total=1))
        self.assertEqual(c.frame.total_datagrams, 1)
        self.assertEqual(c.frame.request_id, 7)


class RobustnessTest(unittest.TestCase):
    def test_unknown_verb_none(self):
        self.assertIsNone(parse_memcached_command(b"HELLO world\r\n"))

    def test_binary_garbage_none(self):
        self.assertIsNone(parse_memcached_command(b"\x00\x01\x02\xff\xfe"))

    def test_empty_none(self):
        self.assertIsNone(parse_memcached_command(b""))

    def test_offset(self):
        c = parse_memcached_command(b"XXget k\r\n", offset=2)
        self.assertEqual(c.verb, "get")

    def test_negative_offset_none(self):
        self.assertIsNone(parse_memcached_command(b"get k\r\n", offset=-1))

    def test_offset_beyond_none(self):
        self.assertIsNone(parse_memcached_command(b"get k\r\n", offset=99))


if __name__ == "__main__":
    unittest.main()
