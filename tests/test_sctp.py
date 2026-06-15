"""forensiclab.sctp 단위 테스트 (stdlib unittest)."""

import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from forensiclab.sctp import (  # noqa: E402
    SCTP_CHUNK_HEADER_LEN,
    SCTP_HEADER_LEN,
    Sctp,
    SctpChunk,
    parse_sctp,
)


def _chunk(chunk_type, chunk_flags=0, value=b""):
    """청크 하나(헤더+값+4바이트 패딩) 바이트를 짠다."""
    length = SCTP_CHUNK_HEADER_LEN + len(value)
    raw = struct.pack(">BBH", chunk_type, chunk_flags, length) + value
    raw += b"\x00" * (-length % 4)  # 4바이트 경계 패딩.
    return raw


def _packet(
    source_port=3868,
    dest_port=3868,
    verification_tag=0xAABBCCDD,
    checksum=0,
    chunks=b"",
):
    """SCTP 공통 헤더(+청크들) 바이트를 짠다."""
    return (
        struct.pack(">HHII", source_port, dest_port, verification_tag, checksum)
        + chunks
    )


class ParseBasicTests(unittest.TestCase):
    def test_common_header_fields(self):
        s = parse_sctp(_packet(chunks=_chunk(0)))
        self.assertIsInstance(s, Sctp)
        self.assertEqual(s.source_port, 3868)
        self.assertEqual(s.dest_port, 3868)
        self.assertEqual(s.verification_tag, 0xAABBCCDD)
        self.assertEqual(s.checksum, 0)
        self.assertEqual(s.payload_offset, SCTP_HEADER_LEN)

    def test_ports_roundtrip(self):
        s = parse_sctp(_packet(source_port=2905, dest_port=12345,
                               chunks=_chunk(1)))
        self.assertEqual(s.source_port, 2905)
        self.assertEqual(s.dest_port, 12345)

    def test_verification_tag_max(self):
        s = parse_sctp(_packet(verification_tag=0xFFFFFFFF, chunks=_chunk(0)))
        self.assertEqual(s.verification_tag, 0xFFFFFFFF)

    def test_checksum_preserved(self):
        s = parse_sctp(_packet(checksum=0x12345678, chunks=_chunk(0)))
        self.assertEqual(s.checksum, 0x12345678)

    def test_offset(self):
        blob = b"\xde\xad" + _packet(chunks=_chunk(0))
        s = parse_sctp(blob, offset=2)
        self.assertEqual(s.payload_offset, 2 + SCTP_HEADER_LEN)
        self.assertEqual(s.source_port, 3868)


class ChunkTests(unittest.TestCase):
    def test_single_data_chunk(self):
        s = parse_sctp(_packet(chunks=_chunk(0, value=b"hello")))
        self.assertEqual(len(s.chunks), 1)
        c = s.first_chunk
        self.assertIsInstance(c, SctpChunk)
        self.assertEqual(c.chunk_type, 0)
        self.assertEqual(c.chunk_name, "DATA")
        self.assertEqual(c.chunk_length, SCTP_CHUNK_HEADER_LEN + 5)
        self.assertEqual(c.value_offset, SCTP_HEADER_LEN + SCTP_CHUNK_HEADER_LEN)

    def test_chunk_flags(self):
        s = parse_sctp(_packet(chunks=_chunk(0, chunk_flags=0x03)))
        self.assertEqual(s.first_chunk.chunk_flags, 0x03)

    def test_multiple_chunks_order(self):
        # SACK + DATA 가 한 패킷에 묶이는 흔한 경우.
        blob = _packet(chunks=_chunk(3) + _chunk(0, value=b"xyz"))
        s = parse_sctp(blob)
        self.assertEqual(s.chunk_types, (3, 0))
        self.assertEqual(s.chunk_names, ("SACK", "DATA"))

    def test_padding_between_chunks(self):
        # 첫 청크 값 5바이트 → 길이 9 → 12로 패딩, 두 번째 청크가 경계에 옴.
        blob = _packet(chunks=_chunk(4, value=b"abcde") + _chunk(5))
        s = parse_sctp(blob)
        self.assertEqual(s.chunk_names, ("HEARTBEAT", "HEARTBEAT-ACK"))
        self.assertEqual(s.chunks[1].value_offset,
                         SCTP_HEADER_LEN + 12 + SCTP_CHUNK_HEADER_LEN)

    def test_unknown_chunk_name(self):
        s = parse_sctp(_packet(chunks=_chunk(200)))
        self.assertEqual(s.first_chunk.chunk_name, "chunk-200")

    def test_known_chunk_names(self):
        for ctype, name in [
            (1, "INIT"), (2, "INIT-ACK"), (6, "ABORT"), (7, "SHUTDOWN"),
            (10, "COOKIE-ECHO"), (11, "COOKIE-ACK"), (14, "SHUTDOWN-COMPLETE"),
            (0x40, "I-DATA"), (0xC0, "FORWARD-TSN"),
        ]:
            s = parse_sctp(_packet(chunks=_chunk(ctype)))
            self.assertEqual(s.first_chunk.chunk_name, name)


class SemanticTests(unittest.TestCase):
    def test_is_init(self):
        self.assertTrue(parse_sctp(_packet(chunks=_chunk(1))).is_init)
        self.assertTrue(parse_sctp(_packet(chunks=_chunk(2))).is_init)
        self.assertFalse(parse_sctp(_packet(chunks=_chunk(0))).is_init)

    def test_is_data(self):
        self.assertTrue(parse_sctp(_packet(chunks=_chunk(0))).is_data)
        self.assertTrue(parse_sctp(_packet(chunks=_chunk(0x40))).is_data)
        self.assertFalse(parse_sctp(_packet(chunks=_chunk(1))).is_data)

    def test_is_abort(self):
        self.assertTrue(parse_sctp(_packet(chunks=_chunk(6))).is_abort)
        self.assertFalse(parse_sctp(_packet(chunks=_chunk(7))).is_abort)

    def test_is_shutdown(self):
        for ctype in (7, 8, 14):
            self.assertTrue(parse_sctp(_packet(chunks=_chunk(ctype))).is_shutdown)
        self.assertFalse(parse_sctp(_packet(chunks=_chunk(6))).is_shutdown)

    def test_has_chunk(self):
        s = parse_sctp(_packet(chunks=_chunk(10) + _chunk(0)))
        self.assertTrue(s.has_chunk(10))
        self.assertTrue(s.has_chunk(0))
        self.assertFalse(s.has_chunk(6))


class GuardTests(unittest.TestCase):
    def test_too_short_for_common_header(self):
        self.assertIsNone(parse_sctp(b"\x00" * 11))

    def test_common_header_but_no_chunk(self):
        # 12바이트 공통 헤더만 있고 청크 헤더가 없으면 SCTP 로 인정하지 않음.
        self.assertIsNone(parse_sctp(struct.pack(">HHII", 1, 2, 3, 4)))

    def test_partial_chunk_header(self):
        blob = struct.pack(">HHII", 1, 2, 3, 4) + b"\x00\x00\x00"  # 3바이트뿐.
        self.assertIsNone(parse_sctp(blob))

    def test_first_chunk_length_too_small(self):
        # chunk_length < 4 면 첫 청크가 망가진 것 → None.
        blob = struct.pack(">HHII", 1, 2, 3, 4) + struct.pack(">BBH", 0, 0, 2)
        self.assertIsNone(parse_sctp(blob))

    def test_negative_offset(self):
        self.assertIsNone(parse_sctp(_packet(chunks=_chunk(0)), offset=-1))

    def test_empty(self):
        self.assertIsNone(parse_sctp(b""))


class TruncationTests(unittest.TestCase):
    def test_chunk_length_exceeds_data(self):
        # 길이가 250이라 주장하지만 실제 값이 절단된 경우 — 첫 청크는 담고 멈춤.
        blob = struct.pack(">HHII", 1, 2, 3, 4) + struct.pack(">BBH", 0, 0, 250)
        s = parse_sctp(blob)
        self.assertIsNotNone(s)
        self.assertEqual(len(s.chunks), 1)
        self.assertEqual(s.first_chunk.chunk_length, 250)

    def test_second_chunk_truncated(self):
        # 정상 첫 청크 + 망가진 둘째 청크(길이 1) → 첫 청크만 유지.
        blob = _packet(chunks=_chunk(0, value=b"ok")
                       + struct.pack(">BBH", 5, 0, 1))
        s = parse_sctp(blob)
        self.assertEqual(s.chunk_types, (0,))


if __name__ == "__main__":
    unittest.main()
