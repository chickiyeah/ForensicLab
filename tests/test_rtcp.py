"""forensiclab.rtcp 단위 테스트 (stdlib unittest)."""

import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from forensiclab.rtcp import (  # noqa: E402
    PT_APP,
    PT_BYE,
    PT_RR,
    PT_SDES,
    PT_SR,
    RTCP_VERSION,
    SDES_CNAME,
    RtcpReportBlock,
    RtcpSdesItem,
    is_rtcp,
    parse_rtcp,
    parse_rtcp_compound,
    rtcp_pt_name,
    sdes_type_name,
)


def _hdr(pt: int, count: int, body: bytes, padding: bool = False) -> bytes:
    """공통 헤더 + body 를 length 워드로 묶는다(body 는 4의 배수여야)."""
    assert len(body) % 4 == 0
    length_words = (len(body) + 4) // 4 - 1
    b0 = 0x80 | (0x20 if padding else 0) | (count & 0x1F)
    return struct.pack(">BBH", b0, pt, length_words) + body


def _report_block(ssrc, frac, lost, hseq, jit, lsr, dlsr) -> bytes:
    lost &= 0xFFFFFF
    return struct.pack(">I", ssrc) + bytes([frac, (lost >> 16) & 0xFF,
            (lost >> 8) & 0xFF, lost & 0xFF]) + struct.pack(">IIII", hseq, jit, lsr, dlsr)


class SenderReportTest(unittest.TestCase):
    def test_sr_basic(self):
        ntp = 0x1234567890ABCDEF
        body = struct.pack(">IQIII", 0xAABBCCDD, ntp, 0x111, 500, 80000)
        pkt = parse_rtcp(_hdr(PT_SR, 0, body))
        self.assertIsNotNone(pkt)
        self.assertTrue(pkt.is_sender_report)
        self.assertEqual(pkt.pt_name, "SR")
        self.assertEqual(pkt.sender_ssrc, 0xAABBCCDD)
        self.assertEqual(pkt.ntp_timestamp, ntp)
        self.assertEqual(pkt.rtp_timestamp, 0x111)
        self.assertEqual(pkt.packet_count, 500)
        self.assertEqual(pkt.octet_count, 80000)
        self.assertEqual(pkt.report_blocks, ())

    def test_sr_with_report_block(self):
        body = struct.pack(">IQIII", 1, 0, 0, 0, 0)
        body += _report_block(0xDEAD, 25, 3, 1000, 7, 0x1111, 0x2222)
        pkt = parse_rtcp(_hdr(PT_SR, 1, body))
        self.assertEqual(len(pkt.report_blocks), 1)
        rb = pkt.report_blocks[0]
        self.assertEqual(rb.ssrc, 0xDEAD)
        self.assertEqual(rb.fraction_lost, 25)
        self.assertEqual(rb.packets_lost, 3)
        self.assertEqual(rb.highest_seq, 1000)
        self.assertEqual(rb.jitter, 7)

    def test_sr_negative_lost(self):
        # 중복 수신 -> 음수 누적 손실(24비트 2의 보수).
        body = struct.pack(">IQIII", 1, 0, 0, 0, 0)
        body += _report_block(2, 0, -2 & 0xFFFFFF, 0, 0, 0, 0)
        pkt = parse_rtcp(_hdr(PT_SR, 1, body))
        self.assertEqual(pkt.report_blocks[0].packets_lost, -2)

    def test_sr_report_block_overflow(self):
        # RC=2 알리지만 블록 하나뿐 -> None.
        body = struct.pack(">IQIII", 1, 0, 0, 0, 0)
        body += _report_block(2, 0, 0, 0, 0, 0, 0)
        self.assertIsNone(parse_rtcp(_hdr(PT_SR, 2, body)))

    def test_ntp_epoch(self):
        # 상위 32비트 = NTP 초(1900 기준), 하위 = 0.5초.
        seconds = 2208988800 + 100  # = unix 100.0
        ntp = (seconds << 32) | (1 << 31)
        body = struct.pack(">IQIII", 1, ntp, 0, 0, 0)
        pkt = parse_rtcp(_hdr(PT_SR, 0, body))
        self.assertAlmostEqual(pkt.ntp_epoch, 100.5, places=4)


class ReceiverReportTest(unittest.TestCase):
    def test_rr_basic(self):
        body = struct.pack(">I", 0xCAFE) + _report_block(0xBEEF, 0, 0, 5, 9, 0, 0)
        pkt = parse_rtcp(_hdr(PT_RR, 1, body))
        self.assertTrue(pkt.is_receiver_report)
        self.assertEqual(pkt.sender_ssrc, 0xCAFE)
        self.assertEqual(pkt.report_blocks[0].ssrc, 0xBEEF)
        self.assertIsNone(pkt.ntp_timestamp)
        self.assertIsNone(pkt.ntp_epoch)


class SdesTest(unittest.TestCase):
    def _chunk(self, ssrc, items):
        b = struct.pack(">I", ssrc)
        for t, v in items:
            b += bytes([t, len(v)]) + v
        b += b"\x00"  # END
        while len(b) % 4:
            b += b"\x00"
        return b

    def test_cnames(self):
        body = self._chunk(0x1234, [(SDES_CNAME, b"alice@10.0.0.5"),
                                    (6, b"softphone-x")])  # 6 = TOOL
        pkt = parse_rtcp(_hdr(PT_SDES, 1, body))
        self.assertTrue(pkt.is_sdes)
        self.assertEqual(pkt.cnames, ("alice@10.0.0.5",))
        self.assertEqual(len(pkt.sdes_chunks), 1)
        ssrc, items = pkt.sdes_chunks[0]
        self.assertEqual(ssrc, 0x1234)
        self.assertEqual(items[0].type_name, "CNAME")
        self.assertEqual(items[1].text, "softphone-x")

    def test_two_chunks(self):
        body = self._chunk(1, [(SDES_CNAME, b"a@h")]) + self._chunk(2, [(SDES_CNAME, b"b@h")])
        pkt = parse_rtcp(_hdr(PT_SDES, 2, body))
        self.assertEqual(pkt.cnames, ("a@h", "b@h"))

    def test_sdes_item_overflow(self):
        # 항목 길이가 청크를 넘어감 -> None.
        body = struct.pack(">I", 1) + bytes([SDES_CNAME, 99]) + b"short\x00"
        self.assertIsNone(parse_rtcp(_hdr(PT_SDES, 1, body)))


class ByeTest(unittest.TestCase):
    def test_bye_with_reason(self):
        reason = b"call ended"
        body = struct.pack(">I", 0xABCD) + bytes([len(reason)]) + reason
        while len(body) % 4:
            body += b"\x00"
        pkt = parse_rtcp(_hdr(PT_BYE, 1, body))
        self.assertTrue(pkt.is_bye)
        self.assertEqual(pkt.bye_ssrcs, (0xABCD,))
        self.assertEqual(pkt.bye_reason, "call ended")

    def test_bye_no_reason(self):
        pkt = parse_rtcp(_hdr(PT_BYE, 1, struct.pack(">I", 7)))
        self.assertEqual(pkt.bye_ssrcs, (7,))
        self.assertIsNone(pkt.bye_reason)


class AppTest(unittest.TestCase):
    def test_app(self):
        body = struct.pack(">I", 0x999) + b"COVT" + b"hidden-payload!!"
        pkt = parse_rtcp(_hdr(PT_APP, 5, body))
        self.assertTrue(pkt.is_app)
        self.assertEqual(pkt.count, 5)  # subtype
        self.assertEqual(pkt.sender_ssrc, 0x999)
        self.assertEqual(pkt.app_name, "COVT")
        self.assertEqual(pkt.app_data, b"hidden-payload!!")


class GuardTest(unittest.TestCase):
    def test_too_short(self):
        self.assertIsNone(parse_rtcp(b"\x80\xc8\x00"))

    def test_wrong_version(self):
        body = struct.pack(">IQIII", 1, 0, 0, 0, 0)
        bad = bytes([0x40, PT_SR]) + struct.pack(">H", (len(body) + 4) // 4 - 1) + body
        self.assertIsNone(parse_rtcp(bad))

    def test_non_rtcp_pt(self):
        # PT=199, 205 는 범위 밖.
        self.assertIsNone(parse_rtcp(_hdr(199, 0, b"\x00\x00\x00\x00")))
        self.assertIsNone(parse_rtcp(_hdr(205, 0, b"\x00\x00\x00\x00")))

    def test_length_overflow(self):
        # length 가 실제 버퍼보다 큼 -> None.
        bad = struct.pack(">BBH", 0x80, PT_SR, 100)
        self.assertIsNone(parse_rtcp(bad))

    def test_negative_offset(self):
        self.assertIsNone(parse_rtcp(_hdr(PT_RR, 0, struct.pack(">I", 1)), offset=-1))

    def test_is_rtcp(self):
        self.assertTrue(is_rtcp(_hdr(PT_SR, 0, struct.pack(">IQIII", 1, 0, 0, 0, 0))))
        self.assertFalse(is_rtcp(b"\x80\x00"))  # PT 범위 밖
        self.assertFalse(is_rtcp(b"\x40\xc8"))  # 버전 아님


class NameTest(unittest.TestCase):
    def test_pt_names(self):
        self.assertEqual(rtcp_pt_name(PT_SR), "SR")
        self.assertEqual(rtcp_pt_name(PT_BYE), "BYE")
        self.assertEqual(rtcp_pt_name(250), "PT-250")

    def test_sdes_names(self):
        self.assertEqual(sdes_type_name(SDES_CNAME), "CNAME")
        self.assertEqual(sdes_type_name(99), "SDES-99")


class CompoundTest(unittest.TestCase):
    def test_sr_then_sdes(self):
        sr = _hdr(PT_SR, 0, struct.pack(">IQIII", 0x1, 0, 0, 0, 0))
        sdes_body = struct.pack(">I", 0x1) + bytes([SDES_CNAME, 3]) + b"a@h" + b"\x00"
        while len(sdes_body) % 4:
            sdes_body += b"\x00"
        sdes = _hdr(PT_SDES, 1, sdes_body)
        compound = sr + sdes
        pkts = parse_rtcp_compound(compound)
        self.assertEqual(len(pkts), 2)
        self.assertTrue(pkts[0].is_sender_report)
        self.assertTrue(pkts[1].is_sdes)
        self.assertEqual(pkts[1].cnames, ("a@h",))

    def test_compound_offsets(self):
        sr = _hdr(PT_SR, 0, struct.pack(">IQIII", 0x1, 0, 0, 0, 0))
        rr = _hdr(PT_RR, 0, struct.pack(">I", 0x2))
        pkts = parse_rtcp_compound(sr + rr)
        self.assertEqual(pkts[0].offset, 0)
        self.assertEqual(pkts[1].offset, len(sr))

    def test_compound_non_rtcp(self):
        self.assertIsNone(parse_rtcp_compound(b"\x00\x00\x00\x00"))


if __name__ == "__main__":
    unittest.main()
