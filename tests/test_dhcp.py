"""forensiclab.dhcp 단위 테스트 (stdlib unittest)."""

import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from forensiclab.dhcp import (  # noqa: E402
    BOOTREPLY,
    BOOTREQUEST,
    MAGIC_COOKIE,
    OPT_END,
    OPT_HOSTNAME,
    OPT_MESSAGE_TYPE,
    OPT_PAD,
    OPT_PARAM_REQ_LIST,
    OPT_REQUESTED_IP,
    OPT_VENDOR_CLASS,
    Dhcp,
    format_ipv4,
    format_mac,
    parse_dhcp,
)

CLIENT_MAC = b"\xde\xad\xbe\xef\x00\x01"


def _tlv(code, value):
    """옵션 1개를 type·len·value TLV 바이트로."""
    return bytes([code, len(value)]) + value


def _dhcp(op=BOOTREQUEST, xid=0x12345678, chaddr=CLIENT_MAC,
          ciaddr=b"\x00\x00\x00\x00", yiaddr=b"\x00\x00\x00\x00",
          options=b"", magic=MAGIC_COOKIE, hlen=6):
    """고정 헤더(240바이트)+옵션 DHCP 메시지 바이트를 짠다."""
    chaddr16 = (chaddr + b"\x00" * 16)[:16]
    fixed = (
        bytes([op, 1, hlen, 0])          # op, htype, hlen, hops
        + struct.pack(">I", xid)         # xid
        + b"\x00\x00\x00\x00"            # secs, flags
        + ciaddr + yiaddr                # ciaddr, yiaddr
        + b"\x00\x00\x00\x00" * 2        # siaddr, giaddr
        + chaddr16                       # chaddr (16)
        + b"\x00" * 64                   # sname
        + b"\x00" * 128                  # file
        + struct.pack(">I", magic)       # magic cookie
    )
    return fixed + options


class FormatTests(unittest.TestCase):
    def test_format_mac(self):
        self.assertEqual(format_mac(CLIENT_MAC), "de:ad:be:ef:00:01")

    def test_format_ipv4(self):
        self.assertEqual(format_ipv4(bytes([10, 8, 0, 17])), "10.8.0.17")

    def test_format_ipv4_nonstandard_length(self):
        self.assertEqual(format_ipv4(b"\x01\x02"), "0102")


class ParseDhcpTests(unittest.TestCase):
    def test_discover_round_trip(self):
        opts = (
            _tlv(OPT_MESSAGE_TYPE, b"\x01")          # DISCOVER
            + _tlv(OPT_HOSTNAME, b"laptop-01")
            + _tlv(OPT_REQUESTED_IP, bytes([192, 168, 0, 50]))
            + _tlv(OPT_VENDOR_CLASS, b"MSFT 5.0")
            + _tlv(OPT_PARAM_REQ_LIST, bytes([1, 3, 6, 15, 31, 33]))
            + bytes([OPT_END])
        )
        pkt = _dhcp(op=BOOTREQUEST, options=opts)
        msg = parse_dhcp(pkt)
        self.assertIsNotNone(msg)
        self.assertEqual(msg.op, BOOTREQUEST)
        self.assertEqual(msg.xid, 0x12345678)
        self.assertEqual(msg.client_mac, "de:ad:be:ef:00:01")
        self.assertEqual(msg.message_type, 1)
        self.assertEqual(msg.message_type_name, "DISCOVER")
        self.assertEqual(msg.hostname, "laptop-01")
        self.assertEqual(msg.requested_ip, "192.168.0.50")
        self.assertEqual(msg.vendor_class, "MSFT 5.0")
        # 핑거프린트는 순서 보존이 핵심.
        self.assertEqual(msg.param_req_list, [1, 3, 6, 15, 31, 33])

    def test_offer_yiaddr(self):
        opts = _tlv(OPT_MESSAGE_TYPE, b"\x02") + bytes([OPT_END])  # OFFER
        pkt = _dhcp(op=BOOTREPLY, yiaddr=bytes([10, 0, 0, 5]), options=opts)
        msg = parse_dhcp(pkt)
        self.assertEqual(msg.op, BOOTREPLY)
        self.assertEqual(msg.message_type_name, "OFFER")
        self.assertEqual(msg.your_ip, "10.0.0.5")

    def test_unknown_message_type_name(self):
        opts = _tlv(OPT_MESSAGE_TYPE, b"\x63") + bytes([OPT_END])
        msg = parse_dhcp(_dhcp(options=opts))
        self.assertEqual(msg.message_type_name, "type-99")

    def test_missing_options_return_none(self):
        msg = parse_dhcp(_dhcp(options=bytes([OPT_END])))
        self.assertIsNone(msg.message_type)
        self.assertIsNone(msg.message_type_name)
        self.assertIsNone(msg.hostname)
        self.assertIsNone(msg.requested_ip)
        self.assertIsNone(msg.vendor_class)
        self.assertIsNone(msg.param_req_list)

    def test_pad_options_skipped(self):
        opts = (
            bytes([OPT_PAD, OPT_PAD])
            + _tlv(OPT_HOSTNAME, b"host")
            + bytes([OPT_PAD])
            + bytes([OPT_END])
        )
        msg = parse_dhcp(_dhcp(options=opts))
        self.assertEqual(msg.hostname, "host")

    def test_split_option_concatenated(self):
        # RFC 3396: 같은 코드가 여러 번 → 값 이어붙임.
        opts = (
            _tlv(OPT_HOSTNAME, b"ab")
            + _tlv(OPT_HOSTNAME, b"cd")
            + bytes([OPT_END])
        )
        msg = parse_dhcp(_dhcp(options=opts))
        self.assertEqual(msg.hostname, "abcd")

    def test_hostname_strips_at_null(self):
        opts = _tlv(OPT_HOSTNAME, b"pc\x00junk") + bytes([OPT_END])
        msg = parse_dhcp(_dhcp(options=opts))
        self.assertEqual(msg.hostname, "pc")

    def test_no_end_option_still_parses(self):
        # end 옵션이 없어도 버퍼 끝까지 읽고 멈춘다.
        opts = _tlv(OPT_HOSTNAME, b"noend")
        msg = parse_dhcp(_dhcp(options=opts))
        self.assertEqual(msg.hostname, "noend")

    def test_offset_parsing(self):
        pkt = _dhcp(options=_tlv(OPT_HOSTNAME, b"x") + bytes([OPT_END]))
        msg = parse_dhcp(b"\xff\xff\xff" + pkt, offset=3)
        self.assertIsNotNone(msg)
        self.assertEqual(msg.hostname, "x")


class RejectTests(unittest.TestCase):
    def test_too_short_returns_none(self):
        self.assertIsNone(parse_dhcp(b"\x01" * 100))

    def test_bad_magic_returns_none(self):
        self.assertIsNone(parse_dhcp(_dhcp(magic=0xDEADBEEF)))

    def test_negative_offset_returns_none(self):
        self.assertIsNone(parse_dhcp(_dhcp(), offset=-1))

    def test_truncated_option_length_stops(self):
        # 길이가 버퍼를 넘는 옵션 → 거기서 멈추되 예외 없음.
        opts = bytes([OPT_HOSTNAME, 200]) + b"short"
        msg = parse_dhcp(_dhcp(options=opts))
        self.assertIsNotNone(msg)
        self.assertIsNone(msg.hostname)


class ChaddrTests(unittest.TestCase):
    def test_client_mac_uses_hlen(self):
        # hlen 이 6 이면 chaddr 의 패딩 0 은 제외.
        msg = parse_dhcp(_dhcp(chaddr=CLIENT_MAC, hlen=6))
        self.assertEqual(msg.client_mac, "de:ad:be:ef:00:01")

    def test_client_mac_bad_hlen_falls_back(self):
        # hlen 이 비정상(0)이면 chaddr 전체를 쓴다(견고성).
        msg = parse_dhcp(_dhcp(chaddr=CLIENT_MAC, hlen=0))
        self.assertEqual(len(msg.client_mac.split(":")), 16)


if __name__ == "__main__":
    unittest.main()
