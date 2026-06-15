"""forensiclab.ntp 단위 테스트 (stdlib unittest)."""

import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from forensiclab.ntp import (  # noqa: E402
    LI_UNSYNCHRONIZED,
    MODE_CLIENT,
    MODE_CONTROL,
    MODE_PRIVATE,
    MODE_SERVER,
    NTP_HEADER_SIZE,
    NTP_UNIX_EPOCH_DELTA,
    Ntp,
    format_ipv4,
    ntp_to_unix,
    parse_ntp,
)


def _ntp(leap=0, version=4, mode=MODE_SERVER, stratum=2, poll=6, precision=-20,
         root_delay=0, root_dispersion=0, reference_id=b"\x00\x00\x00\x00",
         reference_ts=0, originate_ts=0, receive_ts=0, transmit_ts=0):
    """48바이트 NTP 고정 헤더 바이트를 짠다."""
    flags = ((leap & 0x3) << 6) | ((version & 0x7) << 3) | (mode & 0x7)
    return (
        bytes([flags, stratum & 0xFF])
        + struct.pack("b", poll)
        + struct.pack("b", precision)
        + struct.pack(">I", root_delay)
        + struct.pack(">I", root_dispersion)
        + reference_id
        + struct.pack(">Q", reference_ts)
        + struct.pack(">Q", originate_ts)
        + struct.pack(">Q", receive_ts)
        + struct.pack(">Q", transmit_ts)
    )


def _ntp_ts(unix_seconds, fraction=0):
    """유닉스 초를 64비트 NTP timestamp 로."""
    return ((unix_seconds + NTP_UNIX_EPOCH_DELTA) << 32) | (fraction & 0xFFFFFFFF)


class FormatTests(unittest.TestCase):
    def test_format_ipv4(self):
        self.assertEqual(format_ipv4(bytes([10, 8, 0, 17])), "10.8.0.17")

    def test_format_ipv4_nonstandard_length(self):
        self.assertEqual(format_ipv4(b"\x01\x02"), "0102")


class NtpToUnixTests(unittest.TestCase):
    def test_zero_is_none(self):
        self.assertIsNone(ntp_to_unix(0))

    def test_known_conversion(self):
        # 유닉스 1_000_000_000 초 → NTP 로 인코딩 후 환산하면 같은 값.
        ts = _ntp_ts(1_000_000_000)
        self.assertEqual(ntp_to_unix(ts), 1_000_000_000.0)

    def test_fraction(self):
        ts = _ntp_ts(0, fraction=0x80000000)  # 0.5초
        self.assertAlmostEqual(ntp_to_unix(ts), 0.5, places=9)


class ParseNtpTests(unittest.TestCase):
    def test_server_round_trip(self):
        pkt = _ntp(leap=0, version=4, mode=MODE_SERVER, stratum=2, poll=10,
                   precision=-23, reference_id=bytes([129, 6, 15, 28]),
                   transmit_ts=_ntp_ts(1_500_000_000))
        msg = parse_ntp(pkt)
        self.assertIsNotNone(msg)
        self.assertEqual(msg.leap, 0)
        self.assertEqual(msg.version, 4)
        self.assertEqual(msg.mode, MODE_SERVER)
        self.assertEqual(msg.mode_name, "server")
        self.assertEqual(msg.stratum, 2)
        self.assertEqual(msg.poll, 10)
        self.assertEqual(msg.precision, -23)
        self.assertFalse(msg.is_amplification_mode)
        self.assertFalse(msg.unsynchronized)
        # stratum >= 2 → reference ID 는 상위 서버 IPv4.
        self.assertEqual(msg.reference_id_text, "129.6.15.28")
        self.assertEqual(msg.transmit_unix, 1_500_000_000.0)

    def test_signed_precision_negative(self):
        msg = parse_ntp(_ntp(precision=-29))
        self.assertEqual(msg.precision, -29)

    def test_client_mode(self):
        msg = parse_ntp(_ntp(mode=MODE_CLIENT))
        self.assertEqual(msg.mode_name, "client")
        self.assertFalse(msg.is_amplification_mode)


class AmplificationTests(unittest.TestCase):
    def test_private_mode_monlist(self):
        msg = parse_ntp(_ntp(mode=MODE_PRIVATE))
        self.assertEqual(msg.mode_name, "private")
        self.assertTrue(msg.is_amplification_mode)

    def test_control_mode(self):
        msg = parse_ntp(_ntp(mode=MODE_CONTROL))
        self.assertEqual(msg.mode_name, "control")
        self.assertTrue(msg.is_amplification_mode)


class ReferenceIdTests(unittest.TestCase):
    def test_stratum1_refclock_ascii(self):
        msg = parse_ntp(_ntp(stratum=1, reference_id=b"GPS\x00"))
        self.assertEqual(msg.reference_id_text, "GPS")

    def test_stratum0_kiss_code(self):
        msg = parse_ntp(_ntp(stratum=0, reference_id=b"DENY"))
        self.assertEqual(msg.reference_id_text, "DENY")

    def test_stratum1_nonascii_falls_back_to_hex(self):
        msg = parse_ntp(_ntp(stratum=1, reference_id=b"\x01\x02\x03\x04"))
        self.assertEqual(msg.reference_id_text, "01020304")

    def test_stratum2_is_ipv4(self):
        msg = parse_ntp(_ntp(stratum=3, reference_id=bytes([192, 168, 1, 1])))
        self.assertEqual(msg.reference_id_text, "192.168.1.1")


class LeapTests(unittest.TestCase):
    def test_unsynchronized(self):
        msg = parse_ntp(_ntp(leap=LI_UNSYNCHRONIZED))
        self.assertEqual(msg.leap, 3)
        self.assertTrue(msg.unsynchronized)


class TransmitUnixTests(unittest.TestCase):
    def test_unset_transmit_is_none(self):
        msg = parse_ntp(_ntp(transmit_ts=0))
        self.assertIsNone(msg.transmit_unix)


class OffsetAndRejectTests(unittest.TestCase):
    def test_offset_parsing(self):
        pkt = _ntp(mode=MODE_SERVER)
        msg = parse_ntp(b"\xaa\xbb" + pkt, offset=2)
        self.assertIsNotNone(msg)
        self.assertEqual(msg.mode, MODE_SERVER)

    def test_too_short_returns_none(self):
        self.assertIsNone(parse_ntp(b"\x1c" * (NTP_HEADER_SIZE - 1)))

    def test_mode_zero_reserved_returns_none(self):
        self.assertIsNone(parse_ntp(_ntp(mode=0)))

    def test_negative_offset_returns_none(self):
        self.assertIsNone(parse_ntp(_ntp(), offset=-1))


if __name__ == "__main__":
    unittest.main()
