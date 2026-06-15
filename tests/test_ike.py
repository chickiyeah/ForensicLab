"""forensiclab.ike 단위 테스트 (stdlib unittest)."""

import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from forensiclab.ike import (  # noqa: E402
    IkeMessage,
    IkePayload,
    looks_like_ike,
    parse_ike,
)


def _hdr(init_spi, resp_spi, next_payload, version, etype, flags, msg_id, length):
    """28바이트 ISAKMP 헤더 조립."""
    return (
        init_spi
        + resp_spi
        + bytes([next_payload, version, etype, flags])
        + struct.pack(">I", msg_id)
        + struct.pack(">I", length)
    )


def _payload(next_payload, body, critical=False):
    """4바이트 제네릭 헤더 + 본문 페이로드."""
    plen = 4 + len(body)
    crit = 0x80 if critical else 0x00
    return bytes([next_payload, crit]) + struct.pack(">H", plen) + body


INIT = bytes.fromhex("1122334455667788")
RESP = bytes.fromhex("99aabbccddeeff00")
ZERO = b"\x00" * 8


class GuardTests(unittest.TestCase):
    def test_non_bytes(self):
        self.assertIsNone(parse_ike(None))
        self.assertIsNone(parse_ike(12345))

    def test_too_short(self):
        self.assertIsNone(parse_ike(b"\x00" * 10))
        self.assertIsNone(parse_ike(b""))

    def test_bad_version(self):
        # 버전 major 9 는 IKE 아님.
        h = _hdr(INIT, RESP, 0, 0x90, 2, 0, 0, 28)
        self.assertIsNone(parse_ike(h))

    def test_zero_initiator_spi(self):
        # Initiator SPI 전부 0 은 비-IKE 오탐 가드.
        h = _hdr(ZERO, RESP, 0, 0x10, 2, 0, 0, 28)
        self.assertIsNone(parse_ike(h))

    def test_unknown_exchange_type(self):
        # IKEv1 에 교환 타입 99 는 없음.
        h = _hdr(INIT, RESP, 0, 0x10, 99, 0, 0, 28)
        self.assertIsNone(parse_ike(h))

    def test_length_below_header(self):
        h = _hdr(INIT, RESP, 0, 0x10, 2, 0, 0, 10)
        self.assertIsNone(parse_ike(h))

    def test_looks_like_ike(self):
        h = _hdr(INIT, RESP, 0, 0x10, 2, 0, 0, 28)
        self.assertTrue(looks_like_ike(h))
        self.assertFalse(looks_like_ike(b"not ike at all....."))


class HeaderTests(unittest.TestCase):
    def test_ikev1_main_mode(self):
        h = _hdr(INIT, RESP, 0, 0x10, 2, 0, 0, 28)
        msg = parse_ike(h)
        self.assertIsInstance(msg, IkeMessage)
        self.assertTrue(msg.is_ikev1)
        self.assertFalse(msg.is_ikev2)
        self.assertEqual(msg.version_major, 1)
        self.assertEqual(msg.version_minor, 0)
        self.assertEqual(msg.exchange, "IDENTITY_PROTECTION")
        self.assertTrue(msg.is_main_mode)
        self.assertFalse(msg.is_aggressive_mode)
        self.assertEqual(msg.initiator_spi, "1122334455667788")
        self.assertEqual(msg.responder_spi, "99aabbccddeeff00")

    def test_ikev1_aggressive_mode(self):
        # ET=4 = Aggressive Mode (평문 ID·해시 노출).
        h = _hdr(INIT, RESP, 1, 0x10, 4, 0, 0, 28)
        msg = parse_ike(h)
        self.assertTrue(msg.is_aggressive_mode)
        self.assertFalse(msg.is_main_mode)
        self.assertEqual(msg.exchange, "AGGRESSIVE")

    def test_initial_responder_spi_zero(self):
        h = _hdr(INIT, ZERO, 0, 0x20, 34, 0x08, 0, 28)
        msg = parse_ike(h)
        self.assertTrue(msg.is_initial)

    def test_not_initial(self):
        h = _hdr(INIT, RESP, 0, 0x20, 34, 0x08, 0, 28)
        msg = parse_ike(h)
        self.assertFalse(msg.is_initial)

    def test_ikev2_flags(self):
        # IKEv2 IKE_SA_INIT, Initiator 플래그.
        h = _hdr(INIT, ZERO, 33, 0x20, 34, 0x08, 0, 28)
        msg = parse_ike(h)
        self.assertTrue(msg.is_ikev2)
        self.assertEqual(msg.exchange, "IKE_SA_INIT")
        self.assertTrue(msg.is_initiator)
        self.assertFalse(msg.is_response)

    def test_ikev2_response_flag(self):
        h = _hdr(INIT, RESP, 33, 0x20, 34, 0x20, 0, 28)
        msg = parse_ike(h)
        self.assertTrue(msg.is_response)
        self.assertFalse(msg.is_initiator)


class PayloadTests(unittest.TestCase):
    def test_vendor_id_payload(self):
        vid_body = bytes.fromhex("4048b7d56ebce88525e7de7f00d6c2d3")
        body = _payload(0, vid_body)  # next=0 종료
        h = _hdr(INIT, RESP, 13, 0x10, 5, 0, 0, 28 + len(body))  # 13=VENDOR_ID
        msg = parse_ike(h + body)
        self.assertEqual(len(msg.payloads), 1)
        self.assertEqual(msg.payloads[0].name, "VENDOR_ID")
        self.assertEqual(msg.vendor_ids, [vid_body.hex()])
        self.assertEqual(msg.payload_types, ["VENDOR_ID"])

    def test_payload_chain(self):
        # SA(1) -> VENDOR_ID(13) -> NONE
        vid = _payload(0, b"\xde\xad\xbe\xef")
        sa = _payload(13, b"\x00\x00\x00\x01")  # next=13
        body = sa + vid
        h = _hdr(INIT, RESP, 1, 0x10, 2, 0, 0, 28 + len(body))  # first=SA
        msg = parse_ike(h + body)
        self.assertEqual(msg.first_payload, "SA")
        self.assertEqual(msg.payload_types, ["SA", "VENDOR_ID"])
        self.assertEqual(msg.vendor_ids, ["deadbeef"])

    def test_notify_ikev2(self):
        # IKEv2 Notify: Protocol-ID(1)·SPI Size(1)·Notify Type(2)·data
        nbody = bytes([0, 0]) + struct.pack(">H", 14)  # 14 = NO_PROPOSAL_CHOSEN
        body = _payload(0, nbody)
        h = _hdr(INIT, RESP, 41, 0x20, 37, 0x20, 1, 28 + len(body))  # 41=NOTIFY
        msg = parse_ike(h + body)
        self.assertEqual(msg.payloads[0].name, "NOTIFY")
        self.assertEqual(msg.notify_types, [14])

    def test_notify_ikev1(self):
        # IKEv1 Notify: DOI(4)·Protocol-ID(1)·SPI Size(1)·Notify Type(2)
        nbody = b"\x00\x00\x00\x01" + bytes([1, 0]) + struct.pack(">H", 24)
        body = _payload(0, nbody)
        h = _hdr(INIT, RESP, 11, 0x10, 5, 0, 1, 28 + len(body))  # 11=NOTIFY(v1)
        msg = parse_ike(h + body)
        self.assertEqual(msg.payloads[0].name, "NOTIFY")
        self.assertEqual(msg.notify_types, [24])

    def test_critical_bit(self):
        body = _payload(0, b"\x01\x02\x03\x04", critical=True)
        h = _hdr(INIT, RESP, 43, 0x20, 34, 0x08, 0, 28 + len(body))  # 43=VID(v2)
        msg = parse_ike(h + body)
        self.assertTrue(msg.payloads[0].critical)


class EncryptionTests(unittest.TestCase):
    def test_ikev1_encryption_flag_skips_payloads(self):
        # IKEv1 Encryption 플래그 → 페이로드 풀지 않음.
        h = _hdr(INIT, RESP, 8, 0x10, 32, 0x01, 5, 60)  # Quick Mode, encrypted
        garbage = b"\xff" * 32
        msg = parse_ike(h + garbage)
        self.assertTrue(msg.encrypted)
        self.assertEqual(msg.payloads, [])

    def test_ikev2_sk_stops_chain(self):
        # IKEv2 SK(46) 도달 시 암호문으로 보고 멈춤.
        sk = _payload(0, b"\x00" * 16)
        h = _hdr(INIT, RESP, 46, 0x20, 35, 0x08, 1, 28 + len(sk))  # first=SK
        msg = parse_ike(h + sk)
        self.assertTrue(msg.encrypted)
        self.assertEqual(msg.payload_types, ["SK"])


class NatTTests(unittest.TestCase):
    def test_non_esp_marker(self):
        # UDP 4500: 4바이트 0 비-ESP 마커 선행.
        h = _hdr(INIT, RESP, 0, 0x20, 34, 0x08, 0, 28)
        msg = parse_ike(b"\x00\x00\x00\x00" + h)
        self.assertTrue(msg.has_non_esp_marker)
        self.assertEqual(msg.initiator_spi, "1122334455667788")


class RobustnessTests(unittest.TestCase):
    def test_truncated_payload_chain(self):
        # 길이는 큰 값인데 실제 버퍼는 짧음 — 받은 데까지만.
        sa = _payload(13, b"\x00\x00\x00\x01")
        h = _hdr(INIT, RESP, 1, 0x10, 2, 0, 0, 200)  # length 과장
        msg = parse_ike(h + sa)  # VID 페이로드는 없음
        self.assertEqual(msg.payload_types, ["SA"])

    def test_zero_length_payload_no_loop(self):
        # 페이로드 길이 0 은 무한 루프 방지로 멈춤.
        bad = bytes([13, 0]) + struct.pack(">H", 0)  # plen=0
        h = _hdr(INIT, RESP, 1, 0x10, 2, 0, 0, 28 + len(bad))
        msg = parse_ike(h + bad)
        self.assertEqual(msg.payloads, [])

    def test_offset(self):
        h = _hdr(INIT, RESP, 0, 0x10, 2, 0, 0, 28)
        msg = parse_ike(b"\xaa\xbb\xcc" + h, offset=3)
        self.assertEqual(msg.initiator_spi, "1122334455667788")


if __name__ == "__main__":
    unittest.main()
