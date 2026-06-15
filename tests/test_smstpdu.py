"""forensiclab.smstpdu 단위 테스트 (stdlib unittest)."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from forensiclab.smstpdu import (  # noqa: E402
    SmsAddress,
    SmsTpdu,
    decode_gsm7,
    decode_scts,
    decode_sms_address,
    parse_sms_tpdu,
)


def _pack_septets(septets):
    """septet(0..0x7F) 리스트를 GSM 7비트 팩 옥텟열로 인코드(언팩의 역)."""
    out = bytearray()
    val = 0
    bits = 0
    for s in septets:
        val |= (s & 0x7F) << bits
        bits += 7
        while bits >= 8:
            out.append(val & 0xFF)
            val >>= 8
            bits -= 8
    if bits > 0:
        out.append(val & 0xFF)
    return bytes(out)


def _gsm7_pack(text):
    """ASCII 문자열(GSM7 기본 알파벳과 코드포인트 일치 영역)을 팩한다."""
    return _pack_septets([ord(c) for c in text])


def _swap_bcd(digits):
    """전화번호 숫자열을 swapped-BCD(하위 nibble 먼저, 홀수면 0xF) 옥텟열로."""
    out = bytearray()
    pairs = [digits[i:i + 2] for i in range(0, len(digits), 2)]
    for pair in pairs:
        lo = int(pair[0])
        hi = int(pair[1]) if len(pair) == 2 else 0x0F
        out.append((hi << 4) | lo)
    return bytes(out)


def _scts(yy, mm, dd, hh, mi, ss, tz_byte):
    """7옥텟 TP-SCTS(반옥텟 스왑 BCD)을 짠다."""
    def swap(v):
        return ((v % 10) << 4) | (v // 10)
    return bytes([swap(yy), swap(mm), swap(dd), swap(hh), swap(mi), swap(ss), tz_byte])


# 공통 주소: 국제 ISDN "1234" → 길이4 + TOA 0x91 + swapped BCD.
_OA_ADDR = bytes([0x04, 0x91]) + _swap_bcd("1234")


class Gsm7Tests(unittest.TestCase):
    def test_basic_roundtrip(self):
        packed = _gsm7_pack("hello")
        self.assertEqual(decode_gsm7(packed, 5), "hello")

    def test_extension_escape_euro(self):
        # 0x1B 0x65 → €.
        packed = _pack_septets([0x1B, 0x65])
        self.assertEqual(decode_gsm7(packed, 2), "€")

    def test_skip_septets(self):
        packed = _gsm7_pack("ABhello")
        self.assertEqual(decode_gsm7(packed, 7, skip_septets=2), "hello")


class SctsTests(unittest.TestCase):
    def test_basic(self):
        raw = _scts(21, 3, 14, 15, 9, 26, 0x00)
        self.assertEqual(decode_scts(raw), "21-03-14 15:09:26 +00:00")

    def test_negative_tz(self):
        # TZ -05:00 = 20 quarters; bit3(0x08)=부호. 20 → swapped BCD 0x02, sign on.
        raw = _scts(21, 3, 14, 15, 9, 26, 0x02 | 0x08)
        self.assertEqual(decode_scts(raw), "21-03-14 15:09:26 -05:00")

    def test_truncated(self):
        self.assertIsNone(decode_scts(b"\x12\x30\x41"))


class AddressTests(unittest.TestCase):
    def test_international_digits(self):
        res = decode_sms_address(_OA_ADDR, 0, len(_OA_ADDR))
        self.assertIsNotNone(res)
        addr, nxt = res
        self.assertIsInstance(addr, SmsAddress)
        self.assertEqual(addr.digits, "1234")
        self.assertTrue(addr.is_international)
        self.assertFalse(addr.is_alphanumeric)
        self.assertEqual(nxt, len(_OA_ADDR))

    def test_alphanumeric(self):
        # TON=5(alphanumeric, 0x50|0xD0 ext). 값은 GSM7 팩.
        packed = _gsm7_pack("Bank")
        # 길이는 반옥텟 수(자릿수) — alphanumeric 은 4*8/7≈4 septet, raw 길이 기반.
        addr_len = len(packed) * 2
        data = bytes([addr_len, 0xD0]) + packed
        res = decode_sms_address(data, 0, len(data))
        self.assertIsNotNone(res)
        addr, _ = res
        self.assertTrue(addr.is_alphanumeric)
        self.assertTrue(addr.digits.startswith("Bank"))

    def test_truncated_returns_none(self):
        self.assertIsNone(decode_sms_address(b"\x04", 0, 1))


class DeliverTests(unittest.TestCase):
    def setUp(self):
        ud = _gsm7_pack("hello")
        self.pdu = (
            bytes([0x00])           # TP-MTI=0 deliver, no flags.
            + _OA_ADDR              # TP-OA.
            + bytes([0x00, 0x00])   # TP-PID, TP-DCS(gsm7).
            + _scts(21, 3, 14, 15, 9, 26, 0x00)  # TP-SCTS.
            + bytes([5])            # TP-UDL = 5 septets.
            + ud                    # TP-UD.
        )

    def test_parse(self):
        t = parse_sms_tpdu(self.pdu)
        self.assertIsInstance(t, SmsTpdu)
        self.assertTrue(t.is_deliver)
        self.assertEqual(t.message_type, "sms-deliver")
        self.assertEqual(t.originating_address.digits, "1234")
        self.assertIsNone(t.destination_address)
        self.assertEqual(t.encoding, "gsm7")
        self.assertEqual(t.text, "hello")
        self.assertEqual(t.timestamp, "21-03-14 15:09:26 +00:00")
        self.assertEqual(t.target_number, "1234")

    def test_truncated_after_address(self):
        # 주소까지만 — 나머지 필드는 None, OA 는 채워짐.
        t = parse_sms_tpdu(self.pdu[: 1 + len(_OA_ADDR)])
        self.assertIsNotNone(t)
        self.assertEqual(t.originating_address.digits, "1234")
        self.assertIsNone(t.timestamp)
        self.assertIsNone(t.text)


class SubmitTests(unittest.TestCase):
    def test_ucs2_body(self):
        body = "Hi€".encode("utf-16-be")
        pdu = (
            bytes([0x01, 0x00])     # TP-MTI=1 submit (VPF=0), TP-MR=0.
            + _OA_ADDR              # TP-DA.
            + bytes([0x00, 0x08])   # TP-PID, TP-DCS(UCS2).
            + bytes([len(body)])    # TP-UDL = octets.
            + body
        )
        t = parse_sms_tpdu(pdu)
        self.assertTrue(t.is_submit)
        self.assertEqual(t.message_reference, 0)
        self.assertEqual(t.destination_address.digits, "1234")
        self.assertEqual(t.encoding, "ucs2")
        self.assertEqual(t.text, "Hi€")
        self.assertEqual(t.target_number, "1234")


class UdhTests(unittest.TestCase):
    def test_concatenated_8bit(self):
        # UDHI 세팅, UDH=연결 메시지(IEI 0x00, len3) + 8bit 본문.
        udh = bytes([0x05, 0x00, 0x03, 0xAB, 0x02, 0x01])  # UDHL=5.
        payload = b"\xde\xad"
        ud = udh + payload
        pdu = (
            bytes([0x40])           # deliver + UDHI(bit6).
            + _OA_ADDR
            + bytes([0x00, 0x04])   # PID, DCS=8bit.
            + _scts(21, 3, 14, 15, 9, 26, 0x00)
            + bytes([len(ud)])      # UDL(octets for 8bit).
            + ud
        )
        t = parse_sms_tpdu(pdu)
        self.assertTrue(t.udh_present)
        self.assertEqual(t.user_data_header, bytes([0x00, 0x03, 0xAB, 0x02, 0x01]))
        self.assertTrue(t.is_concatenated)
        self.assertEqual(t.text, payload.decode("latin-1"))


class GuardTests(unittest.TestCase):
    def test_empty(self):
        self.assertIsNone(parse_sms_tpdu(b""))

    def test_offset_out_of_range(self):
        self.assertIsNone(parse_sms_tpdu(b"\x00", offset=5))

    def test_status_report_header_only(self):
        # MTI=2 status-report: 헤더 플래그만, 본문 비움.
        t = parse_sms_tpdu(bytes([0x02, 0xFF, 0xFF]))
        self.assertIsNotNone(t)
        self.assertEqual(t.mti, 2)
        self.assertEqual(t.message_type, "sms-status-report")
        self.assertIsNone(t.text)


if __name__ == "__main__":
    unittest.main()
