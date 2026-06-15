"""forensiclab.sdp 단위 테스트 (stdlib unittest)."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from forensiclab.sdp import (  # noqa: E402
    SdpMedia,
    SdpSession,
    parse,
)


def _sdp(*lines: str) -> bytes:
    """CRLF 로 줄을 잇고 바이트로(SIP 바디 와이어 형식)."""
    return ("\r\n".join(lines) + "\r\n").encode("utf-8")


# RFC 4566 예제에 가까운 평문 음성+영상 통화 오퍼.
_OFFER = _sdp(
    "v=0",
    "o=alice 2890844526 2890844526 IN IP4 192.168.1.50",
    "s=Call from Alice",
    "c=IN IP4 192.168.1.50",
    "t=0 0",
    "m=audio 49170 RTP/AVP 0 8 97",
    "a=rtpmap:97 iLBC/8000",
    "a=sendrecv",
    "m=video 51372 RTP/AVP 31",
    "a=rtpmap:31 H261/90000",
)


class ParseBasicTests(unittest.TestCase):
    def test_session_fields(self):
        s = parse(_OFFER)
        self.assertIsInstance(s, SdpSession)
        self.assertEqual(s.version, "0")
        self.assertEqual(s.session_name, "Call from Alice")
        self.assertEqual(s.origin_username, "alice")
        self.assertEqual(s.origin_address, "192.168.1.50")
        self.assertEqual(s.connection_address, "192.168.1.50")

    def test_accepts_str_input(self):
        s = parse(_OFFER.decode("ascii"))
        self.assertIsInstance(s, SdpSession)
        self.assertEqual(s.version, "0")

    def test_two_media_blocks(self):
        s = parse(_OFFER)
        self.assertEqual(len(s.media), 2)
        a, v = s.media
        self.assertTrue(a.is_audio)
        self.assertTrue(v.is_video)
        self.assertEqual(a.port, "49170")
        self.assertEqual(v.port, "51372")

    def test_media_formats_and_protocol(self):
        s = parse(_OFFER)
        a = s.media[0]
        self.assertEqual(a.protocol, "RTP/AVP")
        self.assertEqual(a.formats, ["0", "8", "97"])


class RtpmapTests(unittest.TestCase):
    def test_static_payload_resolved(self):
        # 0/8 은 rtpmap 없이도 정적 표(PCMU/PCMA)로 채워진다.
        s = parse(_OFFER)
        rm = s.media[0].rtpmap
        self.assertEqual(rm[0], "PCMU/8000")
        self.assertEqual(rm[8], "PCMA/8000")

    def test_dynamic_payload_from_rtpmap(self):
        s = parse(_OFFER)
        self.assertEqual(s.media[0].rtpmap[97], "iLBC/8000")
        self.assertEqual(s.media[1].rtpmap[31], "H261/90000")


class AttributeTests(unittest.TestCase):
    def test_direction_default_and_explicit(self):
        s = parse(_OFFER)
        self.assertEqual(s.media[0].direction, "sendrecv")  # 명시
        self.assertEqual(s.media[1].direction, "sendrecv")  # 기본값

    def test_explicit_sendonly(self):
        s = parse(_sdp(
            "v=0",
            "o=- 1 1 IN IP4 10.0.0.1",
            "m=audio 5000 RTP/AVP 0",
            "a=sendonly",
        ))
        self.assertEqual(s.media[0].direction, "sendonly")

    def test_flag_attribute(self):
        s = parse(_sdp(
            "v=0",
            "o=- 1 1 IN IP4 10.0.0.1",
            "m=audio 5000 RTP/AVP 0",
            "a=rtcp-mux",
        ))
        self.assertTrue(s.media[0].has_flag("rtcp-mux"))


class EncryptionTests(unittest.TestCase):
    def test_cleartext_rtp_detected(self):
        s = parse(_OFFER)
        self.assertFalse(s.is_encrypted)
        self.assertTrue(s.has_cleartext_media)
        self.assertFalse(s.media[0].is_encrypted)

    def test_srtp_savp_encrypted(self):
        s = parse(_sdp(
            "v=0",
            "o=- 1 1 IN IP4 10.0.0.1",
            "m=audio 5000 RTP/SAVP 0",
            "a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:WVNfX19zYWx0",
        ))
        self.assertTrue(s.media[0].is_encrypted)
        self.assertTrue(s.is_encrypted)
        self.assertFalse(s.has_cleartext_media)

    def test_crypto_key_material_exposed(self):
        s = parse(_sdp(
            "v=0",
            "o=- 1 1 IN IP4 10.0.0.1",
            "m=audio 5000 RTP/SAVP 0",
            "a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:SECRETKEYMATERIAL",
        ))
        self.assertEqual(len(s.all_crypto), 1)
        self.assertIn("SECRETKEYMATERIAL", s.all_crypto[0])

    def test_dtls_fingerprint(self):
        s = parse(_sdp(
            "v=0",
            "o=- 1 1 IN IP4 10.0.0.1",
            "m=audio 5000 UDP/TLS/RTP/SAVP 0",
            "a=fingerprint:sha-256 AB:CD:EF",
        ))
        self.assertTrue(s.media[0].is_encrypted)
        self.assertEqual(s.media[0].fingerprint, "sha-256 AB:CD:EF")


class IceAndAddressTests(unittest.TestCase):
    def test_ice_candidates_leak_ips(self):
        s = parse(_sdp(
            "v=0",
            "o=- 1 1 IN IP4 10.0.0.1",
            "m=audio 5000 RTP/AVP 0",
            "a=candidate:1 1 UDP 2130706431 192.168.1.50 5000 typ host",
            "a=candidate:2 1 UDP 1694498815 203.0.113.7 54321 typ srflx",
        ))
        cands = s.all_candidates
        self.assertEqual(len(cands), 2)
        self.assertIn("192.168.1.50", cands[0])
        self.assertIn("203.0.113.7", cands[1])

    def test_media_level_connection_overrides_session(self):
        s = parse(_sdp(
            "v=0",
            "o=- 1 1 IN IP4 10.0.0.1",
            "c=IN IP4 10.0.0.1",
            "m=audio 5000 RTP/AVP 0",
            "c=IN IP4 198.51.100.9",
        ))
        self.assertEqual(s.media[0].connection_address, "198.51.100.9")
        self.assertEqual(s.media_addresses, ["198.51.100.9"])

    def test_multicast_ttl_stripped(self):
        s = parse(_sdp(
            "v=0",
            "o=- 1 1 IN IP4 10.0.0.1",
            "c=IN IP4 224.2.36.42/127",
        ))
        self.assertEqual(s.connection_address, "224.2.36.42")


class RejectionTests(unittest.TestCase):
    def test_empty(self):
        self.assertIsNone(parse(b""))
        self.assertIsNone(parse(""))

    def test_non_sdp_first_line_rejected(self):
        self.assertIsNone(parse(b"GET / HTTP/1.1\r\nHost: x\r\n"))

    def test_version_must_be_numeric(self):
        self.assertIsNone(parse(b"v=abc\r\no=- 1 1 IN IP4 x\r\n"))

    def test_non_bytes_non_str_rejected(self):
        self.assertIsNone(parse(12345))

    def test_garbage_lines_skipped(self):
        # 타입이 한 글자가 아닌 줄은 조용히 건너뛰고 나머지를 채운다.
        s = parse(_sdp(
            "v=0",
            "this is not a valid sdp line",
            "o=- 1 1 IN IP4 10.0.0.1",
            "m=audio 5000 RTP/AVP 0",
        ))
        self.assertIsNotNone(s)
        self.assertEqual(s.origin_address, "10.0.0.1")
        self.assertEqual(len(s.media), 1)

    def test_lf_only_line_endings(self):
        raw = "v=0\no=- 1 1 IN IP4 10.0.0.1\nm=audio 5000 RTP/AVP 0\n".encode()
        s = parse(raw)
        self.assertIsNotNone(s)
        self.assertEqual(len(s.media), 1)


if __name__ == "__main__":
    unittest.main()
