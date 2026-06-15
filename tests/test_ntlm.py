"""forensiclab.ntlm 단위 테스트 (stdlib unittest)."""

import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from forensiclab.ntlm import (  # noqa: E402
    AV_DNS_DOMAIN_NAME,
    AV_EOL,
    AV_NB_COMPUTER_NAME,
    AV_NB_DOMAIN_NAME,
    NEGOTIATE_NTLM,
    NEGOTIATE_SEAL,
    NEGOTIATE_SIGN,
    NEGOTIATE_UNICODE,
    NTLMSSP_SIG,
    NTLM_AUTHENTICATE,
    NTLM_CHALLENGE,
    NTLM_NEGOTIATE,
    NTLMMessage,
    find_ntlm,
    netntlmv2,
    parse_ntlm,
)


# --- 최소 NTLMSSP 인코더(테스트 픽스처 전용) ---------------------------

def _negotiate(flags=NEGOTIATE_UNICODE | NEGOTIATE_NTLM):
    msg = bytearray()
    msg += NTLMSSP_SIG
    msg += struct.pack("<I", NTLM_NEGOTIATE)
    msg += struct.pack("<I", flags)
    msg += struct.pack("<HHI", 0, 0, 0)   # DomainName
    msg += struct.pack("<HHI", 0, 0, 0)   # Workstation
    return bytes(msg)


def _av_pairs(pairs):
    out = bytearray()
    for av_id, value in pairs:
        out += struct.pack("<HH", av_id, len(value))
        out += value
    out += struct.pack("<HH", AV_EOL, 0)
    return bytes(out)


def _challenge(target_name, server_challenge, av=None,
               flags=NEGOTIATE_UNICODE | NEGOTIATE_NTLM):
    tn = target_name.encode("utf-16-le")
    av_blob = _av_pairs(av) if av else b""
    header_len = 48
    off_tn = header_len
    off_ti = off_tn + len(tn)
    msg = bytearray()
    msg += NTLMSSP_SIG                                   # 0
    msg += struct.pack("<I", NTLM_CHALLENGE)             # 8
    msg += struct.pack("<HHI", len(tn), len(tn), off_tn)  # 12 TargetName
    msg += struct.pack("<I", flags)                      # 20 flags
    msg += server_challenge                              # 24 (8 bytes)
    msg += struct.pack("<Q", 0)                          # 32 Reserved
    msg += struct.pack("<HHI", len(av_blob), len(av_blob), off_ti)  # 40 TI
    assert len(msg) == header_len
    msg += tn + av_blob
    return bytes(msg)


def _authenticate(domain, user, workstation, nt_response=b"",
                  lm_response=b"", flags=NEGOTIATE_UNICODE):
    enc = "utf-16-le" if flags & NEGOTIATE_UNICODE else "latin-1"
    d = domain.encode(enc)
    u = user.encode(enc)
    w = workstation.encode(enc)
    header_len = 8 + 4 + 6 * 8 + 4  # = 64
    off_lm = header_len
    off_nt = off_lm + len(lm_response)
    off_d = off_nt + len(nt_response)
    off_u = off_d + len(d)
    off_w = off_u + len(u)
    msg = bytearray()
    msg += NTLMSSP_SIG
    msg += struct.pack("<I", NTLM_AUTHENTICATE)
    msg += struct.pack("<HHI", len(lm_response), len(lm_response), off_lm)
    msg += struct.pack("<HHI", len(nt_response), len(nt_response), off_nt)
    msg += struct.pack("<HHI", len(d), len(d), off_d)
    msg += struct.pack("<HHI", len(u), len(u), off_u)
    msg += struct.pack("<HHI", len(w), len(w), off_w)
    msg += struct.pack("<HHI", 0, 0, header_len)   # SessionKey
    msg += struct.pack("<I", flags)
    assert len(msg) == header_len
    msg += lm_response + nt_response + d + u + w
    return bytes(msg)


class ParseBasicsTest(unittest.TestCase):
    def test_negotiate(self):
        m = parse_ntlm(_negotiate())
        self.assertIsNotNone(m)
        self.assertTrue(m.is_negotiate)
        self.assertEqual(m.type_name, "NEGOTIATE")
        self.assertEqual(m.message_type, NTLM_NEGOTIATE)

    def test_bad_signature_returns_none(self):
        self.assertIsNone(parse_ntlm(b"NOTNTLM\x00" + b"\x00" * 20))

    def test_unknown_type_returns_none(self):
        bad = NTLMSSP_SIG + struct.pack("<I", 9) + b"\x00" * 16
        self.assertIsNone(parse_ntlm(bad))

    def test_too_short_returns_none(self):
        self.assertIsNone(parse_ntlm(b"NTLM"))
        self.assertIsNone(parse_ntlm(b""))

    def test_offset_out_of_range(self):
        self.assertIsNone(parse_ntlm(_negotiate(), offset=999))
        self.assertIsNone(parse_ntlm(_negotiate(), offset=-1))


class ChallengeTest(unittest.TestCase):
    def test_server_challenge_and_target(self):
        chal = bytes(range(8))  # 00..07
        m = parse_ntlm(_challenge("CORP", chal))
        self.assertTrue(m.is_challenge)
        self.assertEqual(m.server_challenge, chal)
        self.assertEqual(m.target_name, "CORP")

    def test_target_info_av_pairs(self):
        av = [
            (AV_NB_DOMAIN_NAME, "CORP".encode("utf-16-le")),
            (AV_NB_COMPUTER_NAME, "DC01".encode("utf-16-le")),
            (AV_DNS_DOMAIN_NAME, "corp.local".encode("utf-16-le")),
        ]
        m = parse_ntlm(_challenge("CORP", b"\x11" * 8, av=av))
        ti = m.target_info_map
        self.assertEqual(ti["nb_domain"], "CORP")
        self.assertEqual(ti["nb_computer"], "DC01")
        self.assertEqual(ti["dns_domain"], "corp.local")

    def test_flag_helpers(self):
        flags = NEGOTIATE_UNICODE | NEGOTIATE_SIGN | NEGOTIATE_SEAL
        m = parse_ntlm(_challenge("X", b"\x00" * 8, flags=flags))
        self.assertTrue(m.signing_negotiated)
        self.assertTrue(m.sealing_negotiated)
        self.assertIn("SIGN", m.flag_names)
        self.assertIn("SEAL", m.flag_names)

    def test_no_signing(self):
        m = parse_ntlm(_challenge("X", b"\x00" * 8, flags=NEGOTIATE_UNICODE))
        self.assertFalse(m.signing_negotiated)
        self.assertFalse(m.sealing_negotiated)


class AuthenticateTest(unittest.TestCase):
    def test_account_extraction(self):
        m = parse_ntlm(_authenticate("CORP", "alice", "WS01"))
        self.assertTrue(m.is_authenticate)
        self.assertEqual(m.domain, "CORP")
        self.assertEqual(m.user, "alice")
        self.assertEqual(m.workstation, "WS01")
        self.assertEqual(m.account, "CORP\\alice")

    def test_account_no_domain(self):
        m = parse_ntlm(_authenticate("", "bob", "WS"))
        self.assertEqual(m.account, "bob")

    def test_oem_encoding(self):
        m = parse_ntlm(_authenticate("CORP", "carol", "WS",
                                     flags=0))  # OEM(no UNICODE)
        self.assertEqual(m.user, "carol")
        self.assertEqual(m.domain, "CORP")

    def test_null_session(self):
        m = parse_ntlm(_authenticate("", "", ""))
        self.assertTrue(m.is_null_session)

    def test_not_null_when_user_present(self):
        m = parse_ntlm(_authenticate("D", "u", "w", nt_response=b"\x01" * 24))
        self.assertFalse(m.is_null_session)

    def test_ntlmv2_detection(self):
        # NTLMv2 응답: NTProofStr16 + blob > 24바이트.
        m2 = parse_ntlm(_authenticate("D", "u", "w",
                                      nt_response=b"\xaa" * 16 + b"\xbb" * 40))
        self.assertTrue(m2.is_ntlmv2)

    def test_ntlmv1_detection(self):
        # NTLMv1 응답은 정확히 24바이트.
        m1 = parse_ntlm(_authenticate("D", "u", "w",
                                      nt_response=b"\xcc" * 24))
        self.assertFalse(m1.is_ntlmv2)

    def test_is_ntlmv2_none_for_non_auth(self):
        m = parse_ntlm(_negotiate())
        self.assertIsNone(m.is_ntlmv2)


class NetNTLMv2Test(unittest.TestCase):
    def test_crackable_hash_format(self):
        srvchal = bytes.fromhex("1122334455667788")
        ntproof = b"\xaa" * 16
        blob = b"\x01\x01" + b"\xbb" * 30
        auth = parse_ntlm(_authenticate("CORP", "alice", "WS",
                                        nt_response=ntproof + blob))
        h = netntlmv2(auth, srvchal)
        self.assertIsNotNone(h)
        parts = h.split(":")
        self.assertEqual(parts[0], "alice")
        self.assertEqual(parts[1], "")          # empty (user::domain)
        self.assertEqual(parts[2], "CORP")
        self.assertEqual(parts[3], "1122334455667788")
        self.assertEqual(parts[4], ntproof.hex())
        self.assertEqual(parts[5], blob.hex())

    def test_rejects_ntlmv1(self):
        auth = parse_ntlm(_authenticate("D", "u", "w",
                                        nt_response=b"\xcc" * 24))
        self.assertIsNone(netntlmv2(auth, b"\x00" * 8))

    def test_rejects_bad_challenge_length(self):
        auth = parse_ntlm(_authenticate("D", "u", "w",
                                        nt_response=b"\xaa" * 40))
        self.assertIsNone(netntlmv2(auth, b"\x00" * 4))

    def test_rejects_non_authenticate(self):
        m = parse_ntlm(_challenge("X", b"\x00" * 8))
        self.assertIsNone(netntlmv2(m, b"\x00" * 8))


class FindNtlmTest(unittest.TestCase):
    def test_finds_embedded_signature(self):
        wrapper = b"\x60\x82\x00\x00 SPNEGO junk " + _authenticate(
            "CORP", "dave", "WS")
        m = find_ntlm(wrapper)
        self.assertIsNotNone(m)
        self.assertEqual(m.user, "dave")

    def test_not_found(self):
        self.assertIsNone(find_ntlm(b"no ntlm here at all"))

    def test_negative_offset(self):
        self.assertIsNone(find_ntlm(_negotiate(), offset=-5))


if __name__ == "__main__":
    unittest.main()
