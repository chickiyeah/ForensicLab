"""forensiclab.smb 단위 테스트 (stdlib unittest)."""

import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from forensiclab.smb import (  # noqa: E402
    CMD_NEGOTIATE,
    CMD_SESSION_SETUP,
    CMD_TREE_CONNECT,
    DIALECT_2_0_2,
    DIALECT_3_0,
    DIALECT_3_1_1,
    DIALECT_SMB1_FALLBACK,
    FLAGS_SERVER_TO_REDIR,
    NTLM_AUTHENTICATE,
    NTLM_NEGOTIATE,
    SIGNING_ENABLED,
    SIGNING_REQUIRED,
    SMB1_MAGIC,
    SMB2_MAGIC,
    SMBMessage,
    parse_smb,
)


# --- 최소 SMB2 인코더(테스트 픽스처 전용) -------------------------------

def _smb2_header(command, flags=0, status=0, message_id=1,
                 session_id=0, tree_id=0):
    """64바이트 SMB2 sync 헤더."""
    h = bytearray(64)
    h[0:4] = SMB2_MAGIC
    struct.pack_into("<H", h, 4, 64)        # StructureSize
    struct.pack_into("<H", h, 6, 0)         # CreditCharge
    struct.pack_into("<I", h, 8, status)    # Status
    struct.pack_into("<H", h, 12, command)  # Command
    struct.pack_into("<H", h, 14, 0)        # Credits
    struct.pack_into("<I", h, 16, flags)    # Flags
    struct.pack_into("<I", h, 20, 0)        # NextCommand
    struct.pack_into("<Q", h, 24, message_id)
    struct.pack_into("<I", h, 36, tree_id)  # TreeId
    struct.pack_into("<Q", h, 40, session_id)
    return bytes(h)


def _transport(payload):
    """직접 SMB(445) 4바이트 전송 헤더를 붙인다."""
    return b"\x00" + len(payload).to_bytes(3, "big") + payload


def _negotiate_request(dialects, security_mode=SIGNING_ENABLED):
    body = bytearray(36)
    struct.pack_into("<H", body, 0, 36)               # StructureSize
    struct.pack_into("<H", body, 2, len(dialects))    # DialectCount
    struct.pack_into("<H", body, 4, security_mode)    # SecurityMode
    for d in dialects:
        body += struct.pack("<H", d)
    return _smb2_header(CMD_NEGOTIATE) + bytes(body)


def _ntlm_authenticate(domain, user, workstation, unicode_on=True):
    """NTLMSSP AUTHENTICATE(타입 3) 메시지."""
    enc = "utf-16-le" if unicode_on else "latin-1"
    d = domain.encode(enc)
    u = user.encode(enc)
    w = workstation.encode(enc)
    # 고정 헤더 64바이트(Signature8 + Type4 + 6*8필드 + flags4), payload 뒤따름.
    header_len = 8 + 4 + 8 * 6 + 4  # = 72
    payload = d + u + w
    off_d = header_len
    off_u = off_d + len(d)
    off_w = off_u + len(u)
    msg = bytearray()
    msg += b"NTLMSSP\x00"
    msg += struct.pack("<I", NTLM_AUTHENTICATE)
    msg += struct.pack("<HHI", 0, 0, header_len)               # LmChallenge
    msg += struct.pack("<HHI", 0, 0, header_len)               # NtChallenge
    msg += struct.pack("<HHI", len(d), len(d), off_d)          # DomainName
    msg += struct.pack("<HHI", len(u), len(u), off_u)          # UserName
    msg += struct.pack("<HHI", len(w), len(w), off_w)          # Workstation
    msg += struct.pack("<HHI", 0, 0, header_len)               # SessionKey
    flags = 0x00000001 if unicode_on else 0x00000000
    msg += struct.pack("<I", flags)                            # NegotiateFlags
    assert len(msg) == header_len
    msg += payload
    return bytes(msg)


def _session_setup_request(blob):
    body = bytearray(24)
    struct.pack_into("<H", body, 0, 25)   # StructureSize
    # SecurityBufferOffset 은 SMB2 헤더 시작 기준 = 64 + 본문 내 블롭 위치.
    sec_off = 64 + 24
    struct.pack_into("<H", body, 12, sec_off)
    struct.pack_into("<H", body, 14, len(blob))
    return _smb2_header(CMD_SESSION_SETUP) + bytes(body) + blob


def _tree_connect_request(path):
    raw = path.encode("utf-16-le")
    body = bytearray(8)
    struct.pack_into("<H", body, 0, 9)    # StructureSize
    path_off = 64 + 8
    struct.pack_into("<H", body, 4, path_off)
    struct.pack_into("<H", body, 6, len(raw))
    return _smb2_header(CMD_TREE_CONNECT) + bytes(body) + raw


class TestProtocolDetection(unittest.TestCase):
    def test_smb1_detected_as_legacy(self):
        pkt = SMB1_MAGIC + b"\x72" + b"\x00" * 32  # 0x72 = SMB1 NEGOTIATE.
        msg = parse_smb(pkt)
        self.assertIsNotNone(msg)
        self.assertTrue(msg.is_smb1)
        self.assertEqual(msg.command, 0x72)
        self.assertIn("smb1", msg.command_name)

    def test_non_smb_returns_none(self):
        self.assertIsNone(parse_smb(b"GET / HTTP/1.1\r\n"))
        self.assertIsNone(parse_smb(b"\xff\xff\xff\xff"))

    def test_empty_returns_none(self):
        self.assertIsNone(parse_smb(b""))
        self.assertIsNone(parse_smb(b"abc", offset=10))

    def test_unknown_command_rejected(self):
        pkt = _smb2_header(0x00FF)  # 알려지지 않은 Command.
        self.assertIsNone(parse_smb(pkt))

    def test_truncated_header_returns_none(self):
        self.assertIsNone(parse_smb(SMB2_MAGIC + b"\x00" * 10))

    def test_transport_header_stripped(self):
        pkt = _transport(_negotiate_request([DIALECT_3_1_1]))
        msg = parse_smb(pkt)
        self.assertIsNotNone(msg)
        self.assertTrue(msg.is_negotiate)


class TestNegotiate(unittest.TestCase):
    def test_dialects_extracted(self):
        pkt = _negotiate_request([DIALECT_2_0_2, DIALECT_3_1_1])
        msg = parse_smb(pkt)
        self.assertEqual(msg.dialects, [DIALECT_2_0_2, DIALECT_3_1_1])
        self.assertIn("2.0.2", msg.dialect_names)
        self.assertIn("3.1.1", msg.dialect_names)

    def test_old_dialects_flagged(self):
        pkt = _negotiate_request([DIALECT_2_0_2, DIALECT_SMB1_FALLBACK,
                                  DIALECT_3_1_1])
        msg = parse_smb(pkt)
        self.assertEqual(set(msg.offers_old_dialects),
                         {DIALECT_2_0_2, DIALECT_SMB1_FALLBACK})

    def test_signing_required(self):
        pkt = _negotiate_request([DIALECT_3_1_1],
                                 security_mode=SIGNING_REQUIRED)
        msg = parse_smb(pkt)
        self.assertTrue(msg.signing_required)
        self.assertFalse(msg.signing_not_required)

    def test_signing_not_required_relay_vector(self):
        pkt = _negotiate_request([DIALECT_3_1_1],
                                 security_mode=SIGNING_ENABLED)
        msg = parse_smb(pkt)
        self.assertFalse(msg.signing_required)
        self.assertTrue(msg.signing_not_required)

    def test_response_security_mode(self):
        body = bytearray(8)
        struct.pack_into("<H", body, 0, 65)               # StructureSize
        struct.pack_into("<H", body, 2, SIGNING_REQUIRED) # SecurityMode
        struct.pack_into("<H", body, 4, DIALECT_3_0)       # DialectRevision
        pkt = _smb2_header(CMD_NEGOTIATE,
                           flags=FLAGS_SERVER_TO_REDIR) + bytes(body)
        msg = parse_smb(pkt)
        self.assertTrue(msg.is_response)
        self.assertTrue(msg.signing_required)


class TestSessionSetupNTLM(unittest.TestCase):
    def test_ntlm_authenticate_attribution(self):
        blob = _ntlm_authenticate("CORP", "alice", "WS01")
        pkt = _session_setup_request(blob)
        msg = parse_smb(pkt)
        self.assertTrue(msg.is_session_setup)
        self.assertEqual(msg.ntlm_message_type, NTLM_AUTHENTICATE)
        self.assertTrue(msg.is_ntlm_authenticate)
        self.assertEqual(msg.ntlm_domain, "CORP")
        self.assertEqual(msg.ntlm_user, "alice")
        self.assertEqual(msg.ntlm_workstation, "WS01")
        self.assertEqual(msg.ntlm_account, "CORP\\alice")

    def test_ntlm_oem_encoding(self):
        blob = _ntlm_authenticate("DOM", "bob", "PC", unicode_on=False)
        pkt = _session_setup_request(blob)
        msg = parse_smb(pkt)
        self.assertEqual(msg.ntlm_user, "bob")
        self.assertEqual(msg.ntlm_domain, "DOM")

    def test_ntlm_negotiate_type_only(self):
        blob = b"NTLMSSP\x00" + struct.pack("<I", NTLM_NEGOTIATE) + b"\x00" * 8
        pkt = _session_setup_request(blob)
        msg = parse_smb(pkt)
        self.assertEqual(msg.ntlm_message_type, NTLM_NEGOTIATE)
        self.assertFalse(msg.is_ntlm_authenticate)
        self.assertIsNone(msg.ntlm_user)

    def test_session_setup_without_ntlm(self):
        pkt = _session_setup_request(b"\x60\x06garbage")
        msg = parse_smb(pkt)
        self.assertTrue(msg.is_session_setup)
        self.assertIsNone(msg.ntlm_message_type)


class TestTreeConnect(unittest.TestCase):
    def test_admin_share_detected(self):
        pkt = _tree_connect_request(r"\\DC01\IPC$")
        msg = parse_smb(pkt)
        self.assertTrue(msg.is_tree_connect)
        self.assertEqual(msg.tree_path, r"\\DC01\IPC$")
        self.assertEqual(msg.target_share, "IPC$")
        self.assertTrue(msg.is_admin_share)

    def test_normal_share_not_admin(self):
        pkt = _tree_connect_request(r"\\FS\Shared")
        msg = parse_smb(pkt)
        self.assertEqual(msg.target_share, "Shared")
        self.assertFalse(msg.is_admin_share)

    def test_c_dollar_share(self):
        pkt = _tree_connect_request(r"\\10.0.0.5\C$")
        msg = parse_smb(pkt)
        self.assertTrue(msg.is_admin_share)


class TestHeaderFields(unittest.TestCase):
    def test_response_flag_and_ids(self):
        pkt = _smb2_header(CMD_NEGOTIATE, flags=FLAGS_SERVER_TO_REDIR,
                           status=0xC000006D, message_id=7,
                           session_id=0x1234, tree_id=0x55) + bytes(8)
        msg = parse_smb(pkt)
        self.assertTrue(msg.is_response)
        self.assertEqual(msg.status, 0xC000006D)
        self.assertEqual(msg.message_id, 7)
        self.assertEqual(msg.session_id, 0x1234)
        self.assertEqual(msg.tree_id, 0x55)

    def test_offset_parsing(self):
        pkt = b"\xde\xad" + _negotiate_request([DIALECT_3_1_1])
        msg = parse_smb(pkt, offset=2)
        self.assertIsNotNone(msg)
        self.assertTrue(msg.is_negotiate)


if __name__ == "__main__":
    unittest.main()
