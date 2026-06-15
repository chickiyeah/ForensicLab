"""forensiclab.dcerpc 단위 테스트 (stdlib unittest)."""

import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from forensiclab.dcerpc import (  # noqa: E402
    PFC_FIRST_FRAG,
    PFC_LAST_FRAG,
    PT_BIND,
    PT_BIND_NAK,
    PT_REQUEST,
    TRANSFER_SYNTAX_NDR,
    DceRpcPdu,
    PresentationContext,
    interface_info,
    parse_pdu,
    ptype_name,
)

# 알려진 인터페이스 UUID(테스트에서 사용).
UUID_DRSUAPI = "e3514235-4b06-11d1-ab04-00c04fc2dcd2"
UUID_SVCCTL = "367abb81-9844-35f1-ad32-98f038001003"
UUID_SPOOLSS = "12345678-1234-abcd-ef00-0123456789ab"


# --- 최소 DCE/RPC 인코더(테스트 픽스처 전용, little-endian DREP) -----------

def _uuid_bytes(uuid_str, little=True):
    """표준 UUID 문자열을 16바이트 RPC 표현으로(앞 3필드 엔디안 적용)."""
    parts = uuid_str.split("-")
    order = "little" if little else "big"
    d1 = int(parts[0], 16).to_bytes(4, order)
    d2 = int(parts[1], 16).to_bytes(2, order)
    d3 = int(parts[2], 16).to_bytes(2, order)
    d4 = bytes.fromhex(parts[3])
    d5 = bytes.fromhex(parts[4])
    return d1 + d2 + d3 + d4 + d5


def _header(ptype, frag_length, pfc=PFC_FIRST_FRAG | PFC_LAST_FRAG,
            call_id=1, auth_length=0, drep0=0x10):
    # version(5) version_minor(0) ptype pfc | drep(4) | frag_len(2) auth_len(2) call_id(4)
    return (bytes([5, 0, ptype, pfc, drep0, 0, 0, 0])
            + struct.pack("<HHI", frag_length, auth_length, call_id))


def _bind(contexts, call_id=1):
    """contexts: [(cid, abstract_uuid, ver_major, ver_minor, [transfer_uuids])]."""
    body = struct.pack("<HHI", 4280, 4280, 0)  # max_xmit, max_recv, assoc_group
    body += bytes([len(contexts), 0, 0, 0])    # n_context_elem + reserved
    for cid, auuid, vmaj, vmin, transfers in contexts:
        body += struct.pack("<HBB", cid, len(transfers), 0)
        body += _uuid_bytes(auuid) + struct.pack("<HH", vmaj, vmin)
        for tuuid in transfers:
            body += _uuid_bytes(tuuid) + struct.pack("<HH", 2, 0)
    frag_len = 16 + len(body)
    return _header(PT_BIND, frag_len, call_id=call_id) + body


def _request(context_id, opnum, alloc_hint=0, stub=b"", call_id=1):
    body = struct.pack("<IHH", alloc_hint, context_id, opnum) + stub
    frag_len = 16 + len(body)
    return _header(PT_REQUEST, frag_len, call_id=call_id) + body


class TestHelpers(unittest.TestCase):
    def test_ptype_name_known(self):
        self.assertEqual(ptype_name(PT_BIND), "bind")
        self.assertEqual(ptype_name(PT_REQUEST), "request")

    def test_ptype_name_unknown(self):
        self.assertEqual(ptype_name(99), "ptype-99")

    def test_interface_info_known(self):
        name, note = interface_info(UUID_DRSUAPI)
        self.assertEqual(name, "DRSUAPI")
        self.assertIn("DCSync", note)

    def test_interface_info_case_insensitive(self):
        self.assertIsNotNone(interface_info(UUID_DRSUAPI.upper()))

    def test_interface_info_unknown(self):
        self.assertIsNone(interface_info("00000000-0000-0000-0000-000000000000"))


class TestHeader(unittest.TestCase):
    def test_too_short(self):
        self.assertIsNone(parse_pdu(b"\x05\x00\x0b"))

    def test_wrong_version(self):
        # version 4 (connectionless) 는 거부.
        pkt = bytearray(_bind([(0, UUID_DRSUAPI, 4, 0, [TRANSFER_SYNTAX_NDR])]))
        pkt[0] = 4
        self.assertIsNone(parse_pdu(bytes(pkt)))

    def test_unknown_ptype(self):
        pkt = bytearray(_header(200, 16))
        self.assertIsNone(parse_pdu(bytes(pkt)))

    def test_common_header_fields(self):
        pdu = parse_pdu(_bind([(0, UUID_SVCCTL, 2, 0, [TRANSFER_SYNTAX_NDR])], call_id=7))
        self.assertIsNotNone(pdu)
        self.assertEqual(pdu.version, 5)
        self.assertEqual(pdu.version_minor, 0)
        self.assertEqual(pdu.call_id, 7)
        self.assertTrue(pdu.is_little_endian)
        self.assertTrue(pdu.is_first_frag)
        self.assertTrue(pdu.is_last_frag)
        self.assertEqual(pdu.ptype_name, "bind")

    def test_big_endian_drep(self):
        # DREP 0x00 = big-endian 정수. 길이/UUID 가 big-endian 으로 디코딩돼야.
        body = struct.pack(">HHI", 4280, 4280, 0) + bytes([1, 0, 0, 0])
        body += struct.pack(">HBB", 0, 1, 0)
        body += _uuid_bytes(UUID_DRSUAPI, little=False) + struct.pack(">HH", 4, 0)
        body += _uuid_bytes(TRANSFER_SYNTAX_NDR, little=False) + struct.pack(">HH", 2, 0)
        pkt = (bytes([5, 0, PT_BIND, PFC_FIRST_FRAG | PFC_LAST_FRAG, 0x00, 0, 0, 0])
               + struct.pack(">HHI", 16 + len(body), 0, 1) + body)
        pdu = parse_pdu(pkt)
        self.assertIsNotNone(pdu)
        self.assertFalse(pdu.is_little_endian)
        self.assertEqual(pdu.contexts[0].abstract_uuid, UUID_DRSUAPI)


class TestBind(unittest.TestCase):
    def test_drsuapi_dcsync(self):
        pdu = parse_pdu(_bind([(0, UUID_DRSUAPI, 4, 0, [TRANSFER_SYNTAX_NDR])]))
        self.assertEqual(pdu.ptype, PT_BIND)
        self.assertTrue(pdu.is_bind)
        self.assertEqual(len(pdu.contexts), 1)
        ctx = pdu.contexts[0]
        self.assertEqual(ctx.context_id, 0)
        self.assertEqual(ctx.abstract_uuid, UUID_DRSUAPI)
        self.assertEqual(ctx.abstract_version, "4.0")
        self.assertEqual(ctx.interface_name, "DRSUAPI")
        self.assertIn("DCSync", ctx.attack_note)
        self.assertEqual(ctx.transfer_uuids, [TRANSFER_SYNTAX_NDR])
        self.assertEqual(pdu.bound_interfaces, ["DRSUAPI"])

    def test_unknown_interface(self):
        unknown = "11111111-2222-3333-4444-555555555555"
        pdu = parse_pdu(_bind([(1, unknown, 1, 0, [TRANSFER_SYNTAX_NDR])]))
        ctx = pdu.contexts[0]
        self.assertEqual(ctx.abstract_uuid, unknown)
        self.assertIsNone(ctx.interface_name)
        self.assertIsNone(ctx.attack_note)
        self.assertEqual(pdu.bound_interfaces, [])

    def test_multiple_contexts(self):
        pdu = parse_pdu(_bind([
            (0, UUID_SVCCTL, 2, 0, [TRANSFER_SYNTAX_NDR]),
            (1, UUID_SPOOLSS, 1, 0, [TRANSFER_SYNTAX_NDR]),
        ]))
        self.assertEqual(len(pdu.contexts), 2)
        self.assertEqual(pdu.contexts[0].interface_name, "SVCCTL")
        self.assertEqual(pdu.contexts[1].interface_name, "SPOOLSS")
        self.assertEqual(pdu.bound_interfaces, ["SVCCTL", "SPOOLSS"])

    def test_spoolss_printnightmare(self):
        pdu = parse_pdu(_bind([(0, UUID_SPOOLSS, 1, 0, [TRANSFER_SYNTAX_NDR])]))
        self.assertIn("PrintNightmare", pdu.contexts[0].attack_note)

    def test_truncated_context_list(self):
        # 컨텍스트 2개를 선언했지만 1개분만 담은 본문.
        full = _bind([
            (0, UUID_SVCCTL, 2, 0, [TRANSFER_SYNTAX_NDR]),
            (1, UUID_SPOOLSS, 1, 0, [TRANSFER_SYNTAX_NDR]),
        ])
        # n_context_elem 를 2로 두고 본문을 잘라 한 컨텍스트만 남긴다.
        truncated = full[:16 + 8 + 4 + 4 + 20 + 20]
        pdu = parse_pdu(truncated)
        self.assertIsNotNone(pdu)
        self.assertEqual(len(pdu.contexts), 1)
        self.assertEqual(pdu.contexts[0].interface_name, "SVCCTL")

    def test_no_transfer_syntax(self):
        pdu = parse_pdu(_bind([(0, UUID_DRSUAPI, 4, 0, [])]))
        self.assertEqual(pdu.contexts[0].transfer_uuids, [])
        self.assertEqual(pdu.contexts[0].interface_name, "DRSUAPI")


class TestRequest(unittest.TestCase):
    def test_request_opnum(self):
        # DRSUAPI opnum 3 = DRSGetNCChanges (DCSync 호출).
        pdu = parse_pdu(_request(context_id=0, opnum=3, alloc_hint=64, stub=b"\x00" * 8))
        self.assertEqual(pdu.ptype, PT_REQUEST)
        self.assertEqual(pdu.ptype_name, "request")
        self.assertEqual(pdu.context_id, 0)
        self.assertEqual(pdu.opnum, 3)
        self.assertFalse(pdu.is_bind)
        self.assertEqual(pdu.contexts, [])

    def test_request_truncated_opnum(self):
        # alloc_hint+cont_id 까지만 — opnum 누락.
        body = struct.pack("<IH", 0, 5)
        pkt = _header(PT_REQUEST, 16 + len(body)) + body
        pdu = parse_pdu(pkt)
        self.assertIsNotNone(pdu)
        self.assertEqual(pdu.context_id, 5)
        self.assertIsNone(pdu.opnum)


class TestBindNak(unittest.TestCase):
    def test_nak_reason(self):
        body = struct.pack("<H", 2)  # provider_reject_reason.
        pkt = _header(PT_BIND_NAK, 16 + len(body)) + body
        pdu = parse_pdu(pkt)
        self.assertEqual(pdu.ptype, PT_BIND_NAK)
        self.assertEqual(pdu.nak_reason, 2)


class TestOffset(unittest.TestCase):
    def test_offset_skips_prefix(self):
        pdu_bytes = _bind([(0, UUID_DRSUAPI, 4, 0, [TRANSFER_SYNTAX_NDR])])
        prefixed = b"\xde\xad\xbe\xef" + pdu_bytes
        pdu = parse_pdu(prefixed, offset=4)
        self.assertIsNotNone(pdu)
        self.assertEqual(pdu.contexts[0].interface_name, "DRSUAPI")

    def test_negative_offset(self):
        self.assertIsNone(parse_pdu(b"\x00" * 32, offset=-1))


if __name__ == "__main__":
    unittest.main()
