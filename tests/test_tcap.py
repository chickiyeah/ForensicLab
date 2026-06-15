"""forensiclab.tcap 단위 테스트 (stdlib unittest)."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from forensiclab.tcap import (  # noqa: E402
    SS7_ATTACK_OPERATIONS,
    TCAP_MESSAGE_TYPES,
    Tcap,
    TcapComponent,
    parse_tcap,
)


def _tlv(tag, content):
    """짧은 형식(길이<128) BER TLV 하나를 짠다."""
    assert len(content) < 0x80, "테스트 헬퍼는 짧은 형식만"
    return bytes([tag, len(content)]) + content


def _int(tag, value):
    """정수 INTEGER(또는 임의 태그)를 최소 바이트로 인코드."""
    if value == 0:
        body = b"\x00"
    else:
        body = b""
        v = value
        while v:
            body = bytes([v & 0xFF]) + body
            v >>= 8
    return _tlv(tag, body)


def _invoke(invoke_id, opcode):
    """Invoke(0xA1): invokeID(INTEGER) + operationCode(INTEGER local)."""
    body = _int(0x02, invoke_id) + _int(0x02, opcode)
    return _tlv(0xA1, body)


def _begin(otid=b"\x01\x02\x03\x04", components=b""):
    """Begin(0x62): originating TID(0x48) + component portion(0x6C)."""
    body = _tlv(0x48, otid)
    if components:
        body += _tlv(0x6C, components)
    return _tlv(0x62, body)


class MessageTypeTests(unittest.TestCase):
    def test_begin_name(self):
        m = parse_tcap(_begin())
        self.assertIsInstance(m, Tcap)
        self.assertEqual(m.message_type, 0x62)
        self.assertEqual(m.message_type_name, "Begin")
        self.assertTrue(m.is_begin)
        self.assertFalse(m.is_abort)

    def test_message_type_set(self):
        self.assertEqual(
            TCAP_MESSAGE_TYPES,
            frozenset({0x61, 0x62, 0x64, 0x65, 0x67}),
        )

    def test_continue_both_tids(self):
        body = _tlv(0x48, b"\xaa\xbb") + _tlv(0x49, b"\xcc\xdd")
        m = parse_tcap(_tlv(0x65, body))
        self.assertTrue(m.is_continue)
        self.assertEqual(m.originating_tid, 0xAABB)
        self.assertEqual(m.destination_tid, 0xCCDD)

    def test_end_destination_tid(self):
        body = _tlv(0x49, b"\x00\x00\x00\x05")
        m = parse_tcap(_tlv(0x64, body))
        self.assertTrue(m.is_end)
        self.assertEqual(m.destination_tid, 5)
        self.assertIsNone(m.originating_tid)


class TransactionIdTests(unittest.TestCase):
    def test_originating_tid_value(self):
        m = parse_tcap(_begin(otid=b"\x12\x34\x56\x78"))
        self.assertEqual(m.originating_tid, 0x12345678)

    def test_components_empty_by_default(self):
        m = parse_tcap(_begin())
        self.assertEqual(m.components, [])
        self.assertEqual(m.operation_codes, [])
        self.assertFalse(m.has_attack_operation)


class ComponentTests(unittest.TestCase):
    def test_invoke_sri_sm(self):
        # SRI-SM(45) — SMS 가로채기용 표적 조회.
        m = parse_tcap(_begin(components=_invoke(1, 45)))
        self.assertEqual(len(m.components), 1)
        c = m.components[0]
        self.assertIsInstance(c, TcapComponent)
        self.assertTrue(c.is_invoke)
        self.assertEqual(c.component_name, "Invoke")
        self.assertEqual(c.invoke_id, 1)
        self.assertEqual(c.operation_code, 45)
        self.assertEqual(c.operation_name, "sendRoutingInfoForSM")
        self.assertTrue(c.is_attack_operation)
        self.assertTrue(m.has_attack_operation)
        self.assertEqual(m.operation_names, ["sendRoutingInfoForSM"])

    def test_invoke_ati_location(self):
        m = parse_tcap(_begin(components=_invoke(7, 71)))
        c = m.components[0]
        self.assertEqual(c.operation_name, "anyTimeInterrogation")
        self.assertTrue(c.is_attack_operation)

    def test_invoke_unknown_operation(self):
        m = parse_tcap(_begin(components=_invoke(2, 200)))
        c = m.components[0]
        self.assertEqual(c.operation_code, 200)
        self.assertEqual(c.operation_name, "op-200")
        self.assertFalse(c.is_attack_operation)

    def test_multiple_components(self):
        comps = _invoke(1, 45) + _invoke(2, 2)  # SRI-SM + updateLocation.
        m = parse_tcap(_begin(components=comps))
        self.assertEqual(len(m.components), 2)
        self.assertEqual(m.operation_codes, [45, 2])
        self.assertTrue(m.has_attack_operation)

    def test_return_result_last_opcode(self):
        # ReturnResultLast(0xA2): invokeID + SEQUENCE{ operationCode, ... }.
        seq = _int(0x02, 45)
        body = _int(0x02, 1) + _tlv(0x30, seq)
        comp = _tlv(0xA2, body)
        m = parse_tcap(_begin(components=comp))
        c = m.components[0]
        self.assertEqual(c.component_name, "ReturnResultLast")
        self.assertEqual(c.invoke_id, 1)
        self.assertEqual(c.operation_code, 45)

    def test_return_error_code(self):
        # ReturnError(0xA3): invokeID + errorCode.
        body = _int(0x02, 1) + _int(0x02, 34)  # errorCode 34 = systemFailure.
        comp = _tlv(0xA3, body)
        m = parse_tcap(_begin(components=comp))
        c = m.components[0]
        self.assertEqual(c.component_name, "ReturnError")
        self.assertEqual(c.invoke_id, 1)
        self.assertEqual(c.error_code, 34)
        self.assertIsNone(c.operation_code)

    def test_global_operation_oid(self):
        # operationCode 가 OID(global) → operation_code None, 플래그만.
        oid = _tlv(0x06, b"\x04\x00\x00\x01\x00\x13\x02")
        body = _int(0x02, 1) + oid
        comp = _tlv(0xA1, body)
        m = parse_tcap(_begin(components=comp))
        c = m.components[0]
        self.assertTrue(c.is_global_operation)
        self.assertIsNone(c.operation_code)
        self.assertIsNone(c.operation_name)


class AbortTests(unittest.TestCase):
    def test_p_abort_cause(self):
        # Abort(0x67): destination TID + P-Abort cause(0x4A).
        body = _tlv(0x49, b"\x00\x00\x00\x01") + _int(0x4A, 1)
        m = parse_tcap(_tlv(0x67, body))
        self.assertTrue(m.is_abort)
        self.assertEqual(m.p_abort_cause, 1)
        self.assertEqual(m.p_abort_name, "unrecognizedTransactionID")

    def test_unknown_abort_cause(self):
        body = _int(0x4A, 9)
        m = parse_tcap(_tlv(0x67, body))
        self.assertEqual(m.p_abort_name, "cause-9")


class DialogueTests(unittest.TestCase):
    def test_dialogue_portion_offset(self):
        dialogue = _tlv(0x6B, b"\x28\x06\x07\x04\x00\x00\x01")  # 임의 내용.
        otid = _tlv(0x48, b"\x01")
        m = parse_tcap(_tlv(0x62, otid + dialogue))
        self.assertTrue(m.has_dialogue_portion)
        self.assertIsNotNone(m.dialogue_offset)
        # dialogue_offset 은 0x6B 의 내용 시작 → 첫 바이트 0x28.
        raw = _tlv(0x62, otid + dialogue)
        self.assertEqual(raw[m.dialogue_offset], 0x28)

    def test_no_dialogue(self):
        m = parse_tcap(_begin())
        self.assertFalse(m.has_dialogue_portion)
        self.assertIsNone(m.dialogue_offset)


class GuardTests(unittest.TestCase):
    def test_empty(self):
        self.assertIsNone(parse_tcap(b""))

    def test_negative_offset(self):
        self.assertIsNone(parse_tcap(_begin(), offset=-1))

    def test_offset_past_end(self):
        self.assertIsNone(parse_tcap(b"\x62", offset=5))

    def test_undefined_message_tag(self):
        # 0x30(SEQUENCE)·0x00 등은 TCAP 메시지 타입 아님 → 오탐 가드.
        self.assertIsNone(parse_tcap(b"\x30\x02\x00\x00"))
        self.assertIsNone(parse_tcap(b"\x00\x00"))

    def test_truncated_length(self):
        # 태그만 있고 길이 옥텟 없음.
        self.assertIsNone(parse_tcap(b"\x62"))

    def test_attack_operation_set(self):
        self.assertIn(45, SS7_ATTACK_OPERATIONS)  # SRI-SM.
        self.assertIn(71, SS7_ATTACK_OPERATIONS)  # ATI.
        self.assertNotIn(2, SS7_ATTACK_OPERATIONS)  # updateLocation(정상).

    def test_offset_support(self):
        blob = b"\xde\xad" + _begin(components=_invoke(1, 45))
        m = parse_tcap(blob, offset=2)
        self.assertEqual(m.message_type_name, "Begin")
        self.assertEqual(m.components[0].operation_code, 45)


class TruncationTests(unittest.TestCase):
    def test_truncated_component_portion(self):
        # component portion 길이는 길게 주장하나 내용이 모자람.
        raw = _tlv(0x62, _tlv(0x48, b"\x01") + bytes([0x6C, 0x20]) + _invoke(1, 45))
        m = parse_tcap(raw)
        self.assertIsNotNone(m)
        # 담을 수 있는 컴포넌트는 풀린다.
        self.assertEqual(len(m.components), 1)
        self.assertEqual(m.components[0].operation_code, 45)

    def test_invoke_missing_opcode(self):
        # invokeID 만 있고 operationCode 없음 → operation_code None.
        comp = _tlv(0xA1, _int(0x02, 5))
        m = parse_tcap(_begin(components=comp))
        c = m.components[0]
        self.assertEqual(c.invoke_id, 5)
        self.assertIsNone(c.operation_code)


if __name__ == "__main__":
    unittest.main()
