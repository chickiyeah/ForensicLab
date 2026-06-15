"""forensiclab.bacnet 단위 테스트 (stdlib unittest)."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from forensiclab.bacnet import (  # noqa: E402
    BACnet,
    BACNET_CONFIRMED_SERVICES,
    BACNET_PDU_TYPE_NAMES,
    BACNET_UNCONFIRMED_SERVICES,
    BVLC_FUNCTION_NAMES,
    bvlc_function_name,
    parse_bacnet,
    pdu_type_name,
    service_name,
)


def _bvlc(function, body):
    """BVLC 헤더(Type 0x81 + function + length) + body 를 만든다."""
    total = 4 + len(body)
    return bytes([0x81, function, (total >> 8) & 0xFF, total & 0xFF]) + body


def _npdu(control, apdu=b"", dnet=None, dadr=b"", snet=None, sadr=b"", hop=255):
    """NPDU(version 0x01 + control + 선택적 라우팅) + apdu 를 만든다."""
    out = bytes([0x01, control])
    if control & 0x20 and dnet is not None:  # 목적지.
        out += bytes([(dnet >> 8) & 0xFF, dnet & 0xFF, len(dadr)]) + dadr
    if control & 0x08 and snet is not None:  # 출처.
        out += bytes([(snet >> 8) & 0xFF, snet & 0xFF, len(sadr)]) + sadr
    if control & 0x20 and dnet is not None:
        out += bytes([hop])
    return out + apdu


def _unconfirmed(choice):
    """Unconfirmed-Request APDU(type 1 + service choice)."""
    return bytes([0x10, choice])


def _confirmed(choice, invoke_id=0x01, seg=False):
    """Confirmed-Request APDU(type 0 + max + invoke + [seq/win] + choice)."""
    first = 0x00 | (0x08 if seg else 0x00)
    apdu = bytes([first, 0x05, invoke_id])
    if seg:
        apdu += bytes([0x00, 0x10])  # sequence + window.
    return apdu + bytes([choice])


class BvlcTest(unittest.TestCase):
    def test_original_unicast_readproperty(self):
        apdu = _confirmed(12, invoke_id=0x2A)
        pkt = _bvlc(0x0A, _npdu(0x04, apdu))  # expecting reply.
        m = parse_bacnet(pkt)
        self.assertIsNotNone(m)
        self.assertEqual(m.bvlc_function, 0x0A)
        self.assertEqual(m.bvlc_function_name, "Original-Unicast-NPDU")
        self.assertEqual(m.npdu_version, 0x01)
        self.assertTrue(m.expecting_reply)
        self.assertEqual(m.pdu_type, 0x0)
        self.assertEqual(m.pdu_type_name, "Confirmed-Request")
        self.assertEqual(m.invoke_id, 0x2A)
        self.assertEqual(m.service_choice, 12)
        self.assertEqual(m.service_name, "readProperty")
        self.assertTrue(m.is_confirmed_request)
        self.assertTrue(m.is_read)
        self.assertFalse(m.is_write)
        self.assertFalse(m.truncated)

    def test_packet_length(self):
        pkt = _bvlc(0x0A, _npdu(0x00, _unconfirmed(8)))
        m = parse_bacnet(pkt)
        self.assertEqual(m.bvlc_length, len(pkt))
        self.assertEqual(m.packet_length, len(pkt))


class ServiceIntentTest(unittest.TestCase):
    def test_who_is(self):
        m = parse_bacnet(_bvlc(0x0B, _npdu(0x00, _unconfirmed(8))))  # broadcast.
        self.assertTrue(m.is_unconfirmed_request)
        self.assertTrue(m.is_who_is)
        self.assertFalse(m.is_i_am)
        self.assertEqual(m.service_name, "who-Is")

    def test_i_am(self):
        m = parse_bacnet(_bvlc(0x0B, _npdu(0x00, _unconfirmed(0))))
        self.assertTrue(m.is_i_am)
        self.assertEqual(m.service_name, "i-Am")

    def test_write_property(self):
        m = parse_bacnet(_bvlc(0x0A, _npdu(0x04, _confirmed(15))))
        self.assertTrue(m.is_write)
        self.assertFalse(m.is_read)
        self.assertEqual(m.service_name, "writeProperty")

    def test_device_communication_control(self):
        m = parse_bacnet(_bvlc(0x0A, _npdu(0x04, _confirmed(17))))
        self.assertTrue(m.is_device_control)
        self.assertEqual(m.service_name, "deviceCommunicationControl")

    def test_reinitialize_device(self):
        m = parse_bacnet(_bvlc(0x0A, _npdu(0x04, _confirmed(20))))
        self.assertTrue(m.is_device_control)
        self.assertEqual(m.service_name, "reinitializeDevice")


class PduTypeTest(unittest.TestCase):
    def test_simple_ack(self):
        apdu = bytes([0x20, 0x2A, 15])  # SimpleACK, invoke 0x2A, writeProperty.
        m = parse_bacnet(_bvlc(0x0A, _npdu(0x00, apdu)))
        self.assertEqual(m.pdu_type, 0x2)
        self.assertEqual(m.pdu_type_name, "SimpleACK")
        self.assertEqual(m.invoke_id, 0x2A)
        self.assertEqual(m.service_choice, 15)
        self.assertFalse(m.is_error)

    def test_complex_ack(self):
        apdu = bytes([0x30, 0x2A, 12])  # ComplexACK, invoke 0x2A, readProperty.
        m = parse_bacnet(_bvlc(0x0A, _npdu(0x00, apdu)))
        self.assertEqual(m.pdu_type, 0x3)
        self.assertEqual(m.invoke_id, 0x2A)
        self.assertEqual(m.service_name, "readProperty")

    def test_error(self):
        apdu = bytes([0x50, 0x2A, 12])  # Error, invoke 0x2A.
        m = parse_bacnet(_bvlc(0x0A, _npdu(0x00, apdu)))
        self.assertEqual(m.pdu_type, 0x5)
        self.assertEqual(m.invoke_id, 0x2A)
        self.assertTrue(m.is_error)

    def test_segmented_confirmed_request(self):
        apdu = _confirmed(12, invoke_id=0x07, seg=True)
        m = parse_bacnet(_bvlc(0x0A, _npdu(0x04, apdu)))
        self.assertEqual(m.invoke_id, 0x07)
        self.assertEqual(m.service_choice, 12)  # seq/window 건너뛰고 정확히.


class RoutingTest(unittest.TestCase):
    def test_routed_dnet_snet(self):
        # 목적지+출처 망 번호.
        apdu = _unconfirmed(0)
        npdu = _npdu(0x20 | 0x08, apdu, dnet=0x000A, dadr=b"\x05",
                     snet=0x0014, sadr=b"\x0a\x0b")
        m = parse_bacnet(_bvlc(0x0A, npdu))
        self.assertEqual(m.dnet, 0x000A)
        self.assertEqual(m.snet, 0x0014)
        self.assertTrue(m.is_i_am)

    def test_network_layer_message(self):
        # Control bit7: 망 계층 메시지(APDU 없음), 메시지 타입 0x01.
        npdu = bytes([0x01, 0x80, 0x01])
        m = parse_bacnet(_bvlc(0x0B, npdu))
        self.assertTrue(m.is_network_message)
        self.assertEqual(m.network_message_type, 0x01)
        self.assertIsNone(m.pdu_type)


class SpecialBvlcTest(unittest.TestCase):
    def test_bvlc_result(self):
        pkt = _bvlc(0x00, bytes([0x00, 0x60]))  # result code 0x0060.
        m = parse_bacnet(pkt)
        self.assertEqual(m.bvlc_function_name, "BVLC-Result")
        self.assertEqual(m.result_code, 0x0060)
        self.assertIsNone(m.npdu_version)

    def test_forwarded_npdu(self):
        # Forwarded-NPDU: 6바이트 B/IP 출처 주소 다음 NPDU.
        bip = bytes([10, 0, 0, 5, 0xBA, 0xC0])
        body = bip + _npdu(0x00, _unconfirmed(8))
        m = parse_bacnet(_bvlc(0x04, body))
        self.assertEqual(m.bvlc_function_name, "Forwarded-NPDU")
        self.assertTrue(m.is_who_is)

    def test_register_foreign_device_no_npdu(self):
        pkt = _bvlc(0x05, bytes([0x00, 0x3C]))  # TTL.
        m = parse_bacnet(pkt)
        self.assertEqual(m.bvlc_function_name, "Register-Foreign-Device")
        self.assertIsNone(m.npdu_version)
        self.assertIsNone(m.pdu_type)


class GuardTest(unittest.TestCase):
    def test_wrong_bvlc_type(self):
        pkt = bytearray(_bvlc(0x0A, _npdu(0x00, _unconfirmed(8))))
        pkt[0] = 0x80
        self.assertIsNone(parse_bacnet(bytes(pkt)))

    def test_unknown_bvlc_function(self):
        pkt = bytes([0x81, 0xFE, 0x00, 0x06, 0x01, 0x00])
        self.assertIsNone(parse_bacnet(pkt))

    def test_wrong_npdu_version(self):
        pkt = bytearray(_bvlc(0x0A, _npdu(0x00, _unconfirmed(8))))
        pkt[4] = 0x02  # NPDU version byte (BVLC 0-3, NPDU version at 4).
        self.assertIsNone(parse_bacnet(bytes(pkt)))

    def test_too_short(self):
        self.assertIsNone(parse_bacnet(b"\x81\x0a"))

    def test_empty(self):
        self.assertIsNone(parse_bacnet(b""))

    def test_negative_offset(self):
        self.assertIsNone(parse_bacnet(_bvlc(0x0A, _npdu(0x00, _unconfirmed(8))), offset=-1))


class TruncationTest(unittest.TestCase):
    def test_truncated_apdu(self):
        full = _bvlc(0x0A, _npdu(0x04, _confirmed(15, invoke_id=0x09)))
        m = parse_bacnet(full[:-1])  # service choice 잘림.
        self.assertIsNotNone(m)
        self.assertTrue(m.truncated)
        self.assertEqual(m.invoke_id, 0x09)
        self.assertIsNone(m.service_choice)

    def test_truncated_npdu(self):
        # NPDU version 직전까지만.
        full = _bvlc(0x0A, _npdu(0x00, _unconfirmed(8)))
        m = parse_bacnet(full[:5])  # BVLC(4) + version(1) 만, control 없음.
        self.assertIsNotNone(m)
        self.assertTrue(m.truncated)


class OffsetTest(unittest.TestCase):
    def test_offset(self):
        prefix = b"\xde\xad\xbe\xef"
        buf = prefix + _bvlc(0x0A, _npdu(0x04, _confirmed(15, invoke_id=0x11)))
        m = parse_bacnet(buf, offset=len(prefix))
        self.assertIsNotNone(m)
        self.assertTrue(m.is_write)
        self.assertEqual(m.invoke_id, 0x11)


class HelperTest(unittest.TestCase):
    def test_bvlc_function_name_helper(self):
        self.assertEqual(bvlc_function_name(0x0A), "Original-Unicast-NPDU")
        self.assertTrue(bvlc_function_name(0x55).startswith("bvlc-0x"))

    def test_pdu_type_name_helper(self):
        self.assertEqual(pdu_type_name(0x3), "ComplexACK")
        self.assertTrue(pdu_type_name(0x9).startswith("pdu-"))

    def test_service_name_helper(self):
        self.assertEqual(service_name(0x1, 8), "who-Is")          # unconfirmed.
        self.assertEqual(service_name(0x0, 15), "writeProperty")  # confirmed.
        self.assertTrue(service_name(0x0, 200).startswith("service-"))

    def test_tables_present(self):
        self.assertIn(0x0A, BVLC_FUNCTION_NAMES)
        self.assertIn(0x3, BACNET_PDU_TYPE_NAMES)
        self.assertIn(15, BACNET_CONFIRMED_SERVICES)
        self.assertIn(8, BACNET_UNCONFIRMED_SERVICES)

    def test_frozen_dataclass(self):
        m = parse_bacnet(_bvlc(0x0A, _npdu(0x00, _unconfirmed(8))))
        with self.assertRaises(Exception):
            m.pdu_type = 9  # type: ignore[misc]


if __name__ == "__main__":
    unittest.main()
