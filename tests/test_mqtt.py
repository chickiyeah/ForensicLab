"""forensiclab.mqtt 단위 테스트 (stdlib unittest)."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from forensiclab.mqtt import (  # noqa: E402
    Mqtt,
    MQTT_PACKET_TYPE_NAMES,
    MQTT_CONNACK_RETURN_NAMES,
    connack_return_name,
    packet_type_name,
    parse_mqtt,
)


def _varint(n):
    """MQTT Remaining Length 가변정수 인코딩."""
    out = bytearray()
    while True:
        b = n % 128
        n //= 128
        if n > 0:
            b |= 0x80
        out.append(b)
        if n == 0:
            break
    return bytes(out)


def _field(b):
    """2바이트 길이 접두사 + 바이트열."""
    if isinstance(b, str):
        b = b.encode("utf-8")
    return len(b).to_bytes(2, "big") + b


def _packet(ptype, flags, body):
    """고정 헤더(type/flags + Remaining Length) + 본문."""
    return bytes([(ptype << 4) | flags]) + _varint(len(body)) + body


def _connect(client_id="dev1", username=None, password=None, will_topic=None,
             clean=True, level=4, proto=b"MQTT", keep_alive=60):
    cflags = 0
    if clean:
        cflags |= 0x02
    if will_topic is not None:
        cflags |= 0x04
    if username is not None:
        cflags |= 0x80
    if password is not None:
        cflags |= 0x40
    body = _field(proto) + bytes([level, cflags]) + keep_alive.to_bytes(2, "big")
    body += _field(client_id)
    if will_topic is not None:
        body += _field(will_topic) + _field(b"goodbye")
    if username is not None:
        body += _field(username)
    if password is not None:
        body += _field(password)
    return _packet(1, 0, body)


class FixedHeaderTest(unittest.TestCase):
    def test_pingreq(self):
        m = parse_mqtt(_packet(12, 0, b""))
        self.assertIsInstance(m, Mqtt)
        self.assertEqual(m.packet_type, 12)
        self.assertEqual(m.packet_type_name, "PINGREQ")
        self.assertEqual(m.remaining_length, 0)
        self.assertEqual(m.packet_length, 2)
        self.assertFalse(m.truncated)

    def test_packet_length_and_offset(self):
        m = parse_mqtt(_packet(13, 0, b""))  # PINGRESP
        self.assertEqual(m.packet_type_name, "PINGRESP")
        self.assertEqual(m.payload_offset, 2)

    def test_multi_byte_remaining_length(self):
        body = b"x" * 200
        m = parse_mqtt(_packet(14, 0, body))  # DISCONNECT, 큰 본문(비현실적이나 인코딩 검증)
        self.assertEqual(m.remaining_length, 200)
        self.assertEqual(m.packet_length, 1 + 2 + 200)


class ConnectTest(unittest.TestCase):
    def test_credentials_plaintext(self):
        m = parse_mqtt(_connect(client_id="sensor-7", username="admin",
                                 password="hunter2"))
        self.assertTrue(m.is_connect)
        self.assertEqual(m.protocol_name, "MQTT")
        self.assertEqual(m.protocol_level, 4)
        self.assertEqual(m.client_id, "sensor-7")
        self.assertEqual(m.username, "admin")
        self.assertEqual(m.password, "hunter2")
        self.assertTrue(m.has_credentials)
        self.assertTrue(m.clean_session)
        self.assertEqual(m.keep_alive, 60)

    def test_no_credentials(self):
        m = parse_mqtt(_connect(client_id="anon"))
        self.assertEqual(m.client_id, "anon")
        self.assertIsNone(m.username)
        self.assertIsNone(m.password)
        self.assertFalse(m.has_credentials)

    def test_username_only(self):
        m = parse_mqtt(_connect(username="u", password=None))
        self.assertEqual(m.username, "u")
        self.assertIsNone(m.password)
        self.assertTrue(m.has_credentials)

    def test_will_topic_then_credentials(self):
        m = parse_mqtt(_connect(client_id="c", will_topic="dev/status/will",
                                username="bob", password="pw"))
        self.assertEqual(m.will_topic, "dev/status/will")
        self.assertTrue(m.will_flag)
        self.assertEqual(m.username, "bob")
        self.assertEqual(m.password, "pw")

    def test_legacy_mqisdp(self):
        m = parse_mqtt(_connect(proto=b"MQIsdp", level=3))
        self.assertEqual(m.protocol_name, "MQIsdp")
        self.assertEqual(m.protocol_level, 3)

    def test_bad_protocol_name_rejected(self):
        m = parse_mqtt(_connect(proto=b"HTTP"))
        self.assertIsNone(m)

    def test_v5_properties_skipped(self):
        # CONNECT v5: keep-alive 뒤 properties(길이 0) 블록.
        body = _field(b"MQTT") + bytes([5, 0x02]) + (30).to_bytes(2, "big")
        body += _varint(0)  # properties 길이 0.
        body += _field("v5client")
        m = parse_mqtt(_packet(1, 0, body))
        self.assertEqual(m.protocol_level, 5)
        self.assertEqual(m.client_id, "v5client")


class PublishTest(unittest.TestCase):
    def test_qos0_topic_and_payload_offset(self):
        body = _field("sensors/room1/temp") + b"21.5"
        m = parse_mqtt(_packet(3, 0x00, body))
        self.assertTrue(m.is_publish)
        self.assertEqual(m.topic, "sensors/room1/temp")
        self.assertEqual(m.qos, 0)
        self.assertFalse(m.dup)
        self.assertFalse(m.retain)
        self.assertIsNone(m.packet_id)
        # payload_offset 이 가리키는 곳이 본문 "21.5".
        self.assertEqual(body[m.payload_offset - 2:], b"21.5")

    def test_qos1_has_packet_id(self):
        body = _field("cmd/device/9") + (4660).to_bytes(2, "big") + b"ON"
        m = parse_mqtt(_packet(3, 0x02, body))  # QoS 1
        self.assertEqual(m.qos, 1)
        self.assertEqual(m.packet_id, 4660)
        self.assertEqual(m.topic, "cmd/device/9")

    def test_retain_and_dup_flags(self):
        body = _field("t") + b"x"
        m = parse_mqtt(_packet(3, 0x09, body))  # DUP + RETAIN, QoS 0
        self.assertTrue(m.dup)
        self.assertTrue(m.retain)
        self.assertEqual(m.qos, 0)

    def test_qos3_rejected(self):
        body = _field("t") + b"x"
        m = parse_mqtt(_packet(3, 0x06, body))  # QoS 3 (flags 0b0110)
        self.assertIsNone(m)


class ConnackTest(unittest.TestCase):
    def test_accepted(self):
        m = parse_mqtt(_packet(2, 0, bytes([0x00, 0x00])))
        self.assertTrue(m.is_connack)
        self.assertFalse(m.session_present)
        self.assertEqual(m.return_code, 0)
        self.assertEqual(m.return_code_name, "accepted")
        self.assertFalse(m.is_refused)

    def test_bad_credentials_refused(self):
        m = parse_mqtt(_packet(2, 0, bytes([0x00, 0x04])))
        self.assertEqual(m.return_code, 4)
        self.assertEqual(m.return_code_name, "bad_username_or_password")
        self.assertTrue(m.is_refused)

    def test_session_present(self):
        m = parse_mqtt(_packet(2, 0, bytes([0x01, 0x00])))
        self.assertTrue(m.session_present)


class PacketIdTest(unittest.TestCase):
    def test_puback_packet_id(self):
        m = parse_mqtt(_packet(4, 0, (1234).to_bytes(2, "big")))
        self.assertEqual(m.packet_type_name, "PUBACK")
        self.assertEqual(m.packet_id, 1234)

    def test_subscribe_packet_id(self):
        body = (7).to_bytes(2, "big") + _field("sensors/#") + bytes([0x00])
        m = parse_mqtt(_packet(8, 0x02, body))  # SUBSCRIBE flags=0b0010
        self.assertEqual(m.packet_type_name, "SUBSCRIBE")
        self.assertEqual(m.packet_id, 7)


class FalsePositiveGuardTest(unittest.TestCase):
    def test_empty(self):
        self.assertIsNone(parse_mqtt(b""))

    def test_offset_out_of_range(self):
        self.assertIsNone(parse_mqtt(b"\x10\x00", offset=5))

    def test_reserved_type_zero(self):
        self.assertIsNone(parse_mqtt(bytes([0x00, 0x00])))

    def test_reserved_flags_mismatch(self):
        # CONNECT(1) 는 예약 플래그 0 이어야 한다 — 0b0001 은 거부.
        self.assertIsNone(parse_mqtt(bytes([0x11, 0x00])))

    def test_subscribe_wrong_flags(self):
        # SUBSCRIBE(8) 는 0b0010 이어야 한다 — 0 은 거부.
        self.assertIsNone(parse_mqtt(bytes([0x80, 0x00])))

    def test_varint_overflow(self):
        # 5바이트 연속(최상위 비트 계속 1) = 4바이트 초과 오류.
        self.assertIsNone(parse_mqtt(bytes([0x30, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF])))


class TruncationTest(unittest.TestCase):
    def test_truncated_declared_longer(self):
        # Remaining Length 10 선언하지만 본문 3바이트만.
        data = bytes([0x30, 10]) + _field("ab")[:1]
        m = parse_mqtt(data)
        self.assertIsInstance(m, Mqtt)
        self.assertTrue(m.truncated)
        self.assertEqual(m.remaining_length, 10)

    def test_truncated_connect_partial(self):
        full = _connect(client_id="device", username="u", password="p")
        m = parse_mqtt(full[:6])  # 프로토콜 이름까지만.
        # 프로토콜 이름 확인 가능하면 부분 파싱, 아니면 None — 어느 쪽도 충돌 없음.
        if m is not None:
            self.assertTrue(m.truncated)


class HelperTest(unittest.TestCase):
    def test_packet_type_name_known_and_unknown(self):
        self.assertEqual(packet_type_name(1), "CONNECT")
        self.assertEqual(packet_type_name(99), "type-99")

    def test_connack_return_name(self):
        self.assertEqual(connack_return_name(5), "not_authorized")
        self.assertEqual(connack_return_name(200), "return-200")

    def test_tables_present(self):
        self.assertEqual(MQTT_PACKET_TYPE_NAMES[3], "PUBLISH")
        self.assertEqual(MQTT_CONNACK_RETURN_NAMES[0], "accepted")


if __name__ == "__main__":
    unittest.main()
