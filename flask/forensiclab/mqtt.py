"""MQTT — MQTT Control Packet 파싱 코어(MQTT 3.1.1·일부 5.0).

:mod:`forensiclab.smpp`·:mod:`forensiclab.ucp`·:mod:`forensiclab.cimd2` 가
통신사 SMSC 접속(ESME↔SMSC) 메시징 평면이었다면 MQTT 는 **사물인터넷(IoT)
메시징 평면** — 센서·게이트웨이·모바일 앱이 브로커(broker)에 붙어
``topic`` 으로 발행(publish)/구독(subscribe)하는 경량 pub/sub 프로토콜
(OASIS 표준, 흔히 TCP 1883 평문·8883 TLS). ForensicLab 의 IoT 센서 모니터링
대상과 직접 맞닿는 평면이고, 봇넷 C2·산업제어(ICS) 텔레메트리·스마트홈
침해 분석에서 자주 마주친다.

:mod:`forensiclab.smpp` 처럼 TCP 위 **바이너리 고정 헤더 + 본문** 구조다.
모든 패킷은 ``고정 헤더``(1바이트 type/flags + Remaining Length 가변정수)로
시작하고, 그 뒤 패킷 종류별 가변 헤더·페이로드가 온다. 구조를 확실히 아는
패킷만 깊게 풀고, 나머지는 헤더와 ``payload_offset`` 으로만 가리킨다.

와이어(MQTT 3.1.1):
- **고정 헤더**: 첫 바이트 상위 4비트 = 패킷 종류(1 CONNECT·2 CONNACK·
  3 PUBLISH·4 PUBACK·8 SUBSCRIBE·12 PINGREQ·14 DISCONNECT …), 하위 4비트 =
  플래그(PUBLISH 만 DUP/QoS/RETAIN 으로 의미, 그 외는 예약 고정값).
  이어서 **Remaining Length**(1~4바이트 가변정수, 각 바이트 하위 7비트·
  최상위 비트는 연속 표시) = 가변 헤더+페이로드 길이.
- **CONNECT**(1): 프로토콜 이름(``"MQTT"`` v3.1.1·``"MQIsdp"`` v3.1)·레벨·
  connect 플래그(username/password/will/clean session)·keep-alive, 그 다음
  페이로드에 ``client_id``·(will 토픽/메시지)·**``username``·평문
  ``password``**(:mod:`forensiclab.ftp`·:mod:`forensiclab.smpp` 평문 로그인급
  노출 — 1883 평문 브로커면 자격증명 그대로 캡처).
- **CONNACK**(2): session-present + **return code**(0 수락·4 bad
  username/password·5 not authorized) — 인증 실패 반복 = 브루트포스
  (RADIUS Access-Reject·SMPP ESME_RINVPASWD 대응).
- **PUBLISH**(3): ``topic`` + (QoS>0 이면 ``packet_id``) + 페이로드(센서값·
  명령·C2 데이터 자체). topic 계층 구조가 곧 IoT 자산·디바이스 식별.
- **PUBACK/PUBREC/PUBREL/PUBCOMP/SUBACK/UNSUBACK**: ``packet_id`` 로
  요청↔응답 상관(:mod:`forensiclab.flows` IP 쌍 안, SMPP sequence_number 대응).

포렌식 핵심:
- **자격증명·브루트포스**: CONNECT ``username``/평문 ``password``·CONNACK
  ``return_code`` 4/5 반복(``is_refused``).
- **IoT 자산·C2**: PUBLISH ``topic``/SUBSCRIBE 토픽 필터가 디바이스·명령
  채널 노출, 페이로드는 ``payload_offset`` 으로 가리킴.
- **세션 상관·타임라인**: ``client_id``·``packet_id``·CONNECT→PUBLISH→
  DISCONNECT 흐름(:mod:`forensiclab.timeline`).

설계 원칙(:mod:`forensiclab.smpp` 와 동일):
- 부작용 없음·stdlib 전용·읽기 전용(입력 무변형)·``offset`` 지원.
- 패킷 종류가 0(예약)이거나, PUBLISH 외 패킷의 예약 플래그가 규격값과 다르거나,
  PUBLISH QoS 가 3(불가)이거나, CONNECT 프로토콜 이름이 ``MQTT``/``MQIsdp``
  가 아니거나, Remaining Length 가변정수가 4바이트를 넘으면 ``None``
  (TCP 스트림 오탐 가드).
- Remaining Length 가 가용 바이트보다 크면(절단) 풀 수 있는 만큼만 채우고
  ``truncated=True``. MQTT 5.0 properties 블록은 길이만큼 건너뛴다.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Tuple

__all__ = [
    "Mqtt",
    "MQTT_PACKET_TYPE_NAMES",
    "MQTT_CONNACK_RETURN_NAMES",
    "packet_type_name",
    "connack_return_name",
    "parse_mqtt",
]

# 패킷 종류(고정 헤더 첫 바이트 상위 4비트) → 이름.
MQTT_PACKET_TYPE_NAMES = {
    1: "CONNECT",
    2: "CONNACK",
    3: "PUBLISH",
    4: "PUBACK",
    5: "PUBREC",
    6: "PUBREL",
    7: "PUBCOMP",
    8: "SUBSCRIBE",
    9: "SUBACK",
    10: "UNSUBSCRIBE",
    11: "UNSUBACK",
    12: "PINGREQ",
    13: "PINGRESP",
    14: "DISCONNECT",
    15: "AUTH",  # MQTT 5.0
}

# PUBLISH 외 패킷의 예약 플래그(고정 헤더 하위 4비트)는 규격 고정값을 가진다.
# PUBREL·SUBSCRIBE·UNSUBSCRIBE 는 0b0010, 나머지는 0b0000.
_EXPECTED_FLAGS = {
    1: 0x0,
    2: 0x0,
    4: 0x0,
    5: 0x0,
    6: 0x2,
    7: 0x0,
    8: 0x2,
    9: 0x0,
    10: 0x2,
    11: 0x0,
    12: 0x0,
    13: 0x0,
    14: 0x0,
    15: 0x0,
}

# CONNACK return code(MQTT 3.1.1) → 이름. v5 reason code 는 일부만 겹친다.
MQTT_CONNACK_RETURN_NAMES = {
    0: "accepted",
    1: "unacceptable_protocol_version",
    2: "identifier_rejected",
    3: "server_unavailable",
    4: "bad_username_or_password",
    5: "not_authorized",
}

# CONNECT 가 자격증명을 싣는 패킷 종류.
_CONNECT = 1
_CONNACK = 2
_PUBLISH = 3
# packet_id(2바이트)만 가변 헤더에 싣는 확인/응답 패킷들.
_PACKET_ID_ONLY = {4, 5, 6, 7, 9, 11}
# packet_id + 페이로드(토픽 필터) 구조의 패킷들.
_SUBSCRIBE_LIKE = {8, 10}

_PROTOCOL_NAMES = (b"MQTT", b"MQIsdp")


def packet_type_name(packet_type: int) -> str:
    """패킷 종류 코드 → 이름(미정의면 ``"type-N"``)."""
    return MQTT_PACKET_TYPE_NAMES.get(packet_type, f"type-{packet_type}")


def connack_return_name(return_code: int) -> str:
    """CONNACK return code → 이름(미정의면 ``"return-N"``)."""
    return MQTT_CONNACK_RETURN_NAMES.get(return_code, f"return-{return_code}")


def _read_varint(data: bytes, pos: int, end: int) -> Optional[Tuple[int, int]]:
    """MQTT Remaining Length 가변정수를 읽는다.

    Returns ``(value, next_pos)`` 또는 ``None``(절단·4바이트 초과 오류).
    """
    multiplier = 1
    value = 0
    for _ in range(4):
        if pos >= end:
            return None  # 절단.
        b = data[pos]
        pos += 1
        value += (b & 0x7F) * multiplier
        if (b & 0x80) == 0:
            return value, pos
        multiplier *= 128
    return None  # 4바이트를 넘는 연속 = 오류(비-MQTT).


def _read_field(data: bytes, pos: int, end: int) -> Optional[Tuple[bytes, int]]:
    """2바이트 길이 접두사 + 바이트열(UTF-8 문자열/바이너리)을 읽는다.

    Returns ``(raw_bytes, next_pos)`` 또는 ``None``(절단).
    """
    if pos + 2 > end:
        return None
    n = (data[pos] << 8) | data[pos + 1]
    pos += 2
    if pos + n > end:
        return None
    return data[pos : pos + n], pos + n


def _text(raw: bytes) -> str:
    """MQTT UTF-8 문자열을 사람이 읽는 텍스트로(무손실 best-effort)."""
    return raw.decode("utf-8", "replace")


@dataclass(frozen=True)
class Mqtt:
    """파싱된 MQTT Control Packet 한 개.

    Attributes:
        packet_type: 패킷 종류 코드(1~15).
        packet_type_name: 패킷 종류 이름.
        flags: 고정 헤더 하위 4비트(원값).
        remaining_length: 선언된 Remaining Length(가변 헤더+페이로드).
        packet_length: 실제 패킷 바이트 길이(고정 헤더 포함; 절단이면 가용분).
        truncated: Remaining Length 가 가용 바이트를 넘는지(절단 캡처).
        payload_offset: 파싱하지 않은 본문/페이로드 시작 절대 오프셋.
        dup: PUBLISH 재전송 플래그(그 외 ``None``).
        qos: PUBLISH QoS 0~2(그 외 ``None``).
        retain: PUBLISH retain 플래그(그 외 ``None``).
        protocol_name: CONNECT 프로토콜 이름(``"MQTT"``/``"MQIsdp"``).
        protocol_level: CONNECT 프로토콜 레벨(4 v3.1.1·3 v3.1·5 v5.0).
        clean_session: CONNECT clean session/start 플래그.
        will_flag: CONNECT will 메시지 동반 여부.
        keep_alive: CONNECT keep-alive 초.
        client_id: CONNECT 클라이언트 식별자(세션 상관).
        will_topic: CONNECT will 토픽(있으면).
        username: CONNECT 사용자명(있으면).
        password: CONNECT 평문 패스워드(있으면; 자격증명 노출).
        topic: PUBLISH 토픽(IoT 자산·명령 채널).
        packet_id: PUBLISH(QoS>0)·확인 패킷의 패킷 식별자(요청↔응답 상관).
        session_present: CONNACK 기존 세션 재개 여부.
        return_code: CONNACK return/reason code(0 수락).
        return_code_name: CONNACK return code 이름.
    """

    packet_type: int
    packet_type_name: str
    flags: int
    remaining_length: int
    packet_length: int
    truncated: bool
    payload_offset: int
    dup: Optional[bool] = None
    qos: Optional[int] = None
    retain: Optional[bool] = None
    protocol_name: Optional[str] = None
    protocol_level: Optional[int] = None
    clean_session: Optional[bool] = None
    will_flag: Optional[bool] = None
    keep_alive: Optional[int] = None
    client_id: Optional[str] = None
    will_topic: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    topic: Optional[str] = None
    packet_id: Optional[int] = None
    session_present: Optional[bool] = None
    return_code: Optional[int] = None
    return_code_name: Optional[str] = None

    @property
    def is_connect(self) -> bool:
        """CONNECT(자격증명 운반) 여부."""
        return self.packet_type == _CONNECT

    @property
    def is_connack(self) -> bool:
        """CONNACK(연결 수락/거부) 여부."""
        return self.packet_type == _CONNACK

    @property
    def is_publish(self) -> bool:
        """PUBLISH(메시지 발행) 여부."""
        return self.packet_type == _PUBLISH

    @property
    def has_credentials(self) -> bool:
        """CONNECT 에 username/password 가 실렸는지."""
        return self.username is not None or self.password is not None

    @property
    def is_refused(self) -> bool:
        """CONNACK 연결 거부(return code != 0) 여부 — 인증 실패 단서."""
        return self.return_code is not None and self.return_code != 0


def _parse_connect(data: bytes, pos: int, body_end: int) -> Optional[dict]:
    """CONNECT 가변 헤더·페이로드를 푼다. 프로토콜 이름 불일치면 ``None``."""
    name = _read_field(data, pos, body_end)
    if name is None:
        return None
    proto_raw, pos = name
    if proto_raw not in _PROTOCOL_NAMES:
        return None  # 강한 오탐 가드 — MQTT/MQIsdp 만 CONNECT 로 인정.

    out: dict = {"protocol_name": proto_raw.decode("ascii")}
    if pos >= body_end:
        return out
    level = data[pos]
    pos += 1
    out["protocol_level"] = level
    if pos >= body_end:
        return out
    cflags = data[pos]
    pos += 1
    username_flag = bool(cflags & 0x80)
    password_flag = bool(cflags & 0x40)
    will_flag = bool(cflags & 0x04)
    out["clean_session"] = bool(cflags & 0x02)
    out["will_flag"] = will_flag
    if pos + 2 <= body_end:
        out["keep_alive"] = (data[pos] << 8) | data[pos + 1]
        pos += 2

    # MQTT 5.0: 가변 헤더 끝에 properties(가변정수 길이 + 데이터). 건너뛴다.
    if level == 5:
        vp = _read_varint(data, pos, body_end)
        if vp is None:
            return out
        plen, pos = vp
        pos += plen
        if pos > body_end:
            return out

    # 페이로드: client_id, [will props, will topic, will payload], [username], [password].
    cid = _read_field(data, pos, body_end)
    if cid is None:
        return out
    out["client_id"] = _text(cid[0])
    pos = cid[1]

    if will_flag:
        if level == 5:
            wp = _read_varint(data, pos, body_end)
            if wp is None:
                return out
            wlen, pos = wp
            pos += wlen
            if pos > body_end:
                return out
        wt = _read_field(data, pos, body_end)
        if wt is None:
            return out
        out["will_topic"] = _text(wt[0])
        pos = wt[1]
        wpld = _read_field(data, pos, body_end)  # will payload(바이너리), 건너뜀.
        if wpld is None:
            return out
        pos = wpld[1]

    if username_flag:
        un = _read_field(data, pos, body_end)
        if un is None:
            return out
        out["username"] = _text(un[0])
        pos = un[1]

    if password_flag:
        pw = _read_field(data, pos, body_end)
        if pw is None:
            return out
        out["password"] = _text(pw[0])
        pos = pw[1]

    return out


def parse_mqtt(data: bytes, offset: int = 0) -> Optional[Mqtt]:
    """MQTT Control Packet 한 개를 파싱한다.

    Args:
        data: MQTT 패킷 바이트(보통 TCP 페이로드). ``offset`` 에 고정 헤더.
        offset: 패킷이 시작하는 위치(기본 0).

    Returns:
        :class:`Mqtt`. 패킷 종류가 0(예약)이거나, PUBLISH 외 예약 플래그가
        규격값과 다르거나, PUBLISH QoS 가 3이거나, Remaining Length 가변정수가
        4바이트를 넘거나, CONNECT 프로토콜 이름이 ``MQTT``/``MQIsdp`` 가
        아니면 ``None``(TCP 스트림 오탐 가드). Remaining Length 가 가용
        바이트를 넘으면(절단) 풀 수 있는 만큼만 채우고 ``truncated=True``.
    """
    end = len(data)
    if offset < 0 or offset >= end:
        return None

    b0 = data[offset]
    ptype = (b0 >> 4) & 0x0F
    flags = b0 & 0x0F
    if ptype not in MQTT_PACKET_TYPE_NAMES:  # 0 예약 포함.
        return None

    if ptype == _PUBLISH:
        qos = (flags >> 1) & 0x03
        if qos == 3:
            return None  # QoS 3 은 불가 — 비-MQTT.
    else:
        expected = _EXPECTED_FLAGS.get(ptype)
        if expected is not None and flags != expected:
            return None  # 예약 플래그 불일치 — 비-MQTT.

    rl = _read_varint(data, offset + 1, end)
    if rl is None:
        return None
    remaining_length, var_start = rl

    avail = end - var_start
    truncated = remaining_length > avail
    body_end = var_start + (avail if truncated else remaining_length)
    packet_length = body_end - offset

    fields: dict = {}
    payload_offset = body_end  # 기본: 더 풀 본문 없음.

    if ptype == _CONNECT:
        parsed = _parse_connect(data, var_start, body_end)
        if parsed is None:
            return None
        fields.update(parsed)
        payload_offset = var_start

    elif ptype == _CONNACK:
        if var_start + 2 <= body_end:
            fields["session_present"] = bool(data[var_start] & 0x01)
            rc = data[var_start + 1]
            fields["return_code"] = rc
            fields["return_code_name"] = connack_return_name(rc)

    elif ptype == _PUBLISH:
        qos = (flags >> 1) & 0x03
        fields["dup"] = bool(flags & 0x08)
        fields["qos"] = qos
        fields["retain"] = bool(flags & 0x01)
        topic = _read_field(data, var_start, body_end)
        if topic is not None:
            fields["topic"] = _text(topic[0])
            pos = topic[1]
            if qos > 0 and pos + 2 <= body_end:
                fields["packet_id"] = (data[pos] << 8) | data[pos + 1]
                pos += 2
            payload_offset = pos
        else:
            payload_offset = var_start

    elif ptype in _PACKET_ID_ONLY or ptype in _SUBSCRIBE_LIKE:
        if var_start + 2 <= body_end:
            fields["packet_id"] = (data[var_start] << 8) | data[var_start + 1]
        payload_offset = var_start + 2 if (var_start + 2 <= body_end) else var_start

    return Mqtt(
        packet_type=ptype,
        packet_type_name=packet_type_name(ptype),
        flags=flags,
        remaining_length=remaining_length,
        packet_length=packet_length,
        truncated=truncated,
        payload_offset=payload_offset,
        **fields,
    )
