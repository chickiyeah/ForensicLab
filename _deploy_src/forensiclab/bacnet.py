"""BACnet/IP — 빌딩 자동화 제어망(BVLC/NPDU/APDU) 메시지 파싱 코어.

:mod:`forensiclab.modbus`·:mod:`forensiclab.dnp3`·:mod:`forensiclab.iec104`·
:mod:`forensiclab.s7comm` 이 **공장·발전소·전력망의 OT 제어 평면**(센서·차단기·PLC)이었다면,
BACnet 은 그 **건물(빌딩) 자동화 형제** — HVAC(공조)·조명·엘리베이터·**출입 통제(access
control)**·화재 경보를 묶는 사실상 표준(ASHRAE 135 / ISO 16484-5). ForensicLab 의 IoT 센서
모니터링 대상과 직접 맞닿고, **인터넷에 노출된 BACnet/IP 장치(UDP 47808)** 는 Shodan 단골이라
병원·데이터센터·캠퍼스 공조와 도어락이 무인증으로 드러나는 흔한 무대다.

설계상 **클래식 BACnet 은 인증·암호화가 사실상 없다**(BACnet/SC 이전 평문) — UDP 47808 에
메시지가 보이는 것 자체가 노출된 빌딩 제어 평면 정황이고, ``Who-Is`` 한 번이 장치 열거,
``WriteProperty`` 한 번이 온도 설정점·도어 릴레이 물리 조작, ``DeviceCommunicationControl``
한 번이 장치 통신 마비(DoS), ``ReinitializeDevice`` 한 번이 콜드스타트(재부팅)다.

와이어(big-endian, 3계층 — BVLC → NPDU → APDU):
- **BVLC**(BACnet Virtual Link Control, 4바이트~): Type(1: 항상 ``0x81`` — 강한 오탐 가드)·
  **Function**(1: ``0x0A`` Original-Unicast·``0x0B`` Original-Broadcast·``0x04`` Forwarded-NPDU
  앞 6바이트 B/IP 출처 주소·``0x00`` BVLC-Result 2바이트 결과 코드·NPDU 없음 등)·Length(2: BVLC
  포함 전체).
- **NPDU**(BACnet Network layer): Version(1: 항상 ``0x01`` — 강한 오탐 가드)·**Control**(1:
  bit7 망 계층 메시지(APDU 없음)·bit5 목적지(DNET/DLEN/DADR)·bit3 출처(SNET/SLEN/SADR)·
  bit2 응답 기대·bits1-0 우선순위), 라우팅이면 DNET/SNET 망 번호(장치·세그먼트 열거).
- **APDU**(망 계층 메시지가 아닐 때): 첫 바이트 상위 4비트 **PDU Type**(0 Confirmed-Request·
  1 Unconfirmed-Request·2 SimpleACK·3 ComplexACK·5 Error·6 Reject·7 Abort)+하위 4비트 플래그,
  이어서 (요청이면) Invoke ID·**Service Choice**(무슨 서비스인가).

포렌식 핵심:
- **노출된 빌딩 제어 평면·표적**: UDP 47808 자체가 BACnet 정황. ``bvlc_function_name`` 으로 식별.
- **장치 열거(정찰)**: Unconfirmed ``Who-Is``(8)/응답 ``I-Am``(0) — ``is_who_is``/``is_i_am``.
- **읽기 vs 쓰기(공격 의도)**: ``is_read``(ReadProperty 정찰)·``is_write``(WriteProperty 설정점·
  도어 물리 조작).
- **장치 마비·재부팅**: ``is_device_control``(DeviceCommunicationControl 통신 차단·
  ReinitializeDevice 콜드스타트 = DoS·증거 인멸).
- **세션·타임라인**: ``invoke_id`` 로 요청↔응답 상관(:mod:`forensiclab.timeline`,
  :mod:`forensiclab.modbus` ``transaction_id``·:mod:`forensiclab.s7comm` ``pdu_reference`` 대응).

설계 원칙(:mod:`forensiclab.s7comm` 와 동일):
- 부작용 없음·stdlib 전용·읽기 전용(입력 무변형)·``offset`` 지원.
- BVLC Type 이 ``0x81`` 이 아니거나, Function 이 알려진 집합 밖이거나, NPDU 가 있는 메시지인데
  Version 이 ``0x01`` 이 아니면 ``None``(UDP 스트림 오탐 가드 — 두 계층 상수가 겹쳐 오인 최소).
- NPDU/APDU 본문은 ``npdu_offset``/``apdu_offset`` 으로만 가리키고 깊게 풀지 않으며, APDU 의
  PDU Type·Invoke ID·Service Choice 만 디코드한다. 선언 길이가 가용 바이트를 넘으면(절단 캡처)
  풀 수 있는 만큼만 채우고 ``truncated=True``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

__all__ = [
    "BACnet",
    "BVLC_FUNCTION_NAMES",
    "BACNET_PDU_TYPE_NAMES",
    "BACNET_CONFIRMED_SERVICES",
    "BACNET_UNCONFIRMED_SERVICES",
    "bvlc_function_name",
    "pdu_type_name",
    "service_name",
    "parse_bacnet",
]

# BVLC Type(항상 0x81 — 강한 오탐 가드).
_BVLC_TYPE = 0x81

# NPDU Version(항상 0x01 — 강한 오탐 가드).
_NPDU_VERSION = 0x01

# BVLC Function → 이름.
BVLC_FUNCTION_NAMES = {
    0x00: "BVLC-Result",
    0x01: "Write-Broadcast-Distribution-Table",
    0x02: "Read-Broadcast-Distribution-Table",
    0x03: "Read-Broadcast-Distribution-Table-Ack",
    0x04: "Forwarded-NPDU",
    0x05: "Register-Foreign-Device",
    0x06: "Read-Foreign-Device-Table",
    0x07: "Read-Foreign-Device-Table-Ack",
    0x08: "Delete-Foreign-Device-Table-Entry",
    0x09: "Distribute-Broadcast-To-Network",
    0x0A: "Original-Unicast-NPDU",
    0x0B: "Original-Broadcast-NPDU",
    0x0C: "Secure-BVLL",
}

# NPDU 를 뒤따르는(APDU 운반) BVLC Function 집합.
_BVLC_WITH_NPDU = frozenset({0x04, 0x09, 0x0A, 0x0B})

# Forwarded-NPDU 는 BVLC 헤더 뒤 6바이트 B/IP 출처 주소를 둔다.
_BVLC_FORWARDED = 0x04

# BVLC-Result 는 NPDU 없이 2바이트 결과 코드를 둔다.
_BVLC_RESULT = 0x00

# APDU PDU Type(첫 바이트 상위 4비트) → 이름.
BACNET_PDU_TYPE_NAMES = {
    0x0: "Confirmed-Request",
    0x1: "Unconfirmed-Request",
    0x2: "SimpleACK",
    0x3: "ComplexACK",
    0x4: "SegmentACK",
    0x5: "Error",
    0x6: "Reject",
    0x7: "Abort",
}

# Confirmed Service Choice → 이름(BACnet-Confirmed-Service-Choice).
BACNET_CONFIRMED_SERVICES = {
    0: "acknowledgeAlarm",
    1: "confirmedCOVNotification",
    2: "confirmedEventNotification",
    3: "getAlarmSummary",
    4: "getEnrollmentSummary",
    5: "subscribeCOV",
    6: "atomicReadFile",
    7: "atomicWriteFile",
    8: "addListElement",
    9: "removeListElement",
    10: "createObject",
    11: "deleteObject",
    12: "readProperty",
    13: "readPropertyConditional",
    14: "readPropertyMultiple",
    15: "writeProperty",
    16: "writePropertyMultiple",
    17: "deviceCommunicationControl",
    18: "confirmedPrivateTransfer",
    19: "confirmedTextMessage",
    20: "reinitializeDevice",
    21: "vtOpen",
    22: "vtClose",
    23: "vtData",
    24: "authenticate",
    25: "requestKey",
    26: "readRange",
    27: "lifeSafetyOperation",
    28: "subscribeCOVProperty",
    29: "getEventInformation",
    30: "subscribeCOVPropertyMultiple",
    31: "confirmedCOVNotificationMultiple",
}

# Unconfirmed Service Choice → 이름(BACnet-Unconfirmed-Service-Choice).
BACNET_UNCONFIRMED_SERVICES = {
    0: "i-Am",
    1: "i-Have",
    2: "unconfirmedCOVNotification",
    3: "unconfirmedEventNotification",
    4: "unconfirmedPrivateTransfer",
    5: "unconfirmedTextMessage",
    6: "timeSynchronization",
    7: "who-Has",
    8: "who-Is",
    9: "utcTimeSynchronization",
    10: "writeGroup",
    11: "unconfirmedCOVNotificationMultiple",
}

# PDU Type 코드.
_PDU_CONFIRMED_REQUEST = 0x0
_PDU_UNCONFIRMED_REQUEST = 0x1
_PDU_SIMPLE_ACK = 0x2
_PDU_COMPLEX_ACK = 0x3
_PDU_SEGMENT_ACK = 0x4
_PDU_ERROR = 0x5
_PDU_REJECT = 0x6
_PDU_ABORT = 0x7

# Confirmed-Request 첫 바이트 SEG 플래그(분할이면 seq/window 2바이트 추가).
_APDU_SEG_FLAG = 0x08

# 읽기/쓰기(속성) Confirmed Service.
_READ_SERVICES = frozenset({12, 14, 26})        # readProperty/Multiple/readRange.
_WRITE_SERVICES = frozenset({15, 16})           # writeProperty/Multiple.

# 장치 제어(DoS·재부팅) Confirmed Service.
_DEVICE_CONTROL_SERVICES = frozenset({17, 20})  # deviceCommunicationControl/reinitializeDevice.


def bvlc_function_name(code: int) -> str:
    """BVLC Function 코드 → 이름(미정의면 ``"bvlc-0xNN"``)."""
    return BVLC_FUNCTION_NAMES.get(code, f"bvlc-0x{code:02x}")


def pdu_type_name(code: int) -> str:
    """APDU PDU Type 코드 → 이름(미정의면 ``"pdu-N"``)."""
    return BACNET_PDU_TYPE_NAMES.get(code, f"pdu-{code}")


def service_name(pdu_type: int, choice: int) -> str:
    """Service Choice → 이름. PDU Type 에 따라 confirmed/unconfirmed 표를 고른다.

    Confirmed 계열(Confirmed-Request·ComplexACK 등)은 confirmed 표, Unconfirmed-Request 는
    unconfirmed 표. 미정의면 ``"service-N"``.
    """
    if pdu_type == _PDU_UNCONFIRMED_REQUEST:
        return BACNET_UNCONFIRMED_SERVICES.get(choice, f"service-{choice}")
    return BACNET_CONFIRMED_SERVICES.get(choice, f"service-{choice}")


@dataclass(frozen=True)
class BACnet:
    """파싱된 BACnet/IP 메시지 한 개.

    Attributes:
        bvlc_function: BVLC Function 코드.
        bvlc_function_name: BVLC Function 이름.
        bvlc_length: BVLC Length 필드(BVLC 헤더 포함 전체 길이).
        result_code: BVLC-Result 결과 코드(BVLC-Result 일 때만, 그 외 ``None``).
        npdu_version: NPDU Version(NPDU 없는 BVLC 면 ``None``).
        npdu_control: NPDU Control 옥텟(NPDU 없으면 ``None``).
        is_network_message: NPDU Control bit7(망 계층 메시지 — APDU 없음) 여부.
        network_message_type: 망 계층 메시지 타입(``is_network_message`` 일 때만).
        expecting_reply: NPDU Control bit2(응답 기대) 여부.
        dnet: 목적지 망 번호(라우팅, 없으면 ``None``).
        snet: 출처 망 번호(라우팅, 없으면 ``None``).
        pdu_type: APDU PDU Type(상위 4비트; APDU 없으면 ``None``).
        pdu_type_name: PDU Type 이름(APDU 있을 때만).
        invoke_id: APDU Invoke ID(요청/응답 상관; 해당 PDU 에만, 그 외 ``None``).
        service_choice: Service Choice 코드(해당 PDU 에만, 그 외 ``None``).
        service_name: Service 이름(``service_choice`` 있을 때만).
        npdu_offset: NPDU 시작 절대 오프셋(NPDU 없으면 BVLC 본문 시작).
        apdu_offset: APDU 시작 절대 오프셋(APDU 없으면 NPDU 끝/본문 끝).
        truncated: 선언 길이가 가용 바이트를 넘는지(절단 캡처).
        packet_length: BVLC Length(헤더 포함 전체 길이).
    """

    bvlc_function: int
    bvlc_function_name: str
    bvlc_length: int
    result_code: Optional[int] = None
    npdu_version: Optional[int] = None
    npdu_control: Optional[int] = None
    is_network_message: bool = False
    network_message_type: Optional[int] = None
    expecting_reply: bool = False
    dnet: Optional[int] = None
    snet: Optional[int] = None
    pdu_type: Optional[int] = None
    pdu_type_name: Optional[str] = None
    invoke_id: Optional[int] = None
    service_choice: Optional[int] = None
    service_name: Optional[str] = None
    npdu_offset: int = 0
    apdu_offset: int = 0
    truncated: bool = False
    packet_length: int = 0

    @property
    def is_confirmed_request(self) -> bool:
        """Confirmed-Request(응답 요구 서비스) 여부."""
        return self.pdu_type == _PDU_CONFIRMED_REQUEST

    @property
    def is_unconfirmed_request(self) -> bool:
        """Unconfirmed-Request(브로드캐스트 정찰·통지) 여부."""
        return self.pdu_type == _PDU_UNCONFIRMED_REQUEST

    @property
    def is_who_is(self) -> bool:
        """Who-Is(장치 열거 정찰) 여부."""
        return self.pdu_type == _PDU_UNCONFIRMED_REQUEST and self.service_choice == 8

    @property
    def is_i_am(self) -> bool:
        """I-Am(장치 존재 응답) 여부."""
        return self.pdu_type == _PDU_UNCONFIRMED_REQUEST and self.service_choice == 0

    @property
    def is_read(self) -> bool:
        """ReadProperty 계열(속성 정찰) Confirmed-Request 여부."""
        return self.pdu_type == _PDU_CONFIRMED_REQUEST and self.service_choice in _READ_SERVICES

    @property
    def is_write(self) -> bool:
        """WriteProperty 계열(설정점·도어 물리 조작) Confirmed-Request 여부."""
        return self.pdu_type == _PDU_CONFIRMED_REQUEST and self.service_choice in _WRITE_SERVICES

    @property
    def is_device_control(self) -> bool:
        """DeviceCommunicationControl·ReinitializeDevice(DoS·콜드스타트) 여부."""
        return (self.pdu_type == _PDU_CONFIRMED_REQUEST
                and self.service_choice in _DEVICE_CONTROL_SERVICES)

    @property
    def is_error(self) -> bool:
        """Error/Reject/Abort 응답 여부."""
        return self.pdu_type in (_PDU_ERROR, _PDU_REJECT, _PDU_ABORT)


def _parse_apdu(data: bytes, off: int, end: int, msg: dict) -> bool:
    """APDU 의 PDU Type·Invoke ID·Service Choice 만 디코드해 ``msg`` 에 채운다.

    Returns: 절단으로 일부만 채웠으면 ``True``.
    """
    if off >= end:
        return True  # APDU 가 통째로 잘림.
    first = data[off]
    pdu_type = (first >> 4) & 0x0F
    msg["pdu_type"] = pdu_type
    msg["pdu_type_name"] = pdu_type_name(pdu_type)

    if pdu_type == _PDU_UNCONFIRMED_REQUEST:
        # [type|flags][service choice]
        if off + 1 >= end:
            return True
        choice = data[off + 1]
        msg["service_choice"] = choice
        msg["service_name"] = service_name(pdu_type, choice)
        return False

    if pdu_type == _PDU_CONFIRMED_REQUEST:
        # [type|SEG/MOR/SA][max segs|max apdu][invoke id]([seq][window])[service choice]
        if off + 2 >= end:
            return True
        msg["invoke_id"] = data[off + 2]
        choice_off = off + 3
        if first & _APDU_SEG_FLAG:
            choice_off += 2  # sequence number + proposed window size.
        if choice_off >= end:
            return True
        choice = data[choice_off]
        msg["service_choice"] = choice
        msg["service_name"] = service_name(pdu_type, choice)
        return False

    if pdu_type == _PDU_SIMPLE_ACK:
        # [type|0][invoke id][service ACK choice]
        if off + 2 >= end:
            return True
        msg["invoke_id"] = data[off + 1]
        choice = data[off + 2]
        msg["service_choice"] = choice
        msg["service_name"] = service_name(pdu_type, choice)
        return False

    if pdu_type == _PDU_COMPLEX_ACK:
        # [type|SEG/MOR][invoke id]([seq][window])[service ACK choice]
        if off + 1 >= end:
            return True
        msg["invoke_id"] = data[off + 1]
        choice_off = off + 2
        if first & _APDU_SEG_FLAG:
            choice_off += 2
        if choice_off >= end:
            return True
        choice = data[choice_off]
        msg["service_choice"] = choice
        msg["service_name"] = service_name(pdu_type, choice)
        return False

    if pdu_type in (_PDU_ERROR, _PDU_REJECT, _PDU_ABORT):
        # [type|...][invoke id][error/reject/abort detail]
        if off + 1 >= end:
            return True
        msg["invoke_id"] = data[off + 1]
        return False

    # SegmentACK 등 그 외: invoke id 위치만 보수적으로.
    if off + 2 < end:
        msg["invoke_id"] = data[off + 2]
    return False


def parse_bacnet(data: bytes, offset: int = 0) -> Optional[BACnet]:
    """BACnet/IP 메시지 한 개를 파싱한다(BVLC + NPDU + APDU).

    Args:
        data: UDP 47808 페이로드(``offset`` 에 BVLC 헤더).
        offset: 메시지가 시작하는 위치(기본 0).

    Returns:
        :class:`BACnet`. BVLC Type 이 ``0x81`` 이 아니거나, Function 이 알려진 집합 밖이거나,
        NPDU 가 있는 메시지인데 Version 이 ``0x01`` 이 아니면 ``None``(UDP 스트림 오탐 가드).
        헤더/본문이 가용 바이트를 넘으면(절단) 풀 수 있는 만큼만 채우고 ``truncated=True``.
    """
    end = len(data)
    if offset < 0 or offset + 4 > end:
        return None  # BVLC 헤더 4바이트 필요.

    # --- BVLC ---
    if data[offset] != _BVLC_TYPE:
        return None  # BVLC Type 은 항상 0x81.
    bvlc_function = data[offset + 1]
    if bvlc_function not in BVLC_FUNCTION_NAMES:
        return None  # 알려지지 않은 Function = 비-BACnet 오탐 가드.
    bvlc_length = (data[offset + 2] << 8) | data[offset + 3]

    msg: dict = {
        "bvlc_function": bvlc_function,
        "bvlc_function_name": bvlc_function_name(bvlc_function),
        "bvlc_length": bvlc_length,
        "packet_length": bvlc_length,
    }
    truncated = False

    # BVLC-Result: NPDU 없이 2바이트 결과 코드.
    if bvlc_function == _BVLC_RESULT:
        body = offset + 4
        msg["npdu_offset"] = body
        msg["apdu_offset"] = body
        if body + 2 <= end:
            msg["result_code"] = (data[body] << 8) | data[body + 1]
        else:
            truncated = True
        msg["truncated"] = truncated or (bvlc_length > end - offset)
        return BACnet(**msg)

    # NPDU 를 운반하지 않는 BVLC(분배 테이블 관리 등): BVLC 만.
    if bvlc_function not in _BVLC_WITH_NPDU:
        body = offset + 4
        msg["npdu_offset"] = body
        msg["apdu_offset"] = body
        msg["truncated"] = bvlc_length > end - offset
        return BACnet(**msg)

    # Forwarded-NPDU: BVLC 뒤 6바이트 B/IP 출처 주소.
    npdu_off = offset + 4
    if bvlc_function == _BVLC_FORWARDED:
        npdu_off += 6
    msg["npdu_offset"] = npdu_off

    # --- NPDU ---
    if npdu_off >= end:
        msg["apdu_offset"] = npdu_off
        msg["truncated"] = True
        return BACnet(**msg)
    if data[npdu_off] != _NPDU_VERSION:
        return None  # NPDU Version 은 항상 0x01(오탐 가드).
    if npdu_off + 1 >= end:
        msg["npdu_version"] = _NPDU_VERSION
        msg["apdu_offset"] = npdu_off + 1
        msg["truncated"] = True
        return BACnet(**msg)

    control = data[npdu_off + 1]
    msg["npdu_version"] = _NPDU_VERSION
    msg["npdu_control"] = control
    msg["expecting_reply"] = bool(control & 0x04)
    has_dest = bool(control & 0x20)
    has_src = bool(control & 0x08)
    is_net_msg = bool(control & 0x80)
    msg["is_network_message"] = is_net_msg

    p = npdu_off + 2
    # 목적지: DNET(2)+DLEN(1)+DADR(DLEN).
    if has_dest:
        if p + 3 > end:
            msg["apdu_offset"] = p
            msg["truncated"] = True
            return BACnet(**msg)
        msg["dnet"] = (data[p] << 8) | data[p + 1]
        dlen = data[p + 2]
        p += 3 + dlen
    # 출처: SNET(2)+SLEN(1)+SADR(SLEN).
    if has_src:
        if p + 3 > end:
            msg["apdu_offset"] = min(p, end)
            msg["truncated"] = True
            return BACnet(**msg)
        msg["snet"] = (data[p] << 8) | data[p + 1]
        slen = data[p + 2]
        p += 3 + slen
    # 목적지가 있으면 Hop Count(1).
    if has_dest:
        p += 1

    if is_net_msg:
        # 망 계층 메시지: APDU 없음, 메시지 타입 1바이트.
        if p < end:
            msg["network_message_type"] = data[p]
        else:
            truncated = True
        msg["apdu_offset"] = min(p, end)
        msg["truncated"] = truncated or p > end or (bvlc_length > end - offset)
        return BACnet(**msg)

    # --- APDU ---
    msg["apdu_offset"] = min(p, end)
    apdu_trunc = _parse_apdu(data, p, end, msg)
    msg["truncated"] = apdu_trunc or p > end or (bvlc_length > end - offset)
    return BACnet(**msg)
