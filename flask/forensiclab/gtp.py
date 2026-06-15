"""GTP(GPRS Tunneling Protocol) 헤더 파싱 코어 (3GPP TS 29.060 GTPv1·TS 29.274 GTPv2-C).

:mod:`forensiclab.gre`·:mod:`forensiclab.l2tp`·:mod:`forensiclab.esp`·
:mod:`forensiclab.wireguard` 와 같은 **터널 운반층 묶음**의 한 형제이지만, 그것들이
기업·개인 VPN 인 데 비해 GTP 는 **이동통신 코어망(GPRS/UMTS/LTE/5G NSA)의 내부
터널**이다. 단말(UE)의 사용자 트래픽은 무선 구간을 지나 기지국↔게이트웨이
(SGSN/GGSN·S-GW/P-GW) 사이를 **GTP 터널로 캡슐화**되어 흐른다. 두 평면으로 갈린다:

- **GTP-C(제어, UDP 2123)**: 세션(PDP/EPS 베어러) 생성·수정·삭제 시그널링.
- **GTP-U(사용자, UDP 2152)**: 단말의 실제 IP 패킷을 ``G-PDU``(메시지 타입 255)로
  캡슐화해 나르는 데이터 평면. :mod:`forensiclab.gre` 처럼 **안의 IP 패킷이 평문**으로
  그대로 실려, GTP-U 헤더를 벗기면 단말 트래픽을 그대로 복원·관찰할 수 있다.

GTP-U 가 캡처에 보이는 것 자체가 **코어망 내부 트래픽**(로밍 인터페이스·법집행
합법감청 LI·운영자 백홀·잘못 노출된 코어 장비)이라는 강한 정황이며, 비정상 포트의
GTP 는 **GTP-in-GTP 터널링·코어망 침투·시그널링 폭주(GTP flooding) 정찰** 단서다.

GTPv1 헤더(최소 8바이트, big-endian):
- 1바이트 Flags: Version(상위 3비트, 1)·Protocol Type(PT, 1=GTP·0=GTP')·예약(0)·
  **E**(확장 헤더)·**S**(시퀀스 번호)·**PN**(N-PDU 번호) 플래그.
- 1바이트 Message Type.
- 2바이트 Length(**8바이트 고정 헤더 이후** 바이트 수).
- 4바이트 **TEID**(Tunnel Endpoint Identifier) — 수신측이 터널을 식별하는 32비트
  핸들. :mod:`forensiclab.esp` 의 SPI·:mod:`forensiclab.pptp` 의 Call ID·
  :mod:`forensiclab.wireguard` 의 sender_index 에 대응하는 **세션 귀속 키**로,
  같은 IP 쌍 안에서 어느 베어러/세션인지 못 박고 양방향 터널을 상관한다.
- E/S/PN 중 하나라도 켜지면 **선택 4바이트**(Sequence Number 2 + N-PDU Number 1 +
  Next Extension Header Type 1)가 따라붙는다(셋 다 안 켜지면 헤더는 8바이트).

GTPv2-C 헤더(LTE/EPC 제어; 최소 8바이트, big-endian):
- 1바이트 Flags: Version(상위 3비트, 2)·**P**(Piggyback)·**T**(TEID 존재) 플래그.
- 1바이트 Message Type.
- 2바이트 Length(**처음 4바이트 이후** 바이트 수).
- T=1 이면 4바이트 TEID, 이어서 3바이트 Sequence Number + 1바이트 예약.
- T=0(예: Create Session 직전 일부)이면 TEID 없이 3바이트 Sequence + 1바이트 예약.

이후 본문 IE(Information Element) TLV 는 **풀지 않는다**(버전·옵션·암호 의존이 커
오파싱 위험) — 확실한 평문 헤더 필드(version·message_type·length·teid·sequence)만
풀고 본문은 ``payload_offset`` 으로 가리킨다. GTP-U G-PDU 의 경우 그 오프셋이 곧
캡슐화된 단말 IP 패킷의 시작이라, :mod:`forensiclab.gre` 와 같은 방식으로 안쪽
패킷을 이어서 파싱할 수 있다.

침해/사고 분석에서 GTP 가 드러내는 것:

- **코어망 트래픽 존재·평면 식별**: GTP-C(2123)=시그널링·GTP-U(2152)=사용자 데이터.
  비표준 포트의 유효 GTP 헤더는 코어망 침투·은닉 터널 정황.
- **세션 귀속·터널 상관(TEID)**: 32비트 TEID 로 베어러/세션을 못 박고, 같은 IP 쌍의
  양방향 GTP-U 를 한 터널로 묶는다(:mod:`forensiclab.flows`). 세션 재생성 시 바뀌는
  TEID 로 수명을 추적.
- **시그널링 수명·실패(GTP-C)**: Create/Update/Delete (PDP|Session) Request/Response
  쌍과 sequence 로 세션 개통·수정·종료, Version-Not-Supported·Error-Indication 로
  실패·끊김을 추적.
- **캡슐 단말 트래픽 복원(GTP-U)**: G-PDU(255) 의 ``payload_offset`` 이 평문 단말 IP
  패킷이라 안쪽 통신을 그대로 관찰(:mod:`forensiclab.gre` 형제).

설계 원칙(다른 파서와 동일):
- 부작용 없음·stdlib 전용·읽기 전용.
- 견고: 8바이트 미만이거나 Version 이 1·2 가 아니거나(GTP' 등 제외), GTPv1 인데
  PT≠1 또는 예약 비트≠0 이거나, Message Type 이 알려진 집합이 아니면 예외 대신
  ``None``(오탐 가드). 선택 필드는 바이트가 모자라면 해당 필드만 ``None``(부분 파싱).
- 한 UDP 페이로드/스트림이 여러 메시지를 담을 수 있어 ``offset`` 과 ``length`` 로
  다음 메시지를 이어 읽을 수 있다.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Optional

__all__ = [
    "GTP_C_PORT",
    "GTP_U_PORT",
    "GTP_PRIME_PORT",
    "GTP_VERSION_1",
    "GTP_VERSION_2",
    "ECHO_REQUEST",
    "ECHO_RESPONSE",
    "VERSION_NOT_SUPPORTED",
    "ERROR_INDICATION",
    "SUPPORTED_EXT_HEADERS_NOTIFICATION",
    "CREATE_PDP_CONTEXT_REQUEST",
    "CREATE_PDP_CONTEXT_RESPONSE",
    "UPDATE_PDP_CONTEXT_REQUEST",
    "UPDATE_PDP_CONTEXT_RESPONSE",
    "DELETE_PDP_CONTEXT_REQUEST",
    "DELETE_PDP_CONTEXT_RESPONSE",
    "G_PDU",
    "CREATE_SESSION_REQUEST",
    "CREATE_SESSION_RESPONSE",
    "MODIFY_BEARER_REQUEST",
    "MODIFY_BEARER_RESPONSE",
    "DELETE_SESSION_REQUEST",
    "DELETE_SESSION_RESPONSE",
    "GTPMessage",
    "looks_like_gtp",
    "parse_gtp",
]

# GTP 관용 포트(UDP).
GTP_C_PORT = 2123  # GTP-C 제어 평면(시그널링).
GTP_U_PORT = 2152  # GTP-U 사용자 평면(G-PDU 데이터 터널).
GTP_PRIME_PORT = 3386  # GTP'(과금/CDR; PT=0, 본 파서 미지원).

GTP_VERSION_1 = 1
GTP_VERSION_2 = 2

# GTPv1 메시지 타입(TS 29.060; 공통·GTP-C·GTP-U 핵심).
ECHO_REQUEST = 1
ECHO_RESPONSE = 2
VERSION_NOT_SUPPORTED = 3
SUPPORTED_EXT_HEADERS_NOTIFICATION = 31
ERROR_INDICATION = 26
CREATE_PDP_CONTEXT_REQUEST = 16
CREATE_PDP_CONTEXT_RESPONSE = 17
UPDATE_PDP_CONTEXT_REQUEST = 18
UPDATE_PDP_CONTEXT_RESPONSE = 19
DELETE_PDP_CONTEXT_REQUEST = 20
DELETE_PDP_CONTEXT_RESPONSE = 21
G_PDU = 255  # 캡슐화된 단말 IP 패킷(데이터 평면).

# GTPv2-C 메시지 타입(TS 29.274; LTE/EPC 핵심).
CREATE_SESSION_REQUEST = 32
CREATE_SESSION_RESPONSE = 33
MODIFY_BEARER_REQUEST = 34
MODIFY_BEARER_RESPONSE = 35
DELETE_SESSION_REQUEST = 36
DELETE_SESSION_RESPONSE = 37

_V1_MESSAGE_NAMES = {
    ECHO_REQUEST: "Echo-Request",
    ECHO_RESPONSE: "Echo-Response",
    VERSION_NOT_SUPPORTED: "Version-Not-Supported",
    16: "Create-PDP-Context-Request",
    17: "Create-PDP-Context-Response",
    18: "Update-PDP-Context-Request",
    19: "Update-PDP-Context-Response",
    20: "Delete-PDP-Context-Request",
    21: "Delete-PDP-Context-Response",
    26: "Error-Indication",
    27: "PDU-Notification-Request",
    28: "PDU-Notification-Response",
    31: "Supported-Extension-Headers-Notification",
    G_PDU: "G-PDU",
}

_V2_MESSAGE_NAMES = {
    ECHO_REQUEST: "Echo-Request",
    ECHO_RESPONSE: "Echo-Response",
    VERSION_NOT_SUPPORTED: "Version-Not-Supported-Indication",
    32: "Create-Session-Request",
    33: "Create-Session-Response",
    34: "Modify-Bearer-Request",
    35: "Modify-Bearer-Response",
    36: "Delete-Session-Request",
    37: "Delete-Session-Response",
    70: "Downlink-Data-Notification",
    170: "Release-Access-Bearers-Request",
    171: "Release-Access-Bearers-Response",
}


@dataclass(frozen=True)
class GTPMessage:
    """파싱된 GTP 메시지 한 개(평문 헤더 필드만).

    Attributes:
        version: GTP 버전(1=GTPv1·2=GTPv2-C).
        message_type: 메시지 타입(버전별 의미; ``message_name`` 참고).
        length: Length 필드(v1=8바이트 헤더 이후·v2=4바이트 이후 바이트 수).
        teid: Tunnel Endpoint Identifier(32비트; v2 는 T=0 이면 None) — 세션 귀속 키.
        sequence_number: 시퀀스 번호(v1 S 플래그/선택·v2 3바이트; 없으면 None).
        protocol_type: GTPv1 PT 플래그(1=GTP; v2 는 None).
        next_extension_header_type: GTPv1 E 플래그 시 다음 확장 헤더 타입(없으면 None).
        npdu_number: GTPv1 PN 플래그 시 N-PDU 번호(없으면 None).
        has_teid: v2 에서 TEID 필드가 존재했는지(T 플래그).
        payload_offset: 고정 헤더 끝 = 본문 IE 또는 캡슐 IP 패킷 시작 오프셋
            (:mod:`forensiclab.gre`/:mod:`forensiclab.esp` 와 같은 의미; ``data`` 기준).
            가변 확장 헤더(GTPv1 E 플래그)는 포함하지 않는다.
    """

    version: int
    message_type: int
    length: int
    teid: Optional[int] = None
    sequence_number: Optional[int] = None
    protocol_type: Optional[int] = None
    next_extension_header_type: Optional[int] = None
    npdu_number: Optional[int] = None
    has_teid: bool = True
    payload_offset: int = 0

    @property
    def message_name(self) -> str:
        """메시지 타입 이름(버전별; 알 수 없으면 ``message_<n>``)."""
        names = _V1_MESSAGE_NAMES if self.version == GTP_VERSION_1 else _V2_MESSAGE_NAMES
        return names.get(self.message_type, f"message_{self.message_type}")

    @property
    def is_user_data(self) -> bool:
        """GTP-U G-PDU(캡슐화된 단말 IP 패킷)인지 — ``payload_offset`` 이 안쪽 IP."""
        return self.version == GTP_VERSION_1 and self.message_type == G_PDU

    @property
    def is_echo(self) -> bool:
        """Echo Request/Response 인지(경로 가용성 점검·생존 신호)."""
        return self.message_type in (ECHO_REQUEST, ECHO_RESPONSE)

    @property
    def is_session_create(self) -> bool:
        """세션/컨텍스트 생성 요청인지(터널 개통; v1 16·v2 32)."""
        return (self.version == GTP_VERSION_1 and self.message_type == CREATE_PDP_CONTEXT_REQUEST) or (
            self.version == GTP_VERSION_2 and self.message_type == CREATE_SESSION_REQUEST
        )

    @property
    def is_session_delete(self) -> bool:
        """세션/컨텍스트 삭제 요청인지(터널 종료; v1 20·v2 36)."""
        return (self.version == GTP_VERSION_1 and self.message_type == DELETE_PDP_CONTEXT_REQUEST) or (
            self.version == GTP_VERSION_2 and self.message_type == DELETE_SESSION_REQUEST
        )

    @property
    def is_error_indication(self) -> bool:
        """GTPv1 Error Indication 인지 — 알 수 없는 TEID 수신(터널 불일치·끊김)."""
        return self.version == GTP_VERSION_1 and self.message_type == ERROR_INDICATION


def looks_like_gtp(data: bytes, offset: int = 0) -> bool:
    """``offset`` 바이트가 파싱 가능한 GTP 메시지처럼 보이는지(가벼운 가드).

    Version·플래그·메시지 타입 집합을 검사하므로 비교적 강하다 — UDP 2123/2152
    문맥과 함께 쓰면 더 안전하다.
    """
    return parse_gtp(data, offset) is not None


def parse_gtp(data: bytes, offset: int = 0) -> Optional[GTPMessage]:
    """단일 GTP 메시지(GTPv1 또는 GTPv2-C)를 파싱한다.

    Args:
        data: GTP 바이트(UDP 2123/2152 페이로드).
        offset: 파싱 시작 위치(기본 0; 한 페이로드 다중 메시지 시 이어 읽기).

    Returns:
        :class:`GTPMessage`. 8바이트 미만이거나 Version 이 1·2 가 아니거나, GTPv1
        인데 PT≠1 또는 예약 비트≠0 이거나, Message Type 이 알려진 집합이 아니면
        ``None``(오탐 가드). 선택 필드는 바이트가 모자라면 해당 필드만 ``None``.
    """
    if not isinstance(data, (bytes, bytearray)):
        return None
    if len(data) - offset < 8:
        return None

    flags = data[offset]
    version = (flags >> 5) & 0x07

    def u16(at: int) -> Optional[int]:
        if len(data) - at < 2:
            return None
        return struct.unpack_from(">H", data, at)[0]

    def u24(at: int) -> Optional[int]:
        if len(data) - at < 3:
            return None
        return (data[at] << 16) | (data[at + 1] << 8) | data[at + 2]

    def u32(at: int) -> Optional[int]:
        if len(data) - at < 4:
            return None
        return struct.unpack_from(">I", data, at)[0]

    if version == GTP_VERSION_1:
        protocol_type = (flags >> 4) & 0x01
        reserved = (flags >> 3) & 0x01
        e_flag = (flags >> 2) & 0x01
        s_flag = (flags >> 1) & 0x01
        pn_flag = flags & 0x01
        if protocol_type != 1 or reserved != 0:
            return None  # GTP'(PT=0) 또는 손상 헤더 — 오탐 가드.

        message_type = data[offset + 1]
        if message_type not in _V1_MESSAGE_NAMES:
            return None
        length = u16(offset + 2)
        teid = u32(offset + 4)

        sequence_number: Optional[int] = None
        npdu_number: Optional[int] = None
        next_ext: Optional[int] = None
        optional_present = e_flag or s_flag or pn_flag
        header_len = 12 if optional_present else 8
        if optional_present:
            if s_flag:
                sequence_number = u16(offset + 8)
            if pn_flag and len(data) - (offset + 10) >= 1:
                npdu_number = data[offset + 10]
            if e_flag and len(data) - (offset + 11) >= 1:
                next_ext = data[offset + 11]

        # 본문(IE 또는 캡슐 IP) 시작 = 고정 헤더 끝(:mod:`forensiclab.gre`/esp 와 동일).
        # 가변 확장 헤더(E 플래그)는 풀지 않으며 next_extension_header_type 로 존재만 표시.
        payload_offset = offset + header_len

        return GTPMessage(
            version=GTP_VERSION_1,
            message_type=message_type,
            length=length if length is not None else 0,
            teid=teid,
            sequence_number=sequence_number,
            protocol_type=protocol_type,
            next_extension_header_type=next_ext,
            npdu_number=npdu_number,
            has_teid=True,
            payload_offset=payload_offset,
        )

    if version == GTP_VERSION_2:
        t_flag = (flags >> 3) & 0x01
        message_type = data[offset + 1]
        if message_type not in _V2_MESSAGE_NAMES:
            return None
        length = u16(offset + 2)

        pos = offset + 4
        teid: Optional[int] = None
        if t_flag:
            teid = u32(pos)
            pos += 4
        sequence_number = u24(pos)
        header_len = 12 if t_flag else 8
        payload_offset = offset + header_len  # 본문 IE 시작 = 헤더 끝.

        return GTPMessage(
            version=GTP_VERSION_2,
            message_type=message_type,
            length=length if length is not None else 0,
            teid=teid,
            sequence_number=sequence_number,
            protocol_type=None,
            has_teid=bool(t_flag),
            payload_offset=payload_offset,
        )

    return None  # GTP'(v0)·미지원 버전 — 오탐 가드.
