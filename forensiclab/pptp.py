"""PPTP 제어 채널 메시지 파싱 코어 (RFC 2637, TCP 1723).

:mod:`forensiclab.l2tp`(UDP 1701)·:mod:`forensiclab.openvpn`·
:mod:`forensiclab.wireguard` 와 같은 **VPN 터널 묶음**의 한 형제이자 가장 오래된
대중 VPN — **Microsoft PPTP**(Windows 95/Dial-Up Networking 시절부터 내장). PPTP 는
제어와 데이터가 두 채널로 갈린다: **제어 채널은 TCP 1723 위 평문**(본 모듈), **데이터
채널은 Enhanced GRE**(proto 47, :mod:`forensiclab.gre` 가 GRE Key=Call ID 를 노출).
PPTP 는 MS-CHAPv2 + MPPE 의 구조적 약점(chapcrack/cloudcracker 로 사실상 완전 해독,
NIST 권고 폐기)으로 **레거시·약한 VPN 의 대표** — 1723 에 제어 메시지가 보이는 것
자체가 폐기 권고된 약한 VPN 사용 정황이다.

PPTP 제어 메시지는 모두 **12바이트 공통 헤더**로 시작한다:
- 2바이트 Length(메시지 전체 길이)
- 2바이트 PPTP Message Type(1=Control Connection·2=Management)
- 4바이트 **Magic Cookie ``0x1A2B3C4D``**(고정 상수) — WireGuard 의 고정 길이처럼
  **결정적 핑거프린트**라, 비표준 포트로 위장해도 식별되고 임의 TCP 오인을 막는다.
- 2바이트 Control Message Type(1~15)
- 2바이트 Reserved0

이후 메시지별 필드 중 **확실한 평문 부분만** 푼다(오탐·오파싱 방지):

- **SCCRQ(1)/SCCRP(2)**: 64바이트 ``Host Name`` + 64바이트 ``Vendor String``(NUL 패딩)
  평문 — 단말 호스트명·구현 벤더(예: ``Microsoft``·``linux``)를 그대로 노출하는
  강한 핑거프린트(:mod:`forensiclab.l2tp` SCCRQ AVP·MySQL server_version 계열).
  ``Protocol Version`` 도 함께 노출. SCCRP 는 ``Result Code``/``Error Code``(협상 성패).
- **Outgoing/Incoming-Call-Request(7·9)**: ``call_id`` — 발신측이 배정하는 16비트
  호출 식별자로, **데이터 채널 GRE 의 Key 필드에 그대로 실린다**(:mod:`forensiclab.gre`
  와 상관해 제어 협상↔암호 데이터 터널을 한 호출로 못 박는 키).
- **Outgoing/Incoming-Call-Reply(8·10)**: ``call_id`` + ``peer_call_id``(양방향
  GRE 두 Call ID 쌍) + ``result_code``/``error_code``(호출 성패).
- **ICCN(11)/Call-Disconnect-Notify(13)/WAN-Error-Notify(14)**: ``call_id`` 또는
  ``peer_call_id`` 로 호출 수명·종료를 추적.

침해/사고 분석에서 PPTP 가 드러내는 것:

- **레거시·약한 VPN 존재**: Magic Cookie 유효 + 제어 타입 1~15 면 PPTP 정황 —
  포트 위장에도 식별. MS-CHAPv2/MPPE 약점상 1723 트래픽 자체가 폐기 권고 위반 정황.
- **단말 식별·핑거프린트(SCCRQ/SCCRP)**: 평문 ``hostname``/``vendor_string`` 으로
  연결 단말·구현을 귀속.
- **제어↔데이터 상관(call_id)**: 제어 채널 ``call_id`` ↔ GRE Key 로 암호 데이터 터널을
  같은 호출로 묶고, peer_call_id 쌍으로 양방향을 못 박는다(:mod:`forensiclab.flows`).
- **호출 수명·실패**: SCCRP/OCRP/ICRP ``result_code``/``error_code`` 로 협상·호출
  성패, Disconnect/WAN-Error 로 종료를 추적.

와이어 포맷: big-endian. 공통 헤더 12바이트, 이후 메시지별.

설계 원칙(다른 파서와 동일):
- 부작용 없음·stdlib 전용·읽기 전용.
- 견고: 12바이트 미만이거나 Magic Cookie 가 ``0x1A2B3C4D`` 가 아니거나 Message Type
  이 1·2 가 아니거나 Control Message Type 이 1~15 가 아니면 예외 대신 ``None``
  (오탐 가드). 메시지별 필드는 바이트가 모자라면 해당 필드만 ``None``(부분 파싱).
- TCP 1723 스트림에서 한 세그먼트가 여러 제어 메시지를 담을 수 있어 ``offset`` 과
  ``length`` 로 다음 메시지를 이어 읽을 수 있다.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Optional

__all__ = [
    "PPTP_PORT",
    "PPTP_MAGIC_COOKIE",
    "PPTP_MESSAGE_CONTROL",
    "PPTP_MESSAGE_MANAGEMENT",
    "SCCRQ",
    "SCCRP",
    "STOP_CCRQ",
    "STOP_CCRP",
    "ECHO_REQUEST",
    "ECHO_REPLY",
    "OCRQ",
    "OCRP",
    "ICRQ",
    "ICRP",
    "ICCN",
    "CALL_CLEAR_REQUEST",
    "CALL_DISCONNECT_NOTIFY",
    "WAN_ERROR_NOTIFY",
    "SET_LINK_INFO",
    "PPTPControlMessage",
    "looks_like_pptp",
    "parse_pptp",
]

# PPTP 제어 채널 기본 포트(TCP).
PPTP_PORT = 1723

# 모든 PPTP 제어 메시지에 고정으로 박히는 Magic Cookie(결정적 핑거프린트).
PPTP_MAGIC_COOKIE = 0x1A2B3C4D

# PPTP Message Type(공통 헤더 두 번째 16비트).
PPTP_MESSAGE_CONTROL = 1
PPTP_MESSAGE_MANAGEMENT = 2

# Control Message Type(1~15).
SCCRQ = 1  # Start-Control-Connection-Request
SCCRP = 2  # Start-Control-Connection-Reply
STOP_CCRQ = 3  # Stop-Control-Connection-Request
STOP_CCRP = 4  # Stop-Control-Connection-Reply
ECHO_REQUEST = 5
ECHO_REPLY = 6
OCRQ = 7  # Outgoing-Call-Request
OCRP = 8  # Outgoing-Call-Reply
ICRQ = 9  # Incoming-Call-Request
ICRP = 10  # Incoming-Call-Reply
ICCN = 11  # Incoming-Call-Connected
CALL_CLEAR_REQUEST = 12
CALL_DISCONNECT_NOTIFY = 13
WAN_ERROR_NOTIFY = 14
SET_LINK_INFO = 15

_CONTROL_MESSAGE_NAMES = {
    SCCRQ: "Start-Control-Connection-Request",
    SCCRP: "Start-Control-Connection-Reply",
    STOP_CCRQ: "Stop-Control-Connection-Request",
    STOP_CCRP: "Stop-Control-Connection-Reply",
    ECHO_REQUEST: "Echo-Request",
    ECHO_REPLY: "Echo-Reply",
    OCRQ: "Outgoing-Call-Request",
    OCRP: "Outgoing-Call-Reply",
    ICRQ: "Incoming-Call-Request",
    ICRP: "Incoming-Call-Reply",
    ICCN: "Incoming-Call-Connected",
    CALL_CLEAR_REQUEST: "Call-Clear-Request",
    CALL_DISCONNECT_NOTIFY: "Call-Disconnect-Notify",
    WAN_ERROR_NOTIFY: "WAN-Error-Notify",
    SET_LINK_INFO: "Set-Link-Info",
}

# Host Name / Vendor String 고정 필드 길이(NUL 패딩).
_HOSTNAME_LEN = 64
_VENDOR_LEN = 64
_COMMON_HEADER_LEN = 12


def _fixed_string(data: bytes, start: int, length: int) -> Optional[str]:
    """``start`` 부터 ``length`` 바이트 NUL 패딩 문자열을 디코드(부족하면 None)."""
    if len(data) - start < length:
        return None
    raw = bytes(data[start:start + length])
    raw = raw.split(b"\x00", 1)[0]
    return raw.decode("latin-1", "replace")


@dataclass(frozen=True)
class PPTPControlMessage:
    """파싱된 PPTP 제어 메시지 한 개(공통 헤더 + 확실한 평문 부분).

    Attributes:
        length: 메시지 전체 길이(공통 헤더 Length 필드).
        message_type: PPTP Message Type(1=Control·2=Management).
        control_message_type: Control Message Type(1~15).
        protocol_version: SCCRQ/SCCRP 의 16비트 프로토콜 버전(없으면 None).
        result_code: SCCRP/OCRP/ICRP 등의 결과 코드(없으면 None).
        error_code: 위 메시지의 오류 코드(없으면 None).
        call_id: 발신측이 배정한 16비트 Call ID — GRE Key 상관(없으면 None).
        peer_call_id: 상대측 Call ID(Reply/Connected/Notify; 없으면 None).
        hostname: SCCRQ/SCCRP 의 64바이트 평문 호스트명(없으면 None).
        vendor_string: SCCRQ/SCCRP 의 64바이트 평문 벤더 문자열(없으면 None).
        payload_offset: 이 메시지 끝(다음 메시지 시작) 오프셋(``data`` 기준).
    """

    length: int
    message_type: int
    control_message_type: int
    protocol_version: Optional[int] = None
    result_code: Optional[int] = None
    error_code: Optional[int] = None
    call_id: Optional[int] = None
    peer_call_id: Optional[int] = None
    hostname: Optional[str] = None
    vendor_string: Optional[str] = None
    payload_offset: int = 0

    @property
    def control_message_name(self) -> str:
        """Control Message Type 이름(알 수 없으면 ``control_<n>``)."""
        return _CONTROL_MESSAGE_NAMES.get(
            self.control_message_type, f"control_{self.control_message_type}"
        )

    @property
    def is_start_request(self) -> bool:
        """SCCRQ 인지 — 제어 연결 개통(개시 방향)."""
        return self.control_message_type == SCCRQ

    @property
    def is_start_reply(self) -> bool:
        """SCCRP 인지 — 제어 연결 응답."""
        return self.control_message_type == SCCRP

    @property
    def is_call_request(self) -> bool:
        """Outgoing/Incoming-Call-Request 인지 — 데이터 호출 개통."""
        return self.control_message_type in (OCRQ, ICRQ)

    @property
    def is_call_reply(self) -> bool:
        """Outgoing/Incoming-Call-Reply 인지 — 데이터 호출 응답."""
        return self.control_message_type in (OCRP, ICRP)

    @property
    def is_teardown(self) -> bool:
        """연결/호출 종료 계열인지(Stop-CCRQ/CCRP·Clear·Disconnect·WAN-Error)."""
        return self.control_message_type in (
            STOP_CCRQ,
            STOP_CCRP,
            CALL_CLEAR_REQUEST,
            CALL_DISCONNECT_NOTIFY,
            WAN_ERROR_NOTIFY,
        )


def looks_like_pptp(data: bytes, offset: int = 0) -> bool:
    """``offset`` 바이트가 파싱 가능한 PPTP 제어 메시지처럼 보이는지(가벼운 가드).

    Magic Cookie ``0x1A2B3C4D`` 와 타입 범위를 검사하므로 단독으로도 비교적 강하다 —
    TCP 1723 문맥과 함께 쓰면 더 안전하다.
    """
    return parse_pptp(data, offset) is not None


def parse_pptp(data: bytes, offset: int = 0) -> Optional[PPTPControlMessage]:
    """단일 PPTP 제어 메시지를 파싱한다.

    Args:
        data: PPTP 제어 채널 바이트(TCP 1723 페이로드).
        offset: 파싱 시작 위치(기본 0; 한 세그먼트 다중 메시지 시 이어 읽기).

    Returns:
        :class:`PPTPControlMessage`. 12바이트 미만이거나 Magic Cookie 가
        ``0x1A2B3C4D`` 가 아니거나 Message Type 이 1·2 가 아니거나 Control Message
        Type 이 1~15 가 아니면 ``None``(오탐 가드). 메시지별 필드는 바이트가
        모자라면 해당 필드만 ``None``(부분 파싱).
    """
    if not isinstance(data, (bytes, bytearray)):
        return None
    if len(data) - offset < _COMMON_HEADER_LEN:
        return None

    length, message_type, magic, control_type, _reserved0 = struct.unpack_from(
        ">HHIHH", data, offset
    )
    if magic != PPTP_MAGIC_COOKIE:
        return None
    if message_type not in (PPTP_MESSAGE_CONTROL, PPTP_MESSAGE_MANAGEMENT):
        return None
    if control_type not in _CONTROL_MESSAGE_NAMES:
        return None

    body = offset + _COMMON_HEADER_LEN  # 메시지별 본문 시작.

    protocol_version: Optional[int] = None
    result_code: Optional[int] = None
    error_code: Optional[int] = None
    call_id: Optional[int] = None
    peer_call_id: Optional[int] = None
    hostname: Optional[str] = None
    vendor_string: Optional[str] = None

    def u16(at: int) -> Optional[int]:
        if len(data) - at < 2:
            return None
        return struct.unpack_from(">H", data, at)[0]

    def u8(at: int) -> Optional[int]:
        if len(data) - at < 1:
            return None
        return data[at]

    if control_type in (SCCRQ, SCCRP):
        # Protocol Version(2) 뒤 SCCRQ 는 Reserved1(2), SCCRP 는 Result/Error(1+1).
        protocol_version = u16(body)
        if control_type == SCCRP:
            result_code = u8(body + 2)
            error_code = u8(body + 3)
        # Framing Caps(4)+Bearer Caps(4)+Max Channels(2)+Firmware Rev(2) = 12,
        # Protocol Version+Reserved/Result-Error(4) 합쳐 본문 +16 부터 Host Name.
        host_at = body + 16
        hostname = _fixed_string(data, host_at, _HOSTNAME_LEN)
        vendor_string = _fixed_string(data, host_at + _HOSTNAME_LEN, _VENDOR_LEN)
    elif control_type in (OCRQ, ICRQ):
        # 첫 16비트가 발신측 Call ID(GRE Key 상관).
        call_id = u16(body)
    elif control_type in (OCRP, ICRP):
        # Call ID(2) + Peer's Call ID(2) + Result(1) + Error(1).
        call_id = u16(body)
        peer_call_id = u16(body + 2)
        result_code = u8(body + 4)
        error_code = u8(body + 5)
    elif control_type in (ICCN, CALL_CLEAR_REQUEST, CALL_DISCONNECT_NOTIFY,
                          WAN_ERROR_NOTIFY, SET_LINK_INFO):
        # 모두 첫 16비트가 (Peer's) Call ID — 호출 식별.
        peer_call_id = u16(body)

    # 다음 메시지 시작: Length 가 합리적이면 그대로, 아니면 본문 시작.
    if length >= _COMMON_HEADER_LEN and offset + length <= len(data):
        next_offset = offset + length
    else:
        next_offset = body

    return PPTPControlMessage(
        length=length,
        message_type=message_type,
        control_message_type=control_type,
        protocol_version=protocol_version,
        result_code=result_code,
        error_code=error_code,
        call_id=call_id,
        peer_call_id=peer_call_id,
        hostname=hostname,
        vendor_string=vendor_string,
        payload_offset=next_offset,
    )
