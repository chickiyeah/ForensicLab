"""DNP3 — 전력/수도 SCADA 제어 프로토콜 파싱 코어(IEEE 1815, 보통 TCP/UDP 20000).

:mod:`forensiclab.modbus` 가 ICS 의 "사실상 표준 와이어"라면 DNP3(Distributed Network
Protocol 3)는 **북미 전력망·수도·송유 SCADA 의 표준 제어 프로토콜** — 광역에 흩어진
RTU·IED 를 마스터(제어 센터)가 폴링·제어하는 OT 평면이다. Modbus 가 단순 레지스터/코일
읽기·쓰기라면 DNP3 는 **객체(이진 출력·아날로그·카운터)와 SELECT-before-OPERATE 안전
절차, 비요청 보고(unsolicited)**를 갖춘 더 풍부한 프로토콜. **Industroyer/CRASHOVERRIDE
(2016 우크라이나 정전)**의 무기 모듈 하나가 바로 이 평면에서 차단기(breaker)를 OPERATE 로
열었다 — DNP3 노출 자체가 중요 인프라 제어 평면 정황이고, SELECT/OPERATE/WRITE 한 번이
물리 차단기·밸브 조작이다.

설계상 (전통적으로) **인증·암호화가 없다**(평문; Secure Authentication 은 별도 확장) —
20000 에 프레임이 보이는 것 자체가 노출된 SCADA 정황.

와이어(IEEE 1815 데이터 링크 계층, 8바이트 고정 헤더 + CRC):
- **시작 동기**: ``0x05 0x64``(2바이트, 고정 — 강한 오탐 가드).
- **Length**(1: 제어+주소+사용자 데이터 바이트 수 = 5 + 사용자 데이터; CRC 제외, 5~255).
- **Control**(1): DIR(bit7 방향)·**PRM**(bit6 1=1차/마스터 개시)·FCB(bit5)·FCV(bit4) +
  하위 4비트 **데이터 링크 함수 코드**(PRM 에 따라 의미가 다름).
- **Destination**(2, little-endian)·**Source**(2, little-endian): 출발/도착 RTU 주소
  (장치 열거·:mod:`forensiclab.flows` 상관 키; 1차/2차로 마스터↔아웃스테이션 방향).
- 헤더 CRC(2) 뒤로 사용자 데이터가 16바이트 블록마다 CRC 2바이트를 끼워 실린다(미검증).

사용자 데이터(CONFIRMED/UNCONFIRMED_USER_DATA 일 때)는 **전송 헤더 1바이트** + **응용
제어 1바이트** + **응용 함수 코드 1바이트**로 시작한다(모두 첫 16바이트 블록 안). 응용 함수
코드가 곧 의도: 1 READ(정찰)·2 WRITE·3 SELECT·4 OPERATE·5 DIRECT_OPERATE(**물리 조작**)·
13/14 COLD/WARM_RESTART·129 RESPONSE·130 UNSOLICITED_RESPONSE.

포렌식 핵심:
- **노출된 중요 인프라 제어 평면·표적**: 20000 자체가 SCADA 정황. ``source``/``destination``
  으로 마스터↔RTU 열거.
- **링크 계층 의도**: ``link_function_name``(RESET_LINK_STATES·REQUEST_LINK_STATUS 정찰,
  CONFIRMED/UNCONFIRMED_USER_DATA 가 실제 응용 데이터 운반).
- **응용 의도(공격)**: ``application_function_name`` — SELECT→OPERATE 순서(안전 절차)나
  DIRECT_OPERATE/WRITE 한 번이 차단기·밸브 조작(``is_control``). READ 폭주=객체 열거 정찰.
- **방향·세션**: ``is_master``(DIR/PRM)·``is_request``/``is_response``(:mod:`forensiclab.timeline`).

설계 원칙(:mod:`forensiclab.modbus` 와 동일):
- 부작용 없음·stdlib 전용·읽기 전용(입력 무변형)·``offset`` 지원.
- 8바이트(데이터 링크 헤더) 미만이거나, 시작 동기가 ``0x05 0x64`` 가 아니거나, Length 가
  5 미만이거나, 링크 함수 코드가 그 PRM 방향에서 예약(미정의)이면 ``None``(오탐 가드).
- CRC 는 검증하지 않는다. 사용자 데이터 블록은 ``payload_offset`` 으로 가리키고, 응용 함수
  코드만(첫 블록 내) 디코드한다. 사용자 데이터가 모자라면 ``truncated=True``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

__all__ = [
    "DNP3",
    "DNP3_PRIMARY_FUNCTIONS",
    "DNP3_SECONDARY_FUNCTIONS",
    "DNP3_APPLICATION_FUNCTIONS",
    "link_function_name",
    "application_function_name",
    "parse_dnp3",
]

# 데이터 링크 함수 코드(1차/PRM=1, 마스터 또는 개시측).
DNP3_PRIMARY_FUNCTIONS = {
    0: "RESET_LINK_STATES",
    1: "RESET_USER_PROCESS",
    2: "TEST_LINK_STATES",
    3: "CONFIRMED_USER_DATA",
    4: "UNCONFIRMED_USER_DATA",
    9: "REQUEST_LINK_STATUS",
}

# 데이터 링크 함수 코드(2차/PRM=0, 응답측).
DNP3_SECONDARY_FUNCTIONS = {
    0: "ACK",
    1: "NACK",
    11: "LINK_STATUS",
    15: "NOT_SUPPORTED",
}

# 응용 계층 함수 코드(전송 헤더+응용 제어 뒤 1바이트).
DNP3_APPLICATION_FUNCTIONS = {
    0: "CONFIRM",
    1: "READ",
    2: "WRITE",
    3: "SELECT",
    4: "OPERATE",
    5: "DIRECT_OPERATE",
    6: "DIRECT_OPERATE_NR",
    7: "IMMED_FREEZE",
    8: "IMMED_FREEZE_NR",
    9: "FREEZE_CLEAR",
    10: "FREEZE_CLEAR_NR",
    11: "FREEZE_AT_TIME",
    12: "FREEZE_AT_TIME_NR",
    13: "COLD_RESTART",
    14: "WARM_RESTART",
    15: "INITIALIZE_DATA",
    16: "INITIALIZE_APPL",
    17: "START_APPL",
    18: "STOP_APPL",
    19: "SAVE_CONFIG",
    20: "ENABLE_UNSOLICITED",
    21: "DISABLE_UNSOLICITED",
    22: "ASSIGN_CLASS",
    23: "DELAY_MEASURE",
    24: "RECORD_CURRENT_TIME",
    25: "OPEN_FILE",
    26: "CLOSE_FILE",
    27: "DELETE_FILE",
    28: "GET_FILE_INFO",
    29: "AUTHENTICATE_FILE",
    30: "ABORT_FILE",
    31: "ACTIVATE_CONFIG",
    32: "AUTHENTICATE_REQ",
    33: "AUTH_REQ_NO_ACK",
    129: "RESPONSE",
    130: "UNSOLICITED_RESPONSE",
    131: "AUTHENTICATE_RESP",
}

# 물리 공정 조작(차단기·밸브·출력) 응용 함수.
_CONTROL_APP_FUNCTIONS = frozenset({2, 3, 4, 5, 6})

# 사용자 데이터(응용 계층)를 운반하는 1차 링크 함수.
_USER_DATA_FUNCTIONS = frozenset({3, 4})

# 시작 동기 바이트.
_SYNC = (0x05, 0x64)

# Control 비트.
_DIR = 0x80
_PRM = 0x40
_FCB = 0x20
_FCV = 0x10
_FUNC_MASK = 0x0F


def link_function_name(control: int) -> str:
    """Control 바이트 → 데이터 링크 함수 이름(PRM 방향 반영; 미정의면 ``"reserved-N"``)."""
    func = control & _FUNC_MASK
    table = DNP3_PRIMARY_FUNCTIONS if (control & _PRM) else DNP3_SECONDARY_FUNCTIONS
    return table.get(func, f"reserved-{func}")


def application_function_name(code: int) -> str:
    """응용 함수 코드 → 이름(미정의면 ``"app-N"``)."""
    return DNP3_APPLICATION_FUNCTIONS.get(code, f"app-{code}")


def _is_valid_link_function(control: int) -> bool:
    """링크 함수 코드가 그 PRM 방향에서 정의돼 있는지(오탐 가드)."""
    func = control & _FUNC_MASK
    if control & _PRM:
        return func in DNP3_PRIMARY_FUNCTIONS
    return func in DNP3_SECONDARY_FUNCTIONS


@dataclass(frozen=True)
class DNP3:
    """파싱된 DNP3 데이터 링크 프레임 한 개.

    Attributes:
        length: Length 필드(제어+주소+사용자 데이터 = 5 + 사용자 데이터 바이트 수).
        control: Control 바이트 원값.
        dir: DIR 비트(방향; 1=마스터→아웃스테이션 관례).
        prm: PRM 비트(1=1차/개시측).
        fcb: FCB(Frame Count Bit).
        fcv: FCV(Frame Count Valid).
        link_function: 데이터 링크 함수 코드(하위 4비트).
        link_function_name: 데이터 링크 함수 이름(PRM 방향 반영).
        destination: 도착 RTU 주소(little-endian).
        source: 출발 RTU 주소(little-endian).
        carries_user_data: 사용자 데이터(응용 계층)를 운반하는 프레임인지.
        application_function: 응용 함수 코드(운반·디코드 가능 시, 그 외 ``None``).
        application_function_name: 응용 함수 이름(디코드 시).
        transport_header: 전송 계층 헤더 바이트(디코드 시).
        application_control: 응용 제어 바이트(디코드 시).
        payload_offset: 사용자 데이터(전송 헤더부터) 시작 절대 오프셋.
        user_data_length: 사용자 데이터 바이트 수(Length - 5).
        truncated: 사용자 데이터/헤더 CRC 가 가용 바이트를 넘는지(절단 캡처).
        packet_length: CRC 포함 전체 프레임 길이(헤더 8 + CRC 2 + 데이터 + 블록 CRC).
    """

    length: int
    control: int
    dir: bool
    prm: bool
    fcb: bool
    fcv: bool
    link_function: int
    link_function_name: str
    destination: int
    source: int
    carries_user_data: bool
    application_function: Optional[int] = None
    application_function_name: Optional[str] = None
    transport_header: Optional[int] = None
    application_control: Optional[int] = None
    payload_offset: int = 0
    user_data_length: int = 0
    truncated: bool = False
    packet_length: int = 0

    @property
    def is_master(self) -> bool:
        """마스터(제어 센터)가 보낸 프레임으로 보이는지(DIR 와 PRM 둘 다 1)."""
        return self.dir and self.prm

    @property
    def is_request(self) -> bool:
        """응용 요청(마스터→아웃스테이션, 함수 코드 < 128)인지."""
        return (
            self.application_function is not None
            and self.application_function < 128
        )

    @property
    def is_response(self) -> bool:
        """응용 응답/비요청 보고(함수 코드 ≥ 128)인지."""
        return (
            self.application_function is not None
            and self.application_function >= 128
        )

    @property
    def is_control(self) -> bool:
        """물리 공정 조작(WRITE/SELECT/OPERATE/DIRECT_OPERATE) 응용 함수인지."""
        return self.application_function in _CONTROL_APP_FUNCTIONS


def parse_dnp3(data: bytes, offset: int = 0) -> Optional[DNP3]:
    """DNP3 데이터 링크 프레임 한 개를 파싱한다.

    Args:
        data: DNP3 바이트(보통 TCP/UDP 20000 페이로드). ``offset`` 에 시작 동기.
        offset: 프레임이 시작하는 위치(기본 0).

    Returns:
        :class:`DNP3`. 8바이트 미만이거나, 시작 동기가 ``0x05 0x64`` 가 아니거나,
        Length 가 5 미만이거나, 링크 함수 코드가 그 PRM 방향에서 예약이면 ``None``
        (오탐 가드). 사용자 데이터가 가용 바이트를 넘으면 ``truncated=True``.
        CRC 는 검증하지 않는다.
    """
    end = len(data)
    if offset < 0 or offset + 8 > end:
        return None

    if data[offset] != _SYNC[0] or data[offset + 1] != _SYNC[1]:
        return None  # 시작 동기 불일치 = 비-DNP3 오탐 가드.

    length = data[offset + 2]
    if length < 5:
        return None  # 최소 제어 1 + 주소 4 = 5.

    control = data[offset + 3]
    if not _is_valid_link_function(control):
        return None  # 예약 링크 함수 = 오탐 가드.

    destination = data[offset + 4] | (data[offset + 5] << 8)  # little-endian.
    source = data[offset + 6] | (data[offset + 7] << 8)

    link_function = control & _FUNC_MASK
    carries_user_data = bool((control & _PRM) and link_function in _USER_DATA_FUNCTIONS)

    user_data_length = length - 5  # Length 는 제어+주소(5) + 사용자 데이터.
    # 사용자 데이터 시작: 헤더 8바이트 + 헤더 CRC 2바이트.
    payload_offset = offset + 10

    # 전체 프레임 길이(16바이트 블록마다 CRC 2바이트).
    num_blocks = (user_data_length + 15) // 16 if user_data_length > 0 else 0
    packet_length = 10 + user_data_length + 2 * num_blocks
    truncated = offset + packet_length > end

    application_function: Optional[int] = None
    app_func_name: Optional[str] = None
    transport_header: Optional[int] = None
    application_control: Optional[int] = None

    if carries_user_data:
        # 첫 사용자 데이터 블록: 전송 헤더(1) + 응용 제어(1) + 응용 함수(1).
        if payload_offset + 1 <= end:
            transport_header = data[payload_offset]
        if payload_offset + 2 <= end:
            application_control = data[payload_offset + 1]
        if payload_offset + 3 <= end:
            application_function = data[payload_offset + 2]
            app_func_name = application_function_name(application_function)

    return DNP3(
        length=length,
        control=control,
        dir=bool(control & _DIR),
        prm=bool(control & _PRM),
        fcb=bool(control & _FCB),
        fcv=bool(control & _FCV),
        link_function=link_function,
        link_function_name=link_function_name(control),
        destination=destination,
        source=source,
        carries_user_data=carries_user_data,
        application_function=application_function,
        application_function_name=app_func_name,
        transport_header=transport_header,
        application_control=application_control,
        payload_offset=payload_offset,
        user_data_length=user_data_length,
        truncated=truncated,
        packet_length=packet_length,
    )
