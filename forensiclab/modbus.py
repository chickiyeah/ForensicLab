"""Modbus/TCP — 산업 제어(ICS/SCADA) 필드버스 메시지 파싱 코어(MODBUS Application Protocol V1.1b3).

:mod:`forensiclab.coap` 가 "봇넷 C2·**ICS 원격 제어**·증폭 DDoS 분석에서 자주 마주친다"고
할 때 그 **ICS 원격 제어의 사실상 표준 와이어가 바로 Modbus** — 1979년 Modicon PLC 용으로
태어나 오늘날 발전소·정수장·제조 라인의 PLC·RTU·HMI 가 센서값을 읽고 액추에이터(밸브·릴레이·
모터)를 **물리적으로 조작**하는 OT(운영 기술) 평면. 본 모듈은 그중 TCP 502 위에 얹힌
**Modbus/TCP**(시리얼 Modbus RTU 의 7바이트 MBAP 헤더 추가 변형)를 다룬다. CoAP/MQTT 가
IoT "정보" 평면이라면 Modbus 는 **현장 물리 공정** 평면 — Stuxnet·Industroyer·TRITON 같은
표적 ICS 공격, Shodan 에 노출된 무인증 PLC 직접 제어, Modbus 스캐닝(주소 열거)이 여기서 보인다.

설계상 **인증·암호화가 전혀 없다**(평문, 명령에 권한 검증 없음) — 502 에 메시지가 보이는
것 자체가 노출된 산업 제어 평면 정황이고, Write 계열 함수 코드 하나가 곧 물리 장치 조작이다.

와이어(big-endian, MBAP 헤더 7바이트 + PDU):
- **MBAP 헤더**: Transaction ID(2: 요청↔응답 상관, :mod:`forensiclab.flows` IP 쌍 안에서
  :mod:`forensiclab.coap` ``message_id``·SMPP ``sequence_number`` 대응)·**Protocol ID**
  (2: Modbus 는 **항상 0** — 강한 오탐 가드)·Length(2: 뒤따르는 바이트 수 = Unit ID + PDU)·
  **Unit ID**(1: 슬레이브/장치 주소 — 게이트웨이 뒤 어느 PLC 를 겨냥하는지, 장치 열거 단서).
- **PDU**: **Function Code**(1) + 데이터. 함수 코드가 곧 의도: 1 Read Coils·2 Read Discrete
  Inputs·3 Read Holding Registers·4 Read Input Registers(**읽기/정찰**)·5 Write Single Coil·
  6 Write Single Register·15 Write Multiple Coils·16 Write Multiple Registers·23 Read/Write
  Multiple(**쓰기=물리 공정 조작**)·8 Diagnostics·43 Encapsulated Interface(장치 식별 정찰).
- **예외 응답**: 함수 코드에 ``0x80`` OR(``base | 0x80``) + 예외 코드 1바이트(1 Illegal
  Function·2 Illegal Data Address·3 Illegal Data Value·4 Server Device Failure …). 잘못된
  주소를 훑는 **스캐닝**은 Illegal Data Address(2) 예외를 무더기로 유발한다.

포렌식 핵심:
- **노출된 OT 평면·표적**: 502 자체가 산업 제어 정황. ``unit_id`` 로 게이트웨이 뒤 PLC 열거.
- **읽기 vs 쓰기(공격 의도)**: ``is_write`` 한 번이 밸브·릴레이 물리 조작. ``function_name``
  +``address``/``count`` 로 "어느 레지스터/코일에 무엇을"(쓰기 단일은 ``count`` 가 쓰인 값).
- **스캐닝·실패**: ``is_exception``+``exception_name``(Illegal Data Address 폭주=주소 열거
  정찰, Illegal Function=지원 함수 핑거프린트).
- **세션·타임라인**: ``transaction_id`` 로 요청→응답 상관(:mod:`forensiclab.timeline`).

설계 원칙(:mod:`forensiclab.coap` 와 동일):
- 부작용 없음·stdlib 전용·읽기 전용(입력 무변형)·``offset`` 지원.
- 8바이트(MBAP 7 + 함수 코드 1) 미만이거나, Protocol ID 가 0이 아니거나, Length 가
  비합리(2 미만·254 초과)이거나, 기본 함수 코드가 알려진 집합/사용자 정의 범위 밖이면
  ``None``(TCP 스트림 오탐 가드).
- PDU 데이터 본문은 ``pdu_offset`` 으로 가리키고 깊게 풀지 않는다. 구조가 방향(요청/응답)에
  무관하게 확실한 필드(쓰기 단일/다중·Read/Write 의 시작 주소·개수)만 ``address``/``count``
  로 디코드하며, 읽기(1~4)는 **요청 형식**을 가정한다(Modbus PDU 는 방향이 모호 — 흐름 방향과
  ``transaction_id`` 로 짝지을 것). 데이터가 모자라면 풀 수 있는 만큼만 채우고 ``truncated=True``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

__all__ = [
    "Modbus",
    "MODBUS_FUNCTION_NAMES",
    "MODBUS_EXCEPTION_NAMES",
    "function_name",
    "exception_name",
    "parse_modbus",
]

# 공개(표준) 함수 코드 → 이름(MODBUS Application Protocol V1.1b3).
MODBUS_FUNCTION_NAMES = {
    1: "Read Coils",
    2: "Read Discrete Inputs",
    3: "Read Holding Registers",
    4: "Read Input Registers",
    5: "Write Single Coil",
    6: "Write Single Register",
    7: "Read Exception Status",
    8: "Diagnostics",
    11: "Get Comm Event Counter",
    12: "Get Comm Event Log",
    15: "Write Multiple Coils",
    16: "Write Multiple Registers",
    17: "Report Server ID",
    20: "Read File Record",
    21: "Write File Record",
    22: "Mask Write Register",
    23: "Read/Write Multiple Registers",
    24: "Read FIFO Queue",
    43: "Encapsulated Interface Transport",
}

# 예외 코드 → 이름(예외 응답: 함수 코드 | 0x80 뒤 1바이트).
MODBUS_EXCEPTION_NAMES = {
    1: "Illegal Function",
    2: "Illegal Data Address",
    3: "Illegal Data Value",
    4: "Server Device Failure",
    5: "Acknowledge",
    6: "Server Device Busy",
    7: "Negative Acknowledge",
    8: "Memory Parity Error",
    10: "Gateway Path Unavailable",
    11: "Gateway Target Device Failed to Respond",
}

# 예외 비트(응답에서 함수 코드 최상위 비트).
_EXCEPTION_FLAG = 0x80

# Modbus ADU 최대치(MBAP 7 + PDU 253 = 260). Length 필드 = Unit ID + PDU ≤ 254.
_MAX_LENGTH = 254

# 시작 주소 + 개수/값(2바이트씩)을 방향 무관하게(또는 요청 형식) 디코드하는 함수.
_ADDR_COUNT_FUNCTIONS = frozenset({1, 2, 3, 4, 5, 6, 15, 16, 23})

# 쓰기(물리 공정 조작) 함수.
_WRITE_FUNCTIONS = frozenset({5, 6, 15, 16, 22, 23})

# 읽기(정찰) 함수.
_READ_FUNCTIONS = frozenset({1, 2, 3, 4, 7, 11, 12, 17, 20, 24})


def function_name(code: int) -> str:
    """함수 코드(예외 비트 제외 기본 코드) → 이름(미정의면 ``"function-N"``)."""
    base = code & ~_EXCEPTION_FLAG
    name = MODBUS_FUNCTION_NAMES.get(base)
    if name is not None:
        return name
    if 65 <= base <= 72 or 100 <= base <= 110:
        return f"User-Defined ({base})"
    return f"function-{base}"


def exception_name(code: int) -> str:
    """예외 코드 → 이름(미정의면 ``"exception-N"``)."""
    return MODBUS_EXCEPTION_NAMES.get(code, f"exception-{code}")


def _is_valid_function(base: int) -> bool:
    """기본 함수 코드가 알려진 집합/사용자 정의 범위 안인지(오탐 가드)."""
    if base in MODBUS_FUNCTION_NAMES:
        return True
    return 65 <= base <= 72 or 100 <= base <= 110


@dataclass(frozen=True)
class Modbus:
    """파싱된 Modbus/TCP 메시지 한 개.

    Attributes:
        transaction_id: Transaction ID(요청↔응답 상관).
        protocol_id: Protocol ID(Modbus 는 항상 0).
        length: Length 필드(뒤따르는 바이트 수 = Unit ID + PDU).
        unit_id: Unit ID(슬레이브/장치 주소; 게이트웨이 뒤 PLC 식별).
        function_code: 함수 코드 원값(예외면 ``0x80`` 비트 포함).
        base_function: 예외 비트를 뗀 기본 함수 코드(1~127).
        function_name: 함수 이름.
        is_exception: 예외 응답(최상위 비트 1) 여부.
        exception_code: 예외 코드(예외 응답일 때만, 그 외 ``None``).
        exception_name: 예외 이름(예외 응답일 때만).
        address: 시작 주소(읽기/쓰기 함수에서 디코드, 그 외 ``None``).
        count: 개수(읽기·다중 쓰기) 또는 쓰인 값(단일 쓰기 5/6); 그 외 ``None``.
        pdu_offset: PDU(함수 코드 포함) 시작 절대 오프셋.
        pdu_length: PDU 바이트 길이(Length 필드 - 1; 가용 바이트로 클램프).
        truncated: PDU 가 가용 바이트를 넘는지(절단 캡처).
        packet_length: MBAP 헤더 포함 ADU 길이(MBAP 7 + Length - 1).
    """

    transaction_id: int
    protocol_id: int
    length: int
    unit_id: int
    function_code: int
    base_function: int
    function_name: str
    is_exception: bool
    exception_code: Optional[int] = None
    exception_name: Optional[str] = None
    address: Optional[int] = None
    count: Optional[int] = None
    pdu_offset: int = 0
    pdu_length: int = 0
    truncated: bool = False
    packet_length: int = 0

    @property
    def is_write(self) -> bool:
        """쓰기(물리 공정 조작) 함수 여부."""
        return not self.is_exception and self.base_function in _WRITE_FUNCTIONS

    @property
    def is_read(self) -> bool:
        """읽기(정찰) 함수 여부."""
        return not self.is_exception and self.base_function in _READ_FUNCTIONS


def parse_modbus(data: bytes, offset: int = 0) -> Optional[Modbus]:
    """Modbus/TCP 메시지 한 개를 파싱한다.

    Args:
        data: Modbus/TCP 바이트(보통 TCP 502 페이로드). ``offset`` 에 MBAP 헤더.
        offset: 메시지가 시작하는 위치(기본 0).

    Returns:
        :class:`Modbus`. 8바이트(MBAP 7 + 함수 코드 1) 미만이거나, Protocol ID 가
        0이 아니거나, Length 가 2 미만·254 초과거나, 기본 함수 코드가 알려진 집합/
        사용자 정의 범위 밖이면 ``None``(TCP 스트림 오탐 가드). PDU 가 가용 바이트를
        넘으면(절단) 풀 수 있는 만큼만 채우고 ``truncated=True``.
    """
    end = len(data)
    if offset < 0 or offset + 8 > end:
        return None

    transaction_id = (data[offset] << 8) | data[offset + 1]
    protocol_id = (data[offset + 2] << 8) | data[offset + 3]
    if protocol_id != 0:
        return None  # Modbus Protocol ID 는 항상 0.

    length = (data[offset + 4] << 8) | data[offset + 5]
    if length < 2 or length > _MAX_LENGTH:
        return None  # 최소 Unit ID + 함수 코드, 최대 ADU 한계.

    unit_id = data[offset + 6]
    function_code = data[offset + 7]
    is_exception = bool(function_code & _EXCEPTION_FLAG)
    base_function = function_code & ~_EXCEPTION_FLAG
    if base_function == 0 or not _is_valid_function(base_function):
        return None  # 미지의 함수 코드 = 비-Modbus 오탐 가드.

    pdu_offset = offset + 7
    # PDU 길이는 Length 필드(Unit ID + PDU) - 1. 가용 바이트로 클램프.
    declared_pdu = length - 1
    avail_pdu = end - pdu_offset
    truncated = declared_pdu > avail_pdu
    pdu_length = min(declared_pdu, avail_pdu)

    exception_code: Optional[int] = None
    exc_name: Optional[str] = None
    address: Optional[int] = None
    count: Optional[int] = None

    if is_exception:
        if avail_pdu >= 2:
            exception_code = data[pdu_offset + 1]
            exc_name = exception_name(exception_code)
    elif base_function in _ADDR_COUNT_FUNCTIONS:
        # 함수 코드(1) 뒤 시작 주소(2) + 개수/값(2). 쓰기 단일/다중·Read/Write 는
        # 방향 무관, 읽기(1~4)는 요청 형식 가정.
        if avail_pdu >= 3:
            address = (data[pdu_offset + 1] << 8) | data[pdu_offset + 2]
        if avail_pdu >= 5:
            count = (data[pdu_offset + 3] << 8) | data[pdu_offset + 4]

    return Modbus(
        transaction_id=transaction_id,
        protocol_id=protocol_id,
        length=length,
        unit_id=unit_id,
        function_code=function_code,
        base_function=base_function,
        function_name=function_name(function_code),
        is_exception=is_exception,
        exception_code=exception_code,
        exception_name=exc_name,
        address=address,
        count=count,
        pdu_offset=pdu_offset,
        pdu_length=pdu_length,
        truncated=truncated,
        packet_length=7 + declared_pdu,
    )
