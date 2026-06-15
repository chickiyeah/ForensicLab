"""S7comm — 지멘스 S7 PLC 통신(TPKT/COTP 위 S7 Communication) 메시지 파싱 코어.

:mod:`forensiclab.modbus` 가 "Stuxnet·Industroyer·TRITON 같은 표적 ICS 공격"을 언급하고
:mod:`forensiclab.dnp3`·:mod:`forensiclab.iec104` 가 전력망 SCADA 형제였다면, **Stuxnet 이
실제로 말한 와이어가 바로 S7comm** — 지멘스 SIMATIC S7-300/400/1200/1500 PLC 가 STEP 7
엔지니어링 워크스테이션·HMI·SCADA 와 주고받는 사실상 표준 프로토콜. Modbus/DNP3/IEC104 가
센서값·차단기 제어 평면이라면 S7comm 은 **PLC 의 메모리·로직(블록) 자체를 읽고 쓰는** 더
깊은 평면 — Stuxnet 은 이 평면으로 원심분리기 제어 OB/FC 블록을 다운로드(주입)하고 정상값을
재생(replay)했다.

설계상 **인증·암호화가 사실상 없다**(클래식 S7comm 평문) — TCP 102 에 메시지가 보이는 것
자체가 노출된 PLC 엔지니어링 평면 정황이고, Write Var 한 번이 PLC 변수 조작, PLC Control/Stop
한 번이 CPU 기동·정지, Download 한 번이 **PLC 로직 주입**(Stuxnet 수법)이다.

와이어(big-endian, 3계층 캡슐화 — TPKT → COTP → S7comm):
- **TPKT 헤더**(RFC 1006, 4바이트): Version(1: 항상 ``0x03`` — 강한 오탐 가드)·Reserved(1: 0)·
  Length(2: TPKT 헤더 포함 전체 길이).
- **COTP**(ISO 8073/X.224): Length Indicator(1: 뒤따르는 헤더 옥텟 수)·PDU Type(1). S7comm 은
  **DT Data(``0xF0``)** PDU 에만 실린다(연결 설정 CR ``0xE0``/CC ``0xD0`` 는 S7 페이로드 없음
  — 프레이밍 가드에서 ``None``). COTP 헤더 길이 = LI + 1.
- **S7comm 헤더**: Protocol ID(1: 항상 ``0x32`` — 강한 오탐 가드)·**ROSCTR**(1: 메시지 종류
  1 Job 요청·2 Ack·3 Ack_Data 응답·7 Userdata)·Redundancy ID(2: reserved 0)·**PDU Reference**
  (2: 요청↔응답 상관, :mod:`forensiclab.modbus` ``transaction_id``·:mod:`forensiclab.coap`
  ``message_id`` 대응)·Parameter Length(2)·Data Length(2). ROSCTR 가 Ack(2)/Ack_Data(3)면
  Error Class(1)+Error Code(1) 2바이트 추가(헤더 12바이트, 그 외 10바이트).
- **파라미터**: 첫 바이트가 **함수 코드** — 0x04 Read Var·0x05 Write Var(**메모리 정찰/조작**)·
  0x1A~0x1F Download/Upload 블록(**PLC 로직 주입·추출** = Stuxnet)·0x28 PLC Control(기동·재시작)·
  0x29 PLC Stop(CPU 정지)·0xF0 Setup Communication(세션 협상).

포렌식 핵심:
- **노출된 PLC 엔지니어링 평면·표적**: TCP 102 자체가 S7 PLC 정황. ``rosctr_name`` 으로 평면 식별.
- **읽기 vs 쓰기 vs 로직 주입(공격 의도)**: ``is_read``/``is_write``(메모리)·``is_control``/``is_stop``
  (CPU 상태)·``is_download``/``is_upload``(블록 = STEP 7 로직, Stuxnet 의 핵심 단계).
- **세션·타임라인**: ``pdu_reference`` 로 Job→Ack_Data 상관(:mod:`forensiclab.timeline`).
- **오류**: Ack/Ack_Data 의 ``error_class``/``error_code``(접근 거부·항목 없음=주소 열거 정찰).

설계 원칙(:mod:`forensiclab.modbus` 와 동일):
- 부작용 없음·stdlib 전용·읽기 전용(입력 무변형)·``offset`` 지원.
- TPKT Version 이 ``0x03`` 이 아니거나, COTP PDU Type 이 DT Data(``0xF0``)가 아니거나, S7comm
  Protocol ID 가 ``0x32`` 가 아니거나, ROSCTR 가 알려진 집합(1·2·3·7) 밖이면 ``None``(TCP 스트림
  오탐 가드 — 세 계층 상수가 겹쳐 오인 확률 최소).
- 파라미터·데이터 본문은 ``parameter_offset``/``data_offset`` 으로만 가리키고 깊게 풀지 않으며,
  함수 코드(파라미터 첫 바이트)만 디코드한다. 선언 길이가 가용 바이트를 넘으면(절단 캡처) 풀 수
  있는 만큼만 채우고 ``truncated=True``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

__all__ = [
    "S7comm",
    "S7_ROSCTR_NAMES",
    "S7_FUNCTION_NAMES",
    "rosctr_name",
    "function_name",
    "parse_s7comm",
]

# ROSCTR(메시지 종류) → 이름.
S7_ROSCTR_NAMES = {
    0x01: "Job",        # 요청(마스터 → PLC).
    0x02: "Ack",        # 단순 확인(오류 코드만).
    0x03: "Ack_Data",   # 데이터 동반 응답.
    0x07: "Userdata",   # 진단·프로그래밍·암호 등 확장.
}

# 파라미터 함수 코드 → 이름(S7 PCI).
S7_FUNCTION_NAMES = {
    0x00: "CPU Services",
    0x04: "Read Var",
    0x05: "Write Var",
    0x1A: "Request Download",
    0x1B: "Download Block",
    0x1C: "Download Ended",
    0x1D: "Start Upload",
    0x1E: "Upload",
    0x1F: "End Upload",
    0x28: "PLC Control",
    0x29: "PLC Stop",
    0xF0: "Setup Communication",
}

# S7comm Protocol ID(항상 0x32 — 강한 오탐 가드).
_S7_PROTOCOL_ID = 0x32

# TPKT 버전(RFC 1006 — 항상 0x03).
_TPKT_VERSION = 0x03

# COTP DT Data PDU Type(S7comm 은 여기에만 실림).
_COTP_DT_DATA = 0xF0

# 오류 필드(Error Class+Code)를 동반하는 ROSCTR.
_ROSCTR_WITH_ERROR = frozenset({0x02, 0x03})

# 읽기/쓰기(메모리) 함수.
_READ_FUNCTIONS = frozenset({0x04})
_WRITE_FUNCTIONS = frozenset({0x05})

# CPU 상태 제어 함수.
_CONTROL_FUNCTIONS = frozenset({0x28})
_STOP_FUNCTIONS = frozenset({0x29})

# 블록 다운로드(PLC 로 로직 주입)·업로드(로직 추출) 함수.
_DOWNLOAD_FUNCTIONS = frozenset({0x1A, 0x1B, 0x1C})
_UPLOAD_FUNCTIONS = frozenset({0x1D, 0x1E, 0x1F})


def rosctr_name(code: int) -> str:
    """ROSCTR 코드 → 이름(미정의면 ``"rosctr-N"``)."""
    return S7_ROSCTR_NAMES.get(code, f"rosctr-{code}")


def function_name(code: int) -> str:
    """파라미터 함수 코드 → 이름(미정의면 ``"function-0xNN"``)."""
    return S7_FUNCTION_NAMES.get(code, f"function-0x{code:02x}")


@dataclass(frozen=True)
class S7comm:
    """파싱된 S7comm 메시지 한 개.

    Attributes:
        tpkt_length: TPKT Length 필드(TPKT 헤더 포함 전체 길이).
        cotp_pdu_type: COTP PDU Type(S7comm 은 항상 DT Data ``0xF0``).
        protocol_id: S7comm Protocol ID(항상 ``0x32``).
        rosctr: 메시지 종류 코드(1 Job·2 Ack·3 Ack_Data·7 Userdata).
        rosctr_name: 메시지 종류 이름.
        redundancy_id: Redundancy Identification(reserved, 보통 0).
        pdu_reference: PDU Reference(요청↔응답 상관 키).
        parameter_length: 파라미터부 길이(바이트).
        data_length: 데이터부 길이(바이트).
        error_class: Error Class(Ack/Ack_Data 에서만, 그 외 ``None``).
        error_code: Error Code(Ack/Ack_Data 에서만, 그 외 ``None``).
        function_code: 파라미터 첫 바이트(함수 코드; 파라미터 없으면 ``None``).
        function_name: 함수 이름(함수 코드 있을 때만).
        parameter_offset: 파라미터부 시작 절대 오프셋.
        data_offset: 데이터부 시작 절대 오프셋(= 파라미터부 끝).
        truncated: 선언 길이가 가용 바이트를 넘는지(절단 캡처).
        packet_length: TPKT Length(헤더 포함 ADU 길이).
    """

    tpkt_length: int
    cotp_pdu_type: int
    protocol_id: int
    rosctr: int
    rosctr_name: str
    redundancy_id: int
    pdu_reference: int
    parameter_length: int
    data_length: int
    error_class: Optional[int] = None
    error_code: Optional[int] = None
    function_code: Optional[int] = None
    function_name: Optional[str] = None
    parameter_offset: int = 0
    data_offset: int = 0
    truncated: bool = False
    packet_length: int = 0

    @property
    def is_request(self) -> bool:
        """Job 요청(마스터 → PLC) 여부."""
        return self.rosctr == 0x01

    @property
    def is_response(self) -> bool:
        """Ack/Ack_Data 응답 여부."""
        return self.rosctr in (0x02, 0x03)

    @property
    def is_userdata(self) -> bool:
        """Userdata(진단·프로그래밍 등 확장) 여부."""
        return self.rosctr == 0x07

    @property
    def is_read(self) -> bool:
        """Read Var(메모리 정찰) 함수 여부."""
        return self.function_code in _READ_FUNCTIONS

    @property
    def is_write(self) -> bool:
        """Write Var(메모리 물리 조작) 함수 여부."""
        return self.function_code in _WRITE_FUNCTIONS

    @property
    def is_control(self) -> bool:
        """PLC Control(CPU 기동·재시작) 함수 여부."""
        return self.function_code in _CONTROL_FUNCTIONS

    @property
    def is_stop(self) -> bool:
        """PLC Stop(CPU 정지) 함수 여부."""
        return self.function_code in _STOP_FUNCTIONS

    @property
    def is_download(self) -> bool:
        """블록 다운로드(PLC 로 로직 주입 — Stuxnet 수법) 함수 여부."""
        return self.function_code in _DOWNLOAD_FUNCTIONS

    @property
    def is_upload(self) -> bool:
        """블록 업로드(PLC 로직 추출) 함수 여부."""
        return self.function_code in _UPLOAD_FUNCTIONS

    @property
    def has_error(self) -> bool:
        """오류 응답(Error Class/Code 가 0이 아님) 여부."""
        return bool(self.error_class) or bool(self.error_code)


def parse_s7comm(data: bytes, offset: int = 0) -> Optional[S7comm]:
    """S7comm 메시지 한 개를 파싱한다(TPKT + COTP + S7comm).

    Args:
        data: TCP 102 페이로드(``offset`` 에 TPKT 헤더).
        offset: 메시지가 시작하는 위치(기본 0).

    Returns:
        :class:`S7comm`. TPKT Version 이 ``0x03`` 이 아니거나, COTP PDU Type 이 DT
        Data(``0xF0``)가 아니거나, Protocol ID 가 ``0x32`` 가 아니거나, ROSCTR 가
        알려진 집합(1·2·3·7) 밖이면 ``None``(TCP 스트림 오탐 가드). 헤더/본문이
        가용 바이트를 넘으면(절단) 풀 수 있는 만큼만 채우고 ``truncated=True``.
    """
    end = len(data)
    # TPKT(4) + COTP(최소 LI+PDU type 2) 를 읽을 수 있어야 한다.
    if offset < 0 or offset + 6 > end:
        return None

    # --- TPKT 헤더 ---
    if data[offset] != _TPKT_VERSION:
        return None  # TPKT Version 은 항상 0x03.
    tpkt_length = (data[offset + 4 - 2] << 8) | data[offset + 4 - 1]  # bytes 2,3.

    # --- COTP ---
    cotp_off = offset + 4
    cotp_li = data[cotp_off]
    cotp_pdu_type = data[cotp_off + 1]
    if cotp_pdu_type != _COTP_DT_DATA:
        return None  # S7comm 은 DT Data PDU 에만 실린다(연결 설정 CR/CC 제외).
    s7_off = cotp_off + cotp_li + 1  # COTP 헤더 길이 = LI + 1.

    # --- S7comm 헤더 (최소 10바이트) ---
    if s7_off + 10 > end:
        return None  # 헤더 절단 = 식별 불가(오탐 가드).
    if data[s7_off] != _S7_PROTOCOL_ID:
        return None  # S7comm Protocol ID 는 항상 0x32.

    rosctr = data[s7_off + 1]
    if rosctr not in S7_ROSCTR_NAMES:
        return None  # 알려지지 않은 ROSCTR = 비-S7comm 오탐 가드.

    redundancy_id = (data[s7_off + 2] << 8) | data[s7_off + 3]
    pdu_reference = (data[s7_off + 4] << 8) | data[s7_off + 5]
    parameter_length = (data[s7_off + 6] << 8) | data[s7_off + 7]
    data_length = (data[s7_off + 8] << 8) | data[s7_off + 9]

    error_class: Optional[int] = None
    error_code: Optional[int] = None
    header_len = 10
    if rosctr in _ROSCTR_WITH_ERROR:
        header_len = 12
        if s7_off + 12 > end:
            return None  # Ack/Ack_Data 는 오류 2바이트가 헤더 일부 — 절단 시 거부.
        error_class = data[s7_off + 10]
        error_code = data[s7_off + 11]

    parameter_offset = s7_off + header_len
    data_offset = parameter_offset + parameter_length

    # 함수 코드 = 파라미터 첫 바이트(가용할 때만).
    function_code: Optional[int] = None
    func_name: Optional[str] = None
    if parameter_length >= 1 and parameter_offset < end:
        function_code = data[parameter_offset]
        func_name = function_name(function_code)

    # 절단: 선언된 파라미터+데이터 끝이 가용 바이트를 넘는가.
    declared_end = parameter_offset + parameter_length + data_length
    truncated = declared_end > end

    return S7comm(
        tpkt_length=tpkt_length,
        cotp_pdu_type=cotp_pdu_type,
        protocol_id=_S7_PROTOCOL_ID,
        rosctr=rosctr,
        rosctr_name=rosctr_name(rosctr),
        redundancy_id=redundancy_id,
        pdu_reference=pdu_reference,
        parameter_length=parameter_length,
        data_length=data_length,
        error_class=error_class,
        error_code=error_code,
        function_code=function_code,
        function_name=func_name,
        parameter_offset=parameter_offset,
        data_offset=data_offset,
        truncated=truncated,
        packet_length=tpkt_length,
    )
