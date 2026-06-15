"""IEC 60870-5-104 — 전력망 SCADA 원격제어 프로토콜 파싱 코어(IEC 104, 보통 TCP 2404).

:mod:`forensiclab.dnp3` 가 **북미** 전력망 SCADA 의 표준이라면 IEC 60870-5-104(IEC 104)는
**유럽·아시아·그 외 전 세계** 전력망(및 수도·송유)의 표준 원격제어(telecontrol) 프로토콜이다 —
제어 센터(controlling station)가 광역에 흩어진 변전소(controlled station)의 차단기·아날로그
설정값을 폴링·제어하는 OT 평면. IEC 101(직렬)의 TCP/IP 적응판으로, :mod:`forensiclab.dnp3`
와 **형제 관계의 제어 평면**이다.

**Industroyer/CRASHOVERRIDE(2016 우크라이나 정전)**는 DNP3·IEC 101 뿐 아니라 **IEC 104
전용 무기 모듈**을 갖고 있었다 — 변전소의 차단기(breaker)를 C_SC/C_DC 명령으로 열어 정전을
일으켰다. IEC 104 노출 자체가 중요 인프라 제어 평면 정황이고, C_SC/C_DC/C_RC/C_SE 명령
한 번이 물리 차단기·밸브·설정값 조작이다.

설계상 **인증·암호화가 없다**(평문; Secure Authentication 은 IEC 62351 별도 확장) — 2404 에
APDU 가 보이는 것 자체가 노출된 SCADA 정황.

와이어(APCI + ASDU):
- **APCI**(Application Protocol Control Information):
  - **시작 바이트** ``0x68``(1, 고정 — 강한 오탐 가드).
  - **APDU Length**(1: 시작 바이트·길이 바이트 제외, 제어 4 + ASDU 바이트 수 = 4~253).
  - **제어 필드 4옥텟**: 첫 옥텟 하위 2비트로 프레임 포맷 판별.
- **프레임 포맷**:
  - **I-format**(정보 전송, CF1 bit0=0): 송신열번호 N(S)·수신열번호 N(R) 15비트씩 + **ASDU**.
    실제 데이터·제어 명령이 실린다.
  - **S-format**(감독, CF1 = ``0x01``): N(R) 만 — 수신 확인(ACK)용. ASDU 없음.
  - **U-format**(번호 없는 제어, CF1 하위 2비트=``11``): STARTDT/STOPDT/TESTFR 의 act/con —
    데이터 전송 개시·중지·연결 시험.
- **ASDU**(I-format 일 때, 6바이트 헤더):
  - **Type ID**(1): 정보 종류(1 단일점·45 C_SC_NA_1 단일명령·100 C_IC_NA_1 총괄심문…).
  - **VSQ**(1): bit7 SQ + 정보객체 수(하위 7비트).
  - **COT**(2): 전송 원인(bit0~5)·P/N(bit6 부정확인)·T(bit7 시험) + 발신자 주소(2번째 옥텟).
  - **Common Address**(2, little-endian): 변전소(controlled station) 주소(장치 열거 키).

포렌식 핵심:
- **노출된 중요 인프라 제어 평면·표적**: 2404 자체가 전력망 SCADA 정황. ``common_address``
  로 변전소 열거, N(S)/N(R) 로 :mod:`forensiclab.flows` 안 전송 순서·손실 추적.
- **세션 제어 흐름**: ``u_function_name`` STARTDT_ACT→STARTDT_CON 로 데이터 전송 개시
  (:mod:`forensiclab.timeline`); TESTFR 는 연결 유지(keep-alive).
- **응용 의도(공격)**: ``type_name`` — C_SC/C_DC/C_RC/C_SE(``is_control``)가 차단기·밸브·
  설정값 물리 조작, C_IC(총괄심문)/C_RD(읽기)는 정찰(``is_interrogation``). 명령 폭주·예상치
  못한 ``common_address`` 로의 제어가 Industroyer 류 단서.
- **전송 원인**: ``cause_name``(6 act 활성화·7 actcon·10 actterm·20 inrogen 심문응답)·
  ``is_negative``(P/N=1, 거부된 명령)·``is_test``(T=1).

설계 원칙(:mod:`forensiclab.dnp3`·:mod:`forensiclab.modbus` 와 동일):
- 부작용 없음·stdlib 전용·읽기 전용(입력 무변형)·``offset`` 지원.
- 6바이트(APCI) 미만이거나, 시작 바이트가 ``0x68`` 이 아니거나, Length 가 4 미만/253 초과면
  ``None``(오탐 가드). 정보객체 본문은 ``payload_offset`` 으로 가리키고 ASDU 헤더만 디코드.
  ASDU 가 가용 바이트를 넘으면 ``truncated=True``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

__all__ = [
    "IEC104",
    "IEC104_TYPES",
    "IEC104_CAUSES",
    "IEC104_U_FUNCTIONS",
    "type_name",
    "cause_name",
    "u_function_name",
    "parse_iec104",
]

# ASDU Type Identification(주요 항목). 1~40 모니터링 방향, 45~ 제어 방향, 70~ 시스템.
IEC104_TYPES = {
    1: "M_SP_NA_1",   # 단일점 정보.
    3: "M_DP_NA_1",   # 이중점 정보.
    5: "M_ST_NA_1",   # 스텝 위치.
    7: "M_BO_NA_1",   # 32비트 비트열.
    9: "M_ME_NA_1",   # 측정값(정규화).
    11: "M_ME_NB_1",  # 측정값(스케일).
    13: "M_ME_NC_1",  # 측정값(부동소수).
    15: "M_IT_NA_1",  # 적산값(카운터).
    30: "M_SP_TB_1",  # 단일점+시각.
    31: "M_DP_TB_1",  # 이중점+시각.
    36: "M_ME_TF_1",  # 측정값(부동)+시각.
    37: "M_IT_TB_1",  # 적산값+시각.
    45: "C_SC_NA_1",  # 단일 명령(차단기 ON/OFF) — 물리 조작.
    46: "C_DC_NA_1",  # 이중 명령 — 물리 조작.
    47: "C_RC_NA_1",  # 조정 스텝 명령 — 물리 조작.
    48: "C_SE_NA_1",  # 설정값 명령(정규화) — 물리 조작.
    49: "C_SE_NB_1",  # 설정값 명령(스케일) — 물리 조작.
    50: "C_SE_NC_1",  # 설정값 명령(부동) — 물리 조작.
    51: "C_BO_NA_1",  # 32비트 비트열 명령 — 물리 조작.
    58: "C_SC_TA_1",  # 단일 명령+시각 — 물리 조작.
    59: "C_DC_TA_1",  # 이중 명령+시각 — 물리 조작.
    60: "C_RC_TA_1",  # 조정 스텝+시각 — 물리 조작.
    61: "C_SE_TA_1",  # 설정값(정규화)+시각 — 물리 조작.
    62: "C_SE_TB_1",  # 설정값(스케일)+시각 — 물리 조작.
    63: "C_SE_TC_1",  # 설정값(부동)+시각 — 물리 조작.
    64: "C_BO_TA_1",  # 비트열 명령+시각 — 물리 조작.
    70: "M_EI_NA_1",  # 초기화 종료.
    100: "C_IC_NA_1",  # 총괄 심문(정찰).
    101: "C_CI_NA_1",  # 적산값 심문.
    102: "C_RD_NA_1",  # 읽기 명령(정찰).
    103: "C_CS_NA_1",  # 시각 동기화.
    104: "C_TS_NA_1",  # 시험 명령.
    105: "C_RP_NA_1",  # 프로세스 리셋.
    107: "C_TS_TA_1",  # 시험 명령+시각.
    110: "P_ME_NA_1",  # 측정값 파라미터(정규화).
    113: "P_AC_NA_1",  # 파라미터 활성화.
    120: "F_FR_NA_1",  # 파일 준비됨(파일 전송).
    122: "F_SC_NA_1",  # 파일/섹션 호출.
}

# Cause of Transmission(전송 원인, 하위 6비트).
IEC104_CAUSES = {
    1: "per/cyc",      # 주기적.
    2: "back",         # 배경 스캔.
    3: "spont",        # 자발적(이벤트).
    4: "init",         # 초기화.
    5: "req",          # 요청/요구.
    6: "act",          # 활성화(명령 개시).
    7: "actcon",       # 활성화 확인.
    8: "deact",        # 비활성화.
    9: "deactcon",     # 비활성화 확인.
    10: "actterm",     # 활성화 종료.
    11: "retrem",      # 원격 명령 회신.
    12: "retloc",      # 로컬 명령 회신.
    13: "file",        # 파일 전송.
    20: "inrogen",     # 총괄 심문 응답.
    21: "inro1",       # 그룹 1 심문 응답.
    37: "reqcogen",    # 총괄 카운터 요청.
    44: "unknown type",
    45: "unknown cause",
    46: "unknown asdu addr",
    47: "unknown object addr",
}

# U-format 제어 필드 첫 옥텟 → 기능 이름.
IEC104_U_FUNCTIONS = {
    0x07: "STARTDT_ACT",
    0x0B: "STARTDT_CON",
    0x13: "STOPDT_ACT",
    0x23: "STOPDT_CON",
    0x43: "TESTFR_ACT",
    0x83: "TESTFR_CON",
}

# 물리 공정 조작(차단기·설정값) Type ID(제어 방향 명령).
_CONTROL_TYPES = frozenset(range(45, 52)) | frozenset(range(58, 65))

# 정찰(읽기·심문) Type ID.
_INTERROGATION_TYPES = frozenset({100, 101, 102})

_START = 0x68

# COT 비트.
_COT_CAUSE_MASK = 0x3F
_COT_PN = 0x40   # P/N: 1=부정 확인(거부).
_COT_TEST = 0x80  # T: 1=시험.


def type_name(type_id: int) -> str:
    """ASDU Type ID → 이름(미정의면 ``"type-N"``)."""
    return IEC104_TYPES.get(type_id, f"type-{type_id}")


def cause_name(cause: int) -> str:
    """전송 원인(하위 6비트) → 이름(미정의면 ``"cause-N"``)."""
    return IEC104_CAUSES.get(cause & _COT_CAUSE_MASK, f"cause-{cause & _COT_CAUSE_MASK}")


def u_function_name(cf1: int) -> str:
    """U-format 제어 필드 첫 옥텟 → 기능 이름(미정의면 ``"u-0xNN"``)."""
    return IEC104_U_FUNCTIONS.get(cf1, f"u-0x{cf1:02x}")


@dataclass(frozen=True)
class IEC104:
    """파싱된 IEC 104 APDU 한 개.

    Attributes:
        apdu_length: APDU Length 필드(제어 4 + ASDU 바이트 수).
        frame_format: ``"I"``·``"S"``·``"U"`` 중 하나.
        send_seq: 송신열번호 N(S)(I-format 만, 그 외 ``None``).
        recv_seq: 수신열번호 N(R)(I·S-format 만, 그 외 ``None``).
        u_function: U-format 제어 첫 옥텟 원값(U-format 만).
        u_function_name: U-format 기능 이름(U-format 만).
        type_id: ASDU Type Identification(I-format 만).
        type_name: ASDU Type 이름(I-format 만).
        sq: VSQ 의 SQ 비트(연속 정보객체 주소; I-format 만).
        num_objects: 정보객체 수(VSQ 하위 7비트; I-format 만).
        cause: 전송 원인(하위 6비트; I-format 만).
        cause_name: 전송 원인 이름(I-format 만).
        negative: P/N 비트(거부된 명령; I-format 만).
        test: T 비트(시험; I-format 만).
        originator_address: 발신자 주소(COT 2번째 옥텟; I-format 만).
        common_address: 변전소 공통 주소(little-endian; I-format 만).
        payload_offset: 정보객체 본문 시작 절대 오프셋(I-format 일 때).
        truncated: ASDU 가 가용 바이트를 넘는지(절단 캡처).
        packet_length: 전체 APDU 길이(시작 2 + apdu_length).
    """

    apdu_length: int
    frame_format: str
    send_seq: Optional[int] = None
    recv_seq: Optional[int] = None
    u_function: Optional[int] = None
    u_function_name: Optional[str] = None
    type_id: Optional[int] = None
    type_name: Optional[str] = None
    sq: bool = False
    num_objects: int = 0
    cause: Optional[int] = None
    cause_name: Optional[str] = None
    negative: bool = False
    test: bool = False
    originator_address: Optional[int] = None
    common_address: Optional[int] = None
    payload_offset: int = 0
    truncated: bool = False
    packet_length: int = 0

    @property
    def is_i_format(self) -> bool:
        """정보 전송(ASDU 운반) 프레임인지."""
        return self.frame_format == "I"

    @property
    def is_s_format(self) -> bool:
        """감독(수신 확인) 프레임인지."""
        return self.frame_format == "S"

    @property
    def is_u_format(self) -> bool:
        """번호 없는 제어(STARTDT/STOPDT/TESTFR) 프레임인지."""
        return self.frame_format == "U"

    @property
    def is_command(self) -> bool:
        """제어 방향 명령 Type(45~107 명령군)인지."""
        return self.type_id is not None and (
            self.type_id in _CONTROL_TYPES
            or self.type_id in _INTERROGATION_TYPES
            or self.type_id in (103, 104, 105, 107)
        )

    @property
    def is_control(self) -> bool:
        """물리 공정 조작(차단기·설정값 명령) Type 인지."""
        return self.type_id in _CONTROL_TYPES

    @property
    def is_interrogation(self) -> bool:
        """정찰(총괄 심문·읽기) Type 인지."""
        return self.type_id in _INTERROGATION_TYPES


def parse_iec104(data: bytes, offset: int = 0) -> Optional[IEC104]:
    """IEC 104 APDU 한 개를 파싱한다.

    Args:
        data: IEC 104 바이트(보통 TCP 2404 페이로드). ``offset`` 에 시작 바이트 ``0x68``.
        offset: APDU 가 시작하는 위치(기본 0).

    Returns:
        :class:`IEC104`. 6바이트(APCI) 미만이거나, 시작 바이트가 ``0x68`` 이 아니거나,
        Length 가 4 미만/253 초과면 ``None``(오탐 가드). ASDU 가 가용 바이트를 넘으면
        ``truncated=True``. 정보객체 본문은 ``payload_offset`` 으로만 가리킨다.
    """
    end = len(data)
    if offset < 0 or offset + 6 > end:
        return None

    if data[offset] != _START:
        return None  # 시작 바이트 불일치 = 비-IEC104 오탐 가드.

    apdu_length = data[offset + 1]
    if apdu_length < 4 or apdu_length > 253:
        return None  # 제어 필드 4옥텟이 최소, 최대 253.

    cf1 = data[offset + 2]
    cf2 = data[offset + 3]
    cf3 = data[offset + 4]
    cf4 = data[offset + 5]

    packet_length = 2 + apdu_length
    truncated = offset + packet_length > end

    if (cf1 & 0x01) == 0:
        frame_format = "I"
    elif (cf1 & 0x03) == 0x01:
        frame_format = "S"
    else:  # (cf1 & 0x03) == 0x03
        frame_format = "U"

    if frame_format == "S":
        recv_seq = (cf3 >> 1) | (cf4 << 7)
        return IEC104(
            apdu_length=apdu_length,
            frame_format="S",
            recv_seq=recv_seq,
            payload_offset=offset + 6,
            truncated=truncated,
            packet_length=packet_length,
        )

    if frame_format == "U":
        return IEC104(
            apdu_length=apdu_length,
            frame_format="U",
            u_function=cf1,
            u_function_name=u_function_name(cf1),
            payload_offset=offset + 6,
            truncated=truncated,
            packet_length=packet_length,
        )

    # I-format: 송/수신 열번호 + ASDU 헤더(6바이트).
    send_seq = (cf1 >> 1) | (cf2 << 7)
    recv_seq = (cf3 >> 1) | (cf4 << 7)

    asdu = offset + 6
    type_id: Optional[int] = None
    t_name: Optional[str] = None
    sq = False
    num_objects = 0
    cause: Optional[int] = None
    c_name: Optional[str] = None
    negative = False
    test = False
    originator_address: Optional[int] = None
    common_address: Optional[int] = None

    if asdu + 1 <= end:
        type_id = data[asdu]
        t_name = type_name(type_id)
    if asdu + 2 <= end:
        vsq = data[asdu + 1]
        sq = bool(vsq & 0x80)
        num_objects = vsq & 0x7F
    if asdu + 3 <= end:
        cot = data[asdu + 2]
        cause = cot & _COT_CAUSE_MASK
        c_name = cause_name(cot)
        negative = bool(cot & _COT_PN)
        test = bool(cot & _COT_TEST)
    if asdu + 4 <= end:
        originator_address = data[asdu + 3]
    if asdu + 6 <= end:
        common_address = data[asdu + 4] | (data[asdu + 5] << 8)  # little-endian.

    # 정보객체 본문은 ASDU 헤더(6) 뒤에서 시작.
    payload_offset = asdu + 6

    return IEC104(
        apdu_length=apdu_length,
        frame_format="I",
        send_seq=send_seq,
        recv_seq=recv_seq,
        type_id=type_id,
        type_name=t_name,
        sq=sq,
        num_objects=num_objects,
        cause=cause,
        cause_name=c_name,
        negative=negative,
        test=test,
        originator_address=originator_address,
        common_address=common_address,
        payload_offset=payload_offset,
        truncated=truncated,
        packet_length=packet_length,
    )
