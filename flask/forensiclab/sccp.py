"""SCCP — Signalling Connection Control Part 파싱 코어 (ITU-T Q.713; SS7 사용자부).

:mod:`forensiclab.m3ua` 가 "Protocol Data 파라미터(0x0210) 안에는 SS7 의 라우팅
레이블(OPC/DPC)과 **SCCP/ISUP** 페이로드가 그대로 들어 있다"고 했을 때, 그
**SCCP 가 바로 이 모듈이 푸는 계층**이다. M3UA(또는 전통 SS7 의 MTP3)가 신호점
사이의 *망 라우팅*만 책임진다면, SCCP 는 그 위에서 **노드 안의 어떤 응용
(subsystem)에게 전달할지**를 정하고(SSN), 무엇보다 전화번호 형태의 **Global
Title(GT, E.164 번호)로 주소를 지정**해 라우팅한다. 그 위에 TCAP→MAP(이동망
응용부)이 실려 가입자 위치·인증·SMS 라우팅 질의가 오간다.

따라서 SCCP 의 두 주소(Called/Calling Party Address)는 **SS7 공격의 표적과
출처를 와이어에서 직접 드러낸다**:

- **가입자 위치추적·SMS 가로채기**: MAP ``SRI-SM``/``SendRoutingInfo``/
  ``ProvideSubscriberLocation`` 같은 질의는 Called Party 의 GT 에 **피해자의
  MSISDN(전화번호)** 을 실어 HLR(SSN 6)로 보낸다. 그 GT 숫자가 곧 표적 번호다.
- **출처 위장(SS7 스푸핑)**: Calling Party 의 GT/Point Code 가 통신사 경계를
  넘어온 비인가 노드를 가리키면 망 침투 정황. :mod:`forensiclab.flows`·
  :mod:`forensiclab.timeline` 와 상관해 같은 GT 가 다수 번호를 훑으면 정찰/스캔.
- **표적 노드 식별(SSN)**: Subsystem Number 가 HLR(6)·VLR(7)·MSC(8)·MAP(5)·
  gsmSCF(147)·GMLC(145) 중 무엇을 향하는지가 공격 의도를 가른다(위치 vs 과금 vs SMS).

설계 원칙(:mod:`forensiclab.m3ua`·:mod:`forensiclab.sctp` 와 동일):
- 부작용 없음·stdlib 전용·읽기 전용(입력 무변형).
- **연결 없는 데이터 메시지(UDT/UDTS/XUDT/XUDTS)** 의 고정부와 두 주소만 풀고,
  사용자 데이터(TCAP)는 풀지 않은 채 ``data_offset`` 으로만 가리킨다.
- 연결 지향(CR/CC/DT1 등)·LUDT/LUDTS 는 메시지 타입만 식별하고 주소는 ``None``.
- 견고: 빈 입력·미정의 메시지 타입이면 예외 대신 ``None``(오탐 가드). 포인터가
  데이터를 넘어가거나 주소가 절단되면 풀 수 있는 필드까지만 채우고 나머지는 ``None``.

와이어 포맷(Q.713; 예: UDT, Unitdata)::

    message_type(1) | protocol_class(1) | ptr_called(1) | ptr_calling(1) | ptr_data(1)
    ... 가변부: Called Party Address, Calling Party Address, Data(TCAP)

각 포인터는 **자기 포인터 옥텟 위치 기준 상대 오프셋**(target = 포인터위치 + 값).
각 주소는 ``length(1) | address_indicator(1) | [point_code(2)] | [ssn(1)] | [global_title]``.

Address Indicator(Q.713 §3.4.1, ITU 비트 순서)::

    bit1 0x01  Point Code 존재
    bit2 0x02  SSN 존재
    bit3-6 0x3C  Global Title Indicator(GTI)
    bit7 0x40  Routing Indicator(0=GT 로 라우팅, 1=SSN/PC 로 라우팅)
    bit8 0x80  국가용 예약
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Optional, Tuple

__all__ = [
    "SCCP_CONNECTIONLESS_TYPES",
    "Sccp",
    "SccpAddress",
    "parse_sccp",
]

# 메시지 타입 코드 → 이름(Q.713 Table 1).
_MESSAGE_TYPE_NAMES = {
    0x01: "CR",      # Connection request.
    0x02: "CC",      # Connection confirm.
    0x03: "CREF",    # Connection refused.
    0x04: "RLSD",    # Released.
    0x05: "RLC",     # Release complete.
    0x06: "DT1",     # Data form 1.
    0x07: "DT2",     # Data form 2.
    0x08: "AK",      # Data acknowledgement.
    0x09: "UDT",     # Unitdata(연결 없는 데이터 — TCAP/MAP 운반).
    0x0A: "UDTS",    # Unitdata service(반송).
    0x0B: "ED",      # Expedited data.
    0x0C: "EA",      # Expedited data acknowledgement.
    0x0D: "RSR",     # Reset request.
    0x0E: "RSC",     # Reset confirm.
    0x0F: "ERR",     # Protocol data unit error.
    0x10: "IT",      # Inactivity test.
    0x11: "XUDT",    # Extended unitdata(hop counter 포함).
    0x12: "XUDTS",   # Extended unitdata service.
    0x13: "LUDT",    # Long unitdata(2옥텟 포인터).
    0x14: "LUDTS",   # Long unitdata service.
}

# 연결 없는(connectionless) 메시지 타입 — TCAP/MAP 가 실리는 평면.
SCCP_CONNECTIONLESS_TYPES = frozenset({0x09, 0x0A, 0x11, 0x12, 0x13, 0x14})

# 주소·포인터 파싱을 지원하는(1옥텟 포인터) 연결 없는 타입의 고정부 레이아웃.
# second: 두 번째 옥텟의 의미. hop: hop counter 옥텟 유무. n_ptr: 포인터 개수.
_CL_LAYOUT = {
    0x09: ("protocol_class", False, 3),  # UDT.
    0x0A: ("return_cause", False, 3),    # UDTS.
    0x11: ("protocol_class", True, 4),   # XUDT.
    0x12: ("return_cause", True, 4),     # XUDTS.
}

# Subsystem Number → 이름(Q.713 §3.4.2.2 + 3GPP TS 23.003 / 흔한 할당).
_SSN_NAMES = {
    0: "unknown",
    1: "SCCP management",
    2: "reserved(ITU)",
    3: "ISUP",
    4: "OMAP",
    5: "MAP",          # Mobile Application Part — 이동망 질의의 핵심.
    6: "HLR",          # Home Location Register — 위치/SMS 라우팅 표적.
    7: "VLR",          # Visitor Location Register.
    8: "MSC",          # Mobile Switching Center.
    9: "EIR",          # Equipment Identity Register.
    10: "AUC",         # Authentication Centre.
    11: "ISDN supplementary services",
    13: "broadband ISDN",
    14: "TC test responder",
    142: "RANAP",
    143: "RNSAP",
    145: "GMLC",       # Gateway Mobile Location Centre — 위치 서비스.
    146: "CAP",        # CAMEL Application Part.
    147: "gsmSCF",     # 지능망 서비스 제어 — 과금/리다이렉트.
    148: "SIWF",
    149: "SGSN",       # Serving GPRS Support Node.
    150: "GGSN",       # Gateway GPRS Support Node.
}

# Routing Indicator(bit7) — 0=Global Title 로 라우팅, 1=SSN/Point Code 로 라우팅.
_SCCP_RI_MASK = 0x40
_SCCP_PC_MASK = 0x01
_SCCP_SSN_MASK = 0x02
_SCCP_GTI_MASK = 0x3C

# GTI 별 GT 헤더(주소 숫자 앞) 옥텟 수(ITU Q.713 §3.4.2.3).
_GTI_HEADER_LEN = {
    1: 1,   # nature of address indicator.
    2: 1,   # translation type.
    3: 2,   # translation type + numbering plan/encoding scheme.
    4: 3,   # translation type + NP/ES + nature of address indicator.
}


def _decode_bcd_digits(raw: bytes) -> str:
    """Global Title 주소 숫자(BCD, low nibble first)를 문자열로 디코드한다.

    각 옥텟은 두 자리(하위 4비트가 먼저)다. 0xF(filler)는 멈춤 신호로 보고
    그 자리부터 버린다. 0~9 는 숫자, 그 외 nibble 은 16진수 문자로 표기한다.
    """
    out = []
    for byte in raw:
        for nibble in (byte & 0x0F, byte >> 4):
            if nibble == 0x0F:
                return "".join(out)
            out.append("0123456789abcdef"[nibble])
    return "".join(out)


@dataclass(frozen=True)
class SccpAddress:
    """SCCP Called/Calling Party Address.

    Attributes:
        address_indicator: Address Indicator 옥텟(원본 비트).
        has_point_code: Point Code(SPC) 포함 여부.
        has_ssn: Subsystem Number 포함 여부.
        gti: Global Title Indicator(0~4; 0 이면 GT 없음).
        route_on_ssn: Routing Indicator — True 면 SSN/PC, False 면 GT 로 라우팅.
        point_code: 14비트 신호점 코드(ITU; 없으면 ``None``).
        ssn: Subsystem Number(없으면 ``None``).
        global_title_digits: 디코드된 GT 주소 숫자(보통 E.164 번호; 없거나
            풀 수 없으면 ``None``).
    """

    address_indicator: int
    has_point_code: bool
    has_ssn: bool
    gti: int
    route_on_ssn: bool
    point_code: Optional[int]
    ssn: Optional[int]
    global_title_digits: Optional[str]

    @property
    def ssn_name(self) -> Optional[str]:
        """SSN 의 사람이 읽는 이름(없으면 ``None``, 미상이면 ``"ssn-<n>"``)."""
        if self.ssn is None:
            return None
        return _SSN_NAMES.get(self.ssn, f"ssn-{self.ssn}")

    @property
    def routing_indicator(self) -> str:
        """라우팅 기준 표기 — ``"SSN"`` 또는 ``"GT"``."""
        return "SSN" if self.route_on_ssn else "GT"


def _parse_address(data: bytes, start: int) -> Optional[SccpAddress]:
    """주소 파라미터(length-prefixed)를 :class:`SccpAddress` 로 푼다.

    절단이면 풀 수 있는 필드까지만 채운다. length·Address Indicator 옥텟조차
    없으면 ``None``.
    """
    if start < 0 or start + 1 >= len(data):
        return None
    length = data[start]
    if length < 1:
        return None
    # 주소 내용은 [start+1, start+1+length); 절단 캡처를 고려해 클램프.
    end = min(start + 1 + length, len(data))
    ai = data[start + 1]
    has_pc = bool(ai & _SCCP_PC_MASK)
    has_ssn = bool(ai & _SCCP_SSN_MASK)
    gti = (ai & _SCCP_GTI_MASK) >> 2
    route_on_ssn = bool(ai & _SCCP_RI_MASK)

    pos = start + 2
    point_code = None
    if has_pc:
        if pos + 2 <= end:
            # ITU 14비트 SPC, 2옥텟 little-endian.
            point_code = struct.unpack_from("<H", data, pos)[0] & 0x3FFF
        pos += 2
    ssn = None
    if has_ssn:
        if pos < end:
            ssn = data[pos]
        pos += 1

    gt_digits = None
    if gti != 0 and pos < end:
        header = _GTI_HEADER_LEN.get(gti, 0)
        digit_start = pos + header
        if digit_start < end:
            gt_digits = _decode_bcd_digits(data[digit_start:end])
            if not gt_digits:
                gt_digits = None

    return SccpAddress(
        address_indicator=ai,
        has_point_code=has_pc,
        has_ssn=has_ssn,
        gti=gti,
        route_on_ssn=route_on_ssn,
        point_code=point_code,
        ssn=ssn,
        global_title_digits=gt_digits,
    )


@dataclass(frozen=True)
class Sccp:
    """파싱된 SCCP 메시지(연결 없는 데이터 메시지는 두 주소까지).

    사용자 데이터(TCAP/MAP)는 풀지 않으며 :attr:`data_offset` 으로만 가리킨다.

    Attributes:
        message_type: 메시지 타입 코드.
        protocol_class: Protocol Class 옥텟(UDT/XUDT; 아니면 ``None``).
        return_cause: Return Cause 옥텟(UDTS/XUDTS; 아니면 ``None``).
        hop_counter: Hop Counter(XUDT/XUDTS; 아니면 ``None``).
        called_party: Called Party Address(없으면 ``None``).
        calling_party: Calling Party Address(없으면 ``None``).
        data_offset: 사용자 데이터(TCAP)가 시작하는 절대 오프셋(없으면 ``None``).
        payload_offset: 고정부 다음(첫 가변부) 절대 오프셋.
    """

    message_type: int
    protocol_class: Optional[int]
    return_cause: Optional[int]
    hop_counter: Optional[int]
    called_party: Optional[SccpAddress]
    calling_party: Optional[SccpAddress]
    data_offset: Optional[int]
    payload_offset: int

    @property
    def message_type_name(self) -> str:
        """메시지 타입의 사람이 읽는 이름(미상이면 ``"type-0x.."``)."""
        return _MESSAGE_TYPE_NAMES.get(self.message_type, f"type-0x{self.message_type:02x}")

    @property
    def is_connectionless(self) -> bool:
        """연결 없는(UDT/UDTS/XUDT/XUDTS/LUDT/LUDTS) 메시지 여부 — TCAP/MAP 평면."""
        return self.message_type in SCCP_CONNECTIONLESS_TYPES

    @property
    def is_unitdata(self) -> bool:
        """UDT/XUDT(정상 연결 없는 데이터 전달) 여부."""
        return self.message_type in (0x09, 0x11)

    @property
    def is_unitdata_service(self) -> bool:
        """UDTS/XUDTS(전달 실패 반송) 여부 — 라우팅/주소 오류 단서."""
        return self.message_type in (0x0A, 0x12)

    @property
    def protocol_class_value(self) -> Optional[int]:
        """Protocol Class 의 하위 4비트(클래스 0~3; 없으면 ``None``)."""
        if self.protocol_class is None:
            return None
        return self.protocol_class & 0x0F


def parse_sccp(data: bytes, offset: int = 0) -> Optional[Sccp]:
    """원시 바이트에서 SCCP 메시지를 파싱한다.

    Args:
        data: SCCP 메시지 바이트. 보통 :mod:`forensiclab.m3ua` Protocol Data
            파라미터(0x0210) 안 MTP3 라우팅 레이블 다음부터다.
        offset: 메시지가 시작하는 위치(기본 0).

    Returns:
        :class:`Sccp`. 메시지 타입 옥텟이 없거나 Q.713 정의(0x01~0x14)에 없으면
        ``None``(오탐 가드). 연결 없는 UDT/UDTS/XUDT/XUDTS 는 고정부와 두 주소를
        풀고 ``data_offset`` 으로 TCAP 를 가리킨다. 그 외 타입은 타입만 식별하고
        주소는 ``None``. 포인터/주소가 절단되면 풀 수 있는 만큼만 채운다.
    """
    if offset < 0 or offset >= len(data):
        return None
    message_type = data[offset]
    if message_type not in _MESSAGE_TYPE_NAMES:
        return None

    layout = _CL_LAYOUT.get(message_type)
    if layout is None:
        # 연결 지향·LUDT/LUDTS 등: 타입만 식별.
        return Sccp(
            message_type=message_type,
            protocol_class=None,
            return_cause=None,
            hop_counter=None,
            called_party=None,
            calling_party=None,
            data_offset=None,
            payload_offset=min(offset + 1, len(data)),
        )

    second_kind, has_hop, n_ptr = layout
    fixed_len = 1 + 1 + (1 if has_hop else 0) + n_ptr
    payload_offset = min(offset + fixed_len, len(data))

    # 고정부가 모자라면 풀 수 있는 필드만 채우고 주소는 생략.
    if offset + fixed_len > len(data):
        protocol_class = return_cause = hop_counter = None
        if offset + 1 < len(data):
            if second_kind == "protocol_class":
                protocol_class = data[offset + 1]
            else:
                return_cause = data[offset + 1]
        if has_hop and offset + 2 < len(data):
            hop_counter = data[offset + 2]
        return Sccp(
            message_type=message_type,
            protocol_class=protocol_class,
            return_cause=return_cause,
            hop_counter=hop_counter,
            called_party=None,
            calling_party=None,
            data_offset=None,
            payload_offset=payload_offset,
        )

    protocol_class = data[offset + 1] if second_kind == "protocol_class" else None
    return_cause = data[offset + 1] if second_kind == "return_cause" else None
    hop_counter = data[offset + 2] if has_hop else None

    # 포인터 옥텟들의 절대 위치(고정부 안, second/hop 다음).
    ptr_base = offset + 2 + (1 if has_hop else 0)
    ptr_called_pos = ptr_base
    ptr_calling_pos = ptr_base + 1
    ptr_data_pos = ptr_base + 2

    def _target(ptr_pos: int) -> Optional[int]:
        # 포인터 값은 자기 위치 기준 상대 오프셋. 0 이면 파라미터 없음.
        val = data[ptr_pos]
        if val == 0:
            return None
        return ptr_pos + val

    called_target = _target(ptr_called_pos)
    calling_target = _target(ptr_calling_pos)
    data_target = _target(ptr_data_pos)

    called_party = _parse_address(data, called_target) if called_target is not None else None
    calling_party = _parse_address(data, calling_target) if calling_target is not None else None
    data_offset = data_target if (data_target is not None and data_target < len(data)) else None

    return Sccp(
        message_type=message_type,
        protocol_class=protocol_class,
        return_cause=return_cause,
        hop_counter=hop_counter,
        called_party=called_party,
        calling_party=calling_party,
        data_offset=data_offset,
        payload_offset=payload_offset,
    )
