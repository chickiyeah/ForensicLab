"""ISUP — ISDN User Part 파싱 코어 (ITU-T Q.763; SS7 전화 호 제어부).

:mod:`forensiclab.m3ua` 가 "Protocol Data 파라미터(0x0210) 안에는 SS7 의 라우팅
레이블(OPC/DPC)과 **SCCP/ISUP** 페이로드가 그대로 들어 있다"고 했을 때,
:mod:`forensiclab.sccp`(→TCAP→MAP, 이동망 질의)와 **나란히 갈라지는 다른 한
갈래가 바로 이 ISUP** 다. SCCP 가 노드 안 응용(가입자 DB·SMS)을 주소지정하는
*데이터/질의 평면*이라면, ISUP 는 MTP3(M3UA) 위에 **직접 실려** 회선(trunk)
하나하나로 **전화 호(call)를 세우고·울리고·이어주고·끊는** 호 제어 평면이다 —
전통 전화망(PSTN)과 그 IP 후신(SIGTRAN) 양쪽에서 통화의 골격을 이룬다.

따라서 ISUP 는 **누가 누구에게 전화했는가(CDR 재구성)** 를 와이어에서 직접
드러낸다:

- **호 설정·당사자 번호(IAM)**: Initial Address Message 는 호 개시 메시지로,
  **Called Party Number**(피호출 번호)를 필수로, **Calling Party Number**(발신
  번호)를 선택으로 싣는다. 둘을 BCD 로 디코드하면 통화 기록(CDR)의 핵심인
  "발신→착신" 쌍이 완성된다 — :mod:`forensiclab.sccp` 가 GT 숫자(MSISDN)를 푼 것과
  같은 깊이다.
- **발신번호 위조(caller ID spoofing)**: Calling Party Number 의 *제시 제한
  표시(APRI)* 가 ``presentation restricted`` 면 표시 억제, ``not available`` 면
  발신번호 미상 — 위조·익명 통화 정황. 스크리닝 표시는 망이 검증한 번호인지 가른다.
- **호 수명·종료 사유(타임라인)**: IAM(설정)→ACM(착신 응답완료/링)→ANM(통화
  연결)→REL/RLC(해제) 가 한 호의 :mod:`forensiclab.timeline` 을 이룬다. **CIC
  (Circuit Identification Code)** 는 그 한 통화가 어느 회선에서 일어났는지를 못
  박는 상관 키다(:mod:`forensiclab.tcap` TID·:mod:`forensiclab.sctp`
  verification tag·:mod:`forensiclab.esp` SPI 대응). REL 의 **cause value**
  (Q.850)는 끊긴 이유(통화중·미할당 번호·정상 해제)를 드러내 통화 사기 탐침
  (없는 번호 대량 발신)·플러딩 패턴의 단서가 된다.

설계 원칙(:mod:`forensiclab.sccp`·:mod:`forensiclab.tcap` 와 동일):
- 부작용 없음·stdlib 전용·읽기 전용(입력 무변형).
- **CIC·메시지 타입은 모든 메시지에서** 풀고, 포렌식상 핵심인 **IAM 의 당사자
  번호와 REL 의 cause** 만 깊게 디코드한다. 그 외 메시지·파라미터 본문은 풀지
  않은 채 ``payload_offset`` 으로만 가리킨다.
- 견고: 빈 입력·미정의 메시지 타입이면 예외 대신 ``None``(오탐 가드). 포인터가
  데이터를 넘어가거나 파라미터가 절단되면 풀 수 있는 필드까지만 채운다.

와이어 포맷(Q.763; MTP3 라우팅 레이블 다음부터)::

    CIC(2, little-endian, 하위 12비트) | message_type(1) | <파라미터부>

파라미터부는 메시지 타입별로 ``mandatory fixed`` + ``mandatory variable``
(포인터 기반) + ``optional``(TLV, 0x00 종단)로 나뉜다. 각 포인터는 **자기 위치
기준 상대 오프셋**(target = 포인터위치 + 값; 0=없음) — :mod:`forensiclab.sccp` 와
동일한 규약이다.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Optional, Tuple

__all__ = [
    "ISUP_MESSAGE_TYPES",
    "Isup",
    "parse_isup",
]

# 메시지 타입 코드 → 이름(Q.763 Table 4; 흔한 것 위주).
_MESSAGE_TYPE_NAMES = {
    0x01: "IAM",   # Initial address — 호 개시(피호출/발신 번호).
    0x02: "SAM",   # Subsequent address.
    0x03: "INR",   # Information request.
    0x04: "INF",   # Information.
    0x05: "COT",   # Continuity.
    0x06: "ACM",   # Address complete — 착신 도달(링).
    0x07: "CON",   # Connect.
    0x08: "FOT",   # Forward transfer.
    0x09: "ANM",   # Answer — 통화 연결(과금 시작).
    0x0B: "CPG",   # Call progress.
    0x0C: "REL",   # Release — 호 해제(cause).
    0x0D: "RES",   # Resume.
    0x0E: "SUS",   # Suspend.
    0x10: "RLC",   # Release complete.
    0x12: "CCR",   # Continuity check request.
    0x13: "RSC",   # Reset circuit.
    0x14: "BLO",   # Blocking — 회선 차단.
    0x15: "BLA",   # Blocking acknowledgement.
    0x16: "UBL",   # Unblocking.
    0x17: "UBA",   # Unblocking acknowledgement.
    0x18: "GRS",   # Circuit group reset.
    0x2A: "CFN",   # Confusion.
    0x2C: "GRA",   # Circuit group reset acknowledgement.
    0x2E: "FAC",   # Facility.
    0x31: "USR",   # User-to-user information.
}
ISUP_MESSAGE_TYPES = frozenset(_MESSAGE_TYPE_NAMES)

# 호 설정 흐름의 핵심 메시지(타임라인 골격).
_IAM = 0x01
_ACM = 0x06
_ANM = 0x09
_REL = 0x0C
_RLC = 0x10

# IAM mandatory fixed part 길이(Q.763 §3.34): NCI(1)+FCI(2)+CPC(1)+TMR(1).
_IAM_FIXED_LEN = 5

# 선택 파라미터 코드(Q.763 Table 5; 본 모듈이 깊게 보는 것).
_PARAM_CALLING_PARTY_NUMBER = 0x0A
_PARAM_END_OF_OPTIONAL = 0x00

# Cause value(Q.850; 흔한 것) → 이름.
_CAUSE_NAMES = {
    1: "unallocatedNumber",
    16: "normalCallClearing",
    17: "userBusy",
    18: "noUserResponding",
    19: "noAnswerFromUser",
    21: "callRejected",
    22: "numberChanged",
    27: "destinationOutOfOrder",
    28: "invalidNumberFormat",
    31: "normalUnspecified",
    34: "noCircuitAvailable",
    38: "networkOutOfOrder",
    41: "temporaryFailure",
    42: "switchingEquipmentCongestion",
}

# 발신번호 제시 제한 표시(APRI; Q.763 §3.10 octet 2 bits 4-3) → 이름.
_APRI_NAMES = {
    0: "allowed",
    1: "restricted",
    2: "notAvailable",
    3: "spare",
}


def _decode_address_signals(raw: bytes, odd: bool) -> str:
    """주소 신호(BCD, 옥텟당 2자리·하위 nibble 먼저)를 문자열로 디코드한다.

    ``odd`` 가 참이면 마지막 옥텟의 상위 nibble 은 filler 이므로 버린다(odd/even
    표시에 따른 처리). 0~9 는 숫자, 그 외 nibble 은 16진수 문자로 표기한다.
    """
    out = []
    last = len(raw) - 1
    for i, byte in enumerate(raw):
        out.append("0123456789abcdef"[byte & 0x0F])
        if i == last and odd:
            break
        out.append("0123456789abcdef"[byte >> 4])
    return "".join(out)


def _decode_party_number(data: bytes, start: int) -> Tuple[Optional[str], Optional[int]]:
    """당사자 번호 파라미터(length-prefixed)에서 번호와 octet2(2번째 옥텟)를 푼다.

    Called/Calling Party Number 는 octet1(odd/even+nature of address)·octet2
    (numbering plan 등) 다음에 BCD 주소 신호가 온다. 절단·헤더 부족이면
    ``(None, None)``.

    Returns:
        ``(digits, octet2)``. ``octet2`` 는 호출 측에서 발신번호 제시 제한 등을
        해석하는 데 쓴다(Called 는 무시).
    """
    if start < 0 or start >= len(data):
        return None, None
    length = data[start]
    content_start = start + 1
    content_end = min(content_start + length, len(data))
    # octet1(odd/even+NAI) + octet2(NP 등) 최소 2옥텟 필요.
    if content_end - content_start < 2:
        return None, None
    octet1 = data[content_start]
    octet2 = data[content_start + 1]
    odd = bool(octet1 & 0x80)
    digits = _decode_address_signals(data[content_start + 2:content_end], odd)
    return (digits or None), octet2


def _ptr_target(data: bytes, pos: int) -> Optional[int]:
    """포인터 옥텟(자기 위치 기준 상대 오프셋)의 절대 대상 위치(0=없음·범위 밖이면 ``None``)."""
    if pos < 0 or pos >= len(data):
        return None
    val = data[pos]
    if val == 0:
        return None
    target = pos + val
    return target if target < len(data) else None


@dataclass(frozen=True)
class Isup:
    """파싱된 ISUP 메시지(CIC·타입 + IAM 당사자 번호·REL cause 까지).

    그 외 파라미터 본문은 풀지 않으며 :attr:`payload_offset` 으로만 가리킨다.

    Attributes:
        cic: Circuit Identification Code(12비트; 한 통화가 일어난 회선 상관 키).
        message_type: 메시지 타입 코드.
        called_number: 피호출(착신) 번호 — IAM 의 BCD 디코드(없으면 ``None``).
        calling_number: 발신 번호 — IAM 선택 파라미터의 BCD 디코드(없으면 ``None``).
        calling_presentation: 발신번호 제시 제한 표시(APRI; IAM 발신번호 있을 때만,
            없으면 ``None``).
        cause_value: 해제 사유(REL 의 cause value, Q.850; 없으면 ``None``).
        payload_offset: 파라미터부(메시지 타입 다음) 시작 절대 오프셋.
    """

    cic: int
    message_type: int
    called_number: Optional[str]
    calling_number: Optional[str]
    calling_presentation: Optional[int]
    cause_value: Optional[int]
    payload_offset: int

    @property
    def message_type_name(self) -> str:
        """메시지 타입의 사람이 읽는 이름(미상이면 ``"type-0x.."``)."""
        return _MESSAGE_TYPE_NAMES.get(self.message_type, f"type-0x{self.message_type:02x}")

    @property
    def is_setup(self) -> bool:
        """IAM(호 개시) 여부 — 당사자 번호가 실리는 지점."""
        return self.message_type == _IAM

    @property
    def is_address_complete(self) -> bool:
        """ACM(착신 도달/링) 여부."""
        return self.message_type == _ACM

    @property
    def is_answer(self) -> bool:
        """ANM(통화 연결/과금 시작) 여부."""
        return self.message_type == _ANM

    @property
    def is_release(self) -> bool:
        """REL(호 해제) 여부 — cause value 가 실리는 지점."""
        return self.message_type == _REL

    @property
    def is_release_complete(self) -> bool:
        """RLC(해제 완료) 여부."""
        return self.message_type == _RLC

    @property
    def cause_name(self) -> Optional[str]:
        """해제 사유의 이름(없으면 ``None``, 미상이면 ``"cause-<n>"``)."""
        if self.cause_value is None:
            return None
        return _CAUSE_NAMES.get(self.cause_value, f"cause-{self.cause_value}")

    @property
    def calling_presentation_name(self) -> Optional[str]:
        """발신번호 제시 제한 표시의 이름(없으면 ``None``)."""
        if self.calling_presentation is None:
            return None
        return _APRI_NAMES.get(self.calling_presentation, f"apri-{self.calling_presentation}")

    @property
    def is_calling_number_restricted(self) -> bool:
        """발신번호 제시가 억제됐는지(caller ID 위조·익명 통화 정황) 여부."""
        return self.calling_presentation == 1


def _parse_iam(data: bytes, base: int) -> Tuple[Optional[str], Optional[str], Optional[int]]:
    """IAM 의 Called/Calling Party Number 와 발신번호 APRI 를 푼다.

    mandatory variable part 의 두 포인터(Called Party Number, optional part 시작)를
    따라가 번호를 디코드하고, optional part 를 훑어 Calling Party Number(0x0A)를
    찾는다. 포인터/파라미터가 절단되면 풀 수 있는 만큼만.

    Returns:
        ``(called_number, calling_number, calling_presentation)``.
    """
    mv_start = base + 3 + _IAM_FIXED_LEN  # CIC(2)+type(1)+fixed(5).
    ptr_called_pos = mv_start
    ptr_optional_pos = mv_start + 1

    called_number = None
    called_target = _ptr_target(data, ptr_called_pos)
    if called_target is not None:
        called_number, _ = _decode_party_number(data, called_target)

    calling_number = None
    calling_presentation = None
    opt_target = _ptr_target(data, ptr_optional_pos)
    if opt_target is not None:
        pos = opt_target
        while pos < len(data):
            code = data[pos]
            if code == _PARAM_END_OF_OPTIONAL:
                break
            if pos + 1 >= len(data):
                break
            plen = data[pos + 1]
            if code == _PARAM_CALLING_PARTY_NUMBER:
                calling_number, octet2 = _decode_party_number(data, pos + 1)
                if octet2 is not None:
                    # Q.763 §3.10 octet2 bits 4-3 = address presentation restricted.
                    calling_presentation = (octet2 >> 2) & 0x03
                break
            nxt = pos + 2 + plen
            if nxt <= pos:
                break
            pos = nxt

    return called_number, calling_number, calling_presentation


def _parse_rel_cause(data: bytes, base: int) -> Optional[int]:
    """REL 의 mandatory variable part(Cause Indicators)에서 cause value 를 푼다.

    Cause 파라미터: length + octet1(coding standard/location) + octet2(cause
    value, 하위 7비트). 절단이면 ``None``.
    """
    ptr_cause_pos = base + 3
    target = _ptr_target(data, ptr_cause_pos)
    if target is None:
        return None
    length = data[target]
    content_start = target + 1
    content_end = min(content_start + length, len(data))
    # octet1(location) + octet2(cause value) 최소 2옥텟.
    if content_end - content_start < 2:
        return None
    return data[content_start + 1] & 0x7F


def parse_isup(data: bytes, offset: int = 0) -> Optional[Isup]:
    """원시 바이트에서 ISUP 메시지를 파싱한다.

    Args:
        data: ISUP 메시지 바이트. 보통 :mod:`forensiclab.m3ua` Protocol Data
            파라미터(0x0210) 안 MTP3 라우팅 레이블 다음부터다.
        offset: 메시지가 시작하는 위치(기본 0).

    Returns:
        :class:`Isup`. CIC·메시지 타입을 읽을 수 없거나(3옥텟 미만) 타입이 Q.763
        정의에 없으면 ``None``(오탐 가드). IAM 은 당사자 번호를, REL 은 cause 를
        깊게 풀고, 그 외 메시지는 CIC·타입만 식별한다. 포인터/파라미터가 절단되면
        풀 수 있는 만큼만 채운다.
    """
    if offset < 0 or offset + 3 > len(data):
        return None
    message_type = data[offset + 2]
    if message_type not in _MESSAGE_TYPE_NAMES:
        return None

    cic = struct.unpack_from("<H", data, offset)[0] & 0x0FFF
    payload_offset = offset + 3

    called_number = None
    calling_number = None
    calling_presentation = None
    cause_value = None

    if message_type == _IAM:
        called_number, calling_number, calling_presentation = _parse_iam(data, offset)
    elif message_type == _REL:
        cause_value = _parse_rel_cause(data, offset)

    return Isup(
        cic=cic,
        message_type=message_type,
        called_number=called_number,
        calling_number=calling_number,
        calling_presentation=calling_presentation,
        cause_value=cause_value,
        payload_offset=payload_offset,
    )
