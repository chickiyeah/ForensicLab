"""CAP — CAMEL Application Part 호 제어·과금 연산/번호 추출 코어 (3GPP TS 29.078; SS7 응용).

:mod:`forensiclab.tcap` 가 Invoke 컴포넌트의 ``operationCode`` 로 "무엇을 하려는지"를
드러낼 때, :mod:`forensiclab.map`(MAP, 이동성·SMS·인증) 과 **나란히 TCAP 위에
실리는 다른 응용부**가 바로 CAP 이다. CAMEL(Customised Applications for Mobile
networks Enhanced Logic)은 지능망(IN) 서비스 — 선불(prepaid) 과금·번호 변환·
부가 통화 제어 — 를 위해 교환기(gsmSSF)와 서비스 제어부(gsmSCF) 사이에서 호 하나
하나를 실시간으로 조종한다. MAP 이 **"누구의 위치/SMS/키"**(가입자 평면)였다면
CAP 은 **"이 통화를 어디로·과금을 어떻게"**(호 제어/과금 평면)다.

포렌식상 CAP 은 **CAMEL 사기**의 무대다:

- ``connect``(20)·``initiateCallAttempt``(32): gsmSCF 가 통화를 **임의 번호로
  되돌리거나 새 호를 발신** — 통화 가로채기·프리미엄/리비뉴셰어 사기.
- ``furnishChargingInformation``(34)·``applyCharging``(35)·
  ``sendChargingInformation``(46): **과금 정보 조작** — 무료 통화·과금 우회.
- ``releaseCall``(22): 강제 절단. ``establishTemporaryConnection``(17)·
  ``connectToResource``(19): 자원/안내 삽입.

CAP 의 ``initialDP``(0, Initial Detection Point)는 호 설정 시점에 교환기가 SCF 로
보내는 트리거로, **착신/발신 번호**(calledPartyNumber·callingPartyNumber)와 위치·
IMSI 가 인자에 실린다. ``connect``(20) 인자에는 **재라우팅 대상 번호**
(destinationRoutingAddress)가 실린다 — 둘 다 이 모듈이 얕게 추출하는 표적이다.

CAP 의 번호는 :mod:`forensiclab.map` 의 AddressString(E.164 선두 옥텟+TBCD)과 달리
**ISUP(Q.763) 형식**으로 부호화된다(:mod:`forensiclab.isup` 의 당사자 번호와 동일):
octet1 = odd/even(bit8) + nature of address(bits7-1), octet2 = numbering plan
(bits7-5) 등, 이어서 BCD 주소 신호. 그래서 이 모듈은 MAP 의 TBCD 가 아니라
ISUP 형 BCD 디코드를 쓴다.

설계 원칙(:mod:`forensiclab.map`·:mod:`forensiclab.tcap` 와 동일):
- 부작용 없음·stdlib 전용·읽기 전용(입력 무변형).
- BER/ASN.1 을 **얕게만** 순회: 번호 후보(primitive OCTET STRING)만 ISUP 형으로
  분류·디코드하고 그 외 인자 본문은 풀지 않는다. 구성형 태그는 제한 깊이까지만
  내려가 ``destinationRoutingAddress [0] SEQUENCE OF CalledPartyNumber`` 같은
  한 겹 포장을 통과한다.
- 보수적: 선두 옥텟의 nature/plan 이 알려진 ISUP 값이고 자릿수가 현실적일 때만
  번호로 채택한다(스키마 추측 안 함·과대해석 회피). 빈 입력·첫 TLV 파싱 불가면
  ``None``(오탐 가드). 절단되면 가용분까지.

연산 코드는 MAP 과 *겹치는 local 값을 다른 뜻으로 쓰므로*(예: 22 가 MAP 에선
sendRoutingInfo, CAP 에선 releaseCall) :mod:`forensiclab.tcap` 의 MAP 표를
재사용하지 않고 CAP 전용 표(:data:`CAP_OPERATION_NAMES`)를 둔다.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional, Tuple

__all__ = [
    "CAP_OPERATION_NAMES",
    "CAP_FRAUD_OPERATIONS",
    "CapNumber",
    "CapArgument",
    "decode_isup_bcd",
    "decode_cap_number",
    "parse_cap",
]

# CAP 연산 코드(local; 3GPP TS 29.078, gsmSSF↔gsmSCF) → 이름. MAP 과 값이 겹쳐도
# 뜻이 다르므로 별도 표(드리프트 차단).
CAP_OPERATION_NAMES = {
    0: "initialDP",                      # 호 설정 트리거(착신/발신 번호·위치·IMSI).
    16: "assistRequestInstructions",
    17: "establishTemporaryConnection",  # 자원으로의 임시 연결.
    18: "disconnectForwardConnection",
    19: "connectToResource",             # 안내/자원 삽입.
    20: "connect",                       # 통화 재라우팅(대상 번호 = 사기 표적).
    22: "releaseCall",                   # 강제 절단.
    23: "requestReportBCSMEvent",
    24: "eventReportBCSM",
    27: "collectInformation",
    31: "continue",
    32: "initiateCallAttempt",           # 망 발신 신규 호(리비뉴셰어 사기).
    33: "resetTimer",
    34: "furnishChargingInformation",    # 과금 정보 주입(과금 조작).
    35: "applyCharging",                 # 과금 적용/제어.
    36: "applyChargingReport",
    41: "callGap",
    44: "callInformationReport",
    45: "callInformationRequest",
    46: "sendChargingInformation",       # 과금 정보 전달(과금 조작).
    47: "playAnnouncement",
    48: "promptAndCollectUserInformation",
    49: "specializedResourceReport",
    53: "cancel",
    55: "activityTest",
}

# 통화 재라우팅·신규 호 발신·과금 조작·강제 절단 등 CAMEL 사기에 동원되는 대표 연산.
CAP_FRAUD_OPERATIONS = frozenset({17, 19, 20, 22, 32, 34, 35, 36, 46})

# Nature of Address Indicator(ISUP Q.763) → 이름.
_NAI_NAMES = {
    1: "subscriber",
    2: "unknown",
    3: "national",
    4: "international",
    5: "network-specific",
}

# Numbering Plan Indicator(ISUP Q.763) → 이름.
_NP_NAMES = {
    1: "ISDN-E.164",
    3: "data-X.121",
    4: "telex",
}

# 번호로 채택할 ISUP nature/plan(스키마 없이 보수적으로 — 알려진 값만).
_KNOWN_NAI = frozenset(_NAI_NAMES)
_KNOWN_NP = frozenset(_NP_NAMES)

# 현실적 자릿수 범위(E.164 최대 15; 짧은 단축/서비스 코드도 허용).
_MIN_DIGITS = 3
_MAX_DIGITS = 15

# 구성형 포장을 통과할 최대 재귀 깊이(destinationRoutingAddress 등 한 겹).
_MAX_DEPTH = 4

_BCD = "0123456789abcdef"


def decode_isup_bcd(raw: bytes, odd: bool) -> str:
    """ISUP 주소 신호(BCD, 옥텟당 2자리·하위 nibble 먼저)를 문자열로 디코드한다.

    ``odd`` 가 참이면 마지막 옥텟의 상위 nibble 은 filler 이므로 버린다(odd/even
    표시). 0~9 는 숫자, 그 외 nibble 은 16진수 문자로 표기한다(:mod:`forensiclab.isup`
    과 동일 규칙).
    """
    out: List[str] = []
    last = len(raw) - 1
    for i, byte in enumerate(raw):
        out.append(_BCD[byte & 0x0F])
        if i == last and odd:
            break
        out.append(_BCD[byte >> 4])
    return "".join(out)


def decode_cap_number(raw: bytes) -> Optional[Tuple[str, int, int]]:
    """CAP/ISUP 형 당사자 번호(OCTET STRING 내용)를 ``(digits, nai, plan)`` 으로 푼다.

    내용 = octet1(odd/even bit8 + nature of address bits7-1) + octet2(numbering
    plan bits7-5 등) + BCD 주소 신호. 헤더 2옥텟 + 숫자 1옥텟 이상이 필요하다.
    헤더 부족·숫자 없음이면 ``None``.
    """
    if len(raw) < 3:
        return None
    octet1 = raw[0]
    odd = bool(octet1 & 0x80)
    nai = octet1 & 0x7F
    plan = (raw[1] >> 4) & 0x07
    digits = decode_isup_bcd(raw[2:], odd)
    if not digits:
        return None
    return digits, nai, plan


def _is_valid_digits(text: str) -> bool:
    """추출 번호가 현실적 자릿수 범위인지 검사한다."""
    return _MIN_DIGITS <= len(text) <= _MAX_DIGITS


@dataclass(frozen=True)
class CapNumber:
    """CAP 인자에서 뽑은 ISUP 형 당사자 번호 하나.

    Attributes:
        digits: 디코드된 번호 숫자열(착신/발신/재라우팅 대상 등).
        nature_of_address: ISUP nature of address indicator.
        numbering_plan: ISUP numbering plan indicator.
        offset: 이 번호 값의 내용이 시작하는 절대 오프셋.
    """

    digits: str
    nature_of_address: int
    numbering_plan: int
    offset: int

    @property
    def nature_name(self) -> str:
        """nature of address 의 이름(미상이면 ``"nai-<n>"``)."""
        return _NAI_NAMES.get(self.nature_of_address, f"nai-{self.nature_of_address}")

    @property
    def numbering_plan_name(self) -> str:
        """numbering plan 의 이름(미상이면 ``"plan-<n>"``)."""
        return _NP_NAMES.get(self.numbering_plan, f"plan-{self.numbering_plan}")

    @property
    def is_international(self) -> bool:
        """국제 번호 형식 여부(nature of address == 4)."""
        return self.nature_of_address == 4


def _read_tlv(data: bytes, pos: int, end: int) -> Optional[Tuple[int, int, int, int]]:
    """``pos`` 의 BER TLV 하나를 읽는다 → ``(tag, cs, ce, next)`` 또는 ``None``.

    :mod:`forensiclab.map`·:mod:`forensiclab.tcap` 의 동명 헬퍼와 같은 규칙
    (다중바이트 태그·장형 길이 지원, ``ce`` 는 버퍼 끝으로 클램프, ``next`` 는
    선언 길이 기준).
    """
    if pos < 0 or pos >= end:
        return None
    tag = data[pos]
    cursor = pos + 1
    if (tag & 0x1F) == 0x1F:
        while cursor < end and (data[cursor] & 0x80):
            cursor += 1
        if cursor >= end:
            return None
        cursor += 1
    if cursor >= end:
        return None
    length_octet = data[cursor]
    cursor += 1
    if length_octet < 0x80:
        length = length_octet
    else:
        num = length_octet & 0x7F
        if num == 0 or cursor + num > end:
            return None
        length = 0
        for i in range(num):
            length = (length << 8) | data[cursor + i]
        cursor += num
    content_start = cursor
    content_end = min(content_start + length, end)
    return tag, content_start, content_end, content_start + length


def _classify(data: bytes, cs: int, ce: int) -> Optional[CapNumber]:
    """primitive 값(``cs``..``ce``)을 ISUP 형 번호로 분류·디코드한다(아니면 ``None``).

    보수적: nature of address 와 numbering plan 이 둘 다 알려진 ISUP 값이고
    디코드 결과가 현실적 자릿수일 때만 채택한다.
    """
    decoded = decode_cap_number(data[cs:ce])
    if decoded is None:
        return None
    digits, nai, plan = decoded
    if nai not in _KNOWN_NAI or plan not in _KNOWN_NP:
        return None
    if not _is_valid_digits(digits):
        return None
    return CapNumber(digits, nai, plan, cs)


def _scan(data: bytes, start: int, end: int, depth: int, out: List[CapNumber]) -> None:
    """``start``..``end`` 의 TLV 들을 훑어 번호 후보를 ``out`` 에 모은다.

    primitive(태그 bit6=0)는 :func:`_classify` 로 번호 시도, 구성형(bit6=1)은
    ``_MAX_DEPTH`` 까지 재귀해 한 겹 포장을 통과한다.
    """
    if depth > _MAX_DEPTH:
        return
    cur = start
    while cur < end:
        tlv = _read_tlv(data, cur, end)
        if tlv is None:
            break
        tag, cs, ce, nxt = tlv
        if tag & 0x20:  # 구성형 → 한 겹 더 내려간다.
            _scan(data, cs, ce, depth + 1, out)
        else:           # primitive → 번호 시도.
            num = _classify(data, cs, ce)
            if num is not None:
                out.append(num)
        if nxt <= cur:
            break
        cur = nxt


@dataclass(frozen=True)
class CapArgument:
    """파싱된 CAP 연산 인자(얕게 뽑은 당사자 번호).

    Attributes:
        operation_code: 짝지은 TCAP operationCode(주어졌으면; 없으면 ``None``).
        numbers: 인자에서 뽑은 ISUP 형 번호 목록(없으면 빈 리스트).
        payload_offset: 인자 내용이 시작하는 절대 오프셋.
    """

    operation_code: Optional[int]
    numbers: List[CapNumber] = field(default_factory=list)
    payload_offset: int = 0

    @property
    def operation_name(self) -> Optional[str]:
        """CAP operationCode 이름(없으면 ``None``, 미상이면 ``"op-<n>"``)."""
        if self.operation_code is None:
            return None
        return CAP_OPERATION_NAMES.get(self.operation_code, f"op-{self.operation_code}")

    @property
    def is_fraud_operation(self) -> bool:
        """통화 재라우팅·신규 호 발신·과금 조작 등 CAMEL 사기 대표 연산 여부."""
        return self.operation_code in CAP_FRAUD_OPERATIONS

    @property
    def has_number(self) -> bool:
        """당사자 번호를 하나라도 뽑았는지."""
        return bool(self.numbers)

    @property
    def target_number(self) -> Optional[str]:
        """표적 번호의 대표 숫자열 — 첫 번호(없으면 ``None``).

        ``connect`` 의 재라우팅 대상·``initialDP`` 의 착신 번호처럼 인자 선두에
        표적 번호가 오는 게 일반적이라 첫 번호를 표적으로 본다.
        """
        return self.numbers[0].digits if self.numbers else None

    @property
    def all_digits(self) -> List[str]:
        """뽑은 모든 번호의 숫자열 목록."""
        return [n.digits for n in self.numbers]


def parse_cap(
    data: bytes,
    operation_code: Optional[int] = None,
    offset: int = 0,
    end: Optional[int] = None,
) -> Optional[CapArgument]:
    """CAP 연산 인자에서 ISUP 형 당사자 번호를 얕게 추출한다.

    Args:
        data: CAP 인자 바이트. 보통 :mod:`forensiclab.tcap` Invoke 컴포넌트의
            operationCode 다음에 오는 파라미터(인자)다.
        operation_code: 짝지을 TCAP operationCode(있으면 ``operation_name``·
            ``is_fraud_operation`` 채움). 없어도 번호 추출은 동작한다.
        offset: 인자가 시작하는 위치(기본 0).
        end: 인자 끝(기본 ``len(data)``).

    Returns:
        :class:`CapArgument`. 첫 TLV 를 읽을 수 없으면 ``None``(오탐 가드).
        구조를 :func:`_scan` 으로 훑어 ISUP 형(octet1 nature + octet2 plan + BCD)
        으로 해석되는 primitive 값을 번호로 채운다.

    한계(과대해석 회피): CAP 의 ISDN-AddressString 형 필드(mscAddress·SMSC 주소
    등 :mod:`forensiclab.map` 의 AddressString 부호화)는 이 모듈이 분류하지 않는다
    (ISUP 형 당사자 번호만 대상). 번호 라벨(착신 vs 발신 vs 재라우팅)은 스키마로
    단정하지 않고 등장 순서로만 추정한다(``target_number`` = 첫 번호).
    """
    if end is None:
        end = len(data)
    end = min(end, len(data))
    if offset < 0 or offset >= end:
        return None
    top = _read_tlv(data, offset, end)
    if top is None:
        return None

    numbers: List[CapNumber] = []
    tag, cs, ce, _ = top
    if tag & 0x20:
        # SEQUENCE 등 구성형 인자 → 내부를 훑는다.
        _scan(data, cs, ce, 0, numbers)
    else:
        # 인자 자체가 단일 번호.
        num = _classify(data, cs, ce)
        if num is not None:
            numbers.append(num)

    return CapArgument(
        operation_code=operation_code,
        numbers=numbers,
        payload_offset=cs,
    )
