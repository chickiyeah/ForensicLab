"""MAP — Mobile Application Part 가입자 신원 추출 코어 (3GPP TS 29.002; SS7 응용).

:mod:`forensiclab.tcap` 가 Invoke 컴포넌트의 ``operationCode`` 로 "무엇을 하려는지"
(``45 sendRoutingInfoForSM``·``71 anyTimeInterrogation``·``56
sendAuthenticationInfo`` …)를 드러냈을 때, **그 연산의 인자(argument)에 실리는
표적 가입자 신원**(IMSI·MSISDN)이 바로 이 모듈이 푸는 대상이다. TCAP 가 "무엇을"
이라면 MAP 인자는 **"누구를"** 이며, 둘을 짝지어야 SS7 공격의 표적이 와이어에서
완성된다(:mod:`forensiclab.tcap` 의 "표적 번호와 짝지으면 누구를 무엇으로가
완성된다"가 이 지점).

MAP 은 :mod:`forensiclab.sccp`·:mod:`forensiclab.tcap` 처럼 고정 헤더가 없고
연산별로 깊게 중첩된 ASN.1 이라, 이 모듈은 **전체 MAP 디코드를 시도하지 않는다**.
대신 포렌식상 가장 중요한 한 가지 — **가입자 신원 식별자(전화번호/IMSI)** — 만
얕게·보수적으로 뽑는다. 식별자는 SS7 에서 두 가지 *부호화 형태*로만 나타난다:

- **AddressString(전화번호꼴)**: 선두 1옥텟(ext|nature of address|numbering plan)
  다음에 TBCD 숫자. MSISDN·Service Centre 주소 등(E.164). ``form="address"``.
- **bare TBCD(맨 숫자열)**: 선두 옥텟 없이 통째로 TBCD 숫자. IMSI·IMEI 등
  (E.212). ``form="digits"``.

두 형태는 스키마 없이는 완전히 구분되지 않으므로(둘 다 OCTET STRING 베이스),
이 모듈은 **부호화 형태로만** 분류한다(스키마 추측 안 함): 선두 옥텟에 ext 비트
(0x80)가 서고 numbering plan 이 알려진 값(E.164/E.212 등)이면 ``address``, 아니면
``digits``. 이는 결정적·검증 가능하고 과대해석을 피한다(한계는 :func:`parse_map`
참고). 실제 캡처의 압도적 다수인 ``0x91``(international·ISDN/E.164)은 정확히
``address`` 로 분류된다.

설계 원칙(:mod:`forensiclab.tcap`·:mod:`forensiclab.sccp` 와 동일):
- 부작용 없음·stdlib 전용·읽기 전용(입력 무변형).
- BER/ASN.1 을 **얕게만** 순회: 신원 후보(primitive OCTET STRING·context 태그)만
  훑고 그 외 인자 본문은 풀지 않는다. 구성형(constructed) 태그는 제한 깊이까지만
  내려가 ``subscriberIdentity [0] CHOICE{imsi[0],msisdn[1]}`` 같은 한 겹 포장을
  통과한다.
- 견고: 빈 입력·첫 TLV 파싱 불가면 ``None``(오탐 가드). 후보가 유효 TBCD 가
  아니거나 길이가 비현실적이면 신원으로 채택하지 않는다. 절단되면 가용분까지만.

연산 이름·공격 분류는 :mod:`forensiclab.tcap` 의 표를 재사용해 드리프트를 막는다.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional, Tuple

from forensiclab.tcap import SS7_ATTACK_OPERATIONS, _MAP_OPERATION_NAMES

__all__ = [
    "MapArgument",
    "MapIdentity",
    "decode_tbcd",
    "decode_address_string",
    "parse_map",
]

# TBCD-String nibble → 문자(3GPP TS 29.002). 0xF 는 filler(보통 후행).
_TBCD = "0123456789*#abc"

# Nature of Address Indicator(3GPP TS 23.040/29.002) → 이름.
_NATURE_NAMES = {
    0: "unknown",
    1: "international",
    2: "national",
    3: "network-specific",
    4: "subscriber",
    5: "alphanumeric",
    6: "abbreviated",
}

# Numbering Plan Indicator → 이름.
_PLAN_NAMES = {
    0: "unknown",
    1: "ISDN-telephony",   # E.164 — MSISDN·Service Centre 주소.
    3: "data-X.121",
    4: "telex",
    6: "land-mobile-E.212",  # IMSI 계열.
    8: "national",
    9: "private",
}

# AddressString(전화번호꼴)로 분류할 numbering plan(맨 IMSI 와의 오분류를 줄이려
# 'unknown(0)' 은 제외한다 — 실제 MSISDN/SC 주소는 거의 ISDN(1)).
_ADDRESS_PLANS = frozenset({1, 3, 4, 6, 8, 9})

# 추출 신원의 현실적 자릿수 범위(IMSI 15·E.164 최대 15; 짧은 단축번호도 허용).
_MIN_DIGITS = 4
_MAX_DIGITS = 16

# 구성형 포장을 통과할 최대 재귀 깊이(subscriberIdentity 한 겹 정도).
_MAX_DEPTH = 4


def decode_tbcd(raw: bytes) -> str:
    """TBCD-String(옥텟당 2자리·하위 nibble 먼저)을 문자열로 디코드한다.

    각 옥텟의 하위 nibble 이 먼저, 상위 nibble 이 다음 자리다. ``0xF``(filler)
    nibble 은 건너뛴다(보통 홀수 자릿수의 후행 패딩). 0~9 외 nibble 은
    ``* # a b c`` 로 표기한다(TS 29.002 매핑).
    """
    out: List[str] = []
    for byte in raw:
        for nib in (byte & 0x0F, byte >> 4):
            if nib == 0x0F:
                continue
            out.append(_TBCD[nib])
    return "".join(out)


def decode_address_string(raw: bytes) -> Optional[Tuple[str, int, int]]:
    """AddressString(선두 옥텟 + TBCD 숫자)을 ``(digits, nature, plan)`` 으로 푼다.

    선두 옥텟 = ext(bit8) | nature of address(bit7-5) | numbering plan(bit4-1).
    이어지는 옥텟이 TBCD 숫자다. 1옥텟 이하·숫자 없음이면 ``None``.
    """
    if len(raw) < 2:
        return None
    octet1 = raw[0]
    nature = (octet1 >> 4) & 0x07
    plan = octet1 & 0x0F
    digits = decode_tbcd(raw[1:])
    if not digits:
        return None
    return digits, nature, plan


def _is_valid_digits(text: str) -> bool:
    """추출 문자열이 현실적 신원(자릿수 범위·TBCD 문자만)인지 검사한다."""
    return _MIN_DIGITS <= len(text) <= _MAX_DIGITS


@dataclass(frozen=True)
class MapIdentity:
    """MAP 인자에서 뽑은 가입자 신원 식별자 하나.

    Attributes:
        digits: 디코드된 식별자 숫자열(MSISDN·IMSI 등).
        form: 부호화 형태 — ``"address"``(선두 plan 옥텟 있는 전화번호꼴) 또는
            ``"digits"``(맨 TBCD 숫자열, IMSI 계열).
        nature_of_address: AddressString 의 nature(``form="address"`` 일 때만; 그
            외 ``None``).
        numbering_plan: AddressString 의 numbering plan(``form="address"`` 일 때만;
            그 외 ``None``).
        offset: 이 신원 값의 내용이 시작하는 절대 오프셋.
    """

    digits: str
    form: str
    nature_of_address: Optional[int]
    numbering_plan: Optional[int]
    offset: int

    @property
    def is_address(self) -> bool:
        """전화번호꼴(AddressString·MSISDN/SC) 부호화 여부."""
        return self.form == "address"

    @property
    def nature_name(self) -> Optional[str]:
        """nature of address 의 이름(``form != "address"`` 면 ``None``)."""
        if self.nature_of_address is None:
            return None
        return _NATURE_NAMES.get(self.nature_of_address, f"nature-{self.nature_of_address}")

    @property
    def numbering_plan_name(self) -> Optional[str]:
        """numbering plan 의 이름(``form != "address"`` 면 ``None``)."""
        if self.numbering_plan is None:
            return None
        return _PLAN_NAMES.get(self.numbering_plan, f"plan-{self.numbering_plan}")


def _read_tlv(data: bytes, pos: int, end: int) -> Optional[Tuple[int, int, int, int]]:
    """``pos`` 의 BER TLV 하나를 읽는다 → ``(tag, cs, ce, next)`` 또는 ``None``.

    :mod:`forensiclab.tcap` 의 동명 헬퍼와 같은 규칙(다중바이트 태그·장형 길이
    지원, ``ce`` 는 버퍼 끝으로 클램프, ``next`` 는 선언 길이 기준).
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


def _classify(data: bytes, cs: int, ce: int) -> Optional[MapIdentity]:
    """primitive 값(``cs``..``ce``)을 신원으로 분류·디코드한다(아니면 ``None``).

    부호화 형태로만 가른다: 선두 옥텟에 ext 비트가 서고 numbering plan 이
    :data:`_ADDRESS_PLANS` 면 AddressString(``address``), 아니면 맨 TBCD
    (``digits``). 디코드 결과가 현실적 자릿수가 아니면 채택하지 않는다.
    """
    raw = data[cs:ce]
    if len(raw) < 1:
        return None
    octet1 = raw[0]
    plan = octet1 & 0x0F
    if (octet1 & 0x80) and plan in _ADDRESS_PLANS and len(raw) >= 2:
        decoded = decode_address_string(raw)
        if decoded is not None:
            digits, nature, plan = decoded
            if _is_valid_digits(digits):
                return MapIdentity(digits, "address", nature, plan, cs)
        return None
    digits = decode_tbcd(raw)
    if _is_valid_digits(digits):
        return MapIdentity(digits, "digits", None, None, cs)
    return None


def _scan(data: bytes, start: int, end: int, depth: int, out: List[MapIdentity]) -> None:
    """``start``..``end`` 의 TLV 들을 훑어 신원 후보를 ``out`` 에 모은다.

    primitive(태그 bit6=0)는 :func:`_classify` 로 신원 시도, 구성형(bit6=1·SEQUENCE
    ·context constructed)은 ``_MAX_DEPTH`` 까지 재귀해 한 겹 포장을 통과한다.
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
        else:           # primitive → 신원 시도.
            ident = _classify(data, cs, ce)
            if ident is not None:
                out.append(ident)
        if nxt <= cur:
            break
        cur = nxt


@dataclass(frozen=True)
class MapArgument:
    """파싱된 MAP 연산 인자(얕게 뽑은 가입자 신원).

    Attributes:
        operation_code: 짝지은 TCAP operationCode(주어졌으면; 없으면 ``None``).
        identities: 인자에서 뽑은 신원 목록(없으면 빈 리스트).
        payload_offset: 인자 내용이 시작하는 절대 오프셋.
    """

    operation_code: Optional[int]
    identities: List[MapIdentity] = field(default_factory=list)
    payload_offset: int = 0

    @property
    def operation_name(self) -> Optional[str]:
        """MAP operationCode 이름(없으면 ``None``, 미상이면 ``"op-<n>"``)."""
        if self.operation_code is None:
            return None
        return _MAP_OPERATION_NAMES.get(self.operation_code, f"op-{self.operation_code}")

    @property
    def is_attack_operation(self) -> bool:
        """위치추적·통화/SMS 가로채기·인증 탈취 대표 MAP 연산 여부(TCAP 표 재사용)."""
        return self.operation_code in SS7_ATTACK_OPERATIONS

    @property
    def has_identity(self) -> bool:
        """가입자 신원을 하나라도 뽑았는지."""
        return bool(self.identities)

    @property
    def target_digits(self) -> Optional[str]:
        """표적 신원의 대표 숫자열 — 첫 신원(없으면 ``None``).

        SS7 공격에서 인자 선두에 표적 식별자(MSISDN/IMSI)가 오는 게 일반적이라
        첫 신원을 표적으로 본다.
        """
        return self.identities[0].digits if self.identities else None

    @property
    def all_digits(self) -> List[str]:
        """뽑은 모든 신원의 숫자열 목록."""
        return [i.digits for i in self.identities]


def parse_map(
    data: bytes,
    operation_code: Optional[int] = None,
    offset: int = 0,
    end: Optional[int] = None,
) -> Optional[MapArgument]:
    """MAP 연산 인자에서 가입자 신원(IMSI/MSISDN)을 얕게 추출한다.

    Args:
        data: MAP 인자 바이트. 보통 :mod:`forensiclab.tcap` Invoke 컴포넌트의
            operationCode 다음에 오는 파라미터(인자)다.
        operation_code: 짝지을 TCAP operationCode(있으면 ``operation_name``·
            ``is_attack_operation`` 채움). 없어도 신원 추출은 동작한다.
        offset: 인자가 시작하는 위치(기본 0).
        end: 인자 끝(기본 ``len(data)``).

    Returns:
        :class:`MapArgument`. 첫 TLV 를 읽을 수 없으면 ``None``(오탐 가드).
        구조를 :func:`_scan` 으로 훑어 부호화 형태가 AddressString(전화번호꼴)
        이거나 맨 TBCD(IMSI 계열)인 primitive 값을 신원으로 채운다.

    한계(과대해석 회피): 신원 라벨(MSISDN vs IMSI)을 스키마로 단정하지 않고
    *부호화 형태*(``form``)로만 구분한다. 선두 옥텟 ext 비트가 안 선 IMSI 는
    ``digits``, ``0x91`` 류는 ``address`` 로 분류된다. IMSI 의 두 번째 자리가
    8/9 라 선두 옥텟이 우연히 ext 비트를 갖는 드문 경우 ``address`` 로 오분류될
    수 있으나(plan nibble 검사로 대부분 걸러짐) 숫자열 자체는 대체로 복원된다.
    """
    if end is None:
        end = len(data)
    end = min(end, len(data))
    if offset < 0 or offset >= end:
        return None
    top = _read_tlv(data, offset, end)
    if top is None:
        return None

    identities: List[MapIdentity] = []
    tag, cs, ce, _ = top
    if tag & 0x20:
        # SEQUENCE 등 구성형 인자 → 내부를 훑는다.
        _scan(data, cs, ce, 0, identities)
    else:
        # 인자 자체가 단일 신원(예: sendAuthenticationInfo v2 의 IMSI).
        ident = _classify(data, cs, ce)
        if ident is not None:
            identities.append(ident)

    return MapArgument(
        operation_code=operation_code,
        identities=identities,
        payload_offset=cs,
    )
