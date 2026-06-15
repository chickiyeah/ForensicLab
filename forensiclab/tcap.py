"""TCAP — Transaction Capabilities Application Part 파싱 코어 (ITU-T Q.773; SS7 응용부).

:mod:`forensiclab.sccp` 가 연결 없는 데이터 메시지(UDT/XUDT)의 ``data_offset``
으로 "사용자 데이터(TCAP)는 여기서 시작한다"고 가리켰을 때, 그 **TCAP 가 바로
이 모듈이 푸는 계층**이다. SCCP 가 신호점 안의 어떤 응용(SSN)·전화번호(GT)로
*주소를 지정*해 메시지를 날랐다면, TCAP 는 그 위에서 **대화(transaction)를 묶고
원격 연산(operation)을 호출**하는 RPC 격 계층이다 — 그 위에 MAP(Mobile
Application Part)이 실려 ``SendRoutingInfoForSM``(SMS 라우팅)·
``AnyTimeInterrogation``(위치 조회)·``SendAuthenticationInfo``(인증 벡터) 같은
**실제 SS7 공격 연산**이 호출된다.

따라서 TCAP 의 두 축은 SS7 공격을 와이어에서 직접 드러낸다:

- **연산 식별(operationCode)**: Invoke 컴포넌트의 operationCode 가 곧 무엇을
  하려는지다. MAP ``45 sendRoutingInfoForSM``=SMS 가로채기용 표적 라우팅 조회·
  ``71 anyTimeInterrogation``/``83 provideSubscriberLocation``=가입자 위치추적·
  ``56 sendAuthenticationInfo``=인증 벡터 탈취·``22 sendRoutingInfo``=통화
  가로채기. SCCP Called GT 의 표적 번호와 짝지으면 "누구를 무엇으로" 가 완성된다.
- **대화 상관(Transaction ID)**: Begin 의 originating TID 와 그에 답하는 End/
  Continue 의 destination TID 가 한 대화를 :mod:`forensiclab.flows`·
  :mod:`forensiclab.timeline` 너머로 묶는다(SCCP 주소·SCTP verification tag·
  ESP SPI 대응 상관 키). Abort 폭주는 거부·오류 정황.

설계 원칙(:mod:`forensiclab.sccp`·:mod:`forensiclab.m3ua` 와 동일):
- 부작용 없음·stdlib 전용·읽기 전용(입력 무변형).
- **BER/ASN.1 을 얕게만** 순회한다: 메시지 타입 태그·트랜잭션 ID·dialogue/
  component 포션의 경계만 풀고, MAP 인자(parameter) 본문은 풀지 않은 채
  ``payload_offset`` 으로만 가리킨다. 컴포넌트는 타입·invokeID·operationCode 만.
- 견고: 빈 입력·메시지 타입 태그가 Q.773 정의(0x61/0x62/0x64/0x65/0x67)에 없으면
  예외 대신 ``None``(오탐 가드). TLV 가 버퍼를 넘거나 절단되면 풀 수 있는 만큼만.

와이어 포맷(Q.773; BER, 모두 [APPLICATION] 클래스 구성형 태그)::

    message_type_tag(1) | length(BER) | <transaction portion>
      0x48 Originating TID | 0x49 Destination TID | 0x4A P-Abort Cause
      0x6B Dialogue Portion | 0x6C Component Portion
        0xA1 Invoke | 0xA2 ReturnResultLast | 0xA3 ReturnError
        0xA4 Reject | 0xA7 ReturnResultNotLast
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional, Tuple

__all__ = [
    "TCAP_MESSAGE_TYPES",
    "Tcap",
    "TcapComponent",
    "parse_tcap",
]

# 메시지 타입 태그(Q.773 §3; APPLICATION 클래스 구성형) → 이름.
_MESSAGE_TYPE_NAMES = {
    0x61: "Unidirectional",  # 응답 없는 단방향(대화 없음).
    0x62: "Begin",           # 대화 개시(originating TID 만).
    0x64: "End",             # 대화 종료(destination TID 만).
    0x65: "Continue",        # 대화 진행(양쪽 TID).
    0x67: "Abort",           # 대화 비정상 종료(destination TID + 사유).
}
TCAP_MESSAGE_TYPES = frozenset(_MESSAGE_TYPE_NAMES)

# 트랜잭션 포션 내부 태그(Q.773).
_TAG_OTID = 0x48      # Originating Transaction ID.
_TAG_DTID = 0x49      # Destination Transaction ID.
_TAG_PABORT = 0x4A    # P-Abort Cause(INTEGER).
_TAG_DIALOGUE = 0x6B  # Dialogue Portion(EXTERNAL).
_TAG_COMPONENT = 0x6C  # Component Portion(SEQUENCE).

# 컴포넌트 태그(Q.773 §3.2; CONTEXT 클래스 구성형) → 이름.
_COMPONENT_NAMES = {
    0xA1: "Invoke",
    0xA2: "ReturnResultLast",
    0xA3: "ReturnError",
    0xA4: "Reject",
    0xA7: "ReturnResultNotLast",
}

# P-Abort cause(Q.773 §3.1.6) → 이름.
_PABORT_NAMES = {
    0: "unrecognizedMessageType",
    1: "unrecognizedTransactionID",
    2: "badlyFormattedTransactionPortion",
    3: "incorrectTransactionPortion",
    4: "resourceLimitation",
}

# MAP 연산 코드(local; 3GPP TS 29.002) → 이름. 포렌식상 중요한 부분.
_MAP_OPERATION_NAMES = {
    2: "updateLocation",
    3: "cancelLocation",
    4: "provideRoamingNumber",
    7: "insertSubscriberData",
    8: "deleteSubscriberData",
    22: "sendRoutingInfo",            # 통화 라우팅 조회(가로채기 정찰).
    23: "updateGprsLocation",
    44: "mt-forwardSM",               # SMS 단말 전달.
    45: "sendRoutingInfoForSM",       # SRI-SM — SMS 가로채기용 표적 조회.
    46: "mo-forwardSM",               # SMS 발신 전달.
    50: "activateTraceMode",
    56: "sendAuthenticationInfo",     # 인증 벡터(키 자료) 조회.
    67: "anyTimeModification",        # 가입자 데이터 원격 변조.
    70: "provideSubscriberInfo",      # PSI — 가입자 상태·위치.
    71: "anyTimeInterrogation",       # ATI — 임의 시점 위치추적.
    83: "provideSubscriberLocation",  # PSL — 정밀 위치.
    85: "sendRoutingInfoForLCS",      # 위치 서비스 라우팅.
}

# 위치추적·통화/SMS 가로채기·인증 탈취에 동원되는 대표 MAP 연산(공격 의도 강조).
SS7_ATTACK_OPERATIONS = frozenset({22, 45, 56, 67, 70, 71, 83, 85})

_INTEGER_TAG = 0x02
_SEQUENCE_TAG = 0x30
_OID_TAG = 0x06


def _read_tlv(data: bytes, pos: int, end: int) -> Optional[Tuple[int, int, int, int]]:
    """``pos`` 위치의 BER TLV 하나를 읽는다.

    Returns:
        ``(tag, content_start, content_end, next_pos)`` 또는 파싱 불가 시 ``None``.
        ``content_end`` 는 버퍼 끝으로 클램프(절단 캡처 허용)되며, ``next_pos`` 는
        선언된 길이 기준 다음 TLV 위치다.
    """
    if pos < 0 or pos >= end:
        return None
    tag = data[pos]
    cursor = pos + 1
    # 다중 바이트 태그(하위 5비트가 모두 1): 후속 옥텟 소비.
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
            # 무한 길이(TCAP 미사용)·길이 옥텟 절단 → 파싱 불가.
            return None
        length = 0
        for i in range(num):
            length = (length << 8) | data[cursor + i]
        cursor += num
    content_start = cursor
    declared_end = content_start + length
    content_end = min(declared_end, end)
    return tag, content_start, content_end, declared_end


def _read_uint(data: bytes, start: int, end: int) -> Optional[int]:
    """BER content(big-endian) 를 부호 없는 정수로 읽는다(절단·빈 값이면 ``None``)."""
    if start >= end:
        return None
    value = 0
    for i in range(start, end):
        value = (value << 8) | data[i]
    return value


def _parse_component(data: bytes, tag: int, cs: int, ce: int) -> "TcapComponent":
    """컴포넌트 하나(Invoke/ReturnResult/…)의 invokeID·operationCode 를 얕게 푼다.

    operationCode 추출 규칙(Q.773):
    - Invoke: invokeID(INTEGER) 다음 operationCode(local 이면 INTEGER, global 이면
      OID). linkedID([0] CONTEXT)는 있으면 건너뛴다.
    - ReturnResult(Last/NotLast): invokeID 다음 SEQUENCE 안 첫 INTEGER 가
      operationCode.
    - ReturnError: invokeID 다음 INTEGER 는 errorCode 로 본다.
    """
    invoke_id: Optional[int] = None
    operation_code: Optional[int] = None
    error_code: Optional[int] = None
    is_global_op = False

    # 컴포넌트 내부 자식 TLV 를 차례로 훑는다.
    children: List[Tuple[int, int, int]] = []
    cur = cs
    while cur < ce:
        tlv = _read_tlv(data, cur, ce)
        if tlv is None:
            break
        ctag, ccs, cce, cnext = tlv
        children.append((ctag, ccs, cce))
        if cnext <= cur:
            break
        cur = cnext

    # 첫 INTEGER = invokeID.
    int_indices = [i for i, (t, _, _) in enumerate(children) if t == _INTEGER_TAG]
    if int_indices:
        t, ics, ice = children[int_indices[0]]
        invoke_id = _read_uint(data, ics, ice)

    if tag in (0xA1,):  # Invoke.
        # invokeID 이후의 두 번째 INTEGER(local opCode) 또는 첫 OID(global opCode).
        if len(int_indices) >= 2:
            _, ocs, oce = children[int_indices[1]]
            operation_code = _read_uint(data, ocs, oce)
        else:
            for ctag, ccs, cce in children:
                if ctag == _OID_TAG:
                    is_global_op = True
                    break
    elif tag in (0xA2, 0xA7):  # ReturnResultLast / NotLast.
        for ctag, ccs, cce in children:
            if ctag == _SEQUENCE_TAG:
                inner = _read_tlv(data, ccs, cce)
                if inner is not None and inner[0] == _INTEGER_TAG:
                    operation_code = _read_uint(data, inner[1], inner[2])
                elif inner is not None and inner[0] == _OID_TAG:
                    is_global_op = True
                break
    elif tag == 0xA3:  # ReturnError.
        if len(int_indices) >= 2:
            _, ecs, ece = children[int_indices[1]]
            error_code = _read_uint(data, ecs, ece)

    return TcapComponent(
        component_type=tag,
        invoke_id=invoke_id,
        operation_code=operation_code,
        error_code=error_code,
        is_global_operation=is_global_op,
    )


@dataclass(frozen=True)
class TcapComponent:
    """TCAP 컴포넌트 하나(원격 연산 호출·응답 단위).

    Attributes:
        component_type: 컴포넌트 태그(0xA1 Invoke 등).
        invoke_id: Invoke ID(연산 호출↔응답 정합 키; 없으면 ``None``).
        operation_code: local operationCode(Invoke·ReturnResult; 없으면 ``None``).
        error_code: local errorCode(ReturnError; 없으면 ``None``).
        is_global_operation: operationCode 가 OID(global) 형식이면 ``True``.
    """

    component_type: int
    invoke_id: Optional[int]
    operation_code: Optional[int]
    error_code: Optional[int]
    is_global_operation: bool

    @property
    def component_name(self) -> str:
        """컴포넌트 타입의 사람이 읽는 이름(미상이면 ``"comp-0x.."``)."""
        return _COMPONENT_NAMES.get(self.component_type, f"comp-0x{self.component_type:02x}")

    @property
    def is_invoke(self) -> bool:
        """Invoke(원격 연산 호출) 여부 — operationCode 가 공격 의도를 드러내는 지점."""
        return self.component_type == 0xA1

    @property
    def operation_name(self) -> Optional[str]:
        """MAP operationCode 의 이름(없으면 ``None``, 미상이면 ``"op-<n>"``)."""
        if self.operation_code is None:
            return None
        return _MAP_OPERATION_NAMES.get(self.operation_code, f"op-{self.operation_code}")

    @property
    def is_attack_operation(self) -> bool:
        """위치추적·통화/SMS 가로채기·인증 탈취에 쓰이는 대표 MAP 연산 여부."""
        return self.operation_code in SS7_ATTACK_OPERATIONS


@dataclass(frozen=True)
class Tcap:
    """파싱된 TCAP 메시지(트랜잭션 포션 + 얕게 푼 컴포넌트).

    MAP 인자 본문은 풀지 않으며 컴포넌트는 타입·invokeID·operationCode 까지만.

    Attributes:
        message_type: 메시지 타입 태그(0x62 Begin 등).
        originating_tid: Originating Transaction ID(정수; 없으면 ``None``).
        destination_tid: Destination Transaction ID(정수; 없으면 ``None``).
        p_abort_cause: P-Abort cause(Abort; 없으면 ``None``).
        has_dialogue_portion: Dialogue Portion(0x6B) 존재 여부.
        dialogue_offset: Dialogue Portion 내용 시작 절대 오프셋(없으면 ``None``).
        components: 컴포넌트 목록(없으면 빈 리스트).
        payload_offset: 메시지 내용(트랜잭션 포션) 시작 절대 오프셋.
    """

    message_type: int
    originating_tid: Optional[int]
    destination_tid: Optional[int]
    p_abort_cause: Optional[int]
    has_dialogue_portion: bool
    dialogue_offset: Optional[int]
    components: List[TcapComponent] = field(default_factory=list)
    payload_offset: int = 0

    @property
    def message_type_name(self) -> str:
        """메시지 타입의 사람이 읽는 이름(미상이면 ``"type-0x.."``)."""
        return _MESSAGE_TYPE_NAMES.get(self.message_type, f"type-0x{self.message_type:02x}")

    @property
    def is_begin(self) -> bool:
        """Begin(대화 개시) 여부."""
        return self.message_type == 0x62

    @property
    def is_end(self) -> bool:
        """End(대화 종료) 여부."""
        return self.message_type == 0x64

    @property
    def is_continue(self) -> bool:
        """Continue(대화 진행) 여부."""
        return self.message_type == 0x65

    @property
    def is_abort(self) -> bool:
        """Abort(비정상 종료) 여부 — 거부·자원 한계·오류 정황."""
        return self.message_type == 0x67

    @property
    def p_abort_name(self) -> Optional[str]:
        """P-Abort cause 의 이름(없으면 ``None``, 미상이면 ``"cause-<n>"``)."""
        if self.p_abort_cause is None:
            return None
        return _PABORT_NAMES.get(self.p_abort_cause, f"cause-{self.p_abort_cause}")

    @property
    def operation_codes(self) -> List[int]:
        """컴포넌트들의 operationCode 목록(없는 것 제외)."""
        return [c.operation_code for c in self.components if c.operation_code is not None]

    @property
    def operation_names(self) -> List[str]:
        """컴포넌트들의 연산 이름 목록(없는 것 제외)."""
        return [c.operation_name for c in self.components if c.operation_name is not None]

    @property
    def has_attack_operation(self) -> bool:
        """대표 SS7 공격 MAP 연산을 하나라도 호출하는지 여부."""
        return any(c.is_attack_operation for c in self.components)


def parse_tcap(data: bytes, offset: int = 0) -> Optional[Tcap]:
    """원시 바이트에서 TCAP 메시지를 파싱한다.

    Args:
        data: TCAP 메시지 바이트. 보통 :mod:`forensiclab.sccp` 의 ``data_offset``
            (UDT/XUDT 사용자 데이터 시작)부터다.
        offset: 메시지가 시작하는 위치(기본 0).

    Returns:
        :class:`Tcap`. 첫 태그가 Q.773 메시지 타입(0x61/0x62/0x64/0x65/0x67)이
        아니거나 길이를 읽을 수 없으면 ``None``(오탐 가드). 트랜잭션 ID·dialogue/
        component 경계를 풀고 컴포넌트는 타입·invokeID·operationCode 까지만 채운다.
        TLV 가 절단되면 풀 수 있는 만큼만 채운다.
    """
    if offset < 0 or offset >= len(data):
        return None
    top = _read_tlv(data, offset, len(data))
    if top is None:
        return None
    msg_tag, cs, ce, _ = top
    if msg_tag not in _MESSAGE_TYPE_NAMES:
        return None

    originating_tid: Optional[int] = None
    destination_tid: Optional[int] = None
    p_abort_cause: Optional[int] = None
    has_dialogue = False
    dialogue_offset: Optional[int] = None
    components: List[TcapComponent] = []

    cur = cs
    while cur < ce:
        tlv = _read_tlv(data, cur, ce)
        if tlv is None:
            break
        tag, tcs, tce, tnext = tlv
        if tag == _TAG_OTID:
            originating_tid = _read_uint(data, tcs, tce)
        elif tag == _TAG_DTID:
            destination_tid = _read_uint(data, tcs, tce)
        elif tag == _TAG_PABORT:
            p_abort_cause = _read_uint(data, tcs, tce)
        elif tag == _TAG_DIALOGUE:
            has_dialogue = True
            dialogue_offset = tcs
        elif tag == _TAG_COMPONENT:
            ccur = tcs
            while ccur < tce:
                ctlv = _read_tlv(data, ccur, tce)
                if ctlv is None:
                    break
                ctag, ccs, cce, cnext = ctlv
                components.append(_parse_component(data, ctag, ccs, cce))
                if cnext <= ccur:
                    break
                ccur = cnext
        if tnext <= cur:
            break
        cur = tnext

    return Tcap(
        message_type=msg_tag,
        originating_tid=originating_tid,
        destination_tid=destination_tid,
        p_abort_cause=p_abort_cause,
        has_dialogue_portion=has_dialogue,
        dialogue_offset=dialogue_offset,
        components=components,
        payload_offset=cs,
    )
