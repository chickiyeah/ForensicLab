"""DNS 메시지(질의/응답) 파싱 코어.

:mod:`forensiclab.netdissect` 가 패킷을 L4(UDP 포트 53)까지 해석한다면, 이
모듈은 그 UDP 페이로드(DNS 메시지 바이트)를 받아 헤더와 질문(question) 섹션을
구조화한다. 침해 분석에서 DNS 는 C2 비콘·도메인 생성 알고리즘(DGA)·DNS
터널링을 통한 데이터 유출의 단골 통로라, "어떤 이름을 누가 물어봤는가" 를
뽑아내는 것은 탐지의 핵심 단서다.

지원 범위:
- 12바이트 고정 헤더 전체(ID·플래그·각 섹션 카운트).
- 질문 섹션의 QNAME·QTYPE·QCLASS. 압축 포인터(상위 2비트 ``11``)도 따라가
  잘린 이름을 복원한다.
- 답변/권한/추가 섹션의 리소스 레코드(RR)는 *개수만* 헤더에서 읽고 본문은
  해석하지 않는다(질의 분석에 질문 섹션만으로 충분하고, 증분을 작게 유지).

설계 원칙(:mod:`forensiclab.netdissect`·:mod:`forensiclab.flows` 와 동일):
- 부작용 없음: 디스크/표준출력 없이 순수 함수 (테스트 용이).
- stdlib 전용: 외부 의존성 없음.
- 안전: 입력 바이트를 변형하지 않는다(읽기 전용).
- 견고: 잘렸거나 망가진 메시지는 예외 대신 ``None`` 으로 둔다. 압축 포인터
  루프는 방문한 오프셋을 추적해 무한 루프를 막는다.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import List, Optional

__all__ = [
    "QTYPE_NAMES",
    "Question",
    "DnsMessage",
    "qtype_name",
    "parse_message",
]

_HEADER_SIZE = 12
_PTR_MASK = 0xC0  # 라벨 길이 바이트 상위 2비트가 11 이면 압축 포인터.
_PTR_OFFSET_MASK = 0x3FFF
_MAX_NAME_LENGTH = 255  # RFC 1035: 도메인 이름 전체 길이 상한.

# 자주 보는 QTYPE 번호 → 약어. 그 외는 숫자 문자열로 둔다.
QTYPE_NAMES = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    255: "ANY",
}


def qtype_name(qtype: int) -> str:
    """QTYPE 번호를 약어로(미지의 값은 숫자 문자열)."""
    return QTYPE_NAMES.get(qtype, str(qtype))


@dataclass(frozen=True)
class Question:
    """DNS 질문 섹션의 항목 한 개.

    Attributes:
        name: 질의한 도메인 이름(점 구분, 루트는 빈 문자열 ``""``).
        qtype: 질의 타입 번호(1=A, 28=AAAA …).
        qclass: 질의 클래스 번호(보통 1=IN).
    """

    name: str
    qtype: int
    qclass: int

    @property
    def qtype_name(self) -> str:
        """:attr:`qtype` 의 약어 표기."""
        return qtype_name(self.qtype)


@dataclass(frozen=True)
class DnsMessage:
    """파싱된 DNS 메시지(헤더 + 질문 섹션).

    Attributes:
        id: 트랜잭션 ID.
        is_response: QR 비트(``True``=응답, ``False``=질의).
        opcode: 연산 코드(0=표준 질의 …).
        rcode: 응답 코드(0=정상, 3=NXDOMAIN …).
        truncated: TC 비트(메시지가 잘려 TCP 재시도 필요).
        recursion_desired: RD 비트.
        questions: 질문 섹션 항목 목록.
        answer_count: 답변(answer) RR 개수(본문 미해석).
        authority_count: 권한(authority) RR 개수.
        additional_count: 추가(additional) RR 개수.
    """

    id: int
    is_response: bool
    opcode: int
    rcode: int
    truncated: bool
    recursion_desired: bool
    questions: List[Question]
    answer_count: int
    authority_count: int
    additional_count: int


def _read_name(data: bytes, offset: int) -> Optional[tuple]:
    """``offset`` 위치의 도메인 이름을 읽는다(압축 포인터 추적).

    Returns:
        ``(name, next_offset)``. ``next_offset`` 은 질문의 나머지 필드가
        시작되는, *포인터를 따라가기 전* 의 위치. 망가졌으면 ``None``.
    """
    labels: List[str] = []
    seen: set = set()  # 무한 루프(서로를 가리키는 포인터) 방지.
    cursor = offset
    next_offset: Optional[int] = None
    total = 0
    while True:
        if cursor >= len(data):
            return None
        length = data[cursor]
        if length & _PTR_MASK == _PTR_MASK:
            # 2바이트 압축 포인터.
            if cursor + 1 >= len(data):
                return None
            pointer = struct.unpack(">H", data[cursor:cursor + 2])[0] & _PTR_OFFSET_MASK
            if next_offset is None:
                next_offset = cursor + 2
            if pointer in seen:
                return None
            seen.add(pointer)
            cursor = pointer
            continue
        if length & _PTR_MASK != 0:
            return None  # 0b10/0b01 상위비트는 예약 — 망가진 입력.
        if length == 0:
            cursor += 1
            break
        start = cursor + 1
        end = start + length
        if end > len(data):
            return None
        total += length + 1
        if total > _MAX_NAME_LENGTH:
            return None
        labels.append(data[start:end].decode("ascii", "replace"))
        cursor = end
    if next_offset is None:
        next_offset = cursor
    return ".".join(labels), next_offset


def parse_message(data: bytes) -> Optional[DnsMessage]:
    """UDP 페이로드 바이트를 DNS 메시지로 파싱한다.

    Args:
        data: DNS 메시지 원시 바이트(UDP 포트 53 페이로드).

    Returns:
        :class:`DnsMessage`. 헤더가 12바이트에 못 미치거나 질문 섹션이
        선언된 개수만큼 온전히 들어있지 않으면 ``None``.
    """
    if len(data) < _HEADER_SIZE:
        return None
    txn_id, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", data[:_HEADER_SIZE])
    is_response = bool(flags & 0x8000)
    opcode = (flags >> 11) & 0x0F
    truncated = bool(flags & 0x0200)
    recursion_desired = bool(flags & 0x0100)
    rcode = flags & 0x000F

    questions: List[Question] = []
    offset = _HEADER_SIZE
    for _ in range(qd):
        parsed = _read_name(data, offset)
        if parsed is None:
            return None
        name, offset = parsed
        if offset + 4 > len(data):
            return None
        qtype, qclass = struct.unpack(">HH", data[offset:offset + 4])
        offset += 4
        questions.append(Question(name=name, qtype=qtype, qclass=qclass))

    return DnsMessage(
        id=txn_id,
        is_response=is_response,
        opcode=opcode,
        rcode=rcode,
        truncated=truncated,
        recursion_desired=recursion_desired,
        questions=questions,
        answer_count=an,
        authority_count=ns,
        additional_count=ar,
    )
