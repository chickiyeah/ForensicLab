"""LLMNR — Link-Local Multicast Name Resolution 파싱 코어 (RFC 4795).

:mod:`forensiclab.netdissect` 가 식별한 UDP(포트 5355, 멀티캐스트 224.0.0.252
/ FF02::1:3) 페이로드는 LLMNR 메시지일 수 있다. 이 모듈이 그 메시지를
해석한다(:mod:`forensiclab.dns` 가 UDP 53, :mod:`forensiclab.nbns` 가 UDP
137, :mod:`forensiclab.dhcp` 가 UDP 67/68 을 다루는 것과 같은 위치).

LLMNR 은 NBT-NS(:mod:`forensiclab.nbns`)와 **이름 해석 포이즈닝의 한 쌍**이다.
호스트가 DNS 로 못 푼 이름(오타·존재하지 않는 호스트·``wpad`` 등)을 같은
링크의 이웃에게 멀티캐스트로 물을 때, 공격자(Responder·Inveigh)가 거짓 응답을
흘려 인증 트래픽(NTLM 해시)을 가로챈다. 침해/사고 분석에서 단서가 짙다:

- **LLMNR 포이즈닝(Responder/Inveigh)**: 같은 이름에 대한 질의(QR=0)와 곧이은
  응답(QR=1)의 상관, 비정상적으로 빠른 응답, 한 응답자가 여러 무관한 이름을
  모두 자기 IP 로 답하는 패턴이 포이즈닝 정황이다. 응답의 A/AAAA 레코드에
  실린 주소(:attr:`ResourceRecord.address`)가 공격자가 주장하는 IP — 곧
  NTLM 인증이 향할 목적지다(:mod:`forensiclab.smb`·NTLMSSP 와 상관).
- **WPAD 하이재킹**: ``wpad`` 이름 질의(:attr:`LlmnrQuestion.is_wpad`)에
  거짓 응답을 주면 피해자의 프록시 설정을 탈취해 트래픽을 가로챈다.
- **트리거 표면 정찰**: DNS 실패가 LLMNR 로 흘러나오므로, 질의된 이름 자체가
  내부 호스트명·공유명·오타 흔적을 드러낸다(자산/타임라인 재구성).

LLMNR 메시지 포맷(RFC 4795 §2.1)은 DNS 와 **같은 와이어 포맷**이다: 12바이트
헤더 + 질문 + 자원 레코드. 다만 플래그 비트 일부가 재해석된다::

    header  ID(2) | flags(2) | QDCOUNT(2) | ANCOUNT(2) | NSCOUNT(2) | ARCOUNT(2)
    flags   QR(1) Opcode(4) C(1) TC(1) T(1) Z(4) RCODE(4)

여기서 ``C`` 는 Conflict(고유 이름 충돌), ``T`` 는 Tentative(미검증 응답)다.
이름은 NBNS 의 1차 인코딩이 아니라 **표준 DNS 라벨**로 실린다(LLMNR 은 압축
포인터 사용을 금하지만, 견고함을 위해 :mod:`forensiclab.dns` 처럼 포인터도
방어적으로 따라간다).

설계 원칙(:mod:`forensiclab.dns`·:mod:`forensiclab.nbns` 와 동일):
- 부작용 없음: 순수 함수. 디스크/표준출력/네트워크 없음.
- stdlib 전용.
- 안전: 입력 바이트를 변형하지 않는다(읽기 전용).
- 견고: 너무 짧거나 망가진 입력은 예외 대신 ``None``. 자원 레코드 파싱이
  도중 실패하면 거기까지 읽은 만큼만 반환한다. 압축 포인터 루프는 방문한
  오프셋을 추적해 무한 루프를 막는다.
"""

from __future__ import annotations

import socket
import struct
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

__all__ = [
    "LLMNR_PORT",
    "QTYPE_NAMES",
    "qtype_name",
    "LlmnrQuestion",
    "ResourceRecord",
    "LlmnrMessage",
    "parse_message",
]

LLMNR_PORT = 5355

_HEADER_SIZE = 12
_PTR_MASK = 0xC0  # 라벨 길이 바이트 상위 2비트가 11 이면 압축 포인터.
_PTR_OFFSET_MASK = 0x3FFF
_MAX_NAME_LENGTH = 255  # RFC 1035: 도메인 이름 전체 길이 상한.

# 플래그 비트(RFC 4795 §2.1.1 — DNS 와 같은 위치, 일부 재해석).
_F_QR = 0x8000          # 응답.
_F_CONFLICT = 0x0400    # C — 고유 이름 충돌(DNS AA 위치 재해석).
_F_TRUNCATED = 0x0200   # TC — 잘림.
_F_TENTATIVE = 0x0100   # T — 미검증(잠정) 응답(DNS RD 위치 재해석).

# RR/QTYPE 타입 — DNS 와 공유. A/AAAA 가 포이즈닝 응답의 핵심 페이로드.
TYPE_A = 1
TYPE_AAAA = 28

QTYPE_NAMES = {
    TYPE_A: "A",
    2: "NS",
    5: "CNAME",
    12: "PTR",
    16: "TXT",
    TYPE_AAAA: "AAAA",
    33: "SRV",
    255: "ANY",
}


def qtype_name(qtype: int) -> str:
    """QTYPE/TYPE 번호를 약어로(미지의 값은 숫자 문자열)."""
    return QTYPE_NAMES.get(qtype, str(qtype))


@dataclass(frozen=True)
class LlmnrQuestion:
    """LLMNR 질문 섹션의 항목 한 개.

    Attributes:
        name: 질의한 이름(점 구분, 보통 단일 호스트명).
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

    @property
    def is_wpad(self) -> bool:
        """WPAD 프록시 자동탐색 이름 질의 여부 — 하이재킹 표적 단서."""
        return self.name.lower().split(".", 1)[0] == "wpad"


@dataclass(frozen=True)
class ResourceRecord:
    """자원 레코드 한 개(답변/권한/추가 섹션).

    Attributes:
        name: 레코드가 가리키는 이름.
        rtype: 레코드 타입(1=A, 28=AAAA …).
        rclass: 레코드 클래스(보통 1=IN).
        ttl: TTL(초).
        address: A/AAAA 일 때 사람이 읽는 IP 문자열(포이즈닝 응답이 주장하는
            목적지 IP). 그 외 타입이거나 RDATA 길이가 안 맞으면 ``None``.
    """

    name: str
    rtype: int
    rclass: int
    ttl: int
    address: Optional[str] = None

    @property
    def rtype_name(self) -> str:
        """:attr:`rtype` 의 약어 표기."""
        return qtype_name(self.rtype)


@dataclass(frozen=True)
class LlmnrMessage:
    """파싱된 LLMNR 메시지(헤더 + 질문 + 답변 자원 레코드).

    Attributes:
        id: 트랜잭션 ID(질의/응답 짝짓기).
        is_response: QR 비트(``True``=응답).
        opcode: 연산 코드(LLMNR 은 0=표준 질의만).
        conflict: C 비트(고유 이름 충돌).
        truncated: TC 비트(잘림).
        tentative: T 비트(미검증 응답).
        rcode: 응답 코드(0=정상).
        questions: 질문 섹션 항목 목록.
        answers: 답변(answer) 섹션 자원 레코드 목록(A/AAAA 주소 추출).
        answer_count/authority_count/additional_count: 각 섹션 선언 개수.
    """

    id: int
    is_response: bool
    opcode: int
    conflict: bool
    truncated: bool
    tentative: bool
    rcode: int
    questions: List[LlmnrQuestion] = field(default_factory=list)
    answers: List[ResourceRecord] = field(default_factory=list)
    answer_count: int = 0
    authority_count: int = 0
    additional_count: int = 0

    @property
    def is_query(self) -> bool:
        """질의(QR=0) 여부."""
        return not self.is_response

    @property
    def queried_names(self) -> List[str]:
        """질문 섹션에서 질의된 이름 목록(트리거 표면 정찰 단서)."""
        return [q.name for q in self.questions]

    @property
    def has_wpad_query(self) -> bool:
        """질문 중 WPAD 이름이 있는지 — 프록시 하이재킹 표적 단서."""
        return any(q.is_wpad for q in self.questions)

    @property
    def answer_addresses(self) -> List[str]:
        """응답이 주장하는 A/AAAA 주소 목록(포이즈닝이면 공격자 IP)."""
        return [r.address for r in self.answers if r.address is not None]


def _read_name(data: bytes, offset: int) -> Optional[Tuple[str, int]]:
    """``offset`` 위치의 DNS 형식 이름을 읽는다(압축 포인터 방어적 추적).

    Returns:
        ``(name, next_offset)``. ``next_offset`` 은 이름 뒤 필드가 시작되는,
        *포인터를 따라가기 전* 의 위치. 망가졌으면 ``None``.
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


def _read_rr(data: bytes, offset: int) -> Optional[Tuple[ResourceRecord, int]]:
    """``offset`` 위치의 자원 레코드 하나를 읽어 ``(rr, next_offset)``.

    A/AAAA 면 RDATA 에서 IP 주소를 사람이 읽는 문자열로 뽑는다. 잘렸거나
    형식이 어긋나면 ``None``.
    """
    parsed = _read_name(data, offset)
    if parsed is None:
        return None
    name, pos = parsed
    if pos + 10 > len(data):
        return None
    rtype, rclass, ttl, rdlength = struct.unpack(">HHIH", data[pos:pos + 10])
    pos += 10
    if pos + rdlength > len(data):
        return None
    rdata = data[pos:pos + rdlength]
    pos += rdlength
    address: Optional[str] = None
    try:
        if rtype == TYPE_A and rdlength == 4:
            address = socket.inet_ntop(socket.AF_INET, rdata)
        elif rtype == TYPE_AAAA and rdlength == 16:
            address = socket.inet_ntop(socket.AF_INET6, rdata)
    except (OSError, ValueError):
        address = None
    return ResourceRecord(name=name, rtype=rtype, rclass=rclass, ttl=ttl,
                          address=address), pos


def parse_message(data: bytes, offset: int = 0) -> Optional[LlmnrMessage]:
    """UDP 페이로드 바이트를 LLMNR 메시지로 파싱한다.

    Args:
        data: LLMNR 메시지 원시 바이트(보통 UDP 5355 페이로드,
            :class:`forensiclab.netdissect` 의 ``payload_offset`` 부터).
        offset: 메시지가 시작하는 위치(기본 0).

    Returns:
        :class:`LlmnrMessage`. 12바이트 헤더조차 없거나 Opcode 가 0(표준 질의)이
        아니면 ``None`` — LLMNR 은 Opcode 0 만 정의하므로 오탐 방지 가드로 쓴다.
        질문/답변 파싱이 도중 실패해도 헤더와 읽은 만큼은 반환한다.
    """
    if offset < 0 or offset + _HEADER_SIZE > len(data):
        return None
    txn_id, flags, qd, an, ns, ar = struct.unpack(
        ">HHHHHH", data[offset:offset + _HEADER_SIZE]
    )
    opcode = (flags >> 11) & 0x0F
    if opcode != 0:
        return None  # LLMNR 은 표준 질의(Opcode 0)만 — 다른 트래픽 오탐 차단.

    questions: List[LlmnrQuestion] = []
    pos = offset + _HEADER_SIZE
    for _ in range(qd):
        parsed = _read_name(data, pos)
        if parsed is None:
            break
        name, pos = parsed
        if pos + 4 > len(data):
            break
        qtype, qclass = struct.unpack(">HH", data[pos:pos + 4])
        pos += 4
        questions.append(LlmnrQuestion(name=name, qtype=qtype, qclass=qclass))

    answers: List[ResourceRecord] = []
    for _ in range(an):
        rr = _read_rr(data, pos)
        if rr is None:
            break
        record, pos = rr
        answers.append(record)

    return LlmnrMessage(
        id=txn_id,
        is_response=bool(flags & _F_QR),
        opcode=opcode,
        conflict=bool(flags & _F_CONFLICT),
        truncated=bool(flags & _F_TRUNCATED),
        tentative=bool(flags & _F_TENTATIVE),
        rcode=flags & 0x000F,
        questions=questions,
        answers=answers,
        answer_count=an,
        authority_count=ns,
        additional_count=ar,
    )
