"""mDNS — Multicast DNS 파싱 코어 (RFC 6762).

:mod:`forensiclab.netdissect` 가 식별한 UDP(포트 5353, 멀티캐스트 224.0.0.251
/ FF02::FB) 페이로드는 mDNS 메시지일 수 있다. 이 모듈이 그 메시지를 해석한다
(:mod:`forensiclab.dns` 가 UDP 53, :mod:`forensiclab.llmnr` 가 UDP 5355,
:mod:`forensiclab.nbns` 가 UDP 137 을 다루는 것과 같은 위치).

mDNS 는 :mod:`forensiclab.llmnr`(LLMNR)·:mod:`forensiclab.nbns`(NBT-NS)와 함께
**링크-로컬 이름 해석 삼형제**다. 셋 다 :mod:`forensiclab.dns` 와 같은 와이어
포맷(LLMNR 은 동일, NBNS 는 1차 인코딩)을 멀티캐스트로 흘리며, 같은 포이즈닝
표면을 공유한다. 다만 mDNS 는 ``.local`` 네임스페이스와 **DNS-SD 서비스
디스커버리**(RFC 6763)를 위한 것이라 포렌식 단서의 결이 다르다:

- **자산/장치 정찰(DNS-SD)**: ``_services._dns-sd._udp.local`` 메타-질의 한 방이면
  링크의 모든 서비스 타입이 응답으로 드러난다(:attr:`MdnsMessage.has_service_enumeration`).
  PTR 질의·응답의 서비스 타입(``_airplay._tcp``·``_googlecast._tcp``·
  ``_ipp._tcp``·``_ssh._tcp``·``_smb._tcp`` …)은 장치 종류를 짚어주는
  핑거프린트다(:attr:`MdnsMessage.queried_service_types` /
  :attr:`advertised_service_types`).
- **mDNS 스푸핑/포이즈닝**: 공격자(Responder 의 mDNS 모드·Inveigh)가 ``.local``
  이름을 자기 IP 로 답해 인증 트래픽(NTLM 해시)을 가로챈다 — LLMNR 과 같은
  메커니즘(응답 A/AAAA 의 ``address`` 가 공격자 주장 목적지, 이어서
  :mod:`forensiclab.smb` NTLMSSP 와 상관).
- **QU(unicast-response) 비트 악용**: 질문 클래스 최상위 비트가 켜지면 응답을
  멀티캐스트가 아닌 질의자에게 유니캐스트로 달라는 뜻(:attr:`MdnsQuestion.unicast_response`).
  포이즈너가 응답 경쟁을 피하려 자주 쓴다.
- **cache-flush 비트**: 응답 RR 클래스 최상위 비트는 "기존 캐시 무효화"
  지시(:attr:`ResourceRecord.cache_flush`) — 강제 캐시 덮어쓰기 정황.

mDNS 메시지 포맷(RFC 6762 §18)은 DNS 와 같다: 12바이트 헤더 + 질문 + 자원
레코드. ID 는 보통 0(트랜잭션 짝짓기 안 함), 응답은 AA 비트를 세운다. 이름은
표준 DNS 라벨이며 압축 포인터를 쓸 수 있어(:mod:`forensiclab.dns` 처럼) PTR/SRV
RDATA 안의 이름까지 방어적으로 따라간다.

설계 원칙(:mod:`forensiclab.dns`·:mod:`forensiclab.llmnr` 와 동일):
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
    "MDNS_PORT",
    "QTYPE_NAMES",
    "qtype_name",
    "service_label",
    "MdnsQuestion",
    "ResourceRecord",
    "MdnsMessage",
    "parse_message",
]

MDNS_PORT = 5353

_HEADER_SIZE = 12
_PTR_MASK = 0xC0  # 라벨 길이 바이트 상위 2비트가 11 이면 압축 포인터.
_PTR_OFFSET_MASK = 0x3FFF
_MAX_NAME_LENGTH = 255  # RFC 1035: 도메인 이름 전체 길이 상한.

# 플래그 비트(DNS 와 같은 위치). mDNS 응답은 AA(권한) 비트를 세운다.
_F_QR = 0x8000          # 응답.
_F_AUTHORITATIVE = 0x0400  # AA — 권한 응답(mDNS 응답자는 항상 권한자).
_F_TRUNCATED = 0x0200   # TC — 잘림(알려진 응답 목록이 다음 패킷에 이어짐).

# 클래스 필드 최상위 비트의 재해석(RFC 6762 §5.4, §10.2).
_QU_BIT = 0x8000        # 질문: 유니캐스트 응답 요청.
_CACHE_FLUSH_BIT = 0x8000  # 응답 RR: 기존 캐시 무효화.
_CLASS_MASK = 0x7FFF    # 최상위 비트를 뗀 실제 클래스 값.

# DNS-SD 메타-질의 — 링크의 모든 서비스 타입 열거(자산 정찰).
_SERVICE_ENUM_NAME = "_services._dns-sd._udp.local"

# RR/QTYPE 타입 — DNS 와 공유.
TYPE_A = 1
TYPE_PTR = 12       # DNS-SD 서비스 타입 → 인스턴스 매핑(서비스 디스커버리 핵심).
TYPE_TXT = 16       # 서비스 메타데이터(key=value).
TYPE_AAAA = 28
TYPE_SRV = 33       # 서비스 인스턴스 → 호스트:포트.

QTYPE_NAMES = {
    TYPE_A: "A",
    2: "NS",
    5: "CNAME",
    TYPE_PTR: "PTR",
    TYPE_TXT: "TXT",
    TYPE_AAAA: "AAAA",
    TYPE_SRV: "SRV",
    47: "NSEC",
    255: "ANY",
}


def qtype_name(qtype: int) -> str:
    """QTYPE/TYPE 번호를 약어로(미지의 값은 숫자 문자열)."""
    return QTYPE_NAMES.get(qtype, str(qtype))


def service_label(name: str) -> Optional[str]:
    """이름에서 DNS-SD 서비스 타입 라벨을 뽑는다(없으면 ``None``).

    ``Living Room._airplay._tcp.local`` 또는 ``_ipp._tcp.local`` 에서
    ``_airplay._tcp`` / ``_ipp._tcp`` 처럼 ``_proto`` 직전의 ``_service`` 와
    전송(``_tcp``/``_udp``) 두 라벨을 결합해 장치/서비스 식별 핑거프린트로 쓴다.
    """
    labels = name.split(".")
    for i, lab in enumerate(labels):
        if lab in ("_tcp", "_udp") and i >= 1:
            svc = labels[i - 1]
            if svc.startswith("_"):
                return f"{svc}.{lab}"
    return None


@dataclass(frozen=True)
class MdnsQuestion:
    """mDNS 질문 섹션의 항목 한 개.

    Attributes:
        name: 질의한 이름(점 구분; 보통 ``.local`` 호스트명 또는 서비스 타입).
        qtype: 질의 타입 번호(1=A, 12=PTR, 33=SRV …).
        qclass: 질의 클래스 번호(QU 비트를 뗀 값; 보통 1=IN).
        unicast_response: QU 비트 — 응답을 유니캐스트로 달라는 요청.
    """

    name: str
    qtype: int
    qclass: int
    unicast_response: bool = False

    @property
    def qtype_name(self) -> str:
        """:attr:`qtype` 의 약어 표기."""
        return qtype_name(self.qtype)

    @property
    def is_service_enumeration(self) -> bool:
        """DNS-SD 메타-질의(모든 서비스 타입 열거) 여부 — 자산 정찰 단서."""
        return self.name.lower() == _SERVICE_ENUM_NAME

    @property
    def service_type(self) -> Optional[str]:
        """질의한 이름에 담긴 DNS-SD 서비스 타입(없으면 ``None``)."""
        return service_label(self.name)


@dataclass(frozen=True)
class ResourceRecord:
    """자원 레코드 한 개(답변/권한/추가 섹션).

    Attributes:
        name: 레코드가 가리키는 이름.
        rtype: 레코드 타입(1=A, 12=PTR, 16=TXT, 28=AAAA, 33=SRV …).
        rclass: 레코드 클래스(cache-flush 비트를 뗀 값; 보통 1=IN).
        ttl: TTL(초).
        cache_flush: 클래스 최상위 비트 — 기존 캐시 무효화 지시.
        address: A/AAAA 일 때 사람이 읽는 IP 문자열(포이즈닝 응답이 주장하는
            목적지 IP). 그 외엔 ``None``.
        target: PTR(서비스 인스턴스 이름)·SRV(대상 호스트) 의 RDATA 이름. 그 외 ``None``.
        port: SRV 레코드의 포트 번호(그 외 ``None``).
        txt: TXT 레코드의 ``key=value`` 문자열 목록(그 외 빈 목록).
    """

    name: str
    rtype: int
    rclass: int
    ttl: int
    cache_flush: bool = False
    address: Optional[str] = None
    target: Optional[str] = None
    port: Optional[int] = None
    txt: List[str] = field(default_factory=list)

    @property
    def rtype_name(self) -> str:
        """:attr:`rtype` 의 약어 표기."""
        return qtype_name(self.rtype)

    @property
    def service_type(self) -> Optional[str]:
        """레코드 이름에 담긴 DNS-SD 서비스 타입(없으면 ``None``)."""
        return service_label(self.name)


@dataclass(frozen=True)
class MdnsMessage:
    """파싱된 mDNS 메시지(헤더 + 질문 + 답변 자원 레코드).

    Attributes:
        id: 트랜잭션 ID(mDNS 는 보통 0).
        is_response: QR 비트(``True``=응답).
        opcode: 연산 코드(mDNS 은 0=표준 질의만).
        authoritative: AA 비트(mDNS 응답자는 권한자).
        truncated: TC 비트(알려진 응답 목록이 이어짐).
        rcode: 응답 코드(0=정상).
        questions: 질문 섹션 항목 목록.
        answers: 답변(answer) 섹션 자원 레코드 목록.
        answer_count/authority_count/additional_count: 각 섹션 선언 개수.
    """

    id: int
    is_response: bool
    opcode: int
    authoritative: bool
    truncated: bool
    rcode: int
    questions: List[MdnsQuestion] = field(default_factory=list)
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
    def has_service_enumeration(self) -> bool:
        """DNS-SD 메타-질의가 포함됐는지 — 링크 전체 서비스 정찰 단서."""
        return any(q.is_service_enumeration for q in self.questions)

    @property
    def unicast_requested(self) -> bool:
        """QU 비트가 켜진 질문이 있는지 — 유니캐스트 응답 요구(포이즈너 정황)."""
        return any(q.unicast_response for q in self.questions)

    @property
    def queried_service_types(self) -> List[str]:
        """질의된 DNS-SD 서비스 타입 목록(중복 제거, 등장 순서 유지)."""
        return _dedup(q.service_type for q in self.questions)

    @property
    def advertised_service_types(self) -> List[str]:
        """답변 레코드가 광고하는 서비스 타입 목록(장치 핑거프린트)."""
        return _dedup(r.service_type for r in self.answers)

    @property
    def answer_addresses(self) -> List[str]:
        """응답이 주장하는 A/AAAA 주소 목록(포이즈닝이면 공격자 IP)."""
        return [r.address for r in self.answers if r.address is not None]


def _dedup(items) -> List[str]:
    """``None`` 을 거르고 등장 순서를 지키며 중복 제거."""
    out: List[str] = []
    for it in items:
        if it is not None and it not in out:
            out.append(it)
    return out


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
        labels.append(data[start:end].decode("utf-8", "replace"))
        cursor = end
    if next_offset is None:
        next_offset = cursor
    return ".".join(labels), next_offset


def _parse_txt(rdata: bytes) -> List[str]:
    """TXT RDATA(길이접두 문자열들의 나열)를 ``key=value`` 목록으로."""
    out: List[str] = []
    i = 0
    n = len(rdata)
    while i < n:
        slen = rdata[i]
        i += 1
        if slen == 0 or i + slen > n:
            break
        out.append(rdata[i:i + slen].decode("utf-8", "replace"))
        i += slen
    return out


def _read_rr(data: bytes, offset: int) -> Optional[Tuple[ResourceRecord, int]]:
    """``offset`` 위치의 자원 레코드 하나를 읽어 ``(rr, next_offset)``.

    타입별 RDATA 를 해석한다 — A/AAAA 는 IP 문자열, PTR/SRV 는 대상 이름(압축
    포인터 추적), SRV 는 포트, TXT 는 key=value 목록. 잘렸거나 형식이 어긋나면
    ``None``.
    """
    parsed = _read_name(data, offset)
    if parsed is None:
        return None
    name, pos = parsed
    if pos + 10 > len(data):
        return None
    rtype, rclass_raw, ttl, rdlength = struct.unpack(">HHIH", data[pos:pos + 10])
    pos += 10
    if pos + rdlength > len(data):
        return None
    rdata = data[pos:pos + rdlength]
    rdata_start = pos
    pos += rdlength

    cache_flush = bool(rclass_raw & _CACHE_FLUSH_BIT)
    rclass = rclass_raw & _CLASS_MASK
    address: Optional[str] = None
    target: Optional[str] = None
    port: Optional[int] = None
    txt: List[str] = []
    try:
        if rtype == TYPE_A and rdlength == 4:
            address = socket.inet_ntop(socket.AF_INET, rdata)
        elif rtype == TYPE_AAAA and rdlength == 16:
            address = socket.inet_ntop(socket.AF_INET6, rdata)
        elif rtype == TYPE_PTR:
            got = _read_name(data, rdata_start)
            if got is not None:
                target = got[0]
        elif rtype == TYPE_SRV and rdlength >= 6:
            _prio, _weight, port = struct.unpack(">HHH", rdata[:6])
            got = _read_name(data, rdata_start + 6)
            if got is not None:
                target = got[0]
        elif rtype == TYPE_TXT:
            txt = _parse_txt(rdata)
    except (OSError, ValueError, struct.error):
        address = target = port = None
        txt = []
    return ResourceRecord(
        name=name, rtype=rtype, rclass=rclass, ttl=ttl,
        cache_flush=cache_flush, address=address, target=target,
        port=port, txt=txt,
    ), pos


def parse_message(data: bytes, offset: int = 0) -> Optional[MdnsMessage]:
    """UDP 페이로드 바이트를 mDNS 메시지로 파싱한다.

    Args:
        data: mDNS 메시지 원시 바이트(보통 UDP 5353 페이로드,
            :class:`forensiclab.netdissect` 의 ``payload_offset`` 부터).
        offset: 메시지가 시작하는 위치(기본 0).

    Returns:
        :class:`MdnsMessage`. 12바이트 헤더조차 없거나 Opcode 가 0(표준 질의)이
        아니면 ``None`` — mDNS 은 Opcode 0 만 정의하므로 오탐 방지 가드로 쓴다.
        질문/답변 파싱이 도중 실패해도 헤더와 읽은 만큼은 반환한다.
    """
    if offset < 0 or offset + _HEADER_SIZE > len(data):
        return None
    txn_id, flags, qd, an, ns, ar = struct.unpack(
        ">HHHHHH", data[offset:offset + _HEADER_SIZE]
    )
    opcode = (flags >> 11) & 0x0F
    if opcode != 0:
        return None  # mDNS 은 표준 질의(Opcode 0)만 — 다른 트래픽 오탐 차단.

    questions: List[MdnsQuestion] = []
    pos = offset + _HEADER_SIZE
    for _ in range(qd):
        parsed = _read_name(data, pos)
        if parsed is None:
            break
        name, pos = parsed
        if pos + 4 > len(data):
            break
        qtype, qclass_raw = struct.unpack(">HH", data[pos:pos + 4])
        pos += 4
        questions.append(MdnsQuestion(
            name=name, qtype=qtype, qclass=qclass_raw & _CLASS_MASK,
            unicast_response=bool(qclass_raw & _QU_BIT),
        ))

    answers: List[ResourceRecord] = []
    for _ in range(an):
        rr = _read_rr(data, pos)
        if rr is None:
            break
        record, pos = rr
        answers.append(record)

    return MdnsMessage(
        id=txn_id,
        is_response=bool(flags & _F_QR),
        opcode=opcode,
        authoritative=bool(flags & _F_AUTHORITATIVE),
        truncated=bool(flags & _F_TRUNCATED),
        rcode=flags & 0x000F,
        questions=questions,
        answers=answers,
        answer_count=an,
        authority_count=ns,
        additional_count=ar,
    )
