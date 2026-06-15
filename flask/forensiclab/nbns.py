"""NBNS — NetBIOS Name Service 파싱 코어 (RFC 1001/1002).

:mod:`forensiclab.netdissect` 가 식별한 UDP(포트 137) 페이로드는 NBNS
패킷일 수 있다. 이 모듈이 그 메시지를 해석한다(:mod:`forensiclab.dns` 가
UDP 53, :mod:`forensiclab.dhcp` 가 UDP 67/68, :mod:`forensiclab.ntp` 가
UDP 123, :mod:`forensiclab.tftp` 가 UDP 69 를 다루는 것과 같은 위치).

NBNS 는 윈도 네트워크에서 호스트·도메인 이름을 IP 로 푸는 평문 UDP
브로드캐스트라 침해/사고 분석에서 단서가 짙다:

- **LLMNR/NBT-NS 포이즈닝(Responder 류 공격)**: 공격자가 이름 질의에
  거짓 응답을 흘려 인증 트래픽(NTLM 해시)을 가로챈다. 같은 이름에 대한
  질의(OPCODE 0)와 곧이은 응답(R=1)의 상관, 비정상적으로 빠른 응답이
  포이즈닝 정황이다.
- **호스트·워크그룹 정찰**: NBSTAT(NODE STATUS) 질의·응답은 대상의
  NetBIOS 이름 테이블·워크그룹·로그인 사용자를 드러낸다. 질의의
  ``encoded_name`` 이 ``*`` (와일드카드, 0x2A+NUL 패딩)면 전형적인
  이름 테이블 수집 시도다.
- **이름 등록 스푸핑**: 등록(OPCODE 5)·해제(OPCODE 6) 패킷으로 다른
  호스트의 이름을 가로채거나 충돌을 유발한다.
- **호스트 식별**: 디코드된 16바이트 NetBIOS 이름의 마지막 바이트(suffix)는
  서비스 종류를 가리킨다(0x00 워크스테이션, 0x20 파일 서버, 0x1C 도메인
  컨트롤러, 0x1D 마스터 브라우저 등) — :mod:`forensiclab.timeline`·자산
  목록 재구성에 쓰인다.

NBNS 메시지 포맷(RFC 1002 §4.2)은 DNS 와 같은 헤더(12바이트)에 질문·자원
레코드가 따른다. 다만 이름은 **NetBIOS 1차 인코딩**으로 실린다: 16바이트
이름의 각 바이트를 두 니블로 쪼개 각 니블에 0x41('A')을 더해 32바이트로
부풀린다(이어서 NUL 종단 스코프). 디코드는 그 역연산이다::

    header  TRN_ID(2) | flags(2) | QD(2) | AN(2) | NS(2) | AR(2)
    flags   R(1) OPCODE(4) NM_FLAGS(7) RCODE(4)
    name    len=0x20 | 32 encoded bytes | scope(labels) | 0x00
    q-tail  QTYPE(2) | QCLASS(2)

설계 원칙(:mod:`forensiclab.tftp`·:mod:`forensiclab.dns` 와 동일):
- 부작용 없음: 순수 함수. 디스크/표준출력/네트워크 없음.
- stdlib 전용.
- 안전: 입력 바이트를 변형하지 않는다(읽기 전용).
- 견고: 너무 짧거나 망가진 입력은 예외 대신 ``None``.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

__all__ = [
    "NBNS_OP_QUERY",
    "NBNS_OP_REGISTRATION",
    "NBNS_OP_RELEASE",
    "NBNS_OP_WACK",
    "NBNS_OP_REFRESH",
    "NBNS_TYPE_NB",
    "NBNS_TYPE_NBSTAT",
    "NBNS_SUFFIXES",
    "decode_netbios_name",
    "NbnsQuestion",
    "Nbns",
    "parse_nbns",
]

# OPCODE (RFC 1002 §4.2.1.1).
NBNS_OP_QUERY = 0         # 이름 질의(포이즈닝 공격의 표적).
NBNS_OP_REGISTRATION = 5  # 이름 등록(스푸핑 벡터).
NBNS_OP_RELEASE = 6       # 이름 해제.
NBNS_OP_WACK = 7          # Wait for ACK.
NBNS_OP_REFRESH = 8       # 이름 갱신.

_OPCODE_NAMES = {
    NBNS_OP_QUERY: "query",
    NBNS_OP_REGISTRATION: "registration",
    NBNS_OP_RELEASE: "release",
    NBNS_OP_WACK: "wack",
    NBNS_OP_REFRESH: "refresh",
}

# QTYPE (RFC 1002 §4.2.1.2).
NBNS_TYPE_NB = 0x0020      # NetBIOS 일반 이름(이름→IP).
NBNS_TYPE_NBSTAT = 0x0021  # NODE STATUS(이름 테이블 수집 정찰).

_QTYPE_NAMES = {
    NBNS_TYPE_NB: "NB",
    NBNS_TYPE_NBSTAT: "NBSTAT",
}

# NetBIOS 이름 16번째 바이트(suffix) — 서비스 종류. 자산/호스트 식별 단서.
NBNS_SUFFIXES = {
    0x00: "Workstation",
    0x03: "Messenger",
    0x06: "RAS Server",
    0x1B: "Domain Master Browser",
    0x1C: "Domain Controllers",
    0x1D: "Master Browser",
    0x1E: "Browser Election",
    0x1F: "NetDDE",
    0x20: "File Server",
    0x21: "RAS Client",
    0xBE: "Network Monitor Agent",
    0xBF: "Network Monitor App",
}


def decode_netbios_name(encoded: bytes) -> Optional[Tuple[str, int]]:
    """NetBIOS 1차 인코딩(32바이트)을 (name, suffix) 로 되돌린다.

    각 인코딩 바이트는 원본 니블 + 0x41('A') 이다. 두 바이트가 원본 1바이트로
    합쳐진다(상위 니블 먼저). 16바이트 중 앞 15는 공백 패딩된 이름, 16번째는
    서비스 종류 suffix 다.

    Args:
        encoded: 정확히 32바이트의 인코딩된 이름.

    Returns:
        ``(name, suffix)``. ``name`` 은 우측 공백을 떼고 비출력 문자를 제거한
        문자열, ``suffix`` 는 0~255 의 서비스 바이트. 길이가 32 가 아니거나
        니블이 0x41~0x50 범위를 벗어나면 ``None``.
    """
    if len(encoded) != 32:
        return None
    raw = bytearray()
    for i in range(0, 32, 2):
        hi = encoded[i] - 0x41
        lo = encoded[i + 1] - 0x41
        if not (0 <= hi <= 15 and 0 <= lo <= 15):
            return None
        raw.append((hi << 4) | lo)
    suffix = raw[15]
    name_bytes = bytes(raw[:15])
    name = name_bytes.decode("latin-1").rstrip(" ")
    # 와일드카드 질의(*)는 NUL 패딩이 따라온다 — 첫 NUL 까지만 취한다.
    nul = name.find("\x00")
    if nul != -1:
        name = name[:nul]
    return name, suffix


@dataclass(frozen=True)
class NbnsQuestion:
    """NBNS 질문(또는 자원 레코드의 이름부) 하나.

    Attributes:
        name: 디코드된 NetBIOS 이름(공백·NUL 패딩 제거). 디코드 실패 시 ``None``.
        suffix: 서비스 종류 바이트(0~255). 디코드 실패 시 ``None``.
        qtype: QTYPE(:data:`NBNS_TYPE_NB`·:data:`NBNS_TYPE_NBSTAT`).
        qclass: QCLASS(보통 0x0001=IN).
    """

    name: Optional[str]
    suffix: Optional[int]
    qtype: int
    qclass: int

    @property
    def suffix_name(self) -> str:
        """suffix 의 사람이 읽는 서비스명(미상이면 ``"0x<NN>"``)."""
        if self.suffix is None:
            return "unknown"
        return NBNS_SUFFIXES.get(self.suffix, f"0x{self.suffix:02X}")

    @property
    def qtype_name(self) -> str:
        """QTYPE 의 사람이 읽는 이름(미상이면 ``"type-0x<NNNN>"``)."""
        return _QTYPE_NAMES.get(self.qtype, f"type-0x{self.qtype:04X}")

    @property
    def is_wildcard(self) -> bool:
        """와일드카드(``*``) 질의 여부 — 이름 테이블 수집 정찰 단서."""
        return self.name == "*"


@dataclass(frozen=True)
class Nbns:
    """파싱된 NBNS 메시지(헤더 + 질문).

    Attributes:
        transaction_id: 질의/응답 짝짓기용 16비트 ID.
        is_response: R 비트(1=응답).
        opcode: OPCODE(0=query, 5=registration, ...).
        broadcast: NM_FLAGS 의 B 비트(브로드캐스트 전송).
        rcode: 응답 코드(0=정상).
        qdcount/ancount/nscount/arcount: 각 섹션 레코드 수.
        questions: 디코드된 질문 목록(파싱 가능한 만큼).
    """

    transaction_id: int
    is_response: bool
    opcode: int
    broadcast: bool
    rcode: int
    qdcount: int
    ancount: int
    nscount: int
    arcount: int
    questions: List[NbnsQuestion] = field(default_factory=list)

    @property
    def opcode_name(self) -> str:
        """OPCODE 의 사람이 읽는 이름(미상이면 ``"op-<n>"``)."""
        return _OPCODE_NAMES.get(self.opcode, f"op-{self.opcode}")

    @property
    def is_nbstat(self) -> bool:
        """NBSTAT(NODE STATUS) 질의 포함 여부 — 호스트 정찰 단서."""
        return any(q.qtype == NBNS_TYPE_NBSTAT for q in self.questions)


def _read_name(data: bytes, offset: int) -> Optional[Tuple[bytes, int]]:
    """offset 의 NetBIOS 인코딩 이름을 읽어 (encoded32, next_offset).

    첫 라벨은 길이 0x20(32) 의 인코딩된 이름이어야 한다. 이어지는 스코프
    라벨과 NUL 종단은 건너뛴다. 압축 포인터(상위 2비트 11)는 그 자리에서
    끝낸다(NBNS 질문에선 드묾).
    """
    if offset >= len(data):
        return None
    length = data[offset]
    if length != 0x20 or offset + 1 + 32 > len(data):
        return None
    encoded = data[offset + 1:offset + 33]
    pos = offset + 33
    # 스코프 라벨들을 NUL 종단까지 건너뛴다.
    while pos < len(data):
        ln = data[pos]
        if ln == 0:
            pos += 1
            break
        if ln & 0xC0:  # 압축 포인터 — 2바이트 소비 후 종료.
            pos += 2
            break
        pos += 1 + ln
    return encoded, pos


def parse_nbns(data: bytes, offset: int = 0) -> Optional[Nbns]:
    """원시 바이트에서 NBNS 메시지를 파싱한다.

    Args:
        data: NBNS 패킷을 담은 바이트. 보통 UDP 137 페이로드
            (:class:`forensiclab.netdissect` 의 ``payload_offset`` 부터)다.
        offset: 패킷이 시작하는 위치(기본 0).

    Returns:
        :class:`Nbns`. 12바이트 헤더조차 없거나 OPCODE 가 알려진 값(0/5/6/7/8)
        밖이면 ``None``. 질문 파싱이 도중 실패해도 헤더와 읽은 만큼은 반환한다.
    """
    if offset < 0 or offset + 12 > len(data):
        return None
    trn_id, flags, qd, an, ns, ar = struct.unpack(
        ">HHHHHH", data[offset:offset + 12]
    )
    is_response = bool(flags & 0x8000)
    opcode = (flags >> 11) & 0x0F
    if opcode not in _OPCODE_NAMES:
        return None
    broadcast = bool(flags & 0x0010)  # NM_FLAGS 의 B 비트.
    rcode = flags & 0x000F

    questions: List[NbnsQuestion] = []
    pos = offset + 12
    for _ in range(qd):
        nm = _read_name(data, pos)
        if nm is None:
            break
        encoded, pos = nm
        if pos + 4 > len(data):
            break
        qtype, qclass = struct.unpack(">HH", data[pos:pos + 4])
        pos += 4
        decoded = decode_netbios_name(encoded)
        name, suffix = decoded if decoded else (None, None)
        questions.append(
            NbnsQuestion(name=name, suffix=suffix, qtype=qtype, qclass=qclass)
        )

    return Nbns(
        transaction_id=trn_id,
        is_response=is_response,
        opcode=opcode,
        broadcast=broadcast,
        rcode=rcode,
        qdcount=qd,
        ancount=an,
        nscount=ns,
        arcount=ar,
        questions=questions,
    )
