"""GRE(Generic Routing Encapsulation) 터널 헤더 파싱 코어 (RFC 2784/2890·RFC 2637).

:mod:`forensiclab.netdissect` 가 IPv4 헤더에서 식별한 **IP 프로토콜 번호 47**
페이로드 위에서, 한 패킷을 다른 패킷 안에 그대로 감싸 나르는 **터널 캡슐** 헤더다.
:mod:`forensiclab.ike` 가 IPsec 암호 터널의 *키 협상* 손잡이라면, GRE 는 TCP/UDP 가
아닌 **L3 위의 범용 터널 운반층** 그 자체 — 헤더가 평문이고, 안에 무엇을 실었는지
(``protocol_type``)·어느 세션인지(``key``/Call ID)를 그대로 드러낸다.

침해/사고 분석에서 GRE 가 드러내는 것:

- **방화벽 우회·은닉 터널**: GRE 는 포트가 없는 IP 프로토콜(47)이라 포트 기반
  필터를 비껴간다. 공격자가 내부 IP 패킷을 GRE 로 감싸 외부로 내보내면(IP-in-IP,
  ``carries_ipv4``/``carries_ipv6``) C2·대량 유출을 평범한 터널처럼 위장한다 —
  내부 ``protocol_type`` 으로 캡슐 안 트래픽 종류를 식별.
- **PPTP VPN 데이터 평면(Enhanced GRE, RFC 2637)**: 버전 1 + protocol 0x880B(PPP)는
  레거시 PPTP VPN 의 데이터 채널(``is_pptp``). PPTP 는 MS-CHAPv2·MPPE 의 알려진
  약점으로 깨지는 구식 VPN — 보이는 것 자체가 위험 신호. 16비트 **Call ID**(``call_id``)
  는 PPTP 세션 식별자로 :mod:`forensiclab.flows` 의 흐름을 한 통화/세션에 못 박는다.
- **ERSPAN — 원격 포트 미러링(감시·캡처)**: protocol 0x88BE(II)·0x22EB(III)는
  스위치가 **다른 포트의 트래픽 전체를 떠서** 원격 수집기로 보내는 ERSPAN(``is_erspan``).
  정상 운영 도구지만, 비인가 ERSPAN 세션은 곧 **네트워크 감청·증거 수집 채널** —
  누가 어디로 미러링하는지가 핵심 단서.
- **NVGRE — L2-over-L3 터널**: protocol 0x6558(Transparent Ethernet Bridging)은
  이더넷 프레임을 통째로 캡슐화(``is_nvgre``) — VXLAN 형제로, L3 경계를 넘어
  L2 세그먼트를 잇는 은닉 브리지가 될 수 있다.
- **터널 상관·세션 귀속(Key)**: K 비트가 켜지면 32비트 **Key**(``key``)로 같은
  터널의 양방향을 묶는다(GRE keepalive·다중 터널 구분). 시퀀스 번호(``sequence``)는
  순서·재전송, PPTP 의 Ack 번호(``ack``)는 세션 진행 상태.

와이어 포맷 — GRE 헤더(가변): Flags+Version(2바이트: C/R/K/S/s/Recur·A/Flags/Ver)·
Protocol Type(2). 이어 C 면 Checksum(2)+Reserved1(2), K 면 Key(4)(버전1 은
Payload Length(2)+Call ID(2)), S 면 Sequence(4), A(버전1) 면 Ack(4).

설계 원칙(다른 파서와 동일):
- 부작용 없음·stdlib 전용·읽기 전용.
- 견고: 버전(0/1)이 아니거나 헤더가 잘리면 예외 대신 ``None``.
- 캡슐 **안쪽** 페이로드는 풀지 않고 시작 오프셋(``payload_offset``)만 노출한다
  (다시 :mod:`forensiclab.netdissect` 로 넘겨 재귀 해석할 수 있게).
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Optional

__all__ = [
    "GRE_PROTOCOLS",
    "GreHeader",
    "looks_like_gre",
    "parse_gre",
]

# Protocol Type(EtherType) — 캡슐 안에 무엇이 실렸는지.
GRE_PROTOCOLS = {
    0x0800: "IPv4",
    0x86DD: "IPv6",
    0x0806: "ARP",
    0x880B: "PPP",          # RFC 2637 Enhanced GRE(PPTP) 데이터
    0x6558: "TEB",          # Transparent Ethernet Bridging(NVGRE)
    0x88BE: "ERSPAN_II",    # Remote SPAN(포트 미러링) type II
    0x22EB: "ERSPAN_III",   # Remote SPAN type III
    0x8847: "MPLS_UCAST",
    0x8848: "MPLS_MCAST",
    0x894F: "NSH",          # Network Service Header
    0x6559: "FR",           # Frame Relay
}

# byte 0 비트(상위→하위): C R K S s Recur(3).
_F_CHECKSUM = 0x80
_F_ROUTING = 0x40
_F_KEY = 0x20
_F_SEQUENCE = 0x10
_F_SSR = 0x08
# byte 1 상위 비트: A(Acknowledgment, RFC 2637 버전1 전용).
_F_ACK = 0x80
_VERSION_MASK = 0x07


@dataclass(frozen=True)
class GreHeader:
    """파싱된 GRE 터널 헤더 한 개.

    Attributes:
        version: GRE 버전(0=표준 RFC 2784/2890, 1=Enhanced GRE/PPTP RFC 2637).
        protocol_type: 캡슐 안 페이로드의 EtherType 코드.
        protocol: ``protocol_type`` 이름(미지정은 ``"0x...."``).
        has_checksum·has_key·has_sequence·has_routing·has_ack: 플래그 비트.
        checksum: Checksum 필드(C 비트 시; 그 외 None).
        key: 32비트 Key(버전0 K 비트 시; 터널 상관용. 그 외 None).
        payload_length: PPTP Payload Length(버전1; 그 외 None).
        call_id: PPTP Call ID(16비트, 버전1; 세션 식별. 그 외 None).
        sequence: Sequence Number(S 비트 시; 그 외 None).
        ack: Acknowledgment Number(버전1 A 비트 시; 그 외 None).
        header_length: GRE 헤더 전체 길이(바이트).
        payload_offset: 캡슐 안쪽 페이로드 시작 오프셋(``data`` 기준).
    """

    version: int = 0
    protocol_type: int = 0
    protocol: str = ""
    has_checksum: bool = False
    has_key: bool = False
    has_sequence: bool = False
    has_routing: bool = False
    has_ack: bool = False
    checksum: Optional[int] = None
    key: Optional[int] = None
    payload_length: Optional[int] = None
    call_id: Optional[int] = None
    sequence: Optional[int] = None
    ack: Optional[int] = None
    header_length: int = 0
    payload_offset: int = 0

    @property
    def is_pptp(self) -> bool:
        """Enhanced GRE(버전1)+PPP — 레거시 PPTP VPN 데이터 평면인지."""
        return self.version == 1 and self.protocol_type == 0x880B

    @property
    def is_erspan(self) -> bool:
        """ERSPAN(원격 포트 미러링) 캡슐 — 트래픽 감청·캡처 채널인지."""
        return self.protocol_type in (0x88BE, 0x22EB)

    @property
    def is_nvgre(self) -> bool:
        """NVGRE(Transparent Ethernet Bridging) — L2-over-L3 터널인지."""
        return self.protocol_type == 0x6558

    @property
    def carries_ipv4(self) -> bool:
        """캡슐 안이 IPv4 인지 — IP-in-IP 은닉 터널 정황(재귀 해석 대상)."""
        return self.protocol_type == 0x0800

    @property
    def carries_ipv6(self) -> bool:
        """캡슐 안이 IPv6 인지."""
        return self.protocol_type == 0x86DD


def looks_like_gre(data: bytes, offset: int = 0) -> bool:
    """``offset`` 바이트가 파싱 가능한 GRE 헤더처럼 보이는지(가벼운 가드)."""
    return parse_gre(data, offset) is not None


def _protocol_name(code: int) -> str:
    return GRE_PROTOCOLS.get(code, f"0x{code:04x}")


def parse_gre(data: bytes, offset: int = 0) -> Optional[GreHeader]:
    """단일 GRE 터널 헤더를 파싱한다.

    Args:
        data: GRE 바이트(보통 :attr:`forensiclab.netdissect.IPv4.payload_offset`
            의 IP 프로토콜 47 페이로드).
        offset: 파싱 시작 위치(기본 0).

    Returns:
        :class:`GreHeader`. 버전이 0/1 이 아니거나 헤더가 잘리면 ``None``.
        캡슐 안쪽은 풀지 않고 ``payload_offset`` 만 노출한다.
    """
    if not isinstance(data, (bytes, bytearray)):
        return None
    if len(data) - offset < 4:
        return None

    flags0 = data[offset]
    flags1 = data[offset + 1]
    version = flags1 & _VERSION_MASK
    if version not in (0, 1):
        return None

    has_checksum = bool(flags0 & _F_CHECKSUM)
    has_routing = bool(flags0 & _F_ROUTING)
    has_key = bool(flags0 & _F_KEY)
    has_sequence = bool(flags0 & _F_SEQUENCE)
    has_ack = bool(flags1 & _F_ACK)

    proto = struct.unpack_from(">H", data, offset + 2)[0]

    # 버전1(PPTP): K 비트가 항상 켜지고 protocol 은 PPP(0x880B)여야 정상.
    # 비-GRE 오탐 가드 — 버전1 인데 PPP 가 아니면 거부.
    if version == 1 and proto != 0x880B:
        return None

    pos = offset + 4
    checksum: Optional[int] = None
    key: Optional[int] = None
    payload_length: Optional[int] = None
    call_id: Optional[int] = None
    sequence: Optional[int] = None
    ack: Optional[int] = None

    # Checksum(2)+Reserved1(2): C 비트 시(버전0 만; 버전1 엔 C 없음).
    if has_checksum:
        if len(data) - pos < 4:
            return None
        checksum = struct.unpack_from(">H", data, pos)[0]
        pos += 4

    # Key 필드(4): 버전0 은 32비트 Key, 버전1 은 Payload Length(2)+Call ID(2).
    if version == 1:
        # 버전1 은 K 비트와 무관하게 Key 필드(PayloadLen+CallID)를 항상 포함.
        if len(data) - pos < 4:
            return None
        payload_length, call_id = struct.unpack_from(">HH", data, pos)
        pos += 4
    elif has_key:
        if len(data) - pos < 4:
            return None
        key = struct.unpack_from(">I", data, pos)[0]
        pos += 4

    # Sequence Number(4): S 비트 시.
    if has_sequence:
        if len(data) - pos < 4:
            return None
        sequence = struct.unpack_from(">I", data, pos)[0]
        pos += 4

    # Acknowledgment Number(4): 버전1 A 비트 시.
    if has_ack:
        if len(data) - pos < 4:
            return None
        ack = struct.unpack_from(">I", data, pos)[0]
        pos += 4

    return GreHeader(
        version=version,
        protocol_type=proto,
        protocol=_protocol_name(proto),
        has_checksum=has_checksum,
        has_key=has_key,
        has_sequence=has_sequence,
        has_routing=has_routing,
        has_ack=has_ack,
        checksum=checksum,
        key=key,
        payload_length=payload_length,
        call_id=call_id,
        sequence=sequence,
        ack=ack,
        header_length=pos - offset,
        payload_offset=pos,
    )
