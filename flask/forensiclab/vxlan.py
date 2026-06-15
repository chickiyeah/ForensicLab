"""VXLAN(Virtual eXtensible LAN) 오버레이 터널 헤더 파싱 코어 (RFC 7348·RFC 8926).

:mod:`forensiclab.netdissect` 가 식별한 **UDP 페이로드**(관용 목적지 포트 4789,
구현에 따라 8472) 위에서, 이더넷 프레임 하나를 통째로 UDP/IP 안에 감싸 나르는
**L2-over-L3 오버레이 터널** 헤더다. :mod:`forensiclab.gre` 의 NVGRE(0x6558
Transparent Ethernet Bridging)가 IP 프로토콜 47 위에서 같은 일을 한다면, VXLAN 은
**UDP 위**에서 처리해 포트 기반 장비를 그대로 통과한다 — 헤더가 평문이라 어느
세그먼트(``vni``)를 어떤 종류로(VXLAN-GPE ``next_protocol``) 잇는지 그대로 드러낸다.

침해/사고 분석에서 VXLAN 이 드러내는 것:

- **은닉 L2 브리지·세그먼트 경계 우회**: VXLAN 은 L3 경계를 넘어 멀리 떨어진 두
  L2 세그먼트를 잇는다. 비인가 VXLAN 종단(VTEP)이 보이면, 라우팅·방화벽으로
  분리해 둔 망을 평범한 UDP 4789 트래픽처럼 위장해 **이더넷 수준에서 통째로
  연결**하는 정황 — 내부 프레임(:attr:`payload_offset`)을 다시 해석하면 그 안의
  ARP·내부 IP·평문 프로토콜이 그대로 드러난다.
- **세그먼트 귀속(VNI)**: 24비트 **VNI**(VXLAN Network Identifier, ``vni``)는 어느
  가상 L2 세그먼트(테넌트)인지 못 박는 식별자 — :mod:`forensiclab.flows` 의 같은
  UDP 흐름 안에서도 VNI 로 어떤 오버레이가 흐르는지 구분·상관한다(NVGRE 의
  ``key``·VSID 대응).
- **VXLAN-GPE — 임의 프로토콜 직접 운반**: P 비트가 켜지면(RFC 8926, ``is_gpe``)
  내부가 이더넷이 아니라 **IPv4/IPv6/NSH/MPLS 를 직접** 실을 수 있다
  (``next_protocol``). 표준 VXLAN(이더넷만) 대비 더 유연한 캡슐 — IP-in-UDP
  은닉 터널·서비스 체이닝(NSH) 정황.
- **터널 종단 식별**: UDP/IP 바깥 헤더의 출발/목적 IP 가 곧 VTEP 쌍 —
  :mod:`forensiclab.netdissect`/:mod:`forensiclab.flows` 와 묶어 어느 호스트가
  오버레이를 종단하는지(누가 브리지를 거는지) 확정.

와이어 포맷 — VXLAN 헤더(고정 8바이트): Flags(1)·Reserved(3)·VNI(3)·Reserved(1).
표준 VXLAN 은 Flags 의 **I 비트(0x08)** 만 켜지고 나머지는 0. VXLAN-GPE 는 추가로
**P 비트(0x04)** 를 켜고 마지막 Reserved 자리에 Next Protocol 1바이트를 둔다.
헤더 뒤는 표준이면 내부 **이더넷 프레임**, GPE 면 ``next_protocol`` 이 가리키는
프로토콜이 시작된다(여기서는 풀지 않고 ``payload_offset`` 만 노출).

설계 원칙(다른 파서와 동일):
- 부작용 없음·stdlib 전용·읽기 전용.
- 견고: I 비트가 없거나 헤더가 8바이트 미만이면 예외 대신 ``None``.
- 캡슐 **안쪽**(이너 이더넷/IP)은 풀지 않고 시작 오프셋(``payload_offset``)만
  노출한다(다시 :mod:`forensiclab.netdissect` 로 넘겨 재귀 해석할 수 있게).
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Optional

__all__ = [
    "VXLAN_PORTS",
    "VXLAN_GPE_PROTOCOLS",
    "VxlanHeader",
    "looks_like_vxlan",
    "parse_vxlan",
]

# 관용 UDP 목적지 포트(IANA 4789 표준·Linux 초기 구현 8472).
VXLAN_PORTS = (4789, 8472)

# VXLAN-GPE Next Protocol(RFC 8926 §3.2).
VXLAN_GPE_PROTOCOLS = {
    1: "IPv4",
    2: "IPv6",
    3: "Ethernet",
    4: "NSH",       # Network Service Header(서비스 체이닝)
    5: "MPLS",
}

# Flags byte(상위→하위 비트): R R R I  P B O R  (RFC 7348/8926).
_F_VNI = 0x08       # I: VNI 유효(표준 VXLAN 필수).
_F_NEXT_PROTO = 0x04  # P: Next Protocol 존재(VXLAN-GPE).
_F_BUM = 0x02       # B: BUM(Broadcast/Unknown unicast/Multicast) 트래픽(GPE).
_F_OAM = 0x01       # O: OAM 패킷(GPE; 데이터 아님).

_HEADER_LEN = 8


@dataclass(frozen=True)
class VxlanHeader:
    """파싱된 VXLAN 오버레이 터널 헤더 한 개.

    Attributes:
        vni: 24비트 VXLAN Network Identifier(가상 L2 세그먼트/테넌트 식별).
        flags: Flags 바이트 원본.
        valid_vni: I 비트(0x08) — VNI 유효(표준 VXLAN 필수).
        is_gpe: P 비트(0x04) — VXLAN-GPE(임의 프로토콜 운반).
        is_bum: B 비트(0x02) — BUM 트래픽(GPE).
        is_oam: O 비트(0x01) — OAM 제어 패킷(GPE; 데이터 아님).
        next_protocol: VXLAN-GPE Next Protocol 코드(GPE 아니면 None).
        next_protocol_name: ``next_protocol`` 이름(미지정은 ``"0x.."``, 비-GPE None).
        header_length: VXLAN 헤더 길이(항상 8).
        payload_offset: 캡슐 안쪽(이너 이더넷/IP) 시작 오프셋(``data`` 기준).
    """

    vni: int = 0
    flags: int = 0
    valid_vni: bool = False
    is_gpe: bool = False
    is_bum: bool = False
    is_oam: bool = False
    next_protocol: Optional[int] = None
    next_protocol_name: Optional[str] = None
    header_length: int = _HEADER_LEN
    payload_offset: int = _HEADER_LEN

    @property
    def carries_ethernet(self) -> bool:
        """캡슐 안이 이더넷 프레임인지(표준 VXLAN 또는 GPE NP=3)."""
        return not self.is_gpe or self.next_protocol == 3

    @property
    def carries_ipv4(self) -> bool:
        """캡슐 안이 IPv4 인지(GPE NP=1) — IP-in-UDP 은닉 터널 정황."""
        return self.is_gpe and self.next_protocol == 1

    @property
    def carries_ipv6(self) -> bool:
        """캡슐 안이 IPv6 인지(GPE NP=2)."""
        return self.is_gpe and self.next_protocol == 2


def looks_like_vxlan(data: bytes, offset: int = 0) -> bool:
    """``offset`` 바이트가 파싱 가능한 VXLAN 헤더처럼 보이는지(가벼운 가드)."""
    return parse_vxlan(data, offset) is not None


def parse_vxlan(data: bytes, offset: int = 0) -> Optional[VxlanHeader]:
    """단일 VXLAN 오버레이 터널 헤더를 파싱한다.

    Args:
        data: VXLAN 바이트(보통 UDP 4789 페이로드).
        offset: 파싱 시작 위치(기본 0).

    Returns:
        :class:`VxlanHeader`. I 비트(VNI 유효)가 없거나 헤더가 8바이트 미만이면
        ``None``. 캡슐 안쪽은 풀지 않고 ``payload_offset`` 만 노출한다.
    """
    if not isinstance(data, (bytes, bytearray)):
        return None
    if len(data) - offset < _HEADER_LEN:
        return None

    flags = data[offset]
    # I 비트가 없으면 VXLAN 으로 보지 않음(비-VXLAN 오탐 1차 가드).
    if not (flags & _F_VNI):
        return None

    is_gpe = bool(flags & _F_NEXT_PROTO)
    is_bum = bool(flags & _F_BUM)
    is_oam = bool(flags & _F_OAM)

    # bytes 1-3: Reserved(표준), 또는 GPE 의 Version(2비트)·예약.
    # bytes 4-6: VNI(24비트), byte 7: Reserved 또는 GPE Next Protocol.
    vni = (data[offset + 4] << 16) | (data[offset + 5] << 8) | data[offset + 6]

    next_protocol: Optional[int] = None
    next_protocol_name: Optional[str] = None
    if is_gpe:
        next_protocol = data[offset + 7]
        next_protocol_name = VXLAN_GPE_PROTOCOLS.get(
            next_protocol, f"0x{next_protocol:02x}"
        )
    else:
        # 표준 VXLAN 은 마지막 바이트가 Reserved(0) — 0 이 아니면 비-VXLAN 가드.
        if data[offset + 7] != 0:
            return None

    return VxlanHeader(
        vni=vni,
        flags=flags,
        valid_vni=True,
        is_gpe=is_gpe,
        is_bum=is_bum,
        is_oam=is_oam,
        next_protocol=next_protocol,
        next_protocol_name=next_protocol_name,
        header_length=_HEADER_LEN,
        payload_offset=offset + _HEADER_LEN,
    )
