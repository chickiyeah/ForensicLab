"""ARP — 주소 결정 프로토콜 파싱 코어 (RFC 826).

:mod:`forensiclab.netdissect` 는 Ethernet 프레임의 ethertype 이 ARP(0x0806)
임을 *식별만* 하고(L3 가 IPv4 가 아니므로) 그 본문은 건드리지 않는다.
이 모듈이 그 본문 — ARP 패킷 — 을 해석한다.

ARP 는 침해 분석에서 **ARP 스푸핑/중간자(MITM)** 단서로 쓸모 있다:

- 한 IP(sender protocol address)가 짧은 시간에 *서로 다른* MAC(sender
  hardware address)으로 광고되면 ARP 캐시 포이즈닝 정황이다.
- gratuitous ARP(sender 와 target 의 프로토콜 주소가 같은 광고)는 정상적인
  주소 충돌 알림에도 쓰이지만, 게이트웨이 IP 에 대해 공격자 MAC 으로 반복되면
  MITM 신호다.
- 응답(reply)이 대응하는 요청(request) 없이 쏟아지면(unsolicited reply)
  포이즈닝을 의심한다 — 이 모듈은 단건 파싱만 하고, 상관관계 판단은 호출자가
  여러 :class:`Arp` 를 모아 수행한다.

ARP 패킷 형식(RFC 826)::

    uint16   htype   하드웨어 타입 (1 = Ethernet)
    uint16   ptype   프로토콜 타입 (0x0800 = IPv4)
    byte     hlen    하드웨어 주소 길이 (Ethernet = 6)
    byte     plen    프로토콜 주소 길이 (IPv4 = 4)
    uint16   oper    동작 (1 = request, 2 = reply)
    byte[hlen]  sha  sender hardware address
    byte[plen]  spa  sender protocol address
    byte[hlen]  tha  target hardware address
    byte[plen]  tpa  target protocol address

주소 길이를 ``hlen``/``plen`` 으로 일반화해 파싱하므로 비-Ethernet/비-IPv4
조합도 원시 바이트로 보존한다. Ethernet+IPv4(가장 흔한 조합)일 때
:attr:`Arp.sender_mac`/:attr:`Arp.sender_ip` 등으로 사람이 읽는 문자열을 준다.

설계 원칙(:mod:`forensiclab.netdissect`·:mod:`forensiclab.icmp` 와 동일):
- 부작용 없음: 순수 함수. 디스크/표준출력/네트워크 없음.
- stdlib 전용.
- 안전: 입력 바이트를 변형하지 않는다(읽기 전용).
- 견고: 너무 짧거나 망가진 입력은 예외 대신 ``None``.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Optional

__all__ = [
    "ARP_REQUEST",
    "ARP_REPLY",
    "HTYPE_ETHERNET",
    "PTYPE_IPV4",
    "Arp",
    "parse_arp",
    "format_mac",
    "format_ipv4",
]

ARP_REQUEST = 1
ARP_REPLY = 2

HTYPE_ETHERNET = 1
PTYPE_IPV4 = 0x0800

_ARP_FIXED_SIZE = 8  # htype(2)+ptype(2)+hlen(1)+plen(1)+oper(2).

_OPER_NAMES = {
    1: "request",
    2: "reply",
    3: "rarp-request",
    4: "rarp-reply",
}


def format_mac(raw: bytes) -> str:
    """6바이트 MAC 을 ``aa:bb:cc:dd:ee:ff`` 문자열로 (그 외 길이는 hex)."""
    return ":".join(f"{b:02x}" for b in raw)


def format_ipv4(raw: bytes) -> str:
    """4바이트 IPv4 주소를 점표기 문자열로 (그 외 길이는 hex)."""
    if len(raw) == 4:
        return ".".join(str(b) for b in raw)
    return raw.hex()


@dataclass(frozen=True)
class Arp:
    """파싱된 ARP 패킷.

    Attributes:
        htype: 하드웨어 타입(1 = Ethernet).
        ptype: 프로토콜 타입(0x0800 = IPv4).
        hlen: 하드웨어 주소 바이트 길이.
        plen: 프로토콜 주소 바이트 길이.
        oper: 동작(1 = request, 2 = reply).
        sha: sender hardware address 원본 바이트.
        spa: sender protocol address 원본 바이트.
        tha: target hardware address 원본 바이트.
        tpa: target protocol address 원본 바이트.
    """

    htype: int
    ptype: int
    hlen: int
    plen: int
    oper: int
    sha: bytes
    spa: bytes
    tha: bytes
    tpa: bytes

    @property
    def oper_name(self) -> str:
        """동작의 짧은 이름(미상이면 ``"oper-<n>"``)."""
        return _OPER_NAMES.get(self.oper, f"oper-{self.oper}")

    @property
    def is_ethernet_ipv4(self) -> bool:
        """Ethernet(htype 1, hlen 6) + IPv4(ptype 0x0800, plen 4) 조합인가."""
        return (
            self.htype == HTYPE_ETHERNET
            and self.ptype == PTYPE_IPV4
            and self.hlen == 6
            and self.plen == 4
        )

    @property
    def sender_mac(self) -> str:
        """sender hardware address 의 사람이 읽는 표현."""
        return format_mac(self.sha)

    @property
    def sender_ip(self) -> str:
        """sender protocol address 의 사람이 읽는 표현."""
        return format_ipv4(self.spa)

    @property
    def target_mac(self) -> str:
        """target hardware address 의 사람이 읽는 표현."""
        return format_mac(self.tha)

    @property
    def target_ip(self) -> str:
        """target protocol address 의 사람이 읽는 표현."""
        return format_ipv4(self.tpa)

    @property
    def is_gratuitous(self) -> bool:
        """gratuitous ARP 인가 — sender 와 target 의 프로토콜 주소가 같은가.

        주소 충돌 알림에 정상적으로 쓰이지만, 게이트웨이 IP 에 대해 반복되면
        MITM 신호이므로 상관 분석의 1차 필터로 쓴다.
        """
        return self.spa == self.tpa


def parse_arp(data: bytes, offset: int = 0) -> Optional[Arp]:
    """원시 바이트에서 ARP 패킷을 파싱한다.

    Args:
        data: ARP 패킷을 담은 바이트. 보통 :class:`forensiclab.netdissect.Ethernet`
            의 ``payload_offset`` 부터다.
        offset: ARP 패킷이 시작하는 위치(기본 0).

    Returns:
        :class:`Arp`. 고정 헤더(8바이트)나 주소 4쌍에 못 미치게 짧으면 ``None``.
    """
    if offset < 0 or offset + _ARP_FIXED_SIZE > len(data):
        return None
    htype, ptype, hlen, plen, oper = struct.unpack(
        ">HHBBH", data[offset:offset + _ARP_FIXED_SIZE]
    )
    pos = offset + _ARP_FIXED_SIZE
    need = 2 * hlen + 2 * plen
    if pos + need > len(data):
        return None
    sha = data[pos:pos + hlen]
    pos += hlen
    spa = data[pos:pos + plen]
    pos += plen
    tha = data[pos:pos + hlen]
    pos += hlen
    tpa = data[pos:pos + plen]
    return Arp(
        htype=htype,
        ptype=ptype,
        hlen=hlen,
        plen=plen,
        oper=oper,
        sha=sha,
        spa=spa,
        tha=tha,
        tpa=tpa,
    )
