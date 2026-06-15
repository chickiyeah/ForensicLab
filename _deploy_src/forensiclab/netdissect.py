"""원시 패킷 바이트 → Ethernet/IPv4/TCP·UDP 헤더 해석 코어.

:mod:`forensiclab.pcap` 는 캡처 파일에서 패킷의 *원시 바이트* 만 꺼낸다.
이 모듈은 그 바이트(`Packet.data`)를 받아 링크(L2)·네트워크(L3)·전송(L4)
계층 헤더를 해석해, "누가 누구와 어떤 포트로 통신했는가" 를 구조화한다.
침해 분석에서 흐름(flow) 식별·스캔 탐지·통신 상대 파악의 기반이 된다.

지원 범위:
- L2: Ethernet II 프레임(목적/출발 MAC, ethertype). VLAN 802.1Q 태그
  (0x8100)는 한 겹 벗겨 안쪽 ethertype 을 따라간다.
- L3: IPv4 만(version==4). 옵션 포함 가변 IHL 을 존중. IPv6/ARP 는
  주소·ethertype 만 보고 L4 해석은 생략한다.
- L4: TCP·UDP 의 출발/목적 포트. 그 외 프로토콜은 포트 없이 둔다.

설계 원칙(:mod:`forensiclab.pcap`·:mod:`forensiclab.filetype` 와 동일):
- 부작용 없음: 디스크/표준출력 없이 순수 함수 (테스트 용이).
- stdlib 전용: 외부 의존성 없음.
- 안전: 입력 바이트를 변형하지 않는다(읽기 전용).
- 견고: 너무 짧아 해석 불가한 계층은 예외 대신 ``None`` 으로 둔다.
  (캡처는 snaplen 으로 흔히 잘리므로, 부분 해석이 정상 동작이다.)
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Optional

__all__ = [
    "ETHERTYPE_IPV4",
    "ETHERTYPE_IPV6",
    "ETHERTYPE_ARP",
    "ETHERTYPE_VLAN",
    "IP_PROTO_TCP",
    "IP_PROTO_UDP",
    "IP_PROTO_ICMP",
    "Ethernet",
    "IPv4",
    "Dissection",
    "format_mac",
    "format_ipv4",
    "dissect_ethernet",
    "dissect_ipv4",
    "dissect",
]

ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_IPV6 = 0x86DD
ETHERTYPE_ARP = 0x0806
ETHERTYPE_VLAN = 0x8100

IP_PROTO_ICMP = 1
IP_PROTO_TCP = 6
IP_PROTO_UDP = 17

_ETHER_HEADER_SIZE = 14
_VLAN_TAG_SIZE = 4
_IPV4_MIN_HEADER_SIZE = 20
_L4_PORTS_SIZE = 4  # TCP/UDP 모두 출발(2)+목적(2) 포트가 맨 앞.


def format_mac(raw: bytes) -> str:
    """6바이트 MAC 주소를 ``aa:bb:cc:dd:ee:ff`` 표기로 만든다."""
    return ":".join(f"{b:02x}" for b in raw)


def format_ipv4(raw: bytes) -> str:
    """4바이트 IPv4 주소를 점 구분 십진(``192.168.0.1``) 표기로 만든다."""
    return ".".join(str(b) for b in raw)


@dataclass(frozen=True)
class Ethernet:
    """Ethernet II 프레임 헤더.

    Attributes:
        dst_mac: 목적지 MAC(``aa:bb:cc:dd:ee:ff`` 표기).
        src_mac: 출발지 MAC.
        ethertype: 상위 계층 타입(VLAN 태그는 벗겨낸 뒤의 값).
        vlan_id: 802.1Q VLAN ID. 태그가 없으면 ``None``.
        payload_offset: ``data`` 기준 상위 계층(L3)이 시작되는 바이트 오프셋.
    """

    dst_mac: str
    src_mac: str
    ethertype: int
    vlan_id: Optional[int]
    payload_offset: int


@dataclass(frozen=True)
class IPv4:
    """IPv4 패킷 헤더(옵션 미해석).

    Attributes:
        src_ip: 출발지 IP(점 구분 십진).
        dst_ip: 목적지 IP.
        protocol: 상위 프로토콜 번호(6=TCP, 17=UDP, 1=ICMP …).
        ttl: Time To Live.
        total_length: IP 헤더+페이로드의 선언 길이(바이트).
        header_length: IP 헤더 길이(바이트, IHL*4).
        payload_offset: ``data`` 기준 L4 가 시작되는 바이트 오프셋.
    """

    src_ip: str
    dst_ip: str
    protocol: int
    ttl: int
    total_length: int
    header_length: int
    payload_offset: int


@dataclass(frozen=True)
class Dissection:
    """패킷 한 개의 계층별 해석 결과.

    해석 불가한 계층(너무 짧거나 미지원)은 해당 필드가 ``None`` 이다.

    Attributes:
        ethernet: L2 해석 결과(미지원 링크타입이면 ``None``).
        ipv4: L3 해석 결과(IPv4 아니거나 잘렸으면 ``None``).
        src_port: L4 출발 포트(TCP/UDP 만; 그 외 ``None``).
        dst_port: L4 목적 포트.
    """

    ethernet: Optional[Ethernet]
    ipv4: Optional[IPv4]
    src_port: Optional[int]
    dst_port: Optional[int]

    @property
    def protocol_name(self) -> str:
        """전송 계층 프로토콜의 짧은 이름(``"TCP"``/``"UDP"``/``"ICMP"``/숫자)."""
        if self.ipv4 is None:
            return "?"
        return {
            IP_PROTO_TCP: "TCP",
            IP_PROTO_UDP: "UDP",
            IP_PROTO_ICMP: "ICMP",
        }.get(self.ipv4.protocol, str(self.ipv4.protocol))


def dissect_ethernet(data: bytes) -> Optional[Ethernet]:
    """Ethernet II 프레임 헤더를 해석한다(VLAN 한 겹 제거).

    Args:
        data: 프레임 맨 앞부터의 원시 바이트.

    Returns:
        :class:`Ethernet`. 14바이트(또는 VLAN 포함 18바이트)에 못 미치면 ``None``.
    """
    if len(data) < _ETHER_HEADER_SIZE:
        return None
    dst = data[0:6]
    src = data[6:12]
    ethertype = struct.unpack(">H", data[12:14])[0]
    offset = _ETHER_HEADER_SIZE
    vlan_id: Optional[int] = None
    if ethertype == ETHERTYPE_VLAN:
        if len(data) < _ETHER_HEADER_SIZE + _VLAN_TAG_SIZE:
            return None
        tci, inner = struct.unpack(">HH", data[14:18])
        vlan_id = tci & 0x0FFF
        ethertype = inner
        offset += _VLAN_TAG_SIZE
    return Ethernet(
        dst_mac=format_mac(dst),
        src_mac=format_mac(src),
        ethertype=ethertype,
        vlan_id=vlan_id,
        payload_offset=offset,
    )


def dissect_ipv4(data: bytes, offset: int = 0) -> Optional[IPv4]:
    """IPv4 헤더를 해석한다(옵션은 길이만 반영, 내용 미해석).

    Args:
        data: 패킷 원시 바이트.
        offset: ``data`` 안에서 IPv4 헤더가 시작되는 위치.

    Returns:
        :class:`IPv4`. IPv4 가 아니거나(버전≠4) 헤더가 잘렸으면 ``None``.
    """
    if len(data) - offset < _IPV4_MIN_HEADER_SIZE:
        return None
    ver_ihl = data[offset]
    version = ver_ihl >> 4
    if version != 4:
        return None
    ihl_words = ver_ihl & 0x0F
    header_length = ihl_words * 4
    if header_length < _IPV4_MIN_HEADER_SIZE or len(data) - offset < header_length:
        return None
    total_length = struct.unpack(">H", data[offset + 2:offset + 4])[0]
    ttl = data[offset + 8]
    protocol = data[offset + 9]
    src = data[offset + 12:offset + 16]
    dst = data[offset + 16:offset + 20]
    return IPv4(
        src_ip=format_ipv4(src),
        dst_ip=format_ipv4(dst),
        protocol=protocol,
        ttl=ttl,
        total_length=total_length,
        header_length=header_length,
        payload_offset=offset + header_length,
    )


def dissect(data: bytes, linktype: int = 1) -> Dissection:
    """원시 패킷 바이트를 L2~L4 로 해석한다.

    Args:
        data: 패킷 원시 바이트(:attr:`forensiclab.pcap.Packet.data`).
        linktype: libpcap 링크타입. 1=Ethernet(기본), 101=Raw IP(L2 없음).
            그 외 값은 L2/L3 모두 해석하지 않는다.

    Returns:
        :class:`Dissection`. 해석 못 한 계층은 ``None`` 으로 둔다(예외 없음).
    """
    ethernet: Optional[Ethernet] = None
    if linktype == 101:  # LINKTYPE_RAW: L2 없이 곧장 IP.
        ip_offset = 0
    elif linktype == 1:  # LINKTYPE_ETHERNET.
        ethernet = dissect_ethernet(data)
        if ethernet is None:
            return Dissection(None, None, None, None)
        if ethernet.ethertype != ETHERTYPE_IPV4:
            return Dissection(ethernet, None, None, None)
        ip_offset = ethernet.payload_offset
    else:
        return Dissection(None, None, None, None)

    ipv4 = dissect_ipv4(data, ip_offset)
    if ipv4 is None:
        return Dissection(ethernet, None, None, None)

    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    if ipv4.protocol in (IP_PROTO_TCP, IP_PROTO_UDP):
        l4 = ipv4.payload_offset
        if len(data) - l4 >= _L4_PORTS_SIZE:
            src_port, dst_port = struct.unpack(">HH", data[l4:l4 + _L4_PORTS_SIZE])
    return Dissection(ethernet, ipv4, src_port, dst_port)
