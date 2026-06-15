"""GENEVE(Generic Network Virtualization Encapsulation) 오버레이 터널 헤더 파싱 코어 (RFC 8926).

:mod:`forensiclab.netdissect` 가 식별한 **UDP 페이로드**(관용 목적지 포트 6081) 위에서,
프레임 하나를 통째로 UDP/IP 안에 감싸 나르는 **L2/L3-over-L3 오버레이 터널** 헤더다.
:mod:`forensiclab.vxlan`(UDP 4789, 고정 8바이트)·:mod:`forensiclab.gre` 의 NVGRE(IP
프로토콜 47)와 **같은 가상화 캡슐 형제**이지만, GENEVE 는 둘의 한계를 풀려고 설계된
**확장형** 캡슐 — VXLAN 이 고정 8바이트라 메타데이터를 못 싣는 데 반해 GENEVE 는
가변 길이 **TLV 옵션**을 헤더에 달 수 있고, VXLAN(표준)이 내부를 항상 이더넷으로
가정하는 것과 달리 **Protocol Type** 필드로 내부 종류(이더넷/IPv4/IPv6)를 직접
명시한다(VMware NSX-T 의 기본 오버레이).

침해/사고 분석에서 GENEVE 가 드러내는 것:

- **은닉 L2/L3 브리지·세그먼트 경계 우회**: GENEVE 는 L3 경계를 넘어 떨어진 두
  세그먼트를 잇는다. 비인가 종단(VTEP)이 보이면, 라우팅·방화벽으로 분리해 둔 망을
  평범한 UDP 6081 트래픽처럼 위장해 **통째로 연결**하는 정황 — 내부 프레임
  (:attr:`payload_offset`)을 다시 해석하면 그 안의 ARP·내부 IP·평문 프로토콜이
  그대로 드러난다(:mod:`forensiclab.vxlan` 와 동일한 표면, 다른 포트·포맷).
- **세그먼트 귀속(VNI)**: 24비트 **VNI**(Virtual Network Identifier, ``vni``)는 어느
  가상 네트워크(테넌트)인지 못 박는 식별자 — :mod:`forensiclab.flows` 의 같은 UDP
  흐름 안에서도 VNI 로 어떤 오버레이가 흐르는지 구분·상관한다(VXLAN ``vni``·NVGRE
  ``key`` 대응).
- **내부 종류 직접 노출(Protocol Type)**: ``protocol_type`` 은 캡슐 안 프레임의
  ethertype — 0x6558(Transparent Ethernet Bridging)=이더넷, 0x0800=IPv4,
  0x86DD=IPv6. VXLAN 표준이 항상 이더넷을 가정하던 것과 달리 **IP-in-UDP 은닉
  터널**(``carries_ipv4``/``carries_ipv6``) 정황을 헤더만으로 식별.
- **TLV 옵션 — 메타데이터·은닉 채널**: GENEVE 의 차별점인 가변 옵션은
  ``option_class``(벤더/표준 네임스페이스)+``type``+데이터의 묶음 — NSX 등은 여기에
  논리 포트·보안 그룹 같은 메타데이터를 싣는다. **Critical 비트(C)** 가 켜졌는데
  종단이 모르는 옵션이면 패킷을 버려야 하므로, 알 수 없는 critical 옵션
  (``has_critical_option``)은 비표준 구현·은닉 채널·메타데이터 주입 정황.
- **터널 종단 식별**: UDP/IP 바깥 헤더의 출발/목적 IP 가 곧 VTEP 쌍 —
  :mod:`forensiclab.netdissect`/:mod:`forensiclab.flows` 와 묶어 어느 호스트가
  오버레이를 종단하는지(누가 브리지를 거는지) 확정.

와이어 포맷 — GENEVE 기본 헤더(8바이트): Ver(2비트)·Opt Len(6비트, 4바이트 단위)·
O(OAM)·C(Critical 옵션 존재)·Rsvd(6비트)·Protocol Type(2바이트)·VNI(24비트)·
Reserved(1바이트). 그 뒤로 Opt Len×4 바이트만큼 옵션 TLV 가 이어진다(각 옵션:
Option Class(2)·Type(1, 최상위=critical)·R(3비트)+Length(5비트, 4바이트 단위 데이터)).
옵션 뒤가 내부 프레임 시작이다(여기서는 풀지 않고 ``payload_offset`` 만 노출).

설계 원칙(다른 파서와 동일):
- 부작용 없음·stdlib 전용·읽기 전용.
- 견고: 버전이 0 이 아니거나 헤더/옵션이 잘리면 예외 대신 ``None``.
- 캡슐 **안쪽**(이너 이더넷/IP)은 풀지 않고 시작 오프셋(``payload_offset``)만
  노출한다(다시 :mod:`forensiclab.netdissect` 로 넘겨 재귀 해석할 수 있게).
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import List, Optional, Tuple

__all__ = [
    "GENEVE_PORT",
    "GENEVE_PROTOCOLS",
    "GeneveOption",
    "GeneveHeader",
    "looks_like_geneve",
    "parse_geneve",
]

# 관용 UDP 목적지 포트(IANA 6081).
GENEVE_PORT = 6081

# Protocol Type — 캡슐 안 프레임의 ethertype(RFC 8926 §3.2).
GENEVE_PROTOCOLS = {
    0x6558: "Ethernet",  # Transparent Ethernet Bridging(표준 L2 오버레이).
    0x0800: "IPv4",
    0x86DD: "IPv6",
}

_F_OAM = 0x80       # 둘째 바이트 상위 비트 O: OAM 패킷(데이터 아님).
_F_CRITICAL = 0x40  # 둘째 바이트 C: critical 옵션 존재.
_OPT_CRITICAL = 0x80  # 옵션 Type 최상위 비트: 이 옵션 자체가 critical.

_BASE_LEN = 8
_OPT_HDR_LEN = 4


@dataclass(frozen=True)
class GeneveOption:
    """GENEVE 가변 길이 옵션(TLV) 한 개.

    Attributes:
        option_class: 16비트 Option Class(IANA 벤더/표준 네임스페이스).
        option_type: 8비트 Type(최상위 비트는 critical 표시).
        is_critical: Type 최상위 비트 — 종단이 모르면 패킷을 버려야 하는 옵션.
        length: 옵션 데이터 길이(바이트; Length 필드×4).
        data: 옵션 데이터 원본 바이트(미해석).
    """

    option_class: int
    option_type: int
    is_critical: bool
    length: int
    data: bytes


@dataclass(frozen=True)
class GeneveHeader:
    """파싱된 GENEVE 오버레이 터널 헤더 한 개.

    Attributes:
        vni: 24비트 Virtual Network Identifier(가상 네트워크/테넌트 식별).
        version: Ver 필드(현재 0 만 정의).
        protocol_type: 캡슐 안 프레임 ethertype(0x6558=이더넷 등).
        protocol_name: ``protocol_type`` 이름(미지정은 ``"0x...."``).
        is_oam: O 비트 — OAM 제어 패킷(데이터 아님).
        is_critical: C 비트 — critical 옵션이 헤더에 존재함을 표시.
        opt_len: 옵션 전체 길이(바이트; Opt Len 필드×4).
        options: 파싱된 :class:`GeneveOption` 튜플.
        header_length: GENEVE 헤더 길이(8 + opt_len).
        payload_offset: 캡슐 안쪽(이너 이더넷/IP) 시작 오프셋(``data`` 기준).
    """

    vni: int = 0
    version: int = 0
    protocol_type: int = 0
    protocol_name: Optional[str] = None
    is_oam: bool = False
    is_critical: bool = False
    opt_len: int = 0
    options: Tuple[GeneveOption, ...] = ()
    header_length: int = _BASE_LEN
    payload_offset: int = _BASE_LEN

    @property
    def carries_ethernet(self) -> bool:
        """캡슐 안이 이더넷 프레임인지(Protocol Type=0x6558 TEB)."""
        return self.protocol_type == 0x6558

    @property
    def carries_ipv4(self) -> bool:
        """캡슐 안이 IPv4 인지(0x0800) — IP-in-UDP 은닉 터널 정황."""
        return self.protocol_type == 0x0800

    @property
    def carries_ipv6(self) -> bool:
        """캡슐 안이 IPv6 인지(0x86DD)."""
        return self.protocol_type == 0x86DD

    @property
    def has_critical_option(self) -> bool:
        """critical 비트가 켜진 옵션이 하나라도 있는지(비표준·은닉 채널 정황)."""
        return any(opt.is_critical for opt in self.options)


def looks_like_geneve(data: bytes, offset: int = 0) -> bool:
    """``offset`` 바이트가 파싱 가능한 GENEVE 헤더처럼 보이는지(가벼운 가드)."""
    return parse_geneve(data, offset) is not None


def parse_geneve(data: bytes, offset: int = 0) -> Optional[GeneveHeader]:
    """단일 GENEVE 오버레이 터널 헤더(+옵션 TLV)를 파싱한다.

    Args:
        data: GENEVE 바이트(보통 UDP 6081 페이로드).
        offset: 파싱 시작 위치(기본 0).

    Returns:
        :class:`GeneveHeader`. 버전이 0 이 아니거나 기본 헤더/옵션이 잘렸으면
        ``None``. 캡슐 안쪽은 풀지 않고 ``payload_offset`` 만 노출한다.
    """
    if not isinstance(data, (bytes, bytearray)):
        return None
    if len(data) - offset < _BASE_LEN:
        return None

    ver_optlen = data[offset]
    version = ver_optlen >> 6
    # 현재 버전 0 만 정의 — 비-GENEVE 오탐 1차 가드.
    if version != 0:
        return None
    opt_len = (ver_optlen & 0x3F) * 4

    flags = data[offset + 1]
    is_oam = bool(flags & _F_OAM)
    is_critical = bool(flags & _F_CRITICAL)

    protocol_type = struct.unpack(">H", data[offset + 2:offset + 4])[0]
    protocol_name = GENEVE_PROTOCOLS.get(protocol_type, f"0x{protocol_type:04x}")

    # bytes 4-6: VNI(24비트), byte 7: Reserved.
    vni = (data[offset + 4] << 16) | (data[offset + 5] << 8) | data[offset + 6]

    # 옵션 영역이 버퍼를 넘으면 잘린 캡처 — 비-GENEVE 오탐 가드로 거부.
    opt_start = offset + _BASE_LEN
    if len(data) - opt_start < opt_len:
        return None

    options = _parse_options(data, opt_start, opt_len)

    return GeneveHeader(
        vni=vni,
        version=version,
        protocol_type=protocol_type,
        protocol_name=protocol_name,
        is_oam=is_oam,
        is_critical=is_critical,
        opt_len=opt_len,
        options=tuple(options),
        header_length=_BASE_LEN + opt_len,
        payload_offset=opt_start + opt_len,
    )


def _parse_options(data: bytes, start: int, opt_len: int) -> List[GeneveOption]:
    """옵션 영역(``start`` 부터 ``opt_len`` 바이트)을 TLV 로 순회한다.

    각 옵션은 4바이트 헤더(Class 2·Type 1·R+Length 1) + 데이터(Length×4).
    잘리거나 길이가 영역을 넘으면 거기서 멈춰 읽은 데까지만 반환한다.
    """
    options: List[GeneveOption] = []
    pos = start
    end = start + opt_len
    while pos + _OPT_HDR_LEN <= end:
        option_class = struct.unpack(">H", data[pos:pos + 2])[0]
        option_type = data[pos + 2]
        length = (data[pos + 3] & 0x1F) * 4  # 하위 5비트, 4바이트 단위.
        body = pos + _OPT_HDR_LEN
        if body + length > end:
            break  # 데이터가 옵션 영역을 넘음 — 잘린 것으로 보고 중단.
        options.append(
            GeneveOption(
                option_class=option_class,
                option_type=option_type,
                is_critical=bool(option_type & _OPT_CRITICAL),
                length=length,
                data=bytes(data[body:body + length]),
            )
        )
        pos = body + length
    return options
