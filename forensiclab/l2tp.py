"""L2TP(Layer 2 Tunneling Protocol) 헤더 파싱 코어 (RFC 2661, L2TPv2; UDP 1701).

:mod:`forensiclab.ike` 가 IPsec VPN 키 협상 손잡이, :mod:`forensiclab.esp` 가 그
협상 산물(SA)로 암호화된 데이터 평면이었다면, L2TP 는 그 둘과 **한 묶음으로 흔히
배치되는** 또 다른 터널 운반층이다 — Windows·iOS 기본 VPN 으로 잘 알려진
"L2TP/IPsec" 구성이 바로 그 조합이다. L2TP 자체는 **암호화를 전혀 제공하지 않고**
(RFC 2661 §9.4) PPP 프레임을 UDP 1701 위로 나르기만 한다; 기밀성은 전적으로 바깥을
감싸는 IPsec ESP(:mod:`forensiclab.esp`)에 의존한다. 그래서 ESP 로 감싸이지 않은
**평문 L2TP 가 1701 에 그대로 보이면** 그 VPN 은 보호되지 않은 것 — 안의 PPP·CHAP
핸드셰이크·자격증명이 그대로 캡처된다는 직접 증거다.

L2TP 헤더에서 평문으로 읽을 수 있는 것은 메시지 종류(제어/데이터)와 터널/세션
식별자·제어 채널 시퀀스다. 데이터 메시지의 페이로드는 PPP 프레임, 제어 메시지의
본문은 AVP(Attribute-Value Pair) 목록이지만 본 파서는 헤더만 풀고 시작 오프셋
(``payload_offset``)만 노출한다.

침해/사고 분석에서 L2TP 가 드러내는 것:

- **보호되지 않은 VPN(평문 L2TP)**: L2TP 는 스스로 암호화하지 않는다 — 정상 배치는
  바깥을 ESP 가 감싸 1701 이 보이지 않아야 한다. 캡처에 ``ESP``(:mod:`forensiclab.esp`)
  없이 **평문 L2TP 가 그대로 보이면** IPsec 이 빠진 설정 오류·다운그레이드 — 안의
  PPP 인증(PAP 평문/CHAP 챌린지)이 오프라인 크래킹에 노출된다.
- **제어 평면 vs 데이터 평면(T 비트)**: 제어 메시지(``is_control``, T=1; SCCRQ/SCCRP/
  ICRQ/ICRP 등 터널·세션 협상)는 본문이 AVP 라 호스트명·벤더·인증이 평문으로 흐르고,
  데이터 메시지(``is_data``, T=0)는 PPP 프레임을 나른다 — 협상(제어)과 실제 전송
  (데이터)을 갈라 본다.
- **터널·세션 귀속(Tunnel/Session ID)**: 16비트 ``tunnel_id``·``session_id`` 로
  :mod:`forensiclab.flows` 의 같은 IP 쌍 안에서도 어느 터널·어느 세션인지 못 박는다 —
  한 터널 안 다중 세션(여러 PPP 연결)을 분리하고, ``tunnel_id==0``(``is_setup``)은
  아직 터널 ID 가 배정되기 전 최초 협상(SCCRQ) 시점.
- **제어 채널 진행·재전송(Ns/Nr)**: 제어 메시지의 16비트 ``ns``(이 메시지 시퀀스)·
  ``nr``(다음 기대 시퀀스)로 신뢰 전송 진행을 추적 — 같은 Ns 재출현은 재전송(손실·
  불안정), Nr 점프는 손실 정황.

와이어 포맷 — L2TPv2 헤더(가변): Flags+Version(16비트; T·L·S·O·P 비트와 하위
4비트 Version=2), 이어 L 비트면 Length(16), Tunnel ID(16), Session ID(16),
S 비트면 Ns(16)·Nr(16), O 비트면 Offset Size(16)+Offset Pad(가변).

설계 원칙(다른 파서와 동일):
- 부작용 없음·stdlib 전용·읽기 전용.
- 견고: Version 이 2 가 아니거나, 제어 메시지인데 L/S 비트가 빠졌거나(RFC 2661 §3.1
  은 제어에 L=S=1 강제), 헤더가 잘리면 예외 대신 ``None``.
- 페이로드(PPP/AVP)는 풀지 않고 ``payload_offset`` 만 노출한다.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Optional

__all__ = [
    "L2TP_PORT",
    "L2TP_VERSION",
    "L2tpHeader",
    "looks_like_l2tp",
    "parse_l2tp",
]

# L2TP 는 UDP 1701(IANA). L2TPv2 의 Version 필드는 항상 2.
L2TP_PORT = 1701
L2TP_VERSION = 2

# Flags+Version 워드(상위 바이트)의 비트 마스크.
_T_BIT = 0x8000  # Type: 0=data, 1=control
_L_BIT = 0x4000  # Length 필드 존재
_S_BIT = 0x0800  # Ns/Nr 시퀀스 필드 존재
_O_BIT = 0x0200  # Offset Size 필드 존재
_P_BIT = 0x0100  # Priority
_VERSION_MASK = 0x000F


@dataclass(frozen=True)
class L2tpHeader:
    """파싱된 L2TPv2 헤더 한 개.

    헤더(평문)만 담는다. 데이터 메시지의 PPP 프레임·제어 메시지의 AVP 본문은
    풀지 않고 ``payload_offset`` 만 노출한다.

    Attributes:
        is_control: 제어 메시지인지(T 비트=1). False 면 데이터 메시지.
        has_length: Length 필드가 존재하는지(L 비트).
        has_sequence: Ns/Nr 가 존재하는지(S 비트).
        has_offset: Offset Size 가 존재하는지(O 비트).
        is_priority: 우선순위 데이터 메시지인지(P 비트).
        version: L2TP 버전(항상 2).
        length: Length 필드 값(L 비트 없으면 None).
        tunnel_id: 16비트 Tunnel ID(터널 귀속).
        session_id: 16비트 Session ID(세션 귀속; 데이터는 0 이 아님).
        ns: 이 메시지의 시퀀스(S 비트 없으면 None).
        nr: 다음 기대 시퀀스(S 비트 없으면 None).
        offset_size: Offset Size 값(O 비트 없으면 None).
        payload_offset: PPP/AVP 페이로드 시작 오프셋(``data`` 기준).
    """

    is_control: bool = False
    has_length: bool = False
    has_sequence: bool = False
    has_offset: bool = False
    is_priority: bool = False
    version: int = L2TP_VERSION
    length: Optional[int] = None
    tunnel_id: int = 0
    session_id: int = 0
    ns: Optional[int] = None
    nr: Optional[int] = None
    offset_size: Optional[int] = None
    payload_offset: int = 0

    @property
    def is_data(self) -> bool:
        """데이터 메시지인지(T 비트=0) — PPP 프레임을 나른다."""
        return not self.is_control

    @property
    def is_setup(self) -> bool:
        """터널 ID 배정 전 최초 협상인지(``tunnel_id==0``) — SCCRQ 등."""
        return self.tunnel_id == 0


def looks_like_l2tp(data: bytes, offset: int = 0) -> bool:
    """``offset`` 바이트가 파싱 가능한 L2TPv2 헤더처럼 보이는지(가벼운 가드).

    UDP 1701 이라는 문맥과 함께 써야 신뢰할 수 있다.
    """
    return parse_l2tp(data, offset) is not None


def parse_l2tp(data: bytes, offset: int = 0) -> Optional[L2tpHeader]:
    """단일 L2TPv2 헤더를 파싱한다.

    Args:
        data: L2TP 바이트(UDP 1701 페이로드).
        offset: 파싱 시작 위치(기본 0).

    Returns:
        :class:`L2tpHeader`. Version 이 2 가 아니거나, 제어 메시지인데 L/S 비트가
        빠졌거나, 헤더가 잘리면 ``None``. 페이로드(PPP/AVP)는 풀지 않고
        ``payload_offset`` 만 노출한다.
    """
    if not isinstance(data, (bytes, bytearray)):
        return None
    pos = offset
    if len(data) - pos < 2:
        return None

    (flags,) = struct.unpack(">H", data[pos:pos + 2])
    pos += 2

    version = flags & _VERSION_MASK
    if version != L2TP_VERSION:
        return None

    is_control = bool(flags & _T_BIT)
    has_length = bool(flags & _L_BIT)
    has_sequence = bool(flags & _S_BIT)
    has_offset = bool(flags & _O_BIT)
    is_priority = bool(flags & _P_BIT)

    # RFC 2661 §3.1: 제어 메시지는 반드시 Length·Sequence 비트가 켜져 있어야 한다.
    # (비-L2TP/데이터 페이로드를 제어로 오인하지 않는 오탐 가드.)
    if is_control and not (has_length and has_sequence):
        return None

    length: Optional[int] = None
    if has_length:
        if len(data) - pos < 2:
            return None
        (length,) = struct.unpack(">H", data[pos:pos + 2])
        pos += 2

    # Tunnel ID + Session ID (각 16비트, 항상 존재).
    if len(data) - pos < 4:
        return None
    tunnel_id, session_id = struct.unpack(">HH", data[pos:pos + 4])
    pos += 4

    ns: Optional[int] = None
    nr: Optional[int] = None
    if has_sequence:
        if len(data) - pos < 4:
            return None
        ns, nr = struct.unpack(">HH", data[pos:pos + 4])
        pos += 4

    offset_size: Optional[int] = None
    if has_offset:
        if len(data) - pos < 2:
            return None
        (offset_size,) = struct.unpack(">H", data[pos:pos + 2])
        pos += 2
        # Offset Pad 는 offset_size 바이트만큼 헤더 뒤에 채워진다.
        if len(data) - pos < offset_size:
            return None
        pos += offset_size

    return L2tpHeader(
        is_control=is_control,
        has_length=has_length,
        has_sequence=has_sequence,
        has_offset=has_offset,
        is_priority=is_priority,
        version=version,
        length=length,
        tunnel_id=tunnel_id,
        session_id=session_id,
        ns=ns,
        nr=nr,
        offset_size=offset_size,
        payload_offset=pos,
    )
