"""OpenVPN 패킷 헤더 파싱 코어 (OpenVPN 프로토콜; UDP/TCP, 기본 1194).

:mod:`forensiclab.wireguard` 가 IPsec 묶음(:mod:`forensiclab.ike`·
:mod:`forensiclab.esp`·:mod:`forensiclab.l2tp`)을 대체하는 **현대 커널 VPN** 이라면,
OpenVPN 은 그 둘 사이에 위치하는 **가장 널리 쓰이는 사용자공간 TLS VPN** 이다 —
상용 VPN 서비스·기업 원격접속의 사실상 표준. WireGuard 가 고정 길이로 강하게
식별되는 것과 달리, OpenVPN 은 TLS 제어 채널(핸드셰이크)과 암호 데이터 채널을
같은 소켓에 다중화하며, **UDP(기본 1194)와 TCP(흔히 443 위장) 모두** 탄다 —
TCP/443 위장은 방화벽·DPI 우회의 대표 수법이다.

OpenVPN 패킷의 첫 바이트는 **opcode(상위 5비트)+key_id(하위 3비트)** 다. 제어/리셋/
ACK 패킷은 그 뒤 **8바이트 평문 Session ID**(발신측 세션 식별자)를 싣는다 — 이것이
ESP 의 SPI·WireGuard 의 sender_index 에 대응하는 **세션 귀속 핸들**이다. 데이터
패킷은 opcode 뒤가 전부 HMAC/암호문이라 풀 수 없다(P_DATA_V2 만 3바이트 peer-id 가
평문). tls-auth/tls-crypt 가 켜지면 Session ID 뒤에 HMAC+packet-id 가 끼어들어
ACK 배열/메시지 packet-id 위치가 설정에 따라 달라지므로, 본 파서는 **설정 없이도
확실한 부분(opcode·key_id·session_id·peer_id)만** 풀고 나머지는 ``payload_offset``
만 노출한다(오탐·오파싱 방지).

침해/사고 분석에서 OpenVPN 이 드러내는 것:

- **TLS VPN 존재·포트 위장**: opcode 가 유효 범위(1~11)이고 제어 패킷이 8바이트
  세션 ID 를 갖추면 OpenVPN 정황 — 1194 가 아닌 TCP/443·UDP/53 등으로 위장해도
  핸드셰이크 구조로 식별된다. 풀 수 없는 데이터 채널 자체가 암호 터널·은닉 정황.
- **세션 귀속·터널 상관(session_id)**: 8바이트 ``session_id`` 는 각 끝이 통보하는
  세션 식별자라, :mod:`forensiclab.flows` 의 같은 IP 쌍 안에서 양방향을 한 세션으로
  못 박는다. 핸드셰이크 재수행(hard reset) 시 새 세션 ID 로 세션 수명을 추적한다.
- **세션 개통·방향(hard reset)**: ``is_hard_reset`` (opcode 1·2·7·8·10)은 TLS
  핸드셰이크 시작 — ``is_client_reset`` (1·7·10)/``is_server_reset`` (2·8)으로
  연결 개시자/응답자(방향)를 가른다. ``is_soft_reset`` (3)은 키 재협상(rekey).
- **다중 클라이언트 서버(P_DATA_V2 peer-id)**: ``peer_id`` 는 서버가 한 소켓에서
  여러 클라이언트를 구분하는 24비트 식별자 — 같은 서버에 붙은 여러 피어를 분리.
- **레거시·약점 핑거프린트**: hard reset V1(opcode 1·2)은 구버전 클라이언트 정황,
  V2/V3(7·8·10)은 현대 클라이언트. key_id 회전(0→1→…)은 rekey 진행 흔적.

와이어 포맷(big-endian):
- 1바이트: ``opcode<<3 | key_id``.
- 제어/리셋/ACK(opcode 1·2·3·4·5·7·8·10·11): + 8바이트 Session ID(발신측).
  이후 [tls-auth/tls-crypt HMAC+packet-id] · ACK 배열 · (P_CONTROL)메시지 packet-id
  는 설정 의존이라 풀지 않음.
- 데이터(P_DATA_V1=6): opcode 뒤 전부 암호문(payload_offset 만).
- 데이터(P_DATA_V2=9): + 3바이트 peer-id, 이후 암호문.
- TCP 전송 시 각 패킷 앞에 2바이트 big-endian 길이 접두사 → ``offset=2`` 로 건너뜀.

설계 원칙(다른 파서와 동일):
- 부작용 없음·stdlib 전용·읽기 전용.
- 견고: opcode 가 1~11 이 아니거나, 제어 패킷인데 세션 ID 8바이트가 모자라거나,
  데이터 V2 인데 peer-id 3바이트가 모자라면 예외 대신 ``None``(오탐 가드).
- 암호 본문·HMAC·ACK 배열은 풀지 않고 ``payload_offset`` 만 노출한다.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

__all__ = [
    "OPENVPN_PORT",
    "P_CONTROL_HARD_RESET_CLIENT_V1",
    "P_CONTROL_HARD_RESET_SERVER_V1",
    "P_CONTROL_SOFT_RESET_V1",
    "P_CONTROL_V1",
    "P_ACK_V1",
    "P_DATA_V1",
    "P_CONTROL_HARD_RESET_CLIENT_V2",
    "P_CONTROL_HARD_RESET_SERVER_V2",
    "P_DATA_V2",
    "P_CONTROL_HARD_RESET_CLIENT_V3",
    "P_CONTROL_WKC_V1",
    "OpenVPNHeader",
    "looks_like_openvpn",
    "parse_openvpn",
]

# OpenVPN 기본 포트(UDP/TCP, 설정 가능 — TCP/443 위장 흔함).
OPENVPN_PORT = 1194

# opcode 값(첫 바이트 상위 5비트). key_id 는 하위 3비트.
P_CONTROL_HARD_RESET_CLIENT_V1 = 1
P_CONTROL_HARD_RESET_SERVER_V1 = 2
P_CONTROL_SOFT_RESET_V1 = 3
P_CONTROL_V1 = 4
P_ACK_V1 = 5
P_DATA_V1 = 6
P_CONTROL_HARD_RESET_CLIENT_V2 = 7
P_CONTROL_HARD_RESET_SERVER_V2 = 8
P_DATA_V2 = 9
P_CONTROL_HARD_RESET_CLIENT_V3 = 10
P_CONTROL_WKC_V1 = 11

_OPCODE_NAMES = {
    P_CONTROL_HARD_RESET_CLIENT_V1: "P_CONTROL_HARD_RESET_CLIENT_V1",
    P_CONTROL_HARD_RESET_SERVER_V1: "P_CONTROL_HARD_RESET_SERVER_V1",
    P_CONTROL_SOFT_RESET_V1: "P_CONTROL_SOFT_RESET_V1",
    P_CONTROL_V1: "P_CONTROL_V1",
    P_ACK_V1: "P_ACK_V1",
    P_DATA_V1: "P_DATA_V1",
    P_CONTROL_HARD_RESET_CLIENT_V2: "P_CONTROL_HARD_RESET_CLIENT_V2",
    P_CONTROL_HARD_RESET_SERVER_V2: "P_CONTROL_HARD_RESET_SERVER_V2",
    P_DATA_V2: "P_DATA_V2",
    P_CONTROL_HARD_RESET_CLIENT_V3: "P_CONTROL_HARD_RESET_CLIENT_V3",
    P_CONTROL_WKC_V1: "P_CONTROL_WKc_V1",
}

# 데이터 채널 opcode(세션 ID 없이 opcode 뒤가 암호문).
_DATA_OPCODES = frozenset({P_DATA_V1, P_DATA_V2})
# 세션 ID(8B)를 싣는 제어 채널 opcode.
_CONTROL_OPCODES = frozenset(
    {
        P_CONTROL_HARD_RESET_CLIENT_V1,
        P_CONTROL_HARD_RESET_SERVER_V1,
        P_CONTROL_SOFT_RESET_V1,
        P_CONTROL_V1,
        P_ACK_V1,
        P_CONTROL_HARD_RESET_CLIENT_V2,
        P_CONTROL_HARD_RESET_SERVER_V2,
        P_CONTROL_HARD_RESET_CLIENT_V3,
        P_CONTROL_WKC_V1,
    }
)
# TLS 핸드셰이크를 새로 시작하는 hard reset opcode(세션 개통).
_HARD_RESET_OPCODES = frozenset(
    {
        P_CONTROL_HARD_RESET_CLIENT_V1,
        P_CONTROL_HARD_RESET_SERVER_V1,
        P_CONTROL_HARD_RESET_CLIENT_V2,
        P_CONTROL_HARD_RESET_SERVER_V2,
        P_CONTROL_HARD_RESET_CLIENT_V3,
    }
)
_CLIENT_RESET_OPCODES = frozenset(
    {
        P_CONTROL_HARD_RESET_CLIENT_V1,
        P_CONTROL_HARD_RESET_CLIENT_V2,
        P_CONTROL_HARD_RESET_CLIENT_V3,
    }
)
_SERVER_RESET_OPCODES = frozenset(
    {P_CONTROL_HARD_RESET_SERVER_V1, P_CONTROL_HARD_RESET_SERVER_V2}
)

_SESSION_ID_LEN = 8


@dataclass(frozen=True)
class OpenVPNHeader:
    """파싱된 OpenVPN 패킷 헤더 한 개.

    설정 없이도 확실한 평문 부분(opcode·key_id·session_id·peer_id)만 담는다.
    tls-auth/tls-crypt HMAC·ACK 배열·메시지 packet-id·암호 본문은 풀지 않고,
    이후 바이트는 ``payload_offset`` 만 노출한다.

    Attributes:
        opcode: 패킷 종류(1~11; 첫 바이트 상위 5비트).
        key_id: 키 슬롯 식별자(0~7; 하위 3비트, rekey 시 회전).
        session_id: 발신측 8바이트 세션 ID(제어 채널에만, 데이터 패킷은 None).
        peer_id: 서버측 24비트 피어 식별자(P_DATA_V2 에만, 그 외 None).
        payload_offset: 이후(HMAC/ACK/암호문) 시작 오프셋(``data`` 기준).
    """

    opcode: int
    key_id: int
    session_id: Optional[bytes] = None
    peer_id: Optional[int] = None
    payload_offset: int = 0

    @property
    def opcode_name(self) -> str:
        """opcode 이름(알 수 없으면 ``opcode_<n>``)."""
        return _OPCODE_NAMES.get(self.opcode, f"opcode_{self.opcode}")

    @property
    def session_id_hex(self) -> Optional[str]:
        """세션 ID 16진 문자열(없으면 None) — 흐름 상관 키."""
        return self.session_id.hex() if self.session_id is not None else None

    @property
    def is_data(self) -> bool:
        """데이터 채널 패킷인지(P_DATA_V1·V2) — 암호화된 실제 트래픽."""
        return self.opcode in _DATA_OPCODES

    @property
    def is_control(self) -> bool:
        """제어 채널 패킷인지(TLS 핸드셰이크·ACK·리셋)."""
        return self.opcode in _CONTROL_OPCODES

    @property
    def is_hard_reset(self) -> bool:
        """TLS 핸드셰이크를 새로 여는 hard reset 인지 — 세션 개통."""
        return self.opcode in _HARD_RESET_OPCODES

    @property
    def is_client_reset(self) -> bool:
        """클라이언트가 보낸 hard reset 인지(연결 개시 방향)."""
        return self.opcode in _CLIENT_RESET_OPCODES

    @property
    def is_server_reset(self) -> bool:
        """서버가 보낸 hard reset 인지(연결 응답 방향)."""
        return self.opcode in _SERVER_RESET_OPCODES

    @property
    def is_soft_reset(self) -> bool:
        """soft reset 인지(P_CONTROL_SOFT_RESET_V1) — 키 재협상(rekey)."""
        return self.opcode == P_CONTROL_SOFT_RESET_V1

    @property
    def is_ack(self) -> bool:
        """순수 ACK 패킷인지(P_ACK_V1)."""
        return self.opcode == P_ACK_V1


def looks_like_openvpn(data: bytes, offset: int = 0) -> bool:
    """``offset`` 바이트가 파싱 가능한 OpenVPN 패킷처럼 보이는지(가벼운 가드).

    opcode 범위(1~11)와 제어 패킷의 세션 ID 길이만 검사하므로 단독으로는 약하다 —
    UDP/TCP 포트(1194 등) 문맥과 함께 쓰는 것이 가장 안전하다.
    """
    return parse_openvpn(data, offset) is not None


def parse_openvpn(data: bytes, offset: int = 0) -> Optional[OpenVPNHeader]:
    """단일 OpenVPN 패킷 헤더를 파싱한다.

    Args:
        data: OpenVPN 바이트(UDP 페이로드, 또는 TCP 2바이트 길이 접두사 뒤 ``offset=2``).
        offset: 파싱 시작 위치(기본 0).

    Returns:
        :class:`OpenVPNHeader`. opcode 가 1~11 이 아니거나, 제어 패킷인데 세션 ID
        8바이트가 모자라거나, P_DATA_V2 인데 peer-id 3바이트가 모자라면 ``None``.
        암호 본문·HMAC·ACK 배열은 풀지 않고 ``payload_offset`` 만 노출한다.
    """
    if not isinstance(data, (bytes, bytearray)):
        return None
    pos = offset
    if len(data) - pos < 1:
        return None

    first = data[pos]
    opcode = first >> 3
    key_id = first & 0x07
    if opcode not in _OPCODE_NAMES:
        return None

    pos += 1

    if opcode == P_DATA_V1:
        # opcode 뒤 전부 암호문 — payload_offset 만.
        return OpenVPNHeader(opcode=opcode, key_id=key_id, payload_offset=pos)

    if opcode == P_DATA_V2:
        # 3바이트 peer-id 뒤 암호문.
        if len(data) - pos < 3:
            return None
        peer_id = (data[pos] << 16) | (data[pos + 1] << 8) | data[pos + 2]
        return OpenVPNHeader(
            opcode=opcode, key_id=key_id, peer_id=peer_id, payload_offset=pos + 3
        )

    # 제어 채널: 8바이트 Session ID 필수.
    if len(data) - pos < _SESSION_ID_LEN:
        return None
    session_id = bytes(data[pos:pos + _SESSION_ID_LEN])
    return OpenVPNHeader(
        opcode=opcode,
        key_id=key_id,
        session_id=session_id,
        payload_offset=pos + _SESSION_ID_LEN,
    )
