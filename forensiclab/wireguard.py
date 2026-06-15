"""WireGuard 메시지 헤더 파싱 코어 (WireGuard 프로토콜; UDP, 기본 51820).

:mod:`forensiclab.ike`(IPsec 키 협상)·:mod:`forensiclab.esp`(암호 데이터 평면)·
:mod:`forensiclab.l2tp`(터널 운반층)이 **레거시/표준 IPsec VPN 묶음**이었다면,
WireGuard 는 그 자리를 대체하는 **현대 VPN** 이다 — Linux 커널 내장·모바일 기본
WireGuard 앱이 그것이다. ESP 가 SPI+Sequence 8바이트 뒤 전부 암호문이었듯
WireGuard 도 핸드셰이크 산물 키로 ChaCha20-Poly1305 암호화하지만, 프레임 구조가
**완전히 다르다**: 메시지 종류는 1바이트 type, 뒤 3바이트는 **반드시 0(reserved)**,
세션 색인과 카운터는 little-endian 평문이다.

WireGuard 의 결정적 식별 특징은 **메시지별 고정 길이**다 — Handshake Initiation
148바이트, Handshake Response 92바이트, Cookie Reply 64바이트는 그 자체가 강한
핑거프린트라 **비표준 포트로 위장해도** 식별된다. type 다음 3바이트가 0 이라는
제약과 합쳐, 임의 UDP 페이로드를 WireGuard 로 오인할 확률을 크게 낮춘다.

헤더에서 평문으로 읽히는 것은 메시지 종류·세션 색인·전송 카운터·과부하(mac2)
정황뿐이다. 임시 공개키(ephemeral)는 평문이지만 핸드셰이크마다 회전(forward
secrecy)하므로 장기 피어 식별자가 못 된다. 본 파서는 헤더만 풀고 암호 본문은
풀지 않으며, 전송 데이터는 시작 오프셋(``payload_offset``)만 노출한다.

침해/사고 분석에서 WireGuard 가 드러내는 것:

- **현대 VPN 존재·비표준 포트 위장**: 고정 길이(148/92/64)는 포트와 무관한
  핑거프린트다 — 51820 이 아닌 임의 UDP 포트(443/123 등 위장)에서도 이 크기와
  reserved=0 조합이면 WireGuard. 풀 수 없다는 사실 자체가 암호 VPN 정황이고,
  방화벽 정책을 우회하는 은닉 터널 단서다.
- **세션 귀속·터널 상관(sender/receiver index)**: 32비트 ``sender_index``·
  ``receiver_index`` 는 ESP 의 SPI 대응 — 각 끝이 상대에게 자기 색인을 통보하고,
  :mod:`forensiclab.flows` 의 같은 IP 쌍 안에서 양방향을 한 세션으로 못 박는다.
  핸드셰이크 재수행 시 색인이 바뀌어 세션 수명(rekey) 추적이 된다.
- **전송 진행·재생 공격(counter)**: 전송 데이터의 64비트 ``counter`` 는 세션마다
  0 부터 단조 증가하는 nonce/anti-replay 카운터 — ``counter==0``(``is_initial_transport``)
  은 핸드셰이크 직후 첫 전송(세션 개통), 큰 값=장수명/대량 전송, 같은 색인에서
  되감김·중복=재생 공격/캡처 재주입 정황(ESP ``sequence`` 대응).
- **과부하·DoS 완화(mac2)**: 핸드셰이크의 mac2 가 0 이 아니면(``mac2_present``)
  응답자가 과부하 상태로 cookie 챌린지를 요구한 정황 — Cookie Reply(type 3)
  출현과 짝지어 핸드셰이크 플러딩/DoS 시도를 본다.

와이어 포맷(little-endian) — 1바이트 type + 3바이트 reserved(0) 공통, 이후:
- type 1 Handshake Initiation(148B): sender(4)·ephemeral(32)·enc_static(48)·
  enc_timestamp(28)·mac1(16)·mac2(16).
- type 2 Handshake Response(92B): sender(4)·receiver(4)·ephemeral(32)·
  enc_empty(16)·mac1(16)·mac2(16).
- type 3 Cookie Reply(64B): receiver(4)·nonce(24)·enc_cookie(32).
- type 4 Transport Data(≥32B): receiver(4)·counter(8)·enc_packet(가변, ≥16).

설계 원칙(다른 파서와 동일):
- 부작용 없음·stdlib 전용·읽기 전용.
- 견고: type 이 1~4 가 아니거나, reserved 3바이트가 0 이 아니거나, 메시지별
  고정 길이에 못 미치면(전송은 최소 32B) 예외 대신 ``None``(오탐 가드).
- 암호 본문(ephemeral/encrypted/mac)은 풀지 않고 ``payload_offset`` 만 노출한다.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Optional

__all__ = [
    "WIREGUARD_PORT",
    "MSG_HANDSHAKE_INITIATION",
    "MSG_HANDSHAKE_RESPONSE",
    "MSG_COOKIE_REPLY",
    "MSG_TRANSPORT_DATA",
    "WireGuardHeader",
    "looks_like_wireguard",
    "parse_wireguard",
]

# WireGuard 는 UDP, 기본 포트 51820(설정 가능). type 다음 3바이트는 항상 0.
WIREGUARD_PORT = 51820

# 메시지 종류(1바이트 type, little-endian u8).
MSG_HANDSHAKE_INITIATION = 1
MSG_HANDSHAKE_RESPONSE = 2
MSG_COOKIE_REPLY = 3
MSG_TRANSPORT_DATA = 4

# 메시지별 고정 길이(전송 데이터는 가변·최소값만).
_LEN_INITIATION = 148
_LEN_RESPONSE = 92
_LEN_COOKIE = 64
_LEN_TRANSPORT_MIN = 32  # type(1)+reserved(3)+receiver(4)+counter(8)+poly1305 tag(16)

_MESSAGE_TYPE_NAMES = {
    MSG_HANDSHAKE_INITIATION: "handshake_initiation",
    MSG_HANDSHAKE_RESPONSE: "handshake_response",
    MSG_COOKIE_REPLY: "cookie_reply",
    MSG_TRANSPORT_DATA: "transport_data",
}


@dataclass(frozen=True)
class WireGuardHeader:
    """파싱된 WireGuard 메시지 헤더 한 개.

    헤더(평문)만 담는다. 임시 공개키·암호 본문·MAC 은 풀지 않고, 전송 데이터의
    암호 페이로드는 ``payload_offset`` 만 노출한다.

    Attributes:
        message_type: 메시지 종류(1~4).
        sender_index: 발신측 세션 색인(type 1·2 에만, 그 외 None).
        receiver_index: 수신측 세션 색인(type 2·3·4 에만, type 1 은 None).
        counter: 전송 nonce/anti-replay 카운터(type 4 에만, 그 외 None).
        mac2_present: 핸드셰이크 mac2 가 0 이 아닌지(type 1·2; 과부하/cookie 정황).
        payload_offset: 암호 페이로드 시작 오프셋(``data`` 기준; 전송 데이터에서 유효).
    """

    message_type: int
    sender_index: Optional[int] = None
    receiver_index: Optional[int] = None
    counter: Optional[int] = None
    mac2_present: bool = False
    payload_offset: int = 0

    @property
    def type_name(self) -> str:
        """메시지 종류 이름(알 수 없으면 ``type_<n>``)."""
        return _MESSAGE_TYPE_NAMES.get(self.message_type, f"type_{self.message_type}")

    @property
    def is_handshake_initiation(self) -> bool:
        """Handshake Initiation 인지(type 1) — 세션 개통 첫 메시지."""
        return self.message_type == MSG_HANDSHAKE_INITIATION

    @property
    def is_handshake_response(self) -> bool:
        """Handshake Response 인지(type 2)."""
        return self.message_type == MSG_HANDSHAKE_RESPONSE

    @property
    def is_cookie_reply(self) -> bool:
        """Cookie Reply 인지(type 3) — 응답자 과부하 시 DoS 완화 챌린지."""
        return self.message_type == MSG_COOKIE_REPLY

    @property
    def is_transport_data(self) -> bool:
        """Transport Data 인지(type 4) — 암호화된 실제 트래픽."""
        return self.message_type == MSG_TRANSPORT_DATA

    @property
    def is_handshake(self) -> bool:
        """핸드셰이크 메시지인지(type 1 또는 2)."""
        return self.message_type in (MSG_HANDSHAKE_INITIATION, MSG_HANDSHAKE_RESPONSE)

    @property
    def is_initial_transport(self) -> bool:
        """세션 첫 전송 패킷인지(type 4·``counter==0``) — 핸드셰이크 직후."""
        return self.message_type == MSG_TRANSPORT_DATA and self.counter == 0


def looks_like_wireguard(data: bytes, offset: int = 0) -> bool:
    """``offset`` 바이트가 파싱 가능한 WireGuard 메시지처럼 보이는지(가벼운 가드).

    메시지별 고정 길이 + reserved=0 검사를 거치므로 비표준 포트에서도 비교적
    신뢰할 수 있지만, UDP 문맥과 함께 쓰는 것이 가장 안전하다.
    """
    return parse_wireguard(data, offset) is not None


def parse_wireguard(data: bytes, offset: int = 0) -> Optional[WireGuardHeader]:
    """단일 WireGuard 메시지 헤더를 파싱한다.

    Args:
        data: WireGuard 바이트(UDP 페이로드).
        offset: 파싱 시작 위치(기본 0).

    Returns:
        :class:`WireGuardHeader`. type 이 1~4 가 아니거나, reserved 3바이트가 0 이
        아니거나, 메시지별 고정 길이(전송은 최소 32B)에 못 미치면 ``None``.
        암호 본문은 풀지 않고 전송 데이터의 ``payload_offset`` 만 노출한다.
    """
    if not isinstance(data, (bytes, bytearray)):
        return None
    pos = offset
    if len(data) - pos < 4:
        return None

    message_type = data[pos]
    # type 다음 3바이트 reserved 는 반드시 0 — 강한 오탐 가드.
    if data[pos + 1] != 0 or data[pos + 2] != 0 or data[pos + 3] != 0:
        return None

    avail = len(data) - pos

    if message_type == MSG_HANDSHAKE_INITIATION:
        if avail < _LEN_INITIATION:
            return None
        (sender_index,) = struct.unpack("<I", data[pos + 4:pos + 8])
        # mac2 는 마지막 16바이트(offset 132..148).
        mac2 = data[pos + 132:pos + 148]
        return WireGuardHeader(
            message_type=message_type,
            sender_index=sender_index,
            mac2_present=any(mac2),
            payload_offset=pos + _LEN_INITIATION,
        )

    if message_type == MSG_HANDSHAKE_RESPONSE:
        if avail < _LEN_RESPONSE:
            return None
        sender_index, receiver_index = struct.unpack("<II", data[pos + 4:pos + 12])
        # mac2 는 마지막 16바이트(offset 76..92).
        mac2 = data[pos + 76:pos + 92]
        return WireGuardHeader(
            message_type=message_type,
            sender_index=sender_index,
            receiver_index=receiver_index,
            mac2_present=any(mac2),
            payload_offset=pos + _LEN_RESPONSE,
        )

    if message_type == MSG_COOKIE_REPLY:
        if avail < _LEN_COOKIE:
            return None
        (receiver_index,) = struct.unpack("<I", data[pos + 4:pos + 8])
        return WireGuardHeader(
            message_type=message_type,
            receiver_index=receiver_index,
            payload_offset=pos + _LEN_COOKIE,
        )

    if message_type == MSG_TRANSPORT_DATA:
        if avail < _LEN_TRANSPORT_MIN:
            return None
        receiver_index, counter = struct.unpack("<IQ", data[pos + 4:pos + 16])
        return WireGuardHeader(
            message_type=message_type,
            receiver_index=receiver_index,
            counter=counter,
            payload_offset=pos + 16,
        )

    return None
