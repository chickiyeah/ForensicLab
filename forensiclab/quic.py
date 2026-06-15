"""QUIC 롱 헤더 파싱 코어 (RFC 9000 QUIC v1·RFC 9369 QUIC v2; UDP, 흔히 443).

:mod:`forensiclab.wireguard`·:mod:`forensiclab.openvpn`·:mod:`forensiclab.esp` 가
**암호 VPN 터널** 묶음이었다면, QUIC 는 그 사촌격인 **현대 암호 전송 계층**이다 —
HTTP/3 가 그 위에서 돈다. TCP+TLS 를 UDP 하나로 합쳐 핸드셰이크·혼잡제어·암호화를
한 프로토콜에 넣었고, 구글/유튜브/페이스북/CDN 트래픽의 큰 몫이 이제 QUIC 다.
TLS over TCP 와 달리 거의 모든 것이 암호화되지만, **롱 헤더(핸드셰이크 구간)** 는
버전과 두 연결 ID(Connection ID)를 **평문**으로 노출한다 — 이것이 본 파서의 표적.

QUIC 패킷은 첫 바이트 최상위 비트(``0x80``, Header Form)로 두 형태를 가른다:

- **롱 헤더**(``0x80`` 셋): Initial/0-RTT/Handshake/Retry·Version Negotiation.
  핸드셰이크 동안만 쓰이며 버전·DCID·SCID 가 평문이다 — 본 파서가 푸는 대상.
- **숏 헤더**(``0x80`` 클리어): 1-RTT 데이터. DCID 에 **길이 필드가 없어**(연결
  상태로만 길이를 앎) 상태 없이 DCID 를 못 떼어낸다. 본 파서는 숏 헤더를 ``None``
  으로 돌려보내며(헤더 보호로 첫 바이트 하위 비트도 암호화됨), 식별만 하려면
  :func:`is_short_header` 를 쓴다.

롱 헤더에서 평문으로 읽히는 것은 다음뿐이다(나머지 패킷 번호·페이로드는
헤더 보호+AEAD 로 암호화):

와이어 포맷(롱 헤더, big-endian) — 첫 바이트(Form 1·Fixed 1·Type 2비트·보호된
4비트) + 4바이트 Version + 1바이트 DCID Length + DCID + 1바이트 SCID Length + SCID.
Version==0 이면 Version Negotiation(이후 4바이트 지원 버전 목록).

침해/사고 분석에서 QUIC 롱 헤더가 드러내는 것:

- **현대 암호 전송 존재·포트 위장**: 풀 수 없는 QUIC 가 443 아닌 임의 UDP 포트에
  보이면 그 자체가 암호 터널/우회 정황 — HTTP/3·QUIC VPN·은닉 터널 단서.
- **연결 상관·이주 추적(DCID·SCID)**: 각 끝이 상대에게 자기 Connection ID 를
  통보한다. DCID/SCID 쌍은 :mod:`forensiclab.flows` 의 IP 쌍을 넘어 **NAT 재바인딩·
  연결 이주(connection migration)** 후에도 같은 연결로 못 박는 키 — IP 가 바뀌어도
  같은 DCID 면 동일 세션(WireGuard sender/receiver index·ESP SPI 대응).
- **클라이언트 핑거프린트(version)**: 32비트 버전은 구현/세대를 가른다 — v1(RFC
  9000)·v2(RFC 9369)·draft-NN(구형 클라이언트)·Google QUIC·GREASE 예약 버전.
  GREASE(``0x?a?a?a?a``)는 버전 협상 강제용 더미 — TLS GREASE 처럼 라이브러리
  핑거프린트가 된다.
- **핸드셰이크 단계·DoS 완화(packet type)**: ``is_initial`` 핸드셰이크 개시·
  ``is_retry`` 응답자 주소검증/과부하 완화(WireGuard cookie·SYN cookie 대응)·
  ``is_version_negotiation`` 서버가 클라 버전 미지원 통보. Initial 폭주·Retry 출현은
  핸드셰이크 플러딩/증폭 정찰 정황.

설계 원칙(다른 파서와 동일):
- 부작용 없음·stdlib 전용·읽기 전용.
- 견고: 롱 헤더가 아니거나, Connection ID 길이가 RFC 한계 20 을 넘거나, 버전 있는
  헤더인데 Fixed 비트(``0x40``)가 0 이거나, 바이트가 모자라면 예외 대신 ``None``
  (오탐 가드). Version Negotiation 은 Fixed 비트가 임의값이라 검사하지 않는다.
- 암호 본문(토큰·패킷 번호·페이로드)은 풀지 않고 ``payload_offset`` 만 노출한다.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Optional, Tuple

__all__ = [
    "QUIC_PORT",
    "VERSION_NEGOTIATION",
    "QUIC_V1",
    "QUIC_V2",
    "MAX_CID_LEN",
    "PKT_INITIAL",
    "PKT_0RTT",
    "PKT_HANDSHAKE",
    "PKT_RETRY",
    "QuicLongHeader",
    "is_short_header",
    "looks_like_quic",
    "parse_quic",
]

# QUIC 는 UDP, HTTP/3 는 흔히 443(설정·대체 가능).
QUIC_PORT = 443

# 잘 알려진 버전 값(32비트 big-endian).
VERSION_NEGOTIATION = 0x00000000
QUIC_V1 = 0x00000001            # RFC 9000
QUIC_V2 = 0x6B3343CF            # RFC 9369

# Connection ID 최대 길이(RFC 9000 §17.2): 0~20.
MAX_CID_LEN = 20

# 추상 패킷 종류(버전 무관 의미). 와이어의 2비트 코드는 버전마다 다르므로
# (v1·v2 가 서로 다름) 파싱 시 버전별 매핑으로 이 추상값으로 정규화한다.
PKT_INITIAL = "initial"
PKT_0RTT = "0rtt"
PKT_HANDSHAKE = "handshake"
PKT_RETRY = "retry"

# 와이어 2비트 코드 → 추상 종류. v1(RFC 9000)과 v2(RFC 9369)가 코드를 뒤섞었다.
_V1_TYPES = {0: PKT_INITIAL, 1: PKT_0RTT, 2: PKT_HANDSHAKE, 3: PKT_RETRY}
_V2_TYPES = {1: PKT_INITIAL, 2: PKT_0RTT, 3: PKT_HANDSHAKE, 0: PKT_RETRY}


def _type_name(version: int, code: int) -> str:
    """버전별 2비트 코드를 추상 패킷 종류로 정규화(미지 버전은 v1 매핑 가정)."""
    table = _V2_TYPES if version == QUIC_V2 else _V1_TYPES
    return table.get(code, PKT_INITIAL)


def _version_name(version: int) -> str:
    """버전 32비트를 사람이 읽을 이름으로(핑거프린트용)."""
    if version == VERSION_NEGOTIATION:
        return "version_negotiation"
    if version == QUIC_V1:
        return "quic_v1"
    if version == QUIC_V2:
        return "quic_v2"
    # IETF draft 버전: 0xff0000NN → draft-NN.
    if 0xFF000000 <= version <= 0xFF0000FF:
        return f"draft-{version & 0xFF}"
    # GREASE/예약 버전(RFC 9000 §15): 0x?a?a?a?a.
    if (version & 0x0F0F0F0F) == 0x0A0A0A0A:
        return "grease"
    return f"unknown_0x{version:08x}"


@dataclass(frozen=True)
class QuicLongHeader:
    """파싱된 QUIC 롱 헤더 한 개.

    평문 헤더 필드만 담는다. 토큰·패킷 번호·암호 본문은 풀지 않고
    ``payload_offset`` 만 노출한다.

    Attributes:
        first_byte: 첫 바이트 원본(Form·Fixed·Type·보호 비트 포함).
        version: 32비트 버전(0 이면 Version Negotiation).
        dcid: 목적지 Connection ID(평문 바이트, 0~20).
        scid: 출발지 Connection ID(평문 바이트, 0~20).
        long_packet_type: 추상 패킷 종류 문자열(Version Negotiation 은 None).
        supported_versions: Version Negotiation 의 지원 버전 튜플(그 외 None).
        payload_offset: 암호 페이로드 시작 오프셋(``data`` 기준; SCID 직후).
    """

    first_byte: int
    version: int
    dcid: bytes
    scid: bytes
    long_packet_type: Optional[str] = None
    supported_versions: Optional[Tuple[int, ...]] = None
    payload_offset: int = 0

    @property
    def fixed_bit(self) -> bool:
        """Fixed 비트(``0x40``)가 셋인지 — 버전 있는 헤더는 반드시 1."""
        return bool(self.first_byte & 0x40)

    @property
    def version_name(self) -> str:
        """버전 이름(v1·v2·draft-NN·grease·unknown_0x…)."""
        return _version_name(self.version)

    @property
    def type_name(self) -> str:
        """패킷 종류 이름(version_negotiation 또는 추상 종류)."""
        return self.long_packet_type or "version_negotiation"

    @property
    def is_version_negotiation(self) -> bool:
        """Version Negotiation 패킷인지(version==0) — 서버가 버전 미지원 통보."""
        return self.version == VERSION_NEGOTIATION

    @property
    def is_initial(self) -> bool:
        """Initial 패킷인지 — 핸드셰이크 개시(세션 개통)."""
        return self.long_packet_type == PKT_INITIAL

    @property
    def is_0rtt(self) -> bool:
        """0-RTT 패킷인지 — 이전 세션 재개로 초기 데이터 조기 전송."""
        return self.long_packet_type == PKT_0RTT

    @property
    def is_handshake(self) -> bool:
        """Handshake 패킷인지 — 핸드셰이크 진행 중."""
        return self.long_packet_type == PKT_HANDSHAKE

    @property
    def is_retry(self) -> bool:
        """Retry 패킷인지 — 응답자 주소검증/과부하 완화(DoS 챌린지)."""
        return self.long_packet_type == PKT_RETRY

    @property
    def is_grease_version(self) -> bool:
        """GREASE/예약 버전인지(``0x?a?a?a?a``) — 버전 협상 강제 더미."""
        return self.version != 0 and (self.version & 0x0F0F0F0F) == 0x0A0A0A0A

    @property
    def dcid_hex(self) -> str:
        """DCID 16진 문자열(연결 상관 키)."""
        return self.dcid.hex()

    @property
    def scid_hex(self) -> str:
        """SCID 16진 문자열(연결 상관 키)."""
        return self.scid.hex()


def is_short_header(data: bytes, offset: int = 0) -> bool:
    """``offset`` 바이트가 QUIC 숏 헤더(1-RTT)처럼 보이는지(가벼운 식별만).

    숏 헤더는 Header Form 비트(``0x80``)가 0 이고 Fixed 비트(``0x40``)가 1 이다.
    DCID 길이 필드가 없어 상태 없이 더 파싱할 수 없으므로 식별만 한다. 임의 UDP
    페이로드와 겹칠 수 있으니 UDP 문맥(같은 연결의 롱 헤더 선행)과 함께 쓴다.
    """
    if not isinstance(data, (bytes, bytearray)) or len(data) - offset < 1:
        return False
    b = data[offset]
    return (b & 0x80) == 0 and (b & 0x40) == 0x40


def looks_like_quic(data: bytes, offset: int = 0) -> bool:
    """``offset`` 바이트가 파싱 가능한 QUIC 롱 헤더처럼 보이는지(가벼운 가드)."""
    return parse_quic(data, offset) is not None


def parse_quic(data: bytes, offset: int = 0) -> Optional[QuicLongHeader]:
    """단일 QUIC 롱 헤더를 파싱한다.

    Args:
        data: QUIC 바이트(UDP 페이로드).
        offset: 파싱 시작 위치(기본 0).

    Returns:
        :class:`QuicLongHeader`. 롱 헤더가 아니거나(숏 헤더 포함), Connection ID
        길이가 20 을 넘거나, 버전 있는 헤더인데 Fixed 비트가 0 이거나, 바이트가
        모자라면 ``None``(오탐 가드). 암호 본문은 풀지 않고 ``payload_offset`` 만
        노출한다.
    """
    if not isinstance(data, (bytes, bytearray)):
        return None
    pos = offset
    # 첫 바이트 + 버전(4) = 최소 5바이트.
    if len(data) - pos < 5:
        return None

    first_byte = data[pos]
    # Header Form 비트(0x80)가 0 이면 롱 헤더가 아니다(숏 헤더 등).
    if (first_byte & 0x80) == 0:
        return None

    (version,) = struct.unpack_from(">I", data, pos + 1)
    is_vn = version == VERSION_NEGOTIATION

    # 버전 있는 롱 헤더는 Fixed 비트(0x40)가 반드시 1(RFC 9000 §17.2).
    # Version Negotiation 은 임의값이라 검사하지 않는다.
    if not is_vn and (first_byte & 0x40) == 0:
        return None

    p = pos + 5  # 첫 바이트 + 버전 이후.

    # DCID Length + DCID.
    if len(data) - p < 1:
        return None
    dcid_len = data[p]
    if dcid_len > MAX_CID_LEN:
        return None
    p += 1
    if len(data) - p < dcid_len:
        return None
    dcid = bytes(data[p:p + dcid_len])
    p += dcid_len

    # SCID Length + SCID.
    if len(data) - p < 1:
        return None
    scid_len = data[p]
    if scid_len > MAX_CID_LEN:
        return None
    p += 1
    if len(data) - p < scid_len:
        return None
    scid = bytes(data[p:p + scid_len])
    p += scid_len

    if is_vn:
        # 이후는 4바이트 지원 버전 목록(0개 이상). 4의 배수가 아니면 잘린 것.
        rest = len(data) - p
        if rest % 4 != 0:
            return None
        count = rest // 4
        supported = struct.unpack_from(">%dI" % count, data, p) if count else ()
        return QuicLongHeader(
            first_byte=first_byte,
            version=version,
            dcid=dcid,
            scid=scid,
            long_packet_type=None,
            supported_versions=tuple(supported),
            payload_offset=p,
        )

    long_packet_type = _type_name(version, (first_byte >> 4) & 0x03)
    return QuicLongHeader(
        first_byte=first_byte,
        version=version,
        dcid=dcid,
        scid=scid,
        long_packet_type=long_packet_type,
        payload_offset=p,
    )
