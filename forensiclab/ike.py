"""IKE/ISAKMP 키 교환 핸드셰이크 파싱 코어 (IKEv1 RFC 2408/2409·IKEv2 RFC 7296).

:mod:`forensiclab.netdissect` 가 식별한 UDP 500(평문)·4500(NAT-T) 페이로드 위에서,
두 호스트가 **IPsec VPN 터널의 키를 협상**하는 ISAKMP 핸드셰이크다.
:mod:`forensiclab.socks` 가 응용 계층 프록시 터널을, :mod:`forensiclab.stun` 이
NAT 통과를 다룬다면, IKE 는 **네트워크 계층 암호 터널(IPsec)의 손잡이** — 터널
자체는 암호화되지만 협상 핸드셰이크의 헤더·일부 페이로드는 평문으로 남는다.

침해/사고 분석에서 IKE 가 드러내는 것:

- **공격자 표적: Aggressive Mode(IKEv1 ET=4)**: 메인 모드(2)가 신원을 암호로
  보호하는 것과 달리 어그레시브 모드는 **신원(ID)과 PSK 인증 해시를 평문**으로
  주고받아, 캡처만으로 ``ike-scan``/``psk-crack`` 오프라인 사전 공격이 가능한
  치명적 오설정이다(``is_aggressive_mode``). 레거시 VPN 게이트웨이의 대표 약점.
- **VPN 종단·세션 귀속(SPI 쿠키)**: 8바이트 Initiator/Responder SPI 는 SA 세션
  식별자 — :mod:`forensiclab.flows` 의 양방향 흐름을 한 협상에 못 박는다.
  Responder SPI 가 전부 0 이면 첫 IKE_SA_INIT(``is_initial``) — 협상 시작 시점.
- **구현 핑거프린트(Vendor ID)**: VID 페이로드(IKEv1 13·IKEv2 43)의 해시는
  구현·기능을 식별한다(Cisco·strongSwan·NAT-T 지원·DPD) — ``vendor_ids`` 의
  16진 해시를 알려진 표와 대조해 VPN 제품·버전 귀속.
- **버전·협상 결과(Notify)**: IKEv1/IKEv2 버전 구분, Notify(알림) 페이로드의
  메시지 타입으로 ``NO_PROPOSAL_CHOSEN``·``AUTHENTICATION_FAILED`` 등 실패/상태
  정황(``notify_types``) — 브루트포스·오설정 단서.
- **NAT-T 마커**: UDP 4500 의 IKE 는 ESP 와 구분하려 앞에 4바이트 0 비-ESP
  마커를 붙인다(``has_non_esp_marker``) — NAT 뒤 VPN 클라이언트 정황.

와이어 포맷 — ISAKMP 헤더(28바이트): Initiator SPI(8)·Responder SPI(8)·
Next Payload(1)·Version(1: MjVer<<4|MnVer)·Exchange Type(1)·Flags(1)·
Message ID(4)·Length(4). 이어 4바이트 제네릭 페이로드 헤더
(Next Payload·Critical+Reserved·Payload Length)로 연결된 페이로드 체인.

설계 원칙(다른 파서와 동일):
- 부작용 없음·stdlib 전용·읽기 전용.
- 견고: 버전/구조가 안 맞으면(비-IKE) 예외 대신 ``None``. 페이로드 체인이 잘리거나
  모순되면(길이 0·버퍼 초과·무한 루프) 받은 데까지만 채우고 멈춘다.
- IKEv1 암호화 플래그·IKEv2 SK 페이로드 이후는 암호문이라 내용을 풀지 않는다.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import List, Optional

__all__ = [
    "IKEV1_EXCHANGES",
    "IKEV2_EXCHANGES",
    "IKEV1_PAYLOADS",
    "IKEV2_PAYLOADS",
    "IkePayload",
    "IkeMessage",
    "looks_like_ike",
    "parse_ike",
]

# IKEv1 교환 타입(RFC 2408 §3.1 + RFC 2409).
IKEV1_EXCHANGES = {
    0: "NONE",
    1: "BASE",
    2: "IDENTITY_PROTECTION",   # Main Mode
    3: "AUTH_ONLY",
    4: "AGGRESSIVE",            # Aggressive Mode (평문 ID·해시 노출)
    5: "INFORMATIONAL",
    32: "QUICK",
    33: "NEW_GROUP",
}
# IKEv2 교환 타입(RFC 7296 §3.1).
IKEV2_EXCHANGES = {
    34: "IKE_SA_INIT",
    35: "IKE_AUTH",
    36: "CREATE_CHILD_SA",
    37: "INFORMATIONAL",
}
# IKEv1 페이로드 타입(RFC 2408).
IKEV1_PAYLOADS = {
    0: "NONE",
    1: "SA",
    2: "PROPOSAL",
    3: "TRANSFORM",
    4: "KE",
    5: "ID",
    6: "CERT",
    7: "CERTREQ",
    8: "HASH",
    9: "SIG",
    10: "NONCE",
    11: "NOTIFY",
    12: "DELETE",
    13: "VENDOR_ID",
    14: "CONFIG",
    15: "NAT_D",
    16: "NAT_OA",
}
# IKEv2 페이로드 타입(RFC 7296 §3.2, 33+).
IKEV2_PAYLOADS = {
    0: "NONE",
    33: "SA",
    34: "KE",
    35: "IDi",
    36: "IDr",
    37: "CERT",
    38: "CERTREQ",
    39: "AUTH",
    40: "NONCE",
    41: "NOTIFY",
    42: "DELETE",
    43: "VENDOR_ID",
    44: "TSi",
    45: "TSr",
    46: "SK",          # Encrypted and Authenticated (이후 암호문)
    47: "CONFIG",
    48: "EAP",
}

# IKEv1 플래그 비트.
_F1_ENCRYPTION = 0x01
_F1_COMMIT = 0x02
_F1_AUTH_ONLY = 0x04
# IKEv2 플래그 비트(RFC 7296 §3.1).
_F2_INITIATOR = 0x08
_F2_VERSION = 0x10
_F2_RESPONSE = 0x20

_ZERO_SPI = b"\x00" * 8
_HDR_LEN = 28


@dataclass(frozen=True)
class IkePayload:
    """파싱된 IKE 페이로드 헤더 한 개(체인의 한 마디).

    Attributes:
        type_code: 페이로드 타입 코드.
        name: 타입 이름(버전별 표 기준; 미지정은 ``"0x.."``).
        length: 페이로드 길이(4바이트 제네릭 헤더 포함).
        offset: 이 페이로드의 시작 오프셋(데이터 기준).
        critical: IKEv2 Critical 비트(미인식 시 거부 요구).
        vendor_id: VID 페이로드의 해시(16진; 그 외 None).
        notify_type: Notify 페이로드의 메시지 타입 코드(그 외 None).
    """

    type_code: int = 0
    name: str = ""
    length: int = 0
    offset: int = 0
    critical: bool = False
    vendor_id: Optional[str] = None
    notify_type: Optional[int] = None


@dataclass(frozen=True)
class IkeMessage:
    """파싱된 ISAKMP/IKE 메시지 한 개.

    Attributes:
        initiator_spi·responder_spi: 8바이트 SPI 쿠키(16진 문자열; 세션 식별).
        version_major·version_minor: 프로토콜 버전(1.x=IKEv1, 2.x=IKEv2).
        exchange_code·exchange: 교환 타입 코드와 이름.
        flags: 원시 플래그 바이트.
        message_id: 메시지 ID(0=IKE_SA_INIT/메인모드 단계).
        length: 헤더가 밝힌 전체 메시지 길이.
        first_payload_code·first_payload: 헤더의 Next Payload(첫 페이로드).
        payloads: 파싱된 페이로드 체인.
        encrypted: 이후 페이로드가 암호문인지(IKEv1 암호화 플래그/IKEv2 SK).
        has_non_esp_marker: UDP 4500 비-ESP 마커(4바이트 0) 선행 여부.
    """

    initiator_spi: str = ""
    responder_spi: str = ""
    version_major: int = 0
    version_minor: int = 0
    exchange_code: int = 0
    exchange: str = ""
    flags: int = 0
    message_id: int = 0
    length: int = 0
    first_payload_code: int = 0
    first_payload: str = ""
    payloads: List[IkePayload] = field(default_factory=list)
    encrypted: bool = False
    has_non_esp_marker: bool = False

    @property
    def is_ikev1(self) -> bool:
        """IKEv1(버전 1.x)인지."""
        return self.version_major == 1

    @property
    def is_ikev2(self) -> bool:
        """IKEv2(버전 2.x)인지."""
        return self.version_major == 2

    @property
    def is_initial(self) -> bool:
        """첫 협상 패킷(Responder SPI 전부 0)인지 — 협상 시작 시점."""
        return self.responder_spi == "0000000000000000"

    @property
    def is_aggressive_mode(self) -> bool:
        """IKEv1 어그레시브 모드인지 — 평문 ID·PSK 해시 노출(오프라인 크래킹)."""
        return self.version_major == 1 and self.exchange_code == 4

    @property
    def is_main_mode(self) -> bool:
        """IKEv1 메인 모드(신원 보호 교환)인지."""
        return self.version_major == 1 and self.exchange_code == 2

    @property
    def is_initiator(self) -> bool:
        """IKEv2 Initiator 플래그가 켜졌는지(요청 측)."""
        return self.version_major == 2 and bool(self.flags & _F2_INITIATOR)

    @property
    def is_response(self) -> bool:
        """IKEv2 Response 플래그가 켜졌는지(응답 측)."""
        return self.version_major == 2 and bool(self.flags & _F2_RESPONSE)

    @property
    def payload_types(self) -> List[str]:
        """페이로드 타입 이름 목록(체인 순서)."""
        return [p.name for p in self.payloads]

    @property
    def vendor_ids(self) -> List[str]:
        """모든 VID 페이로드 해시(16진) — 구현·기능 핑거프린트."""
        return [p.vendor_id for p in self.payloads if p.vendor_id is not None]

    @property
    def notify_types(self) -> List[int]:
        """모든 Notify 페이로드의 메시지 타입 코드 — 실패/상태 정황."""
        return [p.notify_type for p in self.payloads if p.notify_type is not None]


def looks_like_ike(data: bytes, offset: int = 0) -> bool:
    """``offset`` 바이트가 파싱 가능한 IKE 메시지처럼 보이는지(가벼운 가드)."""
    return parse_ike(data, offset) is not None


def _payload_name(version_major: int, code: int) -> str:
    table = IKEV1_PAYLOADS if version_major == 1 else IKEV2_PAYLOADS
    return table.get(code, f"0x{code:02x}")


def _parse_payloads(
    data: bytes, start: int, end: int, first_code: int, version_major: int
) -> "tuple[List[IkePayload], bool]":
    """``start``..``end`` 의 페이로드 체인을 순회. (페이로드들, 암호화도달) 반환."""
    payloads: List[IkePayload] = []
    pos = start
    next_code = first_code
    encrypted = False
    # next_code==0(NONE)이거나 4바이트 헤더가 안 들어가면 종료.
    while next_code != 0 and pos + 4 <= end:
        nxt = data[pos]
        crit_res = data[pos + 1]
        plen = struct.unpack_from(">H", data, pos + 2)[0]
        if plen < 4:                       # 길이 0/비정상 — 무한 루프 방지
            break
        body = data[pos + 4:min(pos + plen, end)]
        vid = None
        ntype = None
        name = _payload_name(version_major, next_code)
        if name == "VENDOR_ID":
            vid = body.hex()
        elif name == "NOTIFY":
            ntype = _notify_type(body, version_major)
        payloads.append(
            IkePayload(
                type_code=next_code,
                name=name,
                length=plen,
                offset=pos,
                critical=bool(crit_res & 0x80),
                vendor_id=vid,
                notify_type=ntype,
            )
        )
        if name == "SK":                   # IKEv2 암호화 페이로드 — 이후 암호문
            encrypted = True
            break
        pos += plen
        next_code = nxt
    return payloads, encrypted


def _notify_type(body: bytes, version_major: int) -> Optional[int]:
    """Notify 페이로드 본문에서 2바이트 Notify Message Type 추출.

    IKEv1: DOI(4)·Protocol-ID(1)·SPI Size(1)·Notify Type(2)…
    IKEv2: Protocol-ID(1)·SPI Size(1)·Notify Type(2)…"""
    pos = 6 if version_major == 1 else 2
    if len(body) < pos + 2:
        return None
    return struct.unpack_from(">H", body, pos)[0]


def parse_ike(data: bytes, offset: int = 0) -> Optional[IkeMessage]:
    """단일 ISAKMP/IKE 메시지를 파싱.

    Args:
        data: IKE 바이트(보통 :mod:`forensiclab.netdissect` UDP 500/4500 페이로드).
        offset: 파싱 시작 위치(기본 0).

    Returns:
        :class:`IkeMessage`. 버전(1/2)·교환 타입이 IKE 구조가 아니면 ``None``.
        UDP 4500 의 4바이트 비-ESP 마커(0)는 자동으로 건너뛰고 표시한다.
        암호화(IKEv1 플래그/IKEv2 SK) 이후 페이로드는 풀지 않는다.
    """
    if not isinstance(data, (bytes, bytearray)):
        return None
    non_esp = False
    # UDP 4500: 4바이트 0 비-ESP 마커 선행(Initiator SPI 는 비-0이므로 구분 가능).
    if len(data) - offset >= _HDR_LEN + 4 and data[offset:offset + 4] == b"\x00\x00\x00\x00":
        offset += 4
        non_esp = True
    if len(data) - offset < _HDR_LEN:
        return None

    init_spi = data[offset:offset + 8]
    resp_spi = data[offset + 8:offset + 16]
    next_payload = data[offset + 16]
    ver = data[offset + 17]
    maj, minr = ver >> 4, ver & 0x0F
    etype = data[offset + 18]
    flags = data[offset + 19]
    msg_id = struct.unpack_from(">I", data, offset + 20)[0]
    length = struct.unpack_from(">I", data, offset + 24)[0]

    # 비-IKE 오탐 가드: 버전 1/2·교환 타입 유효·Initiator SPI 비-0·길이 합리.
    if maj not in (1, 2):
        return None
    if init_spi == _ZERO_SPI:
        return None
    exchanges = IKEV1_EXCHANGES if maj == 1 else IKEV2_EXCHANGES
    if etype not in exchanges:
        return None
    if length < _HDR_LEN:
        return None

    # 암호화 판정: IKEv1 Encryption 플래그면 헤더 뒤 전부 암호문.
    encrypted = maj == 1 and bool(flags & _F1_ENCRYPTION)

    payloads: List[IkePayload] = []
    if not encrypted:
        # 메시지 끝은 헤더 length 와 실제 버퍼 중 작은 쪽(잘림 대응).
        end = min(offset + length, len(data))
        payloads, sk_enc = _parse_payloads(
            data, offset + _HDR_LEN, end, next_payload, maj
        )
        encrypted = sk_enc

    return IkeMessage(
        initiator_spi=init_spi.hex(),
        responder_spi=resp_spi.hex(),
        version_major=maj,
        version_minor=minr,
        exchange_code=etype,
        exchange=exchanges[etype],
        flags=flags,
        message_id=msg_id,
        length=length,
        first_payload_code=next_payload,
        first_payload=_payload_name(maj, next_payload),
        payloads=payloads,
        encrypted=encrypted,
        has_non_esp_marker=non_esp,
    )
