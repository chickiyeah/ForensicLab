"""STUN — NAT 세션 통과 유틸리티 파싱 코어 (RFC 5389/8489).

:mod:`forensiclab.netdissect` 가 식별한 UDP(보통 포트 3478, TLS 는 5349) 페이로드
는 STUN 메시지일 수 있다. 이 모듈이 그 20바이트 고정 헤더와 TLV 속성을 해석한다
(:mod:`forensiclab.ntp` 가 UDP 123, :mod:`forensiclab.dns` 가 UDP 53 을 다루는
것과 같은 위치). STUN 은 WebRTC·VoIP(SIP)·게임 P2P·TURN 릴레이의 토대다.

STUN 은 침해/사고 분석에서 여러 단서를 준다:

- **WebRTC IP 누출(de-anonymization)**: ``XOR-MAPPED-ADDRESS`` 속성은 NAT/방화벽
  바깥에서 본 단말의 **반사 주소(reflexive address)** — 브라우저 WebRTC 는 VPN·
  프록시 뒤에 있어도 STUN 으로 진짜 공인 IP 를 알아낸다. 캡처에서 이 속성을 까면
  단말의 실제 외부 IP·포트가 드러난다(호스트 귀속·익명화 우회 단서).
- **반사·증폭 DDoS 벡터**: 노출된 STUN 서버에 ``Binding`` 요청을 위조 소스로 보내면
  더 큰 응답이 피해자에게 반사된다 — :mod:`forensiclab.ntp`·:mod:`forensiclab.snmp`·
  :mod:`forensiclab.ssdp`·:mod:`forensiclab.memcached`·:mod:`forensiclab.cldap`·
  :mod:`forensiclab.wsd` 와 같은 UDP 반사 형제.
- **TURN 릴레이 터널링**: ``Allocate``/``Send``/``Data``(TURN, RFC 5766) 메서드는
  릴레이 서버를 통한 우회 채널 — C2·데이터 유출이 STUN/TURN 으로 위장될 수 있다.
- **구현 핑거프린트**: ``SOFTWARE`` 속성은 클라이언트/서버 구현·버전 문자열을 노출
  (브라우저·VoIP 클라이언트·멀웨어 식별)·``USERNAME``/``REALM`` 은 자격증명 상관.

STUN 메시지 헤더(RFC 5389 §6, 20바이트)::

    uint16   Message Type     상위 2비트 0 + 14비트(class·method 교직 인코딩)
    uint16   Message Length   속성부 길이(4의 배수)
    uint32   Magic Cookie     고정 0x2112A442 (오탐 가드·XOR 키)
    96비트   Transaction ID   12바이트 트랜잭션 식별자(질의-응답 상관)
    ...      Attributes       TLV(type2·len2·value, 4바이트 패딩) 반복

Message Type 14비트는 class(2비트)와 method(12비트)를 비트 교직으로 싣는다
(RFC 5389 §6): class 비트는 0x0100·0x0010 자리, 나머지가 method.

설계 원칙(:mod:`forensiclab.ntp`·:mod:`forensiclab.dns` 와 동일):
- 부작용 없음: 순수 함수. 디스크/표준출력/네트워크 없음.
- stdlib 전용.
- 안전: 입력 바이트를 변형하지 않는다(읽기 전용).
- 견고: 너무 짧거나 매직 쿠키가 틀린 입력은 예외 대신 ``None``.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import List, Optional, Tuple

__all__ = [
    "STUN_HEADER_SIZE",
    "STUN_MAGIC_COOKIE",
    "STUN_PORT",
    "CLASS_REQUEST",
    "CLASS_INDICATION",
    "CLASS_SUCCESS",
    "CLASS_ERROR",
    "METHOD_BINDING",
    "METHOD_ALLOCATE",
    "ATTR_MAPPED_ADDRESS",
    "ATTR_XOR_MAPPED_ADDRESS",
    "ATTR_SOFTWARE",
    "ATTR_USERNAME",
    "StunAttribute",
    "Stun",
    "parse_stun",
]

STUN_HEADER_SIZE = 20
STUN_MAGIC_COOKIE = 0x2112A442
STUN_PORT = 3478

# Message class (RFC 5389 §6) — type 의 0x0100·0x0010 비트 조합.
CLASS_REQUEST = 0b00
CLASS_INDICATION = 0b01
CLASS_SUCCESS = 0b10   # success response
CLASS_ERROR = 0b11     # error response

_CLASS_NAMES = {
    CLASS_REQUEST: "request",
    CLASS_INDICATION: "indication",
    CLASS_SUCCESS: "success-response",
    CLASS_ERROR: "error-response",
}

# Methods. 0x001 STUN(RFC 5389), 0x003.. TURN(RFC 5766).
METHOD_BINDING = 0x001
METHOD_ALLOCATE = 0x003
METHOD_REFRESH = 0x004
METHOD_SEND = 0x006
METHOD_DATA = 0x007
METHOD_CREATE_PERMISSION = 0x008
METHOD_CHANNEL_BIND = 0x009

_METHOD_NAMES = {
    METHOD_BINDING: "Binding",
    METHOD_ALLOCATE: "Allocate",
    METHOD_REFRESH: "Refresh",
    METHOD_SEND: "Send",
    METHOD_DATA: "Data",
    METHOD_CREATE_PERMISSION: "CreatePermission",
    METHOD_CHANNEL_BIND: "ChannelBind",
}

# TURN 메서드 — 릴레이/터널링 단서.
_TURN_METHODS = frozenset({
    METHOD_ALLOCATE, METHOD_REFRESH, METHOD_SEND,
    METHOD_DATA, METHOD_CREATE_PERMISSION, METHOD_CHANNEL_BIND,
})

# 주요 속성 타입(RFC 5389 §15·8489·5766). 0x0000–0x7FFF comprehension-required.
ATTR_MAPPED_ADDRESS = 0x0001
ATTR_USERNAME = 0x0006
ATTR_MESSAGE_INTEGRITY = 0x0008
ATTR_ERROR_CODE = 0x0009
ATTR_UNKNOWN_ATTRIBUTES = 0x000A
ATTR_REALM = 0x0014
ATTR_NONCE = 0x0015
ATTR_XOR_MAPPED_ADDRESS = 0x0020
ATTR_SOFTWARE = 0x8022
ATTR_ALTERNATE_SERVER = 0x8023
ATTR_FINGERPRINT = 0x8028
ATTR_RESPONSE_ORIGIN = 0x802B
ATTR_OTHER_ADDRESS = 0x802C
# TURN 전용.
ATTR_XOR_RELAYED_ADDRESS = 0x0016
ATTR_XOR_PEER_ADDRESS = 0x0012

_ATTR_NAMES = {
    ATTR_MAPPED_ADDRESS: "MAPPED-ADDRESS",
    ATTR_USERNAME: "USERNAME",
    ATTR_MESSAGE_INTEGRITY: "MESSAGE-INTEGRITY",
    ATTR_ERROR_CODE: "ERROR-CODE",
    ATTR_UNKNOWN_ATTRIBUTES: "UNKNOWN-ATTRIBUTES",
    ATTR_XOR_PEER_ADDRESS: "XOR-PEER-ADDRESS",
    ATTR_REALM: "REALM",
    ATTR_NONCE: "NONCE",
    ATTR_XOR_RELAYED_ADDRESS: "XOR-RELAYED-ADDRESS",
    ATTR_XOR_MAPPED_ADDRESS: "XOR-MAPPED-ADDRESS",
    ATTR_SOFTWARE: "SOFTWARE",
    ATTR_ALTERNATE_SERVER: "ALTERNATE-SERVER",
    ATTR_FINGERPRINT: "FINGERPRINT",
    ATTR_RESPONSE_ORIGIN: "RESPONSE-ORIGIN",
    ATTR_OTHER_ADDRESS: "OTHER-ADDRESS",
}

# 주소를 담는(XOR 디코딩 대상) 속성들.
_ADDRESS_ATTRS = frozenset({
    ATTR_MAPPED_ADDRESS, ATTR_XOR_MAPPED_ADDRESS, ATTR_ALTERNATE_SERVER,
    ATTR_RESPONSE_ORIGIN, ATTR_OTHER_ADDRESS,
    ATTR_XOR_RELAYED_ADDRESS, ATTR_XOR_PEER_ADDRESS,
})
_XOR_ADDRESS_ATTRS = frozenset({
    ATTR_XOR_MAPPED_ADDRESS, ATTR_XOR_RELAYED_ADDRESS, ATTR_XOR_PEER_ADDRESS,
})

_FAMILY_IPV4 = 0x01
_FAMILY_IPV6 = 0x02


def _decode_message_type(mtype: int) -> Tuple[int, int]:
    """14비트 Message Type 을 (class, method)로 푼다(RFC 5389 §6 비트 교직)."""
    # class 비트: C1=0x0100, C0=0x0010.
    msg_class = ((mtype >> 7) & 0b10) | ((mtype >> 4) & 0b01)
    # method 비트: 0x000F | (0x00E0>>1) | (0x3E00>>2).
    method = (mtype & 0x000F) | ((mtype & 0x00E0) >> 1) | ((mtype & 0x3E00) >> 2)
    return msg_class, method


def _decode_address(attr_type: int, value: bytes,
                    transaction_id: bytes) -> Optional[Tuple[str, int]]:
    """주소 속성 값을 (ip, port)로 디코딩. XOR 속성은 매직 쿠키로 역XOR."""
    if len(value) < 4:
        return None
    family = value[1]
    raw_port = struct.unpack(">H", value[2:4])[0]
    addr = value[4:]
    is_xor = attr_type in _XOR_ADDRESS_ATTRS
    if is_xor:
        raw_port ^= STUN_MAGIC_COOKIE >> 16  # 상위 16비트(0x2112).
    if family == _FAMILY_IPV4:
        if len(addr) < 4:
            return None
        octets = bytearray(addr[:4])
        if is_xor:
            cookie = struct.pack(">I", STUN_MAGIC_COOKIE)
            octets = bytearray(a ^ b for a, b in zip(octets, cookie))
        return ".".join(str(b) for b in octets), raw_port
    if family == _FAMILY_IPV6:
        if len(addr) < 16:
            return None
        block = bytearray(addr[:16])
        if is_xor:
            key = struct.pack(">I", STUN_MAGIC_COOKIE) + transaction_id[:12]
            block = bytearray(a ^ b for a, b in zip(block, key))
        words = struct.unpack(">8H", bytes(block))
        return ":".join("%x" % w for w in words), raw_port
    return None


@dataclass(frozen=True)
class StunAttribute:
    """파싱된 STUN TLV 속성(값은 원본 바이트, 패딩 제외)."""

    type: int
    value: bytes

    @property
    def type_name(self) -> str:
        """속성의 사람이 읽는 이름(미상이면 ``"0xNNNN"``)."""
        return _ATTR_NAMES.get(self.type, "0x%04X" % self.type)


@dataclass(frozen=True)
class Stun:
    """파싱된 STUN 메시지(고정 헤더 + 속성 목록).

    Attributes:
        message_type: 원본 14비트 Message Type.
        msg_class: 메시지 클래스(0 request·1 indication·2 success·3 error).
        method: 메서드(0x001 Binding·0x003 Allocate ...).
        length: 헤더가 알린 속성부 길이(바이트).
        transaction_id: 12바이트 트랜잭션 ID(질의-응답 상관).
        attributes: 파싱된 :class:`StunAttribute` 튜플.
    """

    message_type: int
    msg_class: int
    method: int
    length: int
    transaction_id: bytes
    attributes: Tuple[StunAttribute, ...]

    @property
    def class_name(self) -> str:
        """클래스의 사람이 읽는 이름."""
        return _CLASS_NAMES.get(self.msg_class, "class-%d" % self.msg_class)

    @property
    def method_name(self) -> str:
        """메서드의 사람이 읽는 이름(미상이면 ``"method-0xNNN"``)."""
        return _METHOD_NAMES.get(self.method, "method-0x%03X" % self.method)

    @property
    def is_request(self) -> bool:
        """요청 클래스 여부."""
        return self.msg_class == CLASS_REQUEST

    @property
    def is_response(self) -> bool:
        """성공/오류 응답 클래스 여부."""
        return self.msg_class in (CLASS_SUCCESS, CLASS_ERROR)

    @property
    def is_turn(self) -> bool:
        """TURN 릴레이 메서드 여부 — 우회 채널/터널링 단서."""
        return self.method in _TURN_METHODS

    @property
    def is_amplification_request(self) -> bool:
        """Binding 요청 여부 — STUN 반사·증폭 DDoS 벡터(소스 위조 시).

        위조 소스로 다수의 Binding 요청이 노출 서버로 향하면 응답이 피해자에게
        반사·증폭된다(:mod:`forensiclab.ntp` mode6/7·:mod:`forensiclab.cldap`
        rootDSE 질의 계열).
        """
        return self.is_request and self.method == METHOD_BINDING

    def find(self, attr_type: int) -> Optional[StunAttribute]:
        """주어진 타입의 첫 속성(없으면 ``None``)."""
        for attr in self.attributes:
            if attr.type == attr_type:
                return attr
        return None

    @property
    def mapped_address(self) -> Optional[Tuple[str, int]]:
        """반사 주소 (ip, port) — XOR-MAPPED-ADDRESS 우선, 없으면 MAPPED-ADDRESS.

        WebRTC IP 누출/호스트 귀속의 핵심 단서: NAT 바깥에서 본 단말 공인 주소.
        """
        attr = self.find(ATTR_XOR_MAPPED_ADDRESS) or self.find(ATTR_MAPPED_ADDRESS)
        if attr is None:
            return None
        return _decode_address(attr.type, attr.value, self.transaction_id)

    @property
    def relayed_address(self) -> Optional[Tuple[str, int]]:
        """TURN 릴레이 할당 주소 (ip, port) — XOR-RELAYED-ADDRESS(없으면 ``None``)."""
        attr = self.find(ATTR_XOR_RELAYED_ADDRESS)
        if attr is None:
            return None
        return _decode_address(attr.type, attr.value, self.transaction_id)

    @property
    def software(self) -> Optional[str]:
        """SOFTWARE 속성 문자열 — 구현/버전 핑거프린트(없으면 ``None``)."""
        attr = self.find(ATTR_SOFTWARE)
        if attr is None:
            return None
        try:
            return attr.value.decode("utf-8").rstrip("\x00")
        except UnicodeDecodeError:
            return attr.value.hex()

    @property
    def username(self) -> Optional[str]:
        """USERNAME 속성 문자열 — 자격증명 상관 단서(없으면 ``None``)."""
        attr = self.find(ATTR_USERNAME)
        if attr is None:
            return None
        try:
            return attr.value.decode("utf-8").rstrip("\x00")
        except UnicodeDecodeError:
            return attr.value.hex()


def parse_stun(data: bytes, offset: int = 0) -> Optional[Stun]:
    """원시 바이트에서 STUN 메시지를 파싱한다.

    Args:
        data: STUN 메시지를 담은 바이트. 보통 UDP 3478 페이로드
            (:class:`forensiclab.netdissect` 의 ``payload_offset`` 부터)다.
        offset: 메시지가 시작하는 위치(기본 0).

    Returns:
        :class:`Stun`. 헤더(20바이트)에 못 미치거나, 상위 2비트가 0이 아니거나,
        매직 쿠키가 ``0x2112A442`` 가 아니면(고전 RFC 3489·비-STUN 오탐 가드)
        ``None``.
    """
    if offset < 0 or offset + STUN_HEADER_SIZE > len(data):
        return None
    mtype, length, cookie = struct.unpack(">HHI", data[offset:offset + 8])
    # 상위 2비트는 반드시 0(STUN 식별), 매직 쿠키 검증(오탐 방지).
    if mtype & 0xC000:
        return None
    if cookie != STUN_MAGIC_COOKIE:
        return None
    transaction_id = data[offset + 8:offset + 20]
    msg_class, method = _decode_message_type(mtype)

    attributes: List[StunAttribute] = []
    pos = offset + STUN_HEADER_SIZE
    end = pos + length
    # 알린 길이가 버퍼를 넘으면 가용분까지만.
    if end > len(data):
        end = len(data)
    while pos + 4 <= end:
        atype, alen = struct.unpack(">HH", data[pos:pos + 4])
        pos += 4
        if pos + alen > end:
            # 잘린 속성 — 가용분만 담고 중단.
            attributes.append(StunAttribute(type=atype, value=data[pos:end]))
            break
        attributes.append(StunAttribute(type=atype, value=data[pos:pos + alen]))
        pos += alen
        # 4바이트 경계 패딩.
        pad = (4 - (alen % 4)) % 4
        pos += pad

    return Stun(
        message_type=mtype,
        msg_class=msg_class,
        method=method,
        length=length,
        transaction_id=transaction_id,
        attributes=tuple(attributes),
    )
