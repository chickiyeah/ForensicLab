"""RADIUS — AAA 인증·과금 프로토콜 파싱 코어 (RFC 2865 / 2866).

:mod:`forensiclab.netdissect` 가 식별한 UDP(포트 1812 인증 / 1813 과금,
구형은 1645/1646) 페이로드는 RADIUS 패킷일 수 있다. 이 모듈이 그 메시지를
해석한다(:mod:`forensiclab.dns` 가 UDP 53, :mod:`forensiclab.ntp` 가 UDP 123,
:mod:`forensiclab.tftp` 가 UDP 69 를 다루는 것과 같은 위치).

RADIUS 는 NAS(스위치·VPN·Wi-Fi AP)와 인증 서버 사이의 AAA 대화라 침해/사고
분석에서 "누가·어디서·언제 로그인했나" 를 복원하는 핵심 단서다
(:mod:`forensiclab.syslog` 의 인증 실패 로그와 짝지어 본다):

- **인증 성공/실패**: Access-Accept(2) 대 Access-Reject(3). 같은 User-Name
  으로 Access-Request(1) 가 반복되고 Reject 가 이어지면 브루트포스·패스워드
  스프레이 정황이다.
- **계정 식별**: User-Name(1) 속성은 시도된 계정명이다(평문). User-Password(2)
  는 공유 비밀로 암호화돼 있어 복호하지 않는다(읽기 전용 원칙).
- **호스트 상관**: Calling-Station-Id(31) 는 보통 클라이언트 MAC/번호,
  NAS-IP-Address(4)·NAS-Identifier(32) 는 인증을 중계한 장비다
  (:mod:`forensiclab.arp`·:mod:`forensiclab.dhcp` 의 MAC↔IP 매핑과 교차).
- **세션 타임라인**: 과금(Acct-Status-Type 40 의 Start/Stop)·Framed-IP-
  Address(8) 는 세션 시작/종료·할당 IP 를 드러내 :mod:`forensiclab.timeline`
  재구성에 쓰인다.

RADIUS 패킷 포맷(RFC 2865 §3)::

    code(1) | identifier(1) | length(2) | authenticator(16) | attributes...

length 는 빅엔디언 16비트(헤더 20바이트 포함, 전체 패킷 길이). 속성은 TLV::

    type(1) | length(1, type+length+value 합) | value(length-2)

설계 원칙(:mod:`forensiclab.tftp`·:mod:`forensiclab.ntp` 와 동일):
- 부작용 없음: 순수 함수. 디스크/표준출력/네트워크 없음.
- stdlib 전용.
- 안전: 입력 바이트를 변형하지 않는다(읽기 전용). 비밀은 복호하지 않는다.
- 견고: 너무 짧거나 망가진 입력은 예외 대신 ``None``.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

__all__ = [
    "RADIUS_CODE_ACCESS_REQUEST",
    "RADIUS_CODE_ACCESS_ACCEPT",
    "RADIUS_CODE_ACCESS_REJECT",
    "RADIUS_CODE_ACCOUNTING_REQUEST",
    "RADIUS_CODE_ACCOUNTING_RESPONSE",
    "RADIUS_CODE_ACCESS_CHALLENGE",
    "RADIUS_ATTR_USER_NAME",
    "RADIUS_ATTR_NAS_IP_ADDRESS",
    "RADIUS_ATTR_FRAMED_IP_ADDRESS",
    "RADIUS_ATTR_CALLED_STATION_ID",
    "RADIUS_ATTR_CALLING_STATION_ID",
    "RADIUS_ATTR_NAS_IDENTIFIER",
    "RADIUS_ATTR_ACCT_STATUS_TYPE",
    "RADIUS_ATTR_ACCT_SESSION_ID",
    "RadiusAttr",
    "Radius",
    "parse_radius",
]

# code (RFC 2865 §3, RFC 2866 §3).
RADIUS_CODE_ACCESS_REQUEST = 1       # NAS→서버: 인증 요청(User-Name 담음).
RADIUS_CODE_ACCESS_ACCEPT = 2        # 서버→NAS: 인증 성공.
RADIUS_CODE_ACCESS_REJECT = 3        # 서버→NAS: 인증 실패(브루트포스 단서).
RADIUS_CODE_ACCOUNTING_REQUEST = 4   # NAS→서버: 세션 과금(Start/Stop).
RADIUS_CODE_ACCOUNTING_RESPONSE = 5  # 서버→NAS: 과금 확인.
RADIUS_CODE_ACCESS_CHALLENGE = 11    # 서버→NAS: 추가 인증 요구.

_CODE_NAMES = {
    RADIUS_CODE_ACCESS_REQUEST: "Access-Request",
    RADIUS_CODE_ACCESS_ACCEPT: "Access-Accept",
    RADIUS_CODE_ACCESS_REJECT: "Access-Reject",
    RADIUS_CODE_ACCOUNTING_REQUEST: "Accounting-Request",
    RADIUS_CODE_ACCOUNTING_RESPONSE: "Accounting-Response",
    RADIUS_CODE_ACCESS_CHALLENGE: "Access-Challenge",
    12: "Status-Server",
    13: "Status-Client",
}

# 정상 code 범위 — 그 밖은 RADIUS 가 아닐 가능성이 높다.
_VALID_CODES = frozenset(_CODE_NAMES)

# 자주 쓰이는 속성 타입(RFC 2865 §5, RFC 2866 §5).
RADIUS_ATTR_USER_NAME = 1            # 시도된 계정명(평문).
RADIUS_ATTR_NAS_IP_ADDRESS = 4      # 인증을 중계한 NAS 의 IP(4바이트).
RADIUS_ATTR_FRAMED_IP_ADDRESS = 8   # 사용자에게 할당된 IP(4바이트).
RADIUS_ATTR_CALLED_STATION_ID = 30  # 접속 대상(AP MAC/번호).
RADIUS_ATTR_CALLING_STATION_ID = 31  # 클라이언트 MAC/번호(호스트 상관).
RADIUS_ATTR_NAS_IDENTIFIER = 32     # NAS 의 문자열 식별자.
RADIUS_ATTR_ACCT_STATUS_TYPE = 40   # 과금 상태(1=Start, 2=Stop, …).
RADIUS_ATTR_ACCT_SESSION_ID = 44    # 세션 식별자(타임라인 상관).

# 문자열로 디코드해 보여 줄 텍스트 속성(latin-1, 무손실).
_TEXT_ATTRS = frozenset({
    RADIUS_ATTR_USER_NAME,
    RADIUS_ATTR_CALLED_STATION_ID,
    RADIUS_ATTR_CALLING_STATION_ID,
    RADIUS_ATTR_NAS_IDENTIFIER,
    RADIUS_ATTR_ACCT_SESSION_ID,
})

# 4바이트 IPv4 주소로 디코드할 속성.
_IP_ATTRS = frozenset({
    RADIUS_ATTR_NAS_IP_ADDRESS,
    RADIUS_ATTR_FRAMED_IP_ADDRESS,
})

# Acct-Status-Type(40) 값 이름(RFC 2866 §5.1).
_ACCT_STATUS_NAMES = {
    1: "Start",
    2: "Stop",
    3: "Interim-Update",
    7: "Accounting-On",
    8: "Accounting-Off",
}


@dataclass(frozen=True)
class RadiusAttr:
    """파싱된 RADIUS 속성(TLV) 하나.

    Attributes:
        type: 속성 타입 번호(RFC 2865 §5).
        value: 원본 값 바이트(헤더 2바이트 제외). 변형하지 않는다.
    """

    type: int
    value: bytes

    def as_text(self) -> str:
        """값을 latin-1 문자열로(텍스트 속성용, 무손실 1:1 디코드)."""
        return self.value.decode("latin-1")

    def as_ipv4(self) -> Optional[str]:
        """값이 4바이트면 점10진 IPv4 문자열로, 아니면 ``None``."""
        if len(self.value) != 4:
            return None
        return ".".join(str(b) for b in self.value)

    def as_uint32(self) -> Optional[int]:
        """값이 4바이트면 빅엔디언 부호 없는 32비트 정수로, 아니면 ``None``."""
        if len(self.value) != 4:
            return None
        return struct.unpack(">I", self.value)[0]


@dataclass(frozen=True)
class Radius:
    """파싱된 RADIUS 메시지.

    Attributes:
        code: 메시지 종류(:data:`RADIUS_CODE_ACCESS_REQUEST` 등).
        identifier: 요청/응답을 짝짓는 1바이트 ID.
        length: 헤더가 선언한 전체 패킷 길이(바이트).
        authenticator: 16바이트 Authenticator 필드.
        attributes: 등장 순서대로의 :class:`RadiusAttr` 목록.
    """

    code: int
    identifier: int
    length: int
    authenticator: bytes
    attributes: List[RadiusAttr] = field(default_factory=list)

    @property
    def code_name(self) -> str:
        """code 의 사람이 읽는 이름(미상이면 ``"code-<n>"``)."""
        return _CODE_NAMES.get(self.code, f"code-{self.code}")

    @property
    def is_request(self) -> bool:
        """Access-Request 여부 — 인증을 여는 패킷(User-Name 을 담는다)."""
        return self.code == RADIUS_CODE_ACCESS_REQUEST

    @property
    def is_accept(self) -> bool:
        """Access-Accept 여부 — 인증 성공."""
        return self.code == RADIUS_CODE_ACCESS_ACCEPT

    @property
    def is_reject(self) -> bool:
        """Access-Reject 여부 — 인증 실패(브루트포스·스프레이 단서)."""
        return self.code == RADIUS_CODE_ACCESS_REJECT

    def get(self, attr_type: int) -> Optional[RadiusAttr]:
        """타입이 ``attr_type`` 인 첫 속성을 반환(없으면 ``None``)."""
        for attr in self.attributes:
            if attr.type == attr_type:
                return attr
        return None

    def get_all(self, attr_type: int) -> List[RadiusAttr]:
        """타입이 ``attr_type`` 인 모든 속성을(등장 순서대로) 반환."""
        return [a for a in self.attributes if a.type == attr_type]

    @property
    def user_name(self) -> Optional[str]:
        """User-Name(1) — 시도된 계정명(없으면 ``None``)."""
        attr = self.get(RADIUS_ATTR_USER_NAME)
        return attr.as_text() if attr is not None else None

    @property
    def calling_station_id(self) -> Optional[str]:
        """Calling-Station-Id(31) — 클라이언트 MAC/번호(호스트 상관 단서)."""
        attr = self.get(RADIUS_ATTR_CALLING_STATION_ID)
        return attr.as_text() if attr is not None else None

    @property
    def nas_ip_address(self) -> Optional[str]:
        """NAS-IP-Address(4) — 인증을 중계한 장비 IP(점10진 문자열)."""
        attr = self.get(RADIUS_ATTR_NAS_IP_ADDRESS)
        return attr.as_ipv4() if attr is not None else None

    @property
    def acct_status(self) -> Optional[str]:
        """Acct-Status-Type(40) — 과금 상태 이름(Start/Stop 등) 또는 ``None``."""
        attr = self.get(RADIUS_ATTR_ACCT_STATUS_TYPE)
        if attr is None:
            return None
        value = attr.as_uint32()
        if value is None:
            return None
        return _ACCT_STATUS_NAMES.get(value, f"status-{value}")


def _parse_attributes(body: bytes) -> List[RadiusAttr]:
    """속성 영역(TLV 연속)을 :class:`RadiusAttr` 목록으로.

    각 속성은 ``type(1) | length(1) | value(length-2)``. length 가 2 미만
    이거나 남은 바이트를 넘으면(망가진 패킷) 거기서 멈춘다.
    """
    out: List[RadiusAttr] = []
    i = 0
    n = len(body)
    while i + 2 <= n:
        attr_type = body[i]
        attr_len = body[i + 1]
        if attr_len < 2 or i + attr_len > n:
            break
        out.append(RadiusAttr(type=attr_type, value=bytes(body[i + 2:i + attr_len])))
        i += attr_len
    return out


def parse_radius(data: bytes, offset: int = 0) -> Optional[Radius]:
    """원시 바이트에서 RADIUS 메시지를 파싱한다.

    Args:
        data: RADIUS 패킷을 담은 바이트. 보통 UDP 1812/1813 페이로드
            (:class:`forensiclab.netdissect` 의 ``payload_offset`` 부터)다.
        offset: 패킷이 시작하는 위치(기본 0).

    Returns:
        :class:`Radius`. 20바이트 헤더조차 없거나 code 가 유효 범위 밖이면
        ``None``. ``length`` 가 헤더보다 짧거나 가용 바이트를 넘으면 가용
        범위로 잘라 속성을 파싱한다(견고성).
    """
    if offset < 0 or offset + 20 > len(data):
        return None
    code, identifier, length = struct.unpack(">BBH", data[offset:offset + 4])
    if code not in _VALID_CODES:
        return None
    authenticator = bytes(data[offset + 4:offset + 20])

    # length 는 헤더가 선언한 전체 길이. 신뢰하되 가용 바이트로 한정한다.
    available_end = len(data)
    declared_end = offset + length if length >= 20 else available_end
    body_end = min(declared_end, available_end)
    body = data[offset + 20:body_end]

    return Radius(
        code=code,
        identifier=identifier,
        length=length,
        authenticator=authenticator,
        attributes=_parse_attributes(body),
    )
