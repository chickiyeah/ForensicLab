"""SOCKS 프록시 핸드셰이크 파싱 코어 (SOCKS4/4a RFC 1928 이전·SOCKS5 RFC 1928).

:mod:`forensiclab.netdissect` 가 식별한 TCP 페이로드 위에서, 한 호스트가 다른
호스트를 **대신해 임의의 목적지로 연결을 중계**하도록 요청하는 프록시 협상이다.
HTTP CONNECT 프록시(:mod:`forensiclab.http`)가 평문 헤더로 터널을 여는 것과 달리
SOCKS 는 바이트 지향 바이너리 핸드셰이크라 별도 해석이 필요하다.

침해/사고 분석에서 SOCKS 는 **피벗(pivoting)·터널링의 손잡이**다 — 공격자가
내부망 깊숙이 들어와 ``proxychains``·Tor·SSH ``-D`` 동적 포워딩·멀웨어 내장
SOCKS 서버로 트래픽을 우회시키는 그 순간이 핸드셰이크에 평문으로 남는다:

- **목적지 귀속(C2·측면 이동 표적)**: 요청의 ``dst_host``/``dst_port`` 는 터널이
  향하는 실제 목적지 — :mod:`forensiclab.flows` 의 프록시까지의 흐름 너머
  **진짜 종착지**를 드러낸다. SOCKS4a·SOCKS5 의 ``ATYP=domain`` 은 목적지를
  **도메인 이름 그대로** 실어(``is_hostname_target``) DNS(:mod:`forensiclab.dns`)
  질의가 캡처에 없어도 C2 도메인을 노출한다(원격 DNS 해석).
- **무인증 열린 프록시**: SOCKS5 그리팅의 제공 메서드에 ``NO_AUTH``(0x00)가 있으면
  (``offers_no_auth``) 누구나 쓸 수 있는 열린 중계 — 멀웨어 내장 프록시·오설정
  정황. ``USERNAME_PASSWORD``(0x02) 제공은 평문 자격증명 인증 단계 예고
  (:mod:`forensiclab.ftp` USER/PASS 계열).
- **사용자 귀속(SOCKS4 USERID)**: SOCKS4 요청 끝의 NUL 종단 ``userid`` 는 호출
  측이 자기 신고하는 식별자(:mod:`forensiclab.ident` USERID 결, 위조 가능).
- **데이터 유출 채널(UDP ASSOCIATE)**: SOCKS5 ``CMD=3``(``is_udp_associate``)은
  UDP 릴레이를 열어 DNS 터널·실시간 미디어·대역외 유출 경로가 된다
  (:mod:`forensiclab.stun` TURN 릴레이 터널링 결).

와이어 포맷(클라이언트 측 핵심 메시지):

- **SOCKS4 요청**: ``VN=4``·``CD``(1 CONNECT·2 BIND)·DSTPORT(2)·DSTIP(4)·
  NUL 종단 USERID. DSTIP 가 ``0.0.0.x``(첫 3바이트 0, 끝 비0)면 **SOCKS4a** —
  USERID NUL 다음에 NUL 종단 도메인이 이어진다.
- **SOCKS4 응답**: ``VN=0``·CD(90 granted·91 rejected·92/93)·DSTPORT·DSTIP.
- **SOCKS5 그리팅**: ``VER=5``·NMETHODS·메서드 목록.
- **SOCKS5 요청**: ``VER=5``·``CMD``(1·2·3)·``RSV=0``·``ATYP``(1 IPv4·3 도메인·
  4 IPv6)·DST.ADDR·DST.PORT(2).

SOCKS5 그리팅과 요청은 둘 다 ``0x05`` 로 시작해 본질적으로 모호하다. 요청은
``RSV==0``·유효 CMD·유효 ATYP 구조에 더해 그 ATYP 가 요구하는 **최소 길이를
모두 충족**할 때만 요청으로 판정하고(짧은 그리팅의 오판 방지), 그 외에는
그리팅으로 본다.

설계 원칙(다른 파서와 동일):
- 부작용 없음·stdlib 전용·읽기 전용.
- 견고: 버전/구조가 안 맞으면(비-SOCKS) 예외 대신 ``None``. 가변 필드가 잘리면
  받은 데까지만 채운다(버퍼 초과 인덱싱 금지).
"""

from __future__ import annotations

import socket
import struct
from dataclasses import dataclass, field
from typing import List, Optional

__all__ = [
    "SOCKS4_COMMANDS",
    "SOCKS5_COMMANDS",
    "SOCKS5_METHODS",
    "SOCKS4_REPLY_CODES",
    "SocksMessage",
    "looks_like_socks",
    "parse_socks",
]

# SOCKS4 명령 코드(CD).
SOCKS4_COMMANDS = {1: "CONNECT", 2: "BIND"}
# SOCKS5 명령 코드(CMD).
SOCKS5_COMMANDS = {1: "CONNECT", 2: "BIND", 3: "UDP_ASSOCIATE"}
# SOCKS5 인증 메서드(그리팅 METHODS / 서버 선택값).
SOCKS5_METHODS = {
    0: "NO_AUTH",
    1: "GSSAPI",
    2: "USERNAME_PASSWORD",
    255: "NO_ACCEPTABLE",
}
# SOCKS4 응답 코드(VN=0 응답의 CD).
SOCKS4_REPLY_CODES = {
    90: "GRANTED",
    91: "REJECTED",
    92: "NO_IDENTD",
    93: "IDENTD_MISMATCH",
}
# SOCKS5 주소 타입(ATYP).
_ATYP = {1: "ipv4", 3: "domain", 4: "ipv6"}


def _ipv6(raw: bytes) -> str:
    """16바이트를 IPv6 문자열로(플랫폼 의존 inet_ntop 실패 시 hex 폴백)."""
    try:
        return socket.inet_ntop(socket.AF_INET6, raw)
    except (OSError, ValueError):
        return raw.hex()


def _cstr(data: bytes, start: int) -> "tuple[str, int]":
    """``start`` 부터 NUL 종단 문자열을 읽고 (문자열, NUL 다음 인덱스) 반환.

    NUL 이 없으면(잘림) 끝까지 읽고 인덱스는 len(data)."""
    i = start
    while i < len(data) and data[i] != 0:
        i += 1
    text = data[start:i].decode("latin-1", "replace")
    return text, (i + 1 if i < len(data) else i)


@dataclass(frozen=True)
class SocksMessage:
    """파싱된 SOCKS 메시지 한 개.

    Attributes:
        version: 프로토콜 버전(4 또는 5; SOCKS4 응답은 VN=0 이나 4 로 정규화).
        kind: 메시지 종류 — ``"request"``·``"greeting"``·``"reply"``.
        command_code·command: 명령 코드와 이름(요청; CONNECT/BIND/UDP_ASSOCIATE).
        address_type: 목적지 주소 타입(``"ipv4"``·``"domain"``·``"ipv6"``).
        dst_host: 목적지 호스트(IP 문자열 또는 도메인; 터널 종착지).
        dst_port: 목적지 포트.
        userid: SOCKS4 요청의 NUL 종단 USERID(자기 신고 식별자).
        is_socks4a: SOCKS4a(DSTIP 0.0.0.x → 도메인 동봉)인지.
        auth_method_codes·auth_methods: SOCKS5 그리팅 제공 메서드(코드/이름).
        reply_code·reply_status: SOCKS4 응답 코드/상태.
    """

    version: int = 0
    kind: str = ""
    command_code: Optional[int] = None
    command: Optional[str] = None
    address_type: Optional[str] = None
    dst_host: Optional[str] = None
    dst_port: Optional[int] = None
    userid: Optional[str] = None
    is_socks4a: bool = False
    auth_method_codes: List[int] = field(default_factory=list)
    auth_methods: List[str] = field(default_factory=list)
    reply_code: Optional[int] = None
    reply_status: Optional[str] = None

    @property
    def is_request(self) -> bool:
        """연결 요청(목적지 포함)인지."""
        return self.kind == "request"

    @property
    def is_greeting(self) -> bool:
        """SOCKS5 그리팅(메서드 협상)인지."""
        return self.kind == "greeting"

    @property
    def is_connect(self) -> bool:
        """CONNECT 명령(아웃바운드 터널)인지."""
        return self.command == "CONNECT"

    @property
    def is_bind(self) -> bool:
        """BIND 명령(인바운드 대기 — FTP 액티브·역연결)인지."""
        return self.command == "BIND"

    @property
    def is_udp_associate(self) -> bool:
        """UDP ASSOCIATE 명령(UDP 릴레이 — DNS 터널·대역외 유출 채널)인지."""
        return self.command == "UDP_ASSOCIATE"

    @property
    def is_hostname_target(self) -> bool:
        """목적지가 IP 가 아니라 **도메인 이름**인지(원격 DNS — C2 도메인 노출)."""
        return self.address_type == "domain" or self.is_socks4a

    @property
    def offers_no_auth(self) -> bool:
        """SOCKS5 그리팅이 무인증(NO_AUTH)을 제공하는지(열린 중계 정황)."""
        return 0 in self.auth_method_codes

    @property
    def offers_userpass(self) -> bool:
        """SOCKS5 그리팅이 사용자/비밀번호 인증을 제공하는지(평문 자격증명 예고)."""
        return 2 in self.auth_method_codes

    @property
    def target(self) -> Optional[str]:
        """``host:port`` 편의 문자열(목적지가 있을 때)."""
        if self.dst_host is None or self.dst_port is None:
            return None
        host = f"[{self.dst_host}]" if self.address_type == "ipv6" else self.dst_host
        return f"{host}:{self.dst_port}"


def _is_socks5_request(data: bytes, offset: int) -> bool:
    """``offset`` 의 SOCKS5 바이트가 그리팅이 아니라 요청 구조인지(길이 포함 판정).

    요청은 ``RSV==0``·유효 CMD·유효 ATYP 에 더해 그 ATYP 가 요구하는 최소 길이를
    모두 충족할 때만 참 — 짧은 그리팅(예: ``05 03 00 01 02``)의 오판을 막는다."""
    if len(data) - offset < 4:
        return False
    cmd, rsv, atyp = data[offset + 1], data[offset + 2], data[offset + 3]
    if cmd not in SOCKS5_COMMANDS or rsv != 0 or atyp not in _ATYP:
        return False
    if atyp == 1:
        need = 10                       # 4 헤더 + 4 IPv4 + 2 포트
    elif atyp == 4:
        need = 22                       # 4 헤더 + 16 IPv6 + 2 포트
    else:                               # 도메인
        if len(data) - offset < 5:
            return False
        need = 4 + 1 + data[offset + 4] + 2
    return len(data) - offset >= need


def looks_like_socks(data: bytes, offset: int = 0) -> bool:
    """``offset`` 바이트가 파싱 가능한 SOCKS 메시지처럼 보이는지(가벼운 가드)."""
    return parse_socks(data, offset) is not None


def _parse_socks4_request(data: bytes, offset: int) -> Optional[SocksMessage]:
    cd = data[offset + 1]
    if cd not in SOCKS4_COMMANDS:
        return None
    port = struct.unpack_from(">H", data, offset + 2)[0]
    ip4 = data[offset + 4:offset + 8]
    userid, after = _cstr(data, offset + 8)
    is_4a = ip4[0:3] == b"\x00\x00\x00" and ip4[3] != 0
    if is_4a:
        host, _ = _cstr(data, after)
        atype = "domain"
    else:
        host = socket.inet_ntoa(ip4)
        atype = "ipv4"
    return SocksMessage(
        version=4,
        kind="request",
        command_code=cd,
        command=SOCKS4_COMMANDS[cd],
        address_type=atype,
        dst_host=host,
        dst_port=port,
        userid=userid,
        is_socks4a=is_4a,
    )


def _parse_socks4_reply(data: bytes, offset: int) -> Optional[SocksMessage]:
    cd = data[offset + 1]
    if cd not in SOCKS4_REPLY_CODES:
        return None
    port = struct.unpack_from(">H", data, offset + 2)[0]
    host = socket.inet_ntoa(data[offset + 4:offset + 8])
    return SocksMessage(
        version=4,
        kind="reply",
        address_type="ipv4",
        dst_host=host,
        dst_port=port,
        reply_code=cd,
        reply_status=SOCKS4_REPLY_CODES[cd],
    )


def _parse_socks5_request(data: bytes, offset: int) -> SocksMessage:
    cmd, atyp = data[offset + 1], data[offset + 3]
    p = offset + 4
    if atyp == 1:
        host = socket.inet_ntoa(data[p:p + 4])
        p += 4
    elif atyp == 4:
        host = _ipv6(data[p:p + 16])
        p += 16
    else:  # 도메인
        dlen = data[p]
        p += 1
        host = data[p:p + dlen].decode("latin-1", "replace")
        p += dlen
    port = struct.unpack_from(">H", data, p)[0]
    return SocksMessage(
        version=5,
        kind="request",
        command_code=cmd,
        command=SOCKS5_COMMANDS[cmd],
        address_type=_ATYP[atyp],
        dst_host=host,
        dst_port=port,
    )


def _parse_socks5_greeting(data: bytes, offset: int) -> Optional[SocksMessage]:
    if len(data) - offset < 2:
        return None
    nmethods = data[offset + 1]
    if nmethods == 0:
        return None
    methods = list(data[offset + 2:offset + 2 + nmethods])  # 잘리면 가용분까지
    return SocksMessage(
        version=5,
        kind="greeting",
        auth_method_codes=methods,
        auth_methods=[SOCKS5_METHODS.get(m, f"0x{m:02x}") for m in methods],
    )


def parse_socks(data: bytes, offset: int = 0) -> Optional[SocksMessage]:
    """단일 SOCKS 메시지를 파싱.

    Args:
        data: SOCKS 바이트(보통 :mod:`forensiclab.netdissect` TCP 페이로드).
        offset: 파싱 시작 위치(기본 0).

    Returns:
        :class:`SocksMessage`. 버전/구조가 SOCKS 가 아니면(가드) ``None``.
        SOCKS5 는 요청 구조+최소 길이를 충족하면 요청, 아니면 그리팅으로 본다.
        SOCKS4(VN=4)/SOCKS4 응답(VN=0)은 명령/응답 코드로 검증한다.
    """
    if not isinstance(data, (bytes, bytearray)):
        return None
    if len(data) - offset < 2:
        return None
    ver = data[offset]
    if ver == 4:
        if len(data) - offset < 8:
            return None
        return _parse_socks4_request(data, offset)
    if ver == 0:
        if len(data) - offset < 8:
            return None
        return _parse_socks4_reply(data, offset)
    if ver == 5:
        if _is_socks5_request(data, offset):
            return _parse_socks5_request(data, offset)
        return _parse_socks5_greeting(data, offset)
    return None
