"""TLS ClientHello 파싱 코어 — SNI·ALPN·핑거프린트 단서 추출.

:mod:`forensiclab.http` 가 평문 HTTP 의 ``Host`` 헤더로 "어떤 호스트에
접속했는가" 를 알려 준다면, HTTPS 트래픽에서는 그 호스트 이름이 암호화되어
보이지 않는다. 단 하나의 예외가 TLS 핸드셰이크 맨 앞 ClientHello 의 **SNI
(Server Name Indication)** 확장으로, 클라이언트가 어떤 도메인에 붙으려는지를
*평문으로* 노출한다. 침해 분석에서 SNI 는 DNS 질의·HTTP Host 와 더불어
C2 비콘·데이터 유출 목적지를 식별하는 핵심 단서다.

이 모듈은 :mod:`forensiclab.flows` 가 같은 대화의 클라이언트→서버 TCP
페이로드를 이어 붙여 만든 바이트(보통 443 포트)를 받아 ClientHello 를
구조화한다. 함께 뽑는 단서:

- ``server_name`` — SNI 확장(type 0x0000)의 host_name. 접속 목적지.
- ``alpn`` — ALPN 확장(type 0x0010)의 프로토콜 목록(``h2``, ``http/1.1`` 등).
- ``cipher_suites`` / ``extensions`` — 제시된 암호 스위트·확장 type 목록.
  JA3 류 클라이언트 핑거프린팅의 입력이 되어, 같은 멀웨어가 만드는 동일한
  핸드셰이크 형태를 도메인과 무관하게 묶어낼 수 있다.

지원 범위(증분을 작게 유지):
- TLS record(content_type 0x16=handshake) 한 개 안의 ClientHello 만 다룬다.
  레코드 분할(여러 record 에 걸친 핸드셰이크)·재조립은 다루지 않는다.
- 확장 중 SNI·ALPN 만 의미 해석하고, 나머지는 type id 만 수집한다.

설계 원칙(:mod:`forensiclab.dns`·:mod:`forensiclab.http` 와 동일):
- 부작용 없음: 디스크/표준출력 없이 순수 함수.
- stdlib 전용: 외부 의존성 없음.
- 안전: 입력 바이트를 변형하지 않는다(읽기 전용).
- 견고: 잘리거나 망가진 입력은 예외 대신 ``None`` 으로 둔다(부분 수신 흔함).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional, Tuple

__all__ = [
    "ContentType",
    "HandshakeType",
    "ExtensionType",
    "ClientHello",
    "ServerHello",
    "parse_client_hello",
    "parse_server_hello",
]

# TLS record content type. 핸드셰이크만 ClientHello 를 담는다.
ContentType_HANDSHAKE = 0x16


class ContentType:
    """TLS record content type 상수(자주 쓰는 것만)."""

    CHANGE_CIPHER_SPEC = 0x14
    ALERT = 0x15
    HANDSHAKE = 0x16
    APPLICATION_DATA = 0x17


class HandshakeType:
    """TLS handshake message type 상수(자주 쓰는 것만)."""

    CLIENT_HELLO = 0x01
    SERVER_HELLO = 0x02


class ExtensionType:
    """의미 해석하는 확장 type 상수."""

    SERVER_NAME = 0x0000  # SNI.
    SUPPORTED_GROUPS = 0x000A  # elliptic_curves. JA3 입력.
    EC_POINT_FORMATS = 0x000B  # ec_point_formats. JA3 입력.
    ALPN = 0x0010  # application_layer_protocol_negotiation.
    SUPPORTED_VERSIONS = 0x002B  # ServerHello 에서 협상된 실제 TLS 버전.


_SNI_HOST_NAME = 0x00  # SNI name_type: host_name.


@dataclass(frozen=True)
class ClientHello:
    """파싱된 TLS ClientHello.

    Attributes:
        legacy_version: ClientHello 안의 client_version(예: ``0x0303`` =
            TLS 1.2). TLS 1.3 는 호환성 때문에 여기에 1.2 를 적고 실제 버전은
            supported_versions 확장에 둔다 — 그래서 "legacy".
        server_name: SNI host_name(없으면 ``None``). 접속 목적지 도메인.
        alpn: ALPN 으로 제시된 프로토콜 목록(없으면 빈 리스트).
        cipher_suites: 제시된 암호 스위트 id(2바이트 정수) 목록.
        extensions: 등장한 확장 type id 목록(등장 순서). 핑거프린트 입력.
        supported_groups: supported_groups(0x000a) 확장의 곡선 id 목록.
            JA3 핑거프린트 입력(없으면 빈 리스트).
        ec_point_formats: ec_point_formats(0x000b) 확장의 포맷 id 목록.
            JA3 핑거프린트 입력(없으면 빈 리스트).
    """

    legacy_version: int
    server_name: Optional[str] = None
    alpn: List[str] = field(default_factory=list)
    cipher_suites: List[int] = field(default_factory=list)
    extensions: List[int] = field(default_factory=list)
    supported_groups: List[int] = field(default_factory=list)
    ec_point_formats: List[int] = field(default_factory=list)

    @property
    def legacy_version_str(self) -> str:
        """``legacy_version`` 을 ``"TLS 1.2"`` 같은 이름으로(미상은 hex)."""
        return _version_name(self.legacy_version)


@dataclass(frozen=True)
class ServerHello:
    """파싱된 TLS ServerHello — 서버가 *고른* 핸드셰이크 파라미터.

    ClientHello 가 클라이언트가 *제시한* 목록이라면, ServerHello 는 서버가
    그중 하나로 *확정한* 결과다. JA3S(서버 핑거프린트)의 입력이 되며,
    같은 서버 스택(C2 프레임워크의 리스너 등)을 도메인·인증서와 무관하게
    묶어내는 침해 지표로 쓰인다.

    Attributes:
        legacy_version: ServerHello 안의 server_version(예: ``0x0303``).
            TLS 1.3 는 호환성 때문에 여기에 1.2 를 적고 실제 버전은
            supported_versions 확장에 둔다 — 그래서 "legacy".
        cipher_suite: 서버가 선택한 단 하나의 암호 스위트 id(2바이트 정수).
        extensions: 등장한 확장 type id 목록(등장 순서). JA3S 입력.
        alpn: ALPN 으로 서버가 확정한 프로토콜 목록(보통 1개, 없으면 빈 리스트).
        selected_version: supported_versions(0x002b) 확장이 있으면 거기서 뽑은
            실제 협상 버전(예: TLS 1.3 의 ``0x0304``). 없으면 ``None`` —
            이때 실제 버전은 ``legacy_version`` 이다.
    """

    legacy_version: int
    cipher_suite: int
    extensions: List[int] = field(default_factory=list)
    alpn: List[str] = field(default_factory=list)
    selected_version: Optional[int] = None

    @property
    def legacy_version_str(self) -> str:
        """``legacy_version`` 을 ``"TLS 1.2"`` 같은 이름으로(미상은 hex)."""
        return _version_name(self.legacy_version)

    @property
    def negotiated_version(self) -> int:
        """실제 협상 버전 — supported_versions 가 있으면 그 값, 없으면 legacy."""
        return self.selected_version if self.selected_version is not None \
            else self.legacy_version

    @property
    def negotiated_version_str(self) -> str:
        """``negotiated_version`` 을 사람이 읽을 이름으로(미상은 hex)."""
        return _version_name(self.negotiated_version)


def _version_name(version: int) -> str:
    """TLS 버전 코드(예: ``0x0303``)를 이름으로(미상은 hex)."""
    return {
        0x0300: "SSL 3.0",
        0x0301: "TLS 1.0",
        0x0302: "TLS 1.1",
        0x0303: "TLS 1.2",
        0x0304: "TLS 1.3",
    }.get(version, f"0x{version:04x}")


def _u16(data: bytes, off: int) -> int:
    """``off`` 위치의 빅엔디언 2바이트 정수(범위 밖이면 IndexError)."""
    return (data[off] << 8) | data[off + 1]


def _read_sni(ext_data: bytes) -> Optional[str]:
    """SNI 확장 데이터에서 첫 host_name 을 뽑는다(없으면 ``None``).

    구조: server_name_list_length(2) + [ name_type(1) name_length(2) name ]*.
    host_name(type 0)만 본다.
    """
    if len(ext_data) < 2:
        return None
    list_len = _u16(ext_data, 0)
    pos = 2
    end = min(2 + list_len, len(ext_data))
    while pos + 3 <= end:
        name_type = ext_data[pos]
        name_len = _u16(ext_data, pos + 1)
        pos += 3
        if pos + name_len > end:
            break
        if name_type == _SNI_HOST_NAME:
            # SNI host_name 은 정의상 ASCII(IDN 은 punycode 로 인코딩됨).
            return ext_data[pos:pos + name_len].decode("ascii", "replace")
        pos += name_len
    return None


def _read_alpn(ext_data: bytes) -> List[str]:
    """ALPN 확장 데이터에서 프로토콜 이름 목록을 뽑는다.

    구조: alpn_list_length(2) + [ proto_length(1) proto ]*.
    """
    out: List[str] = []
    if len(ext_data) < 2:
        return out
    list_len = _u16(ext_data, 0)
    pos = 2
    end = min(2 + list_len, len(ext_data))
    while pos < end:
        proto_len = ext_data[pos]
        pos += 1
        if pos + proto_len > end:
            break
        out.append(ext_data[pos:pos + proto_len].decode("ascii", "replace"))
        pos += proto_len
    return out


def _read_supported_groups(ext_data: bytes) -> List[int]:
    """supported_groups 확장에서 곡선 id 목록을 뽑는다.

    구조: list_length(2) + group(2바이트씩).
    """
    if len(ext_data) < 2:
        return []
    list_len = _u16(ext_data, 0)
    end = min(2 + list_len, len(ext_data))
    return [_u16(ext_data, i) for i in range(2, end - 1, 2)]


def _read_ec_point_formats(ext_data: bytes) -> List[int]:
    """ec_point_formats 확장에서 포맷 id 목록을 뽑는다.

    구조: list_length(1) + format(1바이트씩).
    """
    if len(ext_data) < 1:
        return []
    list_len = ext_data[0]
    end = min(1 + list_len, len(ext_data))
    return list(ext_data[1:end])


def _parse_extensions(
    data: bytes, pos: int, end: int
) -> Tuple[List[int], Optional[str], List[str], List[int], List[int]]:
    """확장 블록을 훑어 (type 목록, SNI, ALPN, 곡선, 포인트포맷) 을 돌려준다.

    각 확장: type(2) length(2) data(length). 길이가 어긋나면 거기서 멈춘다.
    """
    ext_types: List[int] = []
    server_name: Optional[str] = None
    alpn: List[str] = []
    supported_groups: List[int] = []
    ec_point_formats: List[int] = []
    while pos + 4 <= end:
        ext_type = _u16(data, pos)
        ext_len = _u16(data, pos + 2)
        pos += 4
        if pos + ext_len > end:
            break
        ext_data = data[pos:pos + ext_len]
        ext_types.append(ext_type)
        if ext_type == ExtensionType.SERVER_NAME and server_name is None:
            server_name = _read_sni(ext_data)
        elif ext_type == ExtensionType.ALPN and not alpn:
            alpn = _read_alpn(ext_data)
        elif ext_type == ExtensionType.SUPPORTED_GROUPS and not supported_groups:
            supported_groups = _read_supported_groups(ext_data)
        elif ext_type == ExtensionType.EC_POINT_FORMATS and not ec_point_formats:
            ec_point_formats = _read_ec_point_formats(ext_data)
        pos += ext_len
    return ext_types, server_name, alpn, supported_groups, ec_point_formats


def parse_client_hello(data: bytes) -> Optional[ClientHello]:
    """TLS record 바이트를 ClientHello 로 파싱한다.

    Args:
        data: 클라이언트→서버 방향으로 모인 원시 바이트. 보통 TLS record 가
            맨 앞에 오는 형태(content_type 0x16 으로 시작).

    Returns:
        :class:`ClientHello`. 다음이면 ``None``: record 가 handshake 가
        아니거나, handshake 가 ClientHello 가 아니거나, 길이 필드가 받은
        바이트를 벗어나도록 잘렸거나, 고정 필드(random/길이 prefix)가 모자란
        경우. 확장 섹션이 아예 없는 구형 ClientHello 도 정상 파싱한다(SNI 는
        ``None``).
    """
    # --- TLS record layer: content_type(1) version(2) length(2) ---
    if len(data) < 5:
        return None
    if data[0] != ContentType.HANDSHAKE:
        return None
    record_len = _u16(data, 3)
    record_end = min(5 + record_len, len(data))

    # --- Handshake layer: msg_type(1) length(3) ---
    pos = 5
    if pos + 4 > record_end:
        return None
    if data[pos] != HandshakeType.CLIENT_HELLO:
        return None
    hs_len = (data[pos + 1] << 16) | (data[pos + 2] << 8) | data[pos + 3]
    pos += 4
    body_end = min(pos + hs_len, record_end)

    # --- ClientHello body: client_version(2) random(32) ---
    if pos + 2 + 32 > body_end:
        return None
    legacy_version = _u16(data, pos)
    pos += 2 + 32  # client_version + random 건너뜀.

    # session_id: length(1) + id.
    if pos + 1 > body_end:
        return None
    sid_len = data[pos]
    pos += 1 + sid_len
    if pos > body_end:
        return None

    # cipher_suites: length(2) + suites(2바이트씩).
    if pos + 2 > body_end:
        return None
    cs_len = _u16(data, pos)
    pos += 2
    cs_end = pos + cs_len
    if cs_end > body_end:
        return None
    cipher_suites = [_u16(data, i) for i in range(pos, cs_end - 1, 2)]
    pos = cs_end

    # compression_methods: length(1) + methods.
    if pos + 1 > body_end:
        return None
    comp_len = data[pos]
    pos += 1 + comp_len
    if pos > body_end:
        return None

    # extensions: length(2) + 확장들. 없으면(구형) 여기서 끝.
    ext_types: List[int] = []
    server_name: Optional[str] = None
    alpn: List[str] = []
    supported_groups: List[int] = []
    ec_point_formats: List[int] = []
    if pos + 2 <= body_end:
        ext_total = _u16(data, pos)
        pos += 2
        ext_end = min(pos + ext_total, body_end)
        (
            ext_types,
            server_name,
            alpn,
            supported_groups,
            ec_point_formats,
        ) = _parse_extensions(data, pos, ext_end)

    return ClientHello(
        legacy_version=legacy_version,
        server_name=server_name,
        alpn=alpn,
        cipher_suites=cipher_suites,
        extensions=ext_types,
        supported_groups=supported_groups,
        ec_point_formats=ec_point_formats,
    )


def _parse_server_extensions(
    data: bytes, pos: int, end: int
) -> Tuple[List[int], List[str], Optional[str]]:
    """ServerHello 확장 블록을 훑어 (type 목록, ALPN, 협상 버전 hex) 을 돌려준다.

    각 확장: type(2) length(2) data(length). 길이가 어긋나면 거기서 멈춘다.
    supported_versions(0x002b)는 ServerHello 에서 *목록이 아니라* 선택된
    단일 버전 2바이트다(ClientHello 와 구조가 다르다).
    """
    ext_types: List[int] = []
    alpn: List[str] = []
    selected_version: Optional[int] = None
    while pos + 4 <= end:
        ext_type = _u16(data, pos)
        ext_len = _u16(data, pos + 2)
        pos += 4
        if pos + ext_len > end:
            break
        ext_data = data[pos:pos + ext_len]
        ext_types.append(ext_type)
        if ext_type == ExtensionType.ALPN and not alpn:
            alpn = _read_alpn(ext_data)
        elif ext_type == ExtensionType.SUPPORTED_VERSIONS \
                and selected_version is None and len(ext_data) >= 2:
            selected_version = _u16(ext_data, 0)
        pos += ext_len
    return ext_types, alpn, selected_version


def parse_server_hello(data: bytes) -> Optional[ServerHello]:
    """TLS record 바이트를 ServerHello 로 파싱한다.

    Args:
        data: 서버→클라이언트 방향으로 모인 원시 바이트. 보통 TLS record 가
            맨 앞에 오는 형태(content_type 0x16 으로 시작).

    Returns:
        :class:`ServerHello`. 다음이면 ``None``: record 가 handshake 가
        아니거나, handshake 가 ServerHello 가 아니거나, 길이 필드가 받은
        바이트를 벗어나도록 잘렸거나, 고정 필드가 모자란 경우. 확장 섹션이
        아예 없는 구형 ServerHello 도 정상 파싱한다.
    """
    # --- TLS record layer: content_type(1) version(2) length(2) ---
    if len(data) < 5:
        return None
    if data[0] != ContentType.HANDSHAKE:
        return None
    record_len = _u16(data, 3)
    record_end = min(5 + record_len, len(data))

    # --- Handshake layer: msg_type(1) length(3) ---
    pos = 5
    if pos + 4 > record_end:
        return None
    if data[pos] != HandshakeType.SERVER_HELLO:
        return None
    hs_len = (data[pos + 1] << 16) | (data[pos + 2] << 8) | data[pos + 3]
    pos += 4
    body_end = min(pos + hs_len, record_end)

    # --- ServerHello body: server_version(2) random(32) ---
    if pos + 2 + 32 > body_end:
        return None
    legacy_version = _u16(data, pos)
    pos += 2 + 32  # server_version + random 건너뜀.

    # session_id: length(1) + id.
    if pos + 1 > body_end:
        return None
    sid_len = data[pos]
    pos += 1 + sid_len
    if pos > body_end:
        return None

    # cipher_suite: 서버가 고른 단 하나(2바이트).
    if pos + 2 > body_end:
        return None
    cipher_suite = _u16(data, pos)
    pos += 2

    # compression_method: 단 하나(1바이트).
    if pos + 1 > body_end:
        return None
    pos += 1

    # extensions: length(2) + 확장들. 없으면(구형) 여기서 끝.
    ext_types: List[int] = []
    alpn: List[str] = []
    selected_version: Optional[int] = None
    if pos + 2 <= body_end:
        ext_total = _u16(data, pos)
        pos += 2
        ext_end = min(pos + ext_total, body_end)
        ext_types, alpn, selected_version = _parse_server_extensions(
            data, pos, ext_end
        )

    return ServerHello(
        legacy_version=legacy_version,
        cipher_suite=cipher_suite,
        extensions=ext_types,
        alpn=alpn,
        selected_version=selected_version,
    )
