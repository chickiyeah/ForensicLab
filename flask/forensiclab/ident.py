"""Ident — TCP 연결을 사용자 식별로 환원하는 질의/응답 파싱 코어 (RFC 1413).

:mod:`forensiclab.netdissect` 가 식별한 TCP(포트 113) 페이로드는 Ident
프로토콜 한 줄일 수 있다. 이 모듈이 그 줄을 해석한다(:mod:`forensiclab.finger`
가 TCP 79, :mod:`forensiclab.irc` 가 TCP 6667 줄을 다루는 것과 같은 위치).

Ident(Identification Protocol)는 한 줄(``CRLF`` 종단) 질의/응답을 주고받는
평문 프로토콜이다. 질의자는 "당신 호스트에서 이 TCP 연결을 연 사용자가
누구냐"를 묻고, 대상 호스트가 자기 쪽 사용자명을 돌려준다. 그래서 본질이
**연결→사용자 귀속(attribution)** 이다 — 5-튜플 흐름을 계정 이름에 잇는다.

문법(RFC 1413, 양쪽 모두 ``port , port`` 쌍으로 시작)::

    질의   ::= <server-port> "," <client-port>  CRLF
    응답   ::= <server-port> "," <client-port> ":" <resp-type> ":" <add-info> CRLF
    resp-type ::= "USERID" | "ERROR"
    USERID add-info ::= <opsys> [ "," <charset> ] ":" <username>
    ERROR  add-info ::= "INVALID-PORT" | "NO-USER" | "HIDDEN-USER" | "UNKNOWN-ERROR"

즉 콜론이 없으면 **질의**(포트 쌍만), 있으면 **응답**이다. 응답의 포트 쌍은
질의의 포트 쌍을 그대로 되울린다 — 그래서 응답 하나가 어느 TCP 흐름을
가리키는지 포트로 직접 상관된다(:mod:`forensiclab.flows` 의 5-튜플과 연결).

평문 귀속 프로토콜이라 침해/사고 분석에서 단서가 짙다:

- **사용자 귀속(USERID)**: ``USERID`` 응답의 ``username`` 은 그 TCP 연결을
  연 계정이다. 흐름(:mod:`forensiclab.flows`)을 실명 계정에 잇는 직접 증거다
  — IRC 서버가 접속 시 관례적으로 ident 를 물어 봇/사용자 신원을 기록하는
  것과 같은 동작(:mod:`forensiclab.irc`).
- **위조 가능 귀속**: ident 가 돌려주는 이름은 **대상 호스트가 자기 신고**한
  것이라 인증되지 않는다 — 침해된/악의적 호스트는 가짜 이름을 댈 수 있다.
  단서로 쓰되 단독 신뢰 금지(호출자가 다른 증거와 교차 검증).
- **HIDDEN-USER**: 사용자가 ident 노출을 거부(프라이버시/회피)했다는 신호 —
  실제 계정을 가리려는 정황.
- **INVALID-PORT**: 그 포트 쌍에 해당하는 연결이 없다는 응답 — 존재하지 않는
  연결을 캐묻는 스캔/탐침의 부산물 단서.
- **NO-USER**: 연결은 있으나 소유 사용자를 못 찾음 — 흐름 상관 실패 정황.

한 줄 예(텍스트, CRLF 종단)::

    6191, 23\r\n                               (질의: server=6191 client=23)
    6191, 23 : USERID : UNIX : alice\r\n        (응답: alice 가 연 연결)
    6191, 23 : USERID : UNIX,US-ASCII : root\r\n
    6191, 23 : ERROR : HIDDEN-USER\r\n          (사용자가 노출 거부)
    6191, 23 : ERROR : INVALID-PORT\r\n         (해당 연결 없음 — 탐침 정황)

설계 원칙(:mod:`forensiclab.finger`·:mod:`forensiclab.irc` 와 동일):
- 부작용 없음: 순수 함수. 디스크/표준출력/네트워크 없음.
- stdlib 전용.
- 안전: 입력 바이트를 변형하지 않는다(읽기 전용). 신고된 사용자명을
  노출하되 로깅/전송하지 않는다 — 호출자가 처리.
- 견고: 콜론 유무로 질의/응답을 자동 판별. 포트가 숫자가 아니면 ``None``
  으로 두되 메시지는 반환(부분 파싱). 바이트가 아예 없을 때만 ``None``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

__all__ = [
    "IDENT_PORTS",
    "IDENT_ERROR_TYPES",
    "IdentMessage",
    "parse_ident",
]

# Ident 표준 포트(TCP). IANA 지정 113(auth).
IDENT_PORTS = (113,)

# RFC 1413 이 정의한 ERROR add-info 토큰들.
IDENT_ERROR_TYPES = (
    "INVALID-PORT",
    "NO-USER",
    "HIDDEN-USER",
    "UNKNOWN-ERROR",
)


@dataclass(frozen=True)
class IdentMessage:
    """파싱된 Ident 프로토콜 한 줄(질의 또는 응답).

    Attributes:
        is_query: 콜론이 없는 포트 쌍만의 질의인가(아니면 응답).
        server_port: 포트 쌍의 첫 값(질의자 기준 서버측 포트). 숫자가
            아니면 ``None``.
        client_port: 포트 쌍의 둘째 값(질의자 기준 클라이언트측 포트).
            숫자가 아니면 ``None``.
        resp_type: 응답 유형(``"USERID"`` / ``"ERROR"`` / 그 외 대문자
            토큰). 질의면 ``None``.
        opsys: ``USERID`` 응답의 운영체제 토큰(예 ``UNIX``). 없으면 ``None``.
        charset: ``USERID`` 응답의 선택적 문자셋(예 ``US-ASCII``). 없으면
            ``None``.
        username: ``USERID`` 응답이 신고한 계정명 — 연결 귀속 대상. 없으면
            ``None``. **위조 가능**(대상 호스트 자기 신고).
        error_type: ``ERROR`` 응답의 오류 토큰(예 ``HIDDEN-USER``). 없으면
            ``None``.
        raw: 원본 줄(종단 CRLF 제외).
    """

    is_query: bool
    server_port: Optional[int]
    client_port: Optional[int]
    resp_type: Optional[str]
    opsys: Optional[str]
    charset: Optional[str]
    username: Optional[str]
    error_type: Optional[str]
    raw: str

    @property
    def is_reply(self) -> bool:
        """질의가 아닌 응답인가."""
        return not self.is_query

    @property
    def is_userid(self) -> bool:
        """사용자 귀속을 담은 ``USERID`` 응답인가 — 흐름→계정 연결 증거."""
        return self.resp_type == "USERID"

    @property
    def is_error(self) -> bool:
        """``ERROR`` 응답인가."""
        return self.resp_type == "ERROR"

    @property
    def is_hidden_user(self) -> bool:
        """사용자가 ident 노출을 거부했는가(``HIDDEN-USER``) — 회피 정황."""
        return self.error_type == "HIDDEN-USER"

    @property
    def is_invalid_port(self) -> bool:
        """해당 연결 없음(``INVALID-PORT``) — 존재 않는 연결 탐침 부산물."""
        return self.error_type == "INVALID-PORT"

    @property
    def has_attribution(self) -> bool:
        """연결을 실명 계정에 잇는 사용자명이 있는가 — 귀속 증거 존재."""
        return self.is_userid and bool(self.username)

    @property
    def port_pair(self) -> Optional[tuple]:
        """``(server_port, client_port)`` 쌍 — 흐름 상관 키(둘 다 있을 때)."""
        if self.server_port is None or self.client_port is None:
            return None
        return (self.server_port, self.client_port)


def _first_line(data: bytes, offset: int) -> Optional[str]:
    """``offset`` 부터 첫 줄(CRLF/LF 이전)을 텍스트로(UTF-8 관대 디코드).

    바이트가 아예 없거나 offset 이 범위를 벗어나면 ``None``.
    """
    if offset < 0 or offset > len(data):
        return None
    chunk = data[offset:]
    if not chunk:
        return None
    text = chunk.decode("utf-8", "replace")
    return text.replace("\r\n", "\n").split("\n", 1)[0]


def _to_port(token: str) -> Optional[int]:
    """포트 토큰을 정수로(공백 제거). 숫자가 아니면 ``None``."""
    token = token.strip()
    if token.isdigit():
        return int(token)
    return None


def _parse_port_pair(field: str):
    """``"server , client"`` 필드를 ``(server_port, client_port)`` 로."""
    parts = field.split(",")
    server = _to_port(parts[0]) if parts else None
    client = _to_port(parts[1]) if len(parts) > 1 else None
    return server, client


def parse_ident(data: bytes, offset: int = 0) -> Optional[IdentMessage]:
    """원시 바이트에서 Ident 프로토콜 한 줄(질의/응답)을 파싱한다.

    Args:
        data: Ident 흐름 바이트. 보통 TCP 113 페이로드
            (:class:`forensiclab.netdissect` 의 ``payload_offset`` 부터)다.
        offset: 줄이 시작하는 위치(기본 0).

    Returns:
        :class:`IdentMessage`. 콜론 유무로 질의/응답을 자동 판별한다.
        바이트가 아예 없거나 offset 이 범위를 벗어나면 ``None``.

    판별: 첫 콜론(``:``)이 없으면 포트 쌍만의 **질의**, 있으면 **응답**이다.
    응답은 ``port,port : resp-type : add-info`` 로 콜론 구분하되, ``USERID``
    의 ``username`` 은 콜론을 품을 수 있어 마지막 필드를 다시 이어 붙인다.
    """
    line = _first_line(data, offset)
    if line is None:
        return None
    raw = line.rstrip("\r\n")

    fields = raw.split(":")
    server_port, client_port = _parse_port_pair(fields[0])

    # 콜론 없음 → 포트 쌍만의 질의.
    if len(fields) == 1:
        return IdentMessage(
            is_query=True,
            server_port=server_port,
            client_port=client_port,
            resp_type=None,
            opsys=None,
            charset=None,
            username=None,
            error_type=None,
            raw=raw,
        )

    # 콜론 있음 → 응답.
    resp_type = fields[1].strip().upper()
    opsys = charset = username = error_type = None

    if resp_type == "USERID":
        # fields[2] = opsys[,charset], fields[3:] = username(콜론 가능 → 재결합).
        if len(fields) > 2:
            oc = fields[2].split(",", 1)
            opsys = oc[0].strip() or None
            if len(oc) > 1:
                charset = oc[1].strip() or None
        if len(fields) > 3:
            username = ":".join(fields[3:]).strip() or None
    elif resp_type == "ERROR":
        if len(fields) > 2:
            error_type = ":".join(fields[2:]).strip().upper() or None

    return IdentMessage(
        is_query=False,
        server_port=server_port,
        client_port=client_port,
        resp_type=resp_type or None,
        opsys=opsys,
        charset=charset,
        username=username,
        error_type=error_type,
        raw=raw,
    )
