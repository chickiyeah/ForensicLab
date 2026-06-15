"""HTTP 요청(request)·응답(response) 파싱 코어.

:mod:`forensiclab.netdissect` 가 패킷을 L4(TCP)까지 해석하고
:mod:`forensiclab.flows` 가 같은 대화의 TCP 페이로드를 한 방향으로 이어
붙인다면, 이 모듈은 그렇게 모인 바이트를 받아 HTTP 메시지를 구조화한다.
클라이언트→서버 방향은 :func:`parse_request`, 서버→클라이언트 방향은
:func:`parse_response` 가 맡는다. 침해 분석에서 HTTP 는 DNS 와 더불어 C2
비콘·데이터 유출의 단골 통로라, "누가 어떤 호스트의 어떤 경로를, 어떤
User-Agent 로 요청했는가" 와 "서버가 무엇을(어떤 Content-Type 으로, 어떤
상태 코드로) 돌려줬는가" 를 함께 보는 것이 탐지의 핵심 단서다.

지원 범위:
- 요청 라인: ``METHOD SP request-target SP HTTP-version CRLF``.
- 상태 라인: ``HTTP-version SP status-code SP reason-phrase CRLF`` (응답).
- 헤더 섹션: 빈 줄(CRLF CRLF) 전까지의 ``Name: value`` 줄. 헤더 이름은
  대소문자 무시(RFC 7230)라 소문자로 정규화해 보관하고, 같은 이름이 여러 번
  오면 콤마로 합친다(Set-Cookie 류 예외는 다루지 않음 — 요청 분석엔 불필요).
- 바디는 *해석하지 않는다*. 헤더 종료 위치(``body_offset``)만 알려 주어 호출
  측이 필요하면 잘라 쓰게 한다(증분을 작게 유지).

설계 원칙(:mod:`forensiclab.dns`·:mod:`forensiclab.flows` 와 동일):
- 부작용 없음: 디스크/표준출력 없이 순수 함수 (테스트 용이).
- stdlib 전용: 외부 의존성 없음.
- 안전: 입력 바이트를 변형하지 않는다(읽기 전용).
- 견고: 요청 라인이 없거나 망가진 입력은 예외 대신 ``None`` 으로 둔다.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Optional

__all__ = [
    "HTTP_METHODS",
    "HttpRequest",
    "HttpResponse",
    "parse_request",
    "parse_response",
]

# 표준 메서드 화이트리스트. 요청 라인 첫 토큰이 여기 없으면 HTTP 가 아니라고
# 보고 None 을 돌려, TLS 핸드셰이크 등 비-HTTP 페이로드를 걸러낸다.
HTTP_METHODS = frozenset(
    {"GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH"}
)

_CRLF = b"\r\n"
_HEADER_SEP = b"\r\n\r\n"
_MAX_HEADER_BYTES = 64 * 1024  # 헤더 폭주(슬로우로리스 류) 입력 상한.


@dataclass(frozen=True)
class HttpRequest:
    """파싱된 HTTP 요청(요청 라인 + 헤더).

    Attributes:
        method: 요청 메서드(대문자, 예: ``"GET"``).
        target: 요청 대상(원본 그대로, 예: ``"/path?q=1"`` 또는 절대 URI).
        version: HTTP 버전 문자열(예: ``"HTTP/1.1"``).
        headers: 헤더 이름(소문자) → 값. 중복 헤더는 ``", "`` 로 합침.
        body_offset: 입력에서 바디가 시작되는 바이트 오프셋(헤더 종료
            CRLFCRLF 직후). 바디 자체는 보관하지 않는다.
    """

    method: str
    target: str
    version: str
    headers: Dict[str, str] = field(default_factory=dict)
    body_offset: int = 0

    @property
    def host(self) -> Optional[str]:
        """``Host`` 헤더 값(없으면 ``None``)."""
        return self.headers.get("host")

    @property
    def user_agent(self) -> Optional[str]:
        """``User-Agent`` 헤더 값(없으면 ``None``)."""
        return self.headers.get("user-agent")


@dataclass(frozen=True)
class HttpResponse:
    """파싱된 HTTP 응답(상태 라인 + 헤더).

    Attributes:
        version: HTTP 버전 문자열(예: ``"HTTP/1.1"``).
        status_code: 상태 코드 정수(예: ``200``, ``404``).
        reason: reason-phrase(예: ``"OK"``). 없으면 빈 문자열.
        headers: 헤더 이름(소문자) → 값. 중복 헤더는 ``", "`` 로 합침.
        body_offset: 입력에서 바디가 시작되는 바이트 오프셋(헤더 종료
            CRLFCRLF 직후). 바디 자체는 보관하지 않는다.
    """

    version: str
    status_code: int
    reason: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    body_offset: int = 0

    @property
    def content_type(self) -> Optional[str]:
        """``Content-Type`` 헤더 값(없으면 ``None``). 멀웨어 다운로드 판별 단서."""
        return self.headers.get("content-type")

    @property
    def content_length(self) -> Optional[int]:
        """``Content-Length`` 헤더의 정수 값. 없거나 숫자가 아니면 ``None``."""
        raw = self.headers.get("content-length")
        if raw is None or not raw.isdigit():
            return None
        return int(raw)


def _split_head(data: bytes):
    """헤더 섹션을 끊어 ``(첫 줄, 나머지 헤더 줄들, body_offset)`` 을 돌려준다.

    요청·응답이 공유하는 전처리: 헤더 종료 CRLFCRLF 를 찾아 헤더 블록과 바디
    경계를 구하고, 첫 줄(요청 라인/상태 라인)과 이후 ``Name: value`` 줄들을
    분리한다. 입력이 비었거나 헤더가 상한을 넘으면 ``None``.
    """
    if not data:
        return None

    sep_index = data.find(_HEADER_SEP)
    if sep_index == -1:
        # 헤더가 아직 안 끝남. 받은 바이트 범위 안에서만 시도하되, 상한을 둔다.
        header_block = data[:_MAX_HEADER_BYTES]
        body_offset = len(data)
    else:
        if sep_index > _MAX_HEADER_BYTES:
            return None
        header_block = data[:sep_index]
        body_offset = sep_index + len(_HEADER_SEP)

    lines = header_block.split(_CRLF)
    return lines[0], lines[1:], body_offset


def _parse_headers(raw_lines) -> Dict[str, str]:
    """``Name: value`` 줄 목록을 소문자 키 dict 로. 중복은 ``", "`` 로 합침."""
    headers: Dict[str, str] = {}
    for raw in raw_lines:
        if not raw:
            continue  # 빈 줄(이론상 split 으로는 안 나오지만 방어).
        colon = raw.find(b":")
        if colon == -1:
            continue  # 콜론 없는 줄은 접힌 헤더 등 — 보수적으로 건너뜀.
        name = raw[:colon].decode("ascii", "replace").strip().lower()
        value = raw[colon + 1:].decode("ascii", "replace").strip()
        if not name:
            continue
        if name in headers:
            headers[name] = headers[name] + ", " + value
        else:
            headers[name] = value
    return headers


def parse_request(data: bytes) -> Optional[HttpRequest]:
    """TCP 페이로드 바이트를 HTTP 요청으로 파싱한다.

    Args:
        data: 클라이언트→서버 방향으로 모인 원시 바이트.

    Returns:
        :class:`HttpRequest`. 요청 라인이 ``METHOD TARGET HTTP/x.y`` 꼴이
        아니거나 메서드가 :data:`HTTP_METHODS` 에 없으면 ``None``. 헤더 종료
        CRLFCRLF 가 아직 안 왔으면(부분 수신) 헤더는 받은 데까지만 채우고
        ``body_offset`` 은 입력 끝으로 둔다.
    """
    head = _split_head(data)
    if head is None:
        return None
    request_line, header_lines, body_offset = head

    parts = request_line.split(b" ")
    if len(parts) != 3:
        return None

    method = parts[0].decode("ascii", "replace")
    if method not in HTTP_METHODS:
        return None
    version = parts[2].decode("ascii", "replace")
    if not version.startswith("HTTP/"):
        return None
    target = parts[1].decode("ascii", "replace")

    return HttpRequest(
        method=method,
        target=target,
        version=version,
        headers=_parse_headers(header_lines),
        body_offset=body_offset,
    )


def parse_response(data: bytes) -> Optional[HttpResponse]:
    """TCP 페이로드 바이트를 HTTP 응답으로 파싱한다.

    Args:
        data: 서버→클라이언트 방향으로 모인 원시 바이트.

    Returns:
        :class:`HttpResponse`. 상태 라인이 ``HTTP/x.y CODE [reason]`` 꼴이
        아니거나 상태 코드가 3자리 정수가 아니면 ``None``. 헤더 종료
        CRLFCRLF 가 아직 안 왔으면(부분 수신) 헤더는 받은 데까지만 채우고
        ``body_offset`` 은 입력 끝으로 둔다.
    """
    head = _split_head(data)
    if head is None:
        return None
    status_line, header_lines, body_offset = head

    # 상태 라인: "HTTP/1.1 200 OK". reason-phrase 는 비어 있을 수도 있고
    # 공백을 포함할 수도 있으므로 앞쪽 두 토큰만 분리한다(maxsplit=2).
    parts = status_line.split(b" ", 2)
    if len(parts) < 2:
        return None

    version = parts[0].decode("ascii", "replace")
    if not version.startswith("HTTP/"):
        return None

    code_bytes = parts[1]
    if len(code_bytes) != 3 or not code_bytes.isdigit():
        return None
    status_code = int(code_bytes)

    reason = parts[2].decode("ascii", "replace").strip() if len(parts) == 3 else ""

    return HttpResponse(
        version=version,
        status_code=status_code,
        reason=reason,
        headers=_parse_headers(header_lines),
        body_offset=body_offset,
    )
