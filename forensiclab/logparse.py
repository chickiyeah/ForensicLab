"""Apache 접근 로그 파싱·공격 패턴 탐지 코어.

``/tools/log`` 도구의 절차적 로직 중 **Apache access log** 처리 부분을
일반화한 모듈이다. Common Log Format(CLF) 및 Combined Log Format 한 줄을
:class:`AccessLogEntry` 로 파싱하고, 요청 경로에서 흔한 웹 공격 흔적
(경로 조작·SQL 인젝션·XSS)을 휴리스틱으로 탐지한다.

설계 원칙(:mod:`forensiclab.carving`·:mod:`forensiclab.strings` 과 동일):
- 부작용 없음: 디스크 쓰기/표준출력 없이 순수 함수로 동작 (테스트 용이).
- stdlib 전용: :mod:`re` 외 외부 의존성 없음.
- 안전: 입력을 변형하지 않으며 탐지는 보고만 한다(차단·실행 없음).

탐지는 포렌식 *분류 보조*용 휴리스틱이며 오탐/미탐이 있을 수 있다. 자동
차단이 아니라 사람이 검토할 후보를 좁히는 용도로 쓴다.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable

__all__ = [
    "AccessLogEntry",
    "AttackHit",
    "ATTACK_SIGNATURES",
    "parse_access_line",
    "parse_access_log",
    "detect_attacks",
]

# Common/Combined Log Format:
#   host ident authuser [time] "request" status size
#   ...optionally followed by "referer" "user-agent" (combined).
_ACCESS_RE = re.compile(
    r'(?P<host>\S+)\s+'
    r'(?P<ident>\S+)\s+'
    r'(?P<user>\S+)\s+'
    r'\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<request>[^"]*)"\s+'
    r'(?P<status>\d{3})\s+'
    r'(?P<size>\d+|-)'
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<agent>[^"]*)")?'
    r'\s*$'
)


@dataclass(frozen=True)
class AccessLogEntry:
    """Apache 접근 로그 한 줄을 구조화한 결과.

    Attributes:
        host: 원격 호스트(IP 또는 호스트명).
        ident: RFC 1413 identity (대개 ``-``).
        user: HTTP 인증 사용자(대개 ``-``).
        time: 대괄호 안 타임스탬프 원문 문자열.
        method: HTTP 메서드(파싱 실패 시 빈 문자열).
        path: 요청 경로(쿼리 포함, 파싱 실패 시 원문 request).
        protocol: HTTP 프로토콜 문자열(예: ``HTTP/1.1``).
        status: 응답 상태 코드(정수).
        size: 응답 바이트 수. ``-`` 는 0 으로 본다.
        referer: Combined 포맷 referer(없으면 빈 문자열).
        agent: Combined 포맷 User-Agent(없으면 빈 문자열).
    """

    host: str
    ident: str
    user: str
    time: str
    method: str
    path: str
    protocol: str
    status: int
    size: int
    referer: str = ""
    agent: str = ""


@dataclass(frozen=True)
class _Signature:
    """공격 탐지 휴리스틱 한 개."""

    name: str
    pattern: re.Pattern


# 경로/요청 문자열에 적용하는 공격 시그니처(대소문자 무시).
ATTACK_SIGNATURES: tuple[_Signature, ...] = (
    _Signature("path_traversal", re.compile(r"\.\./|\.\.%2f|%2e%2e", re.I)),
    _Signature(
        "sql_injection",
        re.compile(
            r"union\s+select|\bor\s+1\s*=\s*1\b|'\s*or\s*'|--\s|;\s*drop\s",
            re.I,
        ),
    ),
    _Signature("xss", re.compile(r"<script|%3cscript|onerror\s*=|javascript:", re.I)),
)


def parse_access_line(line: str) -> AccessLogEntry | None:
    """Apache CLF/Combined 한 줄을 :class:`AccessLogEntry` 로 파싱한다.

    Args:
        line: 로그 한 줄(개행 포함 가능).

    Returns:
        파싱 성공 시 :class:`AccessLogEntry`, 형식 불일치 시 ``None``.
    """
    m = _ACCESS_RE.match(line.strip())
    if m is None:
        return None

    request = m.group("request")
    method = path = protocol = ""
    parts = request.split(" ")
    if len(parts) == 3:
        method, path, protocol = parts
    elif request:
        # 깨진 요청줄: 경로만이라도 보존한다.
        path = request

    size_raw = m.group("size")
    size = 0 if size_raw == "-" else int(size_raw)

    return AccessLogEntry(
        host=m.group("host"),
        ident=m.group("ident"),
        user=m.group("user"),
        time=m.group("time"),
        method=method,
        path=path,
        protocol=protocol,
        status=int(m.group("status")),
        size=size,
        referer=m.group("referer") or "",
        agent=m.group("agent") or "",
    )


def parse_access_log(lines: Iterable[str]) -> list[AccessLogEntry]:
    """여러 줄을 파싱하되 형식 불일치 줄은 조용히 건너뛴다.

    Args:
        lines: 로그 줄들의 이터러블(파일 객체도 가능).

    Returns:
        파싱에 성공한 :class:`AccessLogEntry` 목록(입력 순서 유지).
    """
    out: list[AccessLogEntry] = []
    for line in lines:
        if not line.strip():
            continue
        entry = parse_access_line(line)
        if entry is not None:
            out.append(entry)
    return out


@dataclass(frozen=True)
class AttackHit:
    """공격 시그니처에 걸린 로그 항목.

    Attributes:
        entry: 원본 :class:`AccessLogEntry`.
        categories: 매칭된 시그니처 이름들(정렬됨).
    """

    entry: AccessLogEntry
    categories: tuple[str, ...] = field(default_factory=tuple)


def detect_attacks(entries: Iterable[AccessLogEntry]) -> list[AttackHit]:
    """파싱된 항목에서 공격 패턴이 보이는 것만 골라낸다.

    요청 경로·referer 문자열에 :data:`ATTACK_SIGNATURES` 를 적용한다.

    Args:
        entries: :func:`parse_access_log` 등의 결과.

    Returns:
        하나 이상 시그니처에 걸린 항목들의 :class:`AttackHit` 목록
        (입력 순서 유지).
    """
    hits: list[AttackHit] = []
    for entry in entries:
        haystack = f"{entry.path} {entry.referer}"
        matched = sorted(
            sig.name for sig in ATTACK_SIGNATURES if sig.pattern.search(haystack)
        )
        if matched:
            hits.append(AttackHit(entry=entry, categories=tuple(matched)))
    return hits
