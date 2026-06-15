"""WHOIS — 도메인/IP 등록정보 조회 질의 파싱 코어 (RFC 3912).

:mod:`forensiclab.netdissect` 가 식별한 TCP(포트 43) 페이로드는 WHOIS
질의 한 줄일 수 있다. 이 모듈이 그 줄을 해석한다(:mod:`forensiclab.finger`
가 TCP 79, :mod:`forensiclab.ident` 가 TCP 113 줄을 다루는 것과 같은 위치).

WHOIS 는 한 줄(``CRLF`` 종단) 질의에 자유 텍스트 응답을 돌려주는 평문
프로토콜이다(RFC 3912). 클라이언트가 조회 대상(도메인·IP·AS 번호·핸들)을
한 줄로 보내면 서버가 그 객체의 등록정보를 텍스트로 답한다. 본질이
**인프라 귀속(attribution)** 이다 — 도메인/주소를 등록 주체에 잇는다.

문법(RFC 3912 — 질의 줄은 자유 텍스트지만 실무 관례가 있다)::

    질의 ::= [flag ...] <object> CRLF
    flag ::= "-h" <server> | "-p" <port> | "type" <object> | "-T" <type> ...

즉 한 줄은 ``[플래그...] <대상>`` 이다. 플래그는 클라이언트/서버 구현마다
달라(ARIN ``n``/``a``, RIPE ``-T``, 일반 ``domain`` 키워드 등) 엄밀 문법이
없다 — 그래서 이 모듈은 토큰을 **플래그(``-`` 로 시작)**, **호스트 지정
(``-h``/``@``)**, **객체 키워드(domain/inetnum 등)**, **조회 대상**으로
나누고, 대상은 형태로 **IPv4/IPv6/ASN/도메인/핸들**을 분류한다.

평문 정찰 프로토콜이라 침해/사고 분석에서 단서가 짙다 — WHOIS 의 본질이
**인프라 정보 공개** 이기 때문이다(:mod:`forensiclab.finger` 의 사용자
정보 공개와 같은 계열, 다만 대상이 사람이 아니라 자산):

- **인프라 정찰·귀속**: 도메인/IP 질의는 공격에 쓸(혹은 분석 중인) 자산의
  등록자·등록일·네임서버·할당 블록을 캐낸다. 침입 전 표적 조사의 직접
  증거이자, 사후 분석에서 C2 인프라를 등록 주체에 잇는 귀속 단서다.
- **대상 분류**: 질의 대상이 IPv4/IPv6/ASN/도메인/핸들 중 무엇인지로 조사
  의도가 갈린다 — IP/ASN 질의는 네트워크 할당(소유 조직) 추적,
  도메인 질의는 등록자 추적, 핸들 질의는 연락처 추적.
- **서버 리다이렉션·재귀 피벗**: ``-h <host>`` 플래그(또는 ``@host``)는
  질의를 **다른 WHOIS 서버로 향하게** 한다 — thin 레지스트리에서 thick
  레지스트라로 넘어가는 재귀 조회. :mod:`forensiclab.finger` 의
  ``user@host`` 전달처럼 경로가 명시된 정황이며, 비표준 호스트 지정은
  내부/특정 서버를 겨냥한 단서다.
- **와일드카드 대량 수집**: ``*`` 를 품은 질의(예 ``example*``)는 한 패턴으로
  다수 객체를 쓸어 담는 대량 열거 정황이다(:mod:`forensiclab.finger` 의
  빈 질의 전원 목록과 같은 대량 수집 계열).

질의 예(텍스트, CRLF 종단)::

    example.com\r\n              (도메인 등록정보 조회)
    8.8.8.8\r\n                  (IPv4 할당 조회)
    2001:4860:4860::8888\r\n     (IPv6 할당 조회)
    AS15169\r\n                  (자율 시스템 번호 조회)
    domain example.com\r\n       (객체 키워드 명시)
    -h whois.arin.net 8.8.8.8\r\n (특정 서버로 리다이렉션 — 피벗 정황)
    example*\r\n                 (와일드카드 대량 수집)

응답은 구현마다 다른 자유 텍스트라 구조가 없다 — 이 모듈은 구조가 있는
**질의 줄**만 해석한다(응답 본문은 :mod:`forensiclab.strings` 등 호출자
처리 영역).

설계 원칙(:mod:`forensiclab.finger`·:mod:`forensiclab.ident` 와 동일):
- 부작용 없음: 순수 함수. 디스크/표준출력/네트워크 없음.
- stdlib 전용.
- 안전: 입력 바이트를 변형하지 않는다(읽기 전용). 질의 대상을 노출하되
  로깅/전송하지 않는다 — 호출자가 처리.
- 견고: 대상 분류는 형태 휴리스틱(``ipaddress`` stdlib)일 뿐 — 확정이
  아니라 단서. 대상을 못 가려도 토큰은 반환(부분 파싱). 바이트가 아예
  없을 때만 ``None``.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Optional, Tuple

__all__ = [
    "WHOIS_PORTS",
    "WHOIS_HOST_FLAGS",
    "WHOIS_OBJECT_KEYWORDS",
    "WhoisQuery",
    "parse_whois",
]

# WHOIS 표준 포트(TCP). IANA 지정 43(nicname).
WHOIS_PORTS = (43,)

# 질의를 다른 WHOIS 서버로 향하게 하는 호스트 지정 플래그 — 리다이렉션 단서.
WHOIS_HOST_FLAGS = ("-h", "--host", "-host")

# 다음 토큰을 값으로 받는 것으로 알려진 플래그(포트/타입/역질의 속성 등).
# WHOIS 플래그는 구현마다 달라 보편 규칙이 없으므로, 값을 흡수할 플래그는
# 명시 집합으로만 한정한다(추측 흡수 금지 — 대상 토큰 오염 방지).
WHOIS_VALUE_FLAGS = ("-p", "--port", "-T", "-t", "-i", "-a")

# 흔한 객체 타입 키워드(레지스트라/RIR 관례) — 조회 의도 분류용.
WHOIS_OBJECT_KEYWORDS = (
    "domain",
    "inetnum",
    "inet6num",
    "person",
    "role",
    "organisation",
    "organization",
    "aut-num",
    "route",
    "network",
    "poc",
    "asn",
)


@dataclass(frozen=True)
class WhoisQuery:
    """파싱된 WHOIS 질의 한 줄.

    Attributes:
        target: 조회 대상 객체(도메인·IP·ASN·핸들). 플래그/키워드를 걷어낸
            나머지 토큰. 없으면 ``None``.
        target_type: 대상의 형태 분류 — ``"ipv4"`` / ``"ipv6"`` / ``"asn"`` /
            ``"domain"`` / ``"handle"`` / ``"unknown"``. 형태 휴리스틱일 뿐
            확정 아님(단서).
        flags: 질의에 붙은 ``-`` 시작 플래그 토큰들(값 포함). 없으면 빈 튜플.
        keyword: 명시된 객체 타입 키워드(``domain`` 등). 없으면 ``None``.
        redirect_host: ``-h``/``@`` 로 지정된 대상 WHOIS 서버 — 리다이렉션/
            재귀 조회 정황. 없으면 ``None``.
        is_wildcard: 대상에 ``*`` 가 있는가 — 와일드카드 대량 수집 정황.
        raw: 원본 줄(종단 CRLF 제외).
    """

    target: Optional[str]
    target_type: str
    flags: Tuple[str, ...]
    keyword: Optional[str]
    redirect_host: Optional[str]
    is_wildcard: bool
    raw: str

    @property
    def is_ip_query(self) -> bool:
        """대상이 IP 주소인가(IPv4/IPv6) — 네트워크 할당/소유 추적 정황."""
        return self.target_type in ("ipv4", "ipv6")

    @property
    def is_asn_query(self) -> bool:
        """대상이 자율 시스템 번호인가 — 네트워크 소유 조직 추적 정황."""
        return self.target_type == "asn"

    @property
    def is_domain_query(self) -> bool:
        """대상이 도메인인가 — 등록자 추적 정황."""
        return self.target_type == "domain"

    @property
    def has_redirect(self) -> bool:
        """특정 WHOIS 서버로의 리다이렉션이 지정됐는가 — 피벗/재귀 정황."""
        return self.redirect_host is not None

    @property
    def is_empty(self) -> bool:
        """조회 대상이 없는가(플래그만/빈 줄)."""
        return self.target is None


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


def _classify(target: str) -> str:
    """대상 토큰의 형태로 종류를 분류한다(휴리스틱, stdlib 전용).

    분류: ipv4 / ipv6 / asn / domain / handle / unknown.
    """
    probe = target.split("/", 1)[0].rstrip("*")  # CIDR/와일드카드 꼬리 제거.
    if not probe:
        return "unknown"

    # IP(주소 또는 네트워크). ipaddress 가 형태를 엄밀 검증.
    try:
        ip = ipaddress.ip_address(probe)
        return "ipv4" if ip.version == 4 else "ipv6"
    except ValueError:
        pass
    try:
        net = ipaddress.ip_network(target.rstrip("*"), strict=False)
        return "ipv4" if net.version == 4 else "ipv6"
    except ValueError:
        pass

    low = probe.lower()
    # ASN: "AS15169" 또는 순수 숫자.
    if low.startswith("as") and low[2:].isdigit():
        return "asn"
    if probe.isdigit():
        return "asn"

    # 도메인: 점이 있고 마지막 라벨이 알파벳 TLD 형태.
    if "." in probe:
        last = probe.rsplit(".", 1)[-1]
        if last.isalpha() and len(last) >= 2:
            return "domain"

    # 점 없는 식별자는 레지스트리 핸들(연락처/객체 ID)일 수 있다.
    return "handle"


def parse_whois(data: bytes, offset: int = 0) -> Optional[WhoisQuery]:
    """원시 바이트에서 WHOIS 질의 한 줄을 파싱한다.

    Args:
        data: WHOIS 흐름 바이트. 보통 TCP 43 페이로드
            (:class:`forensiclab.netdissect` 의 ``payload_offset`` 부터)다.
        offset: 줄이 시작하는 위치(기본 0).

    Returns:
        :class:`WhoisQuery`. 토큰을 플래그/호스트지정/키워드/대상으로 나누고
        대상을 형태 분류한다. 바이트가 아예 없거나 offset 이 범위를 벗어나면
        ``None``.

    파싱: 공백으로 토큰 분리 후 — ``-h``/``@`` 다음 토큰은 리다이렉션 호스트,
    그 밖의 ``-`` 시작 토큰은 플래그(값 토큰 1개 흡수), 알려진 객체 키워드는
    keyword, 나머지 첫 일반 토큰이 조회 대상이다.
    """
    line = _first_line(data, offset)
    if line is None:
        return None
    raw = line.rstrip("\r\n")

    flags: list = []
    keyword: Optional[str] = None
    redirect_host: Optional[str] = None
    target: Optional[str] = None

    tokens = raw.split()
    i = 0
    while i < len(tokens):
        tok = tokens[i]

        if tok in WHOIS_HOST_FLAGS:
            flags.append(tok)
            if i + 1 < len(tokens):
                redirect_host = tokens[i + 1]
                i += 2
                continue
            i += 1
            continue

        # @host 형태의 호스트 지정(클라이언트 관례).
        if tok.startswith("@") and len(tok) > 1:
            redirect_host = tok[1:]
            i += 1
            continue

        if tok.startswith("-") and len(tok) > 1:
            flags.append(tok)
            # 값 받는 것으로 알려진 플래그(-p 포트, -T 타입 등)만 다음 토큰을
            # 값으로 흡수한다 — 그 밖의 플래그는 불리언으로 보고 대상을 남긴다.
            if (
                tok in WHOIS_VALUE_FLAGS
                and i + 1 < len(tokens)
                and not tokens[i + 1].startswith("-")
            ):
                flags.append(tokens[i + 1])
                i += 2
                continue
            i += 1
            continue

        # 객체 타입 키워드(domain/inetnum 등)면 keyword 로, 아니면 대상.
        if keyword is None and target is None and tok.lower() in WHOIS_OBJECT_KEYWORDS:
            keyword = tok.lower()
            i += 1
            continue

        if target is None:
            target = tok
        i += 1

    target_type = _classify(target) if target else "unknown"
    is_wildcard = bool(target and "*" in target)

    return WhoisQuery(
        target=target,
        target_type=target_type,
        flags=tuple(flags),
        keyword=keyword,
        redirect_host=redirect_host,
        is_wildcard=is_wildcard,
        raw=raw,
    )
