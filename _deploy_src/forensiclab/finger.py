"""Finger — 사용자 정보 조회 질의 파싱 코어 (RFC 1288).

:mod:`forensiclab.netdissect` 가 식별한 TCP(포트 79) 페이로드는 Finger
질의 한 줄일 수 있다. 이 모듈이 그 줄을 해석한다(:mod:`forensiclab.ftp`
가 TCP 21, :mod:`forensiclab.smtp` 가 TCP 25, :mod:`forensiclab.irc` 가
TCP 6667 줄을 다루는 것과 같은 위치).

Finger 는 한 줄(``CRLF`` 종단) 질의에 자유 텍스트 응답을 돌려주는 평문
프로토콜이다. 질의 한 줄의 구조(RFC 1288)는::

    {Q1 | Q2}
    Q1  ::= [{W}{S}{U}]{C}              (로컬 질의)
    Q2  ::= [{W}{S}]{U}{H}{C}           (원격 전달 질의)
    U   ::= username                     (조회 대상 사용자)
    H   ::= @hostname [@hostname ...]     (전달 경로)
    W   ::= "/W"                          (verbose "whois" 스위치)
    S   ::= <SP>...                       (공백)
    C   ::= <CRLF>

즉 한 줄은 ``[/W] [username] [@host[@host...]]`` 다. 사용자명이 없으면
"현재 로그인한 전원" 목록 질의이고, ``@host`` 가 붙으면 그 질의를 원격
호스트로 전달한다.

평문 정찰 프로토콜이라 침해/사고 분석에서 단서가 짙다 — Finger 의 본질이
**사용자 정보 공개(information disclosure)** 이기 때문이다
(:mod:`forensiclab.smtp` 의 ``VRFY``/``EXPN`` 사용자 열거와 같은 계열):

- **사용자 열거**: 사용자명을 지정한 질의는 그 계정의 존재·실명·마지막
  로그인·로그인 위치를 캐낸다. 침입 전 정찰의 직접 증거다.
- **전원 목록 수집**: 사용자명 없는 빈 질의(``CRLF`` 만)는 **로그인한
  사용자 전체 목록**을 요구한다 — 한 줄로 호스트의 활성 계정을 쓸어 담는
  대량 열거.
- **전달·릴레이 피벗**: ``user@host`` / ``@host`` 처럼 ``@`` 로 경로가 붙은
  질의는 Finger 게이트웨이가 그 질의를 원격 호스트로 **전달**하게 한다.
  ``a@b@c`` 식 다단 체인은 경계 호스트를 발판으로 내부 호스트를 우회
  탐색하는 피벗 정황이다(RFC 1288 이 보안상 비활성화를 권고하는 바로 그
  동작). :mod:`forensiclab.ssdp` 의 반사·:mod:`forensiclab.nbns` 의
  포이즈닝처럼, 프로토콜 기능 자체가 오용 벡터다.
- **verbose 스위치**: ``/W``("whois")는 응답의 상세도를 최대화하라는
  요청으로, 정보 공개를 키우려는 의도 단서다.

질의 예(텍스트, CRLF 종단)::

    \r\n                  (빈 질의 — 로그인 전원 목록)
    root\r\n              (root 계정 열거)
    /W admin\r\n          (admin 상세 조회)
    user@victim.net\r\n   (victim.net 으로 전달)
    @internal\r\n         (internal 의 전원 목록을 전달로 수집)

응답은 구현마다 다른 자유 텍스트라 구조가 없다 — 이 모듈은 구조가 있는
**질의 줄**만 해석한다(응답 본문은 :mod:`forensiclab.strings` 등 호출자
처리 영역).

설계 원칙(:mod:`forensiclab.irc`·:mod:`forensiclab.smtp` 와 동일):
- 부작용 없음: 순수 함수. 디스크/표준출력/네트워크 없음.
- stdlib 전용.
- 안전: 입력 바이트를 변형하지 않는다(읽기 전용). 질의 대상을 노출하되
  로깅/전송하지 않는다 — 호출자가 처리.
- 견고: 빈 줄(``CRLF`` 만)은 **유효한** 전원 목록 질의다(예외/``None``
  아님). 바이트가 아예 없을 때만 ``None``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Tuple

__all__ = [
    "FINGER_PORTS",
    "FingerQuery",
    "parse_finger",
]

# Finger 표준 포트(TCP). IANA 지정 79.
FINGER_PORTS = (79,)

# verbose("whois") 스위치 토큰 — 응답 상세도 최대화 요청.
_VERBOSE_SWITCH = "/W"


@dataclass(frozen=True)
class FingerQuery:
    """파싱된 Finger 질의 한 줄.

    Attributes:
        verbose: ``/W``("whois") 스위치가 붙었는가 — 상세 정보 공개 요청.
        username: 조회 대상 사용자명. 없으면 ``None``(= 전원 목록 질의).
        hosts: ``@`` 로 이어진 전달 경로 호스트들(순서 보존). 비었으면
            로컬 질의. 한 개 이상이면 원격 전달, 여럿이면 다단 릴레이 체인.
        raw: 원본 질의 줄(종단 CRLF 제외).
    """

    verbose: bool
    username: Optional[str]
    hosts: Tuple[str, ...]
    raw: str

    @property
    def is_list_all(self) -> bool:
        """사용자명 없는 전원 목록 질의인가 — 로그인 계정 대량 열거 정황."""
        return self.username is None

    @property
    def is_forwarding(self) -> bool:
        """``@host`` 전달 경로가 있는가 — 원격 호스트로 질의를 우회·피벗."""
        return bool(self.hosts)

    @property
    def is_relay_chain(self) -> bool:
        """전달 호스트가 둘 이상인가 — 다단 릴레이(경계 호스트 발판) 정황."""
        return len(self.hosts) > 1

    @property
    def target_host(self) -> Optional[str]:
        """질의가 향하는 첫 전달 호스트(없으면 ``None`` = 로컬)."""
        return self.hosts[0] if self.hosts else None


def _first_line(data: bytes, offset: int) -> Optional[str]:
    """``offset`` 부터 첫 줄(CRLF/LF 이전)을 텍스트로(UTF-8 관대 디코드).

    빈 줄(``CRLF`` 만)도 ``""`` 로 돌려준다 — Finger 에선 유효한 질의다.
    바이트가 아예 없거나 offset 이 범위를 벗어나면 ``None``.
    """
    if offset < 0 or offset > len(data):
        return None
    chunk = data[offset:]
    if not chunk:
        return None
    text = chunk.decode("utf-8", "replace")
    line = text.replace("\r\n", "\n").split("\n", 1)[0]
    return line


def parse_finger(data: bytes, offset: int = 0) -> Optional[FingerQuery]:
    """원시 바이트에서 Finger 질의 한 줄을 파싱한다.

    Args:
        data: Finger 흐름 바이트. 보통 TCP 79 페이로드
            (:class:`forensiclab.netdissect` 의 ``payload_offset`` 부터)다.
        offset: 줄이 시작하는 위치(기본 0).

    Returns:
        :class:`FingerQuery`. 빈 줄(``CRLF`` 만)은 전원 목록 질의로
        정상 반환된다. 바이트가 아예 없거나 offset 이 범위를 벗어나면
        ``None``.

    문법(RFC 1288)::

        [/W [SP]] [username] [@host [@host ...]] CRLF

    선행 ``/W`` 스위치는 뒤에 공백이 오거나 줄 끝일 때만 스위치로 본다
    (``/Wfoo`` 처럼 붙은 건 일반 토큰). 나머지를 ``@`` 로 갈라 첫 조각을
    사용자명(비면 ``None`` = 전원 목록), 이후를 전달 호스트로 본다.
    """
    line = _first_line(data, offset)
    if line is None:
        return None
    raw = line.rstrip("\r\n")
    s = raw.strip()

    # 선행 /W("whois") 스위치 — 뒤에 공백 또는 줄 끝이어야 스위치.
    verbose = False
    if s[:2].upper() == _VERBOSE_SWITCH:
        after = s[2:]
        if after == "" or after[0].isspace():
            verbose = True
            s = after.strip()

    # 남은 부분이 user@host 명세. 비면 로컬 전원 목록 질의.
    if not s:
        return FingerQuery(verbose=verbose, username=None, hosts=(), raw=raw)

    # RFC 사용자명엔 공백이 없다 — 망가진 입력은 첫 토큰만 명세로.
    spec = s.split()[0]
    parts = spec.split("@")
    username = parts[0] or None
    hosts = tuple(h for h in parts[1:] if h)

    return FingerQuery(verbose=verbose, username=username, hosts=hosts, raw=raw)
