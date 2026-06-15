"""SMTP — Simple Mail Transfer Protocol 파싱 코어 (RFC 5321).

:mod:`forensiclab.netdissect` 가 식별한 TCP(포트 25 submission 587·smtps 465)
페이로드는 SMTP 한 줄일 수 있다. 이 모듈이 그 줄을 해석한다
(:mod:`forensiclab.ftp` 가 TCP 21 제어 채널을, :mod:`forensiclab.http` 가
TCP 80 을 다루는 것과 같은 위치 — 모두 텍스트 명령/응답 한 줄 계열).

SMTP 제어 흐름은 평문 줄(``CRLF`` 종단)의 교환이다 — 클라이언트는 명령
(``HELO``·``MAIL``·``RCPT``·``DATA``·``AUTH`` …)을, 서버는 3자리 응답 코드
(``250``·``535`` …)를 보낸다. 메일은 침해/사고 분석의 핵심 증거라 단서가 짙다
(:mod:`forensiclab.syslog` 가 텍스트 한 줄을, :mod:`forensiclab.ftp` 가 명령/
응답 한 줄을 다루듯, 이 모듈은 메일 명령/응답 한 줄을 다룬다):

- **평문 자격증명 노출**: ``AUTH PLAIN``/``AUTH LOGIN`` 은 Base64(난독화일
  뿐 암호화가 아님)로 사용자명·비밀번호를 와이어에 흘린다. STARTTLS 없이
  쓰이면 캡처에서 곧바로 자격증명을 복원할 수 있다
  (:mod:`forensiclab.ftp` 의 ``USER``/``PASS`` 와 같은 계열).
- **봉투 주소(발신/수신)**: ``MAIL FROM:<…>``·``RCPT TO:<…>`` 는 실제
  발신자·수신자를 드러낸다 — 헤더의 ``From:`` 과 달리 위조가 어려운 봉투
  주소다. 피싱 발신원·유출 수신처·스팸 표적을 짚는 직접 증거.
- **사용자 열거 정찰**: ``VRFY``/``EXPN`` 은 계정·메일링리스트 존재를
  확인하는 명령이라 정찰에 악용된다(:mod:`forensiclab.snmp` 의
  GetNext 워크·:mod:`forensiclab.nbns` 의 NBSTAT 와 같은 계열).
- **인증 실패·브루트포스**: ``535``(인증 실패)의 반복은 자격증명 추측
  정황이다(:mod:`forensiclab.ftp` 의 ``530``·:mod:`forensiclab.radius` 의
  Access-Reject 와 같은 계열).
- **암호화 협상(STARTTLS)**: ``STARTTLS`` 의 유무는 이후 흐름이 평문인지
  TLS 인지를 가른다 — 다운그레이드(STARTTLS 제거) 공격의 단서.

메시지 포맷(텍스트, CRLF 종단)::

    EHLO mail.evil.example          (명령: 동사 SP 인자)
    AUTH PLAIN AGFsaWNlAHMzY3JldA==  (SASL: Base64 자격증명)
    MAIL FROM:<attacker@evil.example>
    RCPT TO:<victim@corp.example>
    VRFY admin

    220 mail.corp.example ESMTP     (응답: 3자리 코드 SP 텍스트)
    250-mail.corp.example           (멀티라인 중간: 코드 뒤 '-')
    250 AUTH PLAIN LOGIN
    535 5.7.8 Authentication credentials invalid

설계 원칙(:mod:`forensiclab.ftp`·:mod:`forensiclab.ssdp` 와 동일):
- 부작용 없음: 순수 함수. 디스크/표준출력/네트워크 없음.
- stdlib 전용.
- 안전: 입력 바이트를 변형하지 않는다(읽기 전용). 자격증명을 노출하되
  로깅/전송하지 않는다 — 호출자가 처리.
- 견고: 너무 짧거나 망가진 입력은 예외 대신 ``None``.
"""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass
from typing import Optional, Tuple, Union

__all__ = [
    "SMTP_PORTS",
    "SmtpCommand",
    "SmtpReply",
    "parse_smtp",
    "parse_mail_path",
    "decode_auth_plain",
]

# SMTP 표준 포트(TCP): 25 릴레이·587 submission·465 smtps(암묵 TLS).
SMTP_PORTS = (25, 587, 465)

# 자격증명/인증을 협상하는 명령 — 평문(Base64) 노출의 핵심.
_AUTH_VERBS = frozenset({"AUTH"})

# 봉투(발신/수신) 주소를 드러내는 명령.
_ENVELOPE_VERBS = frozenset({"MAIL", "RCPT"})

# 계정·리스트 존재를 캐내는 명령 — 사용자 열거 정찰에 악용.
_RECON_VERBS = frozenset({"VRFY", "EXPN"})


def parse_mail_path(arg: str) -> Optional[str]:
    """``MAIL``/``RCPT`` 인자에서 봉투 주소를 뽑는다.

    인자는 보통 ``FROM:<addr>`` 또는 ``TO:<addr>`` 형태다. 꺾쇠 안의
    주소를 돌려준다. ``<>``(빈 발신자, 반송 메시지)는 빈 문자열로,
    꺾쇠가 없으면 ``:`` 뒤 토큰(파라미터 제외)을 관대하게 돌려준다.
    형식을 전혀 알 수 없으면 ``None``.

    Examples:
        ``FROM:<alice@example.com>`` → ``"alice@example.com"``
        ``TO:<bob@x> SIZE=1000`` → ``"bob@x"``
        ``FROM:<>`` → ``""``  (빈 발신자: 반송/DSN)
    """
    if arg is None:
        return None
    s = arg.strip()
    if not s:
        return None
    # 꺾쇠 경로가 있으면 그 안을 우선. <addr> 또는 <> .
    lo = s.find("<")
    hi = s.find(">", lo + 1) if lo >= 0 else -1
    if lo >= 0 and hi > lo:
        return s[lo + 1:hi].strip()
    # 꺾쇠가 없으면 'FROM:'/'TO:' 접두 뒤 첫 토큰을 관대하게.
    colon = s.find(":")
    rest = s[colon + 1:] if colon >= 0 else s
    rest = rest.strip()
    if not rest:
        return None
    # ESMTP 파라미터(SIZE=… 등)는 공백으로 분리되므로 첫 토큰만.
    return rest.split(None, 1)[0]


def decode_auth_plain(token: str) -> Optional[Tuple[str, str, str]]:
    """``AUTH PLAIN`` 의 Base64 초기 응답을 (authzid, authcid, passwd) 로.

    SASL PLAIN 은 ``authzid \\0 authcid \\0 passwd`` 를 Base64 로 감싼다
    (RFC 4616). Base64 는 난독화일 뿐이라 캡처에서 곧바로 자격증명이
    복원된다. 디코드 실패·필드 수 불일치면 ``None``.

    Examples:
        ``base64("\\0alice\\0s3cret")`` → ``("", "alice", "s3cret")``
    """
    if token is None:
        return None
    t = token.strip()
    if not t:
        return None
    try:
        raw = base64.b64decode(t, validate=True)
    except (binascii.Error, ValueError):
        return None
    parts = raw.split(b"\x00")
    if len(parts) != 3:
        return None
    authzid, authcid, passwd = parts
    return (
        authzid.decode("utf-8", "replace"),
        authcid.decode("utf-8", "replace"),
        passwd.decode("utf-8", "replace"),
    )


@dataclass(frozen=True)
class SmtpCommand:
    """파싱된 SMTP 클라이언트 명령 한 줄.

    Attributes:
        verb: 대문자로 정규화된 명령 동사(``EHLO``·``MAIL``·``AUTH`` …).
        arg: 명령 인자(없으면 빈 문자열). 봉투 주소/자격증명이 여기 담긴다.
        raw: 원본 줄(종단 CRLF 제외).
    """

    verb: str
    arg: str
    raw: str

    @property
    def is_auth(self) -> bool:
        """인증을 협상하는 명령(``AUTH``)인가 — Base64 자격증명 노출 지점."""
        return self.verb in _AUTH_VERBS

    @property
    def is_envelope(self) -> bool:
        """봉투 주소를 드러내는 명령(``MAIL``·``RCPT``)인가."""
        return self.verb in _ENVELOPE_VERBS

    @property
    def is_recon(self) -> bool:
        """사용자 열거 정찰 명령(``VRFY``·``EXPN``)인가."""
        return self.verb in _RECON_VERBS

    @property
    def is_starttls(self) -> bool:
        """``STARTTLS`` — 이후 흐름 암호화 협상(다운그레이드 단서) 명령인가."""
        return self.verb == "STARTTLS"

    @property
    def mail_address(self) -> Optional[str]:
        """``MAIL``/``RCPT`` 봉투 주소 — 그 외 명령이면 ``None``.

        피싱 발신원·유출 수신처를 짚는 단서.
        :func:`parse_mail_path` 로 꺾쇠 경로를 환원한다.
        """
        if self.verb not in _ENVELOPE_VERBS:
            return None
        return parse_mail_path(self.arg)

    @property
    def auth_credentials(self) -> Optional[Tuple[str, str, str]]:
        """``AUTH PLAIN <base64>`` 초기 응답의 (authzid, authcid, passwd).

        ``AUTH PLAIN`` 이 아니거나 초기 응답이 없으면 ``None``.
        :func:`decode_auth_plain` 으로 Base64 를 환원한다.
        """
        if self.verb != "AUTH":
            return None
        parts = self.arg.split(None, 1)
        if len(parts) != 2 or parts[0].upper() != "PLAIN":
            return None
        return decode_auth_plain(parts[1])


@dataclass(frozen=True)
class SmtpReply:
    """파싱된 SMTP 서버 응답 한 줄.

    Attributes:
        code: 3자리 응답 코드(``250``·``535`` …).
        text: 코드 뒤 텍스트(없으면 빈 문자열).
        is_intermediate: 멀티라인 응답의 중간 줄(``NNN-`` 표식)이면 True.
            마지막 줄은 ``NNN<space>`` 라 False.
        raw: 원본 줄(종단 CRLF 제외).
    """

    code: int
    text: str
    is_intermediate: bool
    raw: str

    @property
    def category(self) -> int:
        """응답 코드 1번째 자리(2~5) — 군(group) 분류.

        2=완료, 3=중간(추가 입력 필요), 4=일시 실패, 5=영구 실패.
        """
        return self.code // 100

    @property
    def is_positive_completion(self) -> bool:
        """2yz(요청 성공 완료) 응답인가."""
        return self.category == 2

    @property
    def is_auth_failure(self) -> bool:
        """``535``(인증 자격증명 무효) — 반복 시 브루트포스 정황."""
        return self.code == 535


def _first_line(data: bytes, offset: int) -> Optional[str]:
    """``offset`` 부터 첫 줄(CRLF/LF 이전)을 ASCII 텍스트로."""
    if offset < 0 or offset > len(data):
        return None
    chunk = data[offset:]
    if not chunk:
        return None
    # SMTP 제어 흐름은 ASCII 텍스트. 비텍스트 바이트는 관대하게 무시(replace).
    text = chunk.decode("ascii", "replace")
    line = text.replace("\r\n", "\n").split("\n", 1)[0]
    return line


def parse_smtp(
    data: bytes, offset: int = 0
) -> Optional[Union[SmtpCommand, SmtpReply]]:
    """원시 바이트에서 SMTP 한 줄을 파싱한다.

    Args:
        data: SMTP 제어 흐름 바이트. 보통 TCP 25/587 페이로드
            (:class:`forensiclab.netdissect` 의 ``payload_offset`` 부터)다.
        offset: 줄이 시작하는 위치(기본 0).

    Returns:
        서버 응답이면 :class:`SmtpReply`(3자리 코드로 시작하고 그 뒤가 공백
        또는 ``-`` 인 줄), 그 외 비어 있지 않은 줄이면 :class:`SmtpCommand`.
        빈 입력/공백뿐인 줄은 ``None``.
    """
    line = _first_line(data, offset)
    if line is None:
        return None
    stripped = line.rstrip()
    if not stripped.strip():
        return None

    # 응답 판별: 정확히 3자리 숫자 + (공백|'-') 또는 줄이 코드만일 때.
    if len(stripped) >= 3 and stripped[:3].isdigit():
        sep = stripped[3:4]
        if sep in ("", " ", "-"):
            code = int(stripped[:3])
            is_intermediate = sep == "-"
            text = stripped[4:] if len(stripped) > 4 else ""
            return SmtpReply(
                code=code,
                text=text.strip(),
                is_intermediate=is_intermediate,
                raw=stripped,
            )

    # 명령: 동사 SP 인자. 동사는 대문자로 정규화.
    parts = stripped.split(None, 1)
    verb = parts[0].upper()
    arg = parts[1].strip() if len(parts) > 1 else ""
    return SmtpCommand(verb=verb, arg=arg, raw=stripped)
