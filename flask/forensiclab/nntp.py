"""NNTP — Network News Transfer Protocol 파싱 코어 (RFC 3977/977).

:mod:`forensiclab.netdissect` 가 식별한 TCP(포트 119·nntps 563) 페이로드는
NNTP 한 줄일 수 있다. 이 모듈이 그 줄을 해석한다(:mod:`forensiclab.smtp` 가
TCP 25 메일 명령/응답을, :mod:`forensiclab.ftp` 가 TCP 21 제어 채널을 다루는
것과 같은 위치 — 모두 텍스트 명령/3자리 응답 코드 한 줄 계열).

NNTP 는 평문 줄(``CRLF`` 종단)의 교환이다 — 클라이언트는 명령
(``GROUP``·``ARTICLE``·``POST``·``AUTHINFO`` …)을, 서버는 3자리 응답 코드
(``200``·``281``·``481`` …)를 보낸다. SMTP·POP3 의 메일 형제로, 뉴스(유즈넷)
배포 채널이라 침해/사고 분석에서 단서가 짙다:

- **평문 자격증명 노출**: ``AUTHINFO USER <user>`` / ``AUTHINFO PASS <pass>``
  는 사용자명·비밀번호를 그대로 와이어에 흘린다(:mod:`forensiclab.ftp` 의
  ``USER``/``PASS``·:mod:`forensiclab.pop3` 의 ``USER``/``PASS`` 와 같은
  계열). TLS(nntps/STARTTLS) 없이 쓰이면 캡처에서 곧바로 자격증명을 복원한다.
  ``AUTHINFO SASL PLAIN <base64>`` 는 Base64(난독화일 뿐 암호화 아님)로 같은
  값을 흘린다(:mod:`forensiclab.smtp` 의 ``AUTH PLAIN`` 과 동일).
- **콘텐츠 전송·은닉 채널**: ``ARTICLE``/``BODY``/``HEAD`` 는 글을 내려받고
  (유출 정황), ``POST``/``IHAVE``/``TAKETHIS`` 는 글을 올린다(주입·배포 정황).
  뉴스그룹은 익명·전파성이 높아 멀웨어 배포·C2 메시지·탈취 데이터의 은닉
  채널로 악용된다(:mod:`forensiclab.irc` 의 C2 채널·:mod:`forensiclab.tftp`
  의 스테이징과 같은 계열).
- **뉴스그룹 접근·열거**: ``GROUP <name>`` 은 대상 그룹을 선택하고,
  ``LIST``/``NEWGROUPS``/``NEWNEWS`` 는 그룹·신규 글 목록을 캐낸다 — 어떤
  그룹이 채널로 쓰이는지 짚는 정찰·접근 증거(:mod:`forensiclab.imap` 의
  ``SELECT``·:mod:`forensiclab.smtp` 의 ``VRFY`` 열거와 같은 계열).
- **인증 실패·브루트포스**: ``481``(인증 거부)·``482``(순서 오류)의 반복은
  자격증명 추측 정황이다(:mod:`forensiclab.smtp` 의 ``535``·
  :mod:`forensiclab.ftp` 의 ``530`` 과 같은 계열). ``381`` 은 비밀번호 추가
  입력을 요구하는 중간 응답이라 ``AUTHINFO PASS`` 직전 단계를 짚는다.

메시지 포맷(텍스트, CRLF 종단)::

    AUTHINFO USER attacker            (명령: 동사 SP 인자)
    AUTHINFO PASS s3cret
    GROUP alt.binaries.warez
    ARTICLE <msg-id@host>
    POST
    IHAVE <leak@evil.example>

    200 news.corp.example ready       (응답: 3자리 코드 SP 텍스트)
    381 PASS required                 (중간: 추가 입력 필요)
    281 Authentication accepted
    481 Authentication failed

설계 원칙(:mod:`forensiclab.smtp`·:mod:`forensiclab.ftp` 와 동일):
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
    "NNTP_PORTS",
    "NntpCommand",
    "NntpReply",
    "parse_nntp",
    "decode_sasl_plain",
]

# NNTP 표준 포트(TCP): 119 평문·563 nntps(암묵 TLS).
NNTP_PORTS = (119, 563)

# 자격증명을 협상하는 명령 — 평문/Base64 노출의 핵심.
_AUTH_VERBS = frozenset({"AUTHINFO"})

# 글을 내려받는(유출) 명령.
_RETRIEVE_VERBS = frozenset({"ARTICLE", "HEAD", "BODY", "STAT"})

# 글을 올리는(주입·배포) 명령.
_POST_VERBS = frozenset({"POST", "IHAVE", "TAKETHIS"})

# 그룹·신규 글 목록을 캐내는 열거 명령.
_ENUM_VERBS = frozenset({"LIST", "NEWGROUPS", "NEWNEWS"})


def decode_sasl_plain(token: str) -> Optional[Tuple[str, str, str]]:
    """``AUTHINFO SASL PLAIN`` 의 Base64 초기 응답을 (authzid, authcid, passwd).

    SASL PLAIN 은 ``authzid \\0 authcid \\0 passwd`` 를 Base64 로 감싼다
    (RFC 4616 — :mod:`forensiclab.smtp` 의 ``AUTH PLAIN`` 과 동일한 SASL).
    Base64 는 난독화일 뿐이라 캡처에서 곧바로 자격증명이 복원된다.
    디코드 실패·필드 수 불일치면 ``None``.

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
class NntpCommand:
    """파싱된 NNTP 클라이언트 명령 한 줄.

    Attributes:
        verb: 대문자로 정규화된 명령 동사(``GROUP``·``ARTICLE``·``AUTHINFO`` …).
        arg: 명령 인자(없으면 빈 문자열). 자격증명/그룹명/메시지ID가 여기 담긴다.
        raw: 원본 줄(종단 CRLF 제외).
    """

    verb: str
    arg: str
    raw: str

    @property
    def is_auth(self) -> bool:
        """인증을 협상하는 명령(``AUTHINFO``)인가 — 자격증명 노출 지점."""
        return self.verb in _AUTH_VERBS

    @property
    def is_retrieve(self) -> bool:
        """글을 내려받는 명령(``ARTICLE``·``BODY`` …)인가 — 유출 정황."""
        return self.verb in _RETRIEVE_VERBS

    @property
    def is_post(self) -> bool:
        """글을 올리는 명령(``POST``·``IHAVE``·``TAKETHIS``)인가 — 주입·배포 정황."""
        return self.verb in _POST_VERBS

    @property
    def is_enumeration(self) -> bool:
        """그룹·신규 글 목록 열거 명령(``LIST``·``NEWGROUPS``·``NEWNEWS``)인가."""
        return self.verb in _ENUM_VERBS

    @property
    def is_group_select(self) -> bool:
        """``GROUP`` — 대상 뉴스그룹 선택(채널 접근) 명령인가."""
        return self.verb == "GROUP"

    @property
    def newsgroup(self) -> Optional[str]:
        """``GROUP`` 인자의 뉴스그룹명 — 그 외 명령이면 ``None``.

        어떤 그룹이 배포/은닉 채널로 쓰이는지 짚는 단서.
        """
        if self.verb != "GROUP" or not self.arg:
            return None
        return self.arg.split(None, 1)[0]

    @property
    def cleartext_credential(self) -> Optional[Tuple[str, str]]:
        """``AUTHINFO USER/PASS`` 의 (종류, 값) — 평문 자격증명 노출.

        ``AUTHINFO USER alice`` → ``("USER", "alice")``,
        ``AUTHINFO PASS s3cret`` → ``("PASS", "s3cret")``.
        ``AUTHINFO`` 의 USER/PASS 부명령이 아니면 ``None``.
        """
        if self.verb != "AUTHINFO":
            return None
        parts = self.arg.split(None, 1)
        if not parts:
            return None
        sub = parts[0].upper()
        if sub not in ("USER", "PASS"):
            return None
        value = parts[1].strip() if len(parts) > 1 else ""
        return (sub, value)

    @property
    def sasl_credentials(self) -> Optional[Tuple[str, str, str]]:
        """``AUTHINFO SASL PLAIN <base64>`` 초기 응답의 (authzid, authcid, passwd).

        ``AUTHINFO SASL PLAIN`` 이 아니거나 초기 응답이 없으면 ``None``.
        :func:`decode_sasl_plain` 으로 Base64 를 환원한다.
        """
        if self.verb != "AUTHINFO":
            return None
        parts = self.arg.split(None, 2)
        if len(parts) != 3:
            return None
        if parts[0].upper() != "SASL" or parts[1].upper() != "PLAIN":
            return None
        return decode_sasl_plain(parts[2])


@dataclass(frozen=True)
class NntpReply:
    """파싱된 NNTP 서버 응답 한 줄.

    Attributes:
        code: 3자리 응답 코드(``200``·``281``·``481`` …).
        text: 코드 뒤 텍스트(없으면 빈 문자열).
        raw: 원본 줄(종단 CRLF 제외).
    """

    code: int
    text: str
    raw: str

    @property
    def category(self) -> int:
        """응답 코드 1번째 자리(1~5) — 군(group) 분류.

        1=정보, 2=완료, 3=계속(추가 입력 필요), 4=수행 불가, 5=오류.
        """
        return self.code // 100

    @property
    def is_positive_completion(self) -> bool:
        """2yz(요청 성공 완료) 응답인가."""
        return self.category == 2

    @property
    def is_auth_accepted(self) -> bool:
        """``281``(인증 수락) — 자격증명이 통과한 지점."""
        return self.code == 281

    @property
    def is_password_required(self) -> bool:
        """``381``(비밀번호 추가 입력 요구) — ``AUTHINFO PASS`` 직전 중간 응답."""
        return self.code == 381

    @property
    def is_auth_failure(self) -> bool:
        """``481``(인증 거부)·``482``(순서 오류) — 반복 시 브루트포스 정황."""
        return self.code in (481, 482)


def _first_line(data: bytes, offset: int) -> Optional[str]:
    """``offset`` 부터 첫 줄(CRLF/LF 이전)을 ASCII 텍스트로."""
    if offset < 0 or offset > len(data):
        return None
    chunk = data[offset:]
    if not chunk:
        return None
    # NNTP 제어 흐름은 ASCII 텍스트. 비텍스트 바이트는 관대하게 무시(replace).
    text = chunk.decode("ascii", "replace")
    line = text.replace("\r\n", "\n").split("\n", 1)[0]
    return line


def parse_nntp(
    data: bytes, offset: int = 0
) -> Optional[Union[NntpCommand, NntpReply]]:
    """원시 바이트에서 NNTP 한 줄을 파싱한다.

    Args:
        data: NNTP 흐름 바이트. 보통 TCP 119/563 페이로드
            (:class:`forensiclab.netdissect` 의 ``payload_offset`` 부터)다.
        offset: 줄이 시작하는 위치(기본 0).

    Returns:
        서버 응답이면 :class:`NntpReply`(정확히 3자리 숫자로 시작하고 그 뒤가
        공백 또는 줄 끝인 줄), 그 외 비어 있지 않은 줄이면 :class:`NntpCommand`.
        빈 입력/공백뿐인 줄은 ``None``.
    """
    line = _first_line(data, offset)
    if line is None:
        return None
    stripped = line.rstrip()
    if not stripped.strip():
        return None

    # 응답 판별: 정확히 3자리 숫자 + (공백|줄 끝). NNTP 응답은 멀티라인 중간
    # 표식('-')이 없다 — 본문은 별도 줄로, 종단은 '.' 단독 줄.
    if len(stripped) >= 3 and stripped[:3].isdigit():
        sep = stripped[3:4]
        if sep in ("", " "):
            code = int(stripped[:3])
            text = stripped[4:] if len(stripped) > 4 else ""
            return NntpReply(code=code, text=text.strip(), raw=stripped)

    # 명령: 동사 SP 인자. 동사는 대문자로 정규화.
    parts = stripped.split(None, 1)
    verb = parts[0].upper()
    arg = parts[1].strip() if len(parts) > 1 else ""
    return NntpCommand(verb=verb, arg=arg, raw=stripped)
