"""IMAP — Internet Message Access Protocol v4rev1 파싱 코어 (RFC 3501).

:mod:`forensiclab.netdissect` 가 식별한 TCP(포트 143·imaps 993) 페이로드는
IMAP 한 줄일 수 있다. 이 모듈이 그 줄을 해석한다. 메일 3종 세트의 마지막
조각이다 — :mod:`forensiclab.smtp` 가 메일 *송신*(TCP 25)을,
:mod:`forensiclab.pop3` 가 사서함에서의 단순 *수신·삭제*(TCP 110)를 다룬다면
IMAP 은 서버에 남긴 사서함을 *원격에서 탐색·열람·조작* 한다(POP3 가 "내려받고
지우는" 모델이라면 IMAP 은 "서버에 두고 다루는" 모델).

IMAP 흐름은 평문 줄(``CRLF`` 종단)의 교환이지만 POP3·FTP 와 결정적으로 다른
점은 **태그(tag)** 다. 클라이언트는 명령마다 임의의 태그를 앞에 붙이고
(``a001 LOGIN …``), 서버는 그 태그로 완료 응답을 짝지어 돌려준다
(``a001 OK …``). 서버 응답에는 세 갈래가 있다:

- **태그 응답**: ``<tag> SP <status> SP text`` — 명령 완료 상태(``OK``/``NO``/
  ``BAD``).
- **무태그(untagged) 응답**: ``* …`` — 상태 응답(``* OK …``)이거나 데이터
  응답(``* 18 EXISTS``·``* CAPABILITY …``).
- **연속(continuation) 요청**: ``+ …`` — 서버가 다음 입력을 기다린다(SASL
  교환 등).

평문이라 침해/사고 분석에서 단서가 짙다(:mod:`forensiclab.pop3` 와 같은 계열):

- **평문 자격증명 노출**: ``LOGIN user pass`` 는 사용자명·비밀번호를 와이어에
  그대로 흘린다(:mod:`forensiclab.ftp`·:mod:`forensiclab.pop3` 의 ``USER``/
  ``PASS`` 와 같은 계열). 인자는 따옴표로 감싸일 수 있다(``LOGIN "alice"
  "s3 cret"``).
- **SASL 자격증명**: ``AUTHENTICATE PLAIN <base64>`` 의 초기 응답(SASL-IR)은
  난독화일 뿐 암호화가 아니라 캡처에서 곧바로 자격증명이 복원된다
  (:mod:`forensiclab.smtp`·:mod:`forensiclab.pop3` 의 ``AUTH PLAIN`` 과 같은
  계열).
- **사서함 접근·열람**: ``SELECT``/``EXAMINE`` 는 어떤 사서함이 열렸는지,
  ``FETCH``(``UID FETCH`` 포함)는 어떤 메시지 본문이 끌려갔는지 보여준다 —
  메일 탈취의 직접 증거다(:mod:`forensiclab.pop3` 의 ``RETR`` 와 같은 계열).
- **사후 정리(anti-forensics)**: ``STORE … +FLAGS (\\Deleted)`` 로 삭제
  플래그를 달고 ``EXPUNGE`` 로 영구 제거하는 흐름은 침해 후 흔적/증거 메일을
  지우는 정황이다(:mod:`forensiclab.pop3` 의 ``DELE`` 와 같은 계열).
- **인증 실패·브루트포스**: ``LOGIN`` 에 대한 태그 ``NO`` 응답의 반복은
  자격증명 추측 정황이다(:mod:`forensiclab.ftp` 의 ``530``·
  :mod:`forensiclab.pop3` 의 ``-ERR`` 와 같은 계열). ``BAD`` 는 프로토콜
  오류(비정상 클라이언트/퍼징 정황)다.

메시지 포맷(텍스트, CRLF 종단)::

    * OK [CAPABILITY IMAP4rev1] mail.corp.example ready   (무태그 인사말)
    a001 LOGIN alice s3cret                  (명령: 태그 SP 동사 SP 인자)
    a001 OK [CAPABILITY ...] LOGIN completed (태그 응답: 태그 SP 상태 SP 텍스트)
    a002 AUTHENTICATE PLAIN AGFsaWNlAHMzY3JldA==   (SASL: Base64 자격증명)
    a003 SELECT INBOX
    * 18 EXISTS                              (무태그 데이터 응답)
    a004 UID FETCH 1:* (BODY[])              (메시지 본문 다운로드 = 유출)
    + Ready for additional input             (연속 요청)
    a005 NO [AUTHENTICATIONFAILED] invalid credentials

설계 원칙(:mod:`forensiclab.pop3`·:mod:`forensiclab.smtp` 와 동일):
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
from typing import List, Optional, Tuple, Union

__all__ = [
    "IMAP_PORTS",
    "ImapCommand",
    "ImapResponse",
    "parse_imap",
    "parse_login_argument",
    "decode_auth_plain",
]

# IMAP 표준 포트(TCP): 143 평문·993 imaps(암묵 TLS).
IMAP_PORTS = (143, 993)

# 서버 상태 응답의 상태어 — 명령 완료/인사말의 결과를 표시(RFC 3501 §7.1).
# OK=성공, NO=동작 실패(인증 실패 등), BAD=프로토콜 오류,
# PREAUTH=인증된 채로 시작한 인사말, BYE=서버 종료/로그아웃.
_STATUS_WORDS = frozenset({"OK", "NO", "BAD", "PREAUTH", "BYE"})


def parse_login_argument(arg: str) -> Optional[Tuple[str, str]]:
    """``LOGIN`` 인자를 (user, password) 로 나눈다.

    ``LOGIN`` 인자는 두 개의 astring(사용자·비밀번호)이다. astring 은 그냥
    원자 토큰일 수도, 따옴표로 감싸인 문자열일 수도 있다(``"alice"``,
    ``"s3 cret"``). 따옴표 안에서는 ``\\`` 로 ``"``·``\\`` 를 이스케이프한다.
    이 함수는 두 모양 모두 해석해 평문 자격증명을 환원한다. 토큰이 둘 미만이면
    ``None``.

    Examples:
        ``alice s3cret`` → ``("alice", "s3cret")``
        ``"alice" "s3 cret"`` → ``("alice", "s3 cret")``
    """
    if arg is None:
        return None
    toks = _astring_tokens(arg)
    if len(toks) < 2:
        return None
    return (toks[0], toks[1])


def _astring_tokens(s: str) -> List[str]:
    """공백 분리하되 따옴표 문자열(``"…"``, ``\\`` 이스케이프)을 한 토큰으로."""
    tokens: List[str] = []
    i, n = 0, len(s)
    while i < n:
        while i < n and s[i] in " \t":
            i += 1
        if i >= n:
            break
        if s[i] == '"':
            i += 1
            buf: List[str] = []
            while i < n and s[i] != '"':
                if s[i] == "\\" and i + 1 < n:
                    i += 1
                buf.append(s[i])
                i += 1
            i += 1  # 닫는 따옴표 소비(없으면 줄 끝)
            tokens.append("".join(buf))
        else:
            start = i
            while i < n and s[i] not in " \t":
                i += 1
            tokens.append(s[start:i])
    return tokens


def decode_auth_plain(token: str) -> Optional[Tuple[str, str, str]]:
    """``AUTHENTICATE PLAIN`` 의 Base64 초기 응답을 (authzid, authcid, passwd) 로.

    SASL PLAIN 은 ``authzid \\0 authcid \\0 passwd`` 를 Base64 로 감싼다
    (RFC 4616). Base64 는 난독화일 뿐이라 캡처에서 곧바로 자격증명이
    복원된다(:func:`forensiclab.pop3.decode_auth_plain` 과 같은 계열).
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
class ImapCommand:
    """파싱된 IMAP 클라이언트 명령 한 줄.

    Attributes:
        tag: 클라이언트가 명령마다 붙이는 태그(``a001`` …). 서버는 이 태그로
            완료 응답(:class:`ImapResponse`)을 짝짓는다.
        verb: 대문자로 정규화된 명령 동사(``LOGIN``·``SELECT``·``FETCH`` …).
        arg: 명령 인자(없으면 빈 문자열).
        raw: 원본 줄(종단 CRLF 제외).
    """

    tag: str
    verb: str
    arg: str
    raw: str

    @property
    def effective_verb(self) -> str:
        """UID 접두를 벗긴 실질 동사.

        ``UID FETCH``·``UID STORE`` 는 메시지를 일련번호 대신 UID 로 지정하는
        동등 명령이다. 이때 ``verb`` 는 ``UID`` 지만 실제 동작은 인자 첫
        토큰(``FETCH``/``STORE`` …)에 있다. 유출/삭제 판별이 UID 변형도 잡도록
        그 실질 동사를 돌려준다. UID 명령이 아니면 ``verb`` 그대로.
        """
        if self.verb == "UID" and self.arg:
            return self.arg.split(None, 1)[0].upper()
        return self.verb

    @property
    def is_credential(self) -> bool:
        """평문 자격증명을 흘리는 ``LOGIN`` 명령인가."""
        return self.verb == "LOGIN"

    @property
    def is_select(self) -> bool:
        """사서함을 여는 ``SELECT``/``EXAMINE`` 명령인가 — 접근 대상 사서함 단서."""
        return self.effective_verb in ("SELECT", "EXAMINE")

    @property
    def is_retrieval(self) -> bool:
        """메시지 본문을 끌어가는 ``FETCH``(``UID FETCH`` 포함)인가 — 유출 증거."""
        return self.effective_verb == "FETCH"

    @property
    def is_delete(self) -> bool:
        """증거 정리(anti-forensics) 정황 명령인가.

        ``EXPUNGE``(삭제 플래그가 달린 메시지를 영구 제거)이거나, ``STORE``
        (``UID STORE`` 포함) 인자가 ``\\Deleted`` 플래그를 설정하는 경우다
        (:attr:`forensiclab.pop3.Pop3Command.is_delete` 와 같은 계열).
        """
        ev = self.effective_verb
        if ev == "EXPUNGE":
            return True
        if ev == "STORE":
            return "\\deleted" in self.arg.lower()
        return False

    @property
    def mailbox(self) -> Optional[str]:
        """``SELECT``/``EXAMINE`` 가 여는 사서함 이름 — 그 외면 ``None``.

        UID 접두는 ``SELECT``/``EXAMINE`` 에 쓰이지 않으므로 ``verb`` 직후
        첫 astring 토큰이 사서함이다.
        """
        if not self.is_select:
            return None
        toks = _astring_tokens(self.arg)
        return toks[0] if toks else None

    @property
    def login_credentials(self) -> Optional[Tuple[str, str]]:
        """``LOGIN`` 인자의 (user, password) — 그 외 명령이면 ``None``.

        :func:`parse_login_argument` 로 환원한다(따옴표 astring 처리 포함).
        평문이라 캡처에서 곧바로 복원된다.
        """
        if self.verb != "LOGIN":
            return None
        return parse_login_argument(self.arg)

    @property
    def auth_credentials(self) -> Optional[Tuple[str, str, str]]:
        """``AUTHENTICATE PLAIN <base64>`` 초기 응답의 (authzid, authcid, passwd).

        ``AUTHENTICATE PLAIN`` 이 아니거나 초기 응답(SASL-IR)이 없으면
        ``None``. :func:`decode_auth_plain` 으로 Base64 를 환원한다.
        ``AUTHENTICATE LOGIN`` 처럼 자격증명을 연속 응답(``+``)으로 따로 주는
        방식은 한 줄에 담기지 않으므로 여기서 잡지 않는다.
        """
        if self.verb != "AUTHENTICATE":
            return None
        parts = self.arg.split(None, 1)
        if len(parts) != 2 or parts[0].upper() != "PLAIN":
            return None
        return decode_auth_plain(parts[1])


@dataclass(frozen=True)
class ImapResponse:
    """파싱된 IMAP 서버 응답 한 줄.

    IMAP 서버 응답은 POP3 의 ``+OK``/``-ERR`` 두 갈래와 달리 세 갈래다 —
    태그 응답·무태그 응답·연속 요청. :attr:`tag` 가 어느 갈래인지 결정한다.

    Attributes:
        tag: 태그 응답이면 짝지을 명령 태그(``a001`` …), 무태그 응답이면
            ``"*"``, 연속 요청이면 ``"+"``.
        status: 상태어(``OK``/``NO``/``BAD``/``PREAUTH``/``BYE``, 대문자 정규화)
            또는 상태가 없는 응답(데이터 응답·연속 요청)이면 빈 문자열.
        text: 상태/표시자 뒤 텍스트(없으면 빈 문자열).
        raw: 원본 줄(종단 CRLF 제외).
    """

    tag: str
    status: str
    text: str
    raw: str

    @property
    def is_untagged(self) -> bool:
        """무태그 응답(``*`` 로 시작)인가 — 상태 응답 또는 데이터 응답."""
        return self.tag == "*"

    @property
    def is_continuation(self) -> bool:
        """연속 요청(``+`` 로 시작)인가 — 서버가 다음 입력을 기다림(SASL 등)."""
        return self.tag == "+"

    @property
    def is_tagged(self) -> bool:
        """명령 완료를 짝짓는 태그 응답인가(무태그·연속이 아닌)."""
        return not self.is_untagged and not self.is_continuation

    @property
    def is_ok(self) -> bool:
        """긍정 상태(``OK``)인가."""
        return self.status == "OK"

    @property
    def is_error(self) -> bool:
        """실패 상태(``NO``/``BAD``)인가.

        태그 ``NO`` 가 ``LOGIN`` 에 반복되면 자격증명 추측(브루트포스) 정황,
        ``BAD`` 는 프로토콜 오류(비정상 클라이언트/퍼징) 정황이다.
        """
        return self.status in ("NO", "BAD")

    @property
    def is_bye(self) -> bool:
        """``BYE`` 상태인가 — 서버 종료/연결 강제 종료 정황."""
        return self.status == "BYE"


def _first_line(data: bytes, offset: int) -> Optional[str]:
    """``offset`` 부터 첫 줄(CRLF/LF 이전)을 ASCII 텍스트로."""
    if offset < 0 or offset > len(data):
        return None
    chunk = data[offset:]
    if not chunk:
        return None
    # IMAP 흐름은 ASCII 텍스트. 비텍스트 바이트는 관대하게 무시(replace).
    text = chunk.decode("ascii", "replace")
    line = text.replace("\r\n", "\n").split("\n", 1)[0]
    return line


def parse_imap(
    data: bytes, offset: int = 0
) -> Optional[Union[ImapCommand, ImapResponse]]:
    """원시 바이트에서 IMAP 한 줄을 파싱한다.

    Args:
        data: IMAP 흐름 바이트. 보통 TCP 143 페이로드
            (:class:`forensiclab.netdissect` 의 ``payload_offset`` 부터)다.
        offset: 줄이 시작하는 위치(기본 0).

    Returns:
        서버 응답이면 :class:`ImapResponse`(``*``/``+`` 로 시작하거나, 태그
        뒤 둘째 토큰이 상태어인 줄), 그 외 비어 있지 않은 줄이면
        :class:`ImapCommand`. 빈 입력·공백뿐인 줄·태그만 있고 내용 없는 줄은
        ``None``.

    POP3·FTP 와 달리 IMAP 한 줄만으로는 방향(클라이언트/서버)이 항상 명확하진
    않다. 판별은 RFC 3501 구조를 따른다: ``*``/``+`` 시작은 서버, 태그 뒤 둘째
    토큰이 상태어(``OK``/``NO``/``BAD``/``PREAUTH``/``BYE``)면 서버 응답,
    아니면 클라이언트 명령으로 본다.
    """
    line = _first_line(data, offset)
    if line is None:
        return None
    stripped = line.rstrip()
    if not stripped.strip():
        return None

    head = stripped.split(None, 1)
    first = head[0]
    rest = head[1].strip() if len(head) > 1 else ""

    # 연속 요청: '+' 로 시작.
    if first == "+":
        return ImapResponse(tag="+", status="", text=rest, raw=stripped)

    # 무태그 응답: '*' 로 시작. 둘째 토큰이 상태어면 상태 응답, 아니면 데이터.
    if first == "*":
        sub = rest.split(None, 1)
        if sub and sub[0].upper() in _STATUS_WORDS:
            status = sub[0].upper()
            text = sub[1].strip() if len(sub) > 1 else ""
            return ImapResponse(tag="*", status=status, text=text, raw=stripped)
        return ImapResponse(tag="*", status="", text=rest, raw=stripped)

    # 태그만 있고 내용이 없는 줄은 파싱 불가.
    if not rest:
        return None

    # 태그 뒤 둘째 토큰으로 응답/명령 판별.
    sub = rest.split(None, 1)
    if sub[0].upper() in _STATUS_WORDS:
        status = sub[0].upper()
        text = sub[1].strip() if len(sub) > 1 else ""
        return ImapResponse(tag=first, status=status, text=text, raw=stripped)

    # 명령: 태그 SP 동사 SP 인자. 동사는 대문자로 정규화.
    verb = sub[0].upper()
    arg = sub[1].strip() if len(sub) > 1 else ""
    return ImapCommand(tag=first, verb=verb, arg=arg, raw=stripped)
