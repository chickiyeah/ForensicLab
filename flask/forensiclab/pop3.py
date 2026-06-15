"""POP3 — Post Office Protocol v3 파싱 코어 (RFC 1939).

:mod:`forensiclab.netdissect` 가 식별한 TCP(포트 110·pop3s 995) 페이로드는
POP3 한 줄일 수 있다. 이 모듈이 그 줄을 해석한다(:mod:`forensiclab.ftp` 가
TCP 21 제어 채널을, :mod:`forensiclab.smtp` 가 TCP 25 메일 송신을 다루는
것과 같은 위치 — 모두 텍스트 명령/응답 한 줄 계열). SMTP 가 메일 *송신*
이라면 POP3 는 사서함에서 메일을 *수신·삭제* 하는 반대 방향이다.

POP3 흐름은 평문 줄(``CRLF`` 종단)의 교환이다 — 클라이언트는 명령
(``USER``·``PASS``·``RETR`` …)을, 서버는 상태 표시자(``+OK``/``-ERR``)로
시작하는 응답을 보낸다(:mod:`forensiclab.ftp`·:mod:`forensiclab.smtp` 의
3자리 코드와 달리 POP3 는 ``+OK``/``-ERR`` 두 가지뿐). 평문이라 침해/사고
분석에서 단서가 짙다:

- **평문 자격증명 노출**: ``USER``·``PASS`` 는 사용자명·비밀번호를 와이어에
  그대로 흘린다(:mod:`forensiclab.ftp` 의 ``USER``/``PASS`` 와 같은 계열).
  ``APOP`` 은 서버 인사말의 타임스탬프 배너와 공유 비밀을 MD5 한 다이제스트
  라 비밀번호를 직접 드러내진 않지만, 배너가 캡처에 있으면 오프라인
  사전공격(다이제스트 크래킹)의 입력이 된다.
- **SASL 자격증명**: ``AUTH PLAIN`` 의 Base64 초기 응답은 난독화일 뿐 암호화가
  아니라 캡처에서 곧바로 사용자명·비밀번호가 복원된다(:mod:`forensiclab.smtp`
  의 ``AUTH PLAIN`` 과 같은 계열).
- **메일 수신·유출**: ``RETR``(메시지 전문 다운로드)·``TOP``(헤더+본문 일부)는
  어떤 사서함 메시지가 끌려갔는지 보여준다 — 메일 탈취의 직접 증거다
  (:mod:`forensiclab.ftp` 의 ``RETR``·:mod:`forensiclab.tftp` 의 RRQ 와 같은
  계열).
- **사후 정리(anti-forensics)**: ``DELE``(삭제 표시)는 침해 후 흔적/증거
  메일을 지우는 정황일 수 있다.
- **인증 실패·브루트포스**: ``-ERR`` 응답(특히 ``PASS`` 직후)의 반복은
  자격증명 추측 정황이다(:mod:`forensiclab.ftp` 의 ``530``·
  :mod:`forensiclab.smtp` 의 ``535`` 와 같은 계열).

메시지 포맷(텍스트, CRLF 종단)::

    +OK POP3 server ready <1896.697170952@mail.corp.example>  (인사말+APOP 배너)
    USER alice                     (명령: 동사 SP 인자)
    PASS s3cret
    APOP alice c4c9334bac560ecc979e58001b3e22fb   (name SP MD5다이제스트)
    AUTH PLAIN AGFsaWNlAHMzY3JldA==               (SASL: Base64 자격증명)
    RETR 1
    -ERR invalid password         (응답: 상태 표시자 SP 텍스트)

설계 원칙(:mod:`forensiclab.ftp`·:mod:`forensiclab.smtp` 와 동일):
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
    "POP3_PORTS",
    "Pop3Command",
    "Pop3Reply",
    "parse_pop3",
    "parse_apop_argument",
    "parse_apop_banner",
    "decode_auth_plain",
]

# POP3 표준 포트(TCP): 110 평문·995 pop3s(암묵 TLS).
POP3_PORTS = (110, 995)

# 자격증명을 와이어에 흘리는 명령 — 평문/다이제스트 노출의 핵심.
_CREDENTIAL_VERBS = frozenset({"USER", "PASS", "APOP"})

# 사서함 메시지를 끌어가는 수신 명령 — 메일 탈취/유출의 직접 증거.
_RETRIEVAL_VERBS = frozenset({"RETR", "TOP"})


def parse_apop_banner(text: str) -> Optional[str]:
    """서버 인사말에서 APOP 타임스탬프 배너(``<…>``)를 뽑는다.

    POP3 인사말은 ``+OK ... <process-id.clock@hostname>`` 형태로 끝나기도
    한다. 꺾쇠 안 토큰이 APOP 다이제스트의 MD5 입력 접두사이므로, 이 배너가
    캡처에 있으면 ``APOP`` 다이제스트의 오프라인 크래킹이 가능해진다.
    꺾쇠 쌍을 포함한 전체 토큰(``<…>``)을 돌려준다. 없으면 ``None``.

    Examples:
        ``+OK ready <1896.697@host>`` → ``"<1896.697@host>"``
    """
    if text is None:
        return None
    lo = text.find("<")
    hi = text.find(">", lo + 1) if lo >= 0 else -1
    if lo < 0 or hi <= lo:
        return None
    return text[lo:hi + 1]


def parse_apop_argument(arg: str) -> Optional[Tuple[str, str]]:
    """``APOP`` 인자를 (name, digest) 로 나눈다.

    ``APOP`` 인자는 ``name SP 16바이트-MD5-16진수`` 형태다. 다이제스트는
    비밀번호 자체가 아니라 ``MD5(배너 + 공유비밀)`` 의 16진수지만,
    :func:`parse_apop_banner` 로 얻은 배너와 짝지으면 오프라인 사전공격의
    입력이 된다. 토큰이 둘이 아니면 ``None``.

    Examples:
        ``alice c4c9334bac560ecc979e58001b3e22fb``
            → ``("alice", "c4c9334bac560ecc979e58001b3e22fb")``
    """
    if arg is None:
        return None
    parts = arg.split()
    if len(parts) != 2:
        return None
    return (parts[0], parts[1])


def decode_auth_plain(token: str) -> Optional[Tuple[str, str, str]]:
    """``AUTH PLAIN`` 의 Base64 초기 응답을 (authzid, authcid, passwd) 로.

    SASL PLAIN 은 ``authzid \\0 authcid \\0 passwd`` 를 Base64 로 감싼다
    (RFC 4616). Base64 는 난독화일 뿐이라 캡처에서 곧바로 자격증명이
    복원된다(:func:`forensiclab.smtp.decode_auth_plain` 과 같은 계열).
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
class Pop3Command:
    """파싱된 POP3 클라이언트 명령 한 줄.

    Attributes:
        verb: 대문자로 정규화된 명령 동사(``USER``·``PASS``·``RETR`` …).
        arg: 명령 인자(없으면 빈 문자열). 자격증명/메시지 번호가 여기 담긴다.
        raw: 원본 줄(종단 CRLF 제외).
    """

    verb: str
    arg: str
    raw: str

    @property
    def is_credential(self) -> bool:
        """자격증명을 흘리는 명령(``USER``·``PASS``·``APOP``)인가."""
        return self.verb in _CREDENTIAL_VERBS

    @property
    def is_retrieval(self) -> bool:
        """사서함 메시지를 끌어가는 수신 명령(``RETR``·``TOP``)인가 — 유출 증거."""
        return self.verb in _RETRIEVAL_VERBS

    @property
    def is_delete(self) -> bool:
        """``DELE``(삭제 표시) — 사후 증거 정리(anti-forensics) 정황 명령인가."""
        return self.verb == "DELE"

    @property
    def apop_credentials(self) -> Optional[Tuple[str, str]]:
        """``APOP`` 인자의 (name, digest) — 그 외 명령이면 ``None``.

        :func:`parse_apop_argument` 로 환원한다. 배너
        (:func:`parse_apop_banner`)와 짝지어 오프라인 크래킹의 입력이 된다.
        """
        if self.verb != "APOP":
            return None
        return parse_apop_argument(self.arg)

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
class Pop3Reply:
    """파싱된 POP3 서버 응답 한 줄.

    POP3 응답은 3자리 코드가 아니라 상태 표시자(``+OK``/``-ERR``)로 시작한다
    (:class:`forensiclab.ftp.FtpReply` 와 다른 점).

    Attributes:
        status: 상태 표시자 — ``"+OK"`` 또는 ``"-ERR"``(원본 대소문자 보존).
        text: 표시자 뒤 텍스트(없으면 빈 문자열).
        raw: 원본 줄(종단 CRLF 제외).
    """

    status: str
    text: str
    raw: str

    @property
    def is_ok(self) -> bool:
        """긍정 응답(``+OK``)인가."""
        return self.status == "+OK"

    @property
    def is_error(self) -> bool:
        """부정 응답(``-ERR``)인가 — ``PASS`` 직후 반복 시 브루트포스 정황."""
        return self.status == "-ERR"

    @property
    def apop_banner(self) -> Optional[str]:
        """응답 텍스트의 APOP 타임스탬프 배너(``<…>``) — 없으면 ``None``.

        보통 인사말(첫 ``+OK``)에만 있다. :func:`parse_apop_banner` 로
        환원하며, ``APOP`` 다이제스트(:attr:`Pop3Command.apop_credentials`)와
        짝지어 오프라인 크래킹의 입력이 된다.
        """
        return parse_apop_banner(self.text)


def _first_line(data: bytes, offset: int) -> Optional[str]:
    """``offset`` 부터 첫 줄(CRLF/LF 이전)을 ASCII 텍스트로."""
    if offset < 0 or offset > len(data):
        return None
    chunk = data[offset:]
    if not chunk:
        return None
    # POP3 흐름은 ASCII 텍스트. 비텍스트 바이트는 관대하게 무시(replace).
    text = chunk.decode("ascii", "replace")
    line = text.replace("\r\n", "\n").split("\n", 1)[0]
    return line


def parse_pop3(
    data: bytes, offset: int = 0
) -> Optional[Union[Pop3Command, Pop3Reply]]:
    """원시 바이트에서 POP3 한 줄을 파싱한다.

    Args:
        data: POP3 흐름 바이트. 보통 TCP 110 페이로드
            (:class:`forensiclab.netdissect` 의 ``payload_offset`` 부터)다.
        offset: 줄이 시작하는 위치(기본 0).

    Returns:
        서버 응답이면 :class:`Pop3Reply`(``+OK`` 또는 ``-ERR`` 로 시작하는
        줄), 그 외 비어 있지 않은 줄이면 :class:`Pop3Command`.
        빈 입력/공백뿐인 줄은 ``None``.
    """
    line = _first_line(data, offset)
    if line is None:
        return None
    stripped = line.rstrip()
    if not stripped.strip():
        return None

    # 응답 판별: 상태 표시자(+OK/-ERR)는 한 토큰으로 시작.
    head = stripped.split(None, 1)
    indicator = head[0]
    if indicator in ("+OK", "-ERR"):
        text = head[1].strip() if len(head) > 1 else ""
        return Pop3Reply(status=indicator, text=text, raw=stripped)

    # 명령: 동사 SP 인자. 동사는 대문자로 정규화.
    parts = stripped.split(None, 1)
    verb = parts[0].upper()
    arg = parts[1].strip() if len(parts) > 1 else ""
    return Pop3Command(verb=verb, arg=arg, raw=stripped)
