"""IRC — Internet Relay Chat 메시지 파싱 코어 (RFC 1459·2812).

:mod:`forensiclab.netdissect` 가 식별한 TCP(포트 6667 등) 페이로드는 IRC
흐름의 한 줄일 수 있다. 이 모듈이 그 줄을 해석한다(:mod:`forensiclab.ftp`
가 TCP 21, :mod:`forensiclab.smtp` 가 TCP 25 줄을 다루는 것과 같은 위치).

IRC 는 평문 줄(``CRLF`` 종단)의 교환이다. 한 줄의 구조는::

    [':' prefix SP] command [params...] [':' trailing]

- **prefix**(선택): ``:`` 로 시작. 서버 이름 또는 ``nick!user@host`` 형태의
  발신자 식별. 봇/감염 호스트의 닉·사용자·호스트를 그대로 노출한다.
- **command**: 명령 이름(``PRIVMSG``·``JOIN`` …) 또는 3자리 숫자 응답
  코드(``001``·``433`` …).
- **params**: 공백으로 나뉜 인자들. 마지막 인자가 ``:`` 로 시작하면
  *trailing*(공백 포함 가능한 자유 텍스트)이다.

평문이라 침해/사고 분석에서 단서가 짙다 — 특히 IRC 는 **봇넷 C2 의 고전적
백본**이다(:mod:`forensiclab.dns` 가 C2 도메인을, :mod:`forensiclab.http`
가 C2 비컨을 드러내듯, IRC 는 명령 채널 자체를 평문으로 흘린다):

- **평문 서버 자격증명**: ``PASS`` 는 서버 비밀번호를 와이어에 그대로
  흘린다(:mod:`forensiclab.ftp` 의 ``PASS`` 와 같은 계열). 비공개 C2 서버의
  접속 암호가 캡처에서 곧바로 복원된다.
- **봇 신원·등록**: ``NICK``/``USER`` 는 봇이 자신을 등록하는 줄이다.
  기계적으로 생성된 닉(``[USA|XP]12345`` 류)·반복되는 realname 은 봇넷
  식별 단서다(:mod:`forensiclab.hassh`·:mod:`forensiclab.ja3` 가 구현을
  핑거프린트하듯 명명 규칙이 패밀리를 가른다).
- **C2 채널·명령 전달**: ``JOIN`` 은 봇이 모이는 제어 채널을,
  ``PRIVMSG``/``NOTICE`` 는 채널/봇에 떨어지는 실제 명령(``.ddos``·
  ``!scan``·``.download`` 류)과 그 출력을 노출한다 — C2 command-and-control
  트래픽의 직접 증거다.
- **인증·접속 실패**: ``464``(비밀번호 틀림)·``465``(밴)·``433``(닉 충돌)
  같은 숫자 응답의 반복은 접속 실패/자동 재시도 정황이다
  (:mod:`forensiclab.ftp` 의 ``530`` 과 같은 계열).

메시지 예(텍스트, CRLF 종단)::

    PASS s3cr3t
    NICK [USA|XP]98213
    USER bot 0 0 :infected host
    :irc.evil.net 001 [USA|XP]98213 :Welcome
    JOIN #botnet
    :[USA|XP]98213!bot@1.2.3.4 PRIVMSG #botnet :.ddos 9.9.9.9 80

설계 원칙(:mod:`forensiclab.ftp`·:mod:`forensiclab.smtp` 와 동일):
- 부작용 없음: 순수 함수. 디스크/표준출력/네트워크 없음.
- stdlib 전용.
- 안전: 입력 바이트를 변형하지 않는다(읽기 전용). 자격증명/명령을
  노출하되 로깅/전송하지 않는다 — 호출자가 처리.
- 견고: 너무 짧거나 망가진 입력은 예외 대신 ``None``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Tuple

__all__ = [
    "IRC_PORTS",
    "IrcPrefix",
    "IrcMessage",
    "parse_prefix",
    "parse_irc",
]

# IRC 흔한 포트(TCP). 6667 평문 표준, 6697 TLS, 194 IANA 지정, 6660-6669 범위.
IRC_PORTS = (6667, 6697, 194, 6660, 6661, 6662, 6663, 6664, 6665, 6666, 6668, 6669)

# 서버 비밀번호를 와이어에 흘리는 명령 — 평문 노출의 핵심.
_CREDENTIAL_COMMANDS = frozenset({"PASS", "OPER"})

# 봇이 자신을 등록하는 명령 — 신원/명명 규칙 단서.
_REGISTRATION_COMMANDS = frozenset({"NICK", "USER"})

# C2 명령이 실제로 떨어지는 메시지 명령 — command-and-control 직접 증거.
_MESSAGE_COMMANDS = frozenset({"PRIVMSG", "NOTICE"})

# 접속/인증 실패를 알리는 숫자 응답 코드(RFC 2812).
#   433 ERR_NICKNAMEINUSE · 464 ERR_PASSWDMISMATCH · 465 ERR_YOUREBANNEDCREEP
_AUTH_FAILURE_NUMERICS = frozenset({433, 464, 465})


@dataclass(frozen=True)
class IrcPrefix:
    """``nick!user@host`` 형태의 발신자 prefix 를 분해한 결과.

    서버 이름만 있는 prefix(``irc.evil.net``)는 :attr:`nick` 에 통째로
    들어가고 :attr:`user`·:attr:`host` 는 ``None`` 이다(``!``/``@`` 가 없으니).
    봇/감염 호스트의 닉·사용자·소스 IP 를 그대로 노출한다.

    Attributes:
        nick: ``!`` 이전 부분(또는 서버 이름 전체).
        user: ``!`` 와 ``@`` 사이 사용자명(없으면 ``None``).
        host: ``@`` 이후 호스트/IP(없으면 ``None``).
        raw: 원본 prefix 문자열(앞의 ``:`` 제외).
    """

    nick: str
    user: Optional[str]
    host: Optional[str]
    raw: str

    @property
    def is_server(self) -> bool:
        """서버 이름 prefix 인가 — ``user``/``host`` 가 없고 닉에 ``.`` 포함."""
        return self.user is None and self.host is None and "." in self.nick


def parse_prefix(prefix: str) -> Optional[IrcPrefix]:
    """``nick!user@host`` prefix 문자열을 :class:`IrcPrefix` 로 환원한다.

    앞에 ``:`` 가 있으면 떼고 파싱한다. ``!``/``@`` 가 없으면 전체를
    :attr:`~IrcPrefix.nick`(서버 이름)으로 본다. 빈 문자열이면 ``None``.

    Examples:
        ``nick!user@host`` → nick="nick", user="user", host="host"
        ``irc.evil.net``  → nick="irc.evil.net", user=None, host=None
    """
    if prefix is None:
        return None
    s = prefix.strip()
    if s.startswith(":"):
        s = s[1:]
    if not s:
        return None
    host: Optional[str] = None
    user: Optional[str] = None
    rest = s
    # host 먼저 분리(@ 이후). user 는 ! 와 @ 사이.
    if "@" in rest:
        rest, host = rest.split("@", 1)
    if "!" in rest:
        rest, user = rest.split("!", 1)
    return IrcPrefix(nick=rest, user=user, host=host, raw=s)


@dataclass(frozen=True)
class IrcMessage:
    """파싱된 IRC 메시지 한 줄.

    Attributes:
        prefix: 발신자 prefix(:class:`IrcPrefix`). 없으면 ``None``.
        command: 명령 이름(대문자 정규화, ``PRIVMSG``·``JOIN`` …) 또는
            3자리 숫자 응답 코드 문자열(``001``·``433`` …).
        params: trailing 을 포함한 인자 튜플. 마지막이 trailing 이면 그
            텍스트가 그대로(공백 포함) 마지막 원소로 들어간다.
        trailing: ``:`` 로 시작했던 마지막 자유 텍스트 인자(없으면 ``None``).
            채널 메시지의 본문(C2 명령)이 여기 담긴다.
        raw: 원본 줄(종단 CRLF 제외).
    """

    prefix: Optional[IrcPrefix]
    command: str
    params: Tuple[str, ...]
    trailing: Optional[str]
    raw: str

    @property
    def numeric(self) -> Optional[int]:
        """명령이 3자리 숫자 응답이면 그 정수, 아니면 ``None``."""
        if len(self.command) == 3 and self.command.isdigit():
            return int(self.command)
        return None

    @property
    def is_credential(self) -> bool:
        """서버 비밀번호를 평문으로 흘리는 명령(``PASS``·``OPER``)인가."""
        return self.command in _CREDENTIAL_COMMANDS

    @property
    def is_registration(self) -> bool:
        """봇 신원 등록 명령(``NICK``·``USER``)인가 — 명명 규칙 단서."""
        return self.command in _REGISTRATION_COMMANDS

    @property
    def is_message(self) -> bool:
        """채널/유저로 가는 메시지(``PRIVMSG``·``NOTICE``)인가 — C2 명령 전달."""
        return self.command in _MESSAGE_COMMANDS

    @property
    def is_auth_failure(self) -> bool:
        """접속/인증 실패 숫자 응답(``433``·``464``·``465``)인가 — 재시도 정황."""
        n = self.numeric
        return n is not None and n in _AUTH_FAILURE_NUMERICS

    @property
    def target(self) -> Optional[str]:
        """메시지/JOIN 의 대상(채널 ``#botnet`` 또는 닉) — 첫 번째 인자.

        ``PRIVMSG``·``NOTICE``·``JOIN``·``PART`` 의 첫 인자를 돌려준다. 해당
        명령이 아니거나 인자가 없으면 ``None``. C2 제어 채널 식별 단서.
        """
        if self.command not in _MESSAGE_COMMANDS and self.command not in ("JOIN", "PART"):
            return None
        if not self.params:
            return None
        return self.params[0]

    @property
    def is_channel_target(self) -> bool:
        """대상이 채널인가(``#``·``&``·``+``·``!`` 로 시작) — C2 채널 정황."""
        tgt = self.target
        return bool(tgt) and tgt[0] in "#&+!"


def _first_line(data: bytes, offset: int) -> Optional[str]:
    """``offset`` 부터 첫 줄(CRLF/LF 이전)을 텍스트로(UTF-8 관대 디코드)."""
    if offset < 0 or offset > len(data):
        return None
    chunk = data[offset:]
    if not chunk:
        return None
    # IRC 본문은 임의 인코딩일 수 있다 — 비텍스트 바이트는 관대하게(replace).
    text = chunk.decode("utf-8", "replace")
    line = text.replace("\r\n", "\n").split("\n", 1)[0]
    return line


def parse_irc(data: bytes, offset: int = 0) -> Optional[IrcMessage]:
    """원시 바이트에서 IRC 메시지 한 줄을 파싱한다.

    Args:
        data: IRC 흐름 바이트. 보통 TCP 6667 페이로드
            (:class:`forensiclab.netdissect` 의 ``payload_offset`` 부터)다.
        offset: 줄이 시작하는 위치(기본 0).

    Returns:
        :class:`IrcMessage`. 빈 입력/공백뿐인 줄/명령이 없는 줄은 ``None``.

    문법(RFC 2812)::

        [':' prefix SP] command *( SP middle ) [SP ':' trailing]

    trailing(``:`` 로 시작하는 마지막 인자)은 공백을 포함할 수 있어 그대로
    한 원소로 보존한다. prefix·command 만 있고 인자가 없는 줄도 정상 파싱.
    """
    line = _first_line(data, offset)
    if line is None:
        return None
    rest = line.rstrip("\r\n").strip()
    if not rest:
        return None

    prefix: Optional[IrcPrefix] = None
    if rest.startswith(":"):
        # prefix 는 첫 공백까지. 공백이 없으면 prefix 만 있고 명령이 없는 셈.
        sp = rest.find(" ")
        if sp < 0:
            return None
        prefix = parse_prefix(rest[1:sp])
        rest = rest[sp + 1:].lstrip()
        if not rest:
            return None

    # command 와 그 뒤 인자 영역을 trailing 기준으로 가른다.
    trailing: Optional[str] = None
    # ' :' 가 나오면 그 이후가 trailing(공백 포함 자유 텍스트).
    ti = rest.find(" :")
    if ti >= 0:
        trailing = rest[ti + 2:]
        head = rest[:ti]
    else:
        head = rest

    tokens = head.split()
    if not tokens:
        return None
    command = tokens[0].upper()
    middle = tuple(tokens[1:])
    params = middle + (trailing,) if trailing is not None else middle

    return IrcMessage(
        prefix=prefix,
        command=command,
        params=params,
        trailing=trailing,
        raw=line.rstrip("\r\n"),
    )
