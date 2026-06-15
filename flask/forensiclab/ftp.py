"""FTP — File Transfer Protocol 제어 채널 파싱 코어 (RFC 959).

:mod:`forensiclab.netdissect` 가 식별한 TCP(포트 21) 페이로드는 FTP 제어
채널의 한 줄일 수 있다. 이 모듈이 그 줄을 해석한다(:mod:`forensiclab.http`
가 TCP 80, :mod:`forensiclab.ssh` 가 TCP 22 배너를 다루는 것과 같은 위치).

FTP 제어 채널은 평문 줄(``CRLF`` 종단)의 교환이다 — 클라이언트는 명령
(``USER``·``PASS``·``RETR`` …)을, 서버는 3자리 응답 코드(``230``·``530`` …)를
보낸다. 평문이라 침해/사고 분석에서 단서가 짙다(:mod:`forensiclab.syslog` 가
텍스트 한 줄을, :mod:`forensiclab.ssdp` 가 텍스트 헤더 블록을 다루듯,
이 모듈은 텍스트 명령/응답 한 줄을 다룬다):

- **평문 자격증명 노출**: ``USER``·``PASS``·``ACCT`` 는 사용자명·비밀번호를
  와이어에 그대로 흘린다. 캡처에서 곧바로 자격증명을 복원할 수 있고,
  ``USER anonymous`` 는 익명 로그인(흔한 유출 경유지) 정황이다.
- **데이터 채널 상관**: ``PORT``/``EPRT``(능동) 와 ``227``/``229`` 응답(수동)은
  데이터 전송에 쓸 IP·포트를 드러낸다. 이 종착지를
  :mod:`forensiclab.flows` 의 흐름과 짝지으면 어떤 흐름이 실제 파일
  바이트를 날랐는지 재구성된다.
- **전송 활동·유출/스테이징**: ``RETR``(다운로드)·``STOR``/``STOU``/``APPE``
  (업로드)는 어떤 파일이 오갔는지 보여준다 — 데이터 유출·멀웨어 스테이징의
  직접 증거다(:mod:`forensiclab.tftp` 의 RRQ/WRQ 와 같은 계열).
- **인증 실패·브루트포스**: ``530`` 응답(로그인 실패)의 반복은 자격증명
  추측 정황이다(:mod:`forensiclab.radius` 의 Access-Reject·
  :mod:`forensiclab.syslog` 의 인증 실패와 같은 계열).

메시지 포맷(텍스트, CRLF 종단)::

    USER anonymous              (명령: 동사 SP 인자)
    PASS guest@example.com
    PORT 192,168,0,10,7,138     (능동 데이터: h1,h2,h3,h4,p1,p2 → IP+포트)
    RETR /pub/secret.zip

    230 Login successful.       (응답: 3자리 코드 SP 텍스트)
    530 Login incorrect.
    227 Entering Passive Mode (192,168,0,10,7,138).
    229 Entering Extended Passive Mode (|||50000|).

설계 원칙(:mod:`forensiclab.ssdp`·:mod:`forensiclab.syslog` 와 동일):
- 부작용 없음: 순수 함수. 디스크/표준출력/네트워크 없음.
- stdlib 전용.
- 안전: 입력 바이트를 변형하지 않는다(읽기 전용). 자격증명을 노출하되
  로깅/전송하지 않는다 — 호출자가 처리.
- 견고: 너무 짧거나 망가진 입력은 예외 대신 ``None``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Tuple, Union

__all__ = [
    "FTP_CONTROL_PORT",
    "FtpCommand",
    "FtpReply",
    "parse_ftp",
    "parse_port_argument",
    "parse_passive_reply",
]

# FTP 제어 채널 표준 포트(TCP). 데이터 채널(능동 20·수동 임의)과 구분.
FTP_CONTROL_PORT = 21

# 자격증명을 와이어에 흘리는 명령 — 평문 노출의 핵심.
_CREDENTIAL_VERBS = frozenset({"USER", "PASS", "ACCT"})

# 파일 바이트를 옮기는 전송 명령 — 유출/스테이징의 직접 증거.
_TRANSFER_VERBS = frozenset({"RETR", "STOR", "STOU", "APPE"})

# 익명 로그인에 흔히 쓰이는 사용자명.
_ANONYMOUS_USERS = frozenset({"anonymous", "ftp"})


def parse_port_argument(arg: str) -> Optional[Tuple[str, int]]:
    """능동 데이터 채널 인자를 (ip, port) 로 환원.

    ``PORT`` 명령(``h1,h2,h3,h4,p1,p2``)·``227`` 응답 괄호 안의 6-튜플,
    그리고 ``EPRT``(``|proto|addr|port|``)·``229`` 응답(``|||port|``)을 모두
    받아들인다. 형식이 어긋나면 ``None``.

    Examples:
        ``192,168,0,10,7,138`` → ``("192.168.0.10", 1930)``  (7*256+138)
        ``|1|192.168.0.10|50000|`` → ``("192.168.0.10", 50000)``
        ``|||50000|`` → ``("", 50000)``  (EPSV: 주소 없이 포트만)
    """
    if arg is None:
        return None
    s = arg.strip()
    if not s:
        return None
    # 확장형(EPRT/EPSV): |proto|addr|port| — 구분자는 첫 글자(보통 '|').
    if s[0] in "|!#":
        delim = s[0]
        # 양끝 구분자를 포함해 split → ['', proto, addr, port, ''].
        parts = s.split(delim)
        if len(parts) >= 5:
            addr = parts[2].strip()
            port_str = parts[3].strip()
            try:
                port = int(port_str)
            except ValueError:
                return None
            if not (0 <= port <= 65535):
                return None
            return (addr, port)
        return None
    # 고전형: h1,h2,h3,h4,p1,p2 (각각 0-255).
    nums = [p.strip() for p in s.split(",")]
    if len(nums) != 6:
        return None
    try:
        octets = [int(n) for n in nums]
    except ValueError:
        return None
    if any(not (0 <= n <= 255) for n in octets):
        return None
    ip = ".".join(str(n) for n in octets[:4])
    port = octets[4] * 256 + octets[5]
    return (ip, port)


def parse_passive_reply(text: str) -> Optional[Tuple[str, int]]:
    """수동 모드 응답 텍스트에서 (ip, port) 를 뽑는다.

    ``227 Entering Passive Mode (192,168,0,10,7,138).`` 또는
    ``229 Entering Extended Passive Mode (|||50000|).`` 의 괄호 안을
    :func:`parse_port_argument` 로 환원한다. 괄호가 없거나 형식이 어긋나면
    ``None``.
    """
    if text is None:
        return None
    lo = text.find("(")
    hi = text.rfind(")")
    if lo < 0 or hi < 0 or hi <= lo:
        return None
    inner = text[lo + 1:hi].strip()
    return parse_port_argument(inner)


@dataclass(frozen=True)
class FtpCommand:
    """파싱된 FTP 클라이언트 명령 한 줄.

    Attributes:
        verb: 대문자로 정규화된 명령 동사(``USER``·``RETR`` …).
        arg: 명령 인자(없으면 빈 문자열). 자격증명/경로가 여기 담긴다.
        raw: 원본 줄(종단 CRLF 제외).
    """

    verb: str
    arg: str
    raw: str

    @property
    def is_credential(self) -> bool:
        """자격증명을 평문으로 흘리는 명령(``USER``·``PASS``·``ACCT``)인가."""
        return self.verb in _CREDENTIAL_VERBS

    @property
    def is_transfer(self) -> bool:
        """파일 바이트를 옮기는 전송 명령(``RETR``·``STOR``·``STOU``·``APPE``)인가."""
        return self.verb in _TRANSFER_VERBS

    @property
    def is_anonymous_login(self) -> bool:
        """익명 로그인 시도(``USER anonymous``/``USER ftp``)인가."""
        if self.verb != "USER":
            return False
        user = self.arg.strip().lower()
        return user in _ANONYMOUS_USERS

    @property
    def data_endpoint(self) -> Optional[Tuple[str, int]]:
        """능동 데이터 채널 종착지 — ``PORT``/``EPRT`` 인자의 (ip, port).

        다른 명령이면 ``None``. :mod:`forensiclab.flows` 흐름과 상관해
        파일 바이트를 나른 연결을 짚는 단서.
        """
        if self.verb not in ("PORT", "EPRT"):
            return None
        return parse_port_argument(self.arg)


@dataclass(frozen=True)
class FtpReply:
    """파싱된 FTP 서버 응답 한 줄.

    Attributes:
        code: 3자리 응답 코드(``230``·``530`` …).
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
        """응답 코드 1번째 자리(1~5) — 군(group) 분류.

        2=완료, 3=중간(추가 입력 필요), 4=일시 실패, 5=영구 실패.
        """
        return self.code // 100

    @property
    def is_positive_completion(self) -> bool:
        """2yz(요청 성공 완료) 응답인가."""
        return self.category == 2

    @property
    def is_auth_failure(self) -> bool:
        """``530``(로그인 실패) — 반복 시 브루트포스 정황."""
        return self.code == 530

    @property
    def passive_endpoint(self) -> Optional[Tuple[str, int]]:
        """수동 데이터 채널 종착지 — ``227``/``229`` 응답의 (ip, port).

        해당 응답이 아니면 ``None``.
        """
        if self.code not in (227, 229):
            return None
        return parse_passive_reply(self.text)


def _first_line(data: bytes, offset: int) -> Optional[str]:
    """``offset`` 부터 첫 줄(CRLF/LF 이전)을 ASCII 텍스트로."""
    if offset < 0 or offset > len(data):
        return None
    chunk = data[offset:]
    if not chunk:
        return None
    # FTP 제어 채널은 ASCII 텍스트. 비텍스트 바이트는 관대하게 무시(replace).
    text = chunk.decode("ascii", "replace")
    line = text.replace("\r\n", "\n").split("\n", 1)[0]
    return line


def parse_ftp(
    data: bytes, offset: int = 0
) -> Optional[Union[FtpCommand, FtpReply]]:
    """원시 바이트에서 FTP 제어 채널 한 줄을 파싱한다.

    Args:
        data: FTP 제어 채널 바이트. 보통 TCP 21 페이로드
            (:class:`forensiclab.netdissect` 의 ``payload_offset`` 부터)다.
        offset: 줄이 시작하는 위치(기본 0).

    Returns:
        서버 응답이면 :class:`FtpReply`(3자리 코드로 시작하고 그 뒤가 공백
        또는 ``-`` 인 줄), 그 외 비어 있지 않은 줄이면 :class:`FtpCommand`.
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
            return FtpReply(
                code=code,
                text=text.strip(),
                is_intermediate=is_intermediate,
                raw=stripped,
            )

    # 명령: 동사 SP 인자. 동사는 대문자로 정규화.
    parts = stripped.split(None, 1)
    verb = parts[0].upper()
    arg = parts[1].strip() if len(parts) > 1 else ""
    return FtpCommand(verb=verb, arg=arg, raw=stripped)
