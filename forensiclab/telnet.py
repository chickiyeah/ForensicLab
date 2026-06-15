"""TELNET — 가상 터미널 프로토콜 파싱 코어 (RFC 854·855, RFC 1091·1572).

:mod:`forensiclab.netdissect` 가 식별한 TCP(포트 23) 페이로드는 Telnet 흐름의
한 조각이다. 이 모듈이 그 바이트열을 **데이터(평문)** 와 **제어 시퀀스(IAC
협상)** 로 갈라 해석한다.

메일 3종(:mod:`forensiclab.smtp`·:mod:`forensiclab.pop3`·:mod:`forensiclab.imap`)
이나 :mod:`forensiclab.ftp` 가 *줄 단위* 텍스트 프로토콜이라면, Telnet 은
**바이트 지향** 이다. 데이터 바이트 사이사이에 ``IAC``(Interpret As Command,
0xFF) 로 시작하는 제어 시퀀스가 끼어든다:

- **옵션 협상**: ``IAC <WILL|WONT|DO|DONT> <option>`` — 3바이트. 양측이
  ECHO·SUPPRESS-GO-AHEAD·TERMINAL-TYPE·NAWS 같은 옵션을 켜고 끈다.
- **부협상(subnegotiation)**: ``IAC SB <option> <data...> IAC SE`` — 옵션의
  세부 값 교환(터미널 타입 문자열·환경변수 등).
- **단순 명령**: ``IAC <NOP|IP|AYT|…>`` — 2바이트(인터럽트·Are-You-There 등).
- **리터럴 0xFF**: ``IAC IAC`` — 데이터 안의 실제 바이트 255.

평문이라 침해/사고 분석에서 단서가 짙다 — 사실상 메일 평문 프로토콜들보다 더
짙다. Telnet 은 *세션 전체*(로그인 프롬프트·아이디·비밀번호·이후 모든 명령과
출력)가 와이어에 그대로 흐르기 때문이다:

- **평문 자격증명·세션 노출**: 데이터 스트림 자체가 자격증명 표면이다. 서버의
  ``login:``/``Password:`` 프롬프트와 클라이언트가 친 아이디·비밀번호, 이후
  셸 명령이 모두 캡처에서 그대로 복원된다(:mod:`forensiclab.ftp` 의
  ``USER``/``PASS`` 가 명령 하나에 담긴다면 Telnet 은 키 입력 전체를 흘린다).
- **클라이언트/호스트 핑거프린팅**: ``TERMINAL-TYPE`` 부협상은 클라이언트
  단말 종류(``xterm``·``VT100`` …)를, ``NEW-ENVIRON``/``OLD-ENVIRON`` 부협상은
  사용자명·환경변수를 노출한다 — 호스트 상관·도구 식별 단서
  (:mod:`forensiclab.hassh` 가 SSH 구현을 식별하듯).
- **IoT·임베디드 브루트포스**: 공장 기본 자격증명의 Telnet 은 Mirai 계열
  봇넷의 1차 감염 벡터다. 짧은 세션의 반복 로그인 시도/실패는 자격증명 추측
  정황이다(:mod:`forensiclab.ftp` 의 ``530`` 과 같은 계열이되 응답 코드가 아닌
  프롬프트 반복으로 드러난다).

흐름 예(바이트, ``\\xff`` = IAC)::

    \\xff\\xfd\\x18              IAC DO TERMINAL-TYPE       (옵션 협상)
    \\xff\\xfa\\x18\\x00xterm\\xff\\xf0   IAC SB TT IS "xterm" IAC SE  (부협상)
    login: alice\\r\\n          (서버 프롬프트 + 데이터)
    Password: s3cret\\r\\n      (평문 비밀번호)

설계 원칙(:mod:`forensiclab.imap`·:mod:`forensiclab.snmp` 와 동일):
- 부작용 없음: 순수 함수. 디스크/표준출력/네트워크 없음.
- stdlib 전용.
- 안전: 입력 바이트를 변형하지 않는다(읽기 전용). 평문/자격증명을 노출하되
  로깅/전송하지 않는다 — 호출자가 처리.
- 견고: 잘린/망가진 IAC 시퀀스는 예외 대신 가능한 만큼만 파싱(불완전 꼬리는
  버린다). 빈 입력은 ``None``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional, Tuple

__all__ = [
    "TELNET_PORTS",
    "IAC",
    "TelnetCommand",
    "TelnetStream",
    "parse_telnet",
    "decode_terminal_type",
    "decode_environ",
]

# Telnet 표준 포트(TCP).
TELNET_PORTS = (23,)

# IAC — Interpret As Command. 모든 제어 시퀀스의 도입 바이트(RFC 854).
IAC = 0xFF

# 명령 바이트(RFC 854 §명령어). SE/SB 는 부협상의 끝·시작.
SE = 0xF0  # 240 End of subnegotiation
NOP = 0xF1  # 241 No operation
DM = 0xF2  # 242 Data Mark
BRK = 0xF3  # 243 Break
IP = 0xF4  # 244 Interrupt Process
AO = 0xF5  # 245 Abort Output
AYT = 0xF6  # 246 Are You There
EC = 0xF7  # 247 Erase Character
EL = 0xF8  # 248 Erase Line
GA = 0xF9  # 249 Go Ahead
SB = 0xFA  # 250 Begin subnegotiation
WILL = 0xFB  # 251
WONT = 0xFC  # 252
DO = 0xFD  # 253
DONT = 0xFE  # 254

# 협상 명령 집합 — 뒤에 1바이트 옵션 코드가 따른다.
_NEGOTIATE = frozenset({WILL, WONT, DO, DONT})

_COMMAND_NAMES = {
    SE: "SE",
    NOP: "NOP",
    DM: "DM",
    BRK: "BRK",
    IP: "IP",
    AO: "AO",
    AYT: "AYT",
    EC: "EC",
    EL: "EL",
    GA: "GA",
    SB: "SB",
    WILL: "WILL",
    WONT: "WONT",
    DO: "DO",
    DONT: "DONT",
    IAC: "IAC",
}

# 자주 보는 옵션 코드 → 이름(IANA Telnet Options). 미등록 코드는 None.
_OPTION_NAMES = {
    0: "BINARY",
    1: "ECHO",
    3: "SUPPRESS-GO-AHEAD",
    5: "STATUS",
    6: "TIMING-MARK",
    24: "TERMINAL-TYPE",
    31: "NAWS",  # Negotiate About Window Size
    32: "TERMINAL-SPEED",
    33: "REMOTE-FLOW-CONTROL",
    34: "LINEMODE",
    35: "X-DISPLAY-LOCATION",
    36: "OLD-ENVIRON",
    39: "NEW-ENVIRON",
}

# 부협상 명령 인자(RFC 1091/1572 공통): IS/SEND/INFO.
_SUB_IS = 0
_SUB_SEND = 1
_SUB_INFO = 2

# NEW-ENVIRON/OLD-ENVIRON 항목 타입(RFC 1572).
_ENV_VAR = 0
_ENV_VALUE = 1
_ENV_ESC = 2
_ENV_USERVAR = 3


def _command_name(code: int) -> str:
    """명령 바이트 이름(미등록이면 ``CMD_<10진>``)."""
    return _COMMAND_NAMES.get(code, "CMD_%d" % code)


def _option_name(code: Optional[int]) -> Optional[str]:
    """옵션 코드 이름(미등록이면 ``OPT_<10진>``, ``None`` 이면 ``None``)."""
    if code is None:
        return None
    return _OPTION_NAMES.get(code, "OPT_%d" % code)


@dataclass(frozen=True)
class TelnetCommand:
    """파싱된 Telnet IAC 제어 시퀀스 하나.

    Attributes:
        kind: 시퀀스 종류 — ``"negotiate"``(WILL/WONT/DO/DONT + 옵션),
            ``"subneg"``(SB … SE), ``"command"``(NOP/IP/AYT 등 단순 명령).
        command: 명령 바이트(예: ``WILL``=251, ``SB``=250).
        command_name: 명령 이름(``"WILL"``·``"SB"``·``"IP"`` …).
        option: 협상·부협상의 대상 옵션 코드(단순 명령이면 ``None``).
        option_name: 옵션 이름(``"TERMINAL-TYPE"`` …, 없으면 ``None``).
        data: 부협상 페이로드 바이트(``SB`` 가 아니면 빈 바이트). ``IAC SE``
            종단과 ``IAC IAC`` 이스케이프는 제거된 실데이터.
    """

    kind: str
    command: int
    command_name: str
    option: Optional[int] = None
    option_name: Optional[str] = None
    data: bytes = b""

    @property
    def is_negotiation(self) -> bool:
        """옵션 협상(WILL/WONT/DO/DONT) 시퀀스인가."""
        return self.kind == "negotiate"

    @property
    def is_subnegotiation(self) -> bool:
        """부협상(SB … SE) 시퀀스인가 — 터미널 타입·환경변수 등 값 교환."""
        return self.kind == "subneg"


@dataclass(frozen=True)
class TelnetStream:
    """파싱된 Telnet 페이로드 — 데이터와 제어 시퀀스로 분리된 결과.

    Telnet 은 바이트 지향이라 한 페이로드에 평문 데이터와 IAC 제어 시퀀스가
    뒤섞인다. 이 클래스는 둘을 갈라 :attr:`data`(IAC 시퀀스를 걷어낸 순수
    평문, ``IAC IAC`` 는 단일 0xFF 로 환원)과 :attr:`commands`(제어 시퀀스
    목록)로 제공한다.

    Attributes:
        data: 제어 시퀀스를 제거한 평문 데이터 바이트. 로그인 프롬프트·아이디·
            비밀번호·셸 명령이 그대로 들어 있다 — 자격증명/세션 단서.
        commands: 등장 순서대로의 :class:`TelnetCommand` 튜플.
        raw: 원본 페이로드 바이트.
    """

    data: bytes
    commands: Tuple[TelnetCommand, ...] = field(default_factory=tuple)
    raw: bytes = b""

    def text(self, encoding: str = "ascii", errors: str = "replace") -> str:
        """평문 데이터를 문자열로 디코드(기본 ASCII, 비텍스트는 replace)."""
        return self.data.decode(encoding, errors)

    @property
    def negotiations(self) -> Tuple[TelnetCommand, ...]:
        """옵션 협상 시퀀스만 추린 튜플."""
        return tuple(c for c in self.commands if c.is_negotiation)

    @property
    def subnegotiations(self) -> Tuple[TelnetCommand, ...]:
        """부협상 시퀀스만 추린 튜플 — 핑거프린트/환경변수 단서."""
        return tuple(c for c in self.commands if c.is_subnegotiation)

    @property
    def has_data(self) -> bool:
        """평문 데이터 바이트가 있는가 — 협상만 있는 페이로드와 구분."""
        return len(self.data) > 0


def decode_terminal_type(cmd: TelnetCommand) -> Optional[str]:
    """``TERMINAL-TYPE`` 부협상에서 단말 종류 문자열을 환원한다(RFC 1091).

    페이로드는 ``IS(0)|SEND(1)`` 한 바이트 뒤에 단말 이름 ASCII 가 온다
    (``\\x00xterm`` → ``"xterm"``). 클라이언트가 보고한 단말 종류는 호스트/도구
    핑거프린트 단서다. ``TERMINAL-TYPE`` 부협상이 아니거나 ``IS`` 형식이
    아니거나 이름이 비면 ``None``.
    """
    if not cmd.is_subnegotiation or cmd.option != 24:
        return None
    payload = cmd.data
    if len(payload) < 2 or payload[0] != _SUB_IS:
        return None
    name = payload[1:].decode("ascii", "replace").strip()
    return name or None


def decode_environ(cmd: TelnetCommand) -> Optional[List[Tuple[str, Optional[str]]]]:
    """``NEW-ENVIRON``/``OLD-ENVIRON`` 부협상에서 (이름, 값) 쌍을 환원한다.

    RFC 1572 인코딩: 첫 바이트는 ``IS(0)|SEND(1)|INFO(2)``, 이어서 항목들이
    ``VAR(0)|USERVAR(3) <이름> [VALUE(1) <값>]`` 형태로 늘어선다. ``ESC(2)`` 는
    다음 한 바이트를 리터럴로 만든다(타입 바이트가 이름/값에 섞일 때 escape).

    값이 없는 변수(SEND 요청 등)는 값이 ``None`` 으로 온다. 환경변수는
    사용자명(``USER``)·홈 디렉터리·디스플레이 등 호스트 상관 단서를 노출한다.
    ``NEW-ENVIRON``(39)·``OLD-ENVIRON``(36) 부협상이 아니면 ``None``.

    Examples:
        ``\\x00\\x00USER\\x01alice`` → ``[("USER", "alice")]``
    """
    if not cmd.is_subnegotiation or cmd.option not in (36, 39):
        return None
    payload = cmd.data
    if not payload:
        return None

    # 첫 바이트(IS/SEND/INFO)는 건너뛴다. 명령 종류는 여기서 따지지 않는다.
    i, n = 1, len(payload)
    pairs: List[Tuple[str, Optional[str]]] = []
    name: Optional[List[int]] = None
    value: Optional[List[int]] = None

    def _flush() -> None:
        # 모인 이름/값을 결과에 넣는다(이름이 있을 때만).
        if name is not None:
            nm = bytes(name).decode("ascii", "replace")
            vl = bytes(value).decode("ascii", "replace") if value is not None else None
            pairs.append((nm, vl))

    while i < n:
        b = payload[i]
        if b in (_ENV_VAR, _ENV_USERVAR):
            _flush()
            name, value = [], None
            i += 1
            continue
        if b == _ENV_VALUE:
            value = []
            i += 1
            continue
        if b == _ENV_ESC and i + 1 < n:
            # 다음 바이트는 타입이 아닌 리터럴.
            i += 1
            b = payload[i]
        # 일반 바이트 — 현재 모으는 버퍼(값 우선, 없으면 이름)에 쌓는다.
        if value is not None:
            value.append(b)
        elif name is not None:
            name.append(b)
        i += 1

    _flush()
    return pairs or None


def parse_telnet(data: bytes, offset: int = 0) -> Optional[TelnetStream]:
    """원시 바이트에서 Telnet 페이로드를 데이터/제어 시퀀스로 분해한다.

    Args:
        data: Telnet 흐름 바이트. 보통 TCP 23 페이로드
            (:class:`forensiclab.netdissect` 의 ``payload_offset`` 부터)다.
        offset: 파싱을 시작할 위치(기본 0).

    Returns:
        :class:`TelnetStream`(평문 :attr:`~TelnetStream.data` + 제어
        :attr:`~TelnetStream.commands`). 빈 입력/범위 밖 ``offset`` 이면
        ``None``. 제어 시퀀스가 전혀 없는 평문 페이로드도 정상적으로
        ``commands`` 가 빈 :class:`TelnetStream` 으로 돌려준다.

    잘린 IAC 시퀀스(꼬리의 ``IAC`` 단독, ``IAC WILL`` 만 있고 옵션 없음,
    종단 ``IAC SE`` 없는 ``SB``)는 예외 없이 가능한 만큼만 파싱하고 불완전한
    꼬리는 버린다 — 캡처가 TCP 세그먼트 경계에서 잘릴 수 있기 때문이다.
    """
    if offset < 0 or offset > len(data):
        return None
    buf = data[offset:]
    if not buf:
        return None

    out_data: List[int] = []
    commands: List[TelnetCommand] = []
    i, n = 0, len(buf)

    while i < n:
        b = buf[i]
        if b != IAC:
            out_data.append(b)
            i += 1
            continue

        # b == IAC. 다음 바이트가 시퀀스 종류를 정한다.
        if i + 1 >= n:
            break  # 꼬리의 단독 IAC — 불완전, 버린다.
        c = buf[i + 1]

        if c == IAC:
            # IAC IAC — 데이터 안의 리터럴 0xFF.
            out_data.append(IAC)
            i += 2
            continue

        if c in _NEGOTIATE:
            if i + 2 >= n:
                break  # 옵션 바이트 없음 — 불완전.
            opt = buf[i + 2]
            commands.append(
                TelnetCommand(
                    kind="negotiate",
                    command=c,
                    command_name=_command_name(c),
                    option=opt,
                    option_name=_option_name(opt),
                )
            )
            i += 3
            continue

        if c == SB:
            if i + 2 >= n:
                break  # 옵션 바이트 없음 — 불완전.
            opt = buf[i + 2]
            j = i + 3
            payload: List[int] = []
            terminated = False
            while j < n:
                if buf[j] == IAC and j + 1 < n:
                    nxt = buf[j + 1]
                    if nxt == SE:
                        terminated = True
                        break
                    if nxt == IAC:
                        payload.append(IAC)  # 부협상 안의 리터럴 0xFF.
                        j += 2
                        continue
                    # 그 외 IAC 조합은 드물다 — 리터럴로 취급.
                    payload.append(buf[j])
                    j += 1
                    continue
                payload.append(buf[j])
                j += 1
            if not terminated:
                break  # 종단 IAC SE 없음 — 불완전, 버린다.
            commands.append(
                TelnetCommand(
                    kind="subneg",
                    command=SB,
                    command_name="SB",
                    option=opt,
                    option_name=_option_name(opt),
                    data=bytes(payload),
                )
            )
            i = j + 2  # IAC SE 두 바이트 소비.
            continue

        # 단순 명령(NOP/IP/AYT/…) — 2바이트.
        commands.append(
            TelnetCommand(
                kind="command",
                command=c,
                command_name=_command_name(c),
            )
        )
        i += 2

    return TelnetStream(data=bytes(out_data), commands=tuple(commands), raw=buf)
