"""rlogin — 신뢰 기반 평문 원격 로그인 시작 문자열 파싱 코어 (RFC 1282).

:mod:`forensiclab.netdissect` 가 식별한 TCP(포트 513) 페이로드는 BSD rlogin
연결 시작 레코드일 수 있다. 이 모듈이 그 레코드를 해석한다
(:mod:`forensiclab.telnet` 이 TCP 23, :mod:`forensiclab.ident` 가 TCP 113,
:mod:`forensiclab.finger` 가 TCP 79 줄을 다루는 것과 같은 위치 — 모두
고전 "r-services/평문" 계열).

rlogin 은 연결 직후 클라이언트가 **단 한 번** 보내는 NUL 종단 4-필드
시작 문자열로 세션을 연다. 핵심은 **암호 없는 신뢰 기반 인증**이다 —
서버의 ``~/.rhosts`` / ``/etc/hosts.equiv`` 가 (출발 호스트, 사용자) 쌍을
신뢰하면 비밀번호 없이 로그인이 성립한다. 그래서 rlogin 시작 문자열이
보이고 곧바로 세션 데이터가 흐르면 **신뢰 관계가 악용된 측면 이동
(lateral movement)** 의 직접 정황이다(:mod:`forensiclab.flows` 의 5-튜플과
연결해 출발→목적 호스트 경로를 잇는다).

문법(RFC 1282, 클라이언트→서버, 각 필드 ``NUL`` 종단)::

    시작 ::= <NUL>                          (선두 빈 필드)
             <client-user-name> <NUL>        (출발지 로컬 계정)
             <server-user-name> <NUL>        (목적지 원격 계정 — 로그인 대상)
             <terminal-type> "/" <speed> <NUL>   (예 "xterm/38400")

서버는 시작 문자열을 정상 수신하면 **단일 ``\\x00`` 바이트**로 응답한다
(여기서는 ``is_server_ack``). 이후 윈도우 크기 변경은 긴급(urgent) 데이터
``0xFF 0xFF 's' 's' …`` 매직으로 흐르지만, 이 코어는 인증 정황이 짙은
**시작 문자열**에 집중한다(제어 시퀀스 분해는 호출자/별도 단계).

평문·무암호 프로토콜이라 침해/사고 분석에서 단서가 짙다:

- **사용자 귀속 + 측면 이동(client/server user)**: ``client_user`` 는 출발
  호스트의 로컬 계정, ``server_user`` 는 로그인하려는 원격 계정이다. 두
  이름이 한 레코드에 평문으로 같이 잡혀 흐름을 **두 계정**에 동시에 잇는다
  (:mod:`forensiclab.ident` 가 한 계정만 귀속하는 것보다 강한 신호).
- **계정 교차/권한 상승(``is_cross_account`` / ``targets_root``)**: 출발
  계정과 목적 계정이 다르면 신뢰 관계를 타고 다른 계정으로 건너뛰는 정황 —
  특히 ``server_user == "root"`` 이면 신뢰 기반 루트 탈취 시도 단서.
- **무암호 인증**: rlogin 은 비밀번호를 줄 위로 보내지 않는다 — 인증이
  성공하면 ``.rhosts``/``hosts.equiv`` 신뢰가 존재·악용됐다는 뜻
  (:mod:`forensiclab.telnet`·:mod:`forensiclab.ftp` 의 평문 자격증명과는
  다른, "자격증명 자체가 없는" 신뢰 모델).
- **터미널 핑거프린트(terminal_type/speed)**: 클라이언트 환경 식별 단서
  (자동화 툴은 종종 비전형 값을 보고).

설계 원칙(:mod:`forensiclab.ident`·:mod:`forensiclab.finger` 와 동일):
- 부작용 없음: 순수 함수. 디스크/표준출력/네트워크 없음.
- stdlib 전용.
- 안전: 입력 바이트를 변형하지 않는다(읽기 전용). 신고된 계정명을
  노출하되 로깅/전송하지 않는다 — 호출자가 처리.
- 견고: 선두 NUL 로 시작 레코드를 판별. 단일 ``\\x00`` 은 서버 ACK.
  필드가 모자라도 있는 만큼 부분 파싱. 선두 NUL 이 없거나 바이트가
  아예 없을 때만 ``None``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

__all__ = [
    "RLOGIN_PORTS",
    "RloginStart",
    "parse_rlogin",
]

# rlogin 표준 포트(TCP). IANA 지정 513(login). 형제 rsh=514(shell),
# rexec=512(exec) 는 형식이 조금 달라 별도 — 여기서는 rlogin(513)만.
RLOGIN_PORTS = (513,)


@dataclass(frozen=True)
class RloginStart:
    """파싱된 rlogin 연결 시작 레코드(또는 서버 ACK).

    Attributes:
        client_user: 출발 호스트의 로컬 계정명. 없으면 ``None``. **평문·위조
            가능**(클라이언트 자기 신고).
        server_user: 로그인하려는 목적지 원격 계정명 — 신뢰 기반 인증 대상.
            없으면 ``None``.
        terminal_type: 터미널 종류 토큰(예 ``xterm``). 없으면 ``None``.
        terminal_speed: 터미널 속도(예 ``38400``). 숫자가 아니거나 없으면
            ``None``.
        is_server_ack: 단일 ``\\x00`` 바이트(서버가 시작 문자열 수신 확인)인가.
            참이면 사용자 필드는 모두 ``None``.
        raw: 원본 바이트(읽기 전용 보존).
    """

    client_user: Optional[str]
    server_user: Optional[str]
    terminal_type: Optional[str]
    terminal_speed: Optional[int]
    is_server_ack: bool
    raw: bytes

    @property
    def has_attribution(self) -> bool:
        """출발·목적 계정이 모두 있는가 — 흐름을 두 계정에 잇는 귀속 증거."""
        return bool(self.client_user) and bool(self.server_user)

    @property
    def is_cross_account(self) -> bool:
        """출발 계정과 목적 계정이 다른가 — 신뢰를 타고 다른 계정으로 건너뜀.

        둘 다 있고 서로 다를 때만 참(측면 이동/계정 교차 정황).
        """
        return self.has_attribution and self.client_user != self.server_user

    @property
    def targets_root(self) -> bool:
        """목적 계정이 ``root`` 인가 — 신뢰 기반 루트 탈취 시도 단서."""
        return self.server_user == "root"


def _decode_field(b: bytes) -> Optional[str]:
    """NUL 사이 한 필드 바이트를 텍스트로(UTF-8 관대 디코드). 비면 ``None``."""
    s = b.decode("utf-8", "replace")
    return s or None


def parse_rlogin(data: bytes, offset: int = 0) -> Optional[RloginStart]:
    """원시 바이트에서 rlogin 연결 시작 레코드(또는 서버 ACK)를 파싱한다.

    Args:
        data: rlogin 흐름 바이트. 보통 TCP 513 페이로드
            (:class:`forensiclab.netdissect` 의 ``payload_offset`` 부터)다.
        offset: 레코드가 시작하는 위치(기본 0).

    Returns:
        :class:`RloginStart`. 단일 ``\\x00`` 은 ``is_server_ack=True`` 로
        돌려준다. 선두 NUL 이 없거나 바이트가 아예 없거나 offset 이 범위를
        벗어나면 ``None``.

    판별: rlogin 시작 문자열은 항상 선두 ``\\x00`` (빈 필드)로 시작한다.
    이를 NUL 로 쪼개면 ``["", client_user, server_user, "termtype/speed", ...]``
    가 되고, 마지막 터미널 필드는 ``type/speed`` 로 한 번 더 나눈다.
    """
    if not data or offset < 0 or offset >= len(data):
        return None
    chunk = data[offset:]

    # rlogin 시작/ACK 레코드는 선두 NUL 로 시작한다.
    if chunk[0:1] != b"\x00":
        return None

    # 서버 ACK: 단일 \x00 (그 뒤로 의미 있는 바이트 없음).
    if chunk == b"\x00":
        return RloginStart(
            client_user=None,
            server_user=None,
            terminal_type=None,
            terminal_speed=None,
            is_server_ack=True,
            raw=chunk,
        )

    # NUL 분해: parts[0] 은 선두 NUL 로 인해 항상 빈 문자열.
    parts = chunk.split(b"\x00")
    client_user = _decode_field(parts[1]) if len(parts) > 1 else None
    server_user = _decode_field(parts[2]) if len(parts) > 2 else None

    terminal_type: Optional[str] = None
    terminal_speed: Optional[int] = None
    if len(parts) > 3 and parts[3]:
        term = _decode_field(parts[3])
        if term:
            ts = term.split("/", 1)
            terminal_type = ts[0] or None
            if len(ts) > 1 and ts[1].isdigit():
                terminal_speed = int(ts[1])

    return RloginStart(
        client_user=client_user,
        server_user=server_user,
        terminal_type=terminal_type,
        terminal_speed=terminal_speed,
        is_server_ack=False,
        raw=chunk,
    )
