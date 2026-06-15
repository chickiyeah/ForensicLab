"""rcmd — BSD r-services 원격 명령 실행(rsh/rexec) 요청 파싱 코어.

:mod:`forensiclab.netdissect` 가 식별한 TCP(포트 514 ``shell``/rsh, 512
``exec``/rexec) 페이로드는 BSD ``rcmd(3)`` 원격 명령 실행 요청일 수 있다.
이 모듈이 그 요청을 해석한다. :mod:`forensiclab.rlogin` 이 명시적으로
미룬 형제다 — rlogin(513)이 *대화형 로그인*을 연다면, rsh/rexec 는
**원격에서 단일 명령을 곧장 실행**시킨다(같은 ``.rhosts``/``hosts.equiv``
신뢰 모델, 더 짙은 침해 정황). :mod:`forensiclab.telnet`(23)·
:mod:`forensiclab.ftp`(평문 자격증명)·:mod:`forensiclab.ident`(113)·
:mod:`forensiclab.finger`(79) 와 같은 "고전 평문" 계열.

두 서비스는 NUL 종단 필드 시퀀스로 요청을 보내며 **선두에 stderr 보조
포트 번호**(ASCII 십진, ``0`` 이면 별도 stderr 채널 없음)가 온다. 그
뒤 계정/명령 필드 구성이 서비스마다 다르다::

    rsh   (514, 신뢰 기반·무암호)::
        <stderr-port> NUL <local-user> NUL <remote-user> NUL <command> NUL

    rexec (512, 평문 비밀번호)::
        <stderr-port> NUL <remote-user> NUL <password> NUL <command> NUL

서버는 성공 시 **단일 ``\\x00``**, 실패 시 ``\\x01`` + 오류 메시지로
응답한다(:func:`parse_rcmd_response`).

평문·원격 명령 실행이라 사고 분석 단서가 매우 짙다:

- **명령 실행 귀속(``command``)**: rsh/rexec 요청에는 원격에서 실행할
  명령 문자열이 평문으로 들어 있다 — 공격자가 *무엇을* 실행했는지 직접
  포착한다(rlogin 대화형 세션보다 강한, 단발 명령 증거). 자동화/측면
  이동 스크립트(``uname -a``, ``cat /etc/passwd``, 역방향 셸 등)가 자주
  보인다.
- **평문 비밀번호(``password``, rexec 전용)**: rexec 는 비밀번호를 줄
  위로 평문 전송한다 — :mod:`forensiclab.ftp`·:mod:`forensiclab.telnet`
  의 평문 자격증명과 같은 노출(``has_cleartext_password``).
- **무암호 신뢰 인증(rsh)**: rsh 는 비밀번호가 없다 — 요청이 성공하면
  ``.rhosts``/``hosts.equiv`` 신뢰가 악용됐다는 뜻
  (:mod:`forensiclab.rlogin` 과 동일 모델).
- **이중 계정 귀속·계정 교차(rsh)**: ``client_user``(출발 로컬 계정)와
  ``server_user``(원격 대상 계정)가 한 요청에 같이 잡혀 흐름을 두 계정에
  잇는다. 둘이 다르면 ``is_cross_account``, 대상이 root 면 ``targets_root``
  — 신뢰 기반 측면 이동/권한 상승 정황(:mod:`forensiclab.rlogin` 과 동형).
- **별도 stderr 채널(``stderr_port``)**: 0 이 아니면 클라이언트가 별도
  포트로 stderr 역연결을 요청한 것 — 자동화/대화형 구분 단서.

설계 원칙(:mod:`forensiclab.rlogin`·:mod:`forensiclab.ident` 와 동일):
- 부작용 없음: 순수 함수. 디스크/표준출력/네트워크 없음.
- stdlib 전용.
- 안전: 입력 바이트를 변형하지 않는다(읽기 전용). 신고된 계정명·
  비밀번호·명령을 노출하되 로깅/전송하지 않는다 — 호출자가 처리.
- 견고: 서비스(rsh/rexec)는 포트로 호출자가 지정(와이어 레이아웃이
  같아 자체 판별 불가). 필드가 모자라도 있는 만큼 부분 파싱. 바이트가
  아예 없거나 offset 이 범위를 벗어날 때만 ``None``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

__all__ = [
    "RSH_PORTS",
    "REXEC_PORTS",
    "RCMD_PORTS",
    "RcmdRequest",
    "RcmdResponse",
    "parse_rcmd",
    "parse_rcmd_response",
]

# r-services 원격 명령 실행 포트(TCP, IANA 지정).
RSH_PORTS = (514,)      # "shell" — 신뢰 기반·무암호
REXEC_PORTS = (512,)    # "exec"  — 평문 비밀번호
RCMD_PORTS = (512, 514)

_SERVICE_ALIASES = {
    "rsh": "rsh",
    "shell": "rsh",
    "rexec": "rexec",
    "exec": "rexec",
}


@dataclass(frozen=True)
class RcmdRequest:
    """파싱된 BSD rcmd(rsh/rexec) 원격 명령 실행 요청.

    Attributes:
        service: ``"rsh"`` 또는 ``"rexec"`` (호출자 지정, 포트로 결정).
        stderr_port: 클라이언트가 stderr 역연결을 요청한 보조 포트. ``0`` 은
            별도 채널 없음. 숫자가 아니거나 없으면 ``None``.
        client_user: 출발 호스트의 로컬 계정명. **rsh 전용** — rexec 에는
            이 필드가 없어 ``None``. **평문·위조 가능**(자기 신고).
        server_user: 원격 대상 계정명(명령을 실행할 계정 — 인증 대상).
            없으면 ``None``.
        password: 평문 비밀번호. **rexec 전용** — rsh 는 무암호라 ``None``.
        command: 원격에서 실행할 명령 문자열(평문). 없으면 ``None``.
        raw: 원본 바이트(읽기 전용 보존).
    """

    service: str
    stderr_port: Optional[int]
    client_user: Optional[str]
    server_user: Optional[str]
    password: Optional[str]
    command: Optional[str]
    raw: bytes

    @property
    def has_separate_stderr(self) -> bool:
        """별도 stderr 포트(0 이 아닌)를 요청했는가."""
        return self.stderr_port is not None and self.stderr_port != 0

    @property
    def has_cleartext_password(self) -> bool:
        """평문 비밀번호가 실려 있는가 — rexec 자격증명 노출 정황."""
        return bool(self.password)

    @property
    def has_command(self) -> bool:
        """실행할 명령 문자열이 있는가 — 원격 명령 실행 증거."""
        return bool(self.command)

    @property
    def has_attribution(self) -> bool:
        """출발·대상 계정이 모두 있는가(rsh) — 흐름을 두 계정에 잇는 귀속."""
        return bool(self.client_user) and bool(self.server_user)

    @property
    def is_cross_account(self) -> bool:
        """출발 계정과 대상 계정이 다른가 — 신뢰를 타고 다른 계정으로 건너뜀.

        둘 다 있고 서로 다를 때만 참(rsh 측면 이동/계정 교차 정황).
        """
        return self.has_attribution and self.client_user != self.server_user

    @property
    def targets_root(self) -> bool:
        """대상 계정이 ``root`` 인가 — 신뢰/자격증명 기반 루트 명령 실행 단서."""
        return self.server_user == "root"


@dataclass(frozen=True)
class RcmdResponse:
    """파싱된 rcmd 서버 응답(요청 수신 결과).

    Attributes:
        is_success: 단일 ``\\x00`` (성공 ACK)인가.
        is_error: 선두 ``\\x01`` (실패)인가.
        error_message: 실패 시 뒤따르는 오류 메시지(있으면). 성공이면 ``None``.
        raw: 원본 바이트(읽기 전용 보존).
    """

    is_success: bool
    is_error: bool
    error_message: Optional[str]
    raw: bytes


def _decode_field(b: bytes) -> Optional[str]:
    """NUL 사이 한 필드 바이트를 텍스트로(UTF-8 관대 디코드). 비면 ``None``."""
    s = b.decode("utf-8", "replace")
    return s or None


def _parse_port(b: bytes) -> Optional[int]:
    """선두 stderr 포트 필드(ASCII 십진)를 정수로. 숫자 아니거나 비면 ``None``."""
    s = b.decode("ascii", "replace")
    return int(s) if s.isdigit() else None


def parse_rcmd(
    data: bytes, service: str = "rsh", offset: int = 0
) -> Optional[RcmdRequest]:
    """원시 바이트에서 BSD rcmd(rsh/rexec) 원격 명령 실행 요청을 파싱한다.

    Args:
        data: rcmd 흐름 바이트. 보통 TCP 514(rsh)/512(rexec) 페이로드
            (:class:`forensiclab.netdissect` 의 ``payload_offset`` 부터)다.
        service: ``"rsh"``/``"shell"`` 또는 ``"rexec"``/``"exec"``. 와이어
            레이아웃이 같아 호출자가 포트로 결정해 넘긴다(기본 ``"rsh"``).
        offset: 레코드가 시작하는 위치(기본 0).

    Returns:
        :class:`RcmdRequest`. 바이트가 아예 없거나 offset 이 범위를 벗어나거나
        service 가 알 수 없는 값이면 ``None``.

    구조: NUL 로 쪼개면 ``[stderr-port, A, B, command, ...]`` 가 된다. rsh 는
    ``A=local-user, B=remote-user``, rexec 는 ``A=remote-user, B=password``.
    필드가 모자라면 있는 만큼만 채운다.
    """
    if not data or offset < 0 or offset >= len(data):
        return None
    svc = _SERVICE_ALIASES.get(service.lower())
    if svc is None:
        return None
    chunk = data[offset:]

    parts = chunk.split(b"\x00")
    stderr_port = _parse_port(parts[0]) if parts and parts[0] else None
    field_a = _decode_field(parts[1]) if len(parts) > 1 else None
    field_b = _decode_field(parts[2]) if len(parts) > 2 else None
    command = _decode_field(parts[3]) if len(parts) > 3 else None

    if svc == "rsh":
        client_user = field_a       # local user
        server_user = field_b       # remote user (target)
        password = None
    else:  # rexec
        client_user = None          # rexec 는 로컬 계정 필드가 없음
        server_user = field_a       # remote user (target)
        password = field_b          # 평문 비밀번호

    return RcmdRequest(
        service=svc,
        stderr_port=stderr_port,
        client_user=client_user,
        server_user=server_user,
        password=password,
        command=command,
        raw=chunk,
    )


def parse_rcmd_response(data: bytes, offset: int = 0) -> Optional[RcmdResponse]:
    """원시 바이트에서 rcmd 서버 응답을 파싱한다.

    성공은 단일 ``\\x00`` ACK, 실패는 선두 ``\\x01`` + 오류 메시지다.

    Returns:
        :class:`RcmdResponse`. 바이트가 없거나 offset 이 범위를 벗어나면
        ``None``.
    """
    if not data or offset < 0 or offset >= len(data):
        return None
    chunk = data[offset:]
    first = chunk[0:1]

    if first == b"\x00":
        return RcmdResponse(
            is_success=True,
            is_error=False,
            error_message=None,
            raw=chunk,
        )
    if first == b"\x01":
        msg = _decode_field(chunk[1:].rstrip(b"\x00\r\n"))
        return RcmdResponse(
            is_success=False,
            is_error=True,
            error_message=msg,
            raw=chunk,
        )
    # 선두 바이트가 0x00/0x01 이 아니면 표준 응답 형식이 아님.
    return RcmdResponse(
        is_success=False,
        is_error=False,
        error_message=None,
        raw=chunk,
    )
