"""SSH 프로토콜 버전 식별 배너(identification string) 파싱 코어.

TLS 핸드셰이크가 :mod:`forensiclab.tls`·:mod:`forensiclab.ja3` 로 지문화되듯,
SSH 연결의 첫 평문 교환인 *버전 식별 문자열* 은 양쪽 소프트웨어를 그대로
드러낸다. RFC 4253 §4.2 에 따라 클라이언트와 서버는 키 교환에 앞서 각자

    SSH-protoversion-softwareversion SP comments CR LF

꼴의 한 줄을 보낸다(예: ``SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1``). 이
배너는 암호화 이전이라 패킷에서 평문으로 보이며, 침해 분석에서

- 어떤 SSH 구현·버전이 붙었는가(취약 버전·낯선 클라이언트 라이브러리),
- 자동화 도구/봇넷이 쓰는 특이한 softwareversion 문자열(예: ``libssh``,
  ``paramiko``, ``Go``, 무작위 문자열),

을 빠르게 식별하는 단서다. softwareversion 은 향후 HASSH(SSH 판 JA3) 의
입력이 되기도 하므로 구조화해 둘 가치가 있다.

배너 문법(RFC 4253 §4.2):
- ``protoversion`` 과 ``softwareversion`` 은 첫 ``-`` 로 구분된다.
- ``softwareversion`` 은 공백·``-`` 를 포함하지 않는 출력 가능 US-ASCII.
- 선택적 ``comments`` 는 SP 한 칸 뒤에 오며 공백을 포함할 수 있다.
- 줄은 CR LF 로 끝나야 하지만(LF 만 오는 구현도 있어 둘 다 허용),
  전체 길이는 CR LF 포함 255바이트를 넘지 않는다.
- 서버는 ``SSH-`` 줄 *앞에* 임의의 안내 줄을 더 보낼 수 있다(§4.2). 그래서
  첫 ``SSH-`` 줄을 찾을 때까지 앞 줄들을 건너뛴다.

설계 원칙(:mod:`forensiclab.http`·:mod:`forensiclab.dns` 와 동일):
- 부작용 없음: 디스크/표준출력 없이 순수 함수.
- stdlib 전용: 외부 의존성 없음.
- 안전: 입력 바이트를 변형하지 않는다(읽기 전용).
- 견고: SSH 배너가 아니거나 망가진 입력은 예외 대신 ``None``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

__all__ = [
    "SSH_BANNER_PREFIX",
    "SshBanner",
    "parse_banner",
]

# 모든 SSH 식별 문자열이 시작하는 고정 접두사. 첫 토큰이 이걸로 시작하지
# 않으면 SSH 가 아니라고 보고 None 을 돌려, 비-SSH 페이로드를 걸러낸다.
SSH_BANNER_PREFIX = b"SSH-"

# RFC 4253 §4.2: 식별 문자열은 CR LF 포함 255바이트를 넘지 않는다. 앞 안내
# 줄까지 포함해 폭주 입력을 막도록 스캔 범위에 넉넉한 상한을 둔다.
_MAX_SCAN_BYTES = 64 * 1024
_LF = b"\n"


@dataclass(frozen=True)
class SshBanner:
    """파싱된 SSH 버전 식별 배너.

    Attributes:
        protoversion: SSH 프로토콜 버전(예: ``"2.0"``, ``"1.99"``).
        software: softwareversion 토큰(예: ``"OpenSSH_8.9p1"``). 공백·``-``
            를 포함하지 않는다.
        comments: SP 뒤 선택적 코멘트(예: ``"Ubuntu-3ubuntu0.1"``). 없으면
            빈 문자열.
        raw: 트레일링 CR/LF 를 떼어낸 배너 줄 원본(``"SSH-..."``).
    """

    protoversion: str
    software: str
    comments: str = ""
    raw: str = ""


def parse_banner(data: bytes) -> Optional[SshBanner]:
    """TCP 페이로드 바이트에서 SSH 식별 배너를 파싱한다.

    Args:
        data: 한 방향(클라이언트→서버 또는 서버→클라이언트)으로 모인 원시
            바이트. 연결의 첫 평문 교환을 기대한다.

    Returns:
        :class:`SshBanner`. ``SSH-`` 로 시작하는 줄이 없거나 그 줄이
        ``SSH-proto-software`` 최소 꼴을 못 갖추면 ``None``. 서버가 보내는
        ``SSH-`` 이전 안내 줄들은 건너뛴다.
    """
    if not data:
        return None

    window = data[:_MAX_SCAN_BYTES]

    # 서버는 SSH- 줄 앞에 안내 줄을 더 보낼 수 있다(§4.2). LF 기준으로 줄을
    # 끊고(CR 은 뒤에서 제거) 첫 SSH- 줄을 찾는다.
    for line in window.split(_LF):
        if line.startswith(b"\r"):
            line = line[1:]
        if line.endswith(b"\r"):
            line = line[:-1]
        if line.startswith(SSH_BANNER_PREFIX):
            return _parse_line(line)
    return None


def _parse_line(line: bytes) -> Optional[SshBanner]:
    """``SSH-`` 로 시작하는 한 줄(CR/LF 제거됨)을 :class:`SshBanner` 로."""
    raw = line.decode("ascii", "replace")

    # "SSH-" 접두사 뒤를 protoversion 과 나머지로 가른다. 첫 '-' 까지가
    # protoversion, 그다음이 softwareversion[ SP comments].
    body = raw[len(SSH_BANNER_PREFIX.decode("ascii")):]
    dash = body.find("-")
    if dash == -1:
        return None  # protoversion 과 softwareversion 구분자(-) 없음.
    protoversion = body[:dash]
    rest = body[dash + 1:]
    if not protoversion or not rest:
        return None  # 둘 중 하나라도 비면 유효한 배너가 아님.

    # softwareversion 은 공백을 포함하지 않으며, 첫 SP 뒤는 comments.
    sp = rest.find(" ")
    if sp == -1:
        software, comments = rest, ""
    else:
        software, comments = rest[:sp], rest[sp + 1:]
    if not software:
        return None

    return SshBanner(
        protoversion=protoversion,
        software=software,
        comments=comments,
        raw=raw,
    )
