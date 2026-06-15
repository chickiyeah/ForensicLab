"""Syslog — 네트워크 로그 전송 프로토콜 파싱 코어 (RFC 3164 / 5424).

:mod:`forensiclab.netdissect` 가 식별한 UDP(포트 514) 페이로드는 syslog
메시지일 수 있다. 이 모듈이 그 한 줄을 해석한다(:mod:`forensiclab.dns` 가
UDP 53, :mod:`forensiclab.dhcp` 가 UDP 67/68, :mod:`forensiclab.ntp` 가
UDP 123, :mod:`forensiclab.tftp` 가 UDP 69 를 다루는 것과 같은 위치).

:mod:`forensiclab.logparse` 가 디스크에 쌓인 **로그 파일**을 다룬다면, 이
모듈은 **전선 위를 흐르는 syslog 패킷**(원격 로깅 수집 정황)을 다룬다.
평문 UDP 전송이라 침해/사고 분석에서 단서가 많다:

- **우선순위(PRI)**: ``facility*8 + severity``. severity 가 0~3
  (emerg·alert·crit·err)이면 인증 실패·커널 패닉·서비스 장애 같은 중대한
  사건일 수 있다. facility 4(auth)·10(authpriv)·13(audit) 는 로그인·
  권한 상승·감사 흔적이다.
- **호스트 상관**: ``hostname`` 으로 어느 장비가 어디로 로그를 보내는지
  추적한다(:mod:`forensiclab.flows` 와 짝지어 로그 유출/원격 수집 식별).
- **프로세스 식별**: ``app_name``/``proc_id`` 가 ``sshd``·``sudo``·
  ``kernel`` 이면 인증·권한·시스템 이벤트의 출처를 가른다.
- **로그 위조·인젝션**: 평문이라 공격자가 가짜 PRI/타임스탬프로 로그를
  오염시킬 수 있다 — 원시 필드를 보존해 변조 흔적 비교에 쓴다.

메시지 포맷::

    RFC 3164  <PRI>Mmm dd hh:mm:ss HOSTNAME TAG[PID]: MSG
    RFC 5424  <PRI>VER TIMESTAMP HOSTNAME APP PROCID MSGID [SD] MSG

PRI 는 ``<`` ``>`` 로 감싼 0~191 의 십진수다. RFC 5424 는 PRI 뒤에 버전
숫자(보통 1)가 붙고 공백으로 필드를 나누며 ``-`` 은 nil(없음)이다.

설계 원칙(:mod:`forensiclab.tftp`·:mod:`forensiclab.ntp` 와 동일):
- 부작용 없음: 순수 함수. 디스크/표준출력/네트워크 없음.
- stdlib 전용.
- 안전: 입력 바이트를 변형하지 않는다(읽기 전용).
- 견고: 너무 짧거나 망가진 입력은 예외 대신 ``None``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

__all__ = [
    "SYSLOG_FACILITIES",
    "SYSLOG_SEVERITIES",
    "Syslog",
    "parse_syslog",
]

# facility 코드 → 이름 (RFC 5424 Table 1).
SYSLOG_FACILITIES = {
    0: "kern",
    1: "user",
    2: "mail",
    3: "daemon",
    4: "auth",       # 인증/인가 — 로그인 시도 흔적.
    5: "syslog",
    6: "lpr",
    7: "news",
    8: "uucp",
    9: "cron",
    10: "authpriv",  # 비공개 인증 — 패스워드/세션 이벤트.
    11: "ftp",
    12: "ntp",
    13: "audit",     # 감사 로그 — 권한 상승/정책 위반.
    14: "alert",
    15: "clock",
    16: "local0",
    17: "local1",
    18: "local2",
    19: "local3",
    20: "local4",
    21: "local5",
    22: "local6",
    23: "local7",
}

# severity 코드 → 이름 (RFC 5424 Table 2). 낮을수록 심각.
SYSLOG_SEVERITIES = {
    0: "emerg",    # 시스템 사용 불가.
    1: "alert",    # 즉시 조치 필요.
    2: "crit",     # 위급.
    3: "err",      # 오류 — 인증 실패·서비스 장애.
    4: "warning",
    5: "notice",
    6: "info",
    7: "debug",
}

# severity 가 이 값 이하면 "중대" — emerg·alert·crit·err.
_SEVERITY_IMPORTANT = 3

# RFC 5424 nil 값.
_NIL = "-"


@dataclass(frozen=True)
class Syslog:
    """파싱된 syslog 메시지 한 줄.

    포맷(RFC 3164 vs 5424)에 따라 채워지는 필드가 다르다(없으면 ``None``):

    Attributes:
        pri: 우선순위 값(0~191) = ``facility*8 + severity``.
        facility: 시설 코드(0~23). PRI 가 없으면 ``None``.
        severity: 심각도 코드(0~7). 낮을수록 심각.
        version: RFC 5424 버전 숫자. RFC 3164(BSD)면 ``None``.
        timestamp: 원시 타임스탬프 문자열(변형하지 않음).
        hostname: 메시지를 낸 호스트.
        app_name: 프로세스/태그 이름(RFC 3164 의 TAG, 5424 의 APP-NAME).
        proc_id: PID 또는 프로세스 식별자.
        msg_id: RFC 5424 메시지 종류 식별자.
        structured_data: RFC 5424 구조화 데이터(``[...]`` 원문).
        message: 사람이 읽는 본문.
    """

    pri: Optional[int] = None
    facility: Optional[int] = None
    severity: Optional[int] = None
    version: Optional[int] = None
    timestamp: Optional[str] = None
    hostname: Optional[str] = None
    app_name: Optional[str] = None
    proc_id: Optional[str] = None
    msg_id: Optional[str] = None
    structured_data: Optional[str] = None
    message: Optional[str] = None

    @property
    def facility_name(self) -> Optional[str]:
        """facility 의 사람이 읽는 이름(미상이면 ``"facility-<n>"``)."""
        if self.facility is None:
            return None
        return SYSLOG_FACILITIES.get(self.facility, f"facility-{self.facility}")

    @property
    def severity_name(self) -> Optional[str]:
        """severity 의 사람이 읽는 이름(미상이면 ``"severity-<n>"``)."""
        if self.severity is None:
            return None
        return SYSLOG_SEVERITIES.get(self.severity, f"severity-{self.severity}")

    @property
    def is_rfc5424(self) -> bool:
        """RFC 5424(version 숫자 존재) 여부. 아니면 RFC 3164(BSD)."""
        return self.version is not None

    @property
    def is_important(self) -> bool:
        """severity 가 err 이하(0~3)인가 — 중대 사건 단서."""
        return self.severity is not None and self.severity <= _SEVERITY_IMPORTANT


def _parse_pri(text: str):
    """선두 ``<PRI>`` 를 떼어 (pri, facility, severity, 나머지) 로.

    PRI 가 없거나 0~191 밖이면 ``None`` 을 돌려준다.
    """
    if not text.startswith("<"):
        return None
    end = text.find(">")
    if end == -1:
        return None
    digits = text[1:end]
    if not digits.isdigit():
        return None
    pri = int(digits)
    if pri > 191:  # facility 23 * 8 + severity 7 = 191 이 최대.
        return None
    return pri, pri // 8, pri % 8, text[end + 1:]


def _parse_5424(pri, facility, severity, version_tok: str, rest: str) -> Syslog:
    """RFC 5424 본문(버전 토큰 이후)을 필드로 가른다.

    ``TIMESTAMP HOSTNAME APP PROCID MSGID`` 5개 헤더 필드를 공백으로 떼고,
    그 뒤 STRUCTURED-DATA(``-`` 또는 ``[...]``)와 MSG 를 분리한다.
    """
    version = int(version_tok)
    parts = rest.split(" ", 5)
    # 헤더 필드 + 잔여를 안전하게 꺼낸다(짧으면 ""로 채움).
    fields = (parts + [""] * 6)[:6]
    timestamp, hostname, app_name, proc_id, msg_id, tail = fields

    structured_data: Optional[str] = None
    message: Optional[str] = None
    tail = tail.strip("\n")
    if tail.startswith(_NIL):
        # nil SD — 뒤는 곧 메시지.
        structured_data = None
        message = tail[1:].lstrip(" ") or None
    elif tail.startswith("["):
        # SD 는 균형 잡힌 ``]`` 까지. 이스케이프 ``\]`` 는 종단이 아니다.
        depth = 0
        i = 0
        while i < len(tail):
            ch = tail[i]
            if ch == "\\":
                i += 2
                continue
            if ch == "[":
                depth += 1
            elif ch == "]":
                depth -= 1
                if depth == 0:
                    i += 1
                    break
            i += 1
        structured_data = tail[:i]
        message = tail[i:].lstrip(" ") or None
    elif tail:
        message = tail

    def _nz(value: str) -> Optional[str]:
        return None if value in ("", _NIL) else value

    return Syslog(
        pri=pri,
        facility=facility,
        severity=severity,
        version=version,
        timestamp=_nz(timestamp),
        hostname=_nz(hostname),
        app_name=_nz(app_name),
        proc_id=_nz(proc_id),
        msg_id=_nz(msg_id),
        structured_data=structured_data,
        message=message,
    )


def _parse_3164(pri, facility, severity, rest: str) -> Syslog:
    """RFC 3164(BSD) 본문을 필드로 가른다.

    ``Mmm dd hh:mm:ss HOSTNAME TAG[PID]: MSG`` 형식. 타임스탬프는 고정폭
    15자(``Mmm dd hh:mm:ss``)지만 견고성을 위해 토큰 단위로 떼고, 깨진
    형식이면 전체를 ``message`` 로 둔다.
    """
    rest = rest.strip("\n")
    timestamp: Optional[str] = None
    hostname: Optional[str] = None
    app_name: Optional[str] = None
    proc_id: Optional[str] = None
    body = rest

    # RFC 3164 타임스탬프는 고정폭 15자 "Mmm dd hh:mm:ss"(일자는 공백 패딩,
    # 예 "Jan  1"). 단일 공백 분할로는 패딩이 깨지므로 위치로 검사한다.
    if (len(rest) > 15 and rest[15] == " "
            and rest[:3].isalpha() and rest[3] == " " and rest[6] == " "
            and rest[9] == ":" and rest[12] == ":"):
        timestamp = rest[:15]
        after = rest[16:]
        host, _, tail = after.partition(" ")
        hostname = host or None
        body = tail

    # TAG[PID]: 분리 — 첫 ": " 앞이 태그(+선택적 [PID]).
    colon = body.find(": ")
    if colon != -1:
        tag = body[:colon]
        msg = body[colon + 2:]
        if "[" in tag and tag.endswith("]"):
            name, _, pid = tag[:-1].partition("[")
            app_name = name or None
            proc_id = pid or None
        else:
            app_name = tag or None
        message = msg or None
    else:
        message = body or None

    return Syslog(
        pri=pri,
        facility=facility,
        severity=severity,
        version=None,
        timestamp=timestamp,
        hostname=hostname,
        app_name=app_name,
        proc_id=proc_id,
        msg_id=None,
        structured_data=None,
        message=message,
    )


def parse_syslog(data) -> Optional[Syslog]:
    """원시 바이트/문자열에서 syslog 메시지 한 줄을 파싱한다.

    Args:
        data: syslog 메시지. ``bytes``(보통 UDP 514 페이로드) 또는 ``str``.
            바이트는 UTF-8(실패 시 latin-1)로 디코드한다.

    Returns:
        :class:`Syslog`. 선두에 유효한 ``<PRI>`` 가 없으면 ``None``
        (다른 프로토콜 페이로드를 syslog 로 오인하지 않기 위함).
    """
    if isinstance(data, (bytes, bytearray)):
        try:
            text = bytes(data).decode("utf-8")
        except UnicodeDecodeError:
            text = bytes(data).decode("latin-1")
    else:
        text = data

    parsed = _parse_pri(text)
    if parsed is None:
        return None
    pri, facility, severity, rest = parsed

    # RFC 5424 는 PRI 바로 뒤에 버전 숫자 + 공백이 온다(보통 "1 ").
    space = rest.find(" ")
    if space > 0 and rest[:space].isdigit():
        return _parse_5424(pri, facility, severity, rest[:space], rest[space + 1:])

    return _parse_3164(pri, facility, severity, rest)
