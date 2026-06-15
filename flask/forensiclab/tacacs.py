"""TACACS+ — AAA 인증·인가·과금 프로토콜 헤더 파싱 코어 (RFC 8907; TCP 49).

:mod:`forensiclab.radius` 가 UDP 기반 AAA(NAS↔서버 인증·과금)였다면, TACACS+ 는
그 **TCP 기반 사촌**이다 — 시스코가 만든 장비 관리용 AAA 로, 라우터·스위치·
방화벽에 관리자가 로그인할 때(``enable``·명령 권한 부여) 거의 표준처럼 쓰인다.
RADIUS 가 인증·인가를 한 묶음으로 합치는 데 비해 TACACS+ 는 **A·A·A 를 분리**해
명령 단위 인가(command authorization)와 명령 단위 과금(accounting)을 한다 —
"관리자가 라우터에서 어떤 명령을 쳤나" 를 복원하는 핵심 단서다.

RADIUS 의 패스워드(User-Password)만 가리는 것과 달리, TACACS+ 는 **본문 전체를
난독화**한다(MD5 기반 의사 패드와 XOR; 공유 비밀 필요). 그래서 본 파서는
:mod:`forensiclab.esp`·:mod:`forensiclab.wireguard` 처럼 **평문 12바이트 헤더만**
풀고 난독화된 본문은 ``payload_offset`` 으로만 가리킨다(읽기 전용·비밀 무복호).

와이어 포맷(RFC 8907 §4.1, 12바이트 고정 헤더, big-endian)::

    version(1) | type(1) | seq_no(1) | flags(1) | session_id(4) | length(4)

- **version**: 상위 4비트 major(항상 ``0xc``=TAC_PLUS_MAJOR_VER), 하위 4비트
  minor(0=기본, 1=확장). major≠0xc 면 TACACS+ 가 아니다(강한 오탐 가드).
- **type**: 1=Authentication·2=Authorization·3=Accounting — A·A·A 분리의 핵심.
- **seq_no**: 세션 내 패킷 순번(클라 1 부터 홀수, 서버 짝수). 1 이 세션 개시.
- **flags**: bit0(``0x01``) TAC_PLUS_UNENCRYPTED_FLAG(본문 평문—**미운영 권고**,
  공유 비밀 노출/디버그 정황)·bit2(``0x04``) TAC_PLUS_SINGLE_CONNECT_FLAG.
- **session_id**: 4바이트 세션 식별자 — RADIUS Acct-Session-Id·WireGuard
  index·ESP SPI 대응. :mod:`forensiclab.flows` 의 IP 쌍 안에서 한 AAA 대화를
  못 박는 상관 키(같은 session_id = 같은 로그인 세션).
- **length**: 뒤따르는 본문 길이(헤더 12 제외). 본문은 보통 난독화됨.

침해/사고 분석에서 평문 헤더가 드러내는 것:

- **장비 관리 AAA 존재·표적**: 노출된 TCP 49 자체가 네트워크 장비 관리 평면
  정황 — RADIUS(1812)·:mod:`forensiclab.snmp` 형제. 외부에서 49 로의 시도는
  관리 인터페이스 정찰.
- **A·A·A 단계 식별(type)**: Authentication 후 Authorization·Accounting 흐름은
  "로그인→명령 권한→명령 실행" 타임라인(:mod:`forensiclab.timeline`).
- **세션 상관·브루트포스(session_id·seq_no)**: 같은 IP 쌍에서 새 session_id 가
  쏟아지고 모두 seq_no 1~3 에서 끊기면(인증 단계만 반복) 패스워드 스프레이/
  브루트포스 정황 — RADIUS Access-Reject 반복과 대응.
- **평문 플래그(flags)**: TAC_PLUS_UNENCRYPTED_FLAG 가 켜지면 본문이 평문 —
  잘못된 설정/디버그로 자격증명이 그대로 노출되는 강한 단서.

설계 원칙(:mod:`forensiclab.radius`·:mod:`forensiclab.esp` 와 동일):
- 부작용 없음·stdlib 전용·읽기 전용(입력 무변형).
- 견고: 12바이트 미만·major version≠0xc·type 미정의면 예외 대신 ``None``.
- 비밀(난독화 본문)은 복호하지 않고 ``payload_offset`` 만 노출한다.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Optional

__all__ = [
    "TACACS_HEADER_LEN",
    "TACACS_MAJOR_VERSION",
    "TACACS_TYPE_AUTHENTICATION",
    "TACACS_TYPE_AUTHORIZATION",
    "TACACS_TYPE_ACCOUNTING",
    "TACACS_FLAG_UNENCRYPTED",
    "TACACS_FLAG_SINGLE_CONNECT",
    "Tacacs",
    "parse_tacacs",
]

# 고정 헤더 길이(RFC 8907 §4.1).
TACACS_HEADER_LEN = 12

# major version — 항상 0xc(TAC_PLUS_MAJOR_VER). 다른 값이면 TACACS+ 아님.
TACACS_MAJOR_VERSION = 0xC

# 패킷 종류(type). A·A·A 분리.
TACACS_TYPE_AUTHENTICATION = 0x01  # 인증(누가 로그인?).
TACACS_TYPE_AUTHORIZATION = 0x02   # 인가(이 명령을 쳐도 되나?).
TACACS_TYPE_ACCOUNTING = 0x03      # 과금(무슨 명령을 쳤나—감사 로그).

_TYPE_NAMES = {
    TACACS_TYPE_AUTHENTICATION: "Authentication",
    TACACS_TYPE_AUTHORIZATION: "Authorization",
    TACACS_TYPE_ACCOUNTING: "Accounting",
}

# 정의된 type 집합 — 그 밖은 TACACS+ 가 아닐 가능성이 높다(오탐 가드).
_VALID_TYPES = frozenset(_TYPE_NAMES)

# flags 비트(RFC 8907 §4.1).
TACACS_FLAG_UNENCRYPTED = 0x01     # 본문 평문(미운영 권고·노출 정황).
TACACS_FLAG_SINGLE_CONNECT = 0x04  # 한 TCP 연결로 다중 세션 다중화.


@dataclass(frozen=True)
class Tacacs:
    """파싱된 TACACS+ 평문 헤더(12바이트).

    난독화된 본문은 풀지 않으며 :attr:`payload_offset`/:attr:`length` 로만
    가리킨다(읽기 전용·비밀 무복호).

    Attributes:
        major_version: 상위 4비트 major(정상이면 ``0xc``).
        minor_version: 하위 4비트 minor(0=기본, 1=확장).
        type: 패킷 종류(:data:`TACACS_TYPE_AUTHENTICATION` 등).
        seq_no: 세션 내 패킷 순번(클라 홀수·서버 짝수, 1=개시).
        flags: 플래그 바이트.
        session_id: 4바이트 세션 식별자(AAA 대화 상관 키).
        length: 헤더가 선언한 본문 길이(헤더 12 제외).
        payload_offset: 난독화 본문이 시작하는 절대 오프셋(헤더 끝).
    """

    major_version: int
    minor_version: int
    type: int
    seq_no: int
    flags: int
    session_id: int
    length: int
    payload_offset: int

    @property
    def type_name(self) -> str:
        """type 의 사람이 읽는 이름(미상이면 ``"type-<n>"``)."""
        return _TYPE_NAMES.get(self.type, f"type-{self.type}")

    @property
    def is_authentication(self) -> bool:
        """Authentication 패킷 여부(로그인 자격증명 교환)."""
        return self.type == TACACS_TYPE_AUTHENTICATION

    @property
    def is_authorization(self) -> bool:
        """Authorization 패킷 여부(명령 단위 권한 부여)."""
        return self.type == TACACS_TYPE_AUTHORIZATION

    @property
    def is_accounting(self) -> bool:
        """Accounting 패킷 여부(명령 단위 감사 로그)."""
        return self.type == TACACS_TYPE_ACCOUNTING

    @property
    def is_session_start(self) -> bool:
        """세션 개시 패킷 여부(``seq_no == 1`` — 클라가 여는 첫 패킷)."""
        return self.seq_no == 1

    @property
    def is_unencrypted(self) -> bool:
        """본문 평문 여부(TAC_PLUS_UNENCRYPTED_FLAG — 노출/디버그 정황)."""
        return bool(self.flags & TACACS_FLAG_UNENCRYPTED)

    @property
    def is_single_connect(self) -> bool:
        """단일 연결 다중화 여부(TAC_PLUS_SINGLE_CONNECT_FLAG)."""
        return bool(self.flags & TACACS_FLAG_SINGLE_CONNECT)


def parse_tacacs(data: bytes, offset: int = 0) -> Optional[Tacacs]:
    """원시 바이트에서 TACACS+ 평문 헤더를 파싱한다.

    Args:
        data: TACACS+ 패킷을 담은 바이트. 보통 TCP 49 페이로드
            (:class:`forensiclab.netdissect` 의 ``payload_offset`` 부터)다.
        offset: 패킷이 시작하는 위치(기본 0).

    Returns:
        :class:`Tacacs`. 12바이트 헤더조차 없거나, major version 이 ``0xc``
        가 아니거나, type 이 정의 밖이면 ``None``(오탐 가드). 본문(난독화)은
        풀지 않고 ``payload_offset`` 만 노출한다.
    """
    if offset < 0 or offset + TACACS_HEADER_LEN > len(data):
        return None
    version, ptype, seq_no, flags, session_id, length = struct.unpack(
        ">BBBBII", data[offset:offset + TACACS_HEADER_LEN]
    )
    major_version = version >> 4
    minor_version = version & 0x0F
    if major_version != TACACS_MAJOR_VERSION:
        return None
    if ptype not in _VALID_TYPES:
        return None
    return Tacacs(
        major_version=major_version,
        minor_version=minor_version,
        type=ptype,
        seq_no=seq_no,
        flags=flags,
        session_id=session_id,
        length=length,
        payload_offset=offset + TACACS_HEADER_LEN,
    )
