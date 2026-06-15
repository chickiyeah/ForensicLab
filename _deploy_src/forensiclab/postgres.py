"""PostgreSQL 프론트엔드 시작 메시지(StartupMessage) 파싱 코어.

MySQL(:mod:`forensiclab.mysql`)이 **서버가 먼저 보내는** 평문 인사를
파싱한다면, PostgreSQL 은 정반대로 **클라이언트가 먼저 보내는**
*StartupMessage* 가 첫 패킷이다(PostgreSQL Frontend/Backend Protocol,
관용 포트 5432). 인증 협상 이전에 클라이언트가 평문으로 보내는 이
메시지에는 접속 ``user``·대상 ``database``·클라이언트 ``application_name``
같은 **귀속 가치가 높은 평문 필드** 가 그대로 담긴다. 데이터베이스는
RDP/SSH/VNC/MySQL 과 같은 **원격 접속·측면 이동(lateral movement)** 의
고전적 표적이며, 노출된 5432 서비스 자체가 공격면의 단서다.

메시지 프레이밍(StartupMessage 는 다른 메시지와 달리 1바이트 타입
태그가 없다. 모든 정수는 big-endian/네트워크 바이트 순서)::

    Int32  length            메시지 전체 길이(이 4바이트 포함)
    Int32  protocol/code     프로토콜 버전 또는 특수 요청 코드
    ── 이하 StartupMessage 본문(특수 코드가 아닐 때) ──
    (key<NUL> value<NUL>)*   파라미터 키/값 쌍 나열
    NUL                      마지막 빈 키로 종단

특수 요청은 length=8(또는 CancelRequest=16) 고정에 ``code`` 자리가 매직 값::

    80877103  SSLRequest      TLS 협상 요청(이후 본문 없음)
    80877104  GSSENCRequest   GSSAPI 암호화 요청
    80877102  CancelRequest   Int32 pid + Int32 secret 로 진행 중 질의 취소

일반 StartupMessage 의 ``code`` 는 프로토콜 버전이다: 상위 16비트=major,
하위 16비트=minor. 현대는 ``3.0``(=196608), 레거시는 ``2.0``.

침해/사고 분석에서의 단서:

- **사용자 귀속(user)**: ``user`` 파라미터는 **필수** 이며 평문으로 노출된다
  — 흐름(:mod:`forensiclab.flows` 5-튜플)을 특정 DB 계정에 직접 연결한다
  (MySQL 인사가 서버 버전을 노출하는 것과 대비되는 클라이언트 측 귀속).
- **대상 식별(database)**: 접속 대상 데이터베이스 이름. 미지정 시 관례상
  ``user`` 와 동일. 정찰/유출 대상 범위 추정 근거.
- **클라이언트 핑거프린트(application_name)**: ``psql``·``pgAdmin``·
  드라이버 문자열 또는 ``sqlmap`` 같은 자동화 공격 툴 시그니처가 평문으로
  드러난다(SSH softwareversion 과 같은 도구 식별 역할).
- **TLS 미요청(requests_tls=False)**: 첫 패킷이 SSLRequest 가 아니라 곧장
  평문 StartupMessage 면, 클라이언트가 암호화를 요청하지 않은 것 — 이후
  비밀번호/질의가 평문으로 흐를 정황(MySQL ``CLIENT_SSL`` 미광고와 대응).
- **세션 취소 토큰(CancelRequest)**: pid+secret 쌍이 평문 노출 — 캡처
  시점에 진행 중이던 질의를 가로채 취소할 수 있는 약한 대역외 제어 정황.

설계 원칙(:mod:`forensiclab.mysql`·:mod:`forensiclab.vnc` 와 동일):
- 부작용 없음: 디스크/표준출력/네트워크 없이 순수 함수.
- stdlib 전용: 외부 의존성 없음.
- 안전: 입력 바이트를 변형하지 않는다(읽기 전용).
- 견고: PostgreSQL 시작 메시지가 아니거나 망가진 입력은 예외 대신 ``None``.
  본문이 잘려 있으면 파싱 가능한 파라미터까지만 채운다.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional

__all__ = [
    "POSTGRES_PORTS",
    "PROTOCOL_VERSION_3_0",
    "SSL_REQUEST_CODE",
    "GSSENC_REQUEST_CODE",
    "CANCEL_REQUEST_CODE",
    "PostgresStartup",
    "parse_postgres_startup",
]

# PostgreSQL 관용 TCP 포트. 식별 보조용일 뿐, 파싱은 포트와 무관하게
# 페이로드 형식만으로 판별한다.
POSTGRES_PORTS = (5432,)

# 일반 StartupMessage 의 protocol 코드. major<<16 | minor. 현대는 3.0.
PROTOCOL_VERSION_3_0 = (3 << 16) | 0  # 196608

# 특수 요청 매직 코드(length 자리 다음 Int32). 1234 << 16 | 567x 형태의
# 의도적으로 프로토콜 버전과 겹치지 않는 값들이다.
SSL_REQUEST_CODE = 80877103
GSSENC_REQUEST_CODE = 80877104
CANCEL_REQUEST_CODE = 80877102

# length<4> + code<4>.
_HEADER_LEN = 8

# 합리적인 StartupMessage 길이 상한(파라미터 폭주/오탐 방지). 실제 시작
# 메시지는 수백 바이트 안쪽이지만 넉넉히 잡는다.
_MAX_LENGTH = 100_000


@dataclass(frozen=True)
class PostgresStartup:
    """파싱된 PostgreSQL 프론트엔드 시작 메시지.

    Attributes:
        kind: ``"startup"``(일반)·``"ssl_request"``·``"gssenc_request"``·
            ``"cancel_request"`` 중 하나.
        length: 메시지가 선언한 전체 길이(이 4바이트 포함).
        protocol_major: ``startup`` 일 때 프로토콜 major(보통 3). 그 외 ``None``.
        protocol_minor: ``startup`` 일 때 프로토콜 minor(보통 0). 그 외 ``None``.
        parameters: ``startup`` 일 때 키/값 파라미터(``user``·``database``·
            ``application_name`` 등). 그 외 빈 dict.
        pid: ``cancel_request`` 일 때 대상 백엔드 프로세스 ID. 그 외 ``None``.
        secret_key: ``cancel_request`` 일 때 취소 비밀 키. 그 외 ``None``.
    """

    kind: str
    length: int
    protocol_major: Optional[int]
    protocol_minor: Optional[int]
    parameters: Dict[str, str]
    pid: Optional[int]
    secret_key: Optional[int]

    @property
    def is_startup(self) -> bool:
        """일반 StartupMessage(파라미터를 담는 종류)인가."""
        return self.kind == "startup"

    @property
    def requests_tls(self) -> bool:
        """첫 패킷이 SSLRequest 였는가 — False(곧장 startup)면 평문 정황."""
        return self.kind == "ssl_request"

    @property
    def is_cancel_request(self) -> bool:
        """진행 중 질의 취소 요청(pid+secret 노출)인가."""
        return self.kind == "cancel_request"

    @property
    def user(self) -> Optional[str]:
        """접속 사용자(필수 파라미터). 흐름→DB 계정 귀속의 직접 근거."""
        return self.parameters.get("user")

    @property
    def database(self) -> Optional[str]:
        """대상 데이터베이스. 미지정 시 관례상 ``user`` 와 동일."""
        return self.parameters.get("database") or self.user

    @property
    def application_name(self) -> Optional[str]:
        """클라이언트 application_name(도구/드라이버 핑거프린트)."""
        return self.parameters.get("application_name")


def parse_postgres_startup(data: bytes, offset: int = 0) -> Optional[PostgresStartup]:
    """원시 바이트에서 PostgreSQL 시작 메시지를 파싱한다.

    Args:
        data: PostgreSQL 흐름 바이트. 보통 클라이언트→서버 첫 TCP 페이로드의
            선두(:class:`forensiclab.netdissect` 의 ``payload_offset`` 부터)다.
        offset: 데이터가 시작하는 위치(기본 0).

    Returns:
        :class:`PostgresStartup`. 헤더(8바이트)를 못 갖추거나, 선언 길이가
        비합리적이거나, ``code`` 가 알려진 특수 코드도 아니고 프로토콜
        major 가 2/3 도 아니면 ``None``. CancelRequest 는 length=16 과
        pid/secret 8바이트가 있어야 인정한다. 일반 StartupMessage 본문이
        잘려 있으면 파싱 가능한 파라미터까지만 채운다.
    """
    if not data or offset < 0:
        return None
    if offset + _HEADER_LEN > len(data):
        return None

    length = int.from_bytes(data[offset:offset + 4], "big")
    code = int.from_bytes(data[offset + 4:offset + 8], "big")

    if length < _HEADER_LEN or length > _MAX_LENGTH:
        return None

    # 특수 요청 코드(고정 길이)부터 판별.
    if code == SSL_REQUEST_CODE or code == GSSENC_REQUEST_CODE:
        if length != _HEADER_LEN:
            return None
        kind = "ssl_request" if code == SSL_REQUEST_CODE else "gssenc_request"
        return PostgresStartup(
            kind=kind,
            length=length,
            protocol_major=None,
            protocol_minor=None,
            parameters={},
            pid=None,
            secret_key=None,
        )

    if code == CANCEL_REQUEST_CODE:
        # length<4> code<4> pid<4> secret<4> = 16.
        if length != 16 or offset + 16 > len(data):
            return None
        pid = int.from_bytes(data[offset + 8:offset + 12], "big")
        secret_key = int.from_bytes(data[offset + 12:offset + 16], "big")
        return PostgresStartup(
            kind="cancel_request",
            length=length,
            protocol_major=None,
            protocol_minor=None,
            parameters={},
            pid=pid,
            secret_key=secret_key,
        )

    # 일반 StartupMessage: code 는 프로토콜 버전. major 가 2/3 가 아니면
    # PostgreSQL 시작 메시지로 보지 않는다(오탐 방지).
    protocol_major = code >> 16
    protocol_minor = code & 0xFFFF
    if protocol_major not in (2, 3):
        return None

    # 본문(파라미터 영역): 선언 길이까지, 단 잘려 있으면 가용 범위까지.
    end = min(offset + length, len(data))
    region = data[offset + _HEADER_LEN:end]

    parameters: Dict[str, str] = {}
    # key<NUL> value<NUL> ... 마지막 빈 키로 종단. split 으로 분해 후 쌍 처리.
    parts = region.split(b"\x00")
    i = 0
    while i + 1 < len(parts):
        key = parts[i]
        if not key:  # 빈 키 = 종단자.
            break
        value = parts[i + 1]
        parameters[key.decode("utf-8", "replace")] = value.decode("utf-8", "replace")
        i += 2

    return PostgresStartup(
        kind="startup",
        length=length,
        protocol_major=protocol_major,
        protocol_minor=protocol_minor,
        parameters=parameters,
        pid=None,
        secret_key=None,
    )
