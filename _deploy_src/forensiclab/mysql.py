"""MySQL/MariaDB 초기 핸드셰이크(서버 인사) 파싱 코어 (HandshakeV10).

:mod:`forensiclab.netdissect` 가 식별한 TCP(관용 포트 3306) 페이로드 중
**서버가 가장 먼저 보내는 패킷** 은 MySQL 프로토콜의 *초기 핸드셰이크*
(HandshakeV10, MySQL Internals "Connection Phase")다. 클라이언트 인증
이전에 서버가 평문으로 보내는 **배너성 인사** 라, SSH 배너
(:mod:`forensiclab.ssh`)·VNC ProtocolVersion(:mod:`forensiclab.vnc`)처럼
패킷에 그대로 보이고 핑거프린트·약한 인증 단서가 짙다. 데이터베이스는
RDP/SSH/VNC 와 같은 **원격 접속·측면 이동(lateral movement)** 의 고전적
표적이며, 노출된 3306 서비스 자체가 정찰/공격면의 단서다.

패킷 프레이밍과 페이로드(little-endian)::

    [4바이트 패킷 헤더]  payload_length<3> + sequence_id<1>(인사=0)
    ── 이하 페이로드(HandshakeV10) ──
    protocol_version<1>        = 0x0a (10)
    server_version<NUL>        ASCII NUL 종단 (예: "8.0.32", "5.5.5-10.5.8-MariaDB")
    thread_id<4>               연결/스레드 ID
    auth_plugin_data_part_1<8> 인증 챌린지(salt) 앞부분
    filler<1>                  0x00
    capability_flags_1<2>      능력 플래그 하위 16비트
    character_set<1>           서버 기본 캐릭터셋(collation id)
    status_flags<2>            서버 상태
    capability_flags_2<2>      능력 플래그 상위 16비트
    auth_plugin_data_len<1>    (CLIENT_PLUGIN_AUTH 시) 챌린지 길이
    reserved<10>               0x00
    auth_plugin_data_part_2<…> (CLIENT_SECURE_CONNECTION) 챌린지 뒷부분
    auth_plugin_name<NUL>      (CLIENT_PLUGIN_AUTH) 인증 플러그인 이름

침해/사고 분석에서의 단서:

- **버전 핑거프린트(server_version)**: ``8.0.32``·``5.7.44`` 등 정확한
  빌드 문자열이 평문으로 노출된다(SSH softwareversion 과 같은 역할).
  취약 버전 식별·패치 수준 추정의 직접 근거.
- **벤더 핑거프린트(is_mariadb)**: MariaDB 는 호환성 때문에 버전 앞에
  ``5.5.5-`` 접두를 붙이거나 문자열에 ``MariaDB`` 를 담는다 — Oracle MySQL·
  Percona·MariaDB 구분 단서.
- **TLS 미제공(supports_ssl=False)**: 능력 플래그에 ``CLIENT_SSL`` 이
  없으면 서버가 암호화를 광고하지 않는 것 — 이후 자격증명/질의가 평문으로
  흐를 정황(:mod:`forensiclab.flows` 5-튜플로 클라이언트→서버 경로 연결).
- **약한 인증 플러그인(is_weak_auth_plugin)**: ``mysql_clear_password`` 는
  비밀번호를 평문으로 보내고, ``mysql_old_password`` 는 pre-4.1 취약 해시다.
  널리 쓰이는 ``mysql_native_password`` 도 SHA1 기반 deprecated(8.4+ 비활성
  추세)이며, 현대 기본값은 ``caching_sha2_password``. 서버가 광고하는
  플러그인이 인증 강도/다운그레이드 정황을 가른다.

설계 원칙(:mod:`forensiclab.vnc`·:mod:`forensiclab.ssh` 와 동일):
- 부작용 없음: 디스크/표준출력/네트워크 없이 순수 함수.
- stdlib 전용: 외부 의존성 없음.
- 안전: 입력 바이트를 변형하지 않는다(읽기 전용).
- 견고: MySQL 인사가 아니거나 망가진 입력은 예외 대신 ``None``. 4바이트
  패킷 헤더는 있어도/없어도 자동 감지하고, 확장 필드(능력/캐릭터셋/플러그인)
  가 잘려 있으면 거기까지만 채우고 나머지는 ``None`` 으로 둔다.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

__all__ = [
    "MYSQL_PROTOCOL_V10",
    "MYSQL_PROTOCOL_V9",
    "MYSQL_PORTS",
    "CLIENT_LONG_PASSWORD",
    "CLIENT_CONNECT_WITH_DB",
    "CLIENT_COMPRESS",
    "CLIENT_PROTOCOL_41",
    "CLIENT_SSL",
    "CLIENT_SECURE_CONNECTION",
    "CLIENT_PLUGIN_AUTH",
    "WEAK_AUTH_PLUGINS",
    "MysqlHandshake",
    "parse_mysql_handshake",
]

# protocol_version 첫 바이트. 0x0a=HandshakeV10(현대 전부), 0x09=구식 V9.
MYSQL_PROTOCOL_V10 = 0x0A
MYSQL_PROTOCOL_V9 = 0x09

# MySQL/MariaDB 관용 TCP 포트. 식별 보조용일 뿐, 파싱은 포트와 무관하게
# 페이로드 형식만으로 판별한다.
MYSQL_PORTS = (3306,)

# 능력 플래그(capability flags) — 인사에서 의미 있는 비트만 정의.
CLIENT_LONG_PASSWORD = 0x00000001
CLIENT_CONNECT_WITH_DB = 0x00000008
CLIENT_COMPRESS = 0x00000020
CLIENT_PROTOCOL_41 = 0x00000200
CLIENT_SSL = 0x00000800
CLIENT_SECURE_CONNECTION = 0x00008000
CLIENT_PLUGIN_AUTH = 0x00080000

# 약한 인증 플러그인: clear_password=평문 전송, old_password=pre-4.1 취약 해시.
# native_password(SHA1, deprecated)는 별도 — docstring 참조.
WEAK_AUTH_PLUGINS = frozenset({"mysql_clear_password", "mysql_old_password"})

# 페이로드 길이가 음수일 리 없고, 패킷 헤더 sequence_id 인사값은 0.
_PACKET_HEADER_LEN = 4


@dataclass(frozen=True)
class MysqlHandshake:
    """파싱된 MySQL/MariaDB 초기 핸드셰이크(서버 인사).

    Attributes:
        protocol_version: 첫 바이트(보통 ``10``=HandshakeV10).
        server_version: NUL 종단 버전 문자열(예: ``"8.0.32"``).
        thread_id: 서버가 부여한 연결/스레드 ID.
        capabilities: 능력 플래그 32비트(상·하위 결합). 확장부가 잘려 있으면
            하위 16비트만 또는 ``None``.
        charset: 서버 기본 캐릭터셋(collation id). 없으면 ``None``.
        status_flags: 서버 상태 플래그. 없으면 ``None``.
        auth_plugin_name: 인증 플러그인 이름(예: ``"caching_sha2_password"``).
            CLIENT_PLUGIN_AUTH 미광고/잘림이면 ``None``.
        has_packet_header: 입력에 4바이트 MySQL 패킷 헤더가 있었는지.
    """

    protocol_version: int
    server_version: str
    thread_id: int
    capabilities: Optional[int]
    charset: Optional[int]
    status_flags: Optional[int]
    auth_plugin_name: Optional[str]
    has_packet_header: bool

    def _has_cap(self, flag: int) -> bool:
        return self.capabilities is not None and bool(self.capabilities & flag)

    @property
    def supports_ssl(self) -> bool:
        """``CLIENT_SSL`` 광고 여부 — False 면 평문 자격증명 노출 정황."""
        return self._has_cap(CLIENT_SSL)

    @property
    def supports_plugin_auth(self) -> bool:
        """``CLIENT_PLUGIN_AUTH`` 광고 여부(플러그형 인증 협상)."""
        return self._has_cap(CLIENT_PLUGIN_AUTH)

    @property
    def protocol_41(self) -> bool:
        """``CLIENT_PROTOCOL_41`` 광고 여부(4.1+ 인증 핸드셰이크)."""
        return self._has_cap(CLIENT_PROTOCOL_41)

    @property
    def is_weak_auth_plugin(self) -> bool:
        """광고된 인증 플러그인이 평문/취약(clear_password·old_password)인가."""
        return self.auth_plugin_name in WEAK_AUTH_PLUGINS

    @property
    def is_mariadb(self) -> bool:
        """버전 문자열이 MariaDB 핑거프린트(``MariaDB`` 또는 ``5.5.5-`` 접두)인가."""
        v = self.server_version
        return "mariadb" in v.lower() or v.startswith("5.5.5-")


def parse_mysql_handshake(data: bytes, offset: int = 0) -> Optional[MysqlHandshake]:
    """원시 바이트에서 MySQL 초기 핸드셰이크(HandshakeV10)를 파싱한다.

    Args:
        data: MySQL 흐름 바이트. 보통 서버→클라이언트 첫 TCP 페이로드의 선두
            (:class:`forensiclab.netdissect` 의 ``payload_offset`` 부터)다.
            4바이트 패킷 헤더는 있어도/없어도 자동 감지한다.
        offset: 데이터가 시작하는 위치(기본 0).

    Returns:
        :class:`MysqlHandshake`. protocol_version 바이트가 9/10 이 아니거나,
        server_version NUL 종단 또는 thread_id(4바이트)를 못 갖추면 ``None``.
        확장 필드(능력/캐릭터셋/상태/플러그인)는 입력이 거기까지 있을 때만
        채우고, 잘려 있으면 해당 필드는 ``None`` 으로 둔다.
    """
    if not data or offset < 0 or offset >= len(data):
        return None

    p = offset
    has_header = False

    # 4바이트 패킷 헤더(payload_len<3> + seq_id<1>) 자동 감지.
    # 선두가 바로 protocol_version 이 아니고, 4바이트 뒤가 protocol_version
    # 이며 seq_id 가 인사값 0 이면 헤더가 있는 것으로 본다.
    if data[p] not in (MYSQL_PROTOCOL_V9, MYSQL_PROTOCOL_V10):
        if (
            len(data) >= p + _PACKET_HEADER_LEN + 1
            and data[p + 3] == 0
            and data[p + 4] in (MYSQL_PROTOCOL_V9, MYSQL_PROTOCOL_V10)
        ):
            has_header = True
            p += _PACKET_HEADER_LEN
        else:
            return None

    protocol_version = data[p]
    p += 1

    # server_version: NUL 종단 ASCII.
    nul = data.find(b"\x00", p)
    if nul == -1:
        return None
    server_version = data[p:nul].decode("ascii", "replace")
    if not server_version:
        return None
    p = nul + 1

    # thread_id: 4바이트 LE.
    if p + 4 > len(data):
        return None
    thread_id = int.from_bytes(data[p:p + 4], "little")
    p += 4

    capabilities: Optional[int] = None
    charset: Optional[int] = None
    status_flags: Optional[int] = None
    auth_plugin_name: Optional[str] = None

    # auth_plugin_data_part_1<8> + filler<1> + capability_flags_1<2>.
    if p + 8 + 1 + 2 <= len(data):
        p += 8  # auth-plugin-data-part-1 (챌린지 앞 8바이트)
        p += 1  # filler 0x00
        cap_lo = int.from_bytes(data[p:p + 2], "little")
        p += 2
        capabilities = cap_lo

        # character_set<1> + status_flags<2> + capability_flags_2<2>.
        if p + 1 + 2 + 2 <= len(data):
            charset = data[p]
            p += 1
            status_flags = int.from_bytes(data[p:p + 2], "little")
            p += 2
            cap_hi = int.from_bytes(data[p:p + 2], "little")
            p += 2
            capabilities = cap_lo | (cap_hi << 16)

            # auth_plugin_data_len<1> + reserved<10>.
            if p + 1 + 10 <= len(data):
                apd_len = data[p]
                p += 1
                p += 10  # reserved (0x00 * 10)

                # auth-plugin-data-part-2: max(13, apd_len-8) 바이트.
                if capabilities & CLIENT_SECURE_CONNECTION:
                    p += max(13, apd_len - 8)

                # auth_plugin_name: NUL 종단(끝에서 NUL 누락도 허용).
                if capabilities & CLIENT_PLUGIN_AUTH and p < len(data):
                    nul2 = data.find(b"\x00", p)
                    if nul2 != -1:
                        name = data[p:nul2]
                    else:
                        name = data[p:]
                    auth_plugin_name = (
                        name.decode("ascii", "replace").rstrip("\x00") or None
                    )

    return MysqlHandshake(
        protocol_version=protocol_version,
        server_version=server_version,
        thread_id=thread_id,
        capabilities=capabilities,
        charset=charset,
        status_flags=status_flags,
        auth_plugin_name=auth_plugin_name,
        has_packet_header=has_header,
    )
