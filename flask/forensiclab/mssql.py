"""Microsoft SQL Server TDS PRELOGIN 메시지 파싱 코어.

MySQL(:mod:`forensiclab.mysql`)·PostgreSQL(:mod:`forensiclab.postgres`)에
이은 세 번째 관계형 DB 형제다. MS SQL Server 는 **TDS(Tabular Data
Stream)** 프로토콜을 쓰며(관용 포트 1433), 세션의 맨 처음에 클라이언트가
*PRELOGIN* 패킷을 보내 능력·암호화 의향을 협상하고 서버가 같은 형식으로
응답한다. PRELOGIN 은 인증/암호화 협상 **이전** 의 평문 단계라, 이후
LOGIN7 에 담길 자격증명이 평문으로 흐를지(약한 obfuscation 으로만 가려질지)
여기서 드러난다. 노출된 1433 서비스는 RDP/SSH/VNC/MySQL/PostgreSQL 과 같은
**원격 접속·측면 이동(lateral movement)** 의 고전적 표적이다.

TDS 패킷 헤더(8바이트 고정. 길이/SPID 는 big-endian/네트워크 바이트 순서)::

    UInt8   type        패킷 타입(0x12=PRELOGIN, 0x10=TDS7 LOGIN, …)
    UInt8   status       상태 비트(0x01=EOM 마지막 패킷)
    UInt16  length       헤더 포함 패킷 전체 길이(big-endian)
    UInt16  spid         서버 프로세스 ID(서버→클라이언트 응답에서 유효)
    UInt8   packet_id    패킷 시퀀스 번호
    UInt8   window       창(보통 0)

PRELOGIN 페이로드(헤더 8바이트 다음)는 **옵션 토큰 테이블** 이다. 각
항목은 5바이트(토큰 1 + offset 2 + length 2, offset/length 는 big-endian,
payload 시작 기준)이고 ``0xFF`` 토큰 하나로 테이블을 종단한다. 토큰별
데이터는 테이블 뒤 영역에 offset/length 로 가리켜진다::

    0x00 VERSION          6바이트: UInt32 version + UInt16 subbuild
    0x01 ENCRYPTION       1바이트: 암호화 의향(아래)
    0x02 INSTOPT          NUL 종단 인스턴스 이름
    0x03 THREADID         4바이트 클라이언트 스레드 ID
    0x04 MARS             1바이트 다중 활성 결과셋
    0x05 TRACEID          연결 추적용
    0x06 FEDAUTHREQUIRED  1바이트 연합 인증 필요 여부
    0x07 NONCEOPT         32바이트 논스
    0xFF TERMINATOR       옵션 테이블 종단

ENCRYPTION 값(LOGIN7 자격증명이 평문으로 흐를지의 핵심 단서)::

    0x00 ENCRYPT_OFF      가용하나 로그인만 암호화(이후 데이터 평문)
    0x01 ENCRYPT_ON       암호화 켜짐
    0x02 ENCRYPT_NOT_SUP  암호화 미지원 — 전 구간 평문(약한 obfuscation 만)
    0x03 ENCRYPT_REQ      암호화 강제

침해/사고 분석에서의 단서:

- **평문 자격증명 정황(ENCRYPTION)**: 협상 결과가 ``NOT_SUP``/``OFF`` 면
  이어질 LOGIN7 패킷의 사용자/비밀번호가 사실상 평문 — TDS 비밀번호는
  바이트별 nibble-swap + XOR 0xA5 라는 자명하게 가역적인 난독화만 거친다
  (MySQL ``CLIENT_SSL`` 미광고·PostgreSQL SSLRequest 부재와 같은 역할).
- **버전 핑거프린트(VERSION)**: 응답 PRELOGIN 의 서버 버전은 SQL Server
  빌드(예: 취약 패치 수준)를 평문으로 노출한다(MySQL server_version 대응).
- **인스턴스 식별(INSTOPT)**: 명명된 인스턴스 이름이 평문으로 드러난다.
- **연합 인증 협상(FEDAUTHREQUIRED)**: Azure AD/토큰 인증 경로 정황.

설계 원칙(:mod:`forensiclab.postgres`·:mod:`forensiclab.mysql` 와 동일):
- 부작용 없음: 디스크/표준출력/네트워크 없이 순수 함수.
- stdlib 전용: 외부 의존성 없음.
- 안전: 입력 바이트를 변형하지 않는다(읽기 전용).
- 견고: TDS PRELOGIN 이 아니거나 망가진 입력은 예외 대신 ``None``.
  옵션 데이터가 잘려 있으면 파싱 가능한 옵션까지만 채운다.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Optional

__all__ = [
    "MSSQL_PORTS",
    "TDS_TYPE_PRELOGIN",
    "TDS_TYPE_LOGIN7",
    "PRELOGIN_TOKENS",
    "ENCRYPTION_MODES",
    "MSSQLPrelogin",
    "parse_mssql_prelogin",
]

# MS SQL Server 관용 TCP 포트(기본 인스턴스). 식별 보조용일 뿐, 파싱은
# 포트와 무관하게 페이로드 형식만으로 판별한다.
MSSQL_PORTS = (1433,)

# TDS 패킷 타입(우리가 인식하는 것 + 오탐 방지용 알려진 집합).
TDS_TYPE_SQL_BATCH = 0x01
TDS_TYPE_RPC = 0x03
TDS_TYPE_TABULAR_RESULT = 0x04
TDS_TYPE_LOGIN7 = 0x10
TDS_TYPE_PRELOGIN = 0x12

# PRELOGIN 옵션 토큰 → 이름.
PRELOGIN_TOKENS = {
    0x00: "VERSION",
    0x01: "ENCRYPTION",
    0x02: "INSTOPT",
    0x03: "THREADID",
    0x04: "MARS",
    0x05: "TRACEID",
    0x06: "FEDAUTHREQUIRED",
    0x07: "NONCEOPT",
}
_TERMINATOR = 0xFF

# ENCRYPTION 옵션 값 → 의미.
ENCRYPTION_MODES = {
    0x00: "ENCRYPT_OFF",
    0x01: "ENCRYPT_ON",
    0x02: "ENCRYPT_NOT_SUP",
    0x03: "ENCRYPT_REQ",
}

# TDS 헤더 길이.
_HEADER_LEN = 8

# 합리적인 TDS 패킷 길이 상한/하한(오탐·폭주 방지). PRELOGIN 은 보통
# 수십~수백 바이트.
_MAX_LENGTH = 65_535  # length 필드가 UInt16 이므로 구조적 상한.
_MIN_PRELOGIN = _HEADER_LEN + 1  # 최소한 종단 토큰 하나는 들어갈 자리.

# 옵션 테이블 항목 크기(토큰 1 + offset 2 + length 2).
_OPTION_ENTRY = 5


@dataclass(frozen=True)
class MSSQLPrelogin:
    """파싱된 TDS PRELOGIN 메시지.

    Attributes:
        length: TDS 헤더가 선언한 패킷 전체 길이(헤더 8바이트 포함).
        spid: 서버 프로세스 ID(서버 응답에서 유효, 클라이언트 요청은 보통 0).
        is_eom: status 의 EOM(0x01) 비트 — 이 패킷이 메시지의 끝인가.
        encryption: ENCRYPTION 옵션 값(0~3). 없으면 ``None``.
        version: VERSION 옵션의 (major, minor, build, subbuild) 튜플. 없으면 ``None``.
        instance: INSTOPT 인스턴스 이름(평문). 없으면 ``None``.
        fed_auth_required: FEDAUTHREQUIRED 옵션 값. 없으면 ``None``.
        options: 존재한 모든 옵션의 원시 데이터(토큰 이름 → bytes).
    """

    length: int
    spid: int
    is_eom: bool
    encryption: Optional[int]
    version: Optional[tuple]
    instance: Optional[str]
    fed_auth_required: Optional[int]
    options: Dict[str, bytes] = field(default_factory=dict)

    @property
    def encryption_mode(self) -> Optional[str]:
        """ENCRYPTION 값의 사람이 읽는 이름(``ENCRYPT_NOT_SUP`` 등)."""
        if self.encryption is None:
            return None
        return ENCRYPTION_MODES.get(self.encryption, f"UNKNOWN_{self.encryption}")

    @property
    def plaintext_credentials_likely(self) -> bool:
        """협상 결과가 평문 자격증명 흐름을 시사하는가.

        ``ENCRYPT_NOT_SUP``(미지원)·``ENCRYPT_OFF``(로그인만 암호화 후 평문)
        는 이어질 LOGIN7 의 사용자/비밀번호가 약한 obfuscation 만 거쳐 사실상
        평문임을 뜻한다.
        """
        return self.encryption in (0x00, 0x02)

    @property
    def version_str(self) -> Optional[str]:
        """VERSION 을 ``major.minor.build`` 문자열로(서버 빌드 핑거프린트)."""
        if not self.version:
            return None
        major, minor, build, _sub = self.version
        return f"{major}.{minor}.{build}"


def _read_options(payload: bytes) -> Dict[int, bytes]:
    """PRELOGIN 페이로드에서 토큰→데이터 매핑을 읽는다.

    옵션 테이블이 잘려 있거나 offset/length 가 페이로드 밖을 가리키면 그
    옵션은 건너뛴다(견고성). 종단 토큰(0xFF)을 만나면 멈춘다.
    """
    options: Dict[int, bytes] = {}
    i = 0
    n = len(payload)
    while i < n:
        token = payload[i]
        if token == _TERMINATOR:
            break
        if i + _OPTION_ENTRY > n:
            # 항목 헤더가 잘림 — 더 읽을 수 없다.
            break
        off = int.from_bytes(payload[i + 1:i + 3], "big")
        ln = int.from_bytes(payload[i + 3:i + 5], "big")
        # 데이터가 페이로드 범위 안일 때만 채운다(잘리면 건너뜀).
        if off + ln <= n:
            options[token] = payload[off:off + ln]
        i += _OPTION_ENTRY
    return options


def parse_mssql_prelogin(data: bytes, offset: int = 0) -> Optional[MSSQLPrelogin]:
    """원시 바이트에서 TDS PRELOGIN 메시지를 파싱한다.

    Args:
        data: TDS 흐름 바이트. 보통 클라이언트→서버(또는 서버→클라이언트)
            첫 TCP 페이로드의 선두(:mod:`forensiclab.netdissect` 의
            ``payload_offset`` 부터)다.
        offset: 데이터가 시작하는 위치(기본 0).

    Returns:
        :class:`MSSQLPrelogin`. 헤더(8바이트)를 못 갖추거나, 타입이
        PRELOGIN(0x12)이 아니거나, 선언 길이가 비합리적이면 ``None``.
        옵션 데이터가 잘려 있으면 파싱 가능한 옵션까지만 채운다.
    """
    if not data or offset < 0:
        return None
    if offset + _HEADER_LEN > len(data):
        return None

    ptype = data[offset]
    if ptype != TDS_TYPE_PRELOGIN:
        return None

    status = data[offset + 1]
    length = int.from_bytes(data[offset + 2:offset + 4], "big")
    spid = int.from_bytes(data[offset + 4:offset + 6], "big")

    if length < _MIN_PRELOGIN or length > _MAX_LENGTH:
        return None

    # 본문(옵션 테이블+데이터): 선언 길이까지, 단 잘려 있으면 가용 범위까지.
    end = min(offset + length, len(data))
    payload = data[offset + _HEADER_LEN:end]

    raw = _read_options(payload)

    # ENCRYPTION: 1바이트 값.
    encryption: Optional[int] = None
    enc_raw = raw.get(0x01)
    if enc_raw:
        encryption = enc_raw[0]

    # VERSION: UInt32 version + UInt16 subbuild → (major, minor, build, subbuild).
    version: Optional[tuple] = None
    ver_raw = raw.get(0x00)
    if ver_raw and len(ver_raw) >= 6:
        major = ver_raw[0]
        minor = ver_raw[1]
        build = int.from_bytes(ver_raw[2:4], "big")
        subbuild = int.from_bytes(ver_raw[4:6], "big")
        version = (major, minor, build, subbuild)

    # INSTOPT: NUL 종단 인스턴스 이름.
    instance: Optional[str] = None
    inst_raw = raw.get(0x02)
    if inst_raw is not None:
        instance = inst_raw.split(b"\x00", 1)[0].decode("ascii", "replace")

    # FEDAUTHREQUIRED: 1바이트.
    fed_auth_required: Optional[int] = None
    fed_raw = raw.get(0x06)
    if fed_raw:
        fed_auth_required = fed_raw[0]

    options = {PRELOGIN_TOKENS.get(t, f"UNKNOWN_{t}"): v for t, v in raw.items()}

    return MSSQLPrelogin(
        length=length,
        spid=spid,
        is_eom=bool(status & 0x01),
        encryption=encryption,
        version=version,
        instance=instance,
        fed_auth_required=fed_auth_required,
        options=options,
    )
