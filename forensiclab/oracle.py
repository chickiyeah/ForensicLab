"""Oracle Database TNS(Transparent Network Substrate) CONNECT 파싱 코어.

MySQL(:mod:`forensiclab.mysql`)·PostgreSQL(:mod:`forensiclab.postgres`)·
MS SQL Server(:mod:`forensiclab.mssql`)에 이은 **네 번째 관계형 DB 형제** 다.
Oracle 클라이언트는 리스너(관용 포트 1521)에 접속하면서 맨 처음 **TNS
CONNECT** 패킷을 보낸다. 이 패킷의 본문에는 *connect descriptor* 라 불리는
괄호 트리 문자열이 평문으로 실려, 접속하려는 **서비스 이름(SERVICE_NAME)/
SID**·대상 호스트·포트·그리고 종종 클라이언트 프로그램/OS 사용자(CID)가
그대로 드러난다. 인증(O3LOGON/O5LOGON) **이전** 의 평문 협상 단계라, MySQL
의 server_version 인사·PostgreSQL StartupMessage·MSSQL PRELOGIN 과 같은
"인증 전 평문에서 무엇이 새는가" 자리를 차지한다.

TNS 패킷 헤더(8바이트 고정. 길이/체크섬은 big-endian/네트워크 바이트 순서)::

    UInt16  packet_length     헤더 포함 패킷 전체 길이(고전 8i~ 16비트)
    UInt16  packet_checksum   보통 0
    UInt8   packet_type       패킷 타입(1=CONNECT, 2=ACCEPT, …)
    UInt8   reserved/flags    예약/플래그
    UInt16  header_checksum   보통 0

CONNECT(타입 1) 본문(헤더 8바이트 다음, 모두 big-endian)::

    UInt16  version                협상 버전(예: 0x013A=314 → 11g/12c대)
    UInt16  version_compatible     하위 호환 버전
    UInt16  service_options
    UInt16  sdu                    세션 데이터 단위 크기
    UInt16  max_tdu                최대 전송 데이터 단위
    UInt16  nt_protocol_chars
    UInt16  line_turnaround
    UInt16  value_of_1            바이트 순서 표식(0x0001)
    UInt16  connect_data_length    descriptor 문자열 길이
    UInt16  connect_data_offset    descriptor 시작 오프셋(패킷 선두 기준)
    UInt32  connect_data_max
    …(플래그 등)…
    bytes   connect_data           괄호 descriptor 평문 문자열

connect descriptor 예시(평문)::

    (DESCRIPTION=(CONNECT_DATA=(SERVICE_NAME=orcl)(CID=(PROGRAM=sqlplus)
    (HOST=ws01)(USER=oracle)))(ADDRESS=(PROTOCOL=TCP)(HOST=10.0.0.5)
    (PORT=1521)))

침해/사고 분석에서의 단서:

- **서비스/SID 열거(SERVICE_NAME·SID)**: 접속 대상 DB 인스턴스가 평문으로
  드러난다 — TNS 리스너 정찰(서비스명 추측·brute)의 결과물.
- **버전 핑거프린트(version)**: 협상 버전으로 Oracle 릴리스 세대를 추정
  (취약 패치 수준; MySQL server_version·MSSQL VERSION 대응).
- **호스트/포트 리다이렉션(ADDRESS)**: TNS 는 REDIRECT(타입 5)로 다른
  호스트/포트로 보낼 수 있어 **TNS poisoning/MITM** 정황의 토대.
- **클라이언트 귀속(CID: PROGRAM/HOST/USER)**: 접속 도구·발신 호스트명·
  OS 사용자명이 평문 — 흐름을 사람/도구에 연결(PostgreSQL application_name
  대응). 노출된 1521 은 RDP/SSH/VNC/MySQL/PostgreSQL/MSSQL 형제 원격
  접속·측면 이동 표적.

설계 원칙(:mod:`forensiclab.mssql`·:mod:`forensiclab.postgres` 와 동일):
- 부작용 없음: 디스크/표준출력/네트워크 없이 순수 함수.
- stdlib 전용: 외부 의존성 없음.
- 안전: 입력 바이트를 변형하지 않는다(읽기 전용).
- 견고: TNS CONNECT 가 아니거나 망가진 입력은 예외 대신 ``None``.
  descriptor 가 잘려 있으면 가용 범위까지만 읽는다.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, Optional

__all__ = [
    "ORACLE_PORTS",
    "TNS_TYPE_CONNECT",
    "TNS_TYPES",
    "OracleConnect",
    "parse_oracle_connect",
]

# Oracle 리스너 관용 TCP 포트. 식별 보조용일 뿐, 파싱은 포트와 무관하게
# 페이로드 형식만으로 판별한다.
ORACLE_PORTS = (1521,)

# TNS 패킷 타입(우리가 인식하는 것 + 오탐 방지용 알려진 집합).
TNS_TYPE_CONNECT = 0x01
TNS_TYPE_ACCEPT = 0x02
TNS_TYPE_ACK = 0x03
TNS_TYPE_REFUSE = 0x04
TNS_TYPE_REDIRECT = 0x05
TNS_TYPE_DATA = 0x06
TNS_TYPE_NULL = 0x07
TNS_TYPE_ABORT = 0x09
TNS_TYPE_RESEND = 0x0B
TNS_TYPE_MARKER = 0x0C
TNS_TYPE_ATTENTION = 0x0D
TNS_TYPE_CONTROL = 0x0E

TNS_TYPES = {
    TNS_TYPE_CONNECT: "CONNECT",
    TNS_TYPE_ACCEPT: "ACCEPT",
    TNS_TYPE_ACK: "ACK",
    TNS_TYPE_REFUSE: "REFUSE",
    TNS_TYPE_REDIRECT: "REDIRECT",
    TNS_TYPE_DATA: "DATA",
    TNS_TYPE_NULL: "NULL",
    TNS_TYPE_ABORT: "ABORT",
    TNS_TYPE_RESEND: "RESEND",
    TNS_TYPE_MARKER: "MARKER",
    TNS_TYPE_ATTENTION: "ATTENTION",
    TNS_TYPE_CONTROL: "CONTROL",
}

# TNS 헤더 길이.
_HEADER_LEN = 8
# CONNECT 본문에서 connect_data_length·offset 까지 도달하는 데 필요한 길이.
# 헤더(8) 뒤 8개 UInt16(16바이트) 다음 위치(=오프셋 24/26).
_CD_LEN_AT = 8 * 2  # 본문 시작 기준 connect_data_length 위치(바이트).
_CD_OFF_AT = _CD_LEN_AT + 2

# 합리적인 TNS 패킷 길이 상한/하한(오탐·폭주 방지).
_MAX_LENGTH = 65_535  # length 필드가 UInt16 이므로 구조적 상한.
_MIN_CONNECT = _HEADER_LEN + _CD_OFF_AT + 2  # 헤더 + descriptor 메타까지.

# descriptor 에서 뽑는 관심 키(평문 정찰/귀속 단서).
_INTEREST_KEYS = (
    "SERVICE_NAME", "SID", "SERVER", "INSTANCE_NAME",
    "PROGRAM", "HOST", "USER", "PORT", "PROTOCOL", "GLOBAL_NAME",
)
# (KEY=value) 추출 — value 는 ()· 공백 없는 leaf.
_KV_RE = re.compile(rb"\(([A-Za-z0-9_]+)\s*=\s*([^()=]+)\)")


@dataclass(frozen=True)
class OracleConnect:
    """파싱된 TNS CONNECT 메시지.

    Attributes:
        length: TNS 헤더가 선언한 패킷 전체 길이(헤더 8바이트 포함).
        version: 협상 버전(UInt16). 알 수 없으면 ``None``.
        version_compatible: 하위 호환 버전(UInt16). 없으면 ``None``.
        connect_data: 평문 connect descriptor 문자열. 없으면 ``None``.
        attributes: descriptor 에서 추출한 관심 키→값(SERVICE_NAME 등).
    """

    length: int
    version: Optional[int]
    version_compatible: Optional[int]
    connect_data: Optional[str]
    attributes: Dict[str, str] = field(default_factory=dict)

    @property
    def service_name(self) -> Optional[str]:
        """SERVICE_NAME(없으면 SID) — 접속 대상 DB 인스턴스 식별."""
        return self.attributes.get("SERVICE_NAME") or self.attributes.get("SID")

    @property
    def program(self) -> Optional[str]:
        """CID 의 PROGRAM — 클라이언트 도구 핑거프린트."""
        return self.attributes.get("PROGRAM")

    @property
    def os_user(self) -> Optional[str]:
        """CID 의 USER — 발신 OS 사용자명(귀속 단서)."""
        return self.attributes.get("USER")

    @property
    def version_hex(self) -> Optional[str]:
        """version 을 16진 문자열로(릴리스 핑거프린트 비교용)."""
        if self.version is None:
            return None
        return f"0x{self.version:04x}"


def _extract_attributes(descriptor: bytes) -> Dict[str, str]:
    """connect descriptor 문자열에서 관심 키→값을 뽑는다.

    같은 키가 여러 번 나오면(예: ADDRESS 와 CID 양쪽의 HOST) 첫 값을
    유지한다. 값은 ASCII 로 해석하되 비ASCII 는 대체 문자로.
    """
    attrs: Dict[str, str] = {}
    for m in _KV_RE.finditer(descriptor):
        key = m.group(1).decode("ascii", "replace").upper()
        if key not in _INTEREST_KEYS or key in attrs:
            continue
        val = m.group(2).strip().decode("ascii", "replace")
        attrs[key] = val
    return attrs


def parse_oracle_connect(data: bytes, offset: int = 0) -> Optional[OracleConnect]:
    """원시 바이트에서 TNS CONNECT 메시지를 파싱한다.

    Args:
        data: TNS 흐름 바이트. 보통 클라이언트→서버 첫 TCP 페이로드의 선두
            (:mod:`forensiclab.netdissect` 의 ``payload_offset`` 부터)다.
        offset: 데이터가 시작하는 위치(기본 0).

    Returns:
        :class:`OracleConnect`. 헤더(8바이트)를 못 갖추거나, 타입이
        CONNECT(0x01)이 아니거나, 선언 길이가 비합리적이면 ``None``.
        descriptor 가 잘려 있으면 가용 범위까지만 채운다.
    """
    if not data or offset < 0:
        return None
    if offset + _HEADER_LEN > len(data):
        return None

    length = int.from_bytes(data[offset:offset + 2], "big")
    ptype = data[offset + 4]
    if ptype != TNS_TYPE_CONNECT:
        return None
    if length < _MIN_CONNECT or length > _MAX_LENGTH:
        return None

    body_start = offset + _HEADER_LEN

    # 본문 고정 필드: version·version_compatible(각 UInt16).
    version: Optional[int] = None
    version_compatible: Optional[int] = None
    if body_start + 4 <= len(data):
        version = int.from_bytes(data[body_start:body_start + 2], "big")
        version_compatible = int.from_bytes(data[body_start + 2:body_start + 4], "big")

    # connect_data_length·offset(패킷 선두 기준).
    connect_data: Optional[str] = None
    attributes: Dict[str, str] = {}
    if body_start + _CD_OFF_AT + 2 <= len(data):
        cd_len = int.from_bytes(data[body_start + _CD_LEN_AT:body_start + _CD_LEN_AT + 2], "big")
        cd_off = int.from_bytes(data[body_start + _CD_OFF_AT:body_start + _CD_OFF_AT + 2], "big")
        # offset 은 패킷 선두 기준. 범위 안일 때만 읽고, 잘리면 가용분까지.
        if 0 < cd_off < length and cd_len > 0:
            start = offset + cd_off
            end = min(start + cd_len, offset + length, len(data))
            if start < end:
                blob = data[start:end]
                connect_data = blob.decode("ascii", "replace")
                attributes = _extract_attributes(blob)

    return OracleConnect(
        length=length,
        version=version,
        version_compatible=version_compatible,
        connect_data=connect_data,
        attributes=attributes,
    )
