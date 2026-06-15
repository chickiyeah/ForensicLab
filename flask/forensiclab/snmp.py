"""SNMP — 단순 망 관리 프로토콜 파싱 코어 (RFC 1157 v1 / RFC 1901·3416 v2c).

:mod:`forensiclab.netdissect` 가 식별한 UDP(에이전트 161, 트랩 162) 페이로드는
SNMP 메시지일 수 있다. 이 모듈이 그 메시지를 해석한다(:mod:`forensiclab.dns`
가 UDP 53, :mod:`forensiclab.dhcp` 가 UDP 67/68, :mod:`forensiclab.ntp` 가
UDP 123, :mod:`forensiclab.tftp` 가 UDP 69 를 다루는 것과 같은 위치).

SNMP v1/v2c 는 community 문자열을 평문으로 싣는 무인증·무암호 UDP 라
침해/사고 분석에서 단서가 많다:

- **약한 인증·기본 community**: ``community`` 가 ``public``·``private`` 면
  기본값을 그대로 둔 것 — 정찰·무단 접근의 흔한 진입점이다. 평문이라
  와이어에서 그대로 노출된다.
- **정찰·열거**: ``GetRequest``·``GetNextRequest``·``GetBulkRequest`` 는
  장비 정보(sysDescr·인터페이스·라우팅·ARP 테이블 등)를 긁어가는 데 쓰인다.
  특히 GetBulkRequest(v2c) 는 대량 워킹(walk) 정찰의 신호다.
- **설정 변조**: ``SetRequest`` 는 장비 설정을 바꾸는 쓰기다 — 라우팅/ACL
  변경, 인터페이스 차단, 설정 파일 TFTP 업로드 트리거 등 능동적 침해 정황.
- **이벤트 누출**: ``Trap``(v1)·``SNMPv2-Trap`` 은 장비가 보내는 비동기
  이벤트다. enterprise OID·agent-addr·generic/specific trap 코드는
  :mod:`forensiclab.timeline` 재구성과 호스트 상관에 쓰인다.

SNMP 메시지 포맷(BER/ASN.1 인코딩, RFC 1157 §4)::

    Message ::= SEQUENCE {
        version   INTEGER,            -- 0=v1, 1=v2c
        community OCTET STRING,
        data      PDU }               -- context-specific 태그

    PDU(비-trap) ::= [tag] SEQUENCE {
        request-id INTEGER, error-status INTEGER, error-index INTEGER,
        variable-bindings SEQUENCE OF SEQUENCE { name OID, value } }

PDU 태그(context-specific): 0 GetRequest, 1 GetNextRequest, 2 (Get)Response,
3 SetRequest, 4 Trap(v1, 별도 구조), 5 GetBulkRequest, 6 InformRequest,
7 SNMPv2-Trap, 8 Report.

설계 원칙(:mod:`forensiclab.tftp`·:mod:`forensiclab.dhcp` 와 동일):
- 부작용 없음: 순수 함수. 디스크/표준출력/네트워크 없음.
- stdlib 전용.
- 안전: 입력 바이트를 변형하지 않는다(읽기 전용).
- 견고: 너무 짧거나 망가진 입력은 예외 대신 ``None``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional, Tuple

__all__ = [
    "SNMP_V1",
    "SNMP_V2C",
    "PDU_GET_REQUEST",
    "PDU_GET_NEXT_REQUEST",
    "PDU_RESPONSE",
    "PDU_SET_REQUEST",
    "PDU_TRAP_V1",
    "PDU_GET_BULK_REQUEST",
    "PDU_INFORM_REQUEST",
    "PDU_TRAP_V2",
    "PDU_REPORT",
    "DEFAULT_COMMUNITIES",
    "VarBind",
    "Snmp",
    "parse_snmp",
]

# version 필드 값(RFC 1157 / 1901). 사람이 흔히 말하는 v1/v2c 와 1 차이.
SNMP_V1 = 0
SNMP_V2C = 1

# PDU context-specific 태그 번호.
PDU_GET_REQUEST = 0       # 정찰 — 단일 OID 조회.
PDU_GET_NEXT_REQUEST = 1  # 정찰 — 워킹(walk).
PDU_RESPONSE = 2          # 응답(v1 GetResponse, v2c Response).
PDU_SET_REQUEST = 3       # 설정 변조 — 쓰기.
PDU_TRAP_V1 = 4           # v1 트랩(별도 구조).
PDU_GET_BULK_REQUEST = 5  # 대량 정찰(v2c).
PDU_INFORM_REQUEST = 6    # 확인 응답형 트랩(v2c).
PDU_TRAP_V2 = 7           # SNMPv2-Trap.
PDU_REPORT = 8            # 보고(v3/엔진 협상).

# 기본 community — 그대로 두면 약한 설정·정찰 진입점.
DEFAULT_COMMUNITIES = frozenset({"public", "private"})

_VERSION_NAMES = {SNMP_V1: "v1", SNMP_V2C: "v2c"}

_PDU_NAMES = {
    PDU_GET_REQUEST: "GetRequest",
    PDU_GET_NEXT_REQUEST: "GetNextRequest",
    PDU_RESPONSE: "Response",
    PDU_SET_REQUEST: "SetRequest",
    PDU_TRAP_V1: "Trap",
    PDU_GET_BULK_REQUEST: "GetBulkRequest",
    PDU_INFORM_REQUEST: "InformRequest",
    PDU_TRAP_V2: "SNMPv2-Trap",
    PDU_REPORT: "Report",
}

# 정찰 성격(읽기/열거) PDU.
_RECON_PDUS = frozenset({
    PDU_GET_REQUEST, PDU_GET_NEXT_REQUEST, PDU_GET_BULK_REQUEST,
})

# BER universal 태그.
_TAG_INTEGER = 0x02
_TAG_OCTET_STRING = 0x04
_TAG_NULL = 0x05
_TAG_OID = 0x06
_TAG_SEQUENCE = 0x30  # constructed | SEQUENCE.


def _read_len(data: bytes, pos: int) -> Optional[Tuple[int, int]]:
    """BER 길이를 읽어 (length, next_pos). 망가지면 ``None``.

    short form(0xxxxxxx)·long form(1nnnnnnn + n바이트) 둘 다 지원.
    무한(indefinite) 길이(0x80)는 SNMP 에 없으므로 거부한다.
    """
    if pos >= len(data):
        return None
    first = data[pos]
    pos += 1
    if first < 0x80:
        return first, pos
    n = first & 0x7F
    if n == 0 or pos + n > len(data):
        return None
    length = int.from_bytes(data[pos:pos + n], "big")
    return length, pos + n


def _read_tlv(data: bytes, pos: int) -> Optional[Tuple[int, bytes, int]]:
    """하나의 TLV 를 읽어 (tag, value_bytes, next_pos). 망가지면 ``None``."""
    if pos >= len(data):
        return None
    tag = data[pos]
    res = _read_len(data, pos + 1)
    if res is None:
        return None
    length, vstart = res
    vend = vstart + length
    if vend > len(data):
        return None
    return tag, data[vstart:vend], vend


def _read_int(value: bytes) -> int:
    """BER INTEGER 콘텐츠를 부호 있는 정수로."""
    if not value:
        return 0
    return int.from_bytes(value, "big", signed=True)


def _decode_oid(value: bytes) -> str:
    """BER OID 콘텐츠를 점 표기 문자열(``1.3.6.1...``)로.

    첫 바이트는 ``40*X + Y`` 로 앞 두 서브식별자를 인코딩한다. 이후는
    base-128 가변 길이(상위 비트가 연속 표시)다.
    """
    if not value:
        return ""
    first = value[0]
    parts = [str(first // 40), str(first % 40)]
    cur = 0
    for b in value[1:]:
        cur = (cur << 7) | (b & 0x7F)
        if not (b & 0x80):
            parts.append(str(cur))
            cur = 0
    return ".".join(parts)


@dataclass(frozen=True)
class VarBind:
    """variable-binding 한 쌍 — OID 와 그 값.

    Attributes:
        oid: 객체 식별자(점 표기). 빈 PDU/요청에서는 보통 채워지나 값은 NULL.
        value: 디코드된 값(INTEGER→int, OCTET STRING→str, OID→str,
            NULL/미지원→None). 정찰 요청에선 None(NULL) 이 정상이다.
    """

    oid: str
    value: object = None


@dataclass(frozen=True)
class Snmp:
    """파싱된 SNMP 메시지(v1/v2c).

    Attributes:
        version: version 필드 값(0=v1, 1=v2c).
        community: community 문자열(평문). 약한 설정 단서.
        pdu_type: PDU context 태그 번호(0~8).
        request_id: 요청 식별자(비-trap PDU). v1 trap 에선 None.
        error_status: 오류 상태(비-trap PDU, 0=noError).
        error_index: 오류 인덱스(비-trap PDU).
        varbinds: variable-bindings 목록.
        enterprise: v1 trap 의 enterprise OID(그 외 None).
        agent_addr: v1 trap 의 agent-address(IPv4 문자열, 그 외 None).
        generic_trap: v1 trap 의 generic-trap 코드(그 외 None).
        specific_trap: v1 trap 의 specific-trap 코드(그 외 None).
    """

    version: int
    community: str
    pdu_type: int
    request_id: Optional[int] = None
    error_status: Optional[int] = None
    error_index: Optional[int] = None
    varbinds: List[VarBind] = field(default_factory=list)
    enterprise: Optional[str] = None
    agent_addr: Optional[str] = None
    generic_trap: Optional[int] = None
    specific_trap: Optional[int] = None

    @property
    def version_name(self) -> str:
        """version 의 사람이 읽는 이름(미상이면 ``"ver-<n>"``)."""
        return _VERSION_NAMES.get(self.version, f"ver-{self.version}")

    @property
    def pdu_name(self) -> str:
        """PDU 태그의 사람이 읽는 이름(미상이면 ``"pdu-<n>"``)."""
        return _PDU_NAMES.get(self.pdu_type, f"pdu-{self.pdu_type}")

    @property
    def is_default_community(self) -> bool:
        """community 가 ``public``·``private`` 인지 — 약한 설정 단서."""
        return self.community.lower() in DEFAULT_COMMUNITIES

    @property
    def is_recon(self) -> bool:
        """정찰성 PDU(Get/GetNext/GetBulk) 여부."""
        return self.pdu_type in _RECON_PDUS

    @property
    def is_write(self) -> bool:
        """SetRequest 여부 — 설정 변조(능동적 침해) 단서."""
        return self.pdu_type == PDU_SET_REQUEST

    @property
    def is_trap(self) -> bool:
        """트랩(v1 Trap·SNMPv2-Trap) 여부."""
        return self.pdu_type in (PDU_TRAP_V1, PDU_TRAP_V2)

    @property
    def oids(self) -> List[str]:
        """variable-bindings 의 OID 만 추린 목록(정찰 대상 식별)."""
        return [vb.oid for vb in self.varbinds]


def _decode_value(tag: int, value: bytes) -> object:
    """varbind 의 값 부분을 태그에 맞춰 디코드한다.

    INTEGER/Counter/Gauge/TimeTicks(application 0x41~0x43,0x46)→int,
    OCTET STRING→latin-1 문자열, OID→점 표기, IpAddress(0x40)→IPv4,
    NULL·미지원→None.
    """
    if tag == _TAG_INTEGER or tag in (0x41, 0x42, 0x43, 0x46):
        return _read_int(value)
    if tag == _TAG_OCTET_STRING:
        return value.decode("latin-1")
    if tag == _TAG_OID:
        return _decode_oid(value)
    if tag == 0x40 and len(value) == 4:  # IpAddress.
        return ".".join(str(b) for b in value)
    return None


def _parse_varbinds(body: bytes) -> List[VarBind]:
    """variable-bindings SEQUENCE 콘텐츠를 VarBind 목록으로.

    각 항목은 SEQUENCE { name OID, value } 다. 깨진 항목은 건너뛰고
    읽을 수 있는 만큼만 모은다.
    """
    out: List[VarBind] = []
    pos = 0
    while pos < len(body):
        item = _read_tlv(body, pos)
        if item is None:
            break
        tag, vbbytes, pos = item
        if tag != _TAG_SEQUENCE:
            continue
        name = _read_tlv(vbbytes, 0)
        if name is None or name[0] != _TAG_OID:
            continue
        oid = _decode_oid(name[1])
        val_tlv = _read_tlv(vbbytes, name[2])
        value = _decode_value(val_tlv[0], val_tlv[1]) if val_tlv else None
        out.append(VarBind(oid=oid, value=value))
    return out


def _parse_v1_trap(version: int, community: str, body: bytes) -> Optional[Snmp]:
    """v1 Trap PDU 콘텐츠를 파싱한다(RFC 1157 §4.1.6).

    구조: enterprise OID, agent-addr(IpAddress), generic-trap(INTEGER),
    specific-trap(INTEGER), time-stamp(TimeTicks), variable-bindings.
    """
    pos = 0
    ent = _read_tlv(body, pos)
    if ent is None or ent[0] != _TAG_OID:
        return None
    enterprise = _decode_oid(ent[1])
    pos = ent[2]

    addr = _read_tlv(body, pos)
    agent = ".".join(str(b) for b in addr[1]) if addr and len(addr[1]) == 4 else None
    if addr is not None:
        pos = addr[2]

    gen = _read_tlv(body, pos)
    generic = _read_int(gen[1]) if gen else None
    if gen is not None:
        pos = gen[2]

    spec = _read_tlv(body, pos)
    specific = _read_int(spec[1]) if spec else None
    if spec is not None:
        pos = spec[2]

    ts = _read_tlv(body, pos)  # time-stamp — 위치 전진용으로만.
    if ts is not None:
        pos = ts[2]

    vbs = _read_tlv(body, pos)
    varbinds = _parse_varbinds(vbs[1]) if vbs and vbs[0] == _TAG_SEQUENCE else []

    return Snmp(
        version=version, community=community, pdu_type=PDU_TRAP_V1,
        enterprise=enterprise, agent_addr=agent,
        generic_trap=generic, specific_trap=specific, varbinds=varbinds,
    )


def parse_snmp(data: bytes, offset: int = 0) -> Optional[Snmp]:
    """원시 바이트에서 SNMP v1/v2c 메시지를 파싱한다.

    Args:
        data: SNMP 패킷을 담은 바이트. 보통 UDP 161/162 페이로드
            (:class:`forensiclab.netdissect` 의 ``payload_offset`` 부터)다.
        offset: 패킷이 시작하는 위치(기본 0).

    Returns:
        :class:`Snmp`. 최외곽 SEQUENCE·version·community·PDU 구조가
        SNMP 답지 않으면 ``None``. v3 은 헤더 구조가 달라 지원하지 않는다.
    """
    if offset < 0:
        return None
    outer = _read_tlv(data, offset)
    if outer is None or outer[0] != _TAG_SEQUENCE:
        return None
    body = outer[1]

    ver = _read_tlv(body, 0)
    if ver is None or ver[0] != _TAG_INTEGER:
        return None
    version = _read_int(ver[1])
    if version not in (SNMP_V1, SNMP_V2C):  # v3(=3) 등은 미지원.
        return None

    comm = _read_tlv(body, ver[2])
    if comm is None or comm[0] != _TAG_OCTET_STRING:
        return None
    community = comm[1].decode("latin-1")

    pdu = _read_tlv(body, comm[2])
    if pdu is None or (pdu[0] & 0xC0) != 0x80:  # context-specific 클래스.
        return None
    pdu_type = pdu[0] & 0x1F
    pbody = pdu[1]

    if pdu_type == PDU_TRAP_V1:
        return _parse_v1_trap(version, community, pbody)

    # 비-trap PDU: request-id, error-status, error-index, varbinds.
    rid = _read_tlv(pbody, 0)
    if rid is None or rid[0] != _TAG_INTEGER:
        return None
    request_id = _read_int(rid[1])

    est = _read_tlv(pbody, rid[2])
    error_status = _read_int(est[1]) if est and est[0] == _TAG_INTEGER else None
    pos = est[2] if est else rid[2]

    eix = _read_tlv(pbody, pos)
    error_index = _read_int(eix[1]) if eix and eix[0] == _TAG_INTEGER else None
    pos = eix[2] if eix else pos

    vbs = _read_tlv(pbody, pos)
    varbinds = _parse_varbinds(vbs[1]) if vbs and vbs[0] == _TAG_SEQUENCE else []

    return Snmp(
        version=version, community=community, pdu_type=pdu_type,
        request_id=request_id, error_status=error_status,
        error_index=error_index, varbinds=varbinds,
    )
