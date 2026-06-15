"""DCE/RPC — MSRPC PDU 파싱 코어 (DCE 1.1 / MS-RPCE).

:mod:`forensiclab.smb` 가 식별한 SMB ``IPC$`` 트리 위의 named pipe(``\\PIPE\\``)
나 TCP 135(엔드포인트 매퍼)·동적 고포트로 흐르는 페이로드는 DCE/RPC PDU 일
수 있다. 이 모듈이 그 PDU 를 해석한다. LDAP(389)·Kerberos(88)·SMB(445) 에
이은 **다섯 번째 AD 공격면 형제** — LDAP 가 디렉터리 질의, Kerberos 가 티켓
발급, SMB 가 공유/파이프 접근이면 **DCE/RPC 는 그 파이프 위에서 실제로 호출되는
원격 관리 인터페이스 그 자체**다. 측면 이동·권한 상승의 손잡이가 여기 드러난다.

핵심 단서는 **BIND PDU 의 abstract syntax 인터페이스 UUID** 다. 클라이언트가
어떤 RPC 인터페이스에 바인딩하는지가 곧 의도다:

- **DRSUAPI**(``e3514235-…``) — 디렉터리 복제. ``DRSGetNCChanges``(opnum 3)
  로 **DCSync**(krbtgt 해시 포함 자격증명 일괄 탈취) 수행.
- **SVCCTL**(``367abb81-…``) — 서비스 제어 관리자. **PsExec**·원격 서비스
  생성/실행(측면 이동·코드 실행)의 표준 경로.
- **ATSVC / ITaskSchedulerService** — 작업 스케줄러(``schtasks`` 원격 실행).
- **SAMR**(``12345778-…ac``)·**LSARPC**(``…ab``) — 계정/SID·정책 열거
  (BloodHound·rpcclient·lsadump).
- **SPOOLSS**(MS-RPRN) — **PrintNightmare**(CVE-2021-34527)·프린터 버그 강제.
- **EFSRPC**(MS-EFSR) — **PetitPotam**(인증 강제 릴레이) 코어션.
- **WINREG** — 원격 레지스트리(SAM/SECURITY 하이브 덤프).
- **EPM**(``e1af8308-…``) — 엔드포인트 매퍼(동적 포트 정찰, 135).

설계 원칙(다른 forensiclab 프로토콜 모듈과 동일):
- 부작용 없음: 순수 함수. 디스크/표준출력/네트워크 없음.
- stdlib 전용.
- 안전: 입력 바이트를 변형하지 않는다(읽기 전용).
- 견고: 너무 짧거나 망가진 입력은 예외 대신 ``None``. 컨텍스트 목록 파싱이
  도중 실패하면 거기까지 읽은 만큼만 반환한다.
- 바이트 순서: 공통 헤더의 ``packed_drep`` 첫 옥텟 상위 4비트로 정수
  엔디안(0=big, 1=little)을 판별해 길이/UUID 디코딩에 반영한다(MS 트래픽은
  대개 little-endian, ``0x10``).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

__all__ = [
    "DCERPC_EPM_PORT",
    "PTYPE_NAMES",
    "ptype_name",
    "KNOWN_INTERFACES",
    "interface_info",
    "PresentationContext",
    "DceRpcPdu",
    "parse_pdu",
]

DCERPC_EPM_PORT = 135  # 엔드포인트 매퍼(동적 포트 정찰).

_HEADER_SIZE = 16
_RPC_VERSION = 5  # DCE/RPC v5 (MSRPC). v4 는 connectionless(미지원).
_SYNTAX_ID_SIZE = 20  # UUID(16) + version(major 2 + minor 2).

# PDU type(ptype) — DCE 1.1 §12.6, 관심 값.
PT_REQUEST = 0
PT_PING = 1
PT_RESPONSE = 2
PT_FAULT = 3
PT_BIND = 11
PT_BIND_ACK = 12
PT_BIND_NAK = 13
PT_ALTER_CONTEXT = 14
PT_ALTER_CONTEXT_RESP = 15
PT_AUTH3 = 16
PT_SHUTDOWN = 17
PT_CO_CANCEL = 18
PT_ORPHANED = 19

PTYPE_NAMES = {
    PT_REQUEST: "request",
    PT_PING: "ping",
    PT_RESPONSE: "response",
    PT_FAULT: "fault",
    PT_BIND: "bind",
    PT_BIND_ACK: "bind_ack",
    PT_BIND_NAK: "bind_nak",
    PT_ALTER_CONTEXT: "alter_context",
    PT_ALTER_CONTEXT_RESP: "alter_context_resp",
    PT_AUTH3: "auth3",
    PT_SHUTDOWN: "shutdown",
    PT_CO_CANCEL: "co_cancel",
    PT_ORPHANED: "orphaned",
}
_KNOWN_PTYPES = frozenset(PTYPE_NAMES)

# pfc_flags(DCE 1.1 §12.6.3.1).
PFC_FIRST_FRAG = 0x01
PFC_LAST_FRAG = 0x02
PFC_PENDING_CANCEL = 0x04
PFC_CONC_MPX = 0x10
PFC_DID_NOT_EXECUTE = 0x20
PFC_OBJECT_UUID = 0x80

# 알려진 RPC 인터페이스 UUID → (이름, 공격/포렌식 노트).
# UUID 는 표준 문자열 형식(소문자). MS-RPCE 인터페이스 식별자.
KNOWN_INTERFACES = {
    "e3514235-4b06-11d1-ab04-00c04fc2dcd2": (
        "DRSUAPI", "디렉터리 복제 — DRSGetNCChanges(opnum 3)=DCSync 자격증명 탈취"),
    "367abb81-9844-35f1-ad32-98f038001003": (
        "SVCCTL", "서비스 제어 — 원격 서비스 생성/실행=PsExec·측면 이동"),
    "1ff70682-0a51-30e8-076d-740be8cee98b": (
        "ATSVC", "작업 스케줄러(AT) — 원격 작업 등록 실행"),
    "86d35949-83c9-4044-b424-db363231fd0c": (
        "ITaskSchedulerService", "작업 스케줄러(schtasks) — 원격 실행·지속성"),
    "12345778-1234-abcd-ef00-0123456789ac": (
        "SAMR", "계정 관리자 — 사용자/그룹/SID 열거(rpcclient·BloodHound)"),
    "12345778-1234-abcd-ef00-0123456789ab": (
        "LSARPC", "로컬 보안 정책 — SID·정책·신뢰 열거(lsadump)"),
    "338cd001-2244-31f1-aaaa-900038001003": (
        "WINREG", "원격 레지스트리 — SAM/SECURITY 하이브 원격 덤프"),
    "4b324fc8-1670-01d3-1278-5a47bf6ee188": (
        "SRVSVC", "서버 서비스 — 공유/세션 열거(net view)"),
    "6bffd098-a112-3610-9833-46c3f87e345a": (
        "WKSSVC", "워크스테이션 서비스 — 호스트 정보·세션 열거"),
    "12345678-1234-abcd-ef00-0123456789ab": (
        "SPOOLSS", "프린트 스풀러(MS-RPRN) — PrintNightmare(CVE-2021-34527) 강제"),
    "c681d488-d850-11d0-8c52-00c04fd90f7e": (
        "EFSRPC", "암호화 파일 시스템(MS-EFSR) — PetitPotam 인증 강제 릴레이"),
    "df1941c5-fe89-4e79-bf10-463657acf44d": (
        "EFSRPC", "암호화 파일 시스템(MS-EFSR, lsarpc 별칭) — PetitPotam 코어션"),
    "e1af8308-5d1f-11c9-91a4-08002b14a0fa": (
        "EPM", "엔드포인트 매퍼 — 동적 포트 정찰(135)"),
    "99fcfec4-5260-101b-bbcb-00aa0021347a": (
        "IOXIDResolver", "DCOM OXID resolver(MS-DCOM) — 인증 강제 코어션 벡터"),
    "8a885d04-1ceb-11c9-9fe8-08002b104860": (
        "NDR", "전송 구문(NDR) — abstract 가 아닌 transfer syntax 표지"),
}

# transfer syntax 로 흔히 쓰이는 식별자(abstract 인터페이스가 아님 — 노트용).
TRANSFER_SYNTAX_NDR = "8a885d04-1ceb-11c9-9fe8-08002b104860"
TRANSFER_SYNTAX_NDR64 = "71710533-beba-4937-8319-b5dbef9ccc36"
TRANSFER_SYNTAX_BIND_TIME = "6cb71c2c-9812-4540-0300-000000000000"  # bind-time feature negotiation


def ptype_name(ptype: int) -> str:
    """PDU type 번호를 사람이 읽는 이름으로(미상이면 ``ptype-<n>``)."""
    return PTYPE_NAMES.get(ptype, "ptype-%d" % ptype)


def interface_info(uuid: str):
    """인터페이스 UUID(문자열)에 대응하는 ``(이름, 노트)`` 또는 None."""
    return KNOWN_INTERFACES.get(uuid.lower())


def _u16(data: bytes, pos: int, little: bool) -> Optional[int]:
    if pos + 2 > len(data):
        return None
    return int.from_bytes(data[pos:pos + 2], "little" if little else "big")


def _u32(data: bytes, pos: int, little: bool) -> Optional[int]:
    if pos + 4 > len(data):
        return None
    return int.from_bytes(data[pos:pos + 4], "little" if little else "big")


def _format_uuid(raw: bytes, little: bool) -> str:
    """16바이트 RPC UUID 를 표준 문자열로.

    앞 세 필드(uint32·uint16·uint16)는 DREP 엔디안을 따르고, 뒤 8바이트는
    바이트 배열 그대로다(DCE 1.1 UUID 표현).
    """
    order = "little" if little else "big"
    d1 = int.from_bytes(raw[0:4], order)
    d2 = int.from_bytes(raw[4:6], order)
    d3 = int.from_bytes(raw[6:8], order)
    d4 = raw[8:10].hex()
    d5 = raw[10:16].hex()
    return "%08x-%04x-%04x-%s-%s" % (d1, d2, d3, d4, d5)


@dataclass(frozen=True)
class PresentationContext:
    """BIND PDU 의 제시 컨텍스트 한 건.

    Attributes:
        context_id: p_cont_id(컨텍스트 식별자).
        abstract_uuid: abstract syntax 인터페이스 UUID(문자열). 미상이면 None.
        abstract_version: ``"major.minor"`` 인터페이스 버전. 없으면 None.
        interface_name: 알려진 인터페이스 이름(KNOWN_INTERFACES). 미상이면 None.
        attack_note: 알려진 인터페이스의 공격/포렌식 노트. 없으면 None.
        transfer_uuids: 제시한 transfer syntax UUID 목록(NDR/NDR64 등).
    """

    context_id: int
    abstract_uuid: Optional[str] = None
    abstract_version: Optional[str] = None
    interface_name: Optional[str] = None
    attack_note: Optional[str] = None
    transfer_uuids: List[str] = field(default_factory=list)


@dataclass(frozen=True)
class DceRpcPdu:
    """파싱된 DCE/RPC PDU 한 건.

    Attributes:
        ptype: PDU type 번호.
        ptype_name: PDU type 이름(``bind``·``request`` 등).
        version: RPC 메이저 버전(5).
        version_minor: RPC 마이너 버전.
        is_little_endian: packed_drep 정수 엔디안이 little 이면 True.
        pfc_flags: PFC_* 플래그 비트.
        is_first_frag / is_last_frag: 단편화 플래그.
        frag_length: 이 단편의 전체 길이(헤더+본문).
        auth_length: 인증 verifier 길이(있으면 보안 컨텍스트 협상).
        call_id: 호출 식별자(요청↔응답 상관).
        contexts: BIND/ALTER_CONTEXT 의 제시 컨텍스트 목록.
        opnum: REQUEST 의 연산 번호(opnum). 그 외 None.
        context_id: REQUEST 의 컨텍스트 식별자. 그 외 None.
        nak_reason: BIND_NAK 의 거부 사유 코드. 그 외 None.
    """

    ptype: int
    ptype_name: str
    version: int
    version_minor: int
    is_little_endian: bool
    pfc_flags: int
    frag_length: int
    auth_length: int
    call_id: int
    contexts: List[PresentationContext] = field(default_factory=list)
    opnum: Optional[int] = None
    context_id: Optional[int] = None
    nak_reason: Optional[int] = None

    @property
    def is_first_frag(self) -> bool:
        return bool(self.pfc_flags & PFC_FIRST_FRAG)

    @property
    def is_last_frag(self) -> bool:
        return bool(self.pfc_flags & PFC_LAST_FRAG)

    @property
    def is_bind(self) -> bool:
        return self.ptype in (PT_BIND, PT_ALTER_CONTEXT)

    @property
    def bound_interfaces(self) -> List[str]:
        """BIND 컨텍스트 중 알려진 인터페이스 이름 목록(중복 제거, 순서 유지)."""
        seen: List[str] = []
        for ctx in self.contexts:
            if ctx.interface_name and ctx.interface_name not in seen:
                seen.append(ctx.interface_name)
        return seen


def _parse_bind_contexts(data: bytes, pos: int, little: bool) -> List[PresentationContext]:
    """BIND/ALTER_CONTEXT 본문의 p_context_elem 목록을 파싱.

    레이아웃: max_xmit_frag(2) max_recv_frag(2) assoc_group_id(4)
    그 뒤 p_cont_list_t: n_context_elem(1) reserved(1) reserved2(2)
    이어 각 p_cont_elem_t.
    """
    contexts: List[PresentationContext] = []
    # max_xmit_frag(2) + max_recv_frag(2) + assoc_group_id(4) = 8 바이트.
    pos += 8
    if pos + 4 > len(data):
        return contexts
    n_ctx = data[pos]
    pos += 4  # n_context_elem(1) + reserved(1) + reserved2(2).
    for _ in range(n_ctx):
        # p_cont_id(2) n_transfer_syn(1) reserved(1).
        cid = _u16(data, pos, little)
        if cid is None:
            break
        if pos + 4 > len(data):
            break
        n_transfer = data[pos + 2]
        pos += 4
        # abstract_syntax: UUID(16) + version(4).
        if pos + _SYNTAX_ID_SIZE > len(data):
            break
        abs_uuid = _format_uuid(data[pos:pos + 16], little)
        ver_major = int.from_bytes(data[pos + 16:pos + 18], "little" if little else "big")
        ver_minor = int.from_bytes(data[pos + 18:pos + 20], "little" if little else "big")
        pos += _SYNTAX_ID_SIZE
        info = KNOWN_INTERFACES.get(abs_uuid)
        # transfer syntaxes: n_transfer × syntax_id(20).
        transfers: List[str] = []
        for _t in range(n_transfer):
            if pos + _SYNTAX_ID_SIZE > len(data):
                break
            transfers.append(_format_uuid(data[pos:pos + 16], little))
            pos += _SYNTAX_ID_SIZE
        contexts.append(PresentationContext(
            context_id=cid,
            abstract_uuid=abs_uuid,
            abstract_version="%d.%d" % (ver_major, ver_minor),
            interface_name=info[0] if info else None,
            attack_note=info[1] if info else None,
            transfer_uuids=transfers,
        ))
    return contexts


def parse_pdu(data: bytes, offset: int = 0) -> Optional[DceRpcPdu]:
    """DCE/RPC PDU 한 건을 파싱한다.

    Args:
        data: PDU 가 시작되는 바이트열(SMB named pipe write 본문 또는 TCP
            페이로드). 첫 단편의 시작이어야 한다.
        offset: ``data`` 안에서 PDU 가 시작되는 위치.

    Returns:
        파싱된 :class:`DceRpcPdu`, 또는 DCE/RPC v5 PDU 가 아니거나 헤더가
        너무 짧으면 None. 본문(컨텍스트 목록 등)이 잘렸으면 읽은 만큼만 채운다.
    """
    if offset < 0 or offset + _HEADER_SIZE > len(data):
        return None
    p = offset
    version = data[p]
    version_minor = data[p + 1]
    if version != _RPC_VERSION:
        return None  # connection-oriented MSRPC v5 만 인정(오탐 방지).
    ptype = data[p + 2]
    if ptype not in _KNOWN_PTYPES:
        return None  # 알려진 PDU type 만(오탐 방지).
    pfc_flags = data[p + 3]
    drep0 = data[p + 4]  # packed_drep 첫 옥텟: 상위 4비트=정수 엔디안.
    little = (drep0 >> 4) == 1
    # drep[1:4] 는 부동소수점/문자 표현 — 여기선 미사용.
    frag_length = int.from_bytes(data[p + 8:p + 10], "little" if little else "big")
    auth_length = int.from_bytes(data[p + 10:p + 12], "little" if little else "big")
    call_id = int.from_bytes(data[p + 12:p + 16], "little" if little else "big")

    body = p + _HEADER_SIZE
    contexts: List[PresentationContext] = []
    opnum: Optional[int] = None
    context_id: Optional[int] = None
    nak_reason: Optional[int] = None

    if ptype in (PT_BIND, PT_ALTER_CONTEXT):
        contexts = _parse_bind_contexts(data, body, little)
    elif ptype == PT_REQUEST:
        # alloc_hint(4) p_cont_id(2) opnum(2) [object UUID(16) if PFC_OBJECT_UUID].
        context_id = _u16(data, body + 4, little)
        opnum = _u16(data, body + 6, little)
    elif ptype == PT_BIND_NAK:
        # provider_reject_reason(2).
        nak_reason = _u16(data, body, little)

    return DceRpcPdu(
        ptype=ptype,
        ptype_name=ptype_name(ptype),
        version=version,
        version_minor=version_minor,
        is_little_endian=little,
        pfc_flags=pfc_flags,
        frag_length=frag_length,
        auth_length=auth_length,
        call_id=call_id,
        contexts=contexts,
        opnum=opnum,
        context_id=context_id,
        nak_reason=nak_reason,
    )
