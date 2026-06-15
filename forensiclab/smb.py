"""SMB — SMB1/SMB2 메시지 파싱 코어 (MS-SMB2; 순수 stdlib).

:mod:`forensiclab.netdissect` 가 식별한 TCP 445(직접 SMB) 또는 139
(NetBIOS 세션) 페이로드는 SMB 메시지일 수 있다. 이 모듈이 그 메시지를
해석한다. LDAP(389)·Kerberos(88)·**SMB(445)** 는 Active Directory 공격면의
형제다 — LDAP 가 디렉터리 질의, Kerberos 가 티켓 발급(인증)이라면 SMB 는
**파일/관리 공유 접근·원격 명령 실행(PsExec)·NTLM 인증** 그 자체라
측면 이동(lateral movement) 분석의 핵심이다.

SMB 직접 전송(TCP 445)은 4바이트 전송 헤더(``0x00`` + 3바이트 big-endian
길이) 뒤에 SMB 메시지가 온다. 메시지 첫 4바이트로 버전을 가른다:

- ``\\xffSMB`` (0xFF 'S' 'M' 'B') — **SMB1**. 레거시 프로토콜로 EternalBlue
  (MS17-010, WannaCry/NotPetya) 의 무대다. 2020년대 트래픽에서 SMB1 협상
  자체가 강한 침해/취약 정황(다운그레이드 포함).
- ``\\xfeSMB`` (0xFE 'S' 'M' 'B') — **SMB2/3**. 64바이트 헤더(little-endian).

SMB2 헤더(MS-SMB2 §2.2.1.2, 64바이트):
ProtocolId[4] StructureSize[2]=64 CreditCharge[2] Status[4] Command[2]
Credits[2] Flags[4] NextCommand[4] MessageId[8] Reserved/AsyncId[4]
TreeId/AsyncId[4] SessionId[8] Signature[16].

침해/사고 분석 단서:

- **SMB1 사용**: ``\\xffSMB`` 자체가 레거시·EternalBlue 표적 정황.
- **서명 미요구(NTLM relay)**: NEGOTIATE 의 ``SecurityMode`` 에
  SIGNING_REQUIRED(0x0002) 비트가 없으면 SMB 서명 강제가 아니라
  **NTLM 릴레이**(ntlmrelayx) 가 가능한 구성. SMB2 다이얼렉트 목록에
  0x0202/0x0210(구버전)·0x02FF(SMB1 협상 폴백) 이 끼면 다운그레이드 정황.
- **NTLM 인증 귀속**: SESSION_SETUP 보안 블롭의 ``NTLMSSP`` 메시지에서
  AUTHENTICATE(타입 3) 의 도메인/사용자/워크스테이션을 평문으로 뽑아
  흐름을 AD 계정에 연결한다(Kerberos cname·LDAP bind DN 대응).
- **공유 접근(측면 이동)**: TREE_CONNECT 의 경로 ``\\\\host\\IPC$`` /
  ``ADMIN$`` / ``C$`` 는 PsExec·원격 서비스 제어·관리 공유 정찰의 표적.

설계 원칙(:mod:`forensiclab.kerberos`·:mod:`forensiclab.ldap` 와 동일):
- 부작용 없음: 순수 함수. 디스크/표준출력/네트워크 없음.
- stdlib 전용.
- 안전: 입력 바이트를 변형하지 않는다(읽기 전용).
- 견고: 너무 짧거나 망가진 입력은 예외 대신 ``None``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

__all__ = [
    "SMB1_MAGIC",
    "SMB2_MAGIC",
    "CMD_NEGOTIATE",
    "CMD_SESSION_SETUP",
    "CMD_LOGOFF",
    "CMD_TREE_CONNECT",
    "CMD_CREATE",
    "CMD_READ",
    "CMD_WRITE",
    "CMD_IOCTL",
    "FLAGS_SERVER_TO_REDIR",
    "SIGNING_ENABLED",
    "SIGNING_REQUIRED",
    "DIALECT_SMB1_FALLBACK",
    "DIALECT_2_0_2",
    "DIALECT_2_1",
    "DIALECT_3_0",
    "DIALECT_3_0_2",
    "DIALECT_3_1_1",
    "OLD_DIALECTS",
    "NTLM_NEGOTIATE",
    "NTLM_CHALLENGE",
    "NTLM_AUTHENTICATE",
    "SMBMessage",
    "parse_smb",
]

# 프로토콜 식별 매직(첫 4바이트).
SMB1_MAGIC = b"\xffSMB"
SMB2_MAGIC = b"\xfeSMB"

# SMB2 Command(MS-SMB2 §2.2.1.2) — 관심 값만.
CMD_NEGOTIATE = 0x0000
CMD_SESSION_SETUP = 0x0001
CMD_LOGOFF = 0x0002
CMD_TREE_CONNECT = 0x0003
CMD_TREE_DISCONNECT = 0x0004
CMD_CREATE = 0x0005
CMD_CLOSE = 0x0006
CMD_READ = 0x0008
CMD_WRITE = 0x0009
CMD_IOCTL = 0x000B
CMD_QUERY_DIRECTORY = 0x000E
CMD_QUERY_INFO = 0x0010

_CMD_NAMES = {
    CMD_NEGOTIATE: "NEGOTIATE",
    CMD_SESSION_SETUP: "SESSION_SETUP",
    CMD_LOGOFF: "LOGOFF",
    CMD_TREE_CONNECT: "TREE_CONNECT",
    CMD_TREE_DISCONNECT: "TREE_DISCONNECT",
    CMD_CREATE: "CREATE",
    CMD_CLOSE: "CLOSE",
    CMD_READ: "READ",
    CMD_WRITE: "WRITE",
    CMD_IOCTL: "IOCTL",
    CMD_QUERY_DIRECTORY: "QUERY_DIRECTORY",
    CMD_QUERY_INFO: "QUERY_INFO",
}
_KNOWN_CMDS = frozenset(_CMD_NAMES)

# SMB2 헤더 Flags(MS-SMB2 §2.2.1.2).
FLAGS_SERVER_TO_REDIR = 0x00000001  # 응답(서버→클라이언트).

# SecurityMode 비트(NEGOTIATE) — SMB 서명 정책.
SIGNING_ENABLED = 0x0001
SIGNING_REQUIRED = 0x0002

# SMB2 Dialect revision(MS-SMB2 §2.2.3).
DIALECT_SMB1_FALLBACK = 0x02FF  # SMB1 NEGOTIATE 의 SMB2 폴백 와일드카드.
DIALECT_2_0_2 = 0x0202
DIALECT_2_1 = 0x0210
DIALECT_3_0 = 0x0300
DIALECT_3_0_2 = 0x0302
DIALECT_3_1_1 = 0x0311

_DIALECT_NAMES = {
    DIALECT_SMB1_FALLBACK: "SMB1-fallback",
    DIALECT_2_0_2: "2.0.2",
    DIALECT_2_1: "2.1",
    DIALECT_3_0: "3.0",
    DIALECT_3_0_2: "3.0.2",
    DIALECT_3_1_1: "3.1.1",
}
# 구버전 다이얼렉트(서명·암호화 약함, 다운그레이드 정황).
OLD_DIALECTS = frozenset({DIALECT_SMB1_FALLBACK, DIALECT_2_0_2, DIALECT_2_1})

# NTLMSSP 메시지 타입(MS-NLMP).
_NTLMSSP_SIG = b"NTLMSSP\x00"
NTLM_NEGOTIATE = 1
NTLM_CHALLENGE = 2
NTLM_AUTHENTICATE = 3

# NTLM NegotiateFlags — 문자열 인코딩(MS-NLMP §2.2.2.5).
_NTLMSSP_NEGOTIATE_UNICODE = 0x00000001

# 관리/은닉 공유 — 측면 이동·PsExec 표적.
_ADMIN_SHARES = frozenset({"ADMIN$", "C$", "IPC$"})

_SMB2_HEADER_LEN = 64


def _u16(data: bytes, pos: int) -> Optional[int]:
    if pos + 2 > len(data):
        return None
    return int.from_bytes(data[pos:pos + 2], "little")


def _u32(data: bytes, pos: int) -> Optional[int]:
    if pos + 4 > len(data):
        return None
    return int.from_bytes(data[pos:pos + 4], "little")


def _u64(data: bytes, pos: int) -> Optional[int]:
    if pos + 8 > len(data):
        return None
    return int.from_bytes(data[pos:pos + 8], "little")


def _utf16(value: bytes) -> str:
    """UTF-16LE 바이트를 문자열로(읽을 수 있는 만큼)."""
    try:
        return value.decode("utf-16-le")
    except UnicodeDecodeError:
        return value.decode("latin-1", "replace")


@dataclass(frozen=True)
class SMBMessage:
    """파싱된 SMB 메시지 한 건.

    Attributes:
        dialect: "SMB1" 또는 "SMB2"(프로토콜 매직 기준).
        command: SMB2 Command(또는 SMB1 첫 명령 바이트).
        is_response: 응답(서버→클라이언트)이면 True.
        status: SMB2 헤더 Status(NT 상태 코드). 미상이면 None.
        message_id: SMB2 MessageId. SMB1 은 None.
        session_id: SMB2 SessionId. SMB1 은 None.
        tree_id: SMB2 TreeId. SMB1/async 는 None.
        dialects: NEGOTIATE 요청이 제시한 SMB2 다이얼렉트 목록.
        security_mode: NEGOTIATE 의 SecurityMode 비트. 없으면 None.
        ntlm_message_type: SESSION_SETUP 보안 블롭의 NTLMSSP 타입(1/2/3).
        ntlm_domain: NTLM AUTHENTICATE 의 도메인. 없으면 None.
        ntlm_user: NTLM AUTHENTICATE 의 사용자명. 없으면 None.
        ntlm_workstation: NTLM AUTHENTICATE 의 워크스테이션. 없으면 None.
        tree_path: TREE_CONNECT 요청의 공유 경로(``\\\\host\\share``).
    """

    dialect: str
    command: int
    is_response: bool = False
    status: Optional[int] = None
    message_id: Optional[int] = None
    session_id: Optional[int] = None
    tree_id: Optional[int] = None
    dialects: List[int] = field(default_factory=list)
    security_mode: Optional[int] = None
    ntlm_message_type: Optional[int] = None
    ntlm_domain: Optional[str] = None
    ntlm_user: Optional[str] = None
    ntlm_workstation: Optional[str] = None
    tree_path: Optional[str] = None

    @property
    def is_smb1(self) -> bool:
        """레거시 SMB1 메시지인지 — EternalBlue·다운그레이드 정황."""
        return self.dialect == "SMB1"

    @property
    def command_name(self) -> str:
        """SMB2 Command 의 사람이 읽는 이름(미상이면 ``"cmd-0xNN"``)."""
        if self.is_smb1:
            return f"smb1-0x{self.command:02x}"
        return _CMD_NAMES.get(self.command, f"cmd-0x{self.command:04x}")

    @property
    def is_negotiate(self) -> bool:
        return not self.is_smb1 and self.command == CMD_NEGOTIATE

    @property
    def is_session_setup(self) -> bool:
        return not self.is_smb1 and self.command == CMD_SESSION_SETUP

    @property
    def is_tree_connect(self) -> bool:
        return not self.is_smb1 and self.command == CMD_TREE_CONNECT

    @property
    def dialect_names(self) -> List[str]:
        """제시된 다이얼렉트의 사람이 읽는 이름 목록."""
        return [_DIALECT_NAMES.get(d, f"0x{d:04x}") for d in self.dialects]

    @property
    def offers_old_dialects(self) -> List[int]:
        """제시된 다이얼렉트 중 구버전(다운그레이드 정황)만."""
        return [d for d in self.dialects if d in OLD_DIALECTS]

    @property
    def signing_required(self) -> Optional[bool]:
        """SMB 서명 강제 여부. None 이면 알 수 없음(NEGOTIATE 아님)."""
        if self.security_mode is None:
            return None
        return bool(self.security_mode & SIGNING_REQUIRED)

    @property
    def signing_not_required(self) -> bool:
        """NEGOTIATE 인데 서명 미강제 — NTLM 릴레이 가능 구성."""
        return self.signing_required is False

    @property
    def is_ntlm_authenticate(self) -> bool:
        """NTLMSSP AUTHENTICATE(타입 3) — 자격증명 응답 귀속 표적."""
        return self.ntlm_message_type == NTLM_AUTHENTICATE

    @property
    def ntlm_account(self) -> Optional[str]:
        """NTLM 인증 주체를 ``DOMAIN\\user`` 로(있는 만큼)."""
        if self.ntlm_user is None:
            return None
        if self.ntlm_domain:
            return f"{self.ntlm_domain}\\{self.ntlm_user}"
        return self.ntlm_user

    @property
    def target_share(self) -> Optional[str]:
        """TREE_CONNECT 경로의 마지막 구성요소(공유명)."""
        if not self.tree_path:
            return None
        return self.tree_path.rstrip("\\").rsplit("\\", 1)[-1]

    @property
    def is_admin_share(self) -> bool:
        """관리/은닉 공유(ADMIN$/C$/IPC$) 접근 — 측면 이동·PsExec 정황."""
        share = self.target_share
        return bool(share) and share.upper() in _ADMIN_SHARES


def _parse_negotiate_request(body: bytes) -> dict:
    """SMB2 NEGOTIATE 요청 본문에서 다이얼렉트·SecurityMode 추출.

    NEGOTIATE Request(MS-SMB2 §2.2.3): StructureSize[2]=36 DialectCount[2]
    SecurityMode[2] Reserved[2] Capabilities[4] ClientGuid[16]
    NegotiateContext...[8] Dialects[2*DialectCount].
    """
    out: dict = {}
    count = _u16(body, 2)
    sec = _u16(body, 4)
    if sec is not None:
        out["security_mode"] = sec
    if count is None:
        return out
    # Dialects 는 본문 오프셋 36(헤더 제외 본문 기준)부터.
    dialects: List[int] = []
    pos = 36
    for _ in range(min(count, 64)):  # 비정상적으로 큰 count 방지.
        d = _u16(body, pos)
        if d is None:
            break
        dialects.append(d)
        pos += 2
    out["dialects"] = dialects
    return out


def _parse_negotiate_response(body: bytes) -> dict:
    """SMB2 NEGOTIATE 응답 본문에서 SecurityMode·선택 다이얼렉트 추출.

    NEGOTIATE Response(MS-SMB2 §2.2.4): StructureSize[2]=65 SecurityMode[2]
    DialectRevision[2] ...
    """
    out: dict = {}
    sec = _u16(body, 2)
    if sec is not None:
        out["security_mode"] = sec
    rev = _u16(body, 4)
    if rev is not None:
        out["dialects"] = [rev]
    return out


def _parse_tree_connect_request(data: bytes, hdr: int, body: bytes) -> dict:
    """SMB2 TREE_CONNECT 요청 본문에서 공유 경로 추출.

    TREE_CONNECT Request(MS-SMB2 §2.2.9): StructureSize[2]=9 Flags/Reserved[2]
    PathOffset[2] PathLength[2] Buffer. PathOffset 은 SMB2 헤더 시작 기준.
    """
    poff = _u16(body, 4)
    plen = _u16(body, 6)
    if poff is None or plen is None or plen == 0:
        return {}
    start = hdr + poff
    end = start + plen
    if end > len(data):
        end = len(data)
    if start >= end:
        return {}
    return {"tree_path": _utf16(data[start:end])}


def _ntlm_field(blob: bytes, pos: int) -> Optional[bytes]:
    """NTLM 가변필드(len[2] maxlen[2] offset[4])가 가리키는 바이트.

    offset 은 NTLMSSP 메시지 시작 기준. 범위 밖이면 None.
    """
    ln = _u16(blob, pos)
    off = _u32(blob, pos + 4)
    if ln is None or off is None or ln == 0:
        return None
    if off + ln > len(blob):
        return None
    return blob[off:off + ln]


def _parse_ntlmssp(blob: bytes) -> dict:
    """NTLMSSP 메시지에서 타입과(AUTHENTICATE 면) 주체 정보를 뽑는다.

    blob 은 ``NTLMSSP\\x00`` 으로 시작하는 메시지. AUTHENTICATE(타입 3)
    구조(MS-NLMP §2.2.1.3): Signature[8] MessageType[4]
    LmChallengeResponse[8] NtChallengeResponse[8] DomainName[8] UserName[8]
    Workstation[8] EncryptedRandomSessionKey[8] NegotiateFlags[4] ...
    각 8바이트 필드는 len[2] maxlen[2] offset[4]. 문자열은 UNICODE 플래그면
    UTF-16LE, 아니면 OEM(latin-1).
    """
    mtype = _u32(blob, 8)
    if mtype is None:
        return {}
    out: dict = {"ntlm_message_type": mtype}
    if mtype != NTLM_AUTHENTICATE:
        return out
    domain = _ntlm_field(blob, 28)
    user = _ntlm_field(blob, 36)
    workstation = _ntlm_field(blob, 44)
    flags = _u32(blob, 60)
    unicode_on = flags is None or bool(flags & _NTLMSSP_NEGOTIATE_UNICODE)

    def _dec(raw: Optional[bytes]) -> Optional[str]:
        if raw is None:
            return None
        return _utf16(raw) if unicode_on else raw.decode("latin-1", "replace")

    out["ntlm_domain"] = _dec(domain)
    out["ntlm_user"] = _dec(user)
    out["ntlm_workstation"] = _dec(workstation)
    return out


def _parse_session_setup(data: bytes, hdr: int, body: bytes) -> dict:
    """SMB2 SESSION_SETUP 보안 블롭에서 NTLMSSP 메시지를 찾아 파싱.

    SESSION_SETUP Request(MS-SMB2 §2.2.5)/Response(§2.2.6) 모두
    SecurityBufferOffset[+12 or +8] 로 GSS-API 블롭을 가리킨다. SPNEGO
    래핑을 완전 해석하는 대신, 블롭(없으면 전체 메시지)에서 ``NTLMSSP\\x00``
    시그니처를 찾아 그 지점부터 NTLMSSP 를 파싱한다(실무 도구 관례).
    """
    # 요청: SecurityBufferOffset[12] Length[14]. 응답: Offset[4] Length[6].
    blob = b""
    for off_pos, len_pos in ((12, 14), (4, 6)):
        soff = _u16(body, off_pos)
        slen = _u16(body, len_pos)
        if soff and slen:
            start = hdr + soff
            end = min(start + slen, len(data))
            if 0 <= start < end:
                blob = data[start:end]
                break
    search = blob if blob else data[hdr:]
    idx = search.find(_NTLMSSP_SIG)
    if idx < 0:
        return {}
    return _parse_ntlmssp(search[idx:])


def _strip_transport(data: bytes, offset: int) -> int:
    """직접 SMB(TCP 445) 4바이트 전송 헤더가 있으면 건너뛴 시작 위치 반환.

    전송 헤더는 ``0x00`` + 3바이트 big-endian 길이다. 그 뒤가 SMB 매직이면
    건너뛰고, 아니면 원래 offset 을 그대로 둔다.
    """
    if offset + 4 <= len(data) and data[offset] == 0x00:
        nxt = offset + 4
        if data[nxt:nxt + 4] in (SMB1_MAGIC, SMB2_MAGIC):
            return nxt
    return offset


def parse_smb(data: bytes, offset: int = 0) -> Optional[SMBMessage]:
    """원시 바이트에서 SMB 메시지 한 건을 파싱한다.

    Args:
        data: SMB 페이로드를 담은 바이트. 보통 TCP 445/139 페이로드
            (:class:`forensiclab.netdissect` 의 ``payload_offset`` 부터)다.
            직접 SMB(445) 4바이트 전송 헤더는 자동으로 건너뛴다.
        offset: 메시지가 시작하는 위치(기본 0).

    Returns:
        :class:`SMBMessage`. 첫 4바이트가 SMB1/SMB2 매직이 아니거나
        SMB2 Command 가 알려지지 않았으면 ``None``.
    """
    if offset < 0 or offset >= len(data):
        return None
    start = _strip_transport(data, offset)
    magic = data[start:start + 4]

    if magic == SMB1_MAGIC:
        # SMB1: 매직[4] Command[1] 만 가볍게 뽑는다(레거시 정황 표시).
        if start + 5 > len(data):
            return SMBMessage(dialect="SMB1", command=-1)
        return SMBMessage(dialect="SMB1", command=data[start + 4])

    if magic != SMB2_MAGIC:
        return None
    if start + _SMB2_HEADER_LEN > len(data):
        return None

    command = _u16(data, start + 12)
    if command is None or command not in _KNOWN_CMDS:
        return None
    status = _u32(data, start + 8)
    flags = _u32(data, start + 16)
    message_id = _u64(data, start + 24)
    session_id = _u64(data, start + 40)
    is_response = bool(flags is not None and flags & FLAGS_SERVER_TO_REDIR)

    # TreeId 는 sync 헤더에서만 유효(async 플래그면 AsyncId 와 겹침).
    tree_id = _u32(data, start + 36)

    body = data[start + _SMB2_HEADER_LEN:]
    extra: dict = {}
    if command == CMD_NEGOTIATE:
        extra = (
            _parse_negotiate_response(body)
            if is_response
            else _parse_negotiate_request(body)
        )
    elif command == CMD_SESSION_SETUP:
        extra = _parse_session_setup(data, start, body)
    elif command == CMD_TREE_CONNECT and not is_response:
        extra = _parse_tree_connect_request(data, start, body)

    return SMBMessage(
        dialect="SMB2",
        command=command,
        is_response=is_response,
        status=status,
        message_id=message_id,
        session_id=session_id,
        tree_id=tree_id,
        **extra,
    )
