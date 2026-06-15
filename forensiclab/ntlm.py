"""NTLM — NTLMSSP 메시지 파싱 코어 (MS-NLMP; 순수 stdlib).

NTLMSSP(NTLM Security Support Provider) 는 한 전송(transport)에 매이지 않은
**자격증명 인증 메커니즘**이다. SMB(:mod:`forensiclab.smb` SESSION_SETUP)·
DCE/RPC(:mod:`forensiclab.dcerpc` auth verifier)·HTTP(``Authorization:
NTLM ...`` / ``WWW-Authenticate: NTLM ...``)·LDAP·HTTP 프록시 등 어디에나
같은 ``NTLMSSP\\x00`` 메시지가 실려 흐른다. :mod:`forensiclab.smb` 가
SESSION_SETUP 안에서 가볍게 도메인/사용자만 뽑았다면, 이 모듈은 그 NTLMSSP
메시지 **자체**를 전송과 무관하게 독립적으로 해석한다 — Kerberos 가 막혔거나
다운그레이드된 환경에서 실제로 오가는 인증 흔적이다.

NTLM 인증은 3-메시지 챌린지-응답이다:

- **타입 1 NEGOTIATE**(클라이언트→서버): 협상할 NegotiateFlags 제시.
- **타입 2 CHALLENGE**(서버→클라이언트): 8바이트 **서버 챌린지**(nonce)·
  TargetName·TargetInfo(AV pair 목록: 도메인/서버/DNS 이름) 전달.
- **타입 3 AUTHENTICATE**(클라이언트→서버): 도메인\\사용자\\워크스테이션
  평문·LM/NT 챌린지 응답 전달. NT 응답이 곧 **오프라인 크래킹 표적**.

사고/침해 분석 단서:

- **자격증명 귀속**: AUTHENTICATE 의 domain/user/workstation 평문으로
  흐름을 AD 계정에 연결(Kerberos cname·LDAP bind DN·SMB ntlm_account 대응).
- **Net-NTLMv2 해시 추출**: CHALLENGE 의 서버 챌린지 + AUTHENTICATE 의
  NTProofStr·blob 을 합치면 hashcat ``-m 5600`` 으로 오프라인 크래킹
  가능한 ``user::domain:srvchal:ntproof:blob`` 문자열이 나온다
  (:func:`netntlmv2`). Responder/ntlmrelayx 가 노리는 바로 그 산출물.
- **NTLMv1 다운그레이드**: NT 응답이 24바이트면 NTLMv1(또는 빈 응답).
  취약한 DES 기반·``-m 5500`` 표적이며 NTLMv1 강제는 다운그레이드 정황.
- **서명/봉인 미협상**: NegotiateFlags 에 SIGN/SEAL 비트가 없으면
  릴레이·변조 방어가 약하다(:mod:`forensiclab.smb` signing 대응).
- **익명/널 인증**: AUTHENTICATE 에 user 가 비고 NT 응답이 없으면 널 세션.

설계 원칙(:mod:`forensiclab.smb`·:mod:`forensiclab.kerberos` 와 동일):
- 부작용 없음: 순수 함수. 디스크/표준출력/네트워크 없음.
- stdlib 전용.
- 안전: 입력 바이트를 변형하지 않는다(읽기 전용).
- 견고: 너무 짧거나 망가진 입력은 예외 대신 ``None``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

__all__ = [
    "NTLMSSP_SIG",
    "NTLM_NEGOTIATE",
    "NTLM_CHALLENGE",
    "NTLM_AUTHENTICATE",
    "NEGOTIATE_UNICODE",
    "NEGOTIATE_OEM",
    "NEGOTIATE_SIGN",
    "NEGOTIATE_SEAL",
    "NEGOTIATE_NTLM",
    "NEGOTIATE_EXTENDED_SESSIONSECURITY",
    "NEGOTIATE_TARGET_INFO",
    "NEGOTIATE_KEY_EXCH",
    "NEGOTIATE_VERSION",
    "AV_EOL",
    "AV_NB_COMPUTER_NAME",
    "AV_NB_DOMAIN_NAME",
    "AV_DNS_COMPUTER_NAME",
    "AV_DNS_DOMAIN_NAME",
    "AV_DNS_TREE_NAME",
    "AV_TIMESTAMP",
    "NTLMMessage",
    "parse_ntlm",
    "find_ntlm",
    "netntlmv2",
]

# NTLMSSP 메시지 시그니처(첫 8바이트).
NTLMSSP_SIG = b"NTLMSSP\x00"

# MessageType(MS-NLMP §2.2).
NTLM_NEGOTIATE = 1
NTLM_CHALLENGE = 2
NTLM_AUTHENTICATE = 3

_TYPE_NAMES = {
    NTLM_NEGOTIATE: "NEGOTIATE",
    NTLM_CHALLENGE: "CHALLENGE",
    NTLM_AUTHENTICATE: "AUTHENTICATE",
}
_KNOWN_TYPES = frozenset(_TYPE_NAMES)

# NegotiateFlags(MS-NLMP §2.2.2.5) — 관심 비트만.
NEGOTIATE_UNICODE = 0x00000001
NEGOTIATE_OEM = 0x00000002
NEGOTIATE_SIGN = 0x00000010
NEGOTIATE_SEAL = 0x00000020
NEGOTIATE_NTLM = 0x00000200
NEGOTIATE_TARGET_INFO = 0x00800000
NEGOTIATE_VERSION = 0x02000000
NEGOTIATE_KEY_EXCH = 0x40000000
NEGOTIATE_EXTENDED_SESSIONSECURITY = 0x00080000

_FLAG_NAMES = [
    (NEGOTIATE_UNICODE, "UNICODE"),
    (NEGOTIATE_OEM, "OEM"),
    (NEGOTIATE_SIGN, "SIGN"),
    (NEGOTIATE_SEAL, "SEAL"),
    (NEGOTIATE_NTLM, "NTLM"),
    (NEGOTIATE_EXTENDED_SESSIONSECURITY, "EXTENDED_SESSIONSECURITY"),
    (NEGOTIATE_TARGET_INFO, "TARGET_INFO"),
    (NEGOTIATE_VERSION, "VERSION"),
    (NEGOTIATE_KEY_EXCH, "KEY_EXCH"),
]

# TargetInfo AV pair AvId(MS-NLMP §2.2.2.1).
AV_EOL = 0x0000
AV_NB_COMPUTER_NAME = 0x0001
AV_NB_DOMAIN_NAME = 0x0002
AV_DNS_COMPUTER_NAME = 0x0003
AV_DNS_DOMAIN_NAME = 0x0004
AV_DNS_TREE_NAME = 0x0005
AV_TIMESTAMP = 0x0007

_AV_NAMES = {
    AV_NB_COMPUTER_NAME: "nb_computer",
    AV_NB_DOMAIN_NAME: "nb_domain",
    AV_DNS_COMPUTER_NAME: "dns_computer",
    AV_DNS_DOMAIN_NAME: "dns_domain",
    AV_DNS_TREE_NAME: "dns_tree",
}


def _u16(data: bytes, pos: int) -> Optional[int]:
    if pos < 0 or pos + 2 > len(data):
        return None
    return int.from_bytes(data[pos:pos + 2], "little")


def _u32(data: bytes, pos: int) -> Optional[int]:
    if pos < 0 or pos + 4 > len(data):
        return None
    return int.from_bytes(data[pos:pos + 4], "little")


def _field(blob: bytes, pos: int) -> Optional[bytes]:
    """NTLM 가변필드(len[2] maxlen[2] offset[4])가 가리키는 바이트.

    offset 은 NTLMSSP 메시지 시작 기준. 범위 밖/길이 0 이면 None.
    """
    ln = _u16(blob, pos)
    off = _u32(blob, pos + 4)
    if ln is None or off is None or ln == 0:
        return None
    if off < 0 or off + ln > len(blob):
        return None
    return blob[off:off + ln]


def _decode(raw: Optional[bytes], unicode_on: bool) -> Optional[str]:
    if raw is None:
        return None
    if unicode_on:
        try:
            return raw.decode("utf-16-le")
        except UnicodeDecodeError:
            return raw.decode("latin-1", "replace")
    return raw.decode("latin-1", "replace")


def _parse_av_pairs(blob: bytes) -> List[Tuple[int, bytes]]:
    """TargetInfo AV pair 목록(AvId[2] AvLen[2] Value[AvLen])을 푼다.

    AV_EOL(0) 에서 멈춘다. 잘리면 읽은 만큼.
    """
    pairs: List[Tuple[int, bytes]] = []
    pos = 0
    for _ in range(64):  # AV pair 폭주 방지.
        av_id = _u16(blob, pos)
        av_len = _u16(blob, pos + 2)
        if av_id is None or av_len is None:
            break
        if av_id == AV_EOL:
            break
        start = pos + 4
        end = start + av_len
        if end > len(blob):
            break
        pairs.append((av_id, blob[start:end]))
        pos = end
    return pairs


@dataclass(frozen=True)
class NTLMMessage:
    """파싱된 NTLMSSP 메시지 한 건.

    Attributes:
        message_type: 1 NEGOTIATE / 2 CHALLENGE / 3 AUTHENTICATE.
        negotiate_flags: NegotiateFlags(32비트). 없으면 None.
        server_challenge: CHALLENGE 의 8바이트 서버 nonce. 그 외 None.
        target_name: CHALLENGE 의 TargetName(보통 도메인/서버명).
        domain: AUTHENTICATE 의 DomainName.
        user: AUTHENTICATE 의 UserName.
        workstation: AUTHENTICATE 의 Workstation.
        lm_response: AUTHENTICATE 의 LmChallengeResponse 원바이트.
        nt_response: AUTHENTICATE 의 NtChallengeResponse 원바이트.
        target_info: CHALLENGE TargetInfo 의 AV pair (AvId, value) 목록.
    """

    message_type: int
    negotiate_flags: Optional[int] = None
    server_challenge: Optional[bytes] = None
    target_name: Optional[str] = None
    domain: Optional[str] = None
    user: Optional[str] = None
    workstation: Optional[str] = None
    lm_response: Optional[bytes] = None
    nt_response: Optional[bytes] = None
    target_info: List[Tuple[int, bytes]] = field(default_factory=list)

    @property
    def type_name(self) -> str:
        """메시지 타입의 사람이 읽는 이름."""
        return _TYPE_NAMES.get(self.message_type, f"type-{self.message_type}")

    @property
    def is_negotiate(self) -> bool:
        return self.message_type == NTLM_NEGOTIATE

    @property
    def is_challenge(self) -> bool:
        return self.message_type == NTLM_CHALLENGE

    @property
    def is_authenticate(self) -> bool:
        """AUTHENTICATE(타입 3) — 자격증명 응답·크래킹 표적."""
        return self.message_type == NTLM_AUTHENTICATE

    @property
    def unicode(self) -> bool:
        """NegotiateFlags 에 UNICODE 비트(없으면 OEM 가정)."""
        f = self.negotiate_flags
        return f is None or bool(f & NEGOTIATE_UNICODE)

    @property
    def flag_names(self) -> List[str]:
        """설정된 주요 NegotiateFlags 의 이름 목록."""
        f = self.negotiate_flags
        if f is None:
            return []
        return [name for bit, name in _FLAG_NAMES if f & bit]

    @property
    def signing_negotiated(self) -> Optional[bool]:
        """SIGN 비트 협상 여부. flags 없으면 None."""
        if self.negotiate_flags is None:
            return None
        return bool(self.negotiate_flags & NEGOTIATE_SIGN)

    @property
    def sealing_negotiated(self) -> Optional[bool]:
        """SEAL 비트 협상 여부. flags 없으면 None."""
        if self.negotiate_flags is None:
            return None
        return bool(self.negotiate_flags & NEGOTIATE_SEAL)

    @property
    def account(self) -> Optional[str]:
        """인증 주체를 ``DOMAIN\\user`` 로(있는 만큼)."""
        if self.user is None:
            return None
        if self.domain:
            return f"{self.domain}\\{self.user}"
        return self.user

    @property
    def is_null_session(self) -> bool:
        """AUTHENTICATE 인데 사용자 비고 NT 응답 없음 — 널 세션."""
        return (
            self.is_authenticate
            and not self.user
            and not self.nt_response
        )

    @property
    def is_ntlmv2(self) -> Optional[bool]:
        """NT 응답이 NTLMv2 인지. v2 면 응답 길이 > 24, v1 이면 == 24.

        AUTHENTICATE 가 아니거나 NT 응답이 없으면 None.
        """
        if not self.is_authenticate or not self.nt_response:
            return None
        return len(self.nt_response) > 24

    @property
    def target_info_map(self) -> Dict[str, str]:
        """알려진 AV pair 를 이름→문자열(UTF-16LE)로 변환한 사전."""
        out: Dict[str, str] = {}
        for av_id, value in self.target_info:
            name = _AV_NAMES.get(av_id)
            if name is None:
                continue
            try:
                out[name] = value.decode("utf-16-le")
            except UnicodeDecodeError:
                out[name] = value.decode("latin-1", "replace")
        return out


def _parse_challenge(blob: bytes, flags: Optional[int]) -> dict:
    """CHALLENGE(타입 2): TargetName[12] flags[20] ServerChallenge[24..32]
    TargetInfo[40].
    """
    out: dict = {}
    unicode_on = flags is None or bool(flags & NEGOTIATE_UNICODE)
    out["target_name"] = _decode(_field(blob, 12), unicode_on)
    if len(blob) >= 32:
        out["server_challenge"] = blob[24:32]
    ti = _field(blob, 40)
    if ti is not None:
        out["target_info"] = _parse_av_pairs(ti)
    return out


def _parse_authenticate(blob: bytes, flags: Optional[int]) -> dict:
    """AUTHENTICATE(타입 3): LmResp[12] NtResp[20] Domain[28] User[36]
    Workstation[44] SessionKey[52] flags[60].
    """
    out: dict = {}
    unicode_on = flags is None or bool(flags & NEGOTIATE_UNICODE)
    out["lm_response"] = _field(blob, 12)
    out["nt_response"] = _field(blob, 20)
    out["domain"] = _decode(_field(blob, 28), unicode_on)
    out["user"] = _decode(_field(blob, 36), unicode_on)
    out["workstation"] = _decode(_field(blob, 44), unicode_on)
    return out


def parse_ntlm(data: bytes, offset: int = 0) -> Optional[NTLMMessage]:
    """원시 바이트에서 NTLMSSP 메시지 한 건을 파싱한다.

    Args:
        data: ``NTLMSSP\\x00`` 으로 시작하는 메시지를 담은 바이트. SMB
            SESSION_SETUP 보안 블롭·HTTP ``Authorization`` 헤더 Base64
            디코드 결과·DCE/RPC auth verifier 등에서 얻는다.
        offset: 메시지가 시작하는 위치(기본 0).

    Returns:
        :class:`NTLMMessage`. 시그니처가 ``NTLMSSP\\x00`` 이 아니거나
        MessageType 이 1/2/3 이 아니면 ``None``.
    """
    if offset < 0 or offset >= len(data):
        return None
    blob = data[offset:]
    if blob[:8] != NTLMSSP_SIG:
        return None
    mtype = _u32(blob, 8)
    if mtype is None or mtype not in _KNOWN_TYPES:
        return None

    # NegotiateFlags 위치는 메시지 타입마다 다르다.
    if mtype == NTLM_NEGOTIATE:
        flags = _u32(blob, 12)
    elif mtype == NTLM_CHALLENGE:
        flags = _u32(blob, 20)
    else:  # AUTHENTICATE
        flags = _u32(blob, 60)

    extra: dict = {}
    if mtype == NTLM_CHALLENGE:
        extra = _parse_challenge(blob, flags)
    elif mtype == NTLM_AUTHENTICATE:
        extra = _parse_authenticate(blob, flags)

    return NTLMMessage(message_type=mtype, negotiate_flags=flags, **extra)


def find_ntlm(data: bytes, offset: int = 0) -> Optional[NTLMMessage]:
    """``data`` 안에서 첫 ``NTLMSSP\\x00`` 시그니처를 찾아 파싱한다.

    SPNEGO/GSS-API 래핑이나 HTTP 헤더 잔여 바이트를 완전 해석하는 대신
    시그니처를 스캔하는 실무 도구 관례. 못 찾으면 ``None``.
    """
    if offset < 0:
        return None
    idx = data.find(NTLMSSP_SIG, offset)
    if idx < 0:
        return None
    return parse_ntlm(data, idx)


def netntlmv2(
    auth: NTLMMessage,
    server_challenge: bytes,
) -> Optional[str]:
    """AUTHENTICATE + 서버 챌린지로 Net-NTLMv2 크래킹 해시를 만든다.

    hashcat ``-m 5600`` 형식: ``user::domain:srvchal:ntproof:blob``.
    NtChallengeResponse(NTLMv2) = NTProofStr[16] + blob 이므로 앞 16바이트가
    NTProofStr, 나머지가 blob 이다. 서버 챌린지는 짝지은 CHALLENGE 메시지의
    :attr:`NTLMMessage.server_challenge` (8바이트)에서 가져온다.

    Args:
        auth: AUTHENTICATE 메시지. NTLMv2 NT 응답(>= 24바이트)이어야 한다.
        server_challenge: CHALLENGE 의 8바이트 서버 nonce.

    Returns:
        크래킹 가능한 해시 문자열. v1 응답·짧은 응답·잘못된 챌린지·
        사용자 없음이면 ``None``.
    """
    if not auth.is_authenticate:
        return None
    nt = auth.nt_response
    if nt is None or len(nt) <= 24:  # v1(24) 이하는 v2 아님.
        return None
    if len(server_challenge) != 8:
        return None
    if not auth.user:
        return None
    ntproof = nt[:16].hex()
    blob = nt[16:].hex()
    domain = auth.domain or ""
    srvchal = server_challenge.hex()
    return f"{auth.user}::{domain}:{srvchal}:{ntproof}:{blob}"
