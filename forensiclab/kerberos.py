"""Kerberos — KDC 프로토콜 메시지 파싱 코어 (RFC 4120, DER/ASN.1).

:mod:`forensiclab.netdissect` 가 식별한 UDP/TCP 88(KDC) 페이로드는 Kerberos
메시지일 수 있다. 이 모듈이 그 메시지를 해석한다 — :mod:`forensiclab.ldap`·
:mod:`forensiclab.snmp` 가 같은 BER/ASN.1 인코딩을 다루는 것과 같은 자리이며,
세 모듈은 TLV 디코딩 골격을 공유한다. LDAP(389)·Kerberos(88)·SMB 는 Active
Directory 공격면의 형제다 — LDAP 가 디렉터리 질의/인증이라면 Kerberos 는
**티켓 발급(인증) 그 자체**라 사고 분석에서 단서가 핵심적이다.

Kerberos 메시지는 EXPLICIT context 태그를 쓰는 DER 로, 최외곽이
``[APPLICATION n] SEQUENCE { ... }`` 이다(n 으로 메시지 종류 구분):

- 10 AS-REQ, 11 AS-REP — 초기 인증(TGT 발급).
- 12 TGS-REQ, 13 TGS-REP — 서비스 티켓 발급.
- 14 AP-REQ, 15 AP-REP — 서비스 접속 시 티켓 제시.
- 30 KRB-ERROR — 오류 응답.

침해/사고 분석 단서:

- **AS-REP Roasting(ASREProast)**: AS-REQ 가 ``PA-ENC-TIMESTAMP``(padata
  타입 2) 사전인증 없이 들어오면(``DONT_REQUIRE_PREAUTH`` 계정), 응답
  AS-REP 의 enc-part 가 사용자 키로 암호화되어 **오프라인 크래킹** 표적이
  된다 — 사전인증 없는 AS-REQ 는 강한 신호.
- **Kerberoasting**: TGS-REQ 가 ``krbtgt`` 가 아닌 서비스 SPN(``sname``)
  티켓을, 특히 **RC4-HMAC(etype 23)** 로 요청하면 발급된 서비스 티켓
  enc-part 가 서비스 계정 NTLM 해시로 암호화되어 오프라인 크래킹 표적.
  TGS-REP 의 ticket etype 이 RC4 면 실제로 크래킹 가능한 티켓이 나간 것.
- **암호화 다운그레이드**: etype 목록에 DES(1/3)·RC4(23/24) 가 끼면 약한
  암호 협상 — AES(17/18) 회피 정황.
- **사용자 열거·브루트포스**: KRB-ERROR ``error-code`` 가
  6(C_PRINCIPAL_UNKNOWN) 이면 존재하지 않는 사용자(열거), 24
  (PREAUTH_FAILED) 면 사전인증 실패(패스워드 스프레이/브루트포스;
  :mod:`forensiclab.ldap` resultCode 49·:mod:`forensiclab.radius`
  Access-Reject 대응), 25(PREAUTH_REQUIRED) 는 정상 사전인증 요구.
- **귀속**: ``cname`` 클라이언트 주체(user@REALM)·``sname`` 서비스 주체
  ·``realm`` 으로 흐름을 AD 계정/서비스에 연결한다.

설계 원칙(:mod:`forensiclab.ldap`·:mod:`forensiclab.snmp` 와 동일):
- 부작용 없음: 순수 함수. 디스크/표준출력/네트워크 없음.
- stdlib 전용.
- 안전: 입력 바이트를 변형하지 않는다(읽기 전용).
- 견고: 너무 짧거나 망가진 입력은 예외 대신 ``None``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional, Tuple

__all__ = [
    "KRB_AS_REQ",
    "KRB_AS_REP",
    "KRB_TGS_REQ",
    "KRB_TGS_REP",
    "KRB_AP_REQ",
    "KRB_AP_REP",
    "KRB_ERROR",
    "PA_ENC_TIMESTAMP",
    "ETYPE_DES_CBC_CRC",
    "ETYPE_DES_CBC_MD5",
    "ETYPE_AES128",
    "ETYPE_AES256",
    "ETYPE_RC4_HMAC",
    "WEAK_ETYPES",
    "RC4_ETYPES",
    "ERR_C_PRINCIPAL_UNKNOWN",
    "ERR_PREAUTH_FAILED",
    "ERR_PREAUTH_REQUIRED",
    "KerberosMessage",
    "parse_kerberos",
]

# 최외곽 [APPLICATION n] 태그 번호(RFC 4120 §5.10) — 메시지 종류.
KRB_AS_REQ = 10
KRB_AS_REP = 11
KRB_TGS_REQ = 12
KRB_TGS_REP = 13
KRB_AP_REQ = 14
KRB_AP_REP = 15
KRB_ERROR = 30
_TICKET_APP = 1  # Ticket ::= [APPLICATION 1] SEQUENCE.

_MSG_NAMES = {
    KRB_AS_REQ: "AS-REQ",
    KRB_AS_REP: "AS-REP",
    KRB_TGS_REQ: "TGS-REQ",
    KRB_TGS_REP: "TGS-REP",
    KRB_AP_REQ: "AP-REQ",
    KRB_AP_REP: "AP-REP",
    KRB_ERROR: "KRB-ERROR",
}

_KDC_REQ_TAGS = frozenset({KRB_AS_REQ, KRB_TGS_REQ})
_KDC_REP_TAGS = frozenset({KRB_AS_REP, KRB_TGS_REP})
_KNOWN_APP_TAGS = frozenset(_MSG_NAMES)

# PA-DATA 타입(RFC 4120 §7.5.2) — 관심 값만.
PA_ENC_TIMESTAMP = 2  # 사전인증 타임스탬프 — 있으면 사전인증 제공됨.

# 암호화 타입(RFC 3961/4120 §8) — 관심 값만.
ETYPE_DES_CBC_CRC = 1
ETYPE_DES_CBC_MD5 = 3
ETYPE_AES128 = 17
ETYPE_AES256 = 18
ETYPE_RC4_HMAC = 23
ETYPE_RC4_HMAC_EXP = 24

_ETYPE_NAMES = {
    ETYPE_DES_CBC_CRC: "des-cbc-crc",
    ETYPE_DES_CBC_MD5: "des-cbc-md5",
    ETYPE_AES128: "aes128-cts-hmac-sha1-96",
    ETYPE_AES256: "aes256-cts-hmac-sha1-96",
    ETYPE_RC4_HMAC: "rc4-hmac",
    ETYPE_RC4_HMAC_EXP: "rc4-hmac-exp",
}

# 약한 암호 협상 단서(DES·RC4) — AES 회피.
WEAK_ETYPES = frozenset({1, 2, 3, 23, 24})
# Kerberoast/ASREProast 오프라인 크래킹의 핵심(RC4 = NTLM 해시 기반).
RC4_ETYPES = frozenset({ETYPE_RC4_HMAC, ETYPE_RC4_HMAC_EXP})

# KRB-ERROR error-code(RFC 4120 §7.5.9) — 관심 값만.
ERR_C_PRINCIPAL_UNKNOWN = 6   # 존재하지 않는 클라이언트 — 사용자 열거.
ERR_S_PRINCIPAL_UNKNOWN = 7
ERR_CLIENT_REVOKED = 18
ERR_PREAUTH_FAILED = 24       # 사전인증 실패 — 패스워드 스프레이/브루트포스.
ERR_PREAUTH_REQUIRED = 25     # 사전인증 요구(정상).

_ERR_NAMES = {
    ERR_C_PRINCIPAL_UNKNOWN: "KDC_ERR_C_PRINCIPAL_UNKNOWN",
    ERR_S_PRINCIPAL_UNKNOWN: "KDC_ERR_S_PRINCIPAL_UNKNOWN",
    ERR_CLIENT_REVOKED: "KDC_ERR_CLIENT_REVOKED",
    ERR_PREAUTH_FAILED: "KDC_ERR_PREAUTH_FAILED",
    ERR_PREAUTH_REQUIRED: "KDC_ERR_PREAUTH_REQUIRED",
}

# BER/DER 태그.
_TAG_INTEGER = 0x02
_TAG_SEQUENCE = 0x30  # constructed | SEQUENCE.
_TAG_GENERALSTRING = 0x1B  # KerberosString.


def _read_len(data: bytes, pos: int) -> Optional[Tuple[int, int]]:
    """DER 길이를 읽어 (length, next_pos). 망가지면 ``None``.

    short form(0xxxxxxx)·long form(1nnnnnnn + n바이트) 지원. 무한 길이(0x80)는
    DER 에 없으므로 거부한다. (:mod:`forensiclab.ldap` 와 동일.)
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
    """하나의 TLV 를 읽어 (tag, value_bytes, next_pos). 망가지면 ``None``.

    Kerberos 태그는 모두 단일 바이트(태그 번호 <= 30)다 — high-tag 미사용.
    """
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


def _as_text(value: bytes) -> str:
    """KerberosString 콘텐츠를 사람이 읽는 문자열로(UTF-8 우선)."""
    try:
        return value.decode("utf-8")
    except UnicodeDecodeError:
        return value.decode("latin-1")


def _read_context_fields(body: bytes) -> dict:
    """SEQUENCE 본문의 ``[k]`` EXPLICIT context 필드를 ``{k: inner_tlv_bytes}``.

    Kerberos 는 EXPLICIT 태깅이라 각 ``[k]`` 의 value 가 곧 감싼 TLV 바이트다.
    같은 번호가 중복되면 첫 값만 둔다(정상 메시지엔 중복 없음).
    """
    fields: dict = {}
    pos = 0
    while pos < len(body):
        tlv = _read_tlv(body, pos)
        if tlv is None:
            break
        tag, value, nxt = tlv
        if (tag & 0xC0) == 0x80:  # context class(0b10).
            num = tag & 0x1F
            fields.setdefault(num, value)
        pos = nxt
    return fields


def _read_inner_int(value: Optional[bytes]) -> Optional[int]:
    """EXPLICIT ``[k]`` 가 감싼 INTEGER 를 읽는다."""
    if value is None:
        return None
    inner = _read_tlv(value, 0)
    if inner is None or inner[0] != _TAG_INTEGER:
        return None
    return _read_int(inner[1])


def _read_inner_string(value: Optional[bytes]) -> Optional[str]:
    """EXPLICIT ``[k]`` 가 감싼 KerberosString(GeneralString) 을 읽는다."""
    if value is None:
        return None
    inner = _read_tlv(value, 0)
    if inner is None:
        return None
    return _as_text(inner[1])


def _read_string_seq(body: bytes) -> List[str]:
    """SEQUENCE OF KerberosString 콘텐츠를 문자열 목록으로(읽을 수 있는 만큼)."""
    out: List[str] = []
    pos = 0
    while pos < len(body):
        tlv = _read_tlv(body, pos)
        if tlv is None:
            break
        out.append(_as_text(tlv[1]))
        pos = tlv[2]
    return out


def _read_principal_name(value: Optional[bytes]) -> Optional[str]:
    """EXPLICIT ``[k]`` 가 감싼 PrincipalName 을 ``"comp1/comp2"`` 로.

    PrincipalName ::= SEQUENCE { name-type [0] Int32, name-string [1]
    SEQUENCE OF KerberosString }. 이름 구성요소만 ``/`` 로 잇는다.
    """
    if value is None:
        return None
    seq = _read_tlv(value, 0)
    if seq is None or seq[0] != _TAG_SEQUENCE:
        return None
    fields = _read_context_fields(seq[1])
    ns = fields.get(1)
    if ns is None:
        return None
    inner = _read_tlv(ns, 0)
    if inner is None or inner[0] != _TAG_SEQUENCE:
        return None
    parts = _read_string_seq(inner[1])
    return "/".join(parts) if parts else None


def _read_int_seq(value: Optional[bytes]) -> List[int]:
    """EXPLICIT ``[k]`` 가 감싼 SEQUENCE OF Int32 를 정수 목록으로."""
    if value is None:
        return []
    seq = _read_tlv(value, 0)
    if seq is None or seq[0] != _TAG_SEQUENCE:
        return []
    out: List[int] = []
    pos = 0
    while pos < len(seq[1]):
        tlv = _read_tlv(seq[1], pos)
        if tlv is None:
            break
        if tlv[0] == _TAG_INTEGER:
            out.append(_read_int(tlv[1]))
        pos = tlv[2]
    return out


def _read_padata_types(value: Optional[bytes]) -> List[int]:
    """EXPLICIT ``[k]`` 가 감싼 SEQUENCE OF PA-DATA 의 padata-type 목록.

    PA-DATA ::= SEQUENCE { padata-type [1] Int32, padata-value [2] OCTET STRING }.
    """
    if value is None:
        return []
    seq = _read_tlv(value, 0)
    if seq is None or seq[0] != _TAG_SEQUENCE:
        return []
    out: List[int] = []
    pos = 0
    while pos < len(seq[1]):
        tlv = _read_tlv(seq[1], pos)
        if tlv is None:
            break
        if tlv[0] == _TAG_SEQUENCE:
            f = _read_context_fields(tlv[1])
            t = _read_inner_int(f.get(1))
            if t is not None:
                out.append(t)
        pos = tlv[2]
    return out


@dataclass(frozen=True)
class KerberosMessage:
    """파싱된 Kerberos 메시지 한 건.

    Attributes:
        msg_type: 최외곽 [APPLICATION n] 태그 번호(10 AS-REQ … 30 KRB-ERROR).
        realm: 요청/오류의 영역(realm). 없으면 None.
        cname: 클라이언트 주체("comp1/comp2", 보통 사용자명). 없으면 None.
        sname: 서비스 주체(SPN, 또는 KDC-REP 티켓의 서비스). 없으면 None.
        etypes: 요청 etype 목록(KDC-REQ). KDC-REP 은 빈 목록.
        padata_types: KDC-REQ 의 padata 타입 목록(사전인증 판별용).
        error_code: KRB-ERROR 의 error-code. 그 외 None.
        ticket_etype: KDC-REP 발급 티켓 enc-part 의 etype(크래킹 표적 판별).
    """

    msg_type: int
    realm: Optional[str] = None
    cname: Optional[str] = None
    sname: Optional[str] = None
    etypes: List[int] = field(default_factory=list)
    padata_types: List[int] = field(default_factory=list)
    error_code: Optional[int] = None
    ticket_etype: Optional[int] = None

    @property
    def msg_name(self) -> str:
        """메시지의 사람이 읽는 이름(미상이면 ``"krb-<n>"``)."""
        return _MSG_NAMES.get(self.msg_type, f"krb-{self.msg_type}")

    @property
    def is_as_req(self) -> bool:
        return self.msg_type == KRB_AS_REQ

    @property
    def is_tgs_req(self) -> bool:
        return self.msg_type == KRB_TGS_REQ

    @property
    def is_as_rep(self) -> bool:
        return self.msg_type == KRB_AS_REP

    @property
    def is_tgs_rep(self) -> bool:
        return self.msg_type == KRB_TGS_REP

    @property
    def is_error(self) -> bool:
        return self.msg_type == KRB_ERROR

    @property
    def etype_names(self) -> List[str]:
        """요청 etype 의 사람이 읽는 이름 목록."""
        return [_ETYPE_NAMES.get(e, f"etype-{e}") for e in self.etypes]

    @property
    def weak_etypes(self) -> List[int]:
        """요청 etype 중 약한(DES/RC4) 것만 — 다운그레이드 정황."""
        return [e for e in self.etypes if e in WEAK_ETYPES]

    @property
    def requests_rc4(self) -> bool:
        """RC4-HMAC etype 을 요청했는지 — Kerberoast 크래킹 표적."""
        return any(e in RC4_ETYPES for e in self.etypes)

    @property
    def preauth_supplied(self) -> bool:
        """PA-ENC-TIMESTAMP 사전인증을 실었는지(KDC-REQ)."""
        return PA_ENC_TIMESTAMP in self.padata_types

    @property
    def service_is_krbtgt(self) -> bool:
        """서비스 주체가 ``krbtgt`` 인지(TGT 발급 — Kerberoast 대상 아님)."""
        return bool(self.sname) and self.sname.lower().startswith("krbtgt")

    @property
    def is_asreproast_attempt(self) -> bool:
        """사전인증 없는 AS-REQ — AS-REP Roasting 정황(오프라인 크래킹 표적)."""
        return self.is_as_req and not self.preauth_supplied and bool(self.cname)

    @property
    def is_kerberoast_request(self) -> bool:
        """krbtgt 아닌 SPN 을 RC4 로 요청하는 TGS-REQ — Kerberoasting 정황."""
        return (
            self.is_tgs_req
            and bool(self.sname)
            and not self.service_is_krbtgt
            and self.requests_rc4
        )

    @property
    def is_kerberoastable_reply(self) -> bool:
        """RC4 로 발급된 비-krbtgt 서비스 티켓(TGS-REP) — 실제 크래킹 가능 티켓."""
        return (
            self.is_tgs_rep
            and self.ticket_etype in RC4_ETYPES
            and not self.service_is_krbtgt
        )

    @property
    def error_name(self) -> Optional[str]:
        """error-code 의 사람이 읽는 이름(KRB-ERROR 일 때만)."""
        if self.error_code is None:
            return None
        return _ERR_NAMES.get(self.error_code, f"err-{self.error_code}")

    @property
    def is_principal_unknown(self) -> bool:
        """KDC_ERR_C_PRINCIPAL_UNKNOWN(6) — 사용자 열거 정황."""
        return self.error_code == ERR_C_PRINCIPAL_UNKNOWN

    @property
    def is_preauth_failed(self) -> bool:
        """KDC_ERR_PREAUTH_FAILED(24) — 패스워드 스프레이/브루트포스 신호."""
        return self.error_code == ERR_PREAUTH_FAILED


def _read_ticket_sname_etype(value: Optional[bytes]) -> Tuple[Optional[str], Optional[int]]:
    """KDC-REP 의 ticket([5]) 에서 서비스 주체와 enc-part etype 을 뽑는다.

    Ticket ::= [APPLICATION 1] SEQUENCE { tkt-vno [0], realm [1], sname [2],
    enc-part [3] EncryptedData }. EncryptedData ::= SEQUENCE { etype [0] Int32,
    kvno [1] OPTIONAL, cipher [2] OCTET STRING }.
    """
    if value is None:
        return None, None
    app = _read_tlv(value, 0)
    if app is None or (app[0] & 0x1F) != _TICKET_APP:
        return None, None
    seq = _read_tlv(app[1], 0)
    if seq is None or seq[0] != _TAG_SEQUENCE:
        return None, None
    fields = _read_context_fields(seq[1])
    sname = _read_principal_name(fields.get(2))
    etype = None
    enc = fields.get(3)
    if enc is not None:
        enc_seq = _read_tlv(enc, 0)
        if enc_seq is not None and enc_seq[0] == _TAG_SEQUENCE:
            etype = _read_inner_int(_read_context_fields(enc_seq[1]).get(0))
    return sname, etype


def _parse_kdc_req(fields: dict) -> dict:
    """AS-REQ/TGS-REQ(KDC-REQ) 본문 필드에서 관심 값을 뽑는다.

    KDC-REQ ::= SEQUENCE { pvno [1], msg-type [2], padata [3] OPTIONAL,
    req-body [4] KDC-REQ-BODY }.
    """
    out: dict = {"padata_types": _read_padata_types(fields.get(3))}
    body_val = fields.get(4)
    if body_val is None:
        return out
    body_seq = _read_tlv(body_val, 0)
    if body_seq is None or body_seq[0] != _TAG_SEQUENCE:
        return out
    # KDC-REQ-BODY: kdc-options [0], cname [1], realm [2], sname [3],
    #   from [4], till [5], rtime [6], nonce [7], etype [8], ...
    bf = _read_context_fields(body_seq[1])
    out["cname"] = _read_principal_name(bf.get(1))
    out["realm"] = _read_inner_string(bf.get(2))
    out["sname"] = _read_principal_name(bf.get(3))
    out["etypes"] = _read_int_seq(bf.get(8))
    return out


def _parse_kdc_rep(fields: dict) -> dict:
    """AS-REP/TGS-REP(KDC-REP) 본문 필드에서 관심 값을 뽑는다.

    KDC-REP ::= SEQUENCE { pvno [0], msg-type [1], padata [2] OPTIONAL,
    crealm [3], cname [4], ticket [5], enc-part [6] }.
    """
    out: dict = {
        "realm": _read_inner_string(fields.get(3)),
        "cname": _read_principal_name(fields.get(4)),
    }
    sname, etype = _read_ticket_sname_etype(fields.get(5))
    out["sname"] = sname
    out["ticket_etype"] = etype
    return out


def _parse_krb_error(fields: dict) -> dict:
    """KRB-ERROR 본문 필드에서 관심 값을 뽑는다.

    KRB-ERROR ::= SEQUENCE { pvno [0], msg-type [1], ctime [2], cusec [3],
    stime [4], susec [5], error-code [6] Int32, crealm [7], cname [8],
    realm [9], sname [10], ... }.
    """
    out: dict = {"error_code": _read_inner_int(fields.get(6))}
    out["cname"] = _read_principal_name(fields.get(8))
    out["sname"] = _read_principal_name(fields.get(10))
    # 서비스 영역[9] 우선, 없으면 클라이언트 영역[7].
    out["realm"] = _read_inner_string(fields.get(9)) or _read_inner_string(
        fields.get(7)
    )
    return out


def parse_kerberos(data: bytes, offset: int = 0) -> Optional[KerberosMessage]:
    """원시 바이트에서 Kerberos 메시지 한 건을 파싱한다.

    Args:
        data: Kerberos 패킷을 담은 바이트. 보통 UDP/TCP 88 페이로드
            (:class:`forensiclab.netdissect` 의 ``payload_offset`` 부터)다.
            TCP 전송이면 앞 4바이트 길이 접두사를 ``offset=4`` 로 건너뛸 수 있다.
        offset: 메시지가 시작하는 위치(기본 0).

    Returns:
        :class:`KerberosMessage`. 최외곽이 알려진 ``[APPLICATION n]``
        구조가 아니면 ``None``.
    """
    if offset < 0:
        return None
    outer = _read_tlv(data, offset)
    if outer is None:
        return None
    tag = outer[0]
    # APPLICATION 클래스(0b01) + constructed(0b1) = 0x60. (마스크 0xE0.)
    if (tag & 0xE0) != 0x60:
        return None
    app_tag = tag & 0x1F
    if app_tag not in _KNOWN_APP_TAGS:
        return None

    seq = _read_tlv(outer[1], 0)
    if seq is None or seq[0] != _TAG_SEQUENCE:
        return None
    fields = _read_context_fields(seq[1])

    extra: dict = {}
    if app_tag in _KDC_REQ_TAGS:
        extra = _parse_kdc_req(fields)
    elif app_tag in _KDC_REP_TAGS:
        extra = _parse_kdc_rep(fields)
    elif app_tag == KRB_ERROR:
        extra = _parse_krb_error(fields)

    return KerberosMessage(msg_type=app_tag, **extra)
