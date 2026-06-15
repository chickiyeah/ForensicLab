"""LDAP — 경량 디렉터리 접근 프로토콜 파싱 코어 (RFC 4511, BER/ASN.1).

:mod:`forensiclab.netdissect` 가 식별한 TCP(관용 포트 389, 글로벌 카탈로그
3268) 페이로드는 LDAP 메시지일 수 있다. 이 모듈이 그 메시지를 해석한다
(:mod:`forensiclab.snmp` 가 같은 BER/ASN.1 인코딩을 UDP 161/162 에서 다루는
것과 같은 자리 — 두 모듈은 TLV 디코딩 골격을 공유한다).

LDAP 는 Active Directory·OpenLDAP 등 **디렉터리 서비스의 질의·인증 채널**
이라 침해/사고 분석에서 단서가 많다(636/LDAPS·STARTTLS 가 아닌 평문 389):

- **simple bind 평문 자격증명**: BindRequest 의 ``simple`` 인증은 DN(``name``)과
  비밀번호를 **평문 OCTET STRING** 으로 그대로 싣는다. 와이어에서 사용자 DN
  (``CN=admin,DC=corp,DC=local``)과 비밀번호가 통째로 노출된다 —
  :mod:`forensiclab.ftp` USER/PASS·:mod:`forensiclab.mssql` 평문 자격증명과
  같은 계열. ``name`` 이 비고 ``simple`` 도 비면 익명 bind(정찰 진입점).
- **인증 실패·브루트포스**: BindResponse 의 ``resultCode`` 가 49
  (invalidCredentials) 면 자격증명 실패 — 반복되면 패스워드 스프레이/브루트
  포스 신호(:mod:`forensiclab.radius` Access-Reject·SMTP 535 대응).
- **정찰·열거**: SearchRequest 는 디렉터리를 긁는다. ``baseObject`` 대상
  DN·``scope``(wholeSubtree=2 는 대량 워킹)·요청 ``attributes``
  (``userPassword``·``unicodePwd``·``msDS-*`` 등 민감 속성 요청)는 AD 열거
  (BloodHound·ldapsearch) 정황이다.
- **변조·쓰기**: ModifyRequest·AddRequest·DelRequest·ModifyDNRequest 는
  디렉터리 객체를 바꾸는 쓰기 — 권한 상승(그룹 멤버십 추가)·백도어 계정
  생성·증거 정리 정황.
- **확장 동작**: ExtendedRequest 의 OID(예 STARTTLS ``1.3.6.1.4.1.1466.20037``,
  PasswordModify ``1.3.6.1.4.1.4203.1.11.1``)는 TLS 업그레이드·비밀번호 변경
  등 특수 동작 단서.

LDAPMessage 포맷(RFC 4511 §4.1.1, BER/ASN.1)::

    LDAPMessage ::= SEQUENCE {
        messageID   INTEGER,
        protocolOp  CHOICE { bindRequest [APPLICATION 0], ... },
        controls    [0] Controls OPTIONAL }

protocolOp application 태그: 0 BindRequest, 1 BindResponse, 2 UnbindRequest,
3 SearchRequest, 4 SearchResultEntry, 5 SearchResultDone, 6 ModifyRequest,
7 ModifyResponse, 8 AddRequest, 9 AddResponse, 10 DelRequest, 11 DelResponse,
12 ModifyDNRequest, 13 ModifyDNResponse, 14 CompareRequest, 15 CompareResponse,
16 AbandonRequest, 23 ExtendedRequest, 24 ExtendedResponse.

설계 원칙(:mod:`forensiclab.snmp`·:mod:`forensiclab.mssql` 와 동일):
- 부작용 없음: 순수 함수. 디스크/표준출력/네트워크 없음.
- stdlib 전용.
- 안전: 입력 바이트를 변형하지 않는다(읽기 전용).
- 견고: 너무 짧거나 망가진 입력은 예외 대신 ``None``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional, Tuple

__all__ = [
    "OP_BIND_REQUEST",
    "OP_BIND_RESPONSE",
    "OP_UNBIND_REQUEST",
    "OP_SEARCH_REQUEST",
    "OP_SEARCH_RESULT_ENTRY",
    "OP_SEARCH_RESULT_DONE",
    "OP_MODIFY_REQUEST",
    "OP_ADD_REQUEST",
    "OP_DEL_REQUEST",
    "OP_MODIFY_DN_REQUEST",
    "OP_COMPARE_REQUEST",
    "OP_ABANDON_REQUEST",
    "OP_EXTENDED_REQUEST",
    "OP_EXTENDED_RESPONSE",
    "AUTH_SIMPLE",
    "AUTH_SASL",
    "SCOPE_BASE",
    "SCOPE_ONE_LEVEL",
    "SCOPE_SUBTREE",
    "RESULT_SUCCESS",
    "RESULT_INVALID_CREDENTIALS",
    "SENSITIVE_ATTRIBUTES",
    "LdapMessage",
    "parse_ldap",
]

# protocolOp application 태그 번호(RFC 4511 §4.2~).
OP_BIND_REQUEST = 0
OP_BIND_RESPONSE = 1
OP_UNBIND_REQUEST = 2
OP_SEARCH_REQUEST = 3
OP_SEARCH_RESULT_ENTRY = 4
OP_SEARCH_RESULT_DONE = 5
OP_MODIFY_REQUEST = 6
OP_MODIFY_RESPONSE = 7
OP_ADD_REQUEST = 8
OP_ADD_RESPONSE = 9
OP_DEL_REQUEST = 10
OP_DEL_RESPONSE = 11
OP_MODIFY_DN_REQUEST = 12
OP_MODIFY_DN_RESPONSE = 13
OP_COMPARE_REQUEST = 14
OP_COMPARE_RESPONSE = 15
OP_ABANDON_REQUEST = 16
OP_EXTENDED_REQUEST = 23
OP_EXTENDED_RESPONSE = 24

_OP_NAMES = {
    OP_BIND_REQUEST: "BindRequest",
    OP_BIND_RESPONSE: "BindResponse",
    OP_UNBIND_REQUEST: "UnbindRequest",
    OP_SEARCH_REQUEST: "SearchRequest",
    OP_SEARCH_RESULT_ENTRY: "SearchResultEntry",
    OP_SEARCH_RESULT_DONE: "SearchResultDone",
    OP_MODIFY_REQUEST: "ModifyRequest",
    OP_MODIFY_RESPONSE: "ModifyResponse",
    OP_ADD_REQUEST: "AddRequest",
    OP_ADD_RESPONSE: "AddResponse",
    OP_DEL_REQUEST: "DelRequest",
    OP_DEL_RESPONSE: "DelResponse",
    OP_MODIFY_DN_REQUEST: "ModifyDNRequest",
    OP_MODIFY_DN_RESPONSE: "ModifyDNResponse",
    OP_COMPARE_REQUEST: "CompareRequest",
    OP_COMPARE_RESPONSE: "CompareResponse",
    OP_ABANDON_REQUEST: "AbandonRequest",
    OP_EXTENDED_REQUEST: "ExtendedRequest",
    OP_EXTENDED_RESPONSE: "ExtendedResponse",
}

# 디렉터리 객체를 바꾸는 쓰기 동작(변조·권한상승·증거정리 단서).
_WRITE_OPS = frozenset({
    OP_MODIFY_REQUEST, OP_ADD_REQUEST, OP_DEL_REQUEST, OP_MODIFY_DN_REQUEST,
})

# AuthenticationChoice context 태그(BindRequest 안).
AUTH_SIMPLE = 0  # [0] OCTET STRING — 평문 비밀번호.
AUTH_SASL = 3    # [3] SaslCredentials SEQUENCE { mechanism, credentials }.

# SearchRequest scope ENUMERATED.
SCOPE_BASE = 0
SCOPE_ONE_LEVEL = 1
SCOPE_SUBTREE = 2  # wholeSubtree — 대량 워킹 정찰.

_SCOPE_NAMES = {
    SCOPE_BASE: "baseObject",
    SCOPE_ONE_LEVEL: "singleLevel",
    SCOPE_SUBTREE: "wholeSubtree",
}

# LDAPResult resultCode(RFC 4511 §4.1.9) — 관심 값만.
RESULT_SUCCESS = 0
RESULT_INVALID_CREDENTIALS = 49  # 자격증명 실패 — 브루트포스 신호.

# 검색에 끼면 자격증명/비밀 탈취 정황인 민감 속성(소문자 비교).
SENSITIVE_ATTRIBUTES = frozenset({
    "userpassword", "unicodepwd", "ntpwdhistory", "lmpwdhistory",
    "dbcspwd", "supplementalcredentials", "ms-mcs-admpwd",
    "ms-mcs-admpwdexpirationtime", "msds-managedpassword",
})

# BER universal 태그.
_TAG_BOOLEAN = 0x01
_TAG_INTEGER = 0x02
_TAG_OCTET_STRING = 0x04
_TAG_ENUMERATED = 0x0A
_TAG_SEQUENCE = 0x30  # constructed | SEQUENCE.
_TAG_SET = 0x31       # constructed | SET.


def _read_len(data: bytes, pos: int) -> Optional[Tuple[int, int]]:
    """BER 길이를 읽어 (length, next_pos). 망가지면 ``None``.

    short form(0xxxxxxx)·long form(1nnnnnnn + n바이트) 둘 다 지원.
    무한(indefinite) 길이(0x80)는 LDAP 에 없으므로 거부한다.
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
    """BER INTEGER/ENUMERATED 콘텐츠를 부호 있는 정수로."""
    if not value:
        return 0
    return int.from_bytes(value, "big", signed=True)


def _as_text(value: bytes) -> str:
    """LDAPString/LDAPDN 콘텐츠를 사람이 읽는 문자열로(UTF-8 우선)."""
    try:
        return value.decode("utf-8")
    except UnicodeDecodeError:
        return value.decode("latin-1")


@dataclass(frozen=True)
class LdapMessage:
    """파싱된 LDAPMessage 한 건.

    Attributes:
        message_id: messageID(요청/응답 짝짓기용 정수).
        op_type: protocolOp application 태그 번호(0~24).
        bind_version: BindRequest 의 version(보통 3). 그 외 None.
        bind_dn: BindRequest 의 ``name``(LDAPDN 평문). 익명이면 "".
        auth_type: 인증 방식(AUTH_SIMPLE=0/AUTH_SASL=3). BindRequest 외 None.
        simple_password: simple 인증의 평문 비밀번호(노출!). 그 외 None.
        sasl_mechanism: SASL 인증의 mechanism 문자열(예 GSSAPI). 그 외 None.
        base_object: SearchRequest 의 baseObject DN(검색 기점). 그 외 None.
        scope: SearchRequest 의 scope(0/1/2). 그 외 None.
        attributes: SearchRequest 가 요청한 속성 이름 목록.
        target_dn: 쓰기/Compare/Del 동작의 대상 객체 DN. 해당 없으면 None.
        result_code: *Response 류 LDAPResult 의 resultCode. 그 외 None.
        matched_dn: *Response 류 LDAPResult 의 matchedDN. 그 외 None.
        request_name: ExtendedRequest 의 requestName OID. 그 외 None.
    """

    message_id: int
    op_type: int
    bind_version: Optional[int] = None
    bind_dn: Optional[str] = None
    auth_type: Optional[int] = None
    simple_password: Optional[str] = None
    sasl_mechanism: Optional[str] = None
    base_object: Optional[str] = None
    scope: Optional[int] = None
    attributes: List[str] = field(default_factory=list)
    target_dn: Optional[str] = None
    result_code: Optional[int] = None
    matched_dn: Optional[str] = None
    request_name: Optional[str] = None

    @property
    def op_name(self) -> str:
        """protocolOp 의 사람이 읽는 이름(미상이면 ``"op-<n>"``)."""
        return _OP_NAMES.get(self.op_type, f"op-{self.op_type}")

    @property
    def scope_name(self) -> Optional[str]:
        """scope 의 사람이 읽는 이름(SearchRequest 일 때만)."""
        if self.scope is None:
            return None
        return _SCOPE_NAMES.get(self.scope, f"scope-{self.scope}")

    @property
    def is_simple_bind(self) -> bool:
        """simple bind 인지 — 평문 DN/비밀번호 노출 단서."""
        return self.op_type == OP_BIND_REQUEST and self.auth_type == AUTH_SIMPLE

    @property
    def has_plaintext_password(self) -> bool:
        """비어 있지 않은 평문 비밀번호를 실었는지(익명 bind 제외)."""
        return bool(self.simple_password)

    @property
    def is_anonymous_bind(self) -> bool:
        """익명 bind(빈 DN + 빈 simple 비밀번호) 여부 — 정찰 진입점."""
        return (
            self.op_type == OP_BIND_REQUEST
            and self.auth_type == AUTH_SIMPLE
            and not self.bind_dn
            and not self.simple_password
        )

    @property
    def is_search(self) -> bool:
        """SearchRequest 여부 — 디렉터리 열거 정황."""
        return self.op_type == OP_SEARCH_REQUEST

    @property
    def is_subtree_search(self) -> bool:
        """전체 서브트리(wholeSubtree) 검색 여부 — 대량 워킹 정찰."""
        return self.op_type == OP_SEARCH_REQUEST and self.scope == SCOPE_SUBTREE

    @property
    def is_write(self) -> bool:
        """디렉터리 쓰기(Modify/Add/Del/ModifyDN) 여부 — 변조 단서."""
        return self.op_type in _WRITE_OPS

    @property
    def is_failed_bind(self) -> bool:
        """BindResponse 가 invalidCredentials(49) 인지 — 브루트포스 신호."""
        return (
            self.op_type == OP_BIND_RESPONSE
            and self.result_code == RESULT_INVALID_CREDENTIALS
        )

    @property
    def sensitive_attributes(self) -> List[str]:
        """요청 속성 중 자격증명/비밀 계열만 추린 목록(탈취 정황)."""
        return [a for a in self.attributes if a.lower() in SENSITIVE_ATTRIBUTES]


def _parse_bind_request(body: bytes) -> dict:
    """BindRequest 콘텐츠를 파싱한다(RFC 4511 §4.2).

    구조: version INTEGER, name LDAPDN, authentication AuthenticationChoice.
    """
    out: dict = {}
    ver = _read_tlv(body, 0)
    if ver is None or ver[0] != _TAG_INTEGER:
        return out
    out["bind_version"] = _read_int(ver[1])

    name = _read_tlv(body, ver[2])
    if name is None or name[0] != _TAG_OCTET_STRING:
        return out
    out["bind_dn"] = _as_text(name[1])

    auth = _read_tlv(body, name[2])
    if auth is None:
        return out
    auth_tag = auth[0] & 0x1F  # context-specific 태그 번호.
    out["auth_type"] = auth_tag
    if auth_tag == AUTH_SIMPLE:
        # [0] primitive OCTET STRING — 평문 비밀번호.
        out["simple_password"] = _as_text(auth[1])
    elif auth_tag == AUTH_SASL:
        # [3] SEQUENCE { mechanism LDAPString, credentials OPTIONAL }.
        mech = _read_tlv(auth[1], 0)
        if mech is not None and mech[0] == _TAG_OCTET_STRING:
            out["sasl_mechanism"] = _as_text(mech[1])
    return out


def _parse_search_request(body: bytes) -> dict:
    """SearchRequest 콘텐츠를 파싱한다(RFC 4511 §4.5.1).

    baseObject·scope·derefAliases·sizeLimit·timeLimit·typesOnly·filter
    ·attributes 순. filter 는 건너뛰고 base/scope/attributes 만 모은다.
    """
    out: dict = {}
    base = _read_tlv(body, 0)
    if base is None or base[0] != _TAG_OCTET_STRING:
        return out
    out["base_object"] = _as_text(base[1])

    scope = _read_tlv(body, base[2])
    if scope is None or scope[0] != _TAG_ENUMERATED:
        return out
    out["scope"] = _read_int(scope[1])
    pos = scope[2]

    # derefAliases·sizeLimit·timeLimit·typesOnly(고정 4 필드)를 건너뛴다.
    for _ in range(4):
        tlv = _read_tlv(body, pos)
        if tlv is None:
            return out
        pos = tlv[2]

    # filter(1 필드) 건너뛰기.
    filt = _read_tlv(body, pos)
    if filt is None:
        return out
    pos = filt[2]

    # attributes ::= SEQUENCE OF LDAPString.
    attrs_seq = _read_tlv(body, pos)
    if attrs_seq is not None and attrs_seq[0] == _TAG_SEQUENCE:
        out["attributes"] = _read_string_seq(attrs_seq[1])
    return out


def _read_string_seq(body: bytes) -> List[str]:
    """SEQUENCE OF OCTET STRING 콘텐츠를 문자열 목록으로(읽을 수 있는 만큼)."""
    out: List[str] = []
    pos = 0
    while pos < len(body):
        tlv = _read_tlv(body, pos)
        if tlv is None:
            break
        if tlv[0] == _TAG_OCTET_STRING:
            out.append(_as_text(tlv[1]))
        pos = tlv[2]
    return out


def _parse_ldap_result(body: bytes) -> dict:
    """LDAPResult(*Response 공통 머리) 의 resultCode·matchedDN 을 뽑는다.

    구조: resultCode ENUMERATED, matchedDN LDAPDN, diagnosticMessage ....
    """
    out: dict = {}
    rc = _read_tlv(body, 0)
    if rc is None or rc[0] != _TAG_ENUMERATED:
        return out
    out["result_code"] = _read_int(rc[1])
    md = _read_tlv(body, rc[2])
    if md is not None and md[0] == _TAG_OCTET_STRING:
        out["matched_dn"] = _as_text(md[1])
    return out


def _parse_single_dn(body: bytes) -> dict:
    """첫 필드가 대상 객체 DN(LDAPDN) 인 동작(Modify/Add/ModifyDN/Compare).

    이들은 constructed SEQUENCE 라 첫 내부 TLV(OCTET STRING)가 대상 DN 이다.
    (DelRequest 는 primitive LDAPDN 이라 호출부에서 따로 처리한다.)
    """
    dn = _read_tlv(body, 0)
    if dn is not None and dn[0] == _TAG_OCTET_STRING:
        return {"target_dn": _as_text(dn[1])}
    return {}


def _parse_extended_request(body: bytes) -> dict:
    """ExtendedRequest 의 requestName([0] OID 문자열)을 뽑는다(RFC 4511 §4.12)."""
    rn = _read_tlv(body, 0)
    if rn is None:
        return {}
    # [0] context-specific primitive — OID 가 ASCII 점 표기 문자열로 담긴다.
    return {"request_name": _as_text(rn[1])}


def parse_ldap(data: bytes, offset: int = 0) -> Optional[LdapMessage]:
    """원시 바이트에서 LDAPMessage 한 건을 파싱한다.

    Args:
        data: LDAP 패킷을 담은 바이트. 보통 TCP 389/3268 페이로드
            (:class:`forensiclab.netdissect` 의 ``payload_offset`` 부터)다.
        offset: 메시지가 시작하는 위치(기본 0). 한 TCP 세그먼트에 여러
            LDAPMessage 가 이어질 때 앞 메시지의 끝(외곽 TLV next_pos)을
            넘겨 다음 것을 읽을 수 있다.

    Returns:
        :class:`LdapMessage`. 최외곽 SEQUENCE·messageID·protocolOp 구조가
        LDAP 답지 않으면 ``None``.
    """
    if offset < 0:
        return None
    outer = _read_tlv(data, offset)
    if outer is None or outer[0] != _TAG_SEQUENCE:
        return None
    body = outer[1]

    mid = _read_tlv(body, 0)
    if mid is None or mid[0] != _TAG_INTEGER:
        return None
    message_id = _read_int(mid[1])
    if message_id < 0:  # messageID 는 음수가 될 수 없다 — 오탐 방지.
        return None

    op = _read_tlv(body, mid[2])
    if op is None or (op[0] & 0xC0) != 0x40:  # APPLICATION 클래스(0b01).
        return None
    op_type = op[0] & 0x1F
    op_body = op[1]

    extra: dict = {}
    if op_type == OP_BIND_REQUEST:
        extra = _parse_bind_request(op_body)
    elif op_type == OP_SEARCH_REQUEST:
        extra = _parse_search_request(op_body)
    elif op_type in (
        OP_BIND_RESPONSE, OP_SEARCH_RESULT_DONE, OP_MODIFY_RESPONSE,
        OP_ADD_RESPONSE, OP_DEL_RESPONSE, OP_MODIFY_DN_RESPONSE,
        OP_COMPARE_RESPONSE, OP_EXTENDED_RESPONSE,
    ):
        extra = _parse_ldap_result(op_body)
    elif op_type == OP_DEL_REQUEST:
        # [APPLICATION 10] 은 primitive LDAPDN — 본문이 곧 DN 문자열.
        extra = {"target_dn": _as_text(op_body)}
    elif op_type in _WRITE_OPS or op_type == OP_COMPARE_REQUEST:
        extra = _parse_single_dn(op_body)
    elif op_type == OP_EXTENDED_REQUEST:
        extra = _parse_extended_request(op_body)

    return LdapMessage(message_id=message_id, op_type=op_type, **extra)
