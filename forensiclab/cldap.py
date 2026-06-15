"""CLDAP — 비연결형(Connectionless) LDAP 파싱 코어 (RFC 1798/3352, MS-ADTS).

:mod:`forensiclab.ldap` 가 TCP 389/3268 의 LDAP 메시지를 다룬다면, CLDAP 는
**같은 LDAP 와이어 포맷(BER/ASN.1·같은 protocolOp 태그)을 UDP 389 위에**
얹은 변종이다. 그래서 이 모듈은 구조 파싱을 :func:`forensiclab.ldap.parse_ldap`
에 그대로 위임하고(코드를 다시 만들지 않는다), **UDP/CLDAP 에서만 의미가
생기는 단서**를 그 위에 얹는다 — :mod:`forensiclab.ldap`·:mod:`forensiclab.kerberos`
·:mod:`forensiclab.smb` 에 이은 AD 공격면 형제.

CLDAP 는 연결·bind 없이 단일 searchRequest/searchResultEntry 한 방으로
끝나는 경량 질의라(MS-ADTS §6.3.3 LDAP ping) 두 가지 결의 단서가 두드러진다:

- **반사·증폭 DDoS(CLDAP reflection/amplification)**: ``baseObject=""``·
  ``scope=base`` 의 **rootDSE 질의**는 작은 UDP 요청(수십 바이트) 한 방에
  서버가 rootDSE 속성 전체(수백~수천 바이트)를 토해내게 만든다. 증폭비
  ~50–70× 로 :mod:`forensiclab.ntp`(mode 6/7)·:mod:`forensiclab.snmp`
  ·:mod:`forensiclab.ssdp`·:mod:`forensiclab.memcached` 와 같은 **UDP 반사
  계열**. 출발지 IP 가 위조된(피해자) rootDSE 탐침이 반복되면 반사 봇.
- **Netlogon DC 로케이터(LDAP ping)**: 도메인 가입 클라이언트(및 ``nltest``
  ·Coercer·정찰 도구)는 ``Netlogon`` 속성을 요청하는 rootDSE 검색으로 DC 를
  찾는다. 필터의 ``DnsDomain``/``Host``/``NtVer`` equalityMatch 가 **어느
  도메인/호스트를 겨냥하는지** 드러낸다 — :mod:`forensiclab.ldap` 가 필터를
  건너뛰는 것과 달리 CLDAP 는 이 필터가 핵심이라 직접 파낸다.
- **DC·디렉터리 정찰**: rootDSE 의 ``defaultNamingContext``·``dnsHostName``
  ·``supportedSASLMechanisms`` 등을 끌어오는 질의는 도메인 토폴로지 수집
  정황(:mod:`forensiclab.ldap` SearchRequest 열거의 UDP 판).

설계 원칙(:mod:`forensiclab.ldap` 와 동일):
- 부작용 없음: 순수 함수. 디스크/표준출력/네트워크 없음.
- stdlib 전용. 구조 파싱은 :mod:`forensiclab.ldap` 재사용.
- 견고: 망가진 입력은 예외 대신 ``None``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional, Tuple

from .ldap import (
    OP_SEARCH_REQUEST,
    OP_SEARCH_RESULT_DONE,
    OP_SEARCH_RESULT_ENTRY,
    SCOPE_BASE,
    LdapMessage,
    _as_text,
    _read_tlv,
    parse_ldap,
)

__all__ = [
    "NETLOGON_ATTRIBUTES",
    "ROOTDSE_RECON_ATTRIBUTES",
    "CldapMessage",
    "parse_cldap",
]

# DC 로케이터(LDAP ping)가 요청하는 속성(소문자 비교) — MS-ADTS §6.3.3.
NETLOGON_ATTRIBUTES = frozenset({"netlogon"})

# rootDSE 정찰에서 자주 끌어오는 도메인 토폴로지 속성(소문자 비교).
ROOTDSE_RECON_ATTRIBUTES = frozenset({
    "defaultnamingcontext", "rootdomainnamingcontext", "configurationnamingcontext",
    "schemanamingcontext", "namingcontexts", "dnshostname", "servername",
    "supportedsaslmechanisms", "supportedcontrol", "supportedldapversion",
    "domaincontrollerfunctionality", "domainfunctionality", "forestfunctionality",
})

# searchRequest 안에서 필터가 차지하는 고정 위치(base·scope·deref·sizeLimit
# ·timeLimit·typesOnly 다음 7번째 TLV) — :mod:`forensiclab.ldap` 의 구조와 동일.
_SEARCH_FILTER_INDEX = 6

# Filter CHOICE context 태그(RFC 4511 §4.5.1) — 관심 항목만.
_FILTER_AND = 0x00          # [0] and (constructed SET OF Filter).
_FILTER_OR = 0x01           # [1] or.
_FILTER_NOT = 0x02          # [2] not.
_FILTER_EQUALITY = 0x03     # [3] equalityMatch SEQUENCE { attr, value }.

# BER universal 태그(필요한 것만).
_TAG_OCTET_STRING = 0x04


def _collect_equality(filt_value: bytes, out: List[Tuple[str, str]], depth: int = 0) -> None:
    """Filter 트리를 훑어 equalityMatch (속성, 값) 쌍을 ``out`` 에 모은다.

    and/or/not 안으로 재귀하고, equalityMatch 의 attributeDesc·assertionValue
    를 뽑는다. NtVer 같은 바이너리 값은 ``_as_text`` 가 latin-1 로 보존한다.
    깊이 상한으로 악성 중첩 필터의 무한 재귀를 막는다.
    """
    if depth > 16:
        return
    # filt_value 는 and/or/not Filter TLV 의 value 바이트(하위 Filter 들의
    # 나열). 그 안의 각 하위 Filter 를 순회한다.
    pos = 0
    while pos < len(filt_value):
        sub = _read_tlv(filt_value, pos)
        if sub is None:
            break
        sub_tag = sub[0] & 0x1F  # context-specific 태그 번호.
        if sub_tag in (_FILTER_AND, _FILTER_OR, _FILTER_NOT):
            _collect_equality(sub[1], out, depth + 1)
        elif sub_tag == _FILTER_EQUALITY:
            attr = _read_tlv(sub[1], 0)
            if attr is not None and attr[0] == _TAG_OCTET_STRING:
                val = _read_tlv(sub[1], attr[2])
                value = _as_text(val[1]) if val is not None else ""
                out.append((_as_text(attr[1]), value))
        pos = sub[2]


def _parse_filter_assertions(search_body: bytes) -> List[Tuple[str, str]]:
    """searchRequest 콘텐츠에서 필터의 equalityMatch 쌍을 추출한다.

    base·scope·deref·sizeLimit·timeLimit·typesOnly 6개 필드를 건너뛰고
    7번째(필터)에 도달해 트리를 훑는다. 한 leaf 필터(예 present [7])면 빈
    목록을 돌려준다.
    """
    pos = 0
    for _ in range(_SEARCH_FILTER_INDEX):
        tlv = _read_tlv(search_body, pos)
        if tlv is None:
            return []
        pos = tlv[2]
    filt = _read_tlv(search_body, pos)
    if filt is None:
        return []
    out: List[Tuple[str, str]] = []
    sub_tag = filt[0] & 0x1F
    if sub_tag in (_FILTER_AND, _FILTER_OR, _FILTER_NOT):
        _collect_equality(filt[1], out)
    elif sub_tag == _FILTER_EQUALITY:
        attr = _read_tlv(filt[1], 0)
        if attr is not None and attr[0] == _TAG_OCTET_STRING:
            val = _read_tlv(filt[1], attr[2])
            value = _as_text(val[1]) if val is not None else ""
            out.append((_as_text(attr[1]), value))
    return out


@dataclass(frozen=True)
class CldapMessage:
    """파싱된 CLDAP(UDP LDAP) 메시지 한 건.

    :class:`forensiclab.ldap.LdapMessage` 를 감싸 구조 필드를 위임하고,
    필터 assertion 과 CLDAP/UDP 전용 단서 속성을 더한다.

    Attributes:
        ldap: 위임 대상인 파싱된 LDAPMessage.
        filter_assertions: searchRequest 필터의 (속성, 값) equalityMatch 목록
            (CLDAP 는 :mod:`forensiclab.ldap` 가 건너뛰는 이 필터가 핵심).
    """

    ldap: LdapMessage
    filter_assertions: List[Tuple[str, str]] = field(default_factory=list)

    # --- 위임 편의 속성 ---------------------------------------------------
    @property
    def message_id(self) -> int:
        return self.ldap.message_id

    @property
    def op_type(self) -> int:
        return self.ldap.op_type

    @property
    def op_name(self) -> str:
        return self.ldap.op_name

    @property
    def base_object(self) -> Optional[str]:
        return self.ldap.base_object

    @property
    def scope(self) -> Optional[int]:
        return self.ldap.scope

    @property
    def attributes(self) -> List[str]:
        return self.ldap.attributes

    @property
    def result_code(self) -> Optional[int]:
        return self.ldap.result_code

    # --- CLDAP/UDP 전용 단서 ---------------------------------------------
    @property
    def is_search_request(self) -> bool:
        """CLDAP 질의(searchRequest) 여부."""
        return self.op_type == OP_SEARCH_REQUEST

    @property
    def is_search_response(self) -> bool:
        """CLDAP 응답(searchResultEntry/Done) 여부 — 반사 트래픽의 응답측."""
        return self.op_type in (OP_SEARCH_RESULT_ENTRY, OP_SEARCH_RESULT_DONE)

    @property
    def is_rootdse_query(self) -> bool:
        """rootDSE 질의(빈 baseObject + base 범위) 여부.

        반사 증폭의 트리거이자 DC 정찰의 진입점.
        """
        return (
            self.op_type == OP_SEARCH_REQUEST
            and (self.base_object or "") == ""
            and self.scope == SCOPE_BASE
        )

    @property
    def is_netlogon_query(self) -> bool:
        """Netlogon DC 로케이터(LDAP ping) 여부 — ``Netlogon`` 속성 요청."""
        return self.op_type == OP_SEARCH_REQUEST and any(
            a.lower() in NETLOGON_ATTRIBUTES for a in self.attributes
        )

    @property
    def dns_domain(self) -> Optional[str]:
        """DC 로케이터 필터의 ``DnsDomain``/``Domain`` 대상 도메인(있으면)."""
        for attr, value in self.filter_assertions:
            if attr.lower() in ("dnsdomain", "domain"):
                return value
        return None

    @property
    def queried_host(self) -> Optional[str]:
        """DC 로케이터 필터의 ``Host``/``DomainGuid`` 대상(있으면)."""
        for attr, value in self.filter_assertions:
            if attr.lower() == "host":
                return value
        return None

    @property
    def is_amplification_probe(self) -> bool:
        """반사·증폭 DDoS 의 rootDSE 탐침으로 보이는지.

        Netlogon 같은 특정 목적이 아닌, 큰 응답을 끌어내는 일반 rootDSE 질의
        (속성 미지정=전체 반환, 또는 ``*``/``+`` 와일드카드)를 반사 탐침으로
        본다.
        """
        if not self.is_rootdse_query or self.is_netlogon_query:
            return False
        attrs = self.attributes
        return not attrs or any(a in ("*", "+") for a in attrs)

    @property
    def recon_attributes(self) -> List[str]:
        """요청 속성 중 도메인 토폴로지 정찰 계열만 추린 목록."""
        return [a for a in self.attributes if a.lower() in ROOTDSE_RECON_ATTRIBUTES]


def parse_cldap(data: bytes, offset: int = 0) -> Optional[CldapMessage]:
    """원시 바이트(UDP 389 페이로드)에서 CLDAP 메시지 한 건을 파싱한다.

    구조 파싱은 :func:`forensiclab.ldap.parse_ldap` 에 위임하고, searchRequest
    면 필터의 equalityMatch 쌍을 추가로 뽑아 CLDAP 전용 단서를 채운다.

    Args:
        data: CLDAP 패킷 바이트(보통 UDP 389 페이로드 전체). CLDAP 은 한
            데이터그램에 LDAPMessage 한 건이라 보통 ``offset=0``.
        offset: 메시지 시작 위치(기본 0).

    Returns:
        :class:`CldapMessage`. LDAP 구조가 아니면 ``None``.
    """
    msg = parse_ldap(data, offset)
    if msg is None:
        return None

    assertions: List[Tuple[str, str]] = []
    if msg.op_type == OP_SEARCH_REQUEST:
        # parse_ldap 가 검증한 외곽 구조를 다시 따라가 searchRequest 본문에
        # 도달한 뒤 필터를 훑는다(검증은 이미 끝났으므로 안전하게 가정).
        outer = _read_tlv(data, offset)
        if outer is not None:
            mid = _read_tlv(outer[1], 0)
            if mid is not None:
                op = _read_tlv(outer[1], mid[2])
                if op is not None:
                    assertions = _parse_filter_assertions(op[1])

    return CldapMessage(ldap=msg, filter_assertions=assertions)
