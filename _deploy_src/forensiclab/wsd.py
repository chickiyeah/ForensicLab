"""WSD — WS-Discovery (WS-Dynamic Discovery) 파싱 코어.

:mod:`forensiclab.netdissect` 가 식별한 UDP(포트 3702) 페이로드는 WS-Discovery
메시지일 수 있다. 이 모듈이 그 메시지를 해석한다(:mod:`forensiclab.ssdp` 가
UDP 1900, :mod:`forensiclab.mdns` 가 UDP 5353, :mod:`forensiclab.llmnr` 가
UDP 5355 를 다루는 것과 같은 위치).

WS-Discovery 는 SOAP 1.2 봉투를 UDP 멀티캐스트(239.255.255.250:3702·IPv6
FF02::C)에 얹어 장치를 알리고/찾는 프로토콜이다. SSDP(UPnP)가 HTTP-유사
평문 멀티캐스트라면 WSD 는 **XML(SOAP) 멀티캐스트** — Windows 의 네트워크
장치 탐색, 그리고 ONVIF IP 카메라·네트워크 프린터·NAS 가 같은 표면을 쓴다.
:mod:`forensiclab.ssdp`·:mod:`forensiclab.mdns`·:mod:`forensiclab.llmnr`·
:mod:`forensiclab.nbns` 와 **링크-로컬/멀티캐스트 탐색 형제**이면서, 동시에
**UDP 반사·증폭 DDoS 벡터 형제**(:mod:`forensiclab.ntp`·:mod:`forensiclab.snmp`·
:mod:`forensiclab.ssdp`·:mod:`forensiclab.memcached`·:mod:`forensiclab.cldap`)다:

- **WS-Discovery 증폭 반사 DDoS**: ``Probe`` 질의(특히 ``Types``·``Scopes``
  를 비워 *모든* 장치를 노린 와일드카드 탐침)는 작은 UDP 한 방에 큰
  ``ProbeMatches`` 응답을 끌어낸다. 인터넷에 노출된 UDP 3702 는 알려진
  최대급 반사 증폭 벡터(관측상 ~수백 배, BinaryEdge/Akamai 2019)로,
  출발지 위조 공격자가 피해자 IP 로 응답을 쏟아붓는다.
  ``is_amplification_probe`` 가 이 와일드카드 ``Probe`` 정황을 짚는다.
- **자산·장치 정찰**: ``Probe`` 의 ``Types``(예: ONVIF 카메라
  ``dn:NetworkVideoTransmitter``·프린터 ``PrintDeviceType``)는 무엇을 찾는지,
  ``Hello``/``ProbeMatch``/``ResolveMatch`` 의 ``XAddrs``(``device_addresses``)는
  장치 서비스 URL(IP·포트)을 그대로 드러내 내부 자산 지도·공격면을 재구성한다
  (:mod:`forensiclab.ssdp` 의 ``LOCATION`` 대응).
- **장치 식별·상관**: ``EndpointReference`` 의 ``Address``(보통
  ``urn:uuid:...``)와 ``MessageID``·``RelatesTo`` 로 같은 장치/질의-응답을
  시간에 걸쳐 추적한다(:mod:`forensiclab.timeline`·:mod:`forensiclab.flows` 와
  짝지어). ``Scopes`` 의 ``onvif://``·MAC·하드웨어 정보는 장치 핑거프린트다.
- **악성 광고/위장**: 위조 ``Hello`` 로 가짜 장치를 심거나(중간자 유인),
  대량 ``Probe`` 정찰이 침해 전개에 앞선다.

메시지 포맷(SOAP 1.2 over UDP)::

    <soap:Envelope xmlns:soap=".../soap-envelope"
                   xmlns:wsa=".../addressing"
                   xmlns:wsd=".../discovery">
      <soap:Header>
        <wsa:Action>.../discovery/Probe</wsa:Action>
        <wsa:MessageID>urn:uuid:...</wsa:MessageID>
        <wsa:To>urn:.../ws-discovery</wsa:To>
      </soap:Header>
      <soap:Body>
        <wsd:Probe>
          <wsd:Types>dn:NetworkVideoTransmitter</wsd:Types>
          <wsd:Scopes>onvif://www.onvif.org/...</wsd:Scopes>
        </wsd:Probe>
      </soap:Body>
    </soap:Envelope>

설계 원칙(:mod:`forensiclab.ssdp`·:mod:`forensiclab.mdns` 와 동일):
- 부작용 없음: 순수 함수. 디스크/표준출력/네트워크 없음.
- stdlib 전용(``xml.etree.ElementTree``).
- 안전: 입력 바이트를 변형하지 않는다(읽기 전용). XML 엔티티 폭탄 방어 —
  ``DOCTYPE``/``ENTITY`` 선언이 있으면 거부(정상 WSD 엔 DTD 가 없으므로
  그 자체가 이상 정황이기도 하다).
- 견고: 너무 짧거나 망가진/비-WSD 입력은 예외 대신 ``None``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional
from xml.etree import ElementTree as ET

__all__ = [
    "WSD_MULTICAST",
    "WSD_NS_DISCOVERY",
    "WSD_MESSAGE_TYPES",
    "WsdMessage",
    "parse_wsd",
]

# 표준 WS-Discovery 멀티캐스트 종착지(IPv4). 정찰/증폭 트래픽 식별 기준점.
WSD_MULTICAST = "239.255.255.250:3702"

# WS-Discovery 네임스페이스(2005/04 판이 가장 흔하며 2009 판도 존재).
# 메시지 검증·메시지 타입 판별의 기준이지만, 판 차이를 너그럽게 보려고
# 실제 비교는 localname 기준으로 한다.
WSD_NS_DISCOVERY = "http://schemas.xmlsoap.org/ws/2005/04/discovery"

# wsa:Action localname(과 body 요소 localname)으로 식별하는 메시지 종류.
WSD_MESSAGE_TYPES = (
    "Hello",
    "Bye",
    "Probe",
    "ProbeMatches",
    "Resolve",
    "ResolveMatches",
)

# 질의(요청) 쪽 메시지 — 정찰/증폭의 시작점.
_REQUEST_TYPES = frozenset({"Probe", "Resolve"})

# DTD/엔티티 선언 탐지(billion-laughs 등 XML 폭탄 방어 + 이상 정황 신호).
_DOCTYPE_RE = re.compile(rb"<!\s*(DOCTYPE|ENTITY)", re.IGNORECASE)


def _localname(tag: str) -> str:
    """``{namespace}Local`` 형태의 ElementTree 태그에서 localname 만."""
    return tag.rsplit("}", 1)[-1]


def _find_local(parent, name: str):
    """자식 중 localname 이 ``name`` 인 첫 요소(없으면 ``None``)."""
    for child in parent:
        if _localname(child.tag) == name:
            return child
    return None


def _iter_local(root, name: str):
    """트리 전체에서 localname 이 ``name`` 인 모든 요소."""
    for el in root.iter():
        if _localname(el.tag) == name:
            yield el


def _tokens(el) -> List[str]:
    """공백으로 나뉜 토큰 목록(``Types``/``Scopes``/``XAddrs`` 본문)."""
    if el is None or not el.text:
        return []
    return el.text.split()


@dataclass(frozen=True)
class WsdMessage:
    """파싱된 WS-Discovery 메시지 하나.

    Attributes:
        action: ``wsa:Action`` URI 전체(예: ``.../discovery/Probe``). 없으면 ``None``.
        message_type: 메시지 종류(:data:`WSD_MESSAGE_TYPES` 중 하나). Action
            localname 으로, 없으면 body 요소 localname 으로 판별. 미상이면 ``None``.
        message_id: ``wsa:MessageID``(보통 ``urn:uuid:...``) — 메시지 식별 키.
        relates_to: ``wsa:RelatesTo`` — 응답이 답하는 요청의 MessageID(상관 키).
        to: ``wsa:To`` — 종착지 URI.
        endpoint_reference: body 의 ``wsa:Address``(장치 EPR, 보통 ``urn:uuid:``).
        types: ``Types`` QName 토큰 목록(장치 종류 핑거프린트).
        scopes: ``Scopes`` URI 토큰 목록(``onvif://``·MAC·하드웨어 등).
        xaddrs: ``XAddrs`` 전송 주소(장치 서비스 URL, IP·포트 정찰 단서).
        metadata_version: ``MetadataVersion`` 정수(장치 메타데이터 세대).
    """

    action: Optional[str]
    message_type: Optional[str]
    message_id: Optional[str]
    relates_to: Optional[str]
    to: Optional[str]
    endpoint_reference: Optional[str]
    types: List[str] = field(default_factory=list)
    scopes: List[str] = field(default_factory=list)
    xaddrs: List[str] = field(default_factory=list)
    metadata_version: Optional[int] = None

    @property
    def is_request(self) -> bool:
        """질의(``Probe``·``Resolve``) 여부 — 정찰/증폭의 시작점."""
        return self.message_type in _REQUEST_TYPES

    @property
    def is_response(self) -> bool:
        """응답/광고(``ProbeMatches``·``ResolveMatches``·``Hello``·``Bye``) 여부."""
        return self.message_type is not None and self.message_type not in _REQUEST_TYPES

    @property
    def is_probe(self) -> bool:
        """``Probe`` 질의 여부."""
        return self.message_type == "Probe"

    @property
    def device_addresses(self) -> List[str]:
        """장치 서비스 URL 목록(``XAddrs``) — 자산(IP·포트) 정찰 단서."""
        return self.xaddrs

    @property
    def is_amplification_probe(self) -> bool:
        """증폭 반사 DDoS 정황: ``Types``·``Scopes`` 가 빈 와일드카드 ``Probe``.

        타입/스코프를 지정하지 않은 ``Probe`` 는 *모든* 장치가 응답하게 만들어
        응답을 최대로 부풀린다 — 인터넷에 노출된 UDP 3702 를 노린 반사 증폭의
        전형적 표적이다(:mod:`forensiclab.ssdp` 의 ``ssdp:all``·
        :mod:`forensiclab.cldap` 의 rootDSE 질의와 같은 계열).
        """
        return self.is_probe and not self.types and not self.scopes


def parse_wsd(data: bytes, offset: int = 0) -> Optional[WsdMessage]:
    """원시 바이트에서 WS-Discovery(SOAP) 메시지를 파싱한다.

    Args:
        data: WSD 패킷을 담은 바이트. 보통 UDP 3702 페이로드
            (:class:`forensiclab.netdissect` 의 ``payload_offset`` 부터)다.
        offset: 메시지가 시작하는 위치(기본 0).

    Returns:
        :class:`WsdMessage`. SOAP ``Envelope`` 가 아니거나, WS-Discovery
        메시지로 식별되지 않거나, XML 파싱이 실패하면 ``None``. ``DOCTYPE``/
        ``ENTITY`` 선언이 있으면(엔티티 폭탄 방어) 거부한다.
    """
    if offset < 0 or offset > len(data):
        return None
    chunk = data[offset:].strip()
    if not chunk or _DOCTYPE_RE.search(chunk):
        return None
    # 빠른 사전 검증: SOAP 봉투처럼 보여야 한다(비-XML/비-WSD 조기 차단).
    if b"Envelope" not in chunk:
        return None

    try:
        root = ET.fromstring(chunk)
    except ET.ParseError:
        return None
    except Exception:  # pragma: no cover - 방어적: 예기치 못한 디코딩 등
        return None

    if _localname(root.tag) != "Envelope":
        return None

    header = _find_local(root, "Header")
    body = _find_local(root, "Body")

    action = message_id = relates_to = to = None
    if header is not None:
        a = _find_local(header, "Action")
        if a is not None and a.text:
            action = a.text.strip()
        m = _find_local(header, "MessageID")
        if m is not None and m.text:
            message_id = m.text.strip()
        r = _find_local(header, "RelatesTo")
        if r is not None and r.text:
            relates_to = r.text.strip()
        t = _find_local(header, "To")
        if t is not None and t.text:
            to = t.text.strip()

    # 메시지 타입: 우선 Action localname, 없으면 body 요소 localname.
    message_type = None
    if action:
        cand = action.rstrip("/").rsplit("/", 1)[-1]
        if cand in WSD_MESSAGE_TYPES:
            message_type = cand
    if message_type is None and body is not None:
        for child in body:
            cand = _localname(child.tag)
            if cand in WSD_MESSAGE_TYPES:
                message_type = cand
                break

    # WS-Discovery 메시지로 식별되지 않으면(임의 SOAP 차단) None.
    if message_type is None:
        ns_seen = any("discovery" in el.tag for el in root.iter() if "}" in el.tag)
        if not ns_seen:
            return None

    # Types/Scopes/XAddrs/MetadataVersion/EndpointReference — body 전체에서 수집.
    # (ProbeMatches 는 ProbeMatch 가 여러 개일 수 있어 전부 누적.)
    types: List[str] = []
    scopes: List[str] = []
    xaddrs: List[str] = []
    metadata_version: Optional[int] = None
    endpoint_reference = None
    search_root = body if body is not None else root

    for el in _iter_local(search_root, "Types"):
        types.extend(_tokens(el))
    for el in _iter_local(search_root, "Scopes"):
        scopes.extend(_tokens(el))
    for el in _iter_local(search_root, "XAddrs"):
        xaddrs.extend(_tokens(el))
    for el in _iter_local(search_root, "MetadataVersion"):
        if el.text and el.text.strip():
            try:
                metadata_version = int(el.text.strip())
            except ValueError:
                pass
            break
    # EndpointReference/Address: 장치 EPR(첫 번째).
    epr = _find_local(search_root, "EndpointReference") if body is not None else None
    if epr is None:
        for el in _iter_local(search_root, "EndpointReference"):
            epr = el
            break
    if epr is not None:
        addr = _find_local(epr, "Address")
        if addr is not None and addr.text:
            endpoint_reference = addr.text.strip()

    return WsdMessage(
        action=action,
        message_type=message_type,
        message_id=message_id,
        relates_to=relates_to,
        to=to,
        endpoint_reference=endpoint_reference,
        types=types,
        scopes=scopes,
        xaddrs=xaddrs,
        metadata_version=metadata_version,
    )
