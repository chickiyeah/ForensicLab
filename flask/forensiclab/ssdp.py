"""SSDP — Simple Service Discovery Protocol 파싱 코어 (UPnP).

:mod:`forensiclab.netdissect` 가 식별한 UDP(포트 1900) 페이로드는 SSDP
메시지일 수 있다. 이 모듈이 그 메시지를 해석한다(:mod:`forensiclab.dns` 가
UDP 53, :mod:`forensiclab.nbns` 가 UDP 137, :mod:`forensiclab.ntp` 가
UDP 123 를 다루는 것과 같은 위치).

SSDP 는 UPnP 장치가 자신을 알리고 서로를 찾는 HTTP-유사 평문 멀티캐스트
(239.255.255.250:1900)다. IoT·네트워크 장비가 그득한 환경의 침해/사고
분석에서 단서가 짙다(:mod:`forensiclab.syslog` 가 텍스트 한 줄을 다루듯,
이 모듈은 텍스트 헤더 블록을 다룬다):

- **SSDP 증폭 반사 DDoS**: ``M-SEARCH`` 질의(특히 ``ST: ssdp:all``)는
  작은 요청에 큰 장치 목록 응답을 끌어내, 출발지를 위조한 공격자가 피해자
  IP 로 응답을 쏟아붓는 반사 증폭에 악용된다(:mod:`forensiclab.ntp` mode
  6/7·:mod:`forensiclab.snmp` GetBulk 와 같은 증폭 벡터 계열). 짧은 간격의
  반복 ``M-SEARCH`` 와 ``ssdp:all`` 표적이 전형적 정황이다.
- **자산·호스트 정찰**: ``NOTIFY`` 광고·``200 OK`` 응답의 ``LOCATION``
  헤더는 장치 description XML 의 URL(IP·포트)을 드러내, 내부 자산 목록과
  공격면을 재구성한다. ``SERVER`` 헤더(OS·UPnP 스택·제품명)는 장치
  핑거프린트다.
- **장치 식별·상관**: ``USN``(Unique Service Name, 보통 ``uuid:``)·``NT``/
  ``ST``(서비스 타입)로 같은 장치를 시간에 걸쳐 추적한다
  (:mod:`forensiclab.timeline`·:mod:`forensiclab.flows` 와 짝지어).
- **악성 광고·UPnP 남용**: 위조 ``NOTIFY`` 로 가짜 장치를 심거나
  (evil-SSDP 류 피싱), IGD 포트 매핑 남용의 사전 정찰로 ``M-SEARCH`` 가
  앞선다.

메시지 포맷(HTTP/1.1 over UDP, CRLF 구분)::

    M-SEARCH * HTTP/1.1          (질의: 시작줄 = 메서드 SP 타깃 SP 버전)
    HOST: 239.255.255.250:1900
    MAN: "ssdp:discover"
    ST: ssdp:all
    MX: 2

    NOTIFY * HTTP/1.1            (광고)
    NT: upnp:rootdevice
    NTS: ssdp:alive
    USN: uuid:...::upnp:rootdevice
    LOCATION: http://192.168.0.1:5000/rootDesc.xml
    SERVER: Linux/3.14 UPnP/1.0 MiniUPnPd/1.9

    HTTP/1.1 200 OK             (M-SEARCH 응답: 시작줄 = 버전 SP 코드 SP 사유)
    ST: upnp:rootdevice
    USN: uuid:...

설계 원칙(:mod:`forensiclab.syslog`·:mod:`forensiclab.nbns` 와 동일):
- 부작용 없음: 순수 함수. 디스크/표준출력/네트워크 없음.
- stdlib 전용.
- 안전: 입력 바이트를 변형하지 않는다(읽기 전용).
- 견고: 너무 짧거나 망가진 입력은 예외 대신 ``None``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

__all__ = [
    "SSDP_MULTICAST",
    "SsdpMessage",
    "parse_ssdp",
]

# 표준 SSDP 멀티캐스트 종착지(IPv4). 정찰/증폭 트래픽 식별 기준점.
SSDP_MULTICAST = "239.255.255.250:1900"

# SSDP 가 쓰는 HTTP-유사 메서드(요청 시작줄). 이 셋 밖이면 SSDP 가 아니다.
_METHODS = ("M-SEARCH", "NOTIFY")


@dataclass(frozen=True)
class SsdpMessage:
    """파싱된 SSDP 메시지 하나(요청 또는 응답).

    Attributes:
        is_response: 응답(``HTTP/1.1 200 OK`` 류)이면 True, 요청이면 False.
        method: 요청 메서드(``M-SEARCH``·``NOTIFY``). 응답이면 ``None``.
        status_code: 응답 상태 코드(보통 200). 요청이면 ``None``.
        http_version: 시작줄의 HTTP 버전 문자열(예: ``HTTP/1.1``).
        headers: 소문자 키로 정규화된 헤더 사전(마지막 값 우선).
    """

    is_response: bool
    method: Optional[str]
    status_code: Optional[int]
    http_version: str
    headers: Dict[str, str] = field(default_factory=dict)

    def header(self, name: str) -> Optional[str]:
        """헤더를 대소문자 무관하게 조회(없으면 ``None``)."""
        return self.headers.get(name.lower())

    @property
    def search_target(self) -> Optional[str]:
        """검색/통지 타깃 — 요청은 ``ST``, 응답도 ``ST``, 광고는 ``NT``."""
        return self.header("st") or self.header("nt")

    @property
    def usn(self) -> Optional[str]:
        """Unique Service Name(보통 ``uuid:...``) — 장치 식별/상관 키."""
        return self.header("usn")

    @property
    def location(self) -> Optional[str]:
        """장치 description XML 의 URL — 자산(IP·포트) 정찰 단서."""
        return self.header("location")

    @property
    def server(self) -> Optional[str]:
        """``SERVER`` 헤더(OS·UPnP 스택·제품) — 장치 핑거프린트."""
        return self.header("server")

    @property
    def notification_subtype(self) -> Optional[str]:
        """``NTS``(``ssdp:alive``/``ssdp:byebye``) — 광고 종류."""
        return self.header("nts")

    @property
    def is_discovery(self) -> bool:
        """``M-SEARCH`` 질의 여부 — 정찰/증폭 반사의 시작점."""
        return self.method == "M-SEARCH"

    @property
    def is_amplification_probe(self) -> bool:
        """증폭 반사 DDoS 정황: ``ssdp:all`` 을 노린 ``M-SEARCH``.

        ``ST: ssdp:all`` 은 응답을 최대로 부풀려 반사 증폭에 쓰이는
        전형적 표적이다(:mod:`forensiclab.ntp`·:mod:`forensiclab.snmp` 의
        증폭 벡터와 같은 계열).
        """
        if not self.is_discovery:
            return False
        st = self.header("st")
        return st is not None and st.strip().lower() == "ssdp:all"


def _split_start_line(line: str) -> Optional[tuple]:
    """시작줄을 (is_response, method, status, version) 로 가른다.

    요청:  ``M-SEARCH * HTTP/1.1`` → (False, "M-SEARCH", None, "HTTP/1.1")
    응답:  ``HTTP/1.1 200 OK``     → (True, None, 200, "HTTP/1.1")
    형식이 SSDP 시작줄이 아니면 ``None``.
    """
    parts = line.split(None, 2)
    if len(parts) < 2:
        return None
    first = parts[0]
    if first.upper().startswith("HTTP/"):
        # 응답: HTTP-version SP status-code [SP reason].
        try:
            code = int(parts[1])
        except ValueError:
            return None
        return True, None, code, first
    # 요청: method SP target SP HTTP-version.
    if len(parts) < 3:
        return None
    method = first.upper()
    if method not in _METHODS:
        return None
    version = parts[2].strip()
    if not version.upper().startswith("HTTP/"):
        return None
    return False, method, None, version


def parse_ssdp(data: bytes, offset: int = 0) -> Optional[SsdpMessage]:
    """원시 바이트에서 SSDP 메시지를 파싱한다.

    Args:
        data: SSDP 패킷을 담은 바이트. 보통 UDP 1900 페이로드
            (:class:`forensiclab.netdissect` 의 ``payload_offset`` 부터)다.
        offset: 메시지가 시작하는 위치(기본 0).

    Returns:
        :class:`SsdpMessage`. 시작줄이 SSDP 요청(M-SEARCH·NOTIFY) 또는
        HTTP 응답 형식이 아니면 ``None``. 헤더는 ``Key: value`` 줄을
        CRLF/LF 로 끊어 읽으며, 콜론이 없는 줄은 건너뛴다.
    """
    if offset < 0 or offset > len(data):
        return None
    chunk = data[offset:]
    if not chunk:
        return None
    # SSDP 는 ASCII 텍스트. 비텍스트 바이트는 관대하게 무시(replace)한다.
    try:
        text = chunk.decode("ascii", "replace")
    except Exception:  # pragma: no cover - decode replace 는 예외를 안 냄
        return None
    # 헤더 블록은 빈 줄(CRLFCRLF)에서 끝난다 — 본문이 있어도 잘라낸다.
    head = text.split("\r\n\r\n", 1)[0].split("\n\n", 1)[0]
    lines = head.replace("\r\n", "\n").split("\n")
    if not lines or not lines[0].strip():
        return None

    parsed = _split_start_line(lines[0].strip())
    if parsed is None:
        return None
    is_response, method, status_code, http_version = parsed

    headers: Dict[str, str] = {}
    for line in lines[1:]:
        if not line.strip():
            continue
        idx = line.find(":")
        if idx <= 0:
            continue
        key = line[:idx].strip().lower()
        value = line[idx + 1:].strip()
        headers[key] = value

    return SsdpMessage(
        is_response=is_response,
        method=method,
        status_code=status_code,
        http_version=http_version,
        headers=headers,
    )
