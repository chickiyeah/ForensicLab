"""네트워크 흐름(flow/conversation) 재구성 코어.

:mod:`forensiclab.netdissect` 가 패킷 한 개를 L2~L4 로 해석한다면, 이 모듈은
그렇게 해석한 여러 패킷을 *양방향 대화(flow)* 로 합친다. 침해 분석에서
"누가 누구와, 어떤 포트로, 얼마나 오래·얼마만큼 통신했는가" 를 한눈에 보는
것은 스캔·비콘(C2)·대량 유출 탐지의 출발점이다.

핵심 개념:
- 흐름 키는 5-튜플(프로토콜·양 끝 IP·양 끝 포트)이며, A→B 와 B→A 가 같은
  대화로 묶이도록 두 끝점을 정규(canonical) 순서로 정렬한다.
- 각 흐름은 전체 패킷 수·바이트 수와 방향별 패킷 수, 그리고 (시각이 있으면)
  처음·마지막 관측 시각을 누적한다.

설계 원칙(:mod:`forensiclab.netdissect`·:mod:`forensiclab.timeline` 와 동일):
- 부작용 없음: 디스크/표준출력 없이 순수 함수 (테스트 용이).
- stdlib 전용: 외부 의존성 없음.
- 안전: 입력을 변형하지 않는다(읽기 전용, 새 객체 반환).
- 견고: IPv4 해석이 없는 패킷(ARP·잘린 캡처 등)은 흐름에서 조용히 제외한다.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, List, Optional, Tuple

from forensiclab.netdissect import IP_PROTO_TCP, IP_PROTO_UDP, IP_PROTO_ICMP, Dissection

__all__ = [
    "FlowKey",
    "Flow",
    "flow_key",
    "aggregate_flows",
]

# 포트가 없는(ICMP 등) 끝점을 정렬·비교할 때 쓰는 자리표시 값.
_NO_PORT_SORT = -1


@dataclass(frozen=True)
class FlowKey:
    """양방향 흐름을 식별하는 정규 5-튜플.

    끝점 A 는 항상 ``(ip, port)`` 가 사전식으로 작거나 같은 쪽이다. 덕분에
    같은 대화의 양방향 패킷이 동일한 키로 묶인다.

    Attributes:
        protocol: IP 상위 프로토콜 번호(6=TCP, 17=UDP, 1=ICMP …).
        ip_a: 정규 순서상 앞쪽 끝점 IP.
        port_a: 끝점 A 의 L4 포트(TCP/UDP 만; 그 외 ``None``).
        ip_b: 정규 순서상 뒤쪽 끝점 IP.
        port_b: 끝점 B 의 L4 포트.
    """

    protocol: int
    ip_a: str
    port_a: Optional[int]
    ip_b: str
    port_b: Optional[int]

    @property
    def protocol_name(self) -> str:
        """프로토콜의 짧은 이름(``"TCP"``/``"UDP"``/``"ICMP"``/숫자)."""
        return {
            IP_PROTO_TCP: "TCP",
            IP_PROTO_UDP: "UDP",
            IP_PROTO_ICMP: "ICMP",
        }.get(self.protocol, str(self.protocol))


@dataclass
class Flow:
    """한 양방향 대화로 누적된 통계.

    Attributes:
        key: 이 흐름의 정규 5-튜플.
        packets: 양방향 합산 패킷 수.
        bytes_total: 양방향 합산 바이트 수(관측 길이의 합).
        a_to_b_packets: 끝점 A→B 방향 패킷 수.
        b_to_a_packets: 끝점 B→A 방향 패킷 수.
        first_seen: 처음 관측 시각(시각 없으면 ``None``).
        last_seen: 마지막 관측 시각(시각 없으면 ``None``).
    """

    key: FlowKey
    packets: int = 0
    bytes_total: int = 0
    a_to_b_packets: int = 0
    b_to_a_packets: int = 0
    first_seen: Optional[float] = None
    last_seen: Optional[float] = None

    @property
    def duration(self) -> Optional[float]:
        """``last_seen - first_seen`` 초. 시각이 없으면 ``None``."""
        if self.first_seen is None or self.last_seen is None:
            return None
        return self.last_seen - self.first_seen


def _endpoint_sort(ip: str, port: Optional[int]) -> Tuple[str, int]:
    """끝점 비교용 키(포트 ``None`` 을 정렬 가능한 값으로 바꿈)."""
    return (ip, _NO_PORT_SORT if port is None else port)


def flow_key(dissection: Dissection) -> Optional[FlowKey]:
    """해석된 패킷에서 정규 흐름 키를 만든다.

    Args:
        dissection: :func:`forensiclab.netdissect.dissect` 결과.

    Returns:
        :class:`FlowKey`. IPv4 해석이 없으면(L3 미해석) ``None``.
    """
    ip = dissection.ipv4
    if ip is None:
        return None
    a = (ip.src_ip, dissection.src_port)
    b = (ip.dst_ip, dissection.dst_port)
    if _endpoint_sort(*a) <= _endpoint_sort(*b):
        ip_a, port_a, ip_b, port_b = a[0], a[1], b[0], b[1]
    else:
        ip_a, port_a, ip_b, port_b = b[0], b[1], a[0], a[1]
    return FlowKey(ip.protocol, ip_a, port_a, ip_b, port_b)


def aggregate_flows(
    packets: Iterable[Tuple[Dissection, int, Optional[float]]],
) -> List[Flow]:
    """해석된 패킷들을 양방향 흐름으로 누적한다.

    Args:
        packets: ``(dissection, length, timestamp)`` 3-튜플의 이터러블.
            ``length`` 는 그 패킷의 바이트 수, ``timestamp`` 는 캡처 시각(없으면
            ``None``). :class:`forensiclab.pcap.Packet` 의 ``data``·길이·``timestamp``
            를 :func:`forensiclab.netdissect.dissect` 에 흘려 만들면 된다.

    Returns:
        :class:`Flow` 목록. 처음 관측된 순서로 정렬되며, IPv4 가 없는 패킷은
        제외된다. 입력은 변형하지 않는다.
    """
    flows: dict[FlowKey, Flow] = {}
    for dissection, length, timestamp in packets:
        key = flow_key(dissection)
        if key is None:
            continue
        flow = flows.get(key)
        if flow is None:
            flow = Flow(key=key)
            flows[key] = flow
        flow.packets += 1
        flow.bytes_total += length
        # 방향: 이 패킷의 출발 끝점이 정규 A 면 A→B, 아니면 B→A.
        src_endpoint = (dissection.ipv4.src_ip, dissection.src_port)  # type: ignore[union-attr]
        if _endpoint_sort(*src_endpoint) == _endpoint_sort(key.ip_a, key.port_a):
            flow.a_to_b_packets += 1
        else:
            flow.b_to_a_packets += 1
        if timestamp is not None:
            if flow.first_seen is None or timestamp < flow.first_seen:
                flow.first_seen = timestamp
            if flow.last_seen is None or timestamp > flow.last_seen:
                flow.last_seen = timestamp
    return list(flows.values())
