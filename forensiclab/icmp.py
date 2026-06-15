"""ICMP — IPv4 제어 메시지 파싱 코어 (RFC 792).

:mod:`forensiclab.netdissect` 는 IPv4 페이로드의 상위 프로토콜이 ICMP(번호 1)
임을 *식별만* 하고(TCP/UDP 처럼 포트가 없으므로) 그 본문은 건드리지 않는다.
이 모듈이 그 본문 — ICMP 헤더 — 을 해석한다.

ICMP 는 침해 분석에서 두 갈래로 쓸모 있다:

- **정찰·터널링 단서**: ping 스윕(다수 호스트로 가는 echo request), 비정상적으로
  큰/일정한 payload 를 가진 echo (ICMP 터널은 echo 본문에 데이터를 실어 나른다),
  반복되는 identifier/sequence 패턴 등.
- **연결 실패 진단**: destination unreachable(타입 3)·time exceeded(타입 11)
  같은 오류 메시지는 *원래 보낸 패킷의 IP 헤더 + 첫 8바이트* 를 본문에 되돌려
  담는다(RFC 792). 그 안의 출발/목적 주소·포트로 어떤 흐름이 막혔는지 짚는다.

ICMP 메시지 형식(RFC 792)::

    byte     type
    byte     code
    uint16   checksum
    byte[4]  rest of header   (타입마다 의미가 다름)
    byte[n]  payload

- echo request(8)·echo reply(0): rest of header = identifier(2) + sequence(2).
- destination unreachable(3)·time exceeded(11) 등 오류: rest of header 4바이트는
  (대개) 미사용, payload 에 원본 IP 헤더+8바이트가 담긴다.

이 모듈은 rest of header 를 원시 4바이트로 보존하고, echo 계열은
:attr:`Icmp.echo` 로 (identifier, sequence) 를 풀어 준다. 오류 메시지의 내장
원본 패킷 파싱은 호출자가 :mod:`forensiclab.netdissect` 의 :func:`dissect_ipv4`
로 ``payload`` 를 다시 해석하면 된다(여기선 원시 payload 만 떼어 준다).

설계 원칙(:mod:`forensiclab.netdissect` 와 동일):
- 부작용 없음: 순수 함수. 디스크/표준출력/네트워크 없음.
- stdlib 전용.
- 안전: 입력 바이트를 변형하지 않는다(읽기 전용).
- 견고: 너무 짧거나 망가진 입력은 예외 대신 ``None``.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Optional, Tuple

__all__ = [
    "ICMP_ECHO_REPLY",
    "ICMP_DEST_UNREACHABLE",
    "ICMP_ECHO_REQUEST",
    "ICMP_TIME_EXCEEDED",
    "Icmp",
    "parse_icmp",
    "verify_checksum",
]

# 자주 보는 ICMP 타입 코드(RFC 792 / IANA).
ICMP_ECHO_REPLY = 0
ICMP_DEST_UNREACHABLE = 3
ICMP_ECHO_REQUEST = 8
ICMP_TIME_EXCEEDED = 11

_ICMP_HEADER_SIZE = 8  # type(1)+code(1)+checksum(2)+rest of header(4).

# type → 짧은 이름(IANA ICMP Type Numbers 의 흔한 값들).
_TYPE_NAMES = {
    0: "echo-reply",
    3: "dest-unreachable",
    4: "source-quench",
    5: "redirect",
    8: "echo-request",
    9: "router-advertisement",
    10: "router-solicitation",
    11: "time-exceeded",
    12: "parameter-problem",
    13: "timestamp",
    14: "timestamp-reply",
}


@dataclass(frozen=True)
class Icmp:
    """파싱된 ICMP 메시지 헤더.

    Attributes:
        type: ICMP 타입(8=echo request, 0=echo reply, 3=unreachable …).
        code: 타입 내 세부 코드(예: unreachable 의 0=net, 1=host, 3=port).
        checksum: 헤더가 담고 있는 16비트 체크섬(검증은 :func:`verify_checksum`).
        rest_of_header: rest of header 4바이트 원본(타입마다 의미가 다름).
        payload: ICMP 헤더(8바이트) 뒤의 나머지 바이트. echo 는 데이터,
            오류 메시지는 원본 IP 헤더+8바이트.
    """

    type: int
    code: int
    checksum: int
    rest_of_header: bytes
    payload: bytes

    @property
    def type_name(self) -> str:
        """ICMP 타입의 짧은 이름(미상이면 ``"type-<n>"``)."""
        return _TYPE_NAMES.get(self.type, f"type-{self.type}")

    @property
    def is_echo(self) -> bool:
        """echo request(8) 또는 echo reply(0) 인가."""
        return self.type in (ICMP_ECHO_REQUEST, ICMP_ECHO_REPLY)

    @property
    def is_error(self) -> bool:
        """payload 에 원본 패킷을 되담는 오류 메시지 계열인가.

        unreachable(3)·source-quench(4)·redirect(5)·time-exceeded(11)·
        parameter-problem(12) 이 해당한다(RFC 792).
        """
        return self.type in (3, 4, 5, 11, 12)

    @property
    def echo(self) -> Optional[Tuple[int, int]]:
        """echo 계열이면 (identifier, sequence), 아니면 ``None``.

        rest of header 4바이트를 ``uint16 identifier`` + ``uint16 sequence``
        (둘 다 빅엔디언)로 푼다.
        """
        if not self.is_echo:
            return None
        identifier, sequence = struct.unpack(">HH", self.rest_of_header)
        return identifier, sequence


def parse_icmp(data: bytes, offset: int = 0) -> Optional[Icmp]:
    """원시 바이트에서 ICMP 메시지를 파싱한다.

    Args:
        data: ICMP 메시지를 담은 바이트. 보통 :class:`forensiclab.netdissect.IPv4`
            의 ``payload_offset`` 부터다.
        offset: ICMP 헤더가 시작하는 위치(기본 0).

    Returns:
        :class:`Icmp`. 헤더(8바이트)에 못 미치게 짧으면 ``None``.
    """
    if offset < 0 or offset + _ICMP_HEADER_SIZE > len(data):
        return None
    icmp_type = data[offset]
    code = data[offset + 1]
    checksum = struct.unpack(">H", data[offset + 2:offset + 4])[0]
    rest_of_header = data[offset + 4:offset + 8]
    payload = data[offset + _ICMP_HEADER_SIZE:]
    return Icmp(
        type=icmp_type,
        code=code,
        checksum=checksum,
        rest_of_header=rest_of_header,
        payload=payload,
    )


def verify_checksum(data: bytes, offset: int = 0) -> Optional[bool]:
    """ICMP 메시지의 체크섬이 올바른지 확인한다.

    ICMP 체크섬은 체크섬 필드를 0 으로 둔 ICMP 메시지 전체에 대한 16비트
    1의 보수 합의 1의 보수다(RFC 1071). 메시지 전체가 온전히 있어야 의미가
    있으므로, 잘린 캡처(snaplen)나 오류 메시지의 일부만 든 경우 결과가 거짓
    음성일 수 있다 — 호출자가 전체 길이를 확보했을 때만 신뢰한다.

    Args:
        data: ICMP 메시지를 담은 바이트.
        offset: ICMP 헤더가 시작하는 위치.

    Returns:
        체크섬이 맞으면 ``True``, 틀리면 ``False``. 헤더에 못 미치게 짧으면
        ``None``.
    """
    if offset < 0 or offset + _ICMP_HEADER_SIZE > len(data):
        return None
    segment = data[offset:]
    total = 0
    # 16비트 워드 단위로 합산. 길이가 홀수면 마지막 바이트를 상위로 패딩.
    for i in range(0, len(segment) - 1, 2):
        total += (segment[i] << 8) | segment[i + 1]
    if len(segment) % 2 == 1:
        total += segment[-1] << 8
    # 캐리를 접어 16비트로.
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return total == 0xFFFF
