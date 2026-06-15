"""SCTP — Stream Control Transmission Protocol 공통 헤더·청크 파싱 코어 (RFC 4960; IP proto 132).

:mod:`forensiclab.diameter` 가 "TCP/SCTP 3868 위에서 동작한다"고 했을 때 그
**SCTP 가 바로 이 모듈이 푸는 전송 계층**이다. TCP·UDP 의 형제격 4세대 전송
프로토콜로, TCP 의 신뢰성·혼잡 제어를 가지면서도 UDP 처럼 **메시지 지향**이고
무엇보다 **멀티스트리밍**(한 연결 안 여러 독립 스트림, head-of-line 블로킹 회피)과
**멀티호밍**(한 종단이 여러 IP 보유, 경로 장애 시 자동 전환)을 더했다. 그래서
이동통신 코어망의 신호 전송 표준이다 — SS7 의 IP 시대 후신인 SIGTRAN(M3UA·SUA,
2905) 과 :mod:`forensiclab.diameter`(3868) 가 모두 SCTP 위에서 돌고, WebRTC 의
데이터 채널(DTLS-over-SCTP)도 마찬가지다.

TCP 처럼 세그먼트 하나에 헤더+데이터가 아니라, **12바이트 공통 헤더** 뒤에
**청크(chunk)** 들이 줄지어 붙는다(제어 청크 INIT/SACK/HEARTBEAT 와 데이터 청크
DATA 가 한 패킷에 섞일 수 있다). 본 파서는 :mod:`forensiclab.diameter`·
:mod:`forensiclab.gtp` 와 동일하게 **공통 헤더(12바이트)만** 풀고, 청크는
값(value)을 풀지 않은 채 **타입/플래그/길이 헤더만** 훑어 어떤 청크들이 실렸는지
열거하고 본문은 ``payload_offset`` 으로만 가리킨다(읽기 전용).

와이어 포맷(RFC 4960 §3.1, 12바이트 공통 헤더, big-endian)::

    source_port(2) | dest_port(2) | verification_tag(4) | checksum(4)

이어서 청크들(각 청크 헤더 4바이트, RFC 4960 §3.2)::

    chunk_type(1) | chunk_flags(1) | chunk_length(2) | value(...)
    (chunk_length 는 헤더 4 포함, 다음 청크는 4바이트 경계로 패딩)

- **source_port/dest_port**: TCP/UDP 와 같은 의미의 포트. 3868=Diameter·
  2905=M3UA(SS7) 면 코어망 신호 평면이라는 강한 정황.
- **verification_tag**: 연결(association) 식별 태그. 수신측이 이 association 을
  위해 발급한 값으로, **INIT 청크를 담은 패킷에서는 반드시 0**(아직 태그 협상
  전) — 그 외에는 0이 아니어야 한다(스푸핑/주입 탐지 단서). :mod:`forensiclab.esp`
  의 SPI·:mod:`forensiclab.gtp` 의 TEID 처럼 한 association 을 못 박는 상관 키.
- **checksum**: 패킷 전체 CRC32c. 본 파서는 검증하지 않는다(절단 캡처·비용).
- **청크 타입**: 1=INIT·2=INIT-ACK 가 연결 개시(4-way 핸드셰이크), 0=DATA 가
  사용자 데이터, 6=ABORT·7=SHUTDOWN 이 종료, 4=HEARTBEAT 가 경로 생존 확인.

침해/사고 분석에서 공통 헤더·청크 타입이 드러내는 것:

- **신호 평면 전송 식별**: 노출된 SCTP(IP proto 132) 자체가 흔치 않아 코어망·
  통신 인프라 정황이 짙다. 포트가 3868/2905 면 :mod:`forensiclab.diameter`·
  SS7 신호가 그 위에 실린다는 강한 단서.
- **연결 수립 흐름**: INIT→INIT-ACK→COOKIE-ECHO→COOKIE-ACK 4단계를
  :mod:`forensiclab.timeline` 에서 복원. INIT 만 쏟아지고 INIT-ACK 가 없으면
  **INIT 플러딩(SYN 플러드의 SCTP 판)** 또는 포트 스캔(sctpscan) 단서.
- **연결 리셋·종료**: ABORT 폭주는 강제 절단(스푸핑 공격·정책 차단),
  SHUTDOWN 은 정상 종료 — TCP 의 RST/FIN 에 대응.
- **association 상관**: verification_tag 로 :mod:`forensiclab.flows` 의 IP 쌍을
  가로질러 한 association 의 양방향을 짝짓는다. INIT 패킷의 태그가 0이 아니면
  비정상(주입·재생 공격 의심).

설계 원칙(:mod:`forensiclab.diameter`·:mod:`forensiclab.gtp` 와 동일):
- 부작용 없음·stdlib 전용·읽기 전용(입력 무변형).
- 견고: 12바이트 미만·청크 헤더 없음·첫 청크 길이<4 면 예외 대신 ``None``.
- 청크 값(value)은 풀지 않고 타입/플래그/길이만 훑는다. 체크섬 미검증.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Optional, Tuple

__all__ = [
    "SCTP_HEADER_LEN",
    "SCTP_CHUNK_HEADER_LEN",
    "Sctp",
    "SctpChunk",
    "parse_sctp",
]

# 공통 헤더 길이(RFC 4960 §3.1).
SCTP_HEADER_LEN = 12

# 청크 헤더 길이(type 1 + flags 1 + length 2).
SCTP_CHUNK_HEADER_LEN = 4

# 청크 타입 이름(RFC 4960 §3.3 외).
_CHUNK_NAMES = {
    0: "DATA",                 # 사용자 데이터.
    1: "INIT",                 # 연결 개시(verification_tag=0).
    2: "INIT-ACK",             # 개시 응답(쿠키 전달).
    3: "SACK",                 # 선택적 확인 응답.
    4: "HEARTBEAT",            # 경로 생존 확인(멀티호밍).
    5: "HEARTBEAT-ACK",        # 생존 응답.
    6: "ABORT",                # 강제 절단(TCP RST 대응).
    7: "SHUTDOWN",             # 정상 종료 개시.
    8: "SHUTDOWN-ACK",         # 종료 응답.
    9: "ERROR",                # 오류 통보.
    10: "COOKIE-ECHO",         # 쿠키 반향(핸드셰이크 3단계).
    11: "COOKIE-ACK",          # 쿠키 확인(핸드셰이크 4단계).
    13: "ECNE",                # 명시적 혼잡 통보 에코.
    14: "SHUTDOWN-COMPLETE",   # 종료 완료.
    15: "AUTH",                # 청크 인증(RFC 4895).
    0x40: "I-DATA",            # 인터리브 데이터(RFC 8260).
    0x80: "ASCONF-ACK",        # 주소 설정 응답(RFC 5061).
    0xC0: "FORWARD-TSN",       # TSN 전진(부분 신뢰성, RFC 3758).
    0xC1: "ASCONF",            # 동적 주소 재설정.
}


@dataclass(frozen=True)
class SctpChunk:
    """SCTP 청크 헤더(값은 풀지 않음).

    Attributes:
        chunk_type: 청크 타입 코드.
        chunk_flags: 청크 플래그 바이트(타입별 의미).
        chunk_length: 청크 길이(헤더 4 포함, 패딩 제외).
        value_offset: 청크 값(value)이 시작하는 절대 오프셋(청크 헤더 끝).
    """

    chunk_type: int
    chunk_flags: int
    chunk_length: int
    value_offset: int

    @property
    def chunk_name(self) -> str:
        """청크 타입의 사람이 읽는 이름(미상이면 ``"chunk-<n>"``)."""
        return _CHUNK_NAMES.get(self.chunk_type, f"chunk-{self.chunk_type}")


@dataclass(frozen=True)
class Sctp:
    """파싱된 SCTP 공통 헤더(12바이트)와 청크 헤더 목록.

    청크 값은 풀지 않으며 :attr:`payload_offset` 와 각 청크의 ``value_offset``
    으로만 가리킨다(읽기 전용).

    Attributes:
        source_port: 출발지 포트.
        dest_port: 목적지 포트.
        verification_tag: association 식별 태그(INIT 패킷에서는 0).
        checksum: 패킷 전체 CRC32c(미검증).
        chunks: 훑은 청크 헤더(:class:`SctpChunk`) 튜플.
        payload_offset: 첫 청크가 시작하는 절대 오프셋(공통 헤더 끝).
    """

    source_port: int
    dest_port: int
    verification_tag: int
    checksum: int
    chunks: Tuple[SctpChunk, ...]
    payload_offset: int

    @property
    def chunk_types(self) -> Tuple[int, ...]:
        """실린 청크 타입 코드 튜플(등장 순서)."""
        return tuple(c.chunk_type for c in self.chunks)

    @property
    def chunk_names(self) -> Tuple[str, ...]:
        """실린 청크 이름 튜플(등장 순서)."""
        return tuple(c.chunk_name for c in self.chunks)

    @property
    def first_chunk(self) -> Optional[SctpChunk]:
        """첫 청크(없으면 ``None`` — 정상 SCTP 면 항상 존재)."""
        return self.chunks[0] if self.chunks else None

    def has_chunk(self, chunk_type: int) -> bool:
        """주어진 타입의 청크가 실렸는지 여부."""
        return any(c.chunk_type == chunk_type for c in self.chunks)

    @property
    def is_init(self) -> bool:
        """연결 개시(INIT/INIT-ACK) 청크 포함 여부 — 핸드셰이크 시작 단서."""
        return self.has_chunk(1) or self.has_chunk(2)

    @property
    def is_data(self) -> bool:
        """사용자 데이터(DATA/I-DATA) 청크 포함 여부."""
        return self.has_chunk(0) or self.has_chunk(0x40)

    @property
    def is_abort(self) -> bool:
        """강제 절단(ABORT) 청크 포함 여부 — 리셋/공격 단서."""
        return self.has_chunk(6)

    @property
    def is_shutdown(self) -> bool:
        """정상 종료(SHUTDOWN/SHUTDOWN-ACK/COMPLETE) 청크 포함 여부."""
        return (
            self.has_chunk(7) or self.has_chunk(8) or self.has_chunk(14)
        )


def parse_sctp(data: bytes, offset: int = 0) -> Optional[Sctp]:
    """원시 바이트에서 SCTP 공통 헤더와 청크 헤더 목록을 파싱한다.

    Args:
        data: SCTP 패킷을 담은 바이트. 보통 IPv4 proto 132 페이로드
            (:class:`forensiclab.netdissect` 의 ``payload_offset`` 부터)다.
        offset: 패킷이 시작하는 위치(기본 0).

    Returns:
        :class:`Sctp`. 12바이트 공통 헤더와 첫 청크 4바이트 헤더조차 없거나,
        첫 청크 길이가 4 미만이면 ``None``(오탐 가드). 청크 값은 풀지 않으며
        체크섬은 검증하지 않는다. 청크 길이가 남은 데이터를 넘어가면(절단 캡처)
        그 시점까지의 청크만 담는다.
    """
    if offset < 0 or offset + SCTP_HEADER_LEN + SCTP_CHUNK_HEADER_LEN > len(data):
        return None
    source_port, dest_port, verification_tag, checksum = struct.unpack(
        ">HHII", data[offset:offset + SCTP_HEADER_LEN]
    )

    chunks = []
    pos = offset + SCTP_HEADER_LEN
    end = len(data)
    while pos + SCTP_CHUNK_HEADER_LEN <= end:
        chunk_type = data[pos]
        chunk_flags = data[pos + 1]
        chunk_length = struct.unpack(">H", data[pos + 2:pos + 4])[0]
        if chunk_length < SCTP_CHUNK_HEADER_LEN:
            # 첫 청크가 망가졌으면 SCTP 가 아니다(오탐 가드).
            if not chunks:
                return None
            break
        chunks.append(
            SctpChunk(
                chunk_type=chunk_type,
                chunk_flags=chunk_flags,
                chunk_length=chunk_length,
                value_offset=pos + SCTP_CHUNK_HEADER_LEN,
            )
        )
        # 다음 청크는 4바이트 경계로 패딩된다(RFC 4960 §3.2).
        padded = chunk_length + (-chunk_length % 4)
        pos += padded

    return Sctp(
        source_port=source_port,
        dest_port=dest_port,
        verification_tag=verification_tag,
        checksum=checksum,
        chunks=tuple(chunks),
        payload_offset=offset + SCTP_HEADER_LEN,
    )
