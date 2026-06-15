"""libpcap(.pcap) 캡처 파일 파싱 코어.

네트워크 패킷 캡처(.pcap)는 침해 분석의 핵심 증거다. 이 모듈은 고전
libpcap 포맷의 전역 헤더와 패킷 레코드를 순수 stdlib 만으로 읽어,
각 패킷을 :class:`Packet` 로 표현한다. 페이로드(링크/네트워크 계층) 자체는
해석하지 않고, 캡처 메타데이터(시각·길이·링크타입)와 원시 바이트만 다룬다.

여기서 뽑은 패킷 시각은 :class:`forensiclab.timeline.Event` 로 옮겨
다른 출처(로그·EXIF) 사건과 한 타임라인에 합칠 수 있다.

지원 포맷: 고전 libpcap(매직 ``0xA1B2C3D4``). 마이크로초/나노초 해상도,
빅/리틀 엔디안을 매직 바이트로 자동 판별한다. (pcapng 는 범위 밖.)

제공 기능:
- :func:`parse_header` — 24바이트 전역 헤더를 :class:`PcapHeader` 로 파싱.
- :func:`iter_packets` — 패킷 레코드를 차례로 :class:`Packet` 로 산출.
- :func:`parse` — 헤더와 전체 패킷 목록을 한 번에 반환.

설계 원칙(:mod:`forensiclab.filetype`·:mod:`forensiclab.timeline` 와 동일):
- 부작용 없음: 디스크 쓰기/표준출력 없이 순수 함수로 동작 (테스트 용이).
- stdlib 전용: 외부 의존성 없음.
- 안전: 입력 버퍼를 변형하지 않는다(읽기 전용).
- 견고: 잘린/손상된 파일은 :class:`PcapError` 로 명확히 알린다.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Iterator

__all__ = [
    "PcapError",
    "PcapHeader",
    "Packet",
    "GLOBAL_HEADER_SIZE",
    "RECORD_HEADER_SIZE",
    "parse_header",
    "iter_packets",
    "parse",
]

GLOBAL_HEADER_SIZE = 24
"""고전 libpcap 전역 헤더 크기(바이트)."""

RECORD_HEADER_SIZE = 16
"""패킷 레코드 헤더 크기(바이트): ts_sec, ts_usec, incl_len, orig_len."""

# 매직 바이트 → (struct 엔디안 접두, 나노초 해상도 여부).
# 마이크로초: 0xA1B2C3D4 / 나노초: 0xA1B23C4D. 저장 엔디안에 따라 뒤집힌 값도 본다.
_MAGICS: dict[bytes, tuple[str, bool]] = {
    b"\xa1\xb2\xc3\xd4": (">", False),  # 빅 엔디안, 마이크로초
    b"\xd4\xc3\xb2\xa1": ("<", False),  # 리틀 엔디안, 마이크로초
    b"\xa1\xb2\x3c\x4d": (">", True),   # 빅 엔디안, 나노초
    b"\x4d\x3c\xb2\xa1": ("<", True),   # 리틀 엔디안, 나노초
}


class PcapError(ValueError):
    """pcap 버퍼가 너무 짧거나 매직/길이가 깨졌을 때 발생."""


@dataclass(frozen=True)
class PcapHeader:
    """libpcap 전역 헤더.

    Attributes:
        byte_order: ``struct`` 엔디안 접두 (``"<"`` 또는 ``">"``).
        nanosecond: 타임스탬프 소수부가 나노초면 ``True``, 마이크로초면 ``False``.
        version_major: 포맷 메이저 버전(보통 2).
        version_minor: 포맷 마이너 버전(보통 4).
        thiszone: GMT 와 로컬 시각의 차(초). 보통 0.
        sigfigs: 타임스탬프 유효 자릿수. 보통 0.
        snaplen: 패킷당 캡처된 최대 바이트 수.
        linktype: 데이터 링크 계층 타입 번호(예: 1=Ethernet, 101=Raw IP).
    """

    byte_order: str
    nanosecond: bool
    version_major: int
    version_minor: int
    thiszone: int
    sigfigs: int
    snaplen: int
    linktype: int


@dataclass(frozen=True)
class Packet:
    """캡처된 패킷 하나(메타데이터 + 원시 바이트).

    Attributes:
        timestamp: 패킷 캡처 시각(UTC, tz-aware).
        captured_len: 파일에 실제 저장된 바이트 수(``len(data)`` 와 같음).
        original_len: 회선상 원래 패킷 길이. ``captured_len`` 보다 크면
            snaplen 으로 잘린 패킷이다(:attr:`truncated` 참고).
        data: 캡처된 원시 패킷 바이트.
        index: 파일 안에서 0부터 매기는 패킷 순번.
    """

    timestamp: datetime
    captured_len: int
    original_len: int
    data: bytes = field(repr=False)
    index: int = 0

    @property
    def truncated(self) -> bool:
        """snaplen 때문에 잘린(원래보다 적게 저장된) 패킷이면 ``True``."""
        return self.original_len > self.captured_len


def parse_header(buf: bytes) -> PcapHeader:
    """24바이트 libpcap 전역 헤더를 파싱한다.

    Args:
        buf: pcap 파일의 시작 바이트(최소 :data:`GLOBAL_HEADER_SIZE`).

    Returns:
        파싱된 :class:`PcapHeader`.

    Raises:
        PcapError: 버퍼가 너무 짧거나 매직 바이트가 libpcap 이 아닐 때.
    """
    if len(buf) < GLOBAL_HEADER_SIZE:
        raise PcapError(
            f"전역 헤더에 {GLOBAL_HEADER_SIZE}바이트가 필요하나 {len(buf)}바이트뿐"
        )
    magic = bytes(buf[:4])
    if magic not in _MAGICS:
        raise PcapError(f"libpcap 매직이 아님: {magic.hex()}")
    endian, nanosecond = _MAGICS[magic]
    (v_major, v_minor, thiszone, sigfigs, snaplen, linktype) = struct.unpack(
        endian + "HHiIII", buf[4:GLOBAL_HEADER_SIZE]
    )
    return PcapHeader(
        byte_order=endian,
        nanosecond=nanosecond,
        version_major=v_major,
        version_minor=v_minor,
        thiszone=thiszone,
        sigfigs=sigfigs,
        snaplen=snaplen,
        linktype=linktype,
    )


def iter_packets(buf: bytes, header: PcapHeader | None = None) -> Iterator[Packet]:
    """패킷 레코드를 파일에 나오는 순서대로 산출한다.

    ``header`` 를 주지 않으면 ``buf`` 앞부분에서 전역 헤더를 먼저 파싱한다
    (즉 ``buf`` 는 파일 전체). ``header`` 를 주면 ``buf`` 는 전역 헤더
    *이후* 의 패킷 영역만 담은 것으로 본다.

    Args:
        buf: 파일 전체 또는 (``header`` 제공 시) 패킷 영역 바이트.
        header: 이미 파싱한 전역 헤더(엔디안·해상도 결정용). ``None`` 이면
            ``buf`` 에서 파싱.

    Yields:
        :class:`Packet` (캡처 순서, :attr:`Packet.index` 는 0부터).

    Raises:
        PcapError: 레코드 헤더가 잘렸거나, 선언된 캡처 길이만큼의 데이터가
            남아있지 않을 때.
    """
    if header is None:
        header = parse_header(buf)
        offset = GLOBAL_HEADER_SIZE
    else:
        offset = 0
    endian = header.byte_order
    total = len(buf)
    index = 0
    while offset < total:
        remaining = total - offset
        if remaining < RECORD_HEADER_SIZE:
            raise PcapError(
                f"패킷 {index} 레코드 헤더가 잘림: {remaining}바이트 남음"
            )
        ts_sec, ts_frac, incl_len, orig_len = struct.unpack(
            endian + "IIII", buf[offset:offset + RECORD_HEADER_SIZE]
        )
        offset += RECORD_HEADER_SIZE
        if total - offset < incl_len:
            raise PcapError(
                f"패킷 {index} 데이터가 잘림: {incl_len}바이트 필요, "
                f"{total - offset}바이트 남음"
            )
        data = bytes(buf[offset:offset + incl_len])
        offset += incl_len
        micros = ts_frac // 1000 if header.nanosecond else ts_frac
        timestamp = datetime.fromtimestamp(ts_sec, tz=timezone.utc).replace(
            microsecond=micros % 1_000_000
        )
        yield Packet(
            timestamp=timestamp,
            captured_len=incl_len,
            original_len=orig_len,
            data=data,
            index=index,
        )
        index += 1


def parse(buf: bytes) -> tuple[PcapHeader, list[Packet]]:
    """전역 헤더와 모든 패킷을 한 번에 파싱한다.

    Args:
        buf: pcap 파일 전체 바이트.

    Returns:
        ``(header, packets)`` 튜플.

    Raises:
        PcapError: 헤더나 어느 레코드든 손상/절단되었을 때.
    """
    header = parse_header(buf)
    packets = list(iter_packets(buf[GLOBAL_HEADER_SIZE:], header))
    return header, packets
