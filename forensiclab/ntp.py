"""NTP — 네트워크 시각 프로토콜 파싱 코어 (RFC 5905).

:mod:`forensiclab.netdissect` 가 식별한 UDP(포트 123) 페이로드는 NTP 패킷
일 수 있다. 이 모듈이 그 48바이트 고정 헤더를 해석한다(:mod:`forensiclab.dns`
가 UDP 53, :mod:`forensiclab.dhcp` 가 UDP 67/68 을 다루는 것과 같은 위치).

NTP 는 침해/사고 분석에서 여러 단서를 준다:

- **증폭 DDoS**: mode 7(private; ``monlist``)·mode 6(control; ``readvar``)
  요청은 작은 질의로 큰 응답을 끌어내는 반사·증폭 공격의 고전적 벡터다.
  소스 IP 가 위조된 채 대량으로 보이면 증폭 공격 정황이다.
- **호스트 상관**: stratum ≥ 2 응답의 reference ID 는 상위 NTP 서버의
  IPv4 주소다 — 어떤 시각 소스를 쓰는지로 단말·네트워크를 묶는다. stratum
  0/1 에서는 kiss 코드("DENY","RATE")·refclock 식별자("GPS","PPS")다.
- **시계 편차(clock skew)**: transmit timestamp 를 유닉스 시각으로 환산하면
  서버 시계와 캡처 시각의 차이를 알 수 있다 — 로그 타임라인 보정·위조 탐지에
  쓰인다(:mod:`forensiclab.timeline` 과 연계).
- LI(leap indicator)=3 은 동기화되지 않은(alarm) 서버 — 신뢰 못 할 시각원.

이 모듈은 단건 패킷의 고정 헤더만 파싱한다. mode 6/7 의 가변 본문(monlist
응답 레코드 등)은 호출자가 별도로 다룬다.

NTP 패킷 고정 헤더(RFC 5905 §7.3, 48바이트)::

    byte 0   LI(2비트) | VN(3비트) | Mode(3비트)
    byte 1   stratum         0=kiss-o'-death/미지정, 1=primary, 2..=secondary
    byte 2   poll            log2 초 (signed)
    byte 3   precision       log2 초 (signed)
    uint32   root delay      상위 서버까지 왕복 지연 (16.16 고정소수)
    uint32   root dispersion 누적 분산 (16.16 고정소수)
    uint32   reference ID    stratum 에 따라 IPv4 / refclock / kiss 코드
    uint64   reference ts    마지막 동기화 시각
    uint64   originate ts    클라이언트 송신 시각 (T1)
    uint64   receive ts      서버 수신 시각 (T2)
    uint64   transmit ts     서버 송신 시각 (T3)

NTP timestamp 는 64비트: 상위 32비트가 1900-01-01 부터의 초, 하위 32비트가
초의 분수다. 유닉스 시각으로 바꾸려면 초에서 2208988800(1900↔1970 차이)을
뺀다.

설계 원칙(:mod:`forensiclab.dhcp`·:mod:`forensiclab.arp` 와 동일):
- 부작용 없음: 순수 함수. 디스크/표준출력/네트워크 없음.
- stdlib 전용.
- 안전: 입력 바이트를 변형하지 않는다(읽기 전용).
- 견고: 너무 짧거나 망가진 입력은 예외 대신 ``None``.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Optional

__all__ = [
    "NTP_HEADER_SIZE",
    "NTP_UNIX_EPOCH_DELTA",
    "MODE_SYMMETRIC_ACTIVE",
    "MODE_SYMMETRIC_PASSIVE",
    "MODE_CLIENT",
    "MODE_SERVER",
    "MODE_BROADCAST",
    "MODE_CONTROL",
    "MODE_PRIVATE",
    "LI_NO_WARNING",
    "LI_UNSYNCHRONIZED",
    "Ntp",
    "parse_ntp",
    "ntp_to_unix",
    "format_ipv4",
]

# 고정 헤더 길이(LI..transmit timestamp).
NTP_HEADER_SIZE = 48

# 1900-01-01 ↔ 1970-01-01 초 차이 (NTP epoch → Unix epoch).
NTP_UNIX_EPOCH_DELTA = 2208988800

# Mode(byte 0 하위 3비트) — RFC 5905 §7.3.
MODE_SYMMETRIC_ACTIVE = 1
MODE_SYMMETRIC_PASSIVE = 2
MODE_CLIENT = 3
MODE_SERVER = 4
MODE_BROADCAST = 5
MODE_CONTROL = 6   # NTP control message (readvar 등) — 증폭 벡터.
MODE_PRIVATE = 7   # reserved/private (monlist) — 증폭 벡터.

# Leap Indicator(byte 0 상위 2비트).
LI_NO_WARNING = 0
LI_UNSYNCHRONIZED = 3   # 시계 미동기화(alarm).

_MODE_NAMES = {
    0: "reserved",
    1: "symmetric-active",
    2: "symmetric-passive",
    3: "client",
    4: "server",
    5: "broadcast",
    6: "control",
    7: "private",
}

# mode 6/7 은 반사·증폭 DDoS 에 악용되는 벡터.
_AMPLIFICATION_MODES = frozenset({MODE_CONTROL, MODE_PRIVATE})


def format_ipv4(raw: bytes) -> str:
    """4바이트 IPv4 주소를 점표기 문자열로 (그 외 길이는 hex)."""
    if len(raw) == 4:
        return ".".join(str(b) for b in raw)
    return raw.hex()


def ntp_to_unix(ts: int) -> Optional[float]:
    """64비트 NTP timestamp 를 유닉스 시각(float 초)으로 환산.

    상위 32비트=1900 기준 초, 하위 32비트=초의 분수. NTP timestamp 0 은
    "미설정"(RFC 상 의미 없음)이므로 ``None`` 을 돌려준다.
    """
    if ts == 0:
        return None
    seconds = ts >> 32
    fraction = ts & 0xFFFFFFFF
    return (seconds - NTP_UNIX_EPOCH_DELTA) + fraction / 2 ** 32


@dataclass(frozen=True)
class Ntp:
    """파싱된 NTP 패킷 고정 헤더.

    Attributes:
        leap: leap indicator(0~3). 3 = 미동기화.
        version: NTP 버전(VN, 보통 3·4).
        mode: 패킷 모드(1~7).
        stratum: 시각 계층(0=kiss/미지정, 1=primary, 2.. =secondary).
        poll: 폴 간격 log2 초(signed).
        precision: 시계 정밀도 log2 초(signed).
        root_delay: root delay 원본 32비트(16.16 고정소수).
        root_dispersion: root dispersion 원본 32비트(16.16 고정소수).
        reference_id: reference ID 원본 4바이트.
        reference_ts: reference timestamp 원본 64비트.
        originate_ts: originate timestamp(T1) 원본 64비트.
        receive_ts: receive timestamp(T2) 원본 64비트.
        transmit_ts: transmit timestamp(T3) 원본 64비트.
    """

    leap: int
    version: int
    mode: int
    stratum: int
    poll: int
    precision: int
    root_delay: int
    root_dispersion: int
    reference_id: bytes
    reference_ts: int
    originate_ts: int
    receive_ts: int
    transmit_ts: int

    @property
    def mode_name(self) -> str:
        """모드의 사람이 읽는 이름(미상이면 ``"mode-<n>"``)."""
        return _MODE_NAMES.get(self.mode, f"mode-{self.mode}")

    @property
    def is_amplification_mode(self) -> bool:
        """mode 6(control)·7(private) 여부 — 반사·증폭 DDoS 단서."""
        return self.mode in _AMPLIFICATION_MODES

    @property
    def unsynchronized(self) -> bool:
        """leap indicator 가 3(미동기화/alarm)인지 — 신뢰 못 할 시각원."""
        return self.leap == LI_UNSYNCHRONIZED

    @property
    def reference_id_text(self) -> str:
        """stratum 에 따라 해석한 reference ID.

        - stratum 0: kiss-o'-death 코드(ASCII 4자, 예 ``"DENY"``·``"RATE"``).
        - stratum 1: refclock 식별자(ASCII 4자, 예 ``"GPS"``·``"PPS"``).
        - stratum ≥ 2: 상위 NTP 서버의 IPv4 주소(호스트 상관 단서).
        """
        if self.stratum >= 2:
            return format_ipv4(self.reference_id)
        # stratum 0/1 은 ASCII 식별자/kiss 코드. 비ASCII 는 hex 로 폴백.
        text = self.reference_id.rstrip(b"\x00")
        if text and all(32 <= b < 127 for b in text):
            return text.decode("ascii")
        return self.reference_id.hex()

    @property
    def transmit_unix(self) -> Optional[float]:
        """transmit timestamp(T3)의 유닉스 시각 — 서버 시계 추정(없으면 ``None``)."""
        return ntp_to_unix(self.transmit_ts)


def parse_ntp(data: bytes, offset: int = 0) -> Optional[Ntp]:
    """원시 바이트에서 NTP 패킷 고정 헤더를 파싱한다.

    Args:
        data: NTP 패킷을 담은 바이트. 보통 UDP 123 페이로드
            (:class:`forensiclab.netdissect` 의 ``payload_offset`` 부터)다.
        offset: 패킷이 시작하는 위치(기본 0).

    Returns:
        :class:`Ntp`. 고정 헤더(48바이트)에 못 미치거나 모드가 0(reserved)
        이면 ``None``.
    """
    if offset < 0 or offset + NTP_HEADER_SIZE > len(data):
        return None
    flags = data[offset]
    leap = (flags >> 6) & 0x3
    version = (flags >> 3) & 0x7
    mode = flags & 0x7
    if mode == 0:
        return None
    stratum = data[offset + 1]
    # poll·precision 은 signed 8비트.
    poll = struct.unpack("b", data[offset + 2:offset + 3])[0]
    precision = struct.unpack("b", data[offset + 3:offset + 4])[0]
    root_delay = struct.unpack(">I", data[offset + 4:offset + 8])[0]
    root_dispersion = struct.unpack(">I", data[offset + 8:offset + 12])[0]
    reference_id = data[offset + 12:offset + 16]
    reference_ts = struct.unpack(">Q", data[offset + 16:offset + 24])[0]
    originate_ts = struct.unpack(">Q", data[offset + 24:offset + 32])[0]
    receive_ts = struct.unpack(">Q", data[offset + 32:offset + 40])[0]
    transmit_ts = struct.unpack(">Q", data[offset + 40:offset + 48])[0]
    return Ntp(
        leap=leap,
        version=version,
        mode=mode,
        stratum=stratum,
        poll=poll,
        precision=precision,
        root_delay=root_delay,
        root_dispersion=root_dispersion,
        reference_id=reference_id,
        reference_ts=reference_ts,
        originate_ts=originate_ts,
        receive_ts=receive_ts,
        transmit_ts=transmit_ts,
    )
