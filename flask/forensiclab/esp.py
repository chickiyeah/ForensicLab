"""ESP(Encapsulating Security Payload) IPsec 데이터 평면 헤더 파싱 코어 (RFC 4303).

:mod:`forensiclab.ike` 가 두 호스트가 **IPsec VPN 터널의 키를 협상**하는 손잡이
(키 교환 핸드셰이크)였다면, ESP 는 그 협상이 끝난 뒤 실제 사용자 트래픽이 흐르는
**데이터 평면** 그 자체다 — IKE 가 만든 SA(Security Association)로 암호화된
페이로드를 IP 프로토콜 50(또는 NAT 뒤에서는 UDP 4500)으로 나른다. ESP 가 보이면
그 호스트 쌍은 "협상을 끝내고 실제로 암호 터널을 쓰고 있다"는 직접 증거다.

ESP 헤더에서 평문으로 읽을 수 있는 것은 앞 8바이트뿐이다(SPI 4 + Sequence 4).
페이로드 본문·말미의 Padding/Pad Length/Next Header·ICV(무결성 값)는 전부
암호문이라 풀 수 없다 — 풀 수 없다는 사실 자체가 "암호화된 VPN 데이터"라는 정황.

침해/사고 분석에서 ESP 가 드러내는 것:

- **암호 터널 데이터 평면 확정**: :mod:`forensiclab.gre` 가 평문 헤더로 안에 무엇이
  들었는지 그대로 드러내는 범용 터널이었다면, ESP 는 정반대로 페이로드가 암호화돼
  내용을 볼 수 없다 — IKE(:mod:`forensiclab.ike`) 협상에 이어 ESP 가 흐르면 그 쌍은
  IPsec 으로 실제 데이터를 주고받는 중. 내용은 못 봐도 누가·언제·얼마나 통신했는지
  (메타데이터)는 그대로 남는다.
- **SA 귀속·터널 상관(SPI)**: 32비트 ``spi``(Security Parameters Index)는 수신자가
  어떤 SA(키·알고리즘 묶음)로 복호할지 가리키는 식별자 — 단방향이라 양방향 터널은
  서로 다른 SPI 두 개. :mod:`forensiclab.flows` 의 같은 IP 쌍 흐름 안에서도 SPI 로
  어느 SA(어느 IKE 협상의 산물)인지 못 박고, 재협상(rekey) 시 바뀌는 SPI 로 SA 수명을
  추적한다(:mod:`forensiclab.ike` 의 ``initiator_spi``/``responder_spi`` 와는 별개의
  값 — IKE SA 쿠키가 아니라 ESP SA 색인).
- **흐름 진행·재생 공격(Sequence)**: 32비트 ``sequence`` 는 SA 마다 1부터 단조 증가
  하는 anti-replay 카운터 — ``sequence==1``(``is_initial``)은 그 SA 의 첫 패킷(터널
  개통 직후) 시점, 큰 값은 장수명·대량 전송 정황. 같은 SPI 에서 시퀀스가 되감기거나
  중복되면 재생 공격·캡처 재주입 정황.
- **NAT-T 데이터 평면**: NAT 뒤 VPN 은 ESP 를 UDP 4500 으로 캡슐화한다(ESP-in-UDP).
  이때 첫 4바이트가 0 인 "비-ESP 마커"는 IKE(:mod:`forensiclab.ike`
  ``has_non_esp_marker``)이고, 0 이 아니면 ESP — SPI 0 은 예약값이라 본 파서는
  ``spi==0`` 을 거부해 IKE 의 비-ESP 마커를 ESP 로 오인하지 않는다.

와이어 포맷 — ESP 헤더(앞 8바이트, 평문): SPI(32비트)·Sequence Number(32비트).
그 뒤로 암호화된 Payload Data(가변)·Padding·Pad Length·Next Header·ICV 가 따르지만
키 없이는 풀 수 없어 시작 오프셋(``payload_offset``)만 노출한다.

설계 원칙(다른 파서와 동일):
- 부작용 없음·stdlib 전용·읽기 전용.
- 견고: 8바이트에 못 미치거나 SPI 가 예약값(0)이면 예외 대신 ``None``.
- 암호화된 본문은 풀지 않는다(키 없이 불가) — 평문 SPI/Sequence 만 노출한다.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Optional

__all__ = [
    "ESP_IP_PROTO",
    "ESP_NAT_T_PORT",
    "EspHeader",
    "looks_like_esp",
    "parse_esp",
]

# ESP 는 IP 프로토콜 50(IANA). NAT 뒤에서는 UDP 4500 으로 캡슐화(ESP-in-UDP).
ESP_IP_PROTO = 50
ESP_NAT_T_PORT = 4500

_HEADER_LEN = 8


@dataclass(frozen=True)
class EspHeader:
    """파싱된 ESP(IPsec 데이터 평면) 헤더 한 개.

    평문으로 읽히는 앞 8바이트(SPI+Sequence)만 담는다. 페이로드 본문·ICV 는
    암호문이라 풀지 않고 ``payload_offset`` 만 노출한다.

    Attributes:
        spi: 32비트 Security Parameters Index(SA 색인; 수신자가 복호 SA 선택).
        sequence: 32비트 Sequence Number(SA 마다 1부터 단조 증가, anti-replay).
        header_length: ESP 헤더 길이(항상 8).
        payload_offset: 암호화된 페이로드 시작 오프셋(``data`` 기준).
    """

    spi: int = 0
    sequence: int = 0
    header_length: int = _HEADER_LEN
    payload_offset: int = _HEADER_LEN

    @property
    def is_initial(self) -> bool:
        """SA 의 첫 패킷인지(``sequence==1``) — 터널 개통 직후 시점."""
        return self.sequence == 1


def looks_like_esp(data: bytes, offset: int = 0) -> bool:
    """``offset`` 바이트가 파싱 가능한 ESP 헤더처럼 보이는지(가벼운 가드).

    ESP 페이로드는 암호문이라 강한 식별 단서가 없다 — IP 프로토콜 50(또는 UDP
    4500 의 비-0 첫 4바이트)이라는 문맥과 함께 써야 신뢰할 수 있다.
    """
    return parse_esp(data, offset) is not None


def parse_esp(data: bytes, offset: int = 0) -> Optional[EspHeader]:
    """단일 ESP 헤더(SPI+Sequence)를 파싱한다.

    Args:
        data: ESP 바이트(IP proto 50 페이로드, 또는 UDP 4500 ESP-in-UDP 페이로드).
        offset: 파싱 시작 위치(기본 0).

    Returns:
        :class:`EspHeader`. 8바이트에 못 미치거나 SPI 가 예약값(0)이면 ``None``.
        암호화된 본문은 풀지 않고 ``payload_offset`` 만 노출한다.
    """
    if not isinstance(data, (bytes, bytearray)):
        return None
    if len(data) - offset < _HEADER_LEN:
        return None

    spi, sequence = struct.unpack(">II", data[offset:offset + _HEADER_LEN])

    # SPI 0 은 예약값(RFC 4303 §2.1) — 와이어에 나오면 안 된다. UDP 4500 의
    # 4바이트-0 비-ESP 마커(=IKE)를 ESP 로 오인하지 않는 오탐 가드.
    if spi == 0:
        return None

    return EspHeader(
        spi=spi,
        sequence=sequence,
        header_length=_HEADER_LEN,
        payload_offset=offset + _HEADER_LEN,
    )
