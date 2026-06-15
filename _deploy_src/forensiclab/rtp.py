"""RTP — 실시간 전송 프로토콜 파싱 코어 (RFC 3550/3551).

:mod:`forensiclab.netdissect` 가 식별한 UDP 페이로드(보통 16384–32767 동적 짝수
포트)는 RTP 패킷일 수 있다. RTP 는 VoIP·영상통화·화면공유의 **미디어(media)**
스트림 그 자체로, :mod:`forensiclab.sip`(신호)·:mod:`forensiclab.stun`/TURN(NAT
통과·미디어 경로 설정)이 차린 통로 위로 실제 음성·영상 비트가 흐른다. 즉 SIP
INVITE 의 SDP 가 협상한 코덱·포트, STUN 이 뚫은 반사 주소의 **목적지**가 RTP다.

RTP 는 침해/사고 분석에서 여러 단서를 준다:

- **미디어 스트림 식별·통화 재구성**: ``SSRC``(동기화 소스)는 한 송신원 미디어
  스트림의 고유 ID — :mod:`forensiclab.sip` ``Call-ID``·:mod:`forensiclab.stun`
  Transaction ID 와 상관해 "누가 누구와 언제 통화"를 잇는다(:mod:`forensiclab.flows`·
  :mod:`forensiclab.timeline`). ``CSRC`` 목록은 믹서를 거친 회의 참가자들.
- **코덱·미디어 종류 핑거프린트**: ``payload_type`` 으로 음성(PCMU 0·PCMA 8·G729
  18)·영상(H.263 34·H.264 동적)을 가른다 — G.711(0/8) 평문 음성은 캡처에서 통화
  내용 자체를 복원할 수 있는 표면(법적 감청·증거).
- **RTP 인젝션·블리드(injection/bleed)**: 같은 SSRC 로 더 큰 ``sequence``/
  ``timestamp`` 패킷을 끼워 넣어 진행 중인 통화에 잡음·음성을 주입(RTP injection)
  하거나, 잘못 라우팅된 RTP 를 엿듣는다(RTP bleed). SSRC 충돌·시퀀스 점프가 정황.
- **은닉 채널·스테가노그래피**: RTP 헤더 확장(``X`` 비트)·패딩·비정상 payload
  type 에 데이터를 숨겨 미디어 트래픽으로 위장한 C2·유출(:mod:`forensiclab.stun`
  TURN 터널링과 같은 결).

RTP 고정 헤더(RFC 3550 §5.1, 12바이트)::

    바이트0   V(2) P(1) X(1) CC(4)     버전·패딩·확장·CSRC 개수
    바이트1   M(1) PT(7)               마커·payload type
    uint16    sequence number          순서(인젝션·손실 탐지)
    uint32    timestamp                샘플링 시각
    uint32    SSRC                     동기화 소스 식별자
    ...       CSRC[CC]                 기여 소스(믹서) 0~15개, 각 4바이트
    [X=1]     확장 헤더                profile(2)+length(2,워드)+data

RTP 와 RTCP(제어, PT 200–204)는 같은 포트에 다중화될 수 있어(RFC 5761), 둘째
바이트가 200–204 범위면 RTCP 로 보고 :func:`is_rtcp_packet` 로 가른다.

설계 원칙(:mod:`forensiclab.stun`·:mod:`forensiclab.dns` 와 동일):
- 부작용 없음: 순수 함수. 디스크/표준출력/네트워크 없음.
- stdlib 전용.
- 안전: 입력 바이트를 변형하지 않는다(읽기 전용).
- 견고: 너무 짧거나 버전이 2가 아니면 예외 대신 ``None``.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Optional, Tuple

__all__ = [
    "RTP_HEADER_SIZE",
    "RTP_VERSION",
    "PT_PCMU",
    "PT_GSM",
    "PT_PCMA",
    "PT_G722",
    "PT_G729",
    "PT_H263",
    "Rtp",
    "parse_rtp",
    "is_rtcp_packet",
    "payload_type_name",
    "is_audio_payload",
    "is_video_payload",
]

RTP_HEADER_SIZE = 12
RTP_VERSION = 2

# 정적 payload type(RFC 3551 §6). 동적 96–127 은 SIP/SDP 가 협상.
PT_PCMU = 0        # G.711 µ-law 음성
PT_GSM = 3
PT_G723 = 4
PT_PCMA = 8        # G.711 A-law 음성
PT_G722 = 9
PT_L16_STEREO = 10
PT_L16_MONO = 11
PT_G729 = 18
PT_CELB = 25
PT_JPEG = 26       # 영상
PT_H261 = 31       # 영상
PT_MPV = 32        # 영상(MPEG-1/2)
PT_MP2T = 33       # MPEG-2 transport
PT_H263 = 34       # 영상

_PT_NAMES = {
    PT_PCMU: "PCMU", PT_GSM: "GSM", PT_G723: "G723", PT_PCMA: "PCMA",
    PT_G722: "G722", PT_L16_STEREO: "L16/2", PT_L16_MONO: "L16/1",
    13: "CN", PT_G729: "G729", PT_CELB: "CelB", PT_JPEG: "JPEG",
    28: "nv", PT_H261: "H261", PT_MPV: "MPV", PT_MP2T: "MP2T", PT_H263: "H263",
}

_AUDIO_PTS = frozenset({
    PT_PCMU, 1, PT_GSM, PT_G723, 5, 6, 7, PT_PCMA, PT_G722,
    PT_L16_STEREO, PT_L16_MONO, 12, 13, 14, 15, 16, 17, PT_G729,
})
_VIDEO_PTS = frozenset({
    PT_CELB, PT_JPEG, 28, PT_H261, PT_MPV, PT_MP2T, PT_H263,
})

# RTP/RTCP 다중화 구분(RFC 5761 §4): RTCP 패킷 타입 200–204.
_RTCP_PT_LOW = 200
_RTCP_PT_HIGH = 204


def payload_type_name(pt: int) -> str:
    """payload type 의 사람이 읽는 이름.

    정적 타입은 코덱 이름, 동적 범위(96–127)는 ``"dynamic-NN"``,
    그 외 미할당은 ``"PT-NN"``.
    """
    if pt in _PT_NAMES:
        return _PT_NAMES[pt]
    if 96 <= pt <= 127:
        return "dynamic-%d" % pt
    return "PT-%d" % pt


def is_audio_payload(pt: int) -> bool:
    """정적 음성 코덱 payload type 여부(동적은 SDP 협상이라 판단 불가)."""
    return pt in _AUDIO_PTS


def is_video_payload(pt: int) -> bool:
    """정적 영상 코덱 payload type 여부(동적은 SDP 협상이라 판단 불가)."""
    return pt in _VIDEO_PTS


def is_rtcp_packet(data: bytes, offset: int = 0) -> bool:
    """둘째 바이트(M+PT)가 RTCP 패킷 타입 200–204 범위인지(RFC 5761 다중화 구분).

    RTP 와 RTCP 가 같은 포트에 다중화될 때, RTP 의 ``payload_type`` 은 이 범위를
    피하도록 선택되므로(64–95 권장) 둘째 바이트로 둘을 가를 수 있다. ``True`` 면
    RTP 가 아니라 RTCP(SR 200·RR 201·SDES 202·BYE 203·APP 204)로 보아야 한다.
    """
    if offset < 0 or offset + 2 > len(data):
        return False
    if (data[offset] >> 6) != RTP_VERSION:
        return False
    # RTCP 의 packet type 은 둘째 바이트 전체(M 비트 마스킹 없음). RTP 와 다중화
    # 시 RTP 의 M+PT 합산 바이트는 이 범위를 피하므로 전체 바이트로 비교한다.
    pt = data[offset + 1]
    return _RTCP_PT_LOW <= pt <= _RTCP_PT_HIGH


@dataclass(frozen=True)
class Rtp:
    """파싱된 RTP 패킷(고정 헤더 + 선택적 CSRC·확장, 페이로드는 오프셋만).

    Attributes:
        version: RTP 버전(항상 2).
        padding: P 비트 — 페이로드 끝에 패딩 존재(마지막 바이트가 길이).
        extension: X 비트 — 헤더 확장 존재(은닉 채널 정황 가능).
        csrc_count: CC — CSRC 식별자 개수(0~15).
        marker: M 비트 — 음성은 talkspurt 시작, 영상은 프레임 경계.
        payload_type: 7비트 PT — 코덱·미디어 종류.
        sequence: 16비트 순서 번호(손실·인젝션·재정렬 탐지).
        timestamp: 32비트 샘플링 시각.
        ssrc: 32비트 동기화 소스 — 스트림 고유 ID(통화 상관).
        csrc: 기여 소스(믹서 참가자) 튜플.
        ext_profile: 확장 헤더 profile 식별자(``extension`` 일 때만, 아니면 ``None``).
        ext_data: 확장 헤더 데이터 바이트(없으면 ``b""``).
        payload_offset: 페이로드가 시작하는 절대 오프셋.
    """

    version: int
    padding: bool
    extension: bool
    csrc_count: int
    marker: bool
    payload_type: int
    sequence: int
    timestamp: int
    ssrc: int
    csrc: Tuple[int, ...]
    ext_profile: Optional[int]
    ext_data: bytes
    payload_offset: int

    @property
    def payload_type_name(self) -> str:
        """payload type 의 사람이 읽는 이름(코덱)."""
        return payload_type_name(self.payload_type)

    @property
    def is_audio(self) -> bool:
        """정적 음성 코덱 여부."""
        return is_audio_payload(self.payload_type)

    @property
    def is_video(self) -> bool:
        """정적 영상 코덱 여부."""
        return is_video_payload(self.payload_type)

    @property
    def is_dynamic_payload(self) -> bool:
        """동적 payload type(96–127) 여부 — SIP/SDP 협상 코덱."""
        return 96 <= self.payload_type <= 127

    @property
    def has_contributors(self) -> bool:
        """CSRC 가 있는지 — 믹서를 거친 다자 통화(회의) 정황."""
        return self.csrc_count > 0


def parse_rtp(data: bytes, offset: int = 0) -> Optional[Rtp]:
    """원시 바이트에서 RTP 패킷을 파싱한다.

    Args:
        data: RTP 패킷을 담은 바이트. 보통 동적 UDP 포트 페이로드
            (:class:`forensiclab.netdissect` 의 ``payload_offset`` 부터)다.
        offset: 패킷이 시작하는 위치(기본 0).

    Returns:
        :class:`Rtp`. 고정 헤더(12바이트)에 못 미치거나, 버전이 2가 아니거나
        (비-RTP 오탐 가드), RTCP 패킷 타입(200–204)이거나, CC/확장이 알린
        길이가 버퍼를 넘으면 ``None``.
    """
    if offset < 0 or offset + RTP_HEADER_SIZE > len(data):
        return None
    b0 = data[offset]
    version = b0 >> 6
    if version != RTP_VERSION:
        return None
    # RTCP 다중화 구분 — 같은 포트의 제어 패킷은 RTP 가 아니다.
    if is_rtcp_packet(data, offset):
        return None

    padding = bool(b0 & 0x20)
    extension = bool(b0 & 0x10)
    csrc_count = b0 & 0x0F
    b1 = data[offset + 1]
    marker = bool(b1 & 0x80)
    payload_type = b1 & 0x7F
    sequence, timestamp, ssrc = struct.unpack(
        ">HII", data[offset + 2:offset + 12]
    )

    pos = offset + RTP_HEADER_SIZE
    csrc_end = pos + csrc_count * 4
    if csrc_end > len(data):
        return None  # 알린 CSRC 개수가 버퍼를 넘음 — 비정상.
    csrc = struct.unpack(">%dI" % csrc_count, data[pos:csrc_end]) if csrc_count else ()
    pos = csrc_end

    ext_profile: Optional[int] = None
    ext_data = b""
    if extension:
        if pos + 4 > len(data):
            return None  # 확장 헤더 4바이트도 없음.
        ext_profile, ext_words = struct.unpack(">HH", data[pos:pos + 4])
        pos += 4
        ext_end = pos + ext_words * 4
        if ext_end > len(data):
            return None  # 알린 확장 길이가 버퍼를 넘음.
        ext_data = data[pos:ext_end]
        pos = ext_end

    return Rtp(
        version=version,
        padding=padding,
        extension=extension,
        csrc_count=csrc_count,
        marker=marker,
        payload_type=payload_type,
        sequence=sequence,
        timestamp=timestamp,
        ssrc=ssrc,
        csrc=tuple(csrc),
        ext_profile=ext_profile,
        ext_data=ext_data,
        payload_offset=pos,
    )
