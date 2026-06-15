"""RTCP — RTP 제어 프로토콜 파싱 코어 (RFC 3550 §6).

:mod:`forensiclab.rtp` 가 미디어 비트 그 자체라면, RTCP 는 그 옆을 흐르는
**제어·통계** 채널이다. 보통 RTP 의 다음(홀수) 포트로 흐르거나 RFC 5761 에 따라
같은 포트에 다중화된다(:func:`forensiclab.rtp.is_rtcp_packet` 가 RTP 파서에서
이를 가려 ``None`` 으로 떨어뜨린 패킷이 바로 여기 대상). VoIP 삼각형
sip(신호)→sdp(세션 협상)→rtp(미디어) 에 RTCP 를 더하면 통화의 품질·당사자
신원·종료 시점까지 복원되는 그림이 완성된다.

RTCP 는 침해/사고 분석에서 다음 단서를 준다:

- **호스트·신원 귀속(SDES CNAME)**: SDES(202) 청크의 ``CNAME`` 항목은 보통
  ``user@host`` 형식 — RTP ``SSRC`` 를 사람·호스트 이름에 못 박는 **신원 누출**
  표면이다(:mod:`forensiclab.rtp` 의 익명 SSRC 를 :mod:`forensiclab.sip`
  ``From`` URI·:mod:`forensiclab.flows` 와 상관해 통화 당사자 확정). ``TOOL``·
  ``NAME``·``EMAIL``·``LOC``·``PHONE`` 항목은 소프트폰·사용자 핑거프린트.
- **통화 타이밍·시계 편차(SR NTP)**: 발신자 보고(SR 200)의 64비트 NTP
  타임스탬프(:attr:`RtcpPacket.ntp_epoch`)는 송신원 벽시계 — 캡처 시각과 비교한
  편차로 호스트 식별·로그 시각 보정·통화 시작 시점 상관(:mod:`forensiclab.timeline`).
- **통화 품질·네트워크 경로(RR)**: 수신자 보고 블록의 누적 손실·지터·왕복
  지연(LSR/DLSR)으로 통화 품질 저하·경로 변경·간섭 정황.
- **통화 종료(BYE 203)**: BYE 패킷·선택적 reason 텍스트로 통화 끝 시점·사유
  (정상 종료 vs 강제 끊김)를 표시 — 세션 경계 재구성.
- **은닉 채널(APP 204)**: 앱 정의 RTCP(name 4바이트+임의 데이터)는 미디어
  트래픽으로 위장한 C2·유출 운반 가능(:mod:`forensiclab.rtp` 확장 헤더·
  :mod:`forensiclab.stun` TURN 터널링과 같은 결).

RTCP 공통 헤더(RFC 3550 §6.4.1, 모든 패킷 타입 공통 4바이트)::

    바이트0   V(2) P(1) RC/SC(5)   버전·패딩·보고/소스 개수(또는 APP subtype)
    바이트1   PT(8)                패킷 타입 200–204
    uint16    length               32비트 워드 수 - 1 (총 바이트=(length+1)*4)

RTCP 는 보통 **복합(compound) 패킷** — SR/RR 로 시작해 SDES 등이 뒤따라
연결된다. :func:`parse_rtcp` 가 단일 패킷을, :func:`parse_rtcp_compound` 가
연결된 전체를 리스트로 푼다.

설계 원칙(:mod:`forensiclab.rtp`·:mod:`forensiclab.stun` 과 동일):
- 부작용 없음: 순수 함수. 디스크/표준출력/네트워크 없음.
- stdlib 전용.
- 안전: 입력 바이트를 변형하지 않는다(읽기 전용).
- 견고: 너무 짧거나 버전이 2가 아니거나 PT 가 200–204 밖이면 예외 대신 ``None``.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import List, Optional, Tuple

__all__ = [
    "RTCP_VERSION",
    "RTCP_HEADER_SIZE",
    "PT_SR",
    "PT_RR",
    "PT_SDES",
    "PT_BYE",
    "PT_APP",
    "SDES_CNAME",
    "RtcpReportBlock",
    "RtcpSdesItem",
    "RtcpPacket",
    "parse_rtcp",
    "parse_rtcp_compound",
    "rtcp_pt_name",
    "sdes_type_name",
    "is_rtcp",
]

RTCP_VERSION = 2
RTCP_HEADER_SIZE = 4

# RTCP 패킷 타입(RFC 3550 §12.1).
PT_SR = 200    # Sender Report — 발신자 통계·NTP 시각
PT_RR = 201    # Receiver Report — 수신 품질(손실·지터)
PT_SDES = 202  # Source Description — CNAME 등 신원
PT_BYE = 203   # Goodbye — 통화 종료
PT_APP = 204   # Application-defined — 은닉 채널 정황

_PT_LOW = PT_SR
_PT_HIGH = PT_APP

_PT_NAMES = {
    PT_SR: "SR", PT_RR: "RR", PT_SDES: "SDES", PT_BYE: "BYE", PT_APP: "APP",
}

# SDES 항목 타입(RFC 3550 §6.5).
SDES_END = 0
SDES_CNAME = 1   # 정규 식별자 user@host — 신원 귀속의 핵심
SDES_NAME = 2
SDES_EMAIL = 3
SDES_PHONE = 4
SDES_LOC = 5
SDES_TOOL = 6
SDES_NOTE = 7
SDES_PRIV = 8

_SDES_NAMES = {
    SDES_END: "END", SDES_CNAME: "CNAME", SDES_NAME: "NAME",
    SDES_EMAIL: "EMAIL", SDES_PHONE: "PHONE", SDES_LOC: "LOC",
    SDES_TOOL: "TOOL", SDES_NOTE: "NOTE", SDES_PRIV: "PRIV",
}

# NTP epoch(1900-01-01) ↔ Unix epoch(1970-01-01) 차이(초).
_NTP_UNIX_DELTA = 2208988800


def rtcp_pt_name(pt: int) -> str:
    """RTCP 패킷 타입의 사람이 읽는 이름(미할당은 ``"PT-NN"``)."""
    return _PT_NAMES.get(pt, "PT-%d" % pt)


def sdes_type_name(t: int) -> str:
    """SDES 항목 타입의 사람이 읽는 이름(미할당은 ``"SDES-NN"``)."""
    return _SDES_NAMES.get(t, "SDES-%d" % t)


def is_rtcp(data: bytes, offset: int = 0) -> bool:
    """버전 2 + PT 200–204 인 RTCP 패킷으로 보이는지(가벼운 판별).

    :func:`forensiclab.rtp.is_rtcp_packet` 와 동치이나, RTCP 측에서 부르기
    좋도록 이름을 둔 별칭.
    """
    if offset < 0 or offset + 2 > len(data):
        return False
    if (data[offset] >> 6) != RTCP_VERSION:
        return False
    return _PT_LOW <= data[offset + 1] <= _PT_HIGH


@dataclass(frozen=True)
class RtcpReportBlock:
    """SR/RR 안의 수신 보고 블록(RFC 3550 §6.4.1, 24바이트).

    Attributes:
        ssrc: 이 보고가 가리키는 송신원 SSRC.
        fraction_lost: 직전 보고 이후 손실 비율(0–255, /256).
        packets_lost: 누적 손실 패킷 수(부호 있는 24비트 — 음수는 중복 수신).
        highest_seq: 받은 최고 확장 순서 번호.
        jitter: 도착 간격 지터 추정(타임스탬프 단위).
        lsr: 마지막 SR 타임스탬프(LSR).
        dlsr: 마지막 SR 이후 지연(DLSR, 1/65536초 단위).
    """

    ssrc: int
    fraction_lost: int
    packets_lost: int
    highest_seq: int
    jitter: int
    lsr: int
    dlsr: int


@dataclass(frozen=True)
class RtcpSdesItem:
    """SDES 청크 안의 한 항목(타입+텍스트).

    Attributes:
        item_type: 항목 타입 코드(:data:`SDES_CNAME` 등).
        text: 디코딩한 값(UTF-8 best-effort, 깨지면 ``replace``).
        raw: 원본 바이트(이진 PRIV 등 대비).
    """

    item_type: int
    text: str
    raw: bytes

    @property
    def type_name(self) -> str:
        """항목 타입의 사람이 읽는 이름."""
        return sdes_type_name(self.item_type)


@dataclass(frozen=True)
class RtcpPacket:
    """파싱된 단일 RTCP 패킷(공통 헤더 + 타입별 필드).

    타입에 해당하지 않는 필드는 ``None``/빈 튜플로 둔다.

    Attributes:
        version: RTCP 버전(항상 2).
        padding: P 비트 — 끝에 패딩 존재(마지막 바이트가 길이).
        count: RC(SR/RR 보고 개수) 또는 SC(SDES/BYE 소스 개수), APP 는 subtype.
        packet_type: PT(200–204).
        length_bytes: 이 패킷 전체 길이(바이트, 헤더 포함).
        sender_ssrc: SR/RR 발신자 SSRC(SDES/BYE/APP 은 ``None``).
        ntp_timestamp: SR 의 64비트 NTP 타임스탬프(SR 외 ``None``).
        rtp_timestamp: SR 의 RTP 타임스탬프(SR 외 ``None``).
        packet_count: SR 누적 송신 패킷 수(SR 외 ``None``).
        octet_count: SR 누적 송신 옥텟 수(SR 외 ``None``).
        report_blocks: SR/RR 수신 보고 블록.
        sdes_chunks: SDES (ssrc, 항목 튜플) 청크.
        bye_ssrcs: BYE 가 떠나는 SSRC 목록.
        bye_reason: BYE 선택적 사유 텍스트(없으면 ``None``).
        app_name: APP 4바이트 이름(ASCII, APP 외 ``None``).
        app_data: APP 정의 데이터(은닉 채널 표면).
        offset: 이 패킷이 시작한 절대 오프셋.
    """

    version: int
    padding: bool
    count: int
    packet_type: int
    length_bytes: int
    sender_ssrc: Optional[int] = None
    ntp_timestamp: Optional[int] = None
    rtp_timestamp: Optional[int] = None
    packet_count: Optional[int] = None
    octet_count: Optional[int] = None
    report_blocks: Tuple[RtcpReportBlock, ...] = ()
    sdes_chunks: Tuple[Tuple[int, Tuple[RtcpSdesItem, ...]], ...] = ()
    bye_ssrcs: Tuple[int, ...] = ()
    bye_reason: Optional[str] = None
    app_name: Optional[str] = None
    app_data: bytes = b""
    offset: int = 0

    @property
    def pt_name(self) -> str:
        """패킷 타입의 사람이 읽는 이름."""
        return rtcp_pt_name(self.packet_type)

    @property
    def is_sender_report(self) -> bool:
        return self.packet_type == PT_SR

    @property
    def is_receiver_report(self) -> bool:
        return self.packet_type == PT_RR

    @property
    def is_sdes(self) -> bool:
        return self.packet_type == PT_SDES

    @property
    def is_bye(self) -> bool:
        return self.packet_type == PT_BYE

    @property
    def is_app(self) -> bool:
        return self.packet_type == PT_APP

    @property
    def cnames(self) -> Tuple[str, ...]:
        """모든 SDES 청크의 ``CNAME`` 값(신원 귀속 핵심 — user@host)."""
        out = []
        for _ssrc, items in self.sdes_chunks:
            for it in items:
                if it.item_type == SDES_CNAME:
                    out.append(it.text)
        return tuple(out)

    @property
    def ntp_epoch(self) -> Optional[float]:
        """SR 의 NTP 타임스탬프를 Unix epoch 초(float)로 환산(SR 외 ``None``).

        64비트 NTP 는 상위 32비트 초(1900 기준)+하위 32비트 소수.
        """
        if self.ntp_timestamp is None:
            return None
        seconds = self.ntp_timestamp >> 32
        fraction = self.ntp_timestamp & 0xFFFFFFFF
        return (seconds - _NTP_UNIX_DELTA) + fraction / 2**32


def _parse_report_blocks(body: bytes, start: int, count: int):
    """body[start:] 에서 보고 블록 count 개 파싱. (블록들, 다음위치) 또는 None."""
    blocks = []
    pos = start
    for _ in range(count):
        if pos + 24 > len(body):
            return None  # 알린 개수만큼 블록이 없음 — 비정상.
        ssrc = struct.unpack(">I", body[pos:pos + 4])[0]
        fraction_lost = body[pos + 4]
        raw_lost = (body[pos + 5] << 16) | (body[pos + 6] << 8) | body[pos + 7]
        if raw_lost & 0x800000:  # 24비트 2의 보수(음수=중복 수신).
            raw_lost -= 0x1000000
        highest_seq, jitter, lsr, dlsr = struct.unpack(">IIII", body[pos + 8:pos + 24])
        blocks.append(RtcpReportBlock(
            ssrc=ssrc, fraction_lost=fraction_lost, packets_lost=raw_lost,
            highest_seq=highest_seq, jitter=jitter, lsr=lsr, dlsr=dlsr,
        ))
        pos += 24
    return tuple(blocks), pos


def _parse_sdes_chunks(body: bytes, count: int):
    """SDES 본문에서 청크 count 개 파싱. 청크 튜플 또는 None."""
    chunks = []
    pos = 0
    for _ in range(count):
        if pos + 4 > len(body):
            return None
        ssrc = struct.unpack(">I", body[pos:pos + 4])[0]
        pos += 4
        items = []
        while True:
            if pos >= len(body):
                return None  # END 옥텟 없이 끝남 — 비정상.
            item_type = body[pos]
            if item_type == SDES_END:
                pos += 1
                break
            if pos + 2 > len(body):
                return None
            length = body[pos + 1]
            data_start = pos + 2
            if data_start + length > len(body):
                return None  # 알린 항목 길이가 청크를 넘음.
            raw = body[data_start:data_start + length]
            items.append(RtcpSdesItem(
                item_type=item_type,
                text=raw.decode("utf-8", "replace"),
                raw=raw,
            ))
            pos = data_start + length
        # 청크는 32비트 경계로 패딩(END 옥텟 포함해 4바이트 정렬).
        if pos % 4:
            pos += 4 - (pos % 4)
        chunks.append((ssrc, tuple(items)))
    return tuple(chunks)


def parse_rtcp(data: bytes, offset: int = 0) -> Optional[RtcpPacket]:
    """원시 바이트에서 **단일** RTCP 패킷을 파싱한다.

    Args:
        data: RTCP 패킷을 담은 바이트(보통 :mod:`forensiclab.rtp` 가
            :func:`~forensiclab.rtp.is_rtcp_packet` 로 가려낸 UDP 페이로드).
        offset: 패킷이 시작하는 위치(기본 0).

    Returns:
        :class:`RtcpPacket`. 공통 헤더(4바이트)에 못 미치거나, 버전이 2가
        아니거나, PT 가 200–204 밖이거나, ``length`` 가 알린 길이가 버퍼를
        넘거나 타입별 본문이 모순되면 ``None``.
    """
    if offset < 0 or offset + RTCP_HEADER_SIZE > len(data):
        return None
    b0 = data[offset]
    version = b0 >> 6
    if version != RTCP_VERSION:
        return None
    packet_type = data[offset + 1]
    if not (_PT_LOW <= packet_type <= _PT_HIGH):
        return None

    padding = bool(b0 & 0x20)
    count = b0 & 0x1F
    length_words = struct.unpack(">H", data[offset + 2:offset + 4])[0]
    length_bytes = (length_words + 1) * 4
    end = offset + length_bytes
    if end > len(data):
        return None  # 알린 길이가 버퍼를 넘음.
    body = data[offset + RTCP_HEADER_SIZE:end]

    common = dict(
        version=version, padding=padding, count=count,
        packet_type=packet_type, length_bytes=length_bytes, offset=offset,
    )

    if packet_type in (PT_SR, PT_RR):
        if packet_type == PT_SR:
            if len(body) < 24:
                return None
            sender_ssrc, ntp, rtp_ts, pkt_cnt, oct_cnt = struct.unpack(
                ">IQIII", body[:24]
            )
            rb = _parse_report_blocks(body, 24, count)
            if rb is None:
                return None
            return RtcpPacket(
                sender_ssrc=sender_ssrc, ntp_timestamp=ntp, rtp_timestamp=rtp_ts,
                packet_count=pkt_cnt, octet_count=oct_cnt, report_blocks=rb[0],
                **common,
            )
        if len(body) < 4:
            return None
        sender_ssrc = struct.unpack(">I", body[:4])[0]
        rb = _parse_report_blocks(body, 4, count)
        if rb is None:
            return None
        return RtcpPacket(sender_ssrc=sender_ssrc, report_blocks=rb[0], **common)

    if packet_type == PT_SDES:
        chunks = _parse_sdes_chunks(body, count)
        if chunks is None:
            return None
        return RtcpPacket(sdes_chunks=chunks, **common)

    if packet_type == PT_BYE:
        if len(body) < count * 4:
            return None
        ssrcs = struct.unpack(">%dI" % count, body[:count * 4]) if count else ()
        pos = count * 4
        reason: Optional[str] = None
        if pos < len(body):  # 선택적 reason: 길이 옥텟 + 텍스트.
            rlen = body[pos]
            rstart = pos + 1
            if rstart + rlen <= len(body):
                reason = body[rstart:rstart + rlen].decode("utf-8", "replace")
        return RtcpPacket(bye_ssrcs=tuple(ssrcs), bye_reason=reason, **common)

    # PT_APP: count 는 subtype, 본문 = SSRC(4) + name(4 ASCII) + 데이터.
    if len(body) < 8:
        return None
    app_ssrc = struct.unpack(">I", body[:4])[0]
    app_name = body[4:8].decode("ascii", "replace")
    return RtcpPacket(
        sender_ssrc=app_ssrc, app_name=app_name, app_data=body[8:], **common,
    )


def parse_rtcp_compound(data: bytes, offset: int = 0) -> Optional[List[RtcpPacket]]:
    """연결된 **복합(compound) RTCP** 전체를 패킷 리스트로 파싱한다.

    RTCP 는 보통 SR/RR 로 시작해 SDES 등이 뒤따라 한 UDP 페이로드에 연결된다.
    각 패킷의 ``length`` 로 다음 경계를 찾아 끝까지 푼다.

    Returns:
        하나 이상 파싱하면 :class:`RtcpPacket` 리스트, 첫 패킷부터 RTCP 가
        아니면(버전·PT 불일치·길이 모순) ``None``. 중간 패킷이 모순이면 거기서
        멈추고 그때까지 파싱한 리스트를 돌려준다(부분 캡처 관용).
    """
    packets: List[RtcpPacket] = []
    pos = offset
    while pos + RTCP_HEADER_SIZE <= len(data):
        pkt = parse_rtcp(data, pos)
        if pkt is None:
            break
        packets.append(pkt)
        pos += pkt.length_bytes
    return packets if packets else None
