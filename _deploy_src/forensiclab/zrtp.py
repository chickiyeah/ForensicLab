"""ZRTP — 미디어 경로 키 합의(in-band) 파싱 코어 (RFC 6189).

VoIP 삼각형 sip(신호)→:mod:`forensiclab.sdp`(협상)→:mod:`forensiclab.rtp`(미디어)에
:mod:`forensiclab.rtcp`(제어)가 더해져 통화 그림을 그렸다면, ZRTP 는 그 미디어를
**암호화하는 키를 어떻게 합의하느냐**를 RTP 와 **같은 포트**(짝수 UDP)에서
직접 처리한다. 즉 :mod:`forensiclab.sdp` 의 ``a=crypto``(SDES) 가 세션 키를
신호 평문에 그대로 실어 신호 경로를 본 사람이면 미디어를 복호할 수 있던 것과
정반대로, ZRTP 는 키를 **신호에 절대 싣지 않고** 미디어 경로에서 Diffie-Hellman
으로 합의한다(Zfone·Phil Zimmermann). 따라서 ZRTP 가 보이면 SDP 만으로는 미디어를
복호할 수 없고, 수동 감청이 사실상 막힌다는 강한 신호다.

와이어 포맷은 RTP 와 닮았지만(짝수 포트 다중화) 둘째 워드의 **매직 쿠키
``ZRTP``(0x5a525450)** 로 구분된다(:mod:`forensiclab.rtp` 가 버전 2 가 아니라
``None`` 으로 떨군 패킷, :func:`forensiclab.rtp.is_rtcp_packet` 와 같은 결의
다중화 가드 형제):

- 12바이트 ZRTP 헤더: ``0x10`` 프리앰블+시퀀스 번호·매직 쿠키·SSRC.
- 그 뒤 ZRTP 메시지: 프리앰블 ``0x505a``+length(워드)+8바이트 **Message Type
  Block**(``"Hello   "``·``"Commit  "``·``"DHPart1 "``·``"Confirm1"``·
  ``"GoClear "``·``"Error   "`` 등 ASCII)+타입별 본문+CRC.

ZRTP 는 침해/사고 분석에서 다음 단서를 준다:

- **지속 신원·호스트 귀속(ZID)**: Hello 의 12바이트 ``ZID`` 는 단말이 통화마다
  재사용하는 **영구 식별자** — :mod:`forensiclab.rtp` 의 익명 SSRC·바뀌는 IP 를
  넘어 같은 장치를 통화·세션 간에 못 박는 슈퍼쿠키(:mod:`forensiclab.flows`·
  :mod:`forensiclab.timeline` 상관, :mod:`forensiclab.rtcp` SDES CNAME 신원 누출
  결).
- **소프트폰 핑거프린트(Client Identifier)**: Hello 의 16바이트 ``client_id``
  (``"Zfone"``·``"GNU ZRTP"``·``"Linphone"``·``"CSipSimple"`` 등)는 구현·버전
  핑거프린트(:mod:`forensiclab.sip` User-Agent 결).
- **암호 자세**: Hello 의 hash/cipher/auth/key-agreement/SAS 알고리즘 목록과
  Commit 의 선택값으로 협상된 암호 강도(약한 DH 그룹·구식 알고리즘 정황).
- **평문 다운그레이드 공격**: ``GoClear``/``ClearACK`` 는 암호화된 미디어를
  **평문으로 되돌리는** 전환 — 감청을 위한 MITM 강제 다운그레이드 정황
  (:attr:`ZrtpPacket.is_clear_downgrade`).
- **협상 실패·MITM**: ``Error`` 메시지 ``error_code`` 는 버전/알고리즘 불일치·
  MITM 정황(SAS 불일치는 사용자가 음성으로 확인하는 별도 단계).

설계 원칙(다른 파서와 동일):
- 부작용 없음·stdlib 전용·읽기 전용.
- 견고: 매직 쿠키가 없으면(비-ZRTP) 예외 대신 ``None``. 본문이 잘리면 받은
  데까지만 채운다(버퍼 초과 인덱싱 금지).
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import List, Optional

__all__ = [
    "ZRTP_MAGIC",
    "ZRTP_MESSAGE_PREAMBLE",
    "MESSAGE_TYPES",
    "ZrtpPacket",
    "looks_like_zrtp",
    "parse_zrtp",
]

# 둘째 워드(헤더 offset+4)의 매직 쿠키 'ZRTP'. 비-ZRTP 오탐 가드의 핵심.
ZRTP_MAGIC = 0x5A525450
# ZRTP 메시지(헤더 offset+12) 프리앰블 'PZ' (0x505a).
ZRTP_MESSAGE_PREAMBLE = 0x505A

# RFC 6189 §5.1 정의 메시지 타입(8바이트 ASCII, 공백 패딩). 분류·검증 보조.
MESSAGE_TYPES = frozenset(
    {
        "Hello",
        "HelloACK",
        "Commit",
        "DHPart1",
        "DHPart2",
        "Confirm1",
        "Confirm2",
        "Conf2ACK",
        "Error",
        "ErrorACK",
        "GoClear",
        "ClearACK",
        "SASrelay",
        "RelayACK",
        "Ping",
        "PingACK",
    }
)

# 평문으로의 전환(감청 목적 다운그레이드 정황)을 나타내는 타입.
_CLEAR_TYPES = frozenset({"GoClear", "ClearACK"})


def looks_like_zrtp(data: bytes, offset: int = 0) -> bool:
    """``offset`` 위치 바이트가 ZRTP 패킷처럼 보이는지(매직 쿠키 검사).

    헤더 둘째 워드(offset+4)의 매직 쿠키가 ``ZRTP`` 면 ``True``. RTP 와 같은
    포트로 다중화돼도 이 쿠키로 가른다(:func:`forensiclab.rtp.is_rtcp_packet`
    결의 다중화 가드).
    """
    if not isinstance(data, (bytes, bytearray)):
        return False
    if len(data) - offset < 8:
        return False
    return struct.unpack_from(">I", data, offset + 4)[0] == ZRTP_MAGIC


def _split_words(blob: bytes, count: int) -> List[str]:
    """길이 ``count`` × 4바이트 토큰을 ASCII 문자열(공백 제거) 목록으로.

    blob 이 모자라면 가능한 토큰까지만(버퍼 초과 금지).
    """
    out: List[str] = []
    for i in range(count):
        start = i * 4
        if start + 4 > len(blob):
            break
        out.append(blob[start:start + 4].decode("ascii", "replace").strip())
    return out


@dataclass(frozen=True)
class ZrtpPacket:
    """파싱된 ZRTP 패킷 한 개.

    Attributes:
        sequence: 헤더 시퀀스 번호(재전송 식별).
        ssrc: 동기화 소스 식별자(:mod:`forensiclab.rtp` SSRC 와 상관).
        message_type: 메시지 타입(공백 제거, ``"Hello"``·``"Commit"`` 등).
        message_length: ZRTP 메시지 길이(바이트; 워드×4, CRC 제외).
        message_offset: ZRTP 메시지 프리앰블이 시작하는 절대 offset.
        version: Hello 의 프로토콜 버전(``"1.10"`` 등; 그 외 ``None``).
        client_id: Hello 의 16바이트 Client Identifier(소프트폰 핑거프린트).
        zid: Hello 의 12바이트 ZID 16진 문자열(영구 단말 식별자).
        hash_algos·cipher_algos·auth_tags·key_agreements·sas_types: Hello 의
            협상 알고리즘 목록(4글자 토큰).
        passive·mitm·sign_capable: Hello 플래그 비트(P·M·S).
        error_code: Error 메시지의 32비트 오류 코드(그 외 ``None``).
    """

    sequence: int = 0
    ssrc: int = 0
    message_type: str = ""
    message_length: int = 0
    message_offset: int = 0
    version: Optional[str] = None
    client_id: Optional[str] = None
    zid: Optional[str] = None
    hash_algos: List[str] = field(default_factory=list)
    cipher_algos: List[str] = field(default_factory=list)
    auth_tags: List[str] = field(default_factory=list)
    key_agreements: List[str] = field(default_factory=list)
    sas_types: List[str] = field(default_factory=list)
    passive: bool = False
    mitm: bool = False
    sign_capable: bool = False
    error_code: Optional[int] = None

    @property
    def is_hello(self) -> bool:
        """Hello 메시지(능력·신원 광고)인지."""
        return self.message_type == "Hello"

    @property
    def is_commit(self) -> bool:
        """Commit 메시지(알고리즘 확정·DH 개시)인지."""
        return self.message_type == "Commit"

    @property
    def is_error(self) -> bool:
        """Error 메시지(협상 실패·MITM 정황)인지."""
        return self.message_type == "Error"

    @property
    def is_clear_downgrade(self) -> bool:
        """``GoClear``/``ClearACK`` — 암호화 미디어의 평문 전환(감청 다운그레이드 정황)."""
        return self.message_type in _CLEAR_TYPES

    @property
    def is_known_type(self) -> bool:
        """메시지 타입이 RFC 6189 정의 집합에 속하는지(미지정=오탐/난독 정황)."""
        return self.message_type in MESSAGE_TYPES


def _parse_hello(body: bytes) -> dict:
    """Hello 메시지 본문(Message Type Block 다음)에서 신원·능력 필드 추출.

    body 는 8바이트 타입 블록 **다음**부터 시작. 모든 접근은 길이 검사로 가드해
    잘린 입력에도 받은 데까지만 채운다(버퍼 초과 금지).
    """
    out: dict = {}
    # version(4) + client_id(16) + H3(32) + ZID(12) = 64바이트.
    if len(body) >= 4:
        out["version"] = body[0:4].decode("ascii", "replace").strip()
    if len(body) >= 20:
        out["client_id"] = body[4:20].decode("ascii", "replace").strip()
    # H3 해시 이미지(32바이트, body[20:52])는 건너뛴다.
    if len(body) >= 64:
        out["zid"] = body[52:64].hex()
    # 플래그+알고리즘 카운트 워드(body[64:68]).
    if len(body) >= 68:
        word = struct.unpack_from(">I", body, 64)[0]
        out["sign_capable"] = bool((word >> 27) & 1)  # S
        out["mitm"] = bool((word >> 26) & 1)           # M (PBX 등)
        out["passive"] = bool((word >> 25) & 1)        # P
        hc = (word >> 16) & 0xF
        cc = (word >> 12) & 0xF
        ac = (word >> 8) & 0xF
        kc = (word >> 4) & 0xF
        sc = word & 0xF
        algos = body[68:]
        out["hash_algos"] = _split_words(algos, hc)
        out["cipher_algos"] = _split_words(algos[hc * 4:], cc)
        out["auth_tags"] = _split_words(algos[(hc + cc) * 4:], ac)
        out["key_agreements"] = _split_words(algos[(hc + cc + ac) * 4:], kc)
        out["sas_types"] = _split_words(algos[(hc + cc + ac + kc) * 4:], sc)
    return out


def parse_zrtp(data: bytes, offset: int = 0) -> Optional[ZrtpPacket]:
    """단일 ZRTP 패킷을 파싱.

    Args:
        data: ZRTP 패킷 바이트(보통 :mod:`forensiclab.netdissect` UDP 페이로드,
            :mod:`forensiclab.rtp` 가 버전 검증으로 떨군 짝수 포트 패킷).
        offset: 파싱 시작 위치(기본 0).

    Returns:
        :class:`ZrtpPacket`. 매직 쿠키가 없으면(비-ZRTP 가드) ``None``. 헤더는
        있으나 메시지가 잘리면 헤더 필드만 채워 반환한다(본문은 가용분까지).
    """
    if not isinstance(data, (bytes, bytearray)):
        return None
    # 헤더 12바이트(프리앰블/seq·매직·SSRC) 최소 필요.
    if len(data) - offset < 12:
        return None
    if struct.unpack_from(">I", data, offset + 4)[0] != ZRTP_MAGIC:
        return None

    # 헤더: 첫 워드 하위 16비트=시퀀스, offset+8 워드=SSRC.
    first_word = struct.unpack_from(">I", data, offset)[0]
    sequence = first_word & 0xFFFF
    ssrc = struct.unpack_from(">I", data, offset + 8)[0]

    msg_off = offset + 12
    fields: dict = {}
    message_type = ""
    message_length = 0

    # ZRTP 메시지: 프리앰블(2)+length 워드(2)+타입 블록(8)+본문.
    if len(data) - msg_off >= 4:
        preamble, length_words = struct.unpack_from(">HH", data, msg_off)
        if preamble == ZRTP_MESSAGE_PREAMBLE:
            message_length = length_words * 4
            type_off = msg_off + 4
            if len(data) - type_off >= 8:
                message_type = data[type_off:type_off + 8].decode(
                    "ascii", "replace"
                ).strip()
                body = data[type_off + 8:]
                if message_type == "Hello":
                    fields = _parse_hello(body)
                elif message_type == "Error" and len(body) >= 4:
                    fields["error_code"] = struct.unpack_from(">I", body, 0)[0]

    return ZrtpPacket(
        sequence=sequence,
        ssrc=ssrc,
        message_type=message_type,
        message_length=message_length,
        message_offset=msg_off,
        **fields,
    )
