"""SDP — Session Description Protocol 파싱 코어 (RFC 4566/8866).

:mod:`forensiclab.sip` 가 ``body_offset`` 만 알려 주고 해석하지 않는 INVITE/200
바디가 바로 SDP 다. SDP 는 VoIP/WebRTC 의 **세션 협상서** — 신호(SIP)와
미디어(:mod:`forensiclab.rtp`) 사이에서 "어떤 코덱을, 어느 IP·포트로, 암호화
하나 평문이냐"를 적어 둔 평문 텍스트다. SIP/RTP/STUN 파서가 공통으로 가리키던
"SIP INVITE 의 SDP 가 협상한 코덱·포트, STUN 반사 주소의 목적지" 를 이 모듈이
실제로 파낸다(VoIP 삼각형 sip→sdp→rtp 의 가운데 꼭짓점).

와이어 포맷은 ``<type>=<value>`` 한 글자 타입의 줄 묶음(``v=``/``o=``/``s=``/
``c=``/``t=``/``m=``/``a=`` …)이고, ``m=`` 줄이 나오면 그 아래 줄들은 해당
**미디어 블록** 소속이다. :mod:`forensiclab.sip`/:mod:`forensiclab.http` 의
줄 단위 파싱 정신을 잇되, SDP 전용 단서만 위에 얹는다.

SDP 는 침해/사고 분석에서 다음 단서를 준다:

- **미디어 IP 누출/de-anonymization**: ``c=`` 연결 주소·``a=candidate``(ICE)는
  미디어가 실제로 흐르는 IP — VPN/프록시 뒤 단말의 사설/공인 주소가 평문으로
  드러나 :mod:`forensiclab.stun` 의 XOR-MAPPED 반사 주소와 상관(호스트 귀속).
- **코덱·포트 협상**: ``m=`` 미디어 줄(종류·포트·전송·payload type 목록)과
  ``a=rtpmap`` 은 :mod:`forensiclab.rtp` 가 볼 SSRC 스트림의 포트·코덱을 예고 —
  G.711(PCMU/PCMA) 같은 평문 음성이면 통화 내용 복원 표면.
- **암호화 자세(SRTP vs 평문)**: 전송이 ``RTP/AVP`` 면 평문 RTP(감청 가능),
  ``RTP/SAVP``/``UDP/TLS/RTP/SAVP`` 면 SRTP. ``a=crypto``(SDES)는 **세션 키를
  SDP 평문에 그대로 실어** 신호 경로를 본 사람이 미디어를 복호할 수 있는
  치명적 노출, ``a=fingerprint`` 는 DTLS-SRTP 핑거프린트.
- **세션 핑거프린트·상관**: ``o=`` origin 의 username·세션 ID·발신 IP 와
  ``s=`` 세션명으로 통화 당사자·도구를 귀속하고 :mod:`forensiclab.sip`
  Call-ID·:mod:`forensiclab.timeline` 과 잇는다.

설계 원칙(:mod:`forensiclab.sip` 와 동일):
- 부작용 없음: 디스크/표준출력/네트워크 없이 순수 함수.
- stdlib 전용: 외부 의존성 없음.
- 안전: 입력 바이트를 변형하지 않는다(읽기 전용).
- 견고: ``v=`` 로 시작하지 않으면(비-SDP) 예외 대신 ``None``. 망가진 줄은 건너뛴다.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

__all__ = [
    "MEDIA_TYPES",
    "ENCRYPTED_TRANSPORTS",
    "SdpMedia",
    "SdpSession",
    "parse",
]

# RFC 4566 §5.14 등록 미디어 종류(첫 토큰). 검증용은 아니고 분류 보조.
MEDIA_TYPES = frozenset({"audio", "video", "text", "application", "message"})

# 전송 프로파일에 이 토큰이 있으면 SRTP(암호화). 없으면(RTP/AVP) 평문 RTP.
ENCRYPTED_TRANSPORTS = ("SAVP", "TLS")

# payload type → 잘 알려진 정적 코덱(RFC 3551). rtpmap 이 없을 때 보조 해석.
_STATIC_PAYLOAD = {
    0: "PCMU/8000",
    3: "GSM/8000",
    4: "G723/8000",
    8: "PCMA/8000",
    9: "G722/8000",
    18: "G729/8000",
    34: "H263/90000",
}


def _parse_lines(text: str) -> List[Tuple[str, str]]:
    """``<type>=<value>`` 줄들을 ``(type, value)`` 목록으로. 빈 줄·깨진 줄은 무시."""
    out: List[Tuple[str, str]] = []
    for raw in text.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        if not raw:
            continue
        eq = raw.find("=")
        if eq != 1:  # SDP 타입은 정확히 한 글자(예: 'v=')여야.
            continue
        out.append((raw[0], raw[2:]))
    return out


@dataclass(frozen=True)
class _AttrHolder:
    """세션·미디어가 공유하는 ``a=`` 속성·``c=`` 연결 접근 믹스인(내부용)."""

    # (name, value) 순서 보존 목록. 플래그 속성(a=sendrecv)은 value=""→None 으로 본다.
    attributes: List[Tuple[str, Optional[str]]] = field(default_factory=list)
    connection: Optional[str] = None  # 원본 c= 값(예: 'IN IP4 10.0.0.5').

    def attr_values(self, name: str) -> List[str]:
        """이름이 일치하는 모든 속성 값(값 없는 플래그는 제외)."""
        return [v for n, v in self.attributes if n == name and v is not None]

    def attr_value(self, name: str) -> Optional[str]:
        """이름이 일치하는 첫 속성 값(없으면 ``None``)."""
        vals = self.attr_values(name)
        return vals[0] if vals else None

    def has_flag(self, name: str) -> bool:
        """값 없는 플래그 속성(예: ``a=rtcp-mux``) 존재 여부."""
        return any(n == name for n, _ in self.attributes)

    @property
    def connection_address(self) -> Optional[str]:
        """``c=`` 의 주소 토큰(``IN IP4 <addr>`` 의 ``<addr>``; 멀티캐스트 ``/ttl`` 제거)."""
        if not self.connection:
            return None
        parts = self.connection.split()
        if len(parts) < 3:
            return None
        return parts[2].split("/")[0]

    @property
    def candidates(self) -> List[str]:
        """``a=candidate`` 값 목록 — ICE 후보(host/srflx/relay IP 누출 단서)."""
        return self.attr_values("candidate")

    @property
    def crypto(self) -> List[str]:
        """``a=crypto`` 값 목록 — SDES-SRTP **평문 세션 키** 노출(치명)."""
        return self.attr_values("crypto")

    @property
    def fingerprint(self) -> Optional[str]:
        """``a=fingerprint`` 값 — DTLS-SRTP 인증서 핑거프린트(없으면 ``None``)."""
        return self.attr_value("fingerprint")


@dataclass(frozen=True)
class SdpMedia(_AttrHolder):
    """하나의 ``m=`` 미디어 블록.

    Attributes:
        media: 미디어 종류(``"audio"``·``"video"`` 등).
        port: 미디어 포트(원본 문자열, ``"49170"`` 또는 ``"49170/2"``).
        protocol: 전송 프로파일(``"RTP/AVP"``·``"RTP/SAVP"``·``"UDP/TLS/RTP/SAVP"``).
        formats: payload type/포맷 토큰 목록(``["0", "8", "97"]``).
        attributes: 이 미디어에 딸린 ``a=`` 속성.
        connection: 이 미디어 전용 ``c=`` 값(있으면 세션 c= 를 덮어쓴다).
    """

    media: str = ""
    port: str = ""
    protocol: str = ""
    formats: List[str] = field(default_factory=list)

    @property
    def is_audio(self) -> bool:
        """음성 미디어 여부(평문이면 통화 내용 복원 표면)."""
        return self.media == "audio"

    @property
    def is_video(self) -> bool:
        """영상 미디어 여부."""
        return self.media == "video"

    @property
    def is_encrypted(self) -> bool:
        """전송 프로파일이 SRTP/DTLS(``SAVP``/``TLS``)면 ``True``, ``RTP/AVP`` 면 평문."""
        return any(tok in self.protocol for tok in ENCRYPTED_TRANSPORTS)

    @property
    def direction(self) -> str:
        """미디어 방향 속성(``sendrecv``/``sendonly``/``recvonly``/``inactive``).

        명시 속성이 없으면 RFC 기본값 ``"sendrecv"``.
        """
        for name in ("inactive", "recvonly", "sendonly", "sendrecv"):
            if self.has_flag(name):
                return name
        return "sendrecv"

    @property
    def rtpmap(self) -> Dict[int, str]:
        """payload type(int) → 코덱 문자열. ``a=rtpmap`` 우선, 없으면 정적 표 보조.

        ``a=rtpmap:0 PCMU/8000`` → ``{0: "PCMU/8000"}``. :mod:`forensiclab.rtp`
        의 ``payload_type`` 해석과 상관(어떤 SSRC 스트림이 무슨 코덱인지).
        """
        out: Dict[int, str] = {}
        for fmt in self.formats:
            try:
                pt = int(fmt)
            except ValueError:
                continue
            if pt in _STATIC_PAYLOAD:
                out[pt] = _STATIC_PAYLOAD[pt]
        for val in self.attr_values("rtpmap"):
            tok = val.split(None, 1)
            if len(tok) != 2:
                continue
            try:
                out[int(tok[0])] = tok[1].strip()
            except ValueError:
                continue
        return out


@dataclass(frozen=True)
class SdpSession(_AttrHolder):
    """파싱된 SDP 세션 기술서(세션 레벨 필드 + 미디어 블록 목록).

    Attributes:
        version: ``v=`` 값(보통 ``"0"``).
        origin: ``o=`` 원본 값(``username sess-id sess-ver nettype addrtype addr``).
        session_name: ``s=`` 세션명.
        connection: 세션 레벨 ``c=`` 값(미디어가 자기 c= 없으면 이것을 쓴다).
        attributes: 세션 레벨 ``a=`` 속성.
        media: ``m=`` 미디어 블록 목록.
    """

    version: str = ""
    origin: str = ""
    session_name: str = ""
    media: List[SdpMedia] = field(default_factory=list)

    @property
    def origin_username(self) -> Optional[str]:
        """``o=`` 첫 토큰 — 세션 생성자 username(``"-"`` 면 익명; 없으면 ``None``)."""
        parts = self.origin.split()
        return parts[0] if parts else None

    @property
    def origin_address(self) -> Optional[str]:
        """``o=`` 마지막 토큰 — 세션 생성 호스트의 IP/주소(발신 단말 귀속 단서)."""
        parts = self.origin.split()
        return parts[-1] if len(parts) >= 6 else None

    @property
    def media_addresses(self) -> List[str]:
        """각 미디어가 실제로 흐를 주소(미디어 c= 우선, 없으면 세션 c=).

        미디어 IP 누출의 핵심 — :mod:`forensiclab.stun` 반사 주소·실제 RTP
        목적지와 상관(중복 제거, 순서 보존).
        """
        session_addr = self.connection_address
        out: List[str] = []
        for m in self.media:
            addr = m.connection_address or session_addr
            if addr and addr not in out:
                out.append(addr)
        return out

    @property
    def is_encrypted(self) -> bool:
        """미디어가 하나라도 있고 **모두** SRTP/DTLS 면 ``True``(평문이 섞이면 ``False``)."""
        return bool(self.media) and all(m.is_encrypted for m in self.media)

    @property
    def has_cleartext_media(self) -> bool:
        """평문 RTP(``RTP/AVP``) 미디어가 하나라도 있으면 ``True`` — 감청 표면."""
        return any(not m.is_encrypted for m in self.media)

    @property
    def all_candidates(self) -> List[str]:
        """세션·전 미디어의 ``a=candidate`` 합본 — ICE IP 후보 전수(IP 누출)."""
        out = list(self.candidates)
        for m in self.media:
            out.extend(m.candidates)
        return out

    @property
    def all_crypto(self) -> List[str]:
        """세션·전 미디어의 ``a=crypto`` 합본 — 평문 SRTP 키 노출 전수(치명)."""
        out = list(self.crypto)
        for m in self.media:
            out.extend(m.crypto)
        return out


def parse(data) -> Optional[SdpSession]:
    """SDP 바디(보통 :mod:`forensiclab.sip` INVITE/200 의 ``body_offset`` 이후)를 파싱.

    Args:
        data: SDP 텍스트. ``bytes`` 면 ASCII(UTF-8)로 디코드, ``str`` 도 허용.

    Returns:
        :class:`SdpSession`. 첫 의미 줄이 ``v=<숫자>`` 가 아니면(비-SDP 가드)
        ``None``. ``m=`` 이전 줄은 세션 레벨, 이후 줄은 직전 미디어 블록 소속.
        망가진 줄은 건너뛴다(부분 입력도 받은 데까지 채운다).
    """
    if isinstance(data, (bytes, bytearray)):
        text = bytes(data).decode("utf-8", "replace")
    elif isinstance(data, str):
        text = data
    else:
        return None

    lines = _parse_lines(text)
    if not lines:
        return None

    # 비-SDP 가드: SDP 는 반드시 'v=' 줄로 시작하고 값은 버전 숫자.
    if lines[0][0] != "v" or not lines[0][1].strip().isdigit():
        return None

    version = ""
    origin = ""
    session_name = ""
    sess_attrs: List[Tuple[str, Optional[str]]] = []
    sess_conn: Optional[str] = None
    media_blocks: List[SdpMedia] = []

    # 현재 채우는 미디어 블록의 가변 누적기(없으면 세션 레벨).
    cur: Optional[dict] = None

    def _flush():
        if cur is not None:
            media_blocks.append(
                SdpMedia(
                    media=cur["media"],
                    port=cur["port"],
                    protocol=cur["protocol"],
                    formats=cur["formats"],
                    attributes=cur["attributes"],
                    connection=cur["connection"],
                )
            )

    for typ, value in lines:
        if typ == "m":
            _flush()
            parts = value.split()
            cur = {
                "media": parts[0] if parts else "",
                "port": parts[1] if len(parts) > 1 else "",
                "protocol": parts[2] if len(parts) > 2 else "",
                "formats": parts[3:],
                "attributes": [],
                "connection": None,
            }
            continue

        if typ == "a":
            colon = value.find(":")
            if colon == -1:
                name, val = value, None  # 플래그 속성(a=sendrecv).
            else:
                name, val = value[:colon], value[colon + 1:]
            target = cur["attributes"] if cur is not None else sess_attrs
            target.append((name, val))
            continue

        if typ == "c":
            if cur is not None:
                cur["connection"] = value
            else:
                sess_conn = value
            continue

        # 세션 레벨 단발 필드(미디어 시작 전에만 의미).
        if cur is None:
            if typ == "v":
                version = value
            elif typ == "o":
                origin = value
            elif typ == "s":
                session_name = value

    _flush()

    return SdpSession(
        version=version,
        origin=origin,
        session_name=session_name,
        connection=sess_conn,
        attributes=sess_attrs,
        media=media_blocks,
    )
