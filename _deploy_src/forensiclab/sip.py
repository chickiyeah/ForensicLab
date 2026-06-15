"""SIP — Session Initiation Protocol 파싱 코어 (RFC 3261).

:mod:`forensiclab.netdissect` 가 식별한 UDP/TCP(관용 포트 5060, TLS 는 5061)
페이로드는 SIP 메시지일 수 있다. SIP 는 VoIP/영상통화의 **신호(signaling)**
프로토콜이고, :mod:`forensiclab.stun`/TURN 이 그 **미디어(media)** 경로의 토대인
것과 짝을 이룬다("INVITE 로 누가 누구에게 걸었나" → SDP 바디의 후보 주소가
STUN 반사 주소와 상관). 와이어 포맷은 HTTP 와 매우 닮아서(요청 라인+헤더+빈 줄
+바디) :mod:`forensiclab.http` 의 줄 단위 파싱을 그대로 빌려 SIP 전용 단서만
위에 얹는다.

SIP 는 침해/사고 분석에서 여러 단서를 준다:

- **VoIP 스캐닝·toll fraud**: ``REGISTER``/``OPTIONS``/``INVITE`` 무차별 탐색
  (sipvicious ``friendly-scanner``·``sipcli``·``sundayddr`` 같은 User-Agent)으로
  내선·게이트웨이를 찾아 무단 국제전화(통화료 사기)·war-dialing 으로 잇는다 —
  ``is_scanner`` 로 알려진 스캐너 User-Agent 를 식별.
- **자격증명 수집·brute force**: ``REGISTER`` 의 ``Authorization``/``Proxy-
  Authorization: Digest`` 헤더에서 ``username``/``realm`` 평문 노출(다이제스트
  해시 크래킹·계정 열거 단서) — :mod:`forensiclab.ntlm` 의 자격증명 흔적 형제.
- **통화 메타데이터·CDR 재구성**: ``From``/``To`` URI(누가 누구에게)·``Call-ID``
  (통화 상관)·``CSeq`` 로 한 통화의 INVITE→ACK→BYE 흐름을 잇는다.
- **발신번호 위조(caller-ID spoofing)**: ``From`` 디스플레이/URI 와 실제 전송
  경로(``Via``)·``Contact`` 불일치는 신원 위조 정황.
- **구현 핑거프린트**: ``User-Agent``/``Server`` 는 IP-PBX(Asterisk·FreeSWITCH)·
  소프트폰·멀웨어 봇 식별(취약 버전 상관).

설계 원칙(:mod:`forensiclab.http` 와 동일):
- 부작용 없음: 디스크/표준출력/네트워크 없이 순수 함수.
- stdlib 전용: 외부 의존성 없음.
- 안전: 입력 바이트를 변형하지 않는다(읽기 전용). 바디는 해석하지 않고
  ``body_offset`` 만 알려 준다(증분을 작게 유지).
- 견고: 요청/상태 라인이 없거나 망가진 입력은 예외 대신 ``None``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Optional

__all__ = [
    "SIP_METHODS",
    "SIP_VERSION",
    "SIP_PORT",
    "COMPACT_HEADERS",
    "SCANNER_AGENTS",
    "SipRequest",
    "SipResponse",
    "parse_request",
    "parse_response",
]

# 표준 메서드 화이트리스트(RFC 3261 + 확장 RFC 3262/3265/3311/3428/3515).
# 요청 라인 첫 토큰이 여기 없으면 SIP 가 아니라고 보고 None — HTTP·비-SIP 가드.
SIP_METHODS = frozenset({
    "INVITE", "ACK", "BYE", "CANCEL", "REGISTER", "OPTIONS",
    "PRACK", "SUBSCRIBE", "NOTIFY", "PUBLISH", "INFO",
    "REFER", "MESSAGE", "UPDATE",
})

SIP_VERSION = "SIP/2.0"
SIP_PORT = 5060

# 압축(compact) 헤더 형식 → 정식 이름(소문자). RFC 3261 §20·RFC 3265.
# 단일 문자 키를 정식 이름으로 정규화해 호출 측이 헤더를 예측 가능하게 본다.
COMPACT_HEADERS = {
    "i": "call-id",
    "m": "contact",
    "e": "content-encoding",
    "l": "content-length",
    "c": "content-type",
    "f": "from",
    "s": "subject",
    "k": "supported",
    "t": "to",
    "v": "via",
    "o": "event",
    "u": "allow-events",
    "r": "refer-to",
    "b": "referred-by",
    "x": "session-expires",
}

# 알려진 SIP 스캐너/감사 도구 User-Agent(소문자 부분 일치). VoIP 정찰 단서.
SCANNER_AGENTS = frozenset({
    "friendly-scanner",  # sipvicious svwar/svmap
    "sipvicious",
    "sipcli",
    "sundayddr",
    "sip-scan",
    "sipsak",
    "smap",
    "iwar",
    "warvox",
    "pplsip",
    "vaxsipuseragent",
})

_CRLF = b"\r\n"
_HEADER_SEP = b"\r\n\r\n"
_MAX_HEADER_BYTES = 64 * 1024  # 헤더 폭주 입력 상한.


def _normalize_name(name: str) -> str:
    """헤더 이름을 소문자 정식 이름으로(압축 형식이면 펼친다)."""
    low = name.lower()
    return COMPACT_HEADERS.get(low, low)


@dataclass(frozen=True)
class _SipMessage:
    """요청·응답이 공유하는 헤더 접근 믹스인(내부용)."""

    headers: Dict[str, str] = field(default_factory=dict)
    body_offset: int = 0

    @property
    def call_id(self) -> Optional[str]:
        """``Call-ID`` — 한 통화/대화 상관 키(없으면 ``None``)."""
        return self.headers.get("call-id")

    @property
    def from_uri(self) -> Optional[str]:
        """``From`` 헤더 값 — 발신자(위조 가능, 누가 걸었나; 없으면 ``None``)."""
        return self.headers.get("from")

    @property
    def to_uri(self) -> Optional[str]:
        """``To`` 헤더 값 — 수신자(누구에게 걸었나; 없으면 ``None``)."""
        return self.headers.get("to")

    @property
    def via(self) -> Optional[str]:
        """최상단 ``Via`` 값 — 실제 전송 경로(From 위조 대조 단서)."""
        return self.headers.get("via")

    @property
    def contact(self) -> Optional[str]:
        """``Contact`` 헤더 값 — 직접 도달 주소(없으면 ``None``)."""
        return self.headers.get("contact")

    @property
    def cseq(self) -> Optional[str]:
        """``CSeq`` 헤더 값(``숫자 METHOD``) — 트랜잭션 순서/상관."""
        return self.headers.get("cseq")

    @property
    def user_agent(self) -> Optional[str]:
        """``User-Agent`` — 소프트폰/IP-PBX/봇 핑거프린트(없으면 ``None``)."""
        return self.headers.get("user-agent")

    @property
    def server(self) -> Optional[str]:
        """``Server`` — 서버측 구현 핑거프린트(응답; 없으면 ``None``)."""
        return self.headers.get("server")

    @property
    def authorization(self) -> Optional[str]:
        """``Authorization`` 또는 ``Proxy-Authorization`` 값(Digest 자격증명)."""
        return self.headers.get("authorization") or self.headers.get(
            "proxy-authorization"
        )

    @property
    def auth_username(self) -> Optional[str]:
        """Digest 인증 헤더에서 ``username`` 파라미터 평문(없으면 ``None``).

        ``REGISTER`` brute force·계정 열거·다이제스트 해시 크래킹 상관 단서.
        """
        return self._auth_param("username")

    @property
    def auth_realm(self) -> Optional[str]:
        """Digest 인증 헤더의 ``realm`` 파라미터(인증 도메인; 없으면 ``None``)."""
        return self._auth_param("realm")

    def _auth_param(self, key: str) -> Optional[str]:
        raw = self.authorization
        if raw is None:
            return None
        # 'Digest username="alice", realm="asterisk", ...' 에서 key="value" 추출.
        needle = key + "="
        idx = raw.lower().find(needle)
        if idx == -1:
            return None
        rest = raw[idx + len(needle):].lstrip()
        if rest.startswith('"'):
            end = rest.find('"', 1)
            return rest[1:end] if end != -1 else rest[1:]
        # 따옴표 없는 토큰(콤마/공백 전까지).
        for sep in (",", " "):
            pos = rest.find(sep)
            if pos != -1:
                rest = rest[:pos]
        return rest

    @property
    def is_scanner(self) -> bool:
        """알려진 SIP 스캐너/감사 도구 User-Agent 여부 — VoIP 정찰 단서."""
        ua = self.user_agent or self.server
        if not ua:
            return False
        low = ua.lower()
        return any(sig in low for sig in SCANNER_AGENTS)


@dataclass(frozen=True)
class SipRequest(_SipMessage):
    """파싱된 SIP 요청(요청 라인 + 헤더).

    Attributes:
        method: 요청 메서드(대문자, 예: ``"INVITE"``).
        uri: Request-URI(원본 그대로, 예: ``"sip:bob@biloxi.com"``).
        version: SIP 버전 문자열(항상 ``"SIP/2.0"``).
        headers: 헤더 이름(소문자·압축형 펼침) → 값. 중복은 ``", "`` 로 합침.
        body_offset: 바디 시작 바이트 오프셋(헤더 종료 CRLFCRLF 직후).
    """

    method: str = ""
    uri: str = ""
    version: str = SIP_VERSION

    @property
    def is_register(self) -> bool:
        """``REGISTER`` 여부 — 자격증명/등록 흐름(brute force 표적)."""
        return self.method == "REGISTER"

    @property
    def is_invite(self) -> bool:
        """``INVITE`` 여부 — 통화 시작(toll fraud·CDR 단서)."""
        return self.method == "INVITE"


@dataclass(frozen=True)
class SipResponse(_SipMessage):
    """파싱된 SIP 응답(상태 라인 + 헤더).

    Attributes:
        version: SIP 버전 문자열(항상 ``"SIP/2.0"``).
        status_code: 상태 코드 정수(예: ``200``, ``401``, ``404``).
        reason: reason-phrase(예: ``"OK"``, ``"Unauthorized"``).
        headers: 헤더 이름(소문자·압축형 펼침) → 값. 중복은 ``", "`` 로 합침.
        body_offset: 바디 시작 바이트 오프셋(헤더 종료 CRLFCRLF 직후).
    """

    version: str = SIP_VERSION
    status_code: int = 0
    reason: str = ""

    @property
    def is_auth_required(self) -> bool:
        """401/407 여부 — 인증 챌린지(REGISTER brute force 진행 단서)."""
        return self.status_code in (401, 407)


def _split_head(data: bytes):
    """헤더 섹션을 끊어 ``(첫 줄, 나머지 헤더 줄들, body_offset)``.

    :mod:`forensiclab.http` 와 같은 전처리: 헤더 종료 CRLFCRLF 로 헤더/바디
    경계를 구하고 첫 줄과 ``Name: value`` 줄들을 분리한다. 입력이 비었거나
    헤더가 상한을 넘으면 ``None``.
    """
    if not data:
        return None

    sep_index = data.find(_HEADER_SEP)
    if sep_index == -1:
        header_block = data[:_MAX_HEADER_BYTES]
        body_offset = len(data)
    else:
        if sep_index > _MAX_HEADER_BYTES:
            return None
        header_block = data[:sep_index]
        body_offset = sep_index + len(_HEADER_SEP)

    lines = header_block.split(_CRLF)
    return lines[0], lines[1:], body_offset


def _parse_headers(raw_lines) -> Dict[str, str]:
    """``Name: value`` 줄 목록을 정규화 소문자 키 dict 로. 중복은 ``", "`` 로 합침."""
    headers: Dict[str, str] = {}
    for raw in raw_lines:
        if not raw:
            continue
        colon = raw.find(b":")
        if colon == -1:
            continue
        name = _normalize_name(raw[:colon].decode("ascii", "replace").strip())
        value = raw[colon + 1:].decode("ascii", "replace").strip()
        if not name:
            continue
        if name in headers:
            headers[name] = headers[name] + ", " + value
        else:
            headers[name] = value
    return headers


def parse_request(data: bytes) -> Optional[SipRequest]:
    """UDP/TCP 페이로드 바이트를 SIP 요청으로 파싱한다.

    Args:
        data: 클라이언트→서버 방향 원시 바이트(보통 UDP/TCP 5060 페이로드).

    Returns:
        :class:`SipRequest`. 요청 라인이 ``METHOD URI SIP/2.0`` 꼴이 아니거나
        메서드가 :data:`SIP_METHODS` 에 없거나 버전이 ``SIP/2.0`` 이 아니면
        ``None``(HTTP·비-SIP 가드). 헤더 종료가 아직 안 왔으면 받은 데까지만
        채우고 ``body_offset`` 은 입력 끝으로 둔다.
    """
    head = _split_head(data)
    if head is None:
        return None
    request_line, header_lines, body_offset = head

    parts = request_line.split(b" ")
    if len(parts) != 3:
        return None

    method = parts[0].decode("ascii", "replace")
    if method not in SIP_METHODS:
        return None
    version = parts[2].decode("ascii", "replace")
    if version != SIP_VERSION:
        return None
    uri = parts[1].decode("ascii", "replace")

    return SipRequest(
        method=method,
        uri=uri,
        version=version,
        headers=_parse_headers(header_lines),
        body_offset=body_offset,
    )


def parse_response(data: bytes) -> Optional[SipResponse]:
    """UDP/TCP 페이로드 바이트를 SIP 응답으로 파싱한다.

    Args:
        data: 서버→클라이언트 방향 원시 바이트.

    Returns:
        :class:`SipResponse`. 상태 라인이 ``SIP/2.0 CODE [reason]`` 꼴이 아니거나
        상태 코드가 3자리 정수가 아니면 ``None``. 헤더 종료가 아직 안 왔으면
        받은 데까지만 채우고 ``body_offset`` 은 입력 끝으로 둔다.
    """
    head = _split_head(data)
    if head is None:
        return None
    status_line, header_lines, body_offset = head

    parts = status_line.split(b" ", 2)
    if len(parts) < 2:
        return None

    version = parts[0].decode("ascii", "replace")
    if version != SIP_VERSION:
        return None

    code_bytes = parts[1]
    if len(code_bytes) != 3 or not code_bytes.isdigit():
        return None
    status_code = int(code_bytes)

    reason = parts[2].decode("ascii", "replace").strip() if len(parts) == 3 else ""

    return SipResponse(
        version=version,
        status_code=status_code,
        reason=reason,
        headers=_parse_headers(header_lines),
        body_offset=body_offset,
    )
