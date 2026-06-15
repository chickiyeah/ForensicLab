"""rdp — RDP 연결 요청(X.224 Connection Request) 파싱 코어 (MS-RDPBCGR).

:mod:`forensiclab.netdissect` 가 식별한 TCP(포트 3389) 페이로드의 첫
패킷은 RDP 연결 협상의 시작인 **X.224 Connection Request PDU** 일 수
있다. 이 모듈이 그 PDU 를 해석한다. :mod:`forensiclab.telnet`(23)·
:mod:`forensiclab.rlogin`(513)·:mod:`forensiclab.rcmd`(512/514)·
:mod:`forensiclab.ssh`(22) 와 같은 **원격 접속/측면 이동** 계열이며,
오늘날 Windows 환경의 RDP 브루트포스·측면 이동의 1순위 증거다.

연결 요청은 TPKT 로 프레이밍된다(RFC 1006/2126)::

    TPKT 헤더 (4 바이트):
        version(0x03) · reserved(0x00) · length(big-endian, 2)

그 안에 X.224(ISO 8073) Class 0 Connection Request TPDU 가 온다::

    LI(1) · CR|CDT(0xE0, 1) · DST-REF(2) · SRC-REF(2) · CLASS(1)
    ── 이후 가변부(user data): [routingToken | cookie] [rdpNegReq] ...

가변부의 쿠키 한 줄(``CRLF`` 종단, MS-RDPBCGR 2.2.1.1)이 핵심이다::

    Cookie: mstshash=<IDENTIFIER>\\r\\n   (사용자명/도메인 식별자 — 평문)
    Cookie: msts=<ROUTING-TOKEN>\\r\\n     (브로커 라우팅 토큰)

그 뒤 RDP Negotiation Request(2.2.1.1.1, 8 바이트)가 요청 보안
프로토콜을 평문으로 싣는다::

    type(0x01) · flags(1) · length(0x0008, LE 2) · requestedProtocols(LE 4)

    requestedProtocols 비트:
        0x00000000  PROTOCOL_RDP        표준 RDP 보안(NLA 없음·레거시)
        0x00000001  PROTOCOL_SSL        TLS
        0x00000002  PROTOCOL_HYBRID     CredSSP/NLA
        0x00000004  PROTOCOL_RDSTLS
        0x00000008  PROTOCOL_HYBRID_EX

평문·인증 이전(pre-auth) 메시지라 사고 분석 단서가 매우 짙다:

- **사용자 귀속(``mstshash``)**: 쿠키의 ``mstshash`` 식별자는 클라이언트가
  로그인하려는 사용자명/도메인을 **인증 전에 평문으로** 노출한다 — RDP
  브루트포스·패스워드 스프레이·측면 이동의 대상 계정을 직접 포착한다
  (:mod:`forensiclab.rlogin`·:mod:`forensiclab.rcmd` 의 계정 귀속과 동형).
- **브로커 라우팅 토큰(``msts``)**: ``msts`` 토큰은 연결을 특정 세션/
  브로커로 유도한다 — 세션 리다이렉션·환경 식별 단서(피벗 정황).
- **보안 프로토콜 협상(``requestedProtocols``)**: 클라이언트가 *요청한*
  보안을 평문으로 드러낸다. ``PROTOCOL_RDP`` 단독(값 0)은 **NLA 없는 표준
  RDP 보안** — 레거시·취약(BlueKeep CVE-2019-0708 계열)·다운그레이드
  정황이다. ``HYBRID``/``HYBRID_EX`` 는 NLA(CredSSP) 사용을 뜻한다.
- **Restricted Admin 모드(flags 0x01)**: 자격증명을 원격에 보내지 않는
  모드 요청. PtH 완화책이지만 동시에 pass-the-hash 횡적 이동에 악용되는
  벡터라 단서가 된다.

연결 요청 예(바이트)::

    03 00 00 2c 27 e0 00 00 00 00 00
    Cookie: mstshash=ADMIN\\r\\n
    01 00 08 00 03 00 00 00            (rdpNegReq: HYBRID|SSL = NLA+TLS)

설계 원칙(:mod:`forensiclab.rcmd`·:mod:`forensiclab.rlogin` 와 동일):
- 부작용 없음: 순수 함수. 디스크/표준출력/네트워크 없음.
- stdlib 전용.
- 안전: 입력 바이트를 변형하지 않는다(읽기 전용). 신고된 사용자
  식별자/라우팅 토큰을 노출하되 로깅/전송하지 않는다 — 호출자가 처리.
- 견고: 쿠키·negReq 중 일부만 있어도 있는 만큼 부분 파싱. TPKT/X.224 CR
  프레이밍이 아니거나 바이트가 없거나 offset 이 범위를 벗어나면 ``None``.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Optional, Tuple

__all__ = [
    "RDP_PORTS",
    "PROTOCOL_NAMES",
    "RdpConnectionRequest",
    "parse_rdp_connection_request",
]

# RDP 표준 포트(TCP). IANA 지정 3389.
RDP_PORTS = (3389,)

# requestedProtocols 비트 → 이름(MS-RDPBCGR 2.2.1.1.1).
PROTOCOL_NAMES = (
    (0x00000001, "PROTOCOL_SSL"),
    (0x00000002, "PROTOCOL_HYBRID"),
    (0x00000004, "PROTOCOL_RDSTLS"),
    (0x00000008, "PROTOCOL_HYBRID_EX"),
)

# rdpNegReq 비트 — NLA(CredSSP) 계열.
_PROTOCOL_HYBRID = 0x00000002
_PROTOCOL_HYBRID_EX = 0x00000008
_PROTOCOL_SSL = 0x00000001

# rdpNegReq flags(2.2.1.1.1).
_FLAG_RESTRICTED_ADMIN = 0x01            # RESTRICTED_ADMIN_MODE_REQUIRED
_FLAG_REDIRECTED_AUTH = 0x02             # REDIRECTED_AUTHENTICATION_MODE_REQUIRED
_FLAG_CORRELATION_INFO = 0x08            # CORRELATION_INFO_PRESENT

_TPKT_VERSION = 0x03
_X224_CR = 0xE0                          # Connection Request(상위 니블)
_TYPE_RDP_NEG_REQ = 0x01


@dataclass(frozen=True)
class RdpConnectionRequest:
    """파싱된 RDP X.224 Connection Request PDU.

    Attributes:
        tpkt_length: TPKT 가 신고한 전체 PDU 길이(바이트). 헤더가 없거나
            범위를 벗어나면 ``None``.
        cookie_type: ``"mstshash"``(사용자 식별자)·``"msts"``(라우팅 토큰)·
            ``None``(쿠키 없음).
        cookie_value: 쿠키의 값 문자열(``mstshash`` 면 사용자/도메인,
            ``msts`` 면 라우팅 토큰). 없으면 ``None``. **평문·위조 가능**.
        neg_present: rdpNegReq(요청 보안 협상 블록)가 있는가.
        neg_flags: rdpNegReq flags 바이트. 없으면 ``None``.
        requested_protocols: 요청 보안 프로토콜 비트마스크. 없으면 ``None``
            (값 ``0`` 은 표준 RDP 보안 요청 — ``None`` 과 구별됨).
        raw: 원본 바이트(읽기 전용 보존).
    """

    tpkt_length: Optional[int]
    cookie_type: Optional[str]
    cookie_value: Optional[str]
    neg_present: bool
    neg_flags: Optional[int]
    requested_protocols: Optional[int]
    raw: bytes

    @property
    def has_username(self) -> bool:
        """``mstshash`` 사용자 식별자가 평문으로 노출됐는가 — pre-auth 귀속."""
        return self.cookie_type == "mstshash" and bool(self.cookie_value)

    @property
    def username(self) -> Optional[str]:
        """노출된 ``mstshash`` 사용자/도메인 식별자(없으면 ``None``)."""
        return self.cookie_value if self.cookie_type == "mstshash" else None

    @property
    def has_routing_token(self) -> bool:
        """``msts`` 브로커 라우팅 토큰이 있는가 — 세션 리다이렉션/피벗 단서."""
        return self.cookie_type == "msts" and bool(self.cookie_value)

    @property
    def routing_token(self) -> Optional[str]:
        """브로커 라우팅 토큰(``msts``) 값(없으면 ``None``)."""
        return self.cookie_value if self.cookie_type == "msts" else None

    @property
    def protocols(self) -> Tuple[str, ...]:
        """요청 보안 프로토콜 이름들. 값 ``0`` 이면 ``("PROTOCOL_RDP",)``,
        negReq 가 없으면 빈 튜플."""
        rp = self.requested_protocols
        if rp is None:
            return ()
        if rp == 0:
            return ("PROTOCOL_RDP",)
        return tuple(name for bit, name in PROTOCOL_NAMES if rp & bit)

    @property
    def requests_nla(self) -> bool:
        """NLA(CredSSP, HYBRID/HYBRID_EX)를 요청했는가."""
        rp = self.requested_protocols
        return rp is not None and bool(rp & (_PROTOCOL_HYBRID | _PROTOCOL_HYBRID_EX))

    @property
    def requests_tls(self) -> bool:
        """TLS(PROTOCOL_SSL)를 요청했는가."""
        rp = self.requested_protocols
        return rp is not None and bool(rp & _PROTOCOL_SSL)

    @property
    def is_standard_rdp_security(self) -> bool:
        """표준 RDP 보안(NLA 없음, requestedProtocols==0)을 요청했는가 —
        레거시·취약(BlueKeep 계열)·다운그레이드 정황."""
        return self.requested_protocols == 0

    @property
    def restricted_admin(self) -> bool:
        """Restricted Admin 모드(flags 0x01)를 요청했는가 — PtH 악용 벡터."""
        return self.neg_flags is not None and bool(self.neg_flags & _FLAG_RESTRICTED_ADMIN)


def _parse_cookie(user_data: bytes) -> Tuple[Optional[str], Optional[str], int]:
    """가변부 선두의 ``Cookie:`` 줄을 파싱한다.

    Returns:
        ``(cookie_type, cookie_value, consumed)``. 쿠키가 없으면
        ``(None, None, 0)``. ``consumed`` 는 ``\\r\\n`` 까지 소비한 바이트 수.
    """
    if not user_data.startswith(b"Cookie: "):
        return None, None, 0
    end = user_data.find(b"\r\n")
    if end < 0:
        # CRLF 가 없으면 끝까지를 한 줄로 본다(망가진 입력 관대 처리).
        line = user_data[8:]
        consumed = len(user_data)
    else:
        line = user_data[8:end]
        consumed = end + 2
    text = line.decode("utf-8", "replace")
    if text.startswith("mstshash="):
        return "mstshash", text[len("mstshash="):] or None, consumed
    if text.startswith("msts="):
        return "msts", text[len("msts="):] or None, consumed
    return None, None, 0


def parse_rdp_connection_request(
    data: bytes, offset: int = 0
) -> Optional[RdpConnectionRequest]:
    """원시 바이트에서 RDP X.224 Connection Request PDU 를 파싱한다.

    Args:
        data: RDP 흐름 바이트. 보통 TCP 3389 의 첫 클라이언트 페이로드
            (:class:`forensiclab.netdissect` 의 ``payload_offset`` 부터)다.
        offset: PDU 가 시작하는 위치(기본 0).

    Returns:
        :class:`RdpConnectionRequest`. TPKT(0x03)/X.224 CR(0xE0) 프레이밍이
        아니거나, 바이트가 아예 없거나, offset 이 범위를 벗어나면 ``None``.

    구조: TPKT(4) → X.224 CR 고정부(7) → 가변부([쿠키][rdpNegReq]).
    쿠키·negReq 중 일부만 있어도 있는 만큼 채운다.
    """
    if not data or offset < 0 or offset >= len(data):
        return None
    buf = data[offset:]

    # TPKT 헤더: version(0x03) reserved length(BE 2).
    if len(buf) < 4 or buf[0] != _TPKT_VERSION:
        return None
    tpkt_length = struct.unpack(">H", buf[2:4])[0]

    # X.224 고정부: LI · CR|CDT · DST-REF(2) · SRC-REF(2) · CLASS.
    if len(buf) < 4 + 7:
        return None
    x224 = buf[4:]
    li = x224[0]
    if (x224[1] & 0xF0) != _X224_CR:
        return None

    # 가변부(user data): LI 가 가리키는 헤더 끝까지(범위 안에서).
    cr_end = 1 + li
    if cr_end < 7 or cr_end > len(x224):
        cr_end = len(x224)
    user_data = x224[7:cr_end]

    cookie_type, cookie_value, consumed = _parse_cookie(user_data)
    rest = user_data[consumed:]

    neg_present = False
    neg_flags: Optional[int] = None
    requested_protocols: Optional[int] = None
    if len(rest) >= 8 and rest[0] == _TYPE_RDP_NEG_REQ:
        neg_present = True
        neg_flags = rest[1]
        requested_protocols = struct.unpack("<I", rest[4:8])[0]

    return RdpConnectionRequest(
        tpkt_length=tpkt_length,
        cookie_type=cookie_type,
        cookie_value=cookie_value,
        neg_present=neg_present,
        neg_flags=neg_flags,
        requested_protocols=requested_protocols,
        raw=buf,
    )
