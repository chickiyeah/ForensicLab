"""VNC(RFB) ProtocolVersion 핸드셰이크 파싱 코어 (RFC 6143 §7.1.1).

:mod:`forensiclab.netdissect` 가 식별한 TCP(포트 5900~5906 영역) 페이로드는
VNC 원격 화면 공유 세션의 첫 평문 교환일 수 있다. 이 모듈이 그 첫 줄,
*ProtocolVersion 핸드셰이크* 를 해석한다. RDP(:mod:`forensiclab.rdp`, TCP
3389)·SSH(:mod:`forensiclab.ssh`)·rlogin/telnet 와 같은 **원격 접속·측면
이동** 계열의 또 다른 백본이며, 특히 SSH 배너처럼 **암호화/인증 이전의
평문 버전 줄** 이라 패킷에서 그대로 보인다.

RFB 연결은 서버가 먼저 정확히 12바이트의 ProtocolVersion 문자열을 보내고,
클라이언트가 자신이 지원하는(보통 더 낮거나 같은) 버전으로 응답하며 시작한다
(RFC 6143 §7.1.1)::

    "RFB " <xxx> "." <yyy> "\\n"      (총 12바이트, xxx·yyy 는 3자리 0채움)

예: ``RFB 003.008\\n``. 표준 버전은 ``003.003``·``003.007``·``003.008`` 뿐이며,
실무에선 비표준 값도 흔하다(예: ``003.889`` Apple Remote Desktop,
``004.001``/``005.000`` 일부 구현). 이 비표준 값은 **구현/벤더 핑거프린트**
단서다(SSH softwareversion 토큰과 같은 역할).

평문·약한 인증 프로토콜이라 침해/사고 분석에서 단서가 짙다:

- **원격 접속·측면 이동(remote access)**: RFB 핸드셰이크가 보이고 곧 세션이
  흐르면 화면/키보드/마우스 원격 제어가 성립한 정황이다(RDP 와 같은 위치 —
  :mod:`forensiclab.flows` 의 5-튜플로 출발→목적 호스트 경로를 잇는다).
- **버전 다운그레이드·약한 인증(``is_legacy_3_3``)**: ``003.003`` 은 보안
  타입 협상이 없고 사실상 **VNC Authentication(약한 DES, 비밀번호 앞 8자만
  유효)** 또는 **None(무인증)** 만 쓴다. 서버나 클라이언트가 ``003.003`` 으로
  내려가면 약한 인증으로의 다운그레이드 단서.
- **무인증 노출(보안 타입은 별도 단계)**: 핸드셰이크 자체가 자격증명을
  담지 않는다 — 이후 SecurityType 0(Invalid)/1(None)/2(VNC Auth) 협상이
  인증 여부를 가른다(이 코어는 인증 정황이 시작되는 버전 줄에 집중,
  SecurityType 분해는 호출자/별도 단계).
- **구현 핑거프린트(non-standard version)**: 비표준 ``xxx.yyy`` 값은 특정
  서버/뷰어 구현(ARD·UltraVNC·노출된 임베디드/IoT 장비)을 시사한다.

설계 원칙(:mod:`forensiclab.ssh`·:mod:`forensiclab.rdp` 와 동일):
- 부작용 없음: 디스크/표준출력/네트워크 없이 순수 함수.
- stdlib 전용: 외부 의존성 없음.
- 안전: 입력 바이트를 변형하지 않는다(읽기 전용).
- 견고: RFB 핸드셰이크가 아니거나 망가진 입력은 예외 대신 ``None``.
  엄격한 12바이트 ``RFB nnn.nnn\\n`` 형식을 우선하되, 트레일링 LF 누락은
  허용한다(자투리 바이트가 붙어도 앞 12바이트만 본다).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

__all__ = [
    "RFB_PREFIX",
    "RFB_HANDSHAKE_LEN",
    "VNC_PORTS",
    "STANDARD_VERSIONS",
    "RfbVersion",
    "parse_rfb_version",
]

# 모든 RFB ProtocolVersion 줄이 시작하는 고정 접두사("RFB " — 끝에 공백).
# 첫 4바이트가 이걸로 시작하지 않으면 RFB 가 아니라고 보고 None 을 돌린다.
RFB_PREFIX = b"RFB "

# RFC 6143 §7.1.1: ProtocolVersion 메시지는 정확히 12바이트.
#   "RFB " (4) + "xxx" (3) + "." (1) + "yyy" (3) + "\n" (1) = 12
RFB_HANDSHAKE_LEN = 12

# VNC 디스플레이 :0~:6 의 관용 TCP 포트(5900 + display). 식별 보조용일 뿐,
# 파싱은 포트와 무관하게 페이로드 형식만으로 판별한다.
VNC_PORTS = (5900, 5901, 5902, 5903, 5904, 5905, 5906)

# RFC 6143 이 정의하는 표준 ProtocolVersion 값. 이 밖의 값은 비표준
# 구현(ARD·UltraVNC·임베디드 등) 핑거프린트 단서.
STANDARD_VERSIONS = frozenset({(3, 3), (3, 7), (3, 8)})


@dataclass(frozen=True)
class RfbVersion:
    """파싱된 RFB ProtocolVersion 핸드셰이크.

    Attributes:
        major: 주 버전(``RFB 003.008`` 의 ``3``).
        minor: 부 버전(``RFB 003.008`` 의 ``8``).
        raw: 트레일링 LF 를 떼어낸 핸드셰이크 줄 원본(예: ``"RFB 003.008"``).
    """

    major: int
    minor: int
    raw: str

    @property
    def version(self) -> str:
        """사람이 읽는 ``"major.minor"`` 표기(예: ``"3.8"``)."""
        return f"{self.major}.{self.minor}"

    @property
    def is_standard(self) -> bool:
        """RFC 6143 표준 버전(3.3/3.7/3.8) 인가 — 아니면 구현 핑거프린트 단서."""
        return (self.major, self.minor) in STANDARD_VERSIONS

    @property
    def is_legacy_3_3(self) -> bool:
        """``3.3`` 인가 — 보안 타입 협상 없는 약한 인증(다운그레이드 단서)."""
        return (self.major, self.minor) == (3, 3)


def parse_rfb_version(data: bytes, offset: int = 0) -> Optional[RfbVersion]:
    """원시 바이트에서 RFB ProtocolVersion 핸드셰이크를 파싱한다.

    Args:
        data: RFB 흐름 바이트. 보통 TCP 5900+ 페이로드의 선두
            (:class:`forensiclab.netdissect` 의 ``payload_offset`` 부터)다.
            서버·클라이언트 어느 쪽 방향이든 첫 줄은 같은 형식이다.
        offset: 핸드셰이크가 시작하는 위치(기본 0).

    Returns:
        :class:`RfbVersion`. ``RFB nnn.nnn`` 최소 꼴(12바이트, 트레일링 LF 는
        선택)을 못 갖추거나 숫자 필드가 망가지면 ``None``.

    형식: ``"RFB " + 3자리 major + "." + 3자리 minor + "\\n"`` (12바이트).
    앞 4바이트가 ``RFB `` 가 아니거나 자릿수/구두점이 어긋나면 RFB 가
    아니라고 보고 ``None``. 트레일링 LF 가 없거나 12바이트 뒤에 자투리가
    붙어 있어도 선두 11~12바이트만으로 판별한다.
    """
    if not data or offset < 0:
        return None
    chunk = data[offset:offset + RFB_HANDSHAKE_LEN]

    # "RFB nnn.nnn" 의 핵심 11바이트(LF 제외)가 있어야 한다.
    if len(chunk) < RFB_HANDSHAKE_LEN - 1:
        return None
    if not chunk.startswith(RFB_PREFIX):
        return None

    major_field = chunk[4:7]
    dot = chunk[7:8]
    minor_field = chunk[8:11]

    if dot != b"." or not major_field.isdigit() or not minor_field.isdigit():
        return None

    major = int(major_field)
    minor = int(minor_field)

    # raw: LF 를 뗀 11바이트 "RFB nnn.nnn".
    raw = chunk[:11].decode("ascii", "replace")

    return RfbVersion(major=major, minor=minor, raw=raw)
