"""Diameter — 차세대 AAA 프로토콜 헤더 파싱 코어 (RFC 6733; TCP/SCTP 3868).

:mod:`forensiclab.radius` 가 1차 세대 AAA(NAS↔서버, UDP)였고
:mod:`forensiclab.tacacs` 가 그 장비 관리용 TCP 사촌이었다면, Diameter 는
**RADIUS 의 IETF 공식 후계자**다("RADIUS 보다 두 배 낫다"는 농담에서 이름이
왔다). RADIUS 의 한계(신뢰 가능 전송 부재·동적 발견·확장성)를 메우려
TCP/SCTP 위에서 동작하며, 무엇보다 **이동통신 코어망의 신호 평면 그 자체**다 —
LTE/EPC 의 S6a/S6d(MME↔HSS 가입자 인증·위치 관리), IMS 의 Cx/Dx·Rx, 정책의
Gx(PCRF) 가 모두 Diameter 위에서 돈다. :mod:`forensiclab.gtp`(사용자/베어러
터널)와 **짝을 이루는 제어 평면**으로, GTP 가 "단말 트래픽이 어디로 흐르나"라면
Diameter 는 "그 단말이 누구이고 인증·과금이 어떻게 됐나"를 나른다.

본문은 AVP(Attribute-Value Pair, RADIUS TLV 의 후손) 가변 배열이지만, 본 파서는
:mod:`forensiclab.tacacs`·:mod:`forensiclab.gtp` 와 동일하게 **고정 20바이트
헤더만** 풀고 AVP 본문은 ``payload_offset`` 으로만 가리킨다(읽기 전용).

와이어 포맷(RFC 6733 §3, 20바이트 고정 헤더, big-endian)::

    version(1) | message_length(3) | command_flags(1) | command_code(3)
    | application_id(4) | hop_by_hop_id(4) | end_to_end_id(4)

- **version**: 항상 ``1``(현재 유일). 다른 값이면 Diameter 가 아니다(오탐 가드).
- **message_length**: 헤더+AVP 전체 길이. 4의 배수여야 하고 20 이상이어야 한다
  (둘 다 강한 오탐 가드 — RADIUS 와 달리 Diameter 는 항상 4바이트 정렬).
- **command_flags**: bit7(``0x80``) R=Request(0=Answer)·bit6(``0x40``)
  P=Proxiable·bit5(``0x20``) E=Error·bit4(``0x10``) T=Potentially-retransmitted.
  하위 4비트는 예약(0이어야 함 — 오탐 가드).
- **command_code**: 3바이트. 요청/응답이 **같은 코드**를 공유하므로(R 플래그로
  구분) 257=CER/CEA·280=DWR/DWA·316=ULR/ULA(S6a 위치 갱신) 식이다.
- **application_id**: 메시지가 속한 애플리케이션. 0=기본(CER/DWR/DPR)·4=
  Credit-Control(과금)·16777251=3GPP S6a/S6d(LTE 가입자)·16777216=3GPP Cx(IMS).
  멀티벤더 코어망에서 **어느 인터페이스(S6a·Gx·Rx)인지**를 못 박는 핵심.
- **hop_by_hop_id**: 인접 피어 간 요청↔응답 정합(프록시 한 홉 단위).
- **end_to_end_id**: 출발지↔최종 목적지 종단 간 중복 탐지·정합. 두 식별자가
  :mod:`forensiclab.flows` 의 IP 쌍 안에서 한 트랜잭션을 못 박는 상관 키.

침해/사고 분석에서 평문 헤더가 드러내는 것:

- **코어망 신호 평면 존재·표적**: 노출된 TCP/SCTP 3868 자체가 통신사 코어망
  정황 — Diameter 라우팅 공격(가입자 위치 추적·SMS 가로채기·과금 우회)은
  SS7 의 IP 시대 후신으로 알려진 표적. application_id 가 S6a(16777251)면
  HSS↔MME 가입자 인증 트래픽이라는 강한 단서.
- **명령 식별(command_code+R)**: CER(257) 피어 능력 교환→DWR(280) 워치독으로
  연결 수립·유지를 보고, ULR(316)/AIR(318) 등은 가입자 위치·인증 정보 조회 —
  :mod:`forensiclab.timeline` 에서 "연결→인증→위치 조회" 흐름 복원.
- **오류·재전송 플래그**: E(Error) 응답 폭주는 인증 실패/라우팅 오류,
  T(retransmit) 빈발은 전송 불안정 — RADIUS Access-Reject 반복과 대응.
- **트랜잭션 상관**: hop_by_hop/end_to_end 로 프록시 체인을 가로질러 한 조회의
  요청과 응답을 짝짓는다(다중 Diameter 에이전트 환경 추적).

설계 원칙(:mod:`forensiclab.tacacs`·:mod:`forensiclab.radius` 와 동일):
- 부작용 없음·stdlib 전용·읽기 전용(입력 무변형).
- 견고: 20바이트 미만·version≠1·길이 비정렬/과소·예약 플래그 비트면
  예외 대신 ``None``.
- AVP 본문은 풀지 않고 ``payload_offset`` 만 노출한다.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Optional

__all__ = [
    "DIAMETER_HEADER_LEN",
    "DIAMETER_VERSION",
    "DIAMETER_FLAG_REQUEST",
    "DIAMETER_FLAG_PROXIABLE",
    "DIAMETER_FLAG_ERROR",
    "DIAMETER_FLAG_RETRANSMIT",
    "Diameter",
    "parse_diameter",
]

# 고정 헤더 길이(RFC 6733 §3).
DIAMETER_HEADER_LEN = 20

# 프로토콜 버전 — 현재 항상 1. 다른 값이면 Diameter 아님(오탐 가드).
DIAMETER_VERSION = 1

# command_flags 비트(RFC 6733 §3).
DIAMETER_FLAG_REQUEST = 0x80      # R: 1=요청, 0=응답(Answer).
DIAMETER_FLAG_PROXIABLE = 0x40    # P: 프록시/릴레이 가능.
DIAMETER_FLAG_ERROR = 0x20        # E: 프로토콜 오류 응답.
DIAMETER_FLAG_RETRANSMIT = 0x10   # T: 재전송 가능성 있음(중복 탐지용).

# command_flags 하위 4비트는 예약 — 0이어야 한다(오탐 가드).
_RESERVED_FLAG_BITS = 0x0F

# 명령 코드 이름(요청/응답 공통; R 플래그로 CER/CEA 구분).
_COMMAND_NAMES = {
    257: "Capabilities-Exchange",   # CER/CEA — 피어 능력 교환(연결 개시).
    258: "Re-Auth",                 # RAR/RAA — 재인증/재인가 요청.
    271: "Accounting",              # ACR/ACA — 과금 레코드.
    274: "Abort-Session",           # ASR/ASA — 세션 강제 종료.
    275: "Session-Termination",     # STR/STA — 세션 정상 종료.
    272: "Credit-Control",          # CCR/CCA — 실시간 과금(선불).
    280: "Device-Watchdog",         # DWR/DWA — 연결 생존 확인(keepalive).
    282: "Disconnect-Peer",         # DPR/DPA — 피어 연결 해제.
    # 3GPP S6a/S6d (LTE HSS↔MME 가입자 관리).
    316: "Update-Location",         # ULR/ULA — 단말 위치 갱신.
    317: "Cancel-Location",         # CLR/CLA — 위치 등록 취소.
    318: "Authentication-Information",  # AIR/AIA — 인증 벡터 조회.
    319: "Insert-Subscriber-Data",  # IDR/IDA — 가입자 데이터 주입.
    321: "Purge-UE",                # PUR/PUA — 단말 등록 정리.
    322: "Reset",                   # RSR/RSA — HSS 재시작 통보.
    323: "Notify",                  # NOR/NOA — MME→HSS 통보.
}

# 잘 알려진 application_id(어느 인터페이스인지 못 박음).
_APPLICATION_NAMES = {
    0: "Diameter Common Messages",  # 기본 프로토콜(CER/DWR/DPR).
    1: "NASREQ",                    # 네트워크 접속 서버(RADIUS 대응).
    3: "Diameter Base Accounting",  # 기본 과금.
    4: "Diameter Credit-Control",   # 실시간 과금(RFC 4006).
    16777216: "3GPP Cx",            # IMS HSS↔CSCF.
    16777236: "3GPP Rx",            # IMS 정책(P-CSCF↔PCRF).
    16777238: "3GPP Gx",            # 정책·과금(PCEF↔PCRF).
    16777251: "3GPP S6a/S6d",       # LTE HSS↔MME 가입자 인증·위치.
    16777252: "3GPP S13/S13'",      # 장비 식별(MME↔EIR).
}


@dataclass(frozen=True)
class Diameter:
    """파싱된 Diameter 고정 헤더(20바이트).

    AVP 본문은 풀지 않으며 :attr:`payload_offset`/:attr:`message_length` 로만
    가리킨다(읽기 전용).

    Attributes:
        version: 프로토콜 버전(정상이면 ``1``).
        message_length: 헤더+AVP 전체 길이(헤더 20 포함, 4의 배수).
        command_flags: 명령 플래그 바이트(R/P/E/T).
        command_code: 24비트 명령 코드(요청/응답 공통).
        application_id: 메시지가 속한 애플리케이션 식별자.
        hop_by_hop_id: 인접 피어 간 요청↔응답 정합 식별자.
        end_to_end_id: 종단 간 중복 탐지·정합 식별자.
        payload_offset: AVP 본문이 시작하는 절대 오프셋(헤더 끝).
    """

    version: int
    message_length: int
    command_flags: int
    command_code: int
    application_id: int
    hop_by_hop_id: int
    end_to_end_id: int
    payload_offset: int

    @property
    def command_name(self) -> str:
        """command_code 의 사람이 읽는 이름(미상이면 ``"cmd-<n>"``)."""
        return _COMMAND_NAMES.get(self.command_code, f"cmd-{self.command_code}")

    @property
    def application_name(self) -> str:
        """application_id 의 사람이 읽는 이름(미상이면 ``"app-<n>"``)."""
        return _APPLICATION_NAMES.get(
            self.application_id, f"app-{self.application_id}"
        )

    @property
    def is_request(self) -> bool:
        """요청(R 플래그) 여부 — 거짓이면 응답(Answer)."""
        return bool(self.command_flags & DIAMETER_FLAG_REQUEST)

    @property
    def is_answer(self) -> bool:
        """응답(Answer) 여부 — R 플래그가 꺼진 메시지."""
        return not self.is_request

    @property
    def is_proxiable(self) -> bool:
        """프록시/릴레이 가능(P 플래그) 여부."""
        return bool(self.command_flags & DIAMETER_FLAG_PROXIABLE)

    @property
    def is_error(self) -> bool:
        """오류 응답(E 플래그) 여부 — 인증/라우팅 실패 단서."""
        return bool(self.command_flags & DIAMETER_FLAG_ERROR)

    @property
    def is_retransmit(self) -> bool:
        """재전송 가능성(T 플래그) 여부 — 전송 불안정 단서."""
        return bool(self.command_flags & DIAMETER_FLAG_RETRANSMIT)


def parse_diameter(data: bytes, offset: int = 0) -> Optional[Diameter]:
    """원시 바이트에서 Diameter 고정 헤더를 파싱한다.

    Args:
        data: Diameter 메시지를 담은 바이트. 보통 TCP/SCTP 3868 페이로드
            (:class:`forensiclab.netdissect` 의 ``payload_offset`` 부터)다.
        offset: 메시지가 시작하는 위치(기본 0).

    Returns:
        :class:`Diameter`. 20바이트 헤더조차 없거나, version 이 ``1`` 이
        아니거나, message_length 가 20 미만/4의 배수가 아니거나, 명령 플래그
        예약 비트가 켜져 있으면 ``None``(오탐 가드). AVP 본문은 풀지 않고
        ``payload_offset`` 만 노출한다.
    """
    if offset < 0 or offset + DIAMETER_HEADER_LEN > len(data):
        return None
    version = data[offset]
    if version != DIAMETER_VERSION:
        return None
    # message_length 는 3바이트 — 앞에 0을 붙여 4바이트로 언팩.
    message_length = struct.unpack(">I", b"\x00" + data[offset + 1:offset + 4])[0]
    if message_length < DIAMETER_HEADER_LEN or message_length % 4 != 0:
        return None
    command_flags = data[offset + 4]
    if command_flags & _RESERVED_FLAG_BITS:
        return None
    command_code = struct.unpack(">I", b"\x00" + data[offset + 5:offset + 8])[0]
    application_id, hop_by_hop_id, end_to_end_id = struct.unpack(
        ">III", data[offset + 8:offset + DIAMETER_HEADER_LEN]
    )
    return Diameter(
        version=version,
        message_length=message_length,
        command_flags=command_flags,
        command_code=command_code,
        application_id=application_id,
        hop_by_hop_id=hop_by_hop_id,
        end_to_end_id=end_to_end_id,
        payload_offset=offset + DIAMETER_HEADER_LEN,
    )
