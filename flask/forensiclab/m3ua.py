"""M3UA — MTP3 User Adaptation Layer 공통 헤더·파라미터 파싱 코어 (RFC 4666; SCTP 2905).

:mod:`forensiclab.sctp` 가 "SS7 의 IP 후신 SIGTRAN M3UA(2905) 가 그 위에 실린다"고
했을 때 그 **M3UA 가 바로 이 모듈이 푸는 적응 계층**이다. 전통 전화망의 신호망
SS7(Signalling System No.7)은 MTP1/2/3 라는 자체 하위 계층 위에서 돌았는데,
SIGTRAN 은 그 MTP1/2(물리·링크)를 IP+:mod:`forensiclab.sctp` 로 대체하고
MTP3(망 라우팅)만 "적응(adaptation)"해 IP 위로 올린 것이다. 그 MTP3 적응이
M3UA 이고, 그 위에 SCCP·ISUP·TCAP 같은 실제 SS7 사용자부(user part)가 실린다.

따라서 M3UA 는 :mod:`forensiclab.diameter`(LTE/EPC 코어망 AAA·위치) 와 **세대만
다른 같은 평면** — 둘 다 :mod:`forensiclab.sctp` 위에 얹힌 **이동통신 코어망 신호
평면**이다. M3UA 의 Protocol Data 파라미터(0x0210) 안에는 SS7 의 라우팅 레이블
(OPC/DPC 발·착 신호점 코드)과 SCCP/ISUP 페이로드가 그대로 들어 있어, **SS7 공격**
(가입자 위치추적·SMS 가로채기·통화 도청·과금 사기)의 와이어 증거가 된다.

:mod:`forensiclab.sctp`·:mod:`forensiclab.diameter`·:mod:`forensiclab.gtp` 와
동일하게 **8바이트 공통 헤더만** 풀고, 파라미터는 값(value)을 풀지 않은 채
**태그/길이 헤더만** 훑어 어떤 파라미터들이 실렸는지 열거하고 본문은
``payload_offset`` 과 각 파라미터의 ``value_offset`` 으로만 가리킨다(읽기 전용).

와이어 포맷(RFC 4666 §1.3.1, 8바이트 공통 헤더, big-endian)::

    version(1) | reserved(1) | message_class(1) | message_type(1) | message_length(4)

이어서 파라미터들(각 파라미터 헤더 4바이트, RFC 4666 §3.2)::

    parameter_tag(2) | parameter_length(2) | value(...)
    (parameter_length 는 헤더 4 포함, 다음 파라미터는 4바이트 경계로 패딩)

- **version**: 항상 1(RFC 4666). 1 아니면 M3UA 가 아니다(오탐 가드).
- **reserved**: 0 이어야 한다(오탐 가드).
- **message_class**: 0 MGMT(관리)·1 TFER(전송=실제 SS7 데이터)·2 SSNM(신호망 관리)·
  3 ASPSM(ASP 상태)·4 ASPTM(ASP 트래픽)·9 RKM(라우팅 키). class+type 조합이
  메시지를 못 박는다.
- **message_type**: class 안의 세부 메시지(예: class 3 type 1 = ASPUP).
- **message_length**: 공통 헤더 포함 전체 길이(octets).

침해/사고 분석에서 공통 헤더·메시지 종류가 드러내는 것:

- **신호 평면 식별**: SCTP 2905 위 M3UA 노출 자체가 통신사 코어망(SS7/SIGTRAN)
  정황. :mod:`forensiclab.diameter`(3868) 와 짝지어 4G 이전/이후 신호망 모두 추적.
- **링크 수립 흐름**: ASPUP→ASPUP-ACK(ASP 기동)→ASPAC→ASPAC-ACK(트래픽 활성)
  →BEAT(워치독) 시퀀스를 :mod:`forensiclab.timeline` 에서 복원. ASPUP 만 쏟아지면
  비인가 ASP 연결 시도(코어망 침투) 단서.
- **SS7 데이터 운반**: ``is_data``(class 1, Payload Data)에 Protocol Data
  파라미터(0x0210)가 실리면 그 안이 곧 SS7 라우팅 레이블+SCCP/ISUP —
  ``has_protocol_data`` 로 실제 신호 트래픽 존재를 표시(SS7 공격 와이어 증거).
- **망 가용성 조작**: SSNM(class 2) DUNA(목적지 도달 불가)·DAVA(도달 가능)·
  SCON(혼잡) 폭주는 신호점 가용성 위조로 라우팅을 흔드는 공격 단서.
- **오류·통보**: ERR(0,0)·NTFY(0,1) 빈발은 거부/상태 변화 — 인증/라우팅 실패 정황.

설계 원칙(:mod:`forensiclab.sctp`·:mod:`forensiclab.diameter` 와 동일):
- 부작용 없음·stdlib 전용·읽기 전용(입력 무변형).
- 견고: 8바이트 미만·version≠1·reserved≠0·message_length<8 이면 예외 대신 ``None``.
- 파라미터는 (SS7 메시지와 달리) 없을 수도 있으므로 0개를 허용한다.
- 파라미터 값(value)은 풀지 않고 태그/길이만 훑는다.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Optional, Tuple

__all__ = [
    "M3UA_HEADER_LEN",
    "M3UA_PARAM_HEADER_LEN",
    "M3UA_PROTOCOL_DATA_TAG",
    "M3ua",
    "M3uaParam",
    "parse_m3ua",
]

# 공통 헤더 길이(RFC 4666 §1.3.1).
M3UA_HEADER_LEN = 8

# 파라미터 헤더 길이(tag 2 + length 2).
M3UA_PARAM_HEADER_LEN = 4

# Protocol Data 파라미터 태그 — 실제 SS7 라우팅 레이블+SCCP/ISUP 운반(RFC 4666 §3.3.1).
M3UA_PROTOCOL_DATA_TAG = 0x0210

# 메시지 클래스 이름(RFC 4666 §3.1.2).
_CLASS_NAMES = {
    0: "MGMT",    # Management — ERR/NTFY.
    1: "TFER",    # Transfer — Payload Data(실제 SS7 데이터).
    2: "SSNM",    # SS7 Signalling Network Management — DUNA/DAVA/SCON 등.
    3: "ASPSM",   # ASP State Maintenance — ASPUP/ASPDN/BEAT.
    4: "ASPTM",   # ASP Traffic Maintenance — ASPAC/ASPIA.
    9: "RKM",     # Routing Key Management — 등록/해제.
    10: "IIM",    # Implementation-defined Information Management.
}

# (class, type) → 메시지 이름(RFC 4666 §3.1.2 표).
_MESSAGE_NAMES = {
    (0, 0): "ERR",          # 오류.
    (0, 1): "NTFY",         # 상태 통보.
    (1, 1): "DATA",         # Payload Data — SS7 신호 운반.
    (2, 1): "DUNA",         # Destination Unavailable.
    (2, 2): "DAVA",         # Destination Available.
    (2, 3): "DAUD",         # Destination State Audit.
    (2, 4): "SCON",         # Signalling Congestion.
    (2, 5): "DUPU",         # Destination User Part Unavailable.
    (2, 6): "DRST",         # Destination Restricted.
    (3, 1): "ASPUP",        # ASP Up.
    (3, 2): "ASPDN",        # ASP Down.
    (3, 3): "BEAT",         # Heartbeat(워치독).
    (3, 4): "ASPUP-ACK",    # ASP Up Ack.
    (3, 5): "ASPDN-ACK",    # ASP Down Ack.
    (3, 6): "BEAT-ACK",     # Heartbeat Ack.
    (4, 1): "ASPAC",        # ASP Active.
    (4, 2): "ASPIA",        # ASP Inactive.
    (4, 3): "ASPAC-ACK",    # ASP Active Ack.
    (4, 4): "ASPIA-ACK",    # ASP Inactive Ack.
    (9, 1): "REG-REQ",      # Registration Request.
    (9, 2): "REG-RSP",      # Registration Response.
    (9, 3): "DEREG-REQ",    # Deregistration Request.
    (9, 4): "DEREG-RSP",    # Deregistration Response.
}

# 파라미터 태그 이름(RFC 4666 §3.2; 공통 파라미터 + M3UA 고유).
_PARAM_NAMES = {
    0x0004: "INFO String",
    0x0006: "Routing Context",
    0x0007: "Diagnostic Information",
    0x0009: "Heartbeat Data",
    0x000B: "Traffic Mode Type",
    0x000C: "Error Code",
    0x000D: "Status",
    0x0011: "ASP Identifier",
    0x0012: "Affected Point Code",
    0x0013: "Correlation ID",
    0x0200: "Network Appearance",
    0x0204: "User/Cause",
    0x0205: "Congestion Indications",
    0x0206: "Concerned Destination",
    0x0207: "Routing Key",
    0x0208: "Registration Result",
    0x0209: "Deregistration Result",
    0x020A: "Local Routing Key Identifier",
    0x020B: "Destination Point Code",
    0x020C: "Service Indicators",
    0x020E: "Originating Point Code List",
    0x0210: "Protocol Data",   # 실제 SS7 라우팅 레이블+SCCP/ISUP.
    0x0212: "Registration Status",
    0x0213: "Deregistration Status",
}


@dataclass(frozen=True)
class M3uaParam:
    """M3UA 파라미터 헤더(값은 풀지 않음).

    Attributes:
        tag: 파라미터 태그 코드.
        length: 파라미터 길이(헤더 4 포함, 패딩 제외).
        value_offset: 파라미터 값(value)이 시작하는 절대 오프셋(파라미터 헤더 끝).
    """

    tag: int
    length: int
    value_offset: int

    @property
    def param_name(self) -> str:
        """파라미터 태그의 사람이 읽는 이름(미상이면 ``"param-0x...."``)."""
        return _PARAM_NAMES.get(self.tag, f"param-0x{self.tag:04x}")


@dataclass(frozen=True)
class M3ua:
    """파싱된 M3UA 공통 헤더(8바이트)와 파라미터 헤더 목록.

    파라미터 값은 풀지 않으며 :attr:`payload_offset` 와 각 파라미터의
    ``value_offset`` 으로만 가리킨다(읽기 전용).

    Attributes:
        version: 프로토콜 버전(항상 1).
        reserved: 예약 바이트(항상 0).
        message_class: 메시지 클래스 코드.
        message_type: 메시지 타입 코드(클래스 안의 세부 메시지).
        message_length: 공통 헤더 포함 전체 길이(octets).
        params: 훑은 파라미터 헤더(:class:`M3uaParam`) 튜플.
        payload_offset: 첫 파라미터가 시작하는 절대 오프셋(공통 헤더 끝).
    """

    version: int
    reserved: int
    message_class: int
    message_type: int
    message_length: int
    params: Tuple[M3uaParam, ...]
    payload_offset: int

    @property
    def class_name(self) -> str:
        """메시지 클래스의 사람이 읽는 이름(미상이면 ``"class-<n>"``)."""
        return _CLASS_NAMES.get(self.message_class, f"class-{self.message_class}")

    @property
    def message_name(self) -> str:
        """(class, type) 조합의 메시지 이름(미상이면 ``"<class>/type-<n>"``)."""
        name = _MESSAGE_NAMES.get((self.message_class, self.message_type))
        if name is not None:
            return name
        return f"{self.class_name}/type-{self.message_type}"

    @property
    def param_tags(self) -> Tuple[int, ...]:
        """실린 파라미터 태그 코드 튜플(등장 순서)."""
        return tuple(p.tag for p in self.params)

    @property
    def param_names(self) -> Tuple[str, ...]:
        """실린 파라미터 이름 튜플(등장 순서)."""
        return tuple(p.param_name for p in self.params)

    @property
    def first_param(self) -> Optional[M3uaParam]:
        """첫 파라미터(없으면 ``None`` — M3UA 는 파라미터가 없을 수 있다)."""
        return self.params[0] if self.params else None

    def has_param(self, tag: int) -> bool:
        """주어진 태그의 파라미터가 실렸는지 여부."""
        return any(p.tag == tag for p in self.params)

    @property
    def has_protocol_data(self) -> bool:
        """Protocol Data(0x0210) 파라미터 포함 여부 — 실제 SS7 신호 운반 단서."""
        return self.has_param(M3UA_PROTOCOL_DATA_TAG)

    @property
    def is_data(self) -> bool:
        """Transfer 클래스(실제 SS7 페이로드 전송) 여부."""
        return self.message_class == 1

    @property
    def is_management(self) -> bool:
        """Management(MGMT) 클래스 여부 — ERR/NTFY."""
        return self.message_class == 0

    @property
    def is_ssnm(self) -> bool:
        """SS7 신호망 관리(SSNM) 클래스 여부 — DUNA/DAVA/SCON 등 가용성 통보."""
        return self.message_class == 2

    @property
    def is_aspsm(self) -> bool:
        """ASP 상태 관리(ASPSM) 클래스 여부 — ASPUP/ASPDN/BEAT."""
        return self.message_class == 3

    @property
    def is_asptm(self) -> bool:
        """ASP 트래픽 관리(ASPTM) 클래스 여부 — ASPAC/ASPIA."""
        return self.message_class == 4

    @property
    def is_heartbeat(self) -> bool:
        """워치독(BEAT/BEAT-ACK) 여부."""
        return self.message_class == 3 and self.message_type in (3, 6)

    @property
    def is_error(self) -> bool:
        """오류(ERR, class 0 type 0) 여부 — 거부/실패 단서."""
        return self.message_class == 0 and self.message_type == 0

    @property
    def is_notify(self) -> bool:
        """상태 통보(NTFY, class 0 type 1) 여부."""
        return self.message_class == 0 and self.message_type == 1


def parse_m3ua(data: bytes, offset: int = 0) -> Optional[M3ua]:
    """원시 바이트에서 M3UA 공통 헤더와 파라미터 헤더 목록을 파싱한다.

    Args:
        data: M3UA 메시지를 담은 바이트. 보통 SCTP DATA 청크의 값
            (:class:`forensiclab.sctp` 의 ``SctpChunk.value_offset`` 부터)이며
            SCTP 포트가 2905 인 association 의 페이로드다.
        offset: 메시지가 시작하는 위치(기본 0).

    Returns:
        :class:`M3ua`. 8바이트 공통 헤더가 없거나, version≠1·reserved≠0·
        message_length<8 이면 ``None``(오탐 가드). 파라미터 값은 풀지 않으며,
        파라미터가 0개여도 유효하다. 파라미터 길이가 남은 데이터를 넘어가면
        (절단 캡처) 그 시점까지의 파라미터만 담는다.
    """
    if offset < 0 or offset + M3UA_HEADER_LEN > len(data):
        return None
    version, reserved, message_class, message_type, message_length = struct.unpack(
        ">BBBBI", data[offset:offset + M3UA_HEADER_LEN]
    )
    # 오탐 가드: M3UA 공통 헤더는 version=1·reserved=0 으로 고정, 길이는 헤더 이상.
    if version != 1 or reserved != 0 or message_length < M3UA_HEADER_LEN:
        return None

    params = []
    pos = offset + M3UA_HEADER_LEN
    # 파라미터는 메시지 길이 안에만 존재하나, 절단 캡처를 고려해 가용 범위로 클램프.
    end = min(offset + message_length, len(data))
    while pos + M3UA_PARAM_HEADER_LEN <= end:
        tag = struct.unpack(">H", data[pos:pos + 2])[0]
        length = struct.unpack(">H", data[pos + 2:pos + 4])[0]
        if length < M3UA_PARAM_HEADER_LEN:
            # 길이가 헤더보다 작으면 파라미터가 망가진 것 — 열거 중단.
            break
        params.append(
            M3uaParam(
                tag=tag,
                length=length,
                value_offset=pos + M3UA_PARAM_HEADER_LEN,
            )
        )
        # 다음 파라미터는 4바이트 경계로 패딩된다(RFC 4666 §3.2).
        padded = length + (-length % 4)
        pos += padded

    return M3ua(
        version=version,
        reserved=reserved,
        message_class=message_class,
        message_type=message_type,
        message_length=message_length,
        params=tuple(params),
        payload_offset=offset + M3UA_HEADER_LEN,
    )
