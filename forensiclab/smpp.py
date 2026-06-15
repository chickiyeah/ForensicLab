"""SMPP — Short Message Peer-to-Peer 프로토콜 파싱 코어 (SMPP v3.4, TCP 2775).

:mod:`forensiclab.smstpdu` 가 푼 SMS-TPDU 는 **SS7 신호망 안쪽**(MAP forwardSM
인자의 SM-RP-UI)에 실린 SMS 의 와이어 형태였다. 그 SMS 가 *통신사 코어망 바깥의
응용(ESME — External Short Message Entity)에서 드나드는* 길목이 바로 SMPP 다.
SMS-TPDU 가 "이동망 내부에서 옮겨 다니는 SMS"라면 SMPP 는 **"애플리케이션이 SMSC
에 SMS 를 밀어넣고(submit) 받아오는(deliver) 경로"** — A2P(Application-to-Person)
대량 발송·OTP 발송·마케팅·그리고 **스미싱 캠페인이 실제로 주입되는 평면**이다.

SMS-TPDU 가 SS7(BER/ASN.1·고정 옥텟)였다면 SMPP 는 TCP 위의 **고정 16바이트
헤더 + 본문**(SMPP v3.4 §4)이다. :mod:`forensiclab.smstpdu` 처럼 본문의 고정 필드를
*순서대로* 풀되, 본문 구조를 아는 PDU(bind·submit_sm·deliver_sm·data_sm)만 깊게
풀고 그 외(enquire_link 등)는 헤더와 ``payload_offset`` 으로만 가리킨다.

포렌식 핵심:

- **자격증명**(bind PDU): ``system_id``(ESME 계정명)·``password`` 가 **평문
  C-octet string** 으로 그대로 실린다 — :mod:`forensiclab.ftp`·:mod:`forensiclab.smtp`
  의 평문 로그인과 같은 노출. 누가 어떤 SMSC 에 붙었는지·브루트포스(``command_status``
  ESME_RINVPASWD 반복) 단서.
- **메시지 당사자·본문**(submit_sm/deliver_sm): ``source_addr``(발신, 흔히 위조된
  발신자명/숏코드)·``destination_addr``(착신=표적)·``short_message``(스미싱 링크·
  OTP 텍스트 자체). :mod:`forensiclab.smstpdu` 의 TP-OA/TP-DA/TP-UD 대응 — 이쪽은
  SMSC 진입 *직전* 의 평문이라 위조 발신자명이 그대로 드러난다.
- **연산·결과**(``command_id``/``command_status``): bind→enquire_link→submit_sm 흐름
  (:mod:`forensiclab.timeline`)·``sequence_number`` 로 요청↔응답 상관(:mod:`forensiclab.flows`
  IP 쌍 안에서)·응답 오류 코드로 거부/실패 진단.

설계 원칙(:mod:`forensiclab.smstpdu` 와 동일):
- 부작용 없음·stdlib 전용·읽기 전용(입력 무변형)·``offset`` 지원.
- ``command_id`` 가 알려진 SMPP 연산이 아니거나 16바이트 미만이면 ``None``(TCP
  스트림 오탐 가드). 본문이 절단되면 풀 수 있는 필드까지만 채운다.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Optional, Tuple

__all__ = [
    "Smpp",
    "SMPP_COMMAND_NAMES",
    "SMPP_STATUS_NAMES",
    "command_name",
    "parse_smpp",
    "status_name",
]

# command_id (SMPP v3.4 §5.1.2.1). 응답은 요청 id 에 0x80000000 OR.
SMPP_COMMAND_NAMES = {
    0x80000000: "generic_nack",
    0x00000001: "bind_receiver",
    0x80000001: "bind_receiver_resp",
    0x00000002: "bind_transmitter",
    0x80000002: "bind_transmitter_resp",
    0x00000003: "query_sm",
    0x80000003: "query_sm_resp",
    0x00000004: "submit_sm",
    0x80000004: "submit_sm_resp",
    0x00000005: "deliver_sm",
    0x80000005: "deliver_sm_resp",
    0x00000006: "unbind",
    0x80000006: "unbind_resp",
    0x00000007: "replace_sm",
    0x80000007: "replace_sm_resp",
    0x00000008: "cancel_sm",
    0x80000008: "cancel_sm_resp",
    0x00000009: "bind_transceiver",
    0x80000009: "bind_transceiver_resp",
    0x0000000B: "outbind",
    0x00000015: "enquire_link",
    0x80000015: "enquire_link_resp",
    0x00000021: "submit_multi",
    0x80000021: "submit_multi_resp",
    0x00000102: "alert_notification",
    0x00000103: "data_sm",
    0x80000103: "data_sm_resp",
}

# command_status (SMPP v3.4 §5.1.3) — 포렌식에서 자주 보는 것 위주.
SMPP_STATUS_NAMES = {
    0x00000000: "ESME_ROK",
    0x00000001: "ESME_RINVMSGLEN",
    0x00000002: "ESME_RINVCMDLEN",
    0x00000003: "ESME_RINVCMDID",
    0x00000004: "ESME_RINVBNDSTS",
    0x00000005: "ESME_RALYBND",
    0x0000000A: "ESME_RINVSRCADR",
    0x0000000B: "ESME_RINVDSTADR",
    0x0000000D: "ESME_RBINDFAIL",
    0x0000000E: "ESME_RINVPASWD",
    0x0000000F: "ESME_RINVSYSID",
    0x00000011: "ESME_RCANCELFAIL",
    0x00000013: "ESME_RREPLACEFAIL",
    0x00000014: "ESME_RMSGQFUL",
    0x00000058: "ESME_RTHROTTLED",
    0x00000400: "ESME_RDELIVERYFAILURE",
    0x000000FF: "ESME_RUNKNOWNERR",
}

# 본문에 (system_id, password) 자격증명을 싣는 bind 계열.
_BIND_COMMANDS = {0x00000001, 0x00000002, 0x00000009}
# 본문이 submit_sm 형태(당사자 주소+short_message)인 메시지 PDU.
_MESSAGE_COMMANDS = {0x00000004, 0x00000005}


def command_name(command_id: int) -> str:
    """``command_id`` → 연산 이름(미정의면 ``"unknown-0x..."``)."""
    return SMPP_COMMAND_NAMES.get(command_id, f"unknown-0x{command_id:08x}")


def status_name(command_status: int) -> str:
    """``command_status`` → 상태 이름(미정의면 ``"status-0x..."``)."""
    return SMPP_STATUS_NAMES.get(command_status, f"status-0x{command_status:08x}")


def _read_cstring(data: bytes, pos: int, end: int) -> Tuple[str, int]:
    """``pos`` 부터 NUL 종단 C-octet string 을 ``(텍스트, 다음_pos)`` 로 읽는다.

    NUL 을 못 찾고 ``end`` 에 닿으면 가용분까지 반환(절단 방어). 바이트는 latin-1
    로 무손실 디코드(주소·system_id 는 인쇄 가능 ASCII 가 일반적).
    """
    i = pos
    while i < end and data[i] != 0:
        i += 1
    text = data[pos:i].decode("latin-1")
    return text, (i + 1 if i < end else end)


def _decode_short_message(raw: bytes, data_coding: int) -> Optional[str]:
    """short_message 옥텟을 ``data_coding`` 에 따라 문자열로 푼다.

    SMPP 의 short_message 는 SMS-TPDU 와 달리 보통 *언팩된* 바이트열이다. UCS2
    (0x08)면 UTF-16BE, 그 외엔 latin-1(무손실)로 디코드한다(SMSC 기본 알파벳/IA5
    /Latin1 모두 인쇄 가능 ASCII 영역이 일치).
    """
    if data_coding == 0x08:
        try:
            return raw.decode("utf-16-be")
        except (UnicodeDecodeError, ValueError):
            return None
    return raw.decode("latin-1")


@dataclass(frozen=True)
class Smpp:
    """파싱된 SMPP PDU 한 개.

    Attributes:
        command_length: PDU 전체 길이(헤더 16 포함).
        command_id: 연산 id 원값.
        command_name: 연산 이름.
        command_status: 상태/오류 코드(요청은 보통 0).
        command_status_name: 상태 이름(``ESME_*``).
        sequence_number: 요청↔응답 상관 시퀀스.
        system_id: bind 요청의 ESME 계정명(자격증명; 없으면 ``None``).
        password: bind 의 평문 패스워드(없으면 ``None``).
        system_type: bind 의 system_type(없으면 ``None``).
        interface_version: bind 의 인터페이스 버전(없으면 ``None``).
        source_addr: submit_sm/deliver_sm 발신 주소(없으면 ``None``).
        dest_addr: submit_sm/deliver_sm 착신 주소(없으면 ``None``).
        data_coding: 메시지 PDU 의 data_coding(없으면 ``None``).
        short_message: 디코드된 본문(없으면 ``None``).
        payload_offset: 헤더 다음(본문) 시작 절대 오프셋.
    """

    command_length: int
    command_id: int
    command_name: str
    command_status: int
    command_status_name: str
    sequence_number: int
    system_id: Optional[str]
    password: Optional[str]
    system_type: Optional[str]
    interface_version: Optional[int]
    source_addr: Optional[str]
    dest_addr: Optional[str]
    data_coding: Optional[int]
    short_message: Optional[str]
    payload_offset: int

    @property
    def is_response(self) -> bool:
        """응답 PDU(command_id 최상위 비트 set) 여부."""
        return bool(self.command_id & 0x80000000)

    @property
    def is_request(self) -> bool:
        """요청 PDU 여부."""
        return not self.is_response

    @property
    def is_bind(self) -> bool:
        """bind 요청(자격증명 운반) 여부."""
        return self.command_id in _BIND_COMMANDS

    @property
    def is_error(self) -> bool:
        """응답이 0(ESME_ROK)이 아닌 오류 상태인지."""
        return self.is_response and self.command_status != 0

    @property
    def target_number(self) -> Optional[str]:
        """대표 상대 번호 — 착신(submit/deliver 의 destination)."""
        return self.dest_addr


def parse_smpp(data: bytes, offset: int = 0) -> Optional[Smpp]:
    """SMPP PDU 를 파싱한다(SMPP v3.4).

    Args:
        data: SMPP PDU 바이트(보통 TCP 2775 페이로드).
        offset: PDU 가 시작하는 위치(기본 0).

    Returns:
        :class:`Smpp`. 16바이트(고정 헤더) 미만이거나 ``command_id`` 가 알려진
        SMPP 연산이 아니거나 ``command_length`` < 16 이면 ``None``(TCP 스트림
        오탐 가드). bind 계열은 system_id·password 까지, submit_sm/deliver_sm 는
        당사자 주소·short_message 까지 푼다. 그 외 PDU 는 헤더만 채우고 본문은
        ``payload_offset`` 으로만 가리킨다. 본문이 절단되면 가용분까지만 채운다.
    """
    end = len(data)
    if offset < 0 or offset + 16 > end:
        return None

    command_length, command_id, command_status, sequence_number = struct.unpack_from(
        ">IIII", data, offset
    )
    if command_length < 16:
        return None
    if command_id not in SMPP_COMMAND_NAMES:
        return None

    body_start = offset + 16
    # command_length 가 선언한 본문 끝(절단 시 실제 데이터 끝으로 클램프).
    body_end = min(offset + command_length, end)
    if body_end < body_start:
        body_end = body_start

    system_id: Optional[str] = None
    password: Optional[str] = None
    system_type: Optional[str] = None
    interface_version: Optional[int] = None
    source_addr: Optional[str] = None
    dest_addr: Optional[str] = None
    data_coding: Optional[int] = None
    short_message: Optional[str] = None

    pos = body_start
    if command_id in _BIND_COMMANDS:
        # system_id, password, system_type (C-octet) + interface_version (1).
        system_id, pos = _read_cstring(data, pos, body_end)
        password, pos = _read_cstring(data, pos, body_end)
        system_type, pos = _read_cstring(data, pos, body_end)
        if pos < body_end:
            interface_version = data[pos]
    elif command_id in _MESSAGE_COMMANDS:
        # service_type(C) + src_ton+src_npi(2) + source_addr(C)
        #             + dst_ton+dst_npi(2) + destination_addr(C)
        #             + esm_class, protocol_id, priority(3)
        #             + sched(C) + validity(C)
        #             + reg_delivery, replace, data_coding, sm_default_msg_id(4)
        #             + sm_length(1) + short_message(sm_length).
        _service_type, pos = _read_cstring(data, pos, body_end)
        pos += 2  # source_addr_ton, source_addr_npi.
        source_addr, pos = _read_cstring(data, pos, body_end)
        pos += 2  # dest_addr_ton, dest_addr_npi.
        dest_addr, pos = _read_cstring(data, pos, body_end)
        pos += 3  # esm_class, protocol_id, priority_flag.
        _sched, pos = _read_cstring(data, pos, body_end)
        _validity, pos = _read_cstring(data, pos, body_end)
        # registered_delivery, replace_if_present, data_coding, sm_default_msg_id.
        if pos + 4 <= body_end:
            data_coding = data[pos + 2]
            pos += 4
            if pos < body_end:
                sm_length = data[pos]
                pos += 1
                msg_end = min(pos + sm_length, body_end)
                short_message = _decode_short_message(
                    data[pos:msg_end], data_coding or 0
                )

    return Smpp(
        command_length=command_length,
        command_id=command_id,
        command_name=command_name(command_id),
        command_status=command_status,
        command_status_name=status_name(command_status),
        sequence_number=sequence_number,
        system_id=system_id,
        password=password,
        system_type=system_type,
        interface_version=interface_version,
        source_addr=source_addr,
        dest_addr=dest_addr,
        data_coding=data_coding,
        short_message=short_message,
        payload_offset=body_start,
    )
