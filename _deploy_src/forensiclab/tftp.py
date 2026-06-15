"""TFTP — 단순 파일 전송 프로토콜 파싱 코어 (RFC 1350 / 2347).

:mod:`forensiclab.netdissect` 가 식별한 UDP(포트 69) 페이로드는 TFTP 패킷
일 수 있다. 이 모듈이 그 메시지를 해석한다(:mod:`forensiclab.dns` 가 UDP 53,
:mod:`forensiclab.dhcp` 가 UDP 67/68, :mod:`forensiclab.ntp` 가 UDP 123 을
다루는 것과 같은 위치).

TFTP 는 인증·암호화가 없는 평문 UDP 전송이라 침해/사고 분석에서 단서가 많다:

- **멀웨어 스테이징·페이로드 투하**: WRQ(쓰기 요청)로 감염 호스트에 실행
  파일을 떨어뜨리거나, 펌웨어/부트 이미지를 바꿔치기하는 데 쓰인다. 라우터·
  IoT·PXE 부팅 환경에서 흔한 벡터다.
- **설정/펌웨어 유출**: RRQ(읽기 요청)의 ``filename`` 이 ``running-config``·
  ``startup-config``·``*.bin`` 이면 네트워크 장비 설정·펌웨어 탈취 정황이다.
- **전송 메타데이터**: ``mode`` 가 ``octet`` 이면 바이너리(실행 파일·이미지),
  ``netascii`` 면 텍스트다. RFC 2347 OACK 의 ``blksize``·``tsize`` 옵션은
  전송 크기·청크 크기를 드러내 :mod:`forensiclab.timeline` 재구성에 쓰인다.
- **접근 실패**: ERROR 패킷의 코드/메시지(예 2 "Access violation",
  1 "File not found")는 탐색·권한 시도 흔적이다.

TFTP 메시지 포맷(RFC 1350 §5)::

    RRQ/WRQ  opcode(2) | filename | 0 | mode | 0 | [opt|0|val|0]...  (RFC 2347)
    DATA     opcode(2) | block#(2) | data(0..512+)
    ACK      opcode(2) | block#(2)
    ERROR    opcode(2) | errorcode(2) | errmsg | 0
    OACK     opcode(2) | [opt|0|val|0]...                            (RFC 2347)

opcode·block#·errorcode 는 빅엔디언 16비트. 문자열은 NUL(0x00) 종단이다.

설계 원칙(:mod:`forensiclab.ntp`·:mod:`forensiclab.dhcp` 와 동일):
- 부작용 없음: 순수 함수. 디스크/표준출력/네트워크 없음.
- stdlib 전용.
- 안전: 입력 바이트를 변형하지 않는다(읽기 전용).
- 견고: 너무 짧거나 망가진 입력은 예외 대신 ``None``.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Dict, Optional

__all__ = [
    "TFTP_OP_RRQ",
    "TFTP_OP_WRQ",
    "TFTP_OP_DATA",
    "TFTP_OP_ACK",
    "TFTP_OP_ERROR",
    "TFTP_OP_OACK",
    "TFTP_ERROR_CODES",
    "Tftp",
    "parse_tftp",
]

# opcode (RFC 1350 §5, RFC 2347).
TFTP_OP_RRQ = 1    # Read ReQuest — 파일 다운로드(설정/펌웨어 유출 벡터).
TFTP_OP_WRQ = 2    # Write ReQuest — 파일 업로드(멀웨어 스테이징 벡터).
TFTP_OP_DATA = 3   # 데이터 블록.
TFTP_OP_ACK = 4    # 블록 수신 확인.
TFTP_OP_ERROR = 5  # 오류.
TFTP_OP_OACK = 6   # Option ACK (RFC 2347).

# ERROR 패킷 표준 코드 (RFC 1350 §5.1).
TFTP_ERROR_CODES = {
    0: "Not defined",
    1: "File not found",
    2: "Access violation",
    3: "Disk full or allocation exceeded",
    4: "Illegal TFTP operation",
    5: "Unknown transfer ID",
    6: "File already exists",
    7: "No such user",
    8: "Option negotiation failed",  # RFC 2347.
}

_OP_NAMES = {
    TFTP_OP_RRQ: "RRQ",
    TFTP_OP_WRQ: "WRQ",
    TFTP_OP_DATA: "DATA",
    TFTP_OP_ACK: "ACK",
    TFTP_OP_ERROR: "ERROR",
    TFTP_OP_OACK: "OACK",
}

# 정상 opcode 범위 — 그 밖은 TFTP 가 아닐 가능성이 높다.
_VALID_OPCODES = frozenset(_OP_NAMES)


def _split_nul_strings(data: bytes):
    """NUL 종단 문자열들을 순서대로 잘라 (decoded, ...) 리스트로.

    마지막 토큰이 NUL 로 끝나지 않으면(잘린 패킷) 그 잔여도 포함한다.
    바이트는 latin-1 로 디코드해 손실 없이(1:1) 문자열화한다.
    """
    return [chunk.decode("latin-1") for chunk in data.split(b"\x00")]


@dataclass(frozen=True)
class Tftp:
    """파싱된 TFTP 메시지.

    opcode 에 따라 채워지는 필드가 다르다(해당 없으면 ``None``):

    Attributes:
        opcode: 메시지 종류(1~6).
        filename: RRQ/WRQ 의 대상 파일명.
        mode: RRQ/WRQ 의 전송 모드(``netascii``·``octet``·``mail``).
        options: RFC 2347 옵션(소문자 key→value). RRQ/WRQ/OACK 에서 채워짐.
        block: DATA/ACK 의 블록 번호(0~65535).
        data: DATA 의 페이로드 바이트.
        error_code: ERROR 의 코드(0~8).
        error_message: ERROR 의 사람이 읽는 메시지.
    """

    opcode: int
    filename: Optional[str] = None
    mode: Optional[str] = None
    options: Dict[str, str] = field(default_factory=dict)
    block: Optional[int] = None
    data: Optional[bytes] = None
    error_code: Optional[int] = None
    error_message: Optional[str] = None

    @property
    def opcode_name(self) -> str:
        """opcode 의 사람이 읽는 이름(미상이면 ``"op-<n>"``)."""
        return _OP_NAMES.get(self.opcode, f"op-{self.opcode}")

    @property
    def is_request(self) -> bool:
        """RRQ·WRQ 여부 — 전송을 여는 패킷(파일명·모드를 담는다)."""
        return self.opcode in (TFTP_OP_RRQ, TFTP_OP_WRQ)

    @property
    def is_write(self) -> bool:
        """WRQ 여부 — 업로드(멀웨어 스테이징/설정 덮어쓰기) 단서."""
        return self.opcode == TFTP_OP_WRQ

    @property
    def is_binary(self) -> bool:
        """``octet`` 모드 여부 — 바이너리(실행 파일·이미지) 전송 단서."""
        return self.mode is not None and self.mode.lower() == "octet"


def _parse_options(tokens) -> Dict[str, str]:
    """남은 토큰들을 (opt, val) 쌍으로 묶어 옵션 dict 로 (RFC 2347).

    토큰은 ``filename``·``mode`` 를 떼어낸 뒤의 잔여다. 마지막에 빈 토큰
    (NUL 종단의 산물)이 따라오므로 짝이 맞지 않으면 무시한다.
    """
    out: Dict[str, str] = {}
    i = 0
    while i + 1 < len(tokens):
        key = tokens[i]
        if key == "":
            break
        out[key.lower()] = tokens[i + 1]
        i += 2
    return out


def parse_tftp(data: bytes, offset: int = 0) -> Optional[Tftp]:
    """원시 바이트에서 TFTP 메시지를 파싱한다.

    Args:
        data: TFTP 패킷을 담은 바이트. 보통 UDP 69 페이로드
            (:class:`forensiclab.netdissect` 의 ``payload_offset`` 부터)다.
        offset: 패킷이 시작하는 위치(기본 0).

    Returns:
        :class:`Tftp`. opcode 를 읽을 2바이트조차 없거나 opcode 가 1~6
        밖이면 ``None``.
    """
    if offset < 0 or offset + 2 > len(data):
        return None
    opcode = struct.unpack(">H", data[offset:offset + 2])[0]
    if opcode not in _VALID_OPCODES:
        return None
    body = data[offset + 2:]

    if opcode in (TFTP_OP_RRQ, TFTP_OP_WRQ):
        tokens = _split_nul_strings(body)
        filename = tokens[0] if tokens else None
        mode = tokens[1] if len(tokens) > 1 else None
        options = _parse_options(tokens[2:]) if len(tokens) > 2 else {}
        return Tftp(opcode=opcode, filename=filename, mode=mode, options=options)

    if opcode in (TFTP_OP_DATA, TFTP_OP_ACK):
        if len(body) < 2:
            return None
        block = struct.unpack(">H", body[:2])[0]
        payload = bytes(body[2:]) if opcode == TFTP_OP_DATA else None
        return Tftp(opcode=opcode, block=block, data=payload)

    if opcode == TFTP_OP_ERROR:
        if len(body) < 2:
            return None
        code = struct.unpack(">H", body[:2])[0]
        msg_tokens = _split_nul_strings(body[2:])
        message = msg_tokens[0] if msg_tokens and msg_tokens[0] else \
            TFTP_ERROR_CODES.get(code, "Not defined")
        return Tftp(opcode=opcode, error_code=code, error_message=message)

    # TFTP_OP_OACK — 옵션만.
    tokens = _split_nul_strings(body)
    return Tftp(opcode=opcode, options=_parse_options(tokens))
