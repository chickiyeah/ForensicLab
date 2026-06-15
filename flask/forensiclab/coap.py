"""CoAP — Constrained Application Protocol 메시지 파싱 코어(RFC 7252·일부 7641/7959).

:mod:`forensiclab.mqtt` 가 IoT 기기가 브로커에 붙어 ``topic`` 으로 발행/구독하는
**pub/sub 메시징 평면**이었다면 CoAP 는 같은 사물인터넷 세계의 **REST 평면** —
제약 장치(센서·액추에이터)를 위해 HTTP 를 UDP 위 경량 바이너리로 줄인 요청/응답
프로토콜(IETF CoRE, 흔히 UDP 5683 평문·5684 DTLS). MQTT 가 "메시지를 흘려보낸다"면
CoAP 는 ``GET /sensors/temp`` 처럼 **자원(URI)에 메서드를 건다** — :mod:`forensiclab.http`
의 IoT 사촌. ForensicLab 의 IoT 센서 모니터링 대상과 직접 맞닿고, 봇넷 C2·ICS
원격 제어·CoAP 증폭 반사 DDoS(작은 요청→큰 응답) 분석에서 자주 마주친다.

:mod:`forensiclab.mqtt` 처럼 **바이너리 고정 헤더 + 가변부** 구조이나 UDP 위라
한 데이터그램이 곧 한 메시지다. 4바이트 고정 헤더 다음 Token, 그 뒤 **옵션들**(델타
부호화 TLV)이 오고, ``0xFF`` 페이로드 마커 뒤에 본문이 온다. 구조를 확실히 아는
부분(헤더·토큰·옵션 번호/값)만 풀고, 본문은 ``payload_offset`` 으로만 가리킨다.

와이어(RFC 7252):
- **고정 헤더(4바이트)**: 첫 바이트 = Version(상위 2비트·항상 1)·Type(2비트:
  0 CON 확인 요구·1 NON 비확인·2 ACK 확인응답·3 RST 리셋)·**TKL**(하위 4비트:
  Token 길이 0~8, 9~15 는 형식 오류). 둘째 바이트 = **Code**(상위 3비트 class·
  하위 5비트 detail: ``0.01`` GET·``0.02`` POST·``0.03`` PUT·``0.04`` DELETE·
  ``2.05`` Content·``4.04`` Not Found …). 3·4바이트 = **Message ID**(CON↔ACK
  상관·재전송 중복 탐지).
- **Token**(TKL 바이트): 요청↔응답 상관 토큰(:mod:`forensiclab.flows` IP 쌍 안,
  MQTT ``packet_id``·SMPP ``sequence_number`` 대응).
- **옵션들**: 각 옵션 = 1바이트(상위 4비트 델타·하위 4비트 길이, 13/14 는 확장
  바이트) + 값. 옵션 번호는 누적 델타. 포렌식 핵심은 **Uri-Path(11)**·
  **Uri-Query(15)**·**Uri-Host(3)** — HTTP 요청 라인처럼 어느 자원에 무엇을
  하려는지 드러낸다. **Content-Format(12)**·**Observe(6)**·**Block1/2(27/23)** 등도 열거.
- **0xFF** 페이로드 마커 뒤 본문(센서값·명령·C2 데이터 자체, ``payload_offset`` 만).

포렌식 핵심:
- **IoT 자원·C2**: Code(메서드)+Uri-Path 가 곧 "무엇을 어디에"(``GET /well-known/core``
  자원 정찰·``PUT /actuator`` 제어·비표준 경로 C2). Uri-Host/Uri-Query 로 표적 식별.
- **증폭 반사 DDoS**: 작은 CON GET 에 큰 응답(``Block2``·``/.well-known/core``)·
  위조 출처로 반사. ``is_request``/``code_name`` 과 응답 크기 상관.
- **세션·타임라인**: ``message_id``·``token`` 으로 CON→ACK·요청→응답 상관
  (:mod:`forensiclab.timeline`), ``is_confirmable``/``is_ack``/``is_reset``.

설계 원칙(:mod:`forensiclab.mqtt` 와 동일):
- 부작용 없음·stdlib 전용·읽기 전용(입력 무변형)·``offset`` 지원.
- 4바이트 미만이거나, Version 이 1이 아니거나, TKL 이 8을 넘거나, Code class 가
  예약(1·3·6·7)이거나, 옵션 델타/길이 니블이 15(0xFF 마커가 아닌데)면 ``None``
  (UDP 스트림 오탐 가드).
- 옵션 값이 가용 바이트를 넘으면(절단) 풀 수 있는 만큼만 채우고 ``truncated=True``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Tuple

__all__ = [
    "Coap",
    "CoapOption",
    "COAP_TYPE_NAMES",
    "COAP_OPTION_NAMES",
    "COAP_CONTENT_FORMAT_NAMES",
    "coap_type_name",
    "coap_code_name",
    "option_name",
    "content_format_name",
    "parse_coap",
]

# 메시지 Type(첫 바이트 비트 5-4) → 이름.
COAP_TYPE_NAMES = {
    0: "CON",  # Confirmable — ACK 요구.
    1: "NON",  # Non-confirmable.
    2: "ACK",  # Acknowledgement.
    3: "RST",  # Reset.
}

# Code class 0(요청 메서드) detail → 메서드 이름. 0.00 은 Empty(핑/리셋).
_METHOD_NAMES = {
    1: "GET",
    2: "POST",
    3: "PUT",
    4: "DELETE",
    5: "FETCH",   # RFC 8132
    6: "PATCH",
    7: "iPATCH",
}

# 응답 코드(class.detail) → 이름. CoAP 응답은 HTTP 상태처럼 c.dd 로 표기.
_RESPONSE_NAMES = {
    (2, 1): "Created",
    (2, 2): "Deleted",
    (2, 3): "Valid",
    (2, 4): "Changed",
    (2, 5): "Content",
    (2, 31): "Continue",       # RFC 7959
    (4, 0): "Bad Request",
    (4, 1): "Unauthorized",
    (4, 2): "Bad Option",
    (4, 3): "Forbidden",
    (4, 4): "Not Found",
    (4, 5): "Method Not Allowed",
    (4, 6): "Not Acceptable",
    (4, 8): "Request Entity Incomplete",
    (4, 12): "Precondition Failed",
    (4, 13): "Request Entity Too Large",
    (4, 15): "Unsupported Content-Format",
    (5, 0): "Internal Server Error",
    (5, 1): "Not Implemented",
    (5, 2): "Bad Gateway",
    (5, 3): "Service Unavailable",
    (5, 4): "Gateway Timeout",
    (5, 5): "Proxying Not Supported",
}

# 옵션 번호 → 이름(RFC 7252 + 7641 Observe + 7959 Block).
COAP_OPTION_NAMES = {
    1: "If-Match",
    3: "Uri-Host",
    4: "ETag",
    5: "If-None-Match",
    6: "Observe",
    7: "Uri-Port",
    8: "Location-Path",
    11: "Uri-Path",
    12: "Content-Format",
    14: "Max-Age",
    15: "Uri-Query",
    17: "Accept",
    20: "Location-Query",
    23: "Block2",
    27: "Block1",
    28: "Size2",
    35: "Proxy-Uri",
    39: "Proxy-Scheme",
    60: "Size1",
}

# Content-Format 코드 → 미디어 타입(흔한 값).
COAP_CONTENT_FORMAT_NAMES = {
    0: "text/plain",
    40: "application/link-format",
    41: "application/xml",
    42: "application/octet-stream",
    47: "application/exi",
    50: "application/json",
    60: "application/cbor",
}

# 예약(미정의) Code class — 강한 오탐 가드.
_VALID_CODE_CLASSES = frozenset({0, 2, 4, 5})

# 값을 부호 없는 정수로 다루는 옵션(나머지는 문자열/opaque).
_UINT_OPTIONS = frozenset({6, 7, 12, 14, 17, 23, 27, 28, 60})
# 값을 UTF-8 문자열로 다루는 옵션.
_STRING_OPTIONS = frozenset({3, 8, 11, 15, 20, 35, 39})

_URI_PATH = 11
_URI_QUERY = 15
_URI_HOST = 3
_CONTENT_FORMAT = 12
_OBSERVE = 6

_PAYLOAD_MARKER = 0xFF


def coap_type_name(type_code: int) -> str:
    """메시지 Type 코드 → 이름(미정의면 ``"type-N"``)."""
    return COAP_TYPE_NAMES.get(type_code, f"type-{type_code}")


def coap_code_name(code: int) -> str:
    """Code 바이트 → ``"c.dd Name"`` 표기(미정의면 코드만)."""
    cls = (code >> 5) & 0x07
    detail = code & 0x1F
    if code == 0:
        return "0.00 Empty"
    if cls == 0:
        name = _METHOD_NAMES.get(detail)
        return f"0.{detail:02d} {name}" if name else f"0.{detail:02d}"
    name = _RESPONSE_NAMES.get((cls, detail))
    return f"{cls}.{detail:02d} {name}" if name else f"{cls}.{detail:02d}"


def option_name(number: int) -> str:
    """옵션 번호 → 이름(미정의면 ``"option-N"``)."""
    return COAP_OPTION_NAMES.get(number, f"option-{number}")


def content_format_name(cf: int) -> str:
    """Content-Format 코드 → 미디어 타입(미정의면 ``"format-N"``)."""
    return COAP_CONTENT_FORMAT_NAMES.get(cf, f"format-{cf}")


def _uint(raw: bytes) -> int:
    """CoAP 가변 길이 부호 없는 정수(big-endian, 빈 값=0)."""
    return int.from_bytes(raw, "big") if raw else 0


def _text(raw: bytes) -> str:
    """옵션 문자열 값을 사람이 읽는 텍스트로(무손실 best-effort)."""
    return raw.decode("utf-8", "replace")


@dataclass(frozen=True)
class CoapOption:
    """파싱된 CoAP 옵션 한 개.

    Attributes:
        number: 누적 델타로 계산한 옵션 번호.
        name: 옵션 이름(미정의면 ``"option-N"``).
        value: 옵션 값 원본 바이트.
        value_offset: 값이 시작하는 절대 오프셋.
    """

    number: int
    name: str
    value: bytes
    value_offset: int

    @property
    def as_uint(self) -> int:
        """값을 부호 없는 정수로 해석."""
        return _uint(self.value)

    @property
    def as_text(self) -> str:
        """값을 UTF-8 문자열로 해석."""
        return _text(self.value)


def _read_ext(data: bytes, pos: int, end: int, nibble: int) -> Optional[Tuple[int, int]]:
    """옵션 델타/길이 확장 값을 읽는다(니블 13→1바이트+13·14→2바이트+269).

    Returns ``(value, next_pos)`` 또는 ``None``(절단·예약 니블 15).
    """
    if nibble < 13:
        return nibble, pos
    if nibble == 13:
        if pos + 1 > end:
            return None
        return data[pos] + 13, pos + 1
    if nibble == 14:
        if pos + 2 > end:
            return None
        return ((data[pos] << 8) | data[pos + 1]) + 269, pos + 2
    return None  # 15 = 예약(0xFF 마커는 호출 전 처리됨).


@dataclass(frozen=True)
class Coap:
    """파싱된 CoAP 메시지 한 개.

    Attributes:
        version: 프로토콜 버전(항상 1).
        type: 메시지 Type 코드(0~3).
        type_name: 메시지 Type 이름(CON/NON/ACK/RST).
        token_length: Token 길이(TKL, 0~8).
        code: Code 바이트 원값.
        code_name: ``"c.dd Name"`` 표기.
        code_class: Code 상위 3비트(0 요청·2/4/5 응답).
        code_detail: Code 하위 5비트.
        message_id: Message ID(CON↔ACK 상관).
        token: Token 16진 문자열(요청↔응답 상관).
        options: 파싱된 옵션 튜플.
        uri_path: Uri-Path(11) 옵션을 ``/`` 로 이은 자원 경로.
        uri_query: Uri-Query(15) 옵션을 ``&`` 로 이은 질의.
        uri_host: Uri-Host(3) 옵션(있으면).
        content_format: Content-Format(12) 코드(있으면).
        content_format_name: Content-Format 미디어 타입(있으면).
        observe: Observe(6) 옵션 값(있으면; RFC 7641 구독).
        payload_offset: ``0xFF`` 마커 뒤 본문 시작 절대 오프셋(없으면 ``None``).
        truncated: 옵션 값이 가용 바이트를 넘는지(절단 캡처).
        packet_length: 메시지 바이트 길이(헤더 포함; 데이터그램 끝까지).
    """

    version: int
    type: int
    type_name: str
    token_length: int
    code: int
    code_name: str
    code_class: int
    code_detail: int
    message_id: int
    token: str
    options: Tuple[CoapOption, ...] = ()
    uri_path: Optional[str] = None
    uri_query: Optional[str] = None
    uri_host: Optional[str] = None
    content_format: Optional[int] = None
    content_format_name: Optional[str] = None
    observe: Optional[int] = None
    payload_offset: Optional[int] = None
    truncated: bool = False
    packet_length: int = 0

    @property
    def is_request(self) -> bool:
        """요청(Code class 0·Empty 제외) 여부."""
        return self.code_class == 0 and self.code != 0

    @property
    def is_response(self) -> bool:
        """응답(Code class 2·4·5) 여부."""
        return self.code_class in (2, 4, 5)

    @property
    def is_empty(self) -> bool:
        """Empty 메시지(Code 0.00, 핑/ACK/RST) 여부."""
        return self.code == 0

    @property
    def is_confirmable(self) -> bool:
        """CON(확인 요구) 여부."""
        return self.type == 0

    @property
    def is_ack(self) -> bool:
        """ACK(확인응답) 여부."""
        return self.type == 2

    @property
    def is_reset(self) -> bool:
        """RST(리셋) 여부."""
        return self.type == 3

    @property
    def has_payload(self) -> bool:
        """본문(0xFF 마커 뒤 데이터)이 있는지."""
        return self.payload_offset is not None

    def get_option(self, number: int) -> Optional[CoapOption]:
        """주어진 번호의 첫 옵션을 반환(없으면 ``None``)."""
        for opt in self.options:
            if opt.number == number:
                return opt
        return None


def parse_coap(data: bytes, offset: int = 0) -> Optional[Coap]:
    """CoAP 메시지 한 개를 파싱한다.

    Args:
        data: CoAP 메시지 바이트(보통 UDP 페이로드). ``offset`` 에 고정 헤더.
        offset: 메시지가 시작하는 위치(기본 0).

    Returns:
        :class:`Coap`. 4바이트 미만이거나, Version 이 1이 아니거나, TKL 이 8을
        넘거나, Code class 가 예약(1·3·6·7)이거나, 옵션 델타/길이 니블이 15(0xFF
        마커가 아닌데)면 ``None``(UDP 스트림 오탐 가드). 옵션 값이 가용 바이트를
        넘으면(절단) 풀 수 있는 만큼만 채우고 ``truncated=True``.
    """
    end = len(data)
    if offset < 0 or offset + 4 > end:
        return None

    b0 = data[offset]
    version = (b0 >> 6) & 0x03
    if version != 1:
        return None  # CoAP 버전은 1 고정.
    type_code = (b0 >> 4) & 0x03
    tkl = b0 & 0x0F
    if tkl > 8:
        return None  # 9~15 는 형식 오류.

    code = data[offset + 1]
    code_class = (code >> 5) & 0x07
    code_detail = code & 0x1F
    if code_class not in _VALID_CODE_CLASSES:
        return None  # 예약 class — 비-CoAP.

    message_id = (data[offset + 2] << 8) | data[offset + 3]

    pos = offset + 4
    if pos + tkl > end:
        return None  # Token 절단 = 형식 오류.
    token = data[pos : pos + tkl].hex()
    pos += tkl

    options = []
    truncated = False
    payload_offset: Optional[int] = None
    option_number = 0
    uri_path_parts = []
    uri_query_parts = []
    uri_host: Optional[str] = None
    content_format: Optional[int] = None
    observe: Optional[int] = None

    while pos < end:
        b = data[pos]
        if b == _PAYLOAD_MARKER:
            payload_offset = pos + 1
            break
        delta_nibble = b >> 4
        len_nibble = b & 0x0F
        pos += 1

        d = _read_ext(data, pos, end, delta_nibble)
        if d is None:
            return None  # 예약 니블/절단 = 비-CoAP 또는 형식 오류.
        delta, pos = d
        ln = _read_ext(data, pos, end, len_nibble)
        if ln is None:
            return None
        length, pos = ln

        option_number += delta
        avail = end - pos
        if length > avail:
            value = data[pos:end]
            truncated = True
        else:
            value = data[pos : pos + length]
        opt = CoapOption(
            number=option_number,
            name=option_name(option_number),
            value=value,
            value_offset=pos,
        )
        options.append(opt)

        if option_number == _URI_PATH:
            uri_path_parts.append(_text(value))
        elif option_number == _URI_QUERY:
            uri_query_parts.append(_text(value))
        elif option_number == _URI_HOST and uri_host is None:
            uri_host = _text(value)
        elif option_number == _CONTENT_FORMAT and content_format is None:
            content_format = _uint(value)
        elif option_number == _OBSERVE and observe is None:
            observe = _uint(value)

        if truncated:
            break
        pos += length

    uri_path = "/" + "/".join(uri_path_parts) if uri_path_parts else None
    uri_query = "&".join(uri_query_parts) if uri_query_parts else None
    cf_name = content_format_name(content_format) if content_format is not None else None

    return Coap(
        version=version,
        type=type_code,
        type_name=coap_type_name(type_code),
        token_length=tkl,
        code=code,
        code_name=coap_code_name(code),
        code_class=code_class,
        code_detail=code_detail,
        message_id=message_id,
        token=token,
        options=tuple(options),
        uri_path=uri_path,
        uri_query=uri_query,
        uri_host=uri_host,
        content_format=content_format,
        content_format_name=cf_name,
        observe=observe,
        payload_offset=payload_offset,
        truncated=truncated,
        packet_length=end - offset,
    )
