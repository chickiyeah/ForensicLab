"""CIMD2 — Computer Interface to Message Distribution v2 파싱 코어.

:mod:`forensiclab.smpp`(현대 표준)·:mod:`forensiclab.ucp`(레거시 CMG/LogicaCMG)
에 이은 **세 번째 SMSC 접속 프로토콜 형제** — Nokia 가 자사 SMSC 용으로 정의한
구형 ESME↔SMSC 접속 프로토콜이다. 셋은 같은 평면(A2P 대량 발송·OTP·마케팅·그리고
**스미싱 캠페인이 SMSC 에 주입되는 길**)을 서로 다른 와이어로 나른다.

UCP 처럼 **ASCII 텍스트 프레임**이라 :mod:`forensiclab.ftp`·:mod:`forensiclab.sip`
처럼 사람이 읽는 평문이지만, 와이어 모양은 다르다 — UCP 가 ``/`` 구분 *위치 기반*
필드열이라면 CIMD2 는 ``TAB``(0x09) 구분 **``코드:값`` 쌍**(parameter list)이다.

프레임: ``<STX> OC:PN <TAB> PC:PV <TAB> PC:PV <TAB> … [CC] <ETX>``

- **OC**: operation code(2자리) — 01 login·02 logout·03 submit message·
  10 deliver message(MO)·40 alive 등. **응답은 요청 + 50**(login→51, submit→53),
  98 NACK·99 general error response.
- **PN**: packet number(요청↔응답 상관, :mod:`forensiclab.ucp` ``trn``·
  :mod:`forensiclab.smpp` ``sequence_number`` 대응).
- **PC:PV**: parameter code(3자리)와 값 — TAB 으로 구분, 마지막 TAB 뒤에 선택적
  체크섬(CC, 2자리 16진)이 붙고 ETX 로 끝난다.

포렌식 핵심(:mod:`forensiclab.smpp`/:mod:`forensiclab.ucp` 대응):

- **자격증명**(login, OC 01): ``user_identity``(010)·**평문 ``password``**(011)
  가 그대로 실린다 — :mod:`forensiclab.smpp` bind system_id/password,
  :mod:`forensiclab.ucp` 세션 관리 account/PWD 와 같은 노출. 인증 실패는 login
  응답(51)의 ``error_code``(900) 반복 = 패스워드 추정(RADIUS Access-Reject 대응).
- **당사자·본문**(submit 03/deliver 10): ``recipient``(021 destination address=
  착신 표적)·``originator``(023 originating address=발신, 흔히 위조 발신자명/
  숏코드)·``message``(033 user data=스미싱 링크·OTP 텍스트 자체).
- **연산·결과·무결성**(``operation_name``/``is_request``/``is_response``): login
  (01)→submit(03)→logout(02) 흐름(:mod:`forensiclab.timeline`)·``packet_number``
  상관(:mod:`forensiclab.flows` IP 쌍 안)·``is_nack``/``error_code``·체크섬
  ``checksum_ok`` 무결성.

설계 원칙(:mod:`forensiclab.ucp` 와 동일):
- 부작용 없음·stdlib 전용·읽기 전용(입력 무변형)·``offset`` 지원.
- ``STX`` 로 시작하지 않거나, 헤더가 ``숫자:숫자`` 꼴이 아니거나, operation code
  가 알려진 CIMD2 연산이 아니면 ``None``(TCP 스트림 오탐 가드 — CIMD2 연산 코드는
  닫힌 열거라 미지 코드는 비-CIMD2 로 본다).
- ``ETX`` 가 없어 프레임이 절단되면 풀 수 있는 파라미터까지만 채우고 체크섬은
  검증 불가(``None``)로 둔다. 체크섬은 선택적이라 없으면 ``None``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Tuple

__all__ = [
    "Cimd2",
    "CIMD2_OPERATION_NAMES",
    "CIMD2_PARAMETER_NAMES",
    "operation_name",
    "parameter_name",
    "parse_cimd2",
]

_STX = 0x02
_ETX = 0x03
_TAB = "\t"

# operation code → 연산 이름 (CIMD2 규격). 응답 = 요청 + 50.
CIMD2_OPERATION_NAMES = {
    1: "login",
    2: "logout",
    3: "submit_message",
    4: "enquire_message_status",
    5: "delivery_request",
    6: "cancel_message",
    8: "set_message",
    9: "get_message",
    10: "deliver_message",
    11: "deliver_status_report",
    30: "set",
    31: "get",
    32: "get_parameters",
    40: "alive",
    51: "login_response",
    52: "logout_response",
    53: "submit_message_response",
    54: "enquire_message_status_response",
    55: "delivery_request_response",
    56: "cancel_message_response",
    58: "set_message_response",
    59: "get_message_response",
    60: "deliver_message_response",
    61: "deliver_status_report_response",
    80: "set_response",
    81: "get_response",
    82: "get_parameters_response",
    90: "alive_response",
    98: "nack",
    99: "general_error_response",
}

# parameter code → 이름 (CIMD2 규격, 포렌식상 의미 있는 것 위주).
CIMD2_PARAMETER_NAMES = {
    10: "user_identity",
    11: "password",
    12: "subaddress",
    13: "window_size",
    21: "destination_address",
    23: "originating_address",
    24: "originating_imsi",
    27: "alphanumeric_originating_address",
    28: "originated_visited_msc",
    30: "data_coding_scheme",
    32: "user_data_header",
    33: "user_data",
    34: "user_data_binary",
    35: "more_messages_to_send",
    44: "protocol_identifier",
    50: "validity_period_relative",
    51: "validity_period_absolute",
    58: "first_delivery_time_relative",
    59: "first_delivery_time_absolute",
    60: "reply_path",
    61: "status_report_request",
    63: "cancel_enabled",
    64: "cancel_mode",
    70: "service_centre_time_stamp",
    71: "status_code",
    72: "status_error_code",
    73: "discharge_time",
    74: "tariff_class",
    75: "service_description",
    76: "message_count",
    77: "priority",
    78: "delivery_request_mode",
    79: "service_centre_address",
    100: "get_parameter",
    101: "smsc_time",
    501: "last_response_time",
    900: "error_code",
    901: "error_text",
}

# 본문에 (user_identity, password) 자격증명을 싣는 연산.
_LOGIN_OPS = {1}
# 착신/발신/본문 파라미터를 싣는 메시지 운반 연산(submit·deliver 류).
_MESSAGE_OPS = {3, 10, 20}

# 자주 쓰는 parameter code 상수.
_P_USER_IDENTITY = 10
_P_PASSWORD = 11
_P_DESTINATION = 21
_P_ORIGINATING = 23
_P_ALPHA_ORIGINATING = 27
_P_USER_DATA = 33
_P_ERROR_CODE = 900
_P_ERROR_TEXT = 901


def operation_name(operation_code: int) -> str:
    """``operation_code`` → 연산 이름(미정의면 ``"operation-NN"``)."""
    return CIMD2_OPERATION_NAMES.get(operation_code, f"operation-{operation_code:02d}")


def parameter_name(parameter_code: int) -> str:
    """``parameter_code`` → 파라미터 이름(미정의면 ``"parameter-NNN"``)."""
    return CIMD2_PARAMETER_NAMES.get(parameter_code, f"parameter-{parameter_code:03d}")


@dataclass(frozen=True)
class Cimd2:
    """파싱된 CIMD2 패킷 한 개.

    Attributes:
        operation_code: 연산 코드(OC) 원값.
        operation_name: 연산 이름.
        packet_number: 패킷 번호(PN, 요청↔응답 상관; 파싱 불가면 ``None``).
        frame_length: 실제 프레임 바이트 길이(STX~ETX 포함; 절단이면 가용분).
        user_identity: login(01)의 계정명(010; 없으면 ``None``).
        password: login(01)의 평문 패스워드(011; 없으면 ``None``).
        recipient: 착신 주소(021; 메시지 연산만, 없으면 ``None``).
        originator: 발신 주소(023, 없으면 027 alphanumeric; 없으면 ``None``).
        message: 본문(033 user data; 메시지 연산만, 없으면 ``None``).
        error_code: 응답의 오류 코드(900; 없으면 ``None``).
        error_text: 응답의 오류 텍스트(901; 없으면 ``None``).
        checksum: 선언된 체크섬 문자열(2자리 16진; 없으면 ``""``).
        checksum_ok: 체크섬 일치 여부(없거나 검증 불가면 ``None``).
        parameters: ``(코드, 값)`` 쌍의 원시 파라미터 목록.
        payload_offset: 첫 파라미터(헤더 다음 TAB 뒤)의 절대 오프셋.
    """

    operation_code: int
    operation_name: str
    packet_number: Optional[int]
    frame_length: int
    user_identity: Optional[str]
    password: Optional[str]
    recipient: Optional[str]
    originator: Optional[str]
    message: Optional[str]
    error_code: Optional[str]
    error_text: Optional[str]
    checksum: str
    checksum_ok: Optional[bool]
    parameters: Tuple[Tuple[int, str], ...]
    payload_offset: int

    @property
    def is_request(self) -> bool:
        """요청(operation code < 50) 여부."""
        return self.operation_code < 50

    @property
    def is_response(self) -> bool:
        """응답(operation code >= 51, NACK/error 포함) 여부."""
        return self.operation_code >= 51

    @property
    def is_login(self) -> bool:
        """login(01·자격증명 운반) 연산 여부."""
        return self.operation_code in _LOGIN_OPS

    @property
    def is_nack(self) -> bool:
        """NACK(98) 여부 — 프로토콜 거부 단서."""
        return self.operation_code == 98

    @property
    def is_general_error(self) -> bool:
        """general error response(99) 여부."""
        return self.operation_code == 99

    @property
    def is_error(self) -> bool:
        """오류 응답(NACK·general error·error_code 동반) 여부."""
        return self.is_nack or self.is_general_error or self.error_code is not None

    @property
    def target_number(self) -> Optional[str]:
        """대표 상대 번호 — 착신(메시지 연산의 recipient)."""
        return self.recipient

    def get(self, code: int) -> Optional[str]:
        """주어진 parameter code 의 값(없으면 ``None``)."""
        for c, v in self.parameters:
            if c == code:
                return v
        return None


def parse_cimd2(data: bytes, offset: int = 0) -> Optional[Cimd2]:
    """CIMD2 패킷을 파싱한다.

    Args:
        data: CIMD2 프레임 바이트(보통 TCP 페이로드). ``offset`` 위치에 ``STX``.
        offset: 프레임이 시작하는 위치(기본 0).

    Returns:
        :class:`Cimd2`. ``offset`` 이 ``STX`` 가 아니거나, 헤더가 ``숫자:숫자``
        꼴이 아니거나, operation code 가 알려진 CIMD2 연산이 아니면 ``None``
        (TCP 스트림 오탐 가드). login(01)은 user_identity·password 까지, 메시지
        연산(03/10/20)은 착·발신·본문까지, 응답은 error_code/text 까지 푼다.
        ``ETX`` 가 없으면(절단) 가용분까지 채우고 체크섬은 ``None``.
    """
    end = len(data)
    if offset < 0 or offset >= end:
        return None
    if data[offset] != _STX:
        return None

    etx_pos = data.find(_ETX, offset + 1)
    truncated = etx_pos == -1
    content_end = end if truncated else etx_pos
    frame_length = (content_end - offset) if truncated else (etx_pos - offset + 1)

    try:
        content = data[offset + 1 : content_end].decode("latin-1")
    except ValueError:  # pragma: no cover - latin-1 은 모든 바이트 디코드.
        return None

    parts = content.split(_TAB)
    # 최소한 헤더 + (체크섬/빈 꼬리) 두 토막은 있어야 한다.
    if len(parts) < 2:
        return None

    header = parts[0]
    if ":" not in header:
        return None
    oc_s, _, pn_s = header.partition(":")
    if not oc_s.isdigit() or not pn_s.isdigit():
        return None
    operation_code = int(oc_s)
    # operation code 는 닫힌 열거 — 미지면 비-CIMD2 로 본다(강한 오탐 가드).
    if operation_code not in CIMD2_OPERATION_NAMES:
        return None
    packet_number = int(pn_s)

    # 마지막 TAB 뒤 토막이 체크섬(또는 빈 문자열). 그 사이가 파라미터들.
    checksum = parts[-1]
    raw_params = parts[1:-1]

    parameters = []
    for field in raw_params:
        if not field or ":" not in field:
            continue
        pc_s, _, pv = field.partition(":")
        if not pc_s.isdigit():
            continue
        parameters.append((int(pc_s), pv))
    param_tuple = tuple(parameters)

    # 체크섬 검증: STX 부터 마지막 TAB(체크섬 직전)까지 모든 바이트 합 & 0xFF.
    checksum_ok: Optional[bool] = None
    if not truncated and len(checksum) == 2:
        region = content[: len(content) - len(checksum)]
        computed = (_STX + sum(ord(c) for c in region)) & 0xFF
        try:
            checksum_ok = computed == int(checksum, 16)
        except ValueError:
            checksum_ok = None

    def _find(code: int) -> Optional[str]:
        for c, v in param_tuple:
            if c == code:
                return v or None
        return None

    user_identity: Optional[str] = None
    password: Optional[str] = None
    recipient: Optional[str] = None
    originator: Optional[str] = None
    message: Optional[str] = None
    error_code: Optional[str] = None
    error_text: Optional[str] = None

    if operation_code in _LOGIN_OPS:
        user_identity = _find(_P_USER_IDENTITY)
        password = _find(_P_PASSWORD)
    elif operation_code in _MESSAGE_OPS:
        recipient = _find(_P_DESTINATION)
        originator = _find(_P_ORIGINATING) or _find(_P_ALPHA_ORIGINATING)
        message = _find(_P_USER_DATA)

    # 응답에는 오류 파라미터가 따라올 수 있다(연산 종류 무관).
    error_code = _find(_P_ERROR_CODE)
    error_text = _find(_P_ERROR_TEXT)

    # 첫 파라미터 시작 절대 오프셋 (STX + 헤더 + TAB).
    payload_offset = offset + 1 + len(header) + 1

    return Cimd2(
        operation_code=operation_code,
        operation_name=operation_name(operation_code),
        packet_number=packet_number,
        frame_length=frame_length,
        user_identity=user_identity,
        password=password,
        recipient=recipient,
        originator=originator,
        message=message,
        error_code=error_code,
        error_text=error_text,
        checksum=checksum,
        checksum_ok=checksum_ok,
        parameters=param_tuple,
        payload_offset=payload_offset,
    )
