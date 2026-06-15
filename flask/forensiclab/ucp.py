"""UCP/EMI — Universal Computer Protocol / External Machine Interface 파싱 코어.

:mod:`forensiclab.smpp` 가 ESME(외부 응용)와 SMSC 사이의 *현대* 표준 길목이라면,
UCP/EMI 는 그 **레거시 사촌** — 같은 평면(A2P 대량 발송·OTP·마케팅·스미싱 캠페인이
SMSC 에 주입되는 길)을 다른 와이어 포맷으로 나르는, 여전히 현역인 구형 SMSC 접속
프로토콜이다(CMG/LogicaCMG EMI, 흔히 TCP 2024/3024 등). SMPP 가 고정 16바이트
바이너리 헤더라면 UCP 는 **ASCII 텍스트 프레임** — ``STX`` 와 ``ETX`` 사이를 ``/``
로 구분한 필드열(EMI/UCP 4.x §4)이라 :mod:`forensiclab.ftp`·:mod:`forensiclab.sip`
처럼 사람이 읽는 평문이다.

프레임: ``<STX> TRN / LEN / O_R / OT / <연산별 필드…> / CHECKSUM <ETX>``

- **TRN**: 트랜잭션 참조 번호(요청↔응답 상관, :mod:`forensiclab.smpp` ``sequence_number`` 대응).
- **LEN**: 프레임 전체 길이.
- **O_R**: ``O`` 연산(요청) · ``R`` 결과(응답).
- **OT**: 연산 타입(2자리) — 01 call input(레거시 단문)·51 submit short message·
  52/53 delivery·**60 session management(로그인)**.

포렌식 핵심(:mod:`forensiclab.smpp` 대응):

- **자격증명**(OT 60 session management): ``account``(OAdC, 계정명)·**평문
  ``password``**(PWD 필드) 가 그대로 실린다 — :mod:`forensiclab.smpp` bind
  system_id/password, :mod:`forensiclab.ftp`/:mod:`forensiclab.smtp` 평문 로그인과
  같은 노출. 결과(``R``)의 ``N``(NACK)+``error_code`` 반복 = 패스워드 추정.
- **당사자·본문**(OT 01/51): ``recipient``(AdC=착신 표적)·``originator``(OAdC=
  발신, 흔히 위조된 발신자명/숏코드). OT 01(call input)은 고정 위치라 ``message``
  까지 푼다(MT=3 이면 IRA 16진 → 텍스트, 스미싱 링크·OTP 자체). OT 51 은 필드
  배치가 깊고 버전 의존이라 첫 두 필드(착·발신)만 보수적으로 푼다.
- **연산·결과**(``operation_name``/``is_operation``/``is_result``): 로그인(60)→
  submit(51) 흐름(:mod:`forensiclab.timeline`)·``trn`` 상관(:mod:`forensiclab.flows`
  IP 쌍 안)·결과 ``A``/``N``·``checksum_ok`` 무결성.

설계 원칙(:mod:`forensiclab.smpp` 와 동일):
- 부작용 없음·stdlib 전용·읽기 전용(입력 무변형)·``offset`` 지원.
- ``STX`` 로 시작하지 않거나 필드가 5개 미만이거나 ``O_R`` 이 ``O``/``R`` 가
  아니거나 ``OT`` 가 2자리 숫자가 아니면 ``None``(TCP 스트림 오탐 가드).
- ``ETX`` 가 없어 프레임이 절단되면 풀 수 있는 필드까지만 채우고 체크섬은 검증
  불가(``None``)로 둔다.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Tuple

__all__ = [
    "Ucp",
    "UCP_OPERATION_NAMES",
    "operation_name",
    "decode_ucp_ira",
    "parse_ucp",
]

_STX = 0x02
_ETX = 0x03

# OT(operation type) → 연산 이름 (EMI/UCP 4.x §4).
UCP_OPERATION_NAMES = {
    1: "call_input",
    2: "multiple_address_call_input",
    3: "call_input_supplementary",
    30: "sms_message_transfer",
    31: "sms_alert",
    51: "submit_short_message",
    52: "delivery_short_message",
    53: "delivery_notification",
    54: "modify_message",
    55: "inquiry_message",
    56: "delete_message",
    57: "response_inquiry_message",
    58: "response_delete_message",
    60: "session_management",
    61: "provisioning_actions",
}

# 본문에 (account, password) 자격증명을 싣는 세션 관리 연산.
_SESSION_OPS = {60}
# 첫 두 데이터 필드가 (AdC 착신, OAdC 발신)인 메시지 계열.
_MESSAGE_OPS = {1, 2, 3, 30, 51, 52, 53}
# 고정 위치라 본문(message)까지 안전하게 풀 수 있는 레거시 연산.
_LEGACY_MESSAGE_OPS = {1}


def operation_name(operation_type: int) -> str:
    """``operation_type`` → 연산 이름(미정의면 ``"operation-NN"``)."""
    return UCP_OPERATION_NAMES.get(operation_type, f"operation-{operation_type:02d}")


def decode_ucp_ira(field: str) -> str:
    """IRA(International Reference Alphabet) 16진 인코딩 메시지 필드를 텍스트로 푼다.

    UCP 의 알파뉴메릭 메시지(MT=3)는 각 문자를 두 자리 16진으로 표기한다
    (예 ``"48656C6C6F"`` → ``"Hello"``). 유효한 16진이 아니거나 길이가 홀수면
    원본 문자열을 그대로 돌려준다(무손실·방어적).
    """
    if not field or len(field) % 2 != 0:
        return field
    try:
        return bytes.fromhex(field).decode("latin-1")
    except ValueError:
        return field


@dataclass(frozen=True)
class Ucp:
    """파싱된 UCP/EMI 프레임 한 개.

    Attributes:
        trn: 트랜잭션 참조 번호(요청↔응답 상관; 파싱 불가면 ``None``).
        length: 선언된 프레임 길이(LEN; 파싱 불가면 ``None``).
        frame_length: 실제 프레임 바이트 길이(STX~ETX 포함; 절단이면 가용분).
        operation_or_result: ``"O"``(연산/요청) 또는 ``"R"``(결과/응답).
        operation_type: 연산 타입 원값(OT).
        operation_name: 연산 이름.
        recipient: 착신 주소(AdC; 메시지 연산만, 없으면 ``None``).
        originator: 발신 주소(OAdC; 메시지 연산만, 없으면 ``None``).
        message_type: MT 필드(OT 01 류; 없으면 ``None``).
        message: 디코드된 본문(OT 01 류만; 없으면 ``None``).
        account: 세션 관리(60)의 계정명(OAdC; 없으면 ``None``).
        password: 세션 관리(60)의 평문 패스워드(없으면 ``None``).
        result_ack: 결과의 ``"A"``(ACK)/``"N"``(NACK)(연산이면 ``None``).
        error_code: NACK 의 오류 코드(EC; 없으면 ``None``).
        checksum: 선언된 체크섬 문자열(2자리 16진).
        checksum_ok: 체크섬 일치 여부(검증 불가면 ``None``).
        fields: OT 다음~체크섬 이전의 원시 데이터 필드열.
        payload_offset: 첫 데이터 필드(OT 다음)의 절대 오프셋.
    """

    trn: Optional[int]
    length: Optional[int]
    frame_length: int
    operation_or_result: str
    operation_type: int
    operation_name: str
    recipient: Optional[str]
    originator: Optional[str]
    message_type: Optional[str]
    message: Optional[str]
    account: Optional[str]
    password: Optional[str]
    result_ack: Optional[str]
    error_code: Optional[str]
    checksum: str
    checksum_ok: Optional[bool]
    fields: Tuple[str, ...]
    payload_offset: int

    @property
    def is_operation(self) -> bool:
        """연산(요청, ``O``) 여부."""
        return self.operation_or_result == "O"

    @property
    def is_result(self) -> bool:
        """결과(응답, ``R``) 여부."""
        return self.operation_or_result == "R"

    @property
    def is_session(self) -> bool:
        """세션 관리(60·자격증명 운반) 연산 여부."""
        return self.operation_type in _SESSION_OPS

    @property
    def is_ack(self) -> bool:
        """결과이며 긍정 응답(ACK)인지."""
        return self.result_ack == "A"

    @property
    def is_nack(self) -> bool:
        """결과이며 부정 응답(NACK)인지 — 인증 실패/거부 단서."""
        return self.result_ack == "N"

    @property
    def target_number(self) -> Optional[str]:
        """대표 상대 번호 — 착신(메시지 연산의 recipient)."""
        return self.recipient


def parse_ucp(data: bytes, offset: int = 0) -> Optional[Ucp]:
    """UCP/EMI 프레임을 파싱한다(EMI/UCP 4.x).

    Args:
        data: UCP 프레임 바이트(보통 TCP 페이로드). ``offset`` 위치에 ``STX``.
        offset: 프레임이 시작하는 위치(기본 0).

    Returns:
        :class:`Ucp`. ``offset`` 이 ``STX`` 가 아니거나, ``/`` 로 나눈 필드가 5개
        미만이거나, ``O_R`` 이 ``O``/``R`` 가 아니거나, ``OT`` 가 2자리 숫자가
        아니면 ``None``(TCP 스트림 오탐 가드). 세션 관리(60)는 account·password
        까지, call input(01)은 착·발신·message 까지, 그 외 메시지 연산은 착·발신
        까지 푼다. ``ETX`` 가 없으면(절단) 가용분까지 채우고 체크섬은 ``None``.
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

    parts = content.split("/")
    if len(parts) < 5:
        return None

    trn_s, len_s, oand_r, ot_s = parts[0], parts[1], parts[2], parts[3]
    if oand_r not in ("O", "R"):
        return None
    if len(ot_s) != 2 or not ot_s.isdigit():
        return None
    operation_type = int(ot_s)

    checksum = parts[-1]
    data_fields = tuple(parts[4:-1])

    trn = int(trn_s) if trn_s.isdigit() else None
    length = int(len_s) if len_s.isdigit() else None

    # 체크섬 검증: STX/ETX/체크섬 필드를 뺀 모든 바이트 합 & 0xFF (UCP §5).
    checksum_ok: Optional[bool] = None
    if not truncated and len(checksum) == 2:
        summed = content[: len(content) - len(checksum)]
        computed = sum(ord(c) for c in summed) & 0xFF
        try:
            checksum_ok = computed == int(checksum, 16)
        except ValueError:
            checksum_ok = None

    recipient: Optional[str] = None
    originator: Optional[str] = None
    message_type: Optional[str] = None
    message: Optional[str] = None
    account: Optional[str] = None
    password: Optional[str] = None
    result_ack: Optional[str] = None
    error_code: Optional[str] = None

    if oand_r == "R":
        # 결과: [ACK/NACK, ...]. NACK 면 다음이 오류 코드(EC).
        if data_fields:
            result_ack = data_fields[0][:1] or None
        if result_ack == "N" and len(data_fields) >= 2:
            error_code = data_fields[1] or None
    elif operation_type in _SESSION_OPS:
        # 60 session: [OAdC, OTON, ONPI, STYP, PWD, NPWD, VERS, ...].
        if len(data_fields) >= 1:
            account = data_fields[0] or None
        if len(data_fields) >= 5:
            password = data_fields[4] or None
    elif operation_type in _MESSAGE_OPS:
        # 01/51/…: [AdC, OAdC, AC, MT, Msg, …]. 첫 둘은 착·발신으로 안정적.
        if len(data_fields) >= 1:
            recipient = data_fields[0] or None
        if len(data_fields) >= 2:
            originator = data_fields[1] or None
        if operation_type in _LEGACY_MESSAGE_OPS and len(data_fields) >= 5:
            message_type = data_fields[3] or None
            raw_msg = data_fields[4]
            message = decode_ucp_ira(raw_msg) if message_type == "3" else (raw_msg or None)

    # 첫 데이터 필드 시작 절대 오프셋 (STX + "TRN/LEN/OR/OT/").
    header_chars = len(trn_s) + 1 + len(len_s) + 1 + 1 + 1 + 2 + 1
    payload_offset = offset + 1 + header_chars

    return Ucp(
        trn=trn,
        length=length,
        frame_length=frame_length,
        operation_or_result=oand_r,
        operation_type=operation_type,
        operation_name=operation_name(operation_type),
        recipient=recipient,
        originator=originator,
        message_type=message_type,
        message=message,
        account=account,
        password=password,
        result_ack=result_ack,
        error_code=error_code,
        checksum=checksum,
        checksum_ok=checksum_ok,
        fields=data_fields,
        payload_offset=payload_offset,
    )
