"""MongoDB 와이어 프로토콜 메시지 파싱 코어.

MySQL/PostgreSQL/Redis/memcached 에 이은 노출된 DB 형제. MongoDB 는 관용
포트 27017(샤드 27018·config 27019) 에서 바이너리 **와이어 프로토콜**로
동작한다. 기본 설정이 ``bindIp: 0.0.0.0`` + **무인증**이던 시절(3.x 이전
기본값) 수만 대가 인터넷에 그대로 노출됐고, 2017 년 "MongoDB 랜섬" 사태
(무인증 인스턴스를 통째로 덤프·삭제 후 몸값 요구)의 무대였다. 그래서
침해 분석에서 가치가 높다:

- **무인증 노출·정찰(is_handshake)**: 모든 드라이버는 접속 직후 ``isMaster``
  /``hello`` 핸드셰이크로 서버 역할·버전·레플리카셋을 조회한다. 무인증
  서버는 이 한 번으로 토폴로지를 다 흘린다.
- **인증 정황(is_auth)**: ``saslStart``/``saslContinue``/``authenticate`` 명령이
  보이면 인증을 시도한다는 뜻. ``saslStart`` 의 ``mechanism`` 이
  ``PLAIN`` 이면 자격증명을 (TLS 없으면) 평문 base64 로 보낸다 — SCRAM-SHA
  대비 약한 다운그레이드 정황.
- **데이터 유출(find/getMore/aggregate)**: 무인증 ``find`` 한 번으로 컬렉션이
  유출된다. ``$db``/컬렉션 이름이 표적을 드러낸다.
- **증거 파괴·랜섬(drop/dropDatabase/delete)**: 컬렉션·DB 삭제 — 덤프 후
  지우기, 서비스 방해.

메시지 형식 — 16바이트 헤더(모든 정수 little-endian int32)::

    messageLength(전체 길이) · requestID · responseTo · opCode

opCode 분기:

- ``OP_QUERY``(2004): ``flags`` · cstring ``fullCollectionName``("db.col") ·
  ``numberToSkip`` · ``numberToReturn`` · query 문서(BSON). 레거시지만 3.6
  이전 + 현재도 ``admin.$cmd`` 핸드셰이크/인증에 쓰인다.
- ``OP_MSG``(2013): ``flagBits`` + 섹션들. kind 0 본문 섹션의 BSON 문서가
  명령이다. ``$db`` 필드가 대상 DB.

설계 원칙(:mod:`forensiclab.memcached`·:mod:`forensiclab.mysql` 와 동일):
- 부작용 없음: 디스크/표준출력/네트워크 없이 순수 함수.
- stdlib 전용: 외부 의존성 없음(최소 BSON 최상위 워커 자체 구현).
- 안전: 입력 바이트를 변형하지 않는다(읽기 전용).
- 견고: opCode 가 알려진 값이 아니면(오탐) 예외 대신 ``None``. BSON 이
  잘려 있으면 가용 바이트까지만 훑고 멈춘다.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

__all__ = [
    "MONGODB_PORTS",
    "OP_CODE_NAMES",
    "HANDSHAKE_COMMANDS",
    "AUTH_COMMANDS",
    "WRITE_COMMANDS",
    "MongodbMessage",
    "parse_mongodb_message",
]

# MongoDB 관용 TCP 포트(mongod·샤드·config). 식별 보조용일 뿐, 파싱은
# 포트와 무관하게 페이로드 형식(opCode)으로만 판별한다.
MONGODB_PORTS = (27017, 27018, 27019)

# 알려진 opCode. 오탐 방지의 핵심 — 임의 바이너리가 16바이트 헤더처럼
# 보여도 opCode 가 이 집합에 없으면 MongoDB 메시지로 보지 않는다.
OP_CODE_NAMES = {
    1: "OP_REPLY",
    2001: "OP_UPDATE",
    2002: "OP_INSERT",
    2004: "OP_QUERY",
    2005: "OP_GET_MORE",
    2006: "OP_DELETE",
    2007: "OP_KILL_CURSORS",
    2012: "OP_COMPRESSED",
    2013: "OP_MSG",
}
_OP_QUERY = 2004
_OP_MSG = 2013

# 핸드셰이크/정찰 명령(무인증 노출 시 토폴로지 유출). 대소문자 혼용이라
# 비교는 소문자로.
HANDSHAKE_COMMANDS = frozenset({"ismaster", "hello", "buildinfo", "getlog"})

# 인증 명령(자격증명 흐름). saslStart 의 mechanism=PLAIN 이면 평문 정황.
AUTH_COMMANDS = frozenset({"saslstart", "saslcontinue", "authenticate", "getnonce", "logout"})

# 쓰기/파괴 명령(오염·증거 파괴·랜섬 정황). opCode 기반 레거시 쓰기는 별도.
WRITE_COMMANDS = frozenset({
    "insert", "update", "delete", "findandmodify",
    "drop", "dropdatabase", "create", "renamecollection",
})

# 합리적 상한(폭주 방지). 헤더의 messageLength 가 이보다 크면 거부.
_MAX_MSG = 48 * 1024 * 1024  # MongoDB 기본 maxMessageSize(48MB) 와 동일
_HEADER_LEN = 16


def _i32(data: bytes, i: int) -> int:
    """little-endian int32(부호 있음)."""
    return int.from_bytes(data[i:i + 4], "little", signed=True)


def _read_cstring(data: bytes, i: int) -> Tuple[Optional[str], int]:
    """offset 에서 NUL 종단 문자열을 읽어 (값, 다음오프셋) 반환. 종단 없으면 (None, 끝)."""
    end = data.find(b"\x00", i)
    if end == -1:
        return None, len(data)
    return data[i:end].decode("utf-8", "replace"), end + 1


def _skip_bson_value(data: bytes, i: int, t: int) -> Tuple[Optional[str], Optional[int]]:
    """BSON 값 하나를 건너뛴다.

    Returns:
        (문자열값|None, 다음오프셋|None). 문자열 타입(0x02)이면 값을 함께
        돌려주고, 알 수 없는 타입이거나 잘려 있으면 (None, None).
    """
    n = len(data)
    if t == 0x01:  # double
        return None, i + 8
    if t in (0x02, 0x0D, 0x0E):  # string / code / symbol
        if i + 4 > n:
            return None, None
        ln = _i32(data, i)
        start, end = i + 4, i + 4 + ln
        if ln < 1 or end > n:
            return None, None
        val = data[start:end - 1].decode("utf-8", "replace") if t == 0x02 else None
        return val, end
    if t in (0x03, 0x04):  # embedded doc / array
        if i + 4 > n:
            return None, None
        ln = _i32(data, i)
        if ln < 5 or i + ln > n:
            return None, None
        return None, i + ln
    if t == 0x05:  # binary
        if i + 4 > n:
            return None, None
        ln = _i32(data, i)
        end = i + 4 + 1 + ln  # +1 = subtype byte
        if ln < 0 or end > n:
            return None, None
        return None, end
    if t in (0x06, 0x0A, 0xFF, 0x7F):  # undefined / null / minkey / maxkey
        return None, i
    if t == 0x07:  # objectId
        return None, i + 12
    if t == 0x08:  # bool
        return None, i + 1
    if t in (0x09, 0x11, 0x12):  # datetime / timestamp / int64
        return None, i + 8
    if t == 0x10:  # int32
        return None, i + 4
    if t == 0x13:  # decimal128
        return None, i + 16
    # 0x0B regex·0x0C dbpointer·0x0F code_w_scope 는 드묾 — 안전하게 중단.
    return None, None


def _bson_top_level(data: bytes, i: int) -> Tuple[Optional[str], Dict[str, str]]:
    """``i`` 의 BSON 문서에서 (첫 키=명령 이름, 최상위 문자열 필드 dict) 추출.

    전체 BSON 을 디코드하지 않고 최상위 요소만 훑는다. 명령 이름과
    ``$db``/``mechanism`` 같은 문자열 필드만 있으면 포렌식 분류에 충분하다.
    잘려 있으면 가용 바이트까지만 훑고 멈춘다.
    """
    n = len(data)
    if i + 5 > n:
        return None, {}
    total = _i32(data, i)
    if total < 5:
        return None, {}
    end = min(i + total, n)  # 잘림 허용
    first_key: Optional[str] = None
    strings: Dict[str, str] = {}
    j = i + 4
    while j < end:
        t = data[j]
        if t == 0x00:  # 문서 종단
            break
        j += 1
        key, j = _read_cstring(data, j)
        if key is None:
            break
        if first_key is None:
            first_key = key
        sval, nj = _skip_bson_value(data, j, t)
        if nj is None:
            break
        if sval is not None:
            strings[key] = sval
        j = nj
    return first_key, strings


@dataclass(frozen=True)
class MongodbMessage:
    """파싱된 MongoDB 와이어 메시지 하나.

    Attributes:
        message_length: 헤더가 선언한 전체 메시지 길이(바이트).
        request_id: 송신자가 부여한 메시지 식별자.
        response_to: 응답이면 원 요청의 request_id(요청이면 0).
        op_code: 연산 코드(:data:`OP_CODE_NAMES` 참조).
        command: 명령 이름(BSON 첫 키, 예 ``"isMaster"``·``"find"``). 없으면 ``None``.
        database: 대상 DB(OP_QUERY fullCollectionName 앞부분 또는 OP_MSG ``$db``).
        collection: 대상 컬렉션(OP_QUERY fullCollectionName 뒷부분). 없으면 ``None``.
        full_collection_name: OP_QUERY 의 ``"db.collection"`` 원문. 그 외 ``None``.
        flag_bits: OP_QUERY flags / OP_MSG flagBits. 없으면 ``None``.
        fields: BSON 최상위 문자열 필드(``$db``·``mechanism`` 등).
    """

    message_length: int
    request_id: int
    response_to: int
    op_code: int
    command: Optional[str] = None
    database: Optional[str] = None
    collection: Optional[str] = None
    full_collection_name: Optional[str] = None
    flag_bits: Optional[int] = None
    fields: Dict[str, str] = field(default_factory=dict)

    @property
    def op_name(self) -> str:
        """opCode 의 사람이 읽는 이름(예 ``"OP_MSG"``). 미지값은 ``OP_<n>``."""
        return OP_CODE_NAMES.get(self.op_code, f"OP_{self.op_code}")

    @property
    def is_request(self) -> bool:
        """클라이언트→서버 요청인가(``response_to == 0``)."""
        return self.response_to == 0

    @property
    def _command_lower(self) -> Optional[str]:
        return self.command.lower() if self.command else None

    @property
    def is_handshake(self) -> bool:
        """``isMaster``/``hello`` 등 핸드셰이크·정찰 명령인가(토폴로지 유출)."""
        return self._command_lower in HANDSHAKE_COMMANDS

    @property
    def is_auth(self) -> bool:
        """``saslStart``/``authenticate`` 등 인증 흐름 명령인가."""
        return self._command_lower in AUTH_COMMANDS

    @property
    def is_write(self) -> bool:
        """쓰기/파괴 명령(오염·증거 파괴·랜섬 정황)인가. 레거시 OP_ 쓰기 포함."""
        if self.op_code in (2001, 2002, 2006):  # OP_UPDATE/OP_INSERT/OP_DELETE
            return True
        return self._command_lower in WRITE_COMMANDS

    @property
    def auth_mechanism(self) -> Optional[str]:
        """``saslStart`` 의 SASL ``mechanism``(예 ``"SCRAM-SHA-256"``·``"PLAIN"``)."""
        return self.fields.get("mechanism")

    @property
    def is_plaintext_auth(self) -> bool:
        """SASL 메커니즘이 ``PLAIN`` 인가(TLS 없으면 평문 자격증명 정황)."""
        mech = self.auth_mechanism
        return mech is not None and mech.upper() == "PLAIN"

    @property
    def is_admin_db(self) -> bool:
        """대상 DB 가 ``admin`` 인가(인증·권한 명령은 admin 으로 흐른다)."""
        return self.database == "admin"


def _parse_op_query(data: bytes, body: int, end: int) -> Tuple[
        Optional[str], Optional[str], Optional[str], Optional[str], Optional[int], Dict[str, str]]:
    """OP_QUERY 본문 파싱 → (command, db, col, fcn, flags, fields)."""
    if body + 4 > end:
        return None, None, None, None, None, {}
    flags = _i32(data, body)
    fcn, j = _read_cstring(data, body + 4)
    db = col = None
    if fcn is not None and "." in fcn:
        db, col = fcn.split(".", 1)
    elif fcn is not None:
        db = fcn
    # numberToSkip(4) + numberToReturn(4) 뒤에 query 문서.
    qpos = j + 8
    command, fields = _bson_top_level(data, qpos)
    return command, db, col, fcn, flags, fields


def _parse_op_msg(data: bytes, body: int, end: int) -> Tuple[
        Optional[str], Optional[str], Optional[int], Dict[str, str]]:
    """OP_MSG 본문 파싱 → (command, db, flag_bits, fields). 첫 kind-0 본문 섹션 사용."""
    if body + 4 > end:
        return None, None, None, {}
    flag_bits = _i32(data, body)
    i = body + 4
    while i < end:
        kind = data[i]
        i += 1
        if kind == 0:  # 본문 섹션 — 명령 문서
            command, fields = _bson_top_level(data, i)
            return command, fields.get("$db"), flag_bits, fields
        if kind == 1:  # 문서 시퀀스 — 길이만큼 건너뛰기
            if i + 4 > end:
                break
            seclen = _i32(data, i)
            if seclen < 4:
                break
            i += seclen
            continue
        break  # 알 수 없는 섹션 종류
    return None, None, flag_bits, {}


def parse_mongodb_message(data: bytes, offset: int = 0) -> Optional[MongodbMessage]:
    """원시 바이트에서 MongoDB 와이어 메시지 하나를 파싱한다.

    Args:
        data: MongoDB 흐름 바이트. 보통 TCP 페이로드의 선두(16바이트 헤더부터).
        offset: 데이터가 시작하는 위치(기본 0).

    Returns:
        :class:`MongodbMessage`. opCode 가 알려진 값이 아니거나(오탐),
        messageLength 가 비정상이면 ``None``. OP_QUERY/OP_MSG 면 명령 이름·
        대상 DB/컬렉션·SASL 메커니즘을 BSON 최상위에서 추출하며, 본문이 잘려
        있으면 가용 바이트까지만 훑는다.
    """
    if not data or offset < 0 or offset + _HEADER_LEN > len(data):
        return None

    message_length = _i32(data, offset)
    request_id = _i32(data, offset + 4)
    response_to = _i32(data, offset + 8)
    op_code = _i32(data, offset + 12)

    if op_code not in OP_CODE_NAMES:
        return None
    if message_length < _HEADER_LEN or message_length > _MAX_MSG:
        return None

    body = offset + _HEADER_LEN
    end = min(offset + message_length, len(data))  # 잘림 허용

    command = database = collection = fcn = None
    flag_bits: Optional[int] = None
    fields: Dict[str, str] = {}

    if op_code == _OP_QUERY:
        command, database, collection, fcn, flag_bits, fields = _parse_op_query(data, body, end)
    elif op_code == _OP_MSG:
        command, database, flag_bits, fields = _parse_op_msg(data, body, end)

    return MongodbMessage(
        message_length=message_length,
        request_id=request_id,
        response_to=response_to,
        op_code=op_code,
        command=command,
        database=database,
        collection=collection,
        full_collection_name=fcn,
        flag_bits=flag_bits,
        fields=fields,
    )
