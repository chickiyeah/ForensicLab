"""Redis RESP 명령 파싱 코어.

MySQL(:mod:`forensiclab.mysql`)·PostgreSQL(:mod:`forensiclab.postgres`)에
이은 데이터베이스 형제. Redis 는 관용 포트 6379 에서 **RESP(REdis
Serialization Protocol)** 텍스트 프로토콜로 동작한다. 클라이언트는 명령을
*Bulk String 의 배열* 로 보낸다. 기본 설정의 Redis 가 인증 없이 인터넷에
노출되는 사례가 흔하고, 그 위에서 임의 파일 쓰기로 RCE 까지 이어지는 고전적
공격 표적이라 침해 분석에서 가치가 높다.

RESP 배열 프레이밍(모든 줄 구분은 ``\\r\\n``)::

    *<N>\\r\\n              N = 명령 요소 개수(배열 길이)
    $<len>\\r\\n<bytes>\\r\\n   (N 번 반복) 각 요소는 Bulk String
    ...

레거시 *인라인 명령* 형식도 있다(공백으로 구분된 한 줄, 예 ``PING\\r\\n``).
공격자가 ``nc`` 로 직접 명령을 흘려보낼 때 자주 쓰인다.

침해/사고 분석에서의 단서:

- **평문 자격증명(AUTH)**: ``AUTH <password>`` 또는 Redis 6+ ACL 의
  ``AUTH <user> <password>`` 가 평문으로 노출된다(MySQL/PostgreSQL 형제의
  평문 자격증명 정황과 동일). 비밀번호는 마지막 인자.
- **임의 파일 쓰기 → RCE(CONFIG SET dir/dbfilename)**: ``CONFIG SET dir``
  로 작업 디렉터리를, ``CONFIG SET dbfilename`` 으로 RDB 파일명을 바꾼 뒤
  ``SAVE`` 하면 임의 경로에 파일을 떨어뜨릴 수 있다 — ``~/.ssh/
  authorized_keys`` 주입·웹셸·cron 작성으로 이어지는 Redis 무인증 RCE 의
  핵심 1차 프리미티브.
- **악성 복제(SLAVEOF/REPLICAOF)**: 공격자가 통제하는 마스터로 복제를
  걸어 악성 모듈 동기화로 RCE 를 노리는 벡터.
- **모듈 적재(MODULE LOAD)**: ``.so`` 모듈 적재로 직접 코드 실행.
- **증거 파괴(FLUSHALL/FLUSHDB)**: 데이터셋 전체 삭제 — 흔적 지우기 정황.

설계 원칙(:mod:`forensiclab.postgres`·:mod:`forensiclab.mysql` 와 동일):
- 부작용 없음: 디스크/표준출력/네트워크 없이 순수 함수.
- stdlib 전용: 외부 의존성 없음.
- 안전: 입력 바이트를 변형하지 않는다(읽기 전용).
- 견고: RESP 명령이 아니거나 망가진 입력은 예외 대신 ``None``. 본문이 잘려
  있으면 파싱 가능한 인자까지만 채운다.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional

__all__ = [
    "REDIS_PORTS",
    "RedisCommand",
    "parse_redis_command",
]

# Redis 관용 TCP 포트. 식별 보조용일 뿐, 파싱은 페이로드 형식만으로 판별한다.
REDIS_PORTS = (6379,)

# 명령 동사(verb)로 인정할 형태. 오탐 방지를 위해 글자로 시작하는 토큰만
# Redis 명령으로 본다(임의 바이너리가 RESP 처럼 보여도 거르기 위함).
_VERB_RE = re.compile(rb"[A-Za-z][A-Za-z0-9_]*\Z")

# 합리적 상한(오탐/폭주 방지). 실제 명령 배열은 수십 요소 안쪽이다.
_MAX_ELEMENTS = 1024
# Redis 의 proto-max-bulk-len 기본값(512MB)을 넘는 선언은 거부.
_MAX_BULK = 512 * 1024 * 1024


@dataclass(frozen=True)
class RedisCommand:
    """파싱된 Redis RESP 명령(클라이언트→서버 한 개 명령).

    Attributes:
        verb: 대문자화한 명령 이름(예 ``"AUTH"``·``"CONFIG"``).
        args: 동사 뒤 인자들(디코드된 문자열).
        inline: 인라인 형식(공백 구분 한 줄)이면 ``True``, RESP 배열이면 ``False``.
        arg_count: RESP 배열이 선언한 요소 개수(``*N``). 인라인은 실제 토큰 수.
    """

    verb: str
    args: List[str]
    inline: bool
    arg_count: int

    @property
    def is_auth(self) -> bool:
        """평문 자격증명을 노출하는 AUTH 명령인가."""
        return self.verb == "AUTH"

    @property
    def password(self) -> Optional[str]:
        """AUTH 비밀번호(평문). 1인자/2인자(ACL) 모두 마지막 인자가 비밀번호."""
        if self.verb != "AUTH" or not self.args:
            return None
        return self.args[-1]

    @property
    def username(self) -> Optional[str]:
        """AUTH 의 ACL 사용자명(Redis 6+ 2인자 형식). 1인자 형식이면 ``None``."""
        if self.verb == "AUTH" and len(self.args) >= 2:
            return self.args[0]
        return None

    @property
    def is_config_set(self) -> bool:
        """``CONFIG SET`` (런타임 설정 변조)인가."""
        return (
            self.verb == "CONFIG"
            and len(self.args) >= 1
            and self.args[0].upper() == "SET"
        )

    @property
    def config_set_param(self) -> Optional[str]:
        """``CONFIG SET <param>`` 의 대상 파라미터(소문자). 아니면 ``None``."""
        if self.is_config_set and len(self.args) >= 2:
            return self.args[1].lower()
        return None

    @property
    def is_file_write_vector(self) -> bool:
        """``CONFIG SET dir|dbfilename`` — 임의 파일 쓰기(RDB) RCE 1차 프리미티브인가."""
        return self.config_set_param in ("dir", "dbfilename")

    @property
    def is_replication(self) -> bool:
        """``SLAVEOF``/``REPLICAOF`` — 악성 복제(모듈 동기화 RCE) 벡터인가."""
        return self.verb in ("SLAVEOF", "REPLICAOF")

    @property
    def is_module_load(self) -> bool:
        """``MODULE LOAD`` — 모듈 적재 직접 코드 실행인가."""
        return self.verb == "MODULE" and bool(self.args) and self.args[0].upper() == "LOAD"

    @property
    def is_destructive(self) -> bool:
        """``FLUSHALL``/``FLUSHDB`` — 데이터셋 삭제(증거 파괴) 정황인가."""
        return self.verb in ("FLUSHALL", "FLUSHDB")


def _decode(b: bytes) -> str:
    return b.decode("utf-8", "replace")


def _make(verb: str, args: List[str], inline: bool, arg_count: int) -> Optional[RedisCommand]:
    if not verb:
        return None
    if not _VERB_RE.match(verb.encode("utf-8", "replace")):
        return None
    return RedisCommand(verb=verb.upper(), args=args, inline=inline, arg_count=arg_count)


def _parse_resp_array(data: bytes, offset: int) -> Optional[RedisCommand]:
    line_end = data.find(b"\r\n", offset)
    if line_end == -1:
        return None
    try:
        n = int(data[offset + 1:line_end])
    except ValueError:
        return None
    if n < 1 or n > _MAX_ELEMENTS:
        return None

    pos = line_end + 2
    elems: List[str] = []
    for _ in range(n):
        if pos >= len(data):
            break  # 잘림: 가용 요소까지만
        if data[pos:pos + 1] != b"$":
            break  # Bulk String 이 아님 → 중단
        le = data.find(b"\r\n", pos)
        if le == -1:
            break
        try:
            blen = int(data[pos + 1:le])
        except ValueError:
            break
        start = le + 2
        if blen < 0:  # Null Bulk String
            elems.append("")
            pos = start
            continue
        if blen > _MAX_BULK:
            return None
        end = start + blen
        if end > len(data):
            # 값이 잘림: 가용 바이트까지만 채우고 종료.
            elems.append(_decode(data[start:len(data)]))
            break
        elems.append(_decode(data[start:end]))
        pos = end + 2  # 후행 \r\n 건너뜀

    if not elems:
        return None
    return _make(elems[0], elems[1:], inline=False, arg_count=n)


def _parse_inline(data: bytes, offset: int) -> Optional[RedisCommand]:
    # 첫 줄(\n 까지)을 공백으로 분해. 인라인 명령은 한 줄짜리.
    nl = data.find(b"\n", offset)
    line = data[offset:nl if nl != -1 else len(data)]
    line = line.rstrip(b"\r")
    tokens = line.split()
    if not tokens:
        return None
    args = [_decode(t) for t in tokens[1:]]
    return _make(_decode(tokens[0]), args, inline=True, arg_count=len(tokens))


def parse_redis_command(data: bytes, offset: int = 0) -> Optional[RedisCommand]:
    """원시 바이트에서 Redis RESP 명령 하나를 파싱한다.

    Args:
        data: Redis 흐름 바이트. 보통 클라이언트→서버 TCP 페이로드의 선두
            (:mod:`forensiclab.netdissect` 의 ``payload_offset`` 부터)다.
        offset: 데이터가 시작하는 위치(기본 0).

    Returns:
        :class:`RedisCommand`. ``*`` 로 시작하면 RESP 배열로, 그 외에는 인라인
        명령으로 해석한다. 동사가 글자로 시작하지 않거나(오탐), 프레이밍이
        망가졌거나, 합리적 상한을 넘으면 ``None``. RESP 본문이 잘려 있으면
        파싱 가능한 인자까지만 채운다.
    """
    if not data or offset < 0:
        return None
    if offset >= len(data):
        return None

    if data[offset:offset + 1] == b"*":
        return _parse_resp_array(data, offset)
    return _parse_inline(data, offset)
