"""memcached 텍스트 프로토콜 명령 파싱 코어.

Redis(:mod:`forensiclab.redis`)에 이은 인메모리 캐시 형제. memcached 는
관용 포트 11211(TCP·UDP 양쪽) 에서 줄 단위 **텍스트 프로토콜**로 동작한다.
고전 텍스트 프로토콜에는 인증이 없어(SASL 인증은 바이너리 프로토콜 전용),
기본 설정의 memcached 가 인터넷에 그대로 노출되는 사례가 흔하다. 그래서
침해 분석에서 가치가 높다:

- **UDP 반사·증폭 DDoS(memcrashed)**: UDP 11211 로 작은 ``stats`` /
  ``get`` 질의를 보내면 거대한 응답이 위조된 피해자 IP 로 되돌아간다.
  2018 년 1.3~1.7Tbps 급 증폭 공격(증폭률 수만 배)의 매개체였다. UDP
  데이터그램은 텍스트 앞에 8바이트 프레임 헤더(request_id·sequence·
  total_datagrams·reserved)를 둔다 — 반사 트래픽 식별의 핵심.
- **데이터 유출(get/gets/gat)**: 캐시에는 세션 토큰·앱 데이터가 평문으로
  들어있다. 무인증 ``get <key>`` 한 번으로 유출된다.
- **캐시 오염/주입(set/add/replace/append/prepend/cas)**: 저장 명령으로
  악성 값을 심어 애플리케이션 로직을 변조한다.
- **증거 파괴·DoS(flush_all)**: 캐시 전체 무효화 — 흔적 지우기·서비스 방해.
- **정찰(stats/version)**: ``stats`` 계열은 슬랩·아이템·연결 정보를 흘리고
  (증폭의 기반이기도 하다), ``version`` 은 빌드 핑거프린트를 노출한다.

명령 줄 형식(모든 줄 구분은 ``\\r\\n``)::

    set <key> <flags> <exptime> <bytes> [noreply]\\r\\n<data>\\r\\n
    get <key1> [<key2> ...]\\r\\n
    delete <key> [noreply]\\r\\n
    incr|decr <key> <value> [noreply]\\r\\n
    stats [<arg>]\\r\\n
    flush_all [<delay>] [noreply]\\r\\n
    version\\r\\n   /   quit\\r\\n

설계 원칙(:mod:`forensiclab.redis` 와 동일):
- 부작용 없음: 디스크/표준출력/네트워크 없이 순수 함수.
- stdlib 전용: 외부 의존성 없음.
- 안전: 입력 바이트를 변형하지 않는다(읽기 전용).
- 견고: 알려진 동사로 시작하지 않으면(오탐) 예외 대신 ``None``. 저장
  명령의 데이터 블록이 잘려 있으면 가용 바이트까지만 채운다.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import List, Optional, Tuple

__all__ = [
    "MEMCACHED_PORTS",
    "MemcachedFrame",
    "MemcachedCommand",
    "parse_memcached_command",
]

# memcached 관용 TCP/UDP 포트. 식별 보조용일 뿐, 파싱은 페이로드 형식으로 판별한다.
MEMCACHED_PORTS = (11211,)

# 알려진 명령 동사. 오탐 방지의 핵심 — 임의 바이너리가 텍스트처럼 보여도
# 이 집합에 없으면 memcached 명령으로 보지 않는다.
_STORAGE_VERBS = frozenset({"set", "add", "replace", "append", "prepend", "cas"})
_RETRIEVAL_VERBS = frozenset({"get", "gets", "gat", "gats"})
_KNOWN_VERBS = _STORAGE_VERBS | _RETRIEVAL_VERBS | frozenset({
    "delete", "incr", "decr", "touch",
    "stats", "flush_all", "version", "verbosity", "quit",
})

# UDP 프레임 헤더 길이(request_id·sequence_number·total_datagrams·reserved).
_UDP_FRAME_LEN = 8

# 합리적 상한(폭주 방지). 한 줄 명령이 이보다 길면 거부.
_MAX_LINE = 64 * 1024


@dataclass(frozen=True)
class MemcachedFrame:
    """UDP 데이터그램 앞 8바이트 프레임 헤더(반사·증폭 DDoS 식별용).

    Attributes:
        request_id: 클라이언트가 응답을 짝짓는 식별자.
        sequence_number: 이 데이터그램의 순번(0-base).
        total_datagrams: 이 요청 응답을 이루는 데이터그램 총수.
        reserved: 예약 필드(항상 0이어야 함).
    """

    request_id: int
    sequence_number: int
    total_datagrams: int
    reserved: int


@dataclass(frozen=True)
class MemcachedCommand:
    """파싱된 memcached 텍스트 명령(클라이언트→서버 한 개 명령).

    Attributes:
        verb: 소문자화한 명령 이름(예 ``"get"``·``"flush_all"``).
        args: 동사 뒤 토큰들(공백 분리).
        data: 저장 명령의 데이터 블록(있으면). 잘려 있으면 가용 바이트까지만.
        frame: UDP 프레임 헤더(UDP 데이터그램이면). TCP 면 ``None``.
    """

    verb: str
    args: List[str]
    data: Optional[bytes]
    frame: Optional[MemcachedFrame]

    @property
    def is_udp(self) -> bool:
        """UDP 데이터그램(반사·증폭 매개)에서 파싱됐는가."""
        return self.frame is not None

    @property
    def keys(self) -> List[str]:
        """명령 대상 키 목록. 조회 명령은 다중 키, 그 외는 첫 인자 한 개."""
        if self.verb in _RETRIEVAL_VERBS:
            # gat/gats 는 첫 인자가 exptime, 그 뒤가 키들.
            if self.verb in ("gat", "gats"):
                return self.args[1:]
            return list(self.args)
        if self.args:
            return [self.args[0]]
        return []

    @property
    def is_storage(self) -> bool:
        """저장 명령(캐시 오염/주입 벡터)인가."""
        return self.verb in _STORAGE_VERBS

    @property
    def is_retrieval(self) -> bool:
        """조회 명령(데이터 유출 벡터)인가."""
        return self.verb in _RETRIEVAL_VERBS

    @property
    def is_destructive(self) -> bool:
        """``flush_all`` — 캐시 전체 무효화(증거 파괴·DoS) 정황인가."""
        return self.verb == "flush_all"

    @property
    def is_stats(self) -> bool:
        """``stats`` — 정찰·UDP 증폭의 기반 질의인가."""
        return self.verb == "stats"

    @property
    def is_amplification_probe(self) -> bool:
        """UDP 로 도착한 ``stats``/``get`` — 반사·증폭 DDoS 탐침 정황인가."""
        return self.is_udp and self.verb in ("stats", "get", "gets")

    @property
    def bytes_declared(self) -> Optional[int]:
        """저장 명령이 선언한 데이터 바이트 수(``<bytes>``). 아니면 ``None``."""
        if self.verb in _STORAGE_VERBS and len(self.args) >= 4:
            try:
                return int(self.args[3])
            except ValueError:
                return None
        return None

    @property
    def noreply(self) -> bool:
        """마지막 인자가 ``noreply`` 인가(응답 억제 — UDP 증폭과 무관한 자동화 단서)."""
        return bool(self.args) and self.args[-1] == "noreply"


def _try_udp_frame(data: bytes, offset: int) -> Tuple[Optional[MemcachedFrame], int]:
    """offset 에 UDP 프레임 헤더가 있으면 (frame, 본문오프셋) 반환.

    오탐 방지: 헤더 뒤 토큰이 알려진 동사일 때만 프레임으로 인정한다. 헤더
    없이 곧장 텍스트면 (None, offset).
    """
    if offset + _UDP_FRAME_LEN > len(data):
        return None, offset
    head_verb = _peek_verb(data, offset)
    if head_verb in _KNOWN_VERBS:
        return None, offset  # 이미 동사로 시작 → UDP 헤더 없음(TCP)
    req, seq, total, reserved = struct.unpack(">HHHH", data[offset:offset + _UDP_FRAME_LEN])
    if reserved != 0:
        return None, offset
    body = offset + _UDP_FRAME_LEN
    if _peek_verb(data, body) not in _KNOWN_VERBS:
        return None, offset  # 헤더 뒤가 동사가 아니면 프레임 아님
    return MemcachedFrame(req, seq, total, reserved), body


def _peek_verb(data: bytes, offset: int) -> Optional[str]:
    """offset 에서 첫 토큰(동사 후보)을 소문자로 들여다본다."""
    end = offset
    limit = min(len(data), offset + 20)
    while end < limit and data[end:end + 1] not in (b" ", b"\r", b"\n"):
        end += 1
    if end == offset:
        return None
    return data[offset:end].decode("ascii", "replace").lower()


def parse_memcached_command(data: bytes, offset: int = 0) -> Optional[MemcachedCommand]:
    """원시 바이트에서 memcached 텍스트 명령 하나를 파싱한다.

    Args:
        data: memcached 흐름 바이트. 보통 클라이언트→서버 TCP 페이로드의 선두,
            또는 UDP 데이터그램(8바이트 프레임 헤더 포함) 전체다.
        offset: 데이터가 시작하는 위치(기본 0).

    Returns:
        :class:`MemcachedCommand`. UDP 프레임 헤더는 자동 감지한다. 첫 토큰이
        알려진 동사가 아니거나(오탐), 줄이 비정상적으로 길면 ``None``. 저장
        명령의 데이터 블록이 잘려 있으면 가용 바이트까지만 채운다.
    """
    if not data or offset < 0 or offset >= len(data):
        return None

    frame, body = _try_udp_frame(data, offset)

    nl = data.find(b"\n", body)
    line_end = nl if nl != -1 else len(data)
    if line_end - body > _MAX_LINE:
        return None
    line = data[body:line_end].rstrip(b"\r")
    tokens = line.split()
    if not tokens:
        return None

    verb = tokens[0].decode("ascii", "replace").lower()
    if verb not in _KNOWN_VERBS:
        return None
    args = [t.decode("utf-8", "replace") for t in tokens[1:]]

    data_block: Optional[bytes] = None
    if verb in _STORAGE_VERBS and len(tokens) >= 5 and nl != -1:
        try:
            nbytes = int(tokens[4])
        except ValueError:
            nbytes = -1
        if nbytes >= 0:
            start = nl + 1
            end = start + nbytes
            data_block = data[start:min(end, len(data))]  # 잘리면 가용분까지

    return MemcachedCommand(verb=verb, args=args, data=data_block, frame=frame)
