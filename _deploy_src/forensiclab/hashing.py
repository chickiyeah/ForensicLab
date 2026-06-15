"""파일/바이트 해시 계산·검증 코어.

기존 ``0316.py`` 의 단일 알고리즘·대화형 해시 스크립트를 일반화한 모듈이다.
여러 알고리즘을 한 번의 스트림 통과로 계산하고, 기대값과 대소문자 무관하게
비교하는 순수 함수를 제공한다.

설계 원칙(:mod:`forensiclab.carving` 과 동일):
- 부작용 최소화: 표준출력/입력 없이 값만 돌려준다 (테스트 용이).
- stdlib 전용: :mod:`hashlib` 외 외부 의존성 없음.
- 확장 가능: :data:`DEFAULT_ALGORITHMS` 에 항목을 추가하면 기본 출력 확장.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import BinaryIO, Iterable, Sequence

__all__ = [
    "DEFAULT_ALGORITHMS",
    "HashResult",
    "hash_bytes",
    "hash_stream",
    "hash_file",
    "compare_hash",
]

# 포렌식 해시 검증에서 흔히 쓰는 알고리즘(0316.py 와 동일 집합).
DEFAULT_ALGORITHMS: tuple[str, ...] = ("md5", "sha1", "sha256", "sha512")

# 한 번에 읽을 청크 크기(0316.py 의 4096 을 계승, 약간 키움).
_CHUNK_SIZE = 1 << 16  # 64 KiB


@dataclass(frozen=True)
class HashResult:
    """하나 이상의 알고리즘으로 계산한 해시 묶음.

    Attributes:
        digests: ``{알고리즘명: 16진수 소문자 해시}`` 매핑.
        size: 해시 대상 총 바이트 수.
    """

    digests: dict[str, str]
    size: int

    def __getitem__(self, algorithm: str) -> str:
        return self.digests[algorithm.lower()]

    def matches(self, expected: str, algorithm: str | None = None) -> bool:
        """``expected`` 가 계산된 해시 중 하나와 (대소문자 무관) 일치하는지.

        ``algorithm`` 을 주면 해당 알고리즘과만 비교하고, 생략하면 계산된
        모든 해시와 비교해 하나라도 맞으면 ``True`` (알고리즘 미상 입력 대비).
        """
        if algorithm is not None:
            return compare_hash(self.digests.get(algorithm.lower(), ""), expected)
        return any(compare_hash(d, expected) for d in self.digests.values())


def _normalize_algorithms(algorithms: Iterable[str]) -> list[str]:
    """알고리즘 이름을 소문자로 정규화하고 순서를 유지하며 중복 제거·검증."""
    seen: dict[str, None] = {}
    for name in algorithms:
        key = name.lower()
        if key not in seen:
            try:
                hashlib.new(key)
            except (ValueError, TypeError) as exc:
                raise ValueError(f"지원하지 않는 알고리즘: {name!r}") from exc
            seen[key] = None
    if not seen:
        raise ValueError("최소 한 개의 알고리즘이 필요합니다")
    return list(seen)


def hash_stream(
    stream: BinaryIO,
    algorithms: Sequence[str] = DEFAULT_ALGORITHMS,
) -> HashResult:
    """이진 스트림을 청크 단위로 읽어 여러 해시를 한 번에 계산한다.

    스트림을 한 번만 통과하므로 대용량 파일에도 메모리 효율적이다.
    """
    names = _normalize_algorithms(algorithms)
    hashers = {name: hashlib.new(name) for name in names}
    total = 0
    while chunk := stream.read(_CHUNK_SIZE):
        total += len(chunk)
        for h in hashers.values():
            h.update(chunk)
    return HashResult(
        digests={name: h.hexdigest() for name, h in hashers.items()},
        size=total,
    )


def hash_bytes(
    data: bytes,
    algorithms: Sequence[str] = DEFAULT_ALGORITHMS,
) -> HashResult:
    """바이트 버퍼의 해시를 계산한다(순수 함수)."""
    names = _normalize_algorithms(algorithms)
    digests = {name: hashlib.new(name, data).hexdigest() for name in names}
    return HashResult(digests=digests, size=len(data))


def hash_file(
    path: str,
    algorithms: Sequence[str] = DEFAULT_ALGORITHMS,
) -> HashResult:
    """파일 경로를 읽어 해시를 계산한다.

    Raises:
        FileNotFoundError: 파일이 없을 때.
        ValueError: 지원하지 않는 알고리즘일 때.
    """
    with open(path, "rb") as f:
        return hash_stream(f, algorithms)


def compare_hash(actual: str, expected: str) -> bool:
    """두 16진수 해시 문자열을 공백·대소문자 무관하게 비교한다.

    빈 문자열끼리는 일치로 보지 않는다(미계산/미입력 오판 방지).
    """
    a = actual.strip().lower()
    b = expected.strip().lower()
    if not a or not b:
        return False
    return a == b
