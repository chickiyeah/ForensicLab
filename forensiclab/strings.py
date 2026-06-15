"""바이너리에서 사람이 읽을 문자열 추출 코어.

``/tools/strings`` 도구의 절차적 로직을 일반화한 모듈이다. 바이트 버퍼에서
연속된 출력 가능 문자(ASCII 및 UTF-16LE 의사 "유니코드") 시퀀스를 찾아
:class:`ExtractedString` 목록으로 돌려준다. classic ``strings(1)`` 의
부분집합에 해당한다.

설계 원칙(:mod:`forensiclab.carving`·:mod:`forensiclab.mbr` 과 동일):
- 부작용 없음: 디스크 쓰기/표준출력 없이 순수 함수로 동작 (테스트 용이).
- stdlib 전용: 외부 의존성 없음.
- 안전: 입력 버퍼를 변형하지 않는다(읽기 전용).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterator

__all__ = [
    "DEFAULT_MIN_LENGTH",
    "ExtractedString",
    "extract_ascii",
    "extract_utf16le",
    "extract_strings",
    "filter_by_keyword",
]

# strings(1) 기본값과 동일하게 최소 4자 이상 시퀀스만 문자열로 본다.
DEFAULT_MIN_LENGTH = 4

# 출력 가능한 ASCII 범위: 공백(0x20)~물결표(0x7E) + 탭(0x09).
_PRINTABLE = frozenset(range(0x20, 0x7F)) | {0x09}


@dataclass(frozen=True)
class ExtractedString:
    """버퍼에서 추출한 문자열 하나.

    Attributes:
        offset: 버퍼 내 시작 바이트 오프셋.
        encoding: ``"ascii"`` 또는 ``"utf-16le"``.
        text: 디코딩된 문자열(끝 NUL/제어문자 제외).
    """

    offset: int
    encoding: str
    text: str

    def __len__(self) -> int:
        return len(self.text)


def _runs(data: bytes, min_length: int) -> Iterator[tuple[int, str]]:
    """``data`` 에서 출력 가능 바이트의 연속 구간을 (오프셋, 문자열)로 생성."""
    start = -1
    for i, b in enumerate(data):
        if b in _PRINTABLE:
            if start == -1:
                start = i
        else:
            if start != -1 and i - start >= min_length:
                yield start, data[start:i].decode("ascii")
            start = -1
    if start != -1 and len(data) - start >= min_length:
        yield start, data[start:].decode("ascii")


def extract_ascii(
    data: bytes, min_length: int = DEFAULT_MIN_LENGTH
) -> list[ExtractedString]:
    """버퍼에서 ASCII 출력 가능 문자열을 추출한다.

    Args:
        data: 대상 바이트.
        min_length: 이 길이 이상인 연속 구간만 결과에 포함(1 이상).

    Returns:
        오프셋 오름차순 :class:`ExtractedString` 목록.

    Raises:
        ValueError: ``min_length`` 가 1 미만일 때.
    """
    if min_length < 1:
        raise ValueError(f"min_length 는 1 이상이어야 합니다 (받은 값: {min_length})")
    return [
        ExtractedString(offset=off, encoding="ascii", text=text)
        for off, text in _runs(data, min_length)
    ]


def extract_utf16le(
    data: bytes, min_length: int = DEFAULT_MIN_LENGTH
) -> list[ExtractedString]:
    """버퍼에서 UTF-16LE(널바이트 끼인) 출력 가능 문자열을 추출한다.

    윈도우 바이너리에서 흔한 ``X\\x00Y\\x00`` 패턴, 즉 ASCII 문자 뒤에
    NUL 이 오는 시퀀스를 한 문자열로 본다.

    Args:
        data: 대상 바이트.
        min_length: 이 길이(문자 수) 이상만 포함(1 이상).

    Returns:
        오프셋 오름차순 :class:`ExtractedString` 목록.

    Raises:
        ValueError: ``min_length`` 가 1 미만일 때.
    """
    if min_length < 1:
        raise ValueError(f"min_length 는 1 이상이어야 합니다 (받은 값: {min_length})")

    results: list[ExtractedString] = []
    chars: list[str] = []
    run_start = -1
    i = 0
    n = len(data)
    while i + 1 < n:
        lo, hi = data[i], data[i + 1]
        if hi == 0x00 and lo in _PRINTABLE:
            if run_start == -1:
                run_start = i
            chars.append(chr(lo))
            i += 2
        else:
            if run_start != -1 and len(chars) >= min_length:
                results.append(
                    ExtractedString(
                        offset=run_start, encoding="utf-16le", text="".join(chars)
                    )
                )
            chars = []
            run_start = -1
            i += 1
    if run_start != -1 and len(chars) >= min_length:
        results.append(
            ExtractedString(offset=run_start, encoding="utf-16le", text="".join(chars))
        )
    return results


def extract_strings(
    data: bytes,
    min_length: int = DEFAULT_MIN_LENGTH,
    *,
    ascii_only: bool = False,
) -> list[ExtractedString]:
    """ASCII 와 UTF-16LE 문자열을 함께 추출해 오프셋순으로 합친다.

    Args:
        data: 대상 바이트.
        min_length: 최소 길이.
        ascii_only: 참이면 UTF-16LE 추출을 건너뛴다.

    Returns:
        오프셋(같으면 ASCII 우선) 오름차순 정렬된 목록.
    """
    results = extract_ascii(data, min_length)
    if not ascii_only:
        results = results + extract_utf16le(data, min_length)
    # ASCII 와 UTF-16LE 는 시작 오프셋이 겹칠 수 없다(UTF-16LE 의 끼인 NUL 이
    # ASCII 연속 구간을 끊으므로). 오프셋만으로 정렬하면 결정적이다.
    results.sort(key=lambda s: s.offset)
    return results


def filter_by_keyword(
    strings: list[ExtractedString], keyword: str, *, case_sensitive: bool = False
) -> list[ExtractedString]:
    """추출 결과에서 키워드를 포함한 문자열만 남긴다.

    Args:
        strings: :func:`extract_strings` 등의 결과.
        keyword: 부분 일치할 검색어.
        case_sensitive: 거짓이면 대소문자 무시(기본).

    Returns:
        조건을 만족하는 부분집합(원본 순서 유지).
    """
    if case_sensitive:
        return [s for s in strings if keyword in s.text]
    needle = keyword.lower()
    return [s for s in strings if needle in s.text.lower()]
