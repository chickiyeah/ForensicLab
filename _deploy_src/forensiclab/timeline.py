"""포렌식 타임라인 재구성 코어.

서로 다른 출처(로그·EXIF 촬영시각·파일 MAC 타임 등)에서 뽑은 시각 있는
사건들을 하나의 시간순 타임라인으로 합치는 것은 포렌식 분석의 기본 작업이다.
이 모듈은 그 사건들을 :class:`Event` 로 표현하고, 정렬·구간 필터·출처별
묶음 같은 순수 연산을 제공한다.

:mod:`forensiclab.logparse` 가 한 로그 줄을 파싱하고
:mod:`forensiclab.exif` 가 촬영 시각을 뽑는다면, 이 모듈은 그렇게 얻은
서로 다른 사건들을 시간축 위에 모은다.

제공 기능:
- :func:`build_timeline` — 사건들을 시각 오름차순으로 안정 정렬.
- :func:`filter_range` — 주어진 [시작, 끝] 구간에 드는 사건만 추림.
- :func:`group_by_source` — 출처별로 사건을 묶음(원래 순서 유지).
- :func:`time_span` — 사건들이 걸친 (가장 이른, 가장 늦은) 시각.

설계 원칙(:mod:`forensiclab.entropy`·:mod:`forensiclab.logparse` 와 동일):
- 부작용 없음: 디스크 쓰기/표준출력 없이 순수 함수로 동작 (테스트 용이).
- stdlib 전용: 외부 의존성 없음.
- 안전: 입력 목록·사건을 변형하지 않는다(읽기 전용, 새 목록 반환).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Iterable, Mapping

__all__ = [
    "Event",
    "build_timeline",
    "filter_range",
    "group_by_source",
    "time_span",
]


@dataclass(frozen=True)
class Event:
    """타임라인 위의 시각 있는 사건 하나.

    Attributes:
        timestamp: 사건 발생 시각.
        source: 사건 출처 라벨 (예: ``"apache"``, ``"exif"``, ``"mft"``).
        description: 사람이 읽을 사건 설명.
        data: 부가 메타데이터(원본 필드 등). 기본은 빈 매핑.
    """

    timestamp: datetime
    source: str
    description: str = ""
    data: Mapping[str, object] = field(default_factory=dict)


def build_timeline(events: Iterable[Event]) -> list[Event]:
    """사건들을 발생 시각 오름차순으로 안정 정렬한다.

    같은 시각의 사건들은 입력에서의 상대 순서를 그대로 유지한다(안정 정렬).
    원본 입력은 변형하지 않고 새 리스트를 돌려준다.

    Args:
        events: 정렬할 :class:`Event` 들.

    Returns:
        시각 오름차순으로 정렬된 새 :class:`Event` 리스트.
    """
    return sorted(events, key=lambda e: e.timestamp)


def filter_range(
    events: Iterable[Event],
    start: datetime | None = None,
    end: datetime | None = None,
) -> list[Event]:
    """[start, end] 구간(양 끝 포함)에 드는 사건만 추린다.

    경계값을 ``None`` 으로 두면 그 쪽은 열린 구간으로 본다
    (``start=None`` 이면 끝 이전 전부, ``end=None`` 이면 시작 이후 전부).

    Args:
        events: 대상 :class:`Event` 들.
        start: 포함 하한 시각. ``None`` 이면 하한 없음.
        end: 포함 상한 시각. ``None`` 이면 상한 없음.

    Returns:
        구간에 드는 사건만 담은 새 리스트(입력 순서 유지).

    Raises:
        ValueError: ``start`` 와 ``end`` 가 둘 다 주어졌고 ``start > end`` 일 때.
    """
    if start is not None and end is not None and start > end:
        raise ValueError(f"start({start}) 가 end({end}) 보다 늦습니다")
    result: list[Event] = []
    for event in events:
        if start is not None and event.timestamp < start:
            continue
        if end is not None and event.timestamp > end:
            continue
        result.append(event)
    return result


def group_by_source(events: Iterable[Event]) -> dict[str, list[Event]]:
    """사건을 출처(:attr:`Event.source`) 별로 묶는다.

    각 출처 안에서는 입력에서 나타난 순서를 그대로 유지한다.
    출처 키의 순서는 처음 등장한 순서(삽입 순서)를 따른다.

    Args:
        events: 대상 :class:`Event` 들.

    Returns:
        출처 라벨 → 그 출처의 사건 리스트. 빈 입력은 빈 dict.
    """
    grouped: dict[str, list[Event]] = {}
    for event in events:
        grouped.setdefault(event.source, []).append(event)
    return grouped


def time_span(events: Iterable[Event]) -> tuple[datetime, datetime] | None:
    """사건들이 걸친 (가장 이른, 가장 늦은) 시각을 구한다.

    Args:
        events: 대상 :class:`Event` 들.

    Returns:
        ``(earliest, latest)`` 튜플. 사건이 하나도 없으면 ``None``.
        사건이 하나면 두 값이 같다.
    """
    timestamps = [event.timestamp for event in events]
    if not timestamps:
        return None
    return (min(timestamps), max(timestamps))
