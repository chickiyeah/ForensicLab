"""바이트 엔트로피(Shannon entropy) 분석 코어.

암호화·압축·패킹된 데이터는 바이트 분포가 균일에 가까워 엔트로피가
8 bit/byte 에 근접한다. 반대로 일반 텍스트·실행 코드는 특정 바이트에
편중되어 엔트로피가 낮다. 이 성질을 이용하면 디스크 이미지·파일에서
암호화/압축 영역을 빠르게 가려낼 수 있다.

제공 기능:
- :func:`byte_histogram` — 256개 바이트 값별 출현 횟수.
- :func:`shannon_entropy` — 버퍼 전체의 Shannon 엔트로피(bit/byte).
- :func:`sliding_entropy` — 슬라이딩 윈도우별 엔트로피(국소 분석).
- :func:`classify_entropy` — 엔트로피 값을 사람이 읽을 분류 라벨로.

설계 원칙(:mod:`forensiclab.strings`·:mod:`forensiclab.mbr` 과 동일):
- 부작용 없음: 디스크 쓰기/표준출력 없이 순수 함수로 동작 (테스트 용이).
- stdlib 전용: 외부 의존성 없음.
- 안전: 입력 버퍼를 변형하지 않는다(읽기 전용).
"""

from __future__ import annotations

import math
from collections import Counter
from dataclasses import dataclass

__all__ = [
    "MAX_ENTROPY",
    "DEFAULT_WINDOW_SIZE",
    "EntropyWindow",
    "byte_histogram",
    "shannon_entropy",
    "sliding_entropy",
    "classify_entropy",
]

# 바이트(8 bit) 한 개가 가질 수 있는 최대 Shannon 엔트로피.
MAX_ENTROPY = 8.0

# 슬라이딩 윈도우 기본 크기(바이트). 256 은 한 섹터(512)의 절반으로
# 작은 입력에도 의미 있는 분포 추정을 주면서 가볍다.
DEFAULT_WINDOW_SIZE = 256


@dataclass(frozen=True)
class EntropyWindow:
    """슬라이딩 윈도우 한 구간의 엔트로피 측정 결과.

    Attributes:
        offset: 버퍼 내 윈도우 시작 바이트 오프셋.
        size: 윈도우에 포함된 실제 바이트 수.
        entropy: 해당 구간의 Shannon 엔트로피(0.0~8.0 bit/byte).
    """

    offset: int
    size: int
    entropy: float


def byte_histogram(data: bytes) -> list[int]:
    """버퍼의 바이트 값(0~255)별 출현 횟수를 센다.

    Args:
        data: 대상 바이트.

    Returns:
        길이 256 의 리스트. 인덱스 ``i`` 는 바이트 값 ``i`` 의 출현 횟수.
    """
    counts = Counter(data)
    return [counts.get(i, 0) for i in range(256)]


def shannon_entropy(data: bytes) -> float:
    """버퍼의 Shannon 엔트로피를 bit/byte 단위로 계산한다.

    공식: ``H = -Σ p(b) · log2 p(b)`` (b 는 등장한 각 바이트 값).
    결과 범위는 0.0(단일 바이트만 반복) ~ 8.0(완전 균일).

    Args:
        data: 대상 바이트.

    Returns:
        엔트로피 값. 빈 버퍼는 0.0.
    """
    n = len(data)
    if n == 0:
        return 0.0
    entropy = 0.0
    for count in Counter(data).values():
        p = count / n
        entropy -= p * math.log2(p)
    return entropy


def sliding_entropy(
    data: bytes,
    window_size: int = DEFAULT_WINDOW_SIZE,
    step: int | None = None,
) -> list[EntropyWindow]:
    """버퍼를 슬라이딩 윈도우로 훑으며 국소 엔트로피를 측정한다.

    전체 엔트로피는 암호화 영역과 텍스트 영역이 섞이면 평균값으로 가려진다.
    윈도우별로 보면 "여기부터 어디까지가 고엔트로피 구간"인지 드러난다.

    Args:
        data: 대상 바이트.
        window_size: 윈도우 크기(바이트, 1 이상).
        step: 윈도우 이동 간격(바이트, 1 이상). ``None`` 이면
            ``window_size`` 와 같게 두어 겹치지 않는 블록으로 나눈다.

    Returns:
        오프셋 오름차순 :class:`EntropyWindow` 목록. 빈 버퍼는 빈 목록.
        마지막 윈도우는 버퍼 끝까지의 잔여 바이트만 포함할 수 있다.

    Raises:
        ValueError: ``window_size`` 나 ``step`` 이 1 미만일 때.
    """
    if window_size < 1:
        raise ValueError(f"window_size 는 1 이상이어야 합니다 (받은 값: {window_size})")
    if step is None:
        step = window_size
    if step < 1:
        raise ValueError(f"step 은 1 이상이어야 합니다 (받은 값: {step})")

    n = len(data)
    windows: list[EntropyWindow] = []
    offset = 0
    while offset < n:
        chunk = data[offset : offset + window_size]
        windows.append(
            EntropyWindow(
                offset=offset,
                size=len(chunk),
                entropy=shannon_entropy(chunk),
            )
        )
        offset += step
    return windows


def classify_entropy(entropy: float) -> str:
    """엔트로피 값을 사람이 읽을 분류 라벨로 변환한다.

    경계값은 일반적인 포렌식 휴리스틱을 따른다(절대 기준 아님, 참고용):
    7.5 이상은 암호화/압축으로 의심하는 통상적 임계값이다.

    Args:
        entropy: :func:`shannon_entropy` 등이 돌려준 0.0~8.0 값.

    Returns:
        분류 라벨 문자열.

    Raises:
        ValueError: 값이 0.0~8.0 범위를 벗어날 때.
    """
    if not 0.0 <= entropy <= MAX_ENTROPY:
        raise ValueError(f"entropy 는 0.0~8.0 범위여야 합니다 (받은 값: {entropy})")
    if entropy >= 7.5:
        return "암호화/압축 가능성 높음"
    if entropy >= 6.0:
        return "고엔트로피(압축 데이터·미디어 등)"
    if entropy >= 4.0:
        return "보통(실행 코드·구조화 데이터 등)"
    if entropy >= 1.0:
        return "저엔트로피(텍스트·반복 패턴 등)"
    return "매우 낮음(단조 데이터·패딩 등)"
