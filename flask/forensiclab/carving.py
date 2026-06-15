"""시그니처 기반 파일 카빙 코어.

기존 ``web/crawfile.py`` 의 GIF 전용·절차적 카빙 로직을 일반화한 모듈이다.
파일 시그니처(헤더/푸터)를 데이터 클래스로 선언하고, 바이트 버퍼에서
연속 매칭을 찾아 :class:`CarvedFile` 목록으로 돌려준다.

설계 원칙:
- 부작용 없음: 디스크 쓰기/표준출력 없이 순수 함수로 동작 (테스트 용이).
- stdlib 전용: 외부 의존성 없음.
- 확장 가능: :data:`DEFAULT_SIGNATURES` 에 항목을 추가하면 새 포맷 지원.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, Sequence

__all__ = [
    "FileSignature",
    "CarvedFile",
    "DEFAULT_SIGNATURES",
    "carve_buffer",
]


@dataclass(frozen=True)
class FileSignature:
    """카빙 대상 파일 포맷의 시그니처 정의.

    Attributes:
        name: 포맷 이름 (예: ``"gif"``).
        extension: 추출 파일 확장자 (점 제외, 예: ``"gif"``).
        headers: 파일 시작을 나타내는 매직 바이트 후보들. 여러 변형
            (예: GIF87a/GIF89a)을 허용한다.
        footer: 파일 끝 마커. ``None`` 이면 ``max_size`` 만큼 고정 추출한다.
        footer_extra: 푸터 매치 위치 이후 추가로 포함할 바이트 수.
            결과 크기는 ``footer_idx + len(footer) + footer_extra`` 까지다.
        max_size: 푸터를 못 찾거나 푸터가 없을 때 헤더에서부터 잘라낼
            최대 바이트 수. ``None`` 이면 푸터가 없는 헤더는 건너뛴다.
    """

    name: str
    extension: str
    headers: Sequence[bytes]
    footer: bytes | None = None
    footer_extra: int = 0
    max_size: int | None = None

    def __post_init__(self) -> None:
        if not self.headers:
            raise ValueError(f"signature {self.name!r} must have at least one header")
        if self.footer is None and self.max_size is None:
            raise ValueError(
                f"signature {self.name!r} needs a footer or a max_size to bound carving"
            )


@dataclass(frozen=True)
class CarvedFile:
    """카빙으로 복구한 단일 파일."""

    name: str
    extension: str
    offset: int
    size: int
    data: bytes = field(repr=False)

    @property
    def sector(self) -> int:
        """512바이트 섹터 기준 시작 섹터 번호."""
        return self.offset // 512

    def suggested_filename(self, index: int) -> str:
        return f"recovered_{index}.{self.extension}"


# 흔한 파일 포맷 시그니처. crawfile.py(GIF) 외 JPEG/PNG/PDF/ZIP 확장.
DEFAULT_SIGNATURES: tuple[FileSignature, ...] = (
    FileSignature(
        name="gif",
        extension="gif",
        headers=(b"GIF89a", b"GIF87a"),
        footer=b"\x00\x3b",
    ),
    FileSignature(
        name="jpeg",
        extension="jpg",
        headers=(b"\xff\xd8\xff",),
        footer=b"\xff\xd9",
    ),
    FileSignature(
        name="png",
        extension="png",
        headers=(b"\x89PNG\r\n\x1a\n",),
        footer=b"\x49\x45\x4e\x44\xae\x42\x60\x82",  # IEND + CRC
    ),
    FileSignature(
        name="pdf",
        extension="pdf",
        headers=(b"%PDF",),
        footer=b"%%EOF",
    ),
    FileSignature(
        name="zip",
        extension="zip",
        headers=(b"PK\x03\x04",),
        footer=b"PK\x05\x06",  # End Of Central Directory
        footer_extra=18,  # EOCD 레코드 최소 길이(22) - len(footer)(4)
    ),
)


def _first_header(data: bytes, headers: Iterable[bytes], start: int) -> tuple[int, bytes | None]:
    """``start`` 이후 가장 먼저 등장하는 헤더의 (위치, 헤더) 반환. 없으면 (-1, None)."""
    best_idx = -1
    best_header: bytes | None = None
    for header in headers:
        idx = data.find(header, start)
        if idx != -1 and (best_idx == -1 or idx < best_idx):
            best_idx = idx
            best_header = header
    return best_idx, best_header


def carve_buffer(
    data: bytes,
    signatures: Sequence[FileSignature] = DEFAULT_SIGNATURES,
) -> list[CarvedFile]:
    """바이트 버퍼에서 시그니처에 맞는 파일들을 카빙한다.

    각 시그니처를 독립적으로 스캔하며, 헤더 발견 → (있으면) 헤더 이후
    가장 가까운 푸터까지 추출한다. 푸터를 못 찾으면 ``max_size`` 로 자르고,
    그것도 없으면 해당 매치를 건너뛴다.

    Args:
        data: 카빙 대상 원본 바이트.
        signatures: 사용할 시그니처 목록. 기본값은 :data:`DEFAULT_SIGNATURES`.

    Returns:
        오프셋 오름차순으로 정렬된 :class:`CarvedFile` 목록.
    """
    results: list[CarvedFile] = []

    for sig in signatures:
        start = 0
        while True:
            header_idx, header = _first_header(data, sig.headers, start)
            if header_idx == -1 or header is None:
                break

            end: int | None = None
            if sig.footer is not None:
                footer_idx = data.find(sig.footer, header_idx + len(header))
                if footer_idx != -1:
                    end = footer_idx + len(sig.footer) + sig.footer_extra

            if end is None and sig.max_size is not None:
                end = header_idx + sig.max_size

            if end is None:
                # 푸터도 max_size도 못 정함 → 깨진 헤더로 보고 다음으로.
                start = header_idx + len(header)
                continue

            end = min(end, len(data))
            chunk = data[header_idx:end]
            results.append(
                CarvedFile(
                    name=sig.name,
                    extension=sig.extension,
                    offset=header_idx,
                    size=len(chunk),
                    data=chunk,
                )
            )
            start = end if end > header_idx else header_idx + len(header)

    results.sort(key=lambda c: c.offset)
    return results
