"""매직 바이트 기반 파일 타입 식별 코어.

:mod:`forensiclab.carving` 이 버퍼 *어디서나* 파일 시그니처를 찾아 추출하는
것과 달리, 이 모듈은 "이 파일은 *무엇인가*" 를 파일 머리(또는 지정 오프셋)의
매직 바이트로 판별한다. 확장자 위조(예: 실행 파일을 ``.jpg`` 로 둔갑) 탐지 같은
포렌식 작업에 쓰인다.

제공 기능:
- :func:`identify` — 버퍼와 가장 잘 맞는 단일 타입(가장 구체적인 매치).
- :func:`identify_all` — 매치되는 모든 타입(중첩 시그니처 진단용).
- :func:`extension_mismatch` — 파일명 확장자와 실제 매직이 어긋나는지 판정.

설계 원칙(:mod:`forensiclab.carving`·:mod:`forensiclab.entropy` 와 동일):
- 부작용 없음: 디스크 쓰기/표준출력 없이 순수 함수로 동작 (테스트 용이).
- stdlib 전용: 외부 의존성 없음.
- 안전: 입력 버퍼를 변형하지 않는다(읽기 전용).
- 확장 가능: :data:`DEFAULT_MAGICS` 에 항목을 추가하면 새 포맷 지원.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Sequence

__all__ = [
    "Magic",
    "DEFAULT_MAGICS",
    "identify",
    "identify_all",
    "extension_mismatch",
]


@dataclass(frozen=True)
class Magic:
    """파일 타입을 식별하는 매직 바이트 정의.

    Attributes:
        name: 포맷 이름 (예: ``"png"``).
        extensions: 이 타입에 흩어진 정상 확장자들(점 제외, 소문자).
            확장자 위조 판정 시 "정상" 집합으로 쓰인다.
        signature: 비교할 매직 바이트.
        offset: ``signature`` 가 위치해야 할 버퍼 내 바이트 오프셋.
        description: 사람이 읽을 설명.
    """

    name: str
    extensions: Sequence[str]
    signature: bytes
    offset: int = 0
    description: str = ""

    def __post_init__(self) -> None:
        if not self.signature:
            raise ValueError(f"magic {self.name!r} must have a non-empty signature")
        if self.offset < 0:
            raise ValueError(f"magic {self.name!r} offset must be >= 0")

    def matches(self, data: bytes) -> bool:
        """``data`` 가 이 매직과 일치하는지 검사한다(읽기 전용)."""
        end = self.offset + len(self.signature)
        if len(data) < end:
            return False
        return data[self.offset : end] == self.signature


# 흔한 파일 포맷의 매직 바이트. carving.DEFAULT_SIGNATURES 와 겹치는 포맷이
# 있으나, 이쪽은 "헤더 식별" 목적이라 오프셋·확장자 집합을 따로 둔다.
DEFAULT_MAGICS: tuple[Magic, ...] = (
    Magic("png", ("png",), b"\x89PNG\r\n\x1a\n", description="PNG 이미지"),
    Magic("jpeg", ("jpg", "jpeg"), b"\xff\xd8\xff", description="JPEG 이미지"),
    Magic("gif", ("gif",), b"GIF89a", description="GIF 이미지 (89a)"),
    Magic("gif", ("gif",), b"GIF87a", description="GIF 이미지 (87a)"),
    Magic("bmp", ("bmp",), b"BM", description="BMP 이미지"),
    Magic("pdf", ("pdf",), b"%PDF", description="PDF 문서"),
    Magic("zip", ("zip", "jar", "apk", "docx", "xlsx", "pptx"),
          b"PK\x03\x04", description="ZIP 계열 컨테이너"),
    Magic("gzip", ("gz",), b"\x1f\x8b", description="GZIP 압축"),
    Magic("rar", ("rar",), b"Rar!\x1a\x07", description="RAR 아카이브"),
    Magic("7z", ("7z",), b"7z\xbc\xaf\x27\x1c", description="7-Zip 아카이브"),
    Magic("elf", ("elf", "so", ""), b"\x7fELF", description="ELF 실행/공유 객체"),
    Magic("pe", ("exe", "dll"), b"MZ", description="Windows PE(MZ) 실행 파일"),
    Magic("class", ("class",), b"\xca\xfe\xba\xbe", description="Java 클래스"),
    Magic("wav", ("wav",), b"RIFF", description="RIFF 컨테이너(WAV/AVI 등)"),
    Magic("mp3", ("mp3",), b"ID3", description="MP3 (ID3 태그)"),
    Magic("png_ico", ("ico",), b"\x00\x00\x01\x00", description="Windows 아이콘"),
    Magic("sqlite", ("sqlite", "db"), b"SQLite format 3\x00",
          description="SQLite 3 데이터베이스"),
)


def identify_all(
    data: bytes,
    magics: Sequence[Magic] = DEFAULT_MAGICS,
) -> list[Magic]:
    """버퍼와 일치하는 모든 매직을 반환한다.

    Args:
        data: 식별 대상 바이트.
        magics: 사용할 매직 목록. 기본값은 :data:`DEFAULT_MAGICS`.

    Returns:
        일치하는 :class:`Magic` 목록. 시그니처가 긴(=더 구체적인) 순으로
        정렬하고, 같으면 오프셋이 작은 순으로 둔다. 일치 없으면 빈 목록.
    """
    hits = [m for m in magics if m.matches(data)]
    hits.sort(key=lambda m: (-len(m.signature), m.offset))
    return hits


def identify(
    data: bytes,
    magics: Sequence[Magic] = DEFAULT_MAGICS,
) -> Magic | None:
    """버퍼와 가장 잘 맞는 단일 매직을 반환한다.

    여러 시그니처가 겹칠 때는 가장 긴(=더 구체적인) 시그니처를 우선한다.
    예를 들어 ``"\\x00\\x00\\x01\\x00"`` 와 더 짧은 후보가 동시에 맞으면
    긴 쪽을 택한다.

    Args:
        data: 식별 대상 바이트.
        magics: 사용할 매직 목록. 기본값은 :data:`DEFAULT_MAGICS`.

    Returns:
        가장 구체적인 :class:`Magic`. 일치 없으면 ``None``.
    """
    hits = identify_all(data, magics)
    return hits[0] if hits else None


def extension_mismatch(
    filename: str,
    data: bytes,
    magics: Sequence[Magic] = DEFAULT_MAGICS,
) -> bool:
    """파일명 확장자가 실제 매직과 어긋나는지(위조 의심) 판정한다.

    확장자 위조 탐지의 보수적 휴리스틱이다. 판단 불가한 경우는 모두
    "어긋나지 않음(False)" 으로 처리해 거짓 양성을 줄인다:

    - 매직을 식별하지 못하면(알 수 없는 타입) ``False``.
    - 파일명에 확장자가 없으면 ``False``.

    식별된 타입의 정상 확장자 집합(:attr:`Magic.extensions`)에 파일명
    확장자가 들어 있지 않을 때만 ``True`` 를 돌려준다.

    Args:
        filename: 검사할 파일명(경로 포함 가능). 확장자만 소문자로 비교.
        data: 파일 내용 바이트.
        magics: 사용할 매직 목록. 기본값은 :data:`DEFAULT_MAGICS`.

    Returns:
        확장자와 실제 타입이 어긋나면 ``True``, 아니면 ``False``.
    """
    magic = identify(data, magics)
    if magic is None:
        return False
    ext = os.path.splitext(filename)[1].lstrip(".").lower()
    if not ext:
        return False
    return ext not in {e.lower() for e in magic.extensions}
