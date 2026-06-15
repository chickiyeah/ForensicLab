"""MBR(마스터 부트 레코드) 파티션 테이블 파싱 코어.

기존 ``anl*.py`` 의 절차적·파괴적(쓰기 포함) MBR 처리 로직 중 **읽기 전용
파싱** 부분만 떼어내 일반화한 모듈이다. 512바이트 부트 섹터를 받아
4개 파티션 엔트리와 부트 시그니처를 데이터 클래스로 돌려준다.

설계 원칙(:mod:`forensiclab.carving`·:mod:`forensiclab.hashing` 과 동일):
- 부작용 없음: 디스크 쓰기 없이 순수 함수로 파싱만 한다 (테스트 용이).
- stdlib 전용: :mod:`struct` 외 외부 의존성 없음.
- 안전: 절대 장치/파일에 쓰지 않는다(복구는 별도 도구의 책임).
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import BinaryIO

__all__ = [
    "SECTOR_SIZE",
    "MBR_SIGNATURE",
    "PARTITION_TYPES",
    "PartitionEntry",
    "MasterBootRecord",
    "parse_mbr",
    "read_mbr",
]

# 표준 섹터 크기(anl.py 와 동일).
SECTOR_SIZE = 512

# MBR 끝 2바이트 부트 시그니처(리틀엔디언으로 0xAA55).
MBR_SIGNATURE = b"\x55\xaa"

# 파티션 테이블은 오프셋 446(0x1BE)에서 시작, 16바이트 엔트리 4개.
_PARTITION_TABLE_OFFSET = 446
_ENTRY_SIZE = 16
_ENTRY_COUNT = 4

# 자주 보이는 파티션 타입 코드 → 사람이 읽을 이름. anl.py 의 FAT32/NTFS 포함.
PARTITION_TYPES: dict[int, str] = {
    0x00: "Empty",
    0x05: "Extended (CHS)",
    0x07: "NTFS / exFAT",
    0x0B: "FAT32 (CHS)",
    0x0C: "FAT32 (LBA)",
    0x0E: "FAT16 (LBA)",
    0x0F: "Extended (LBA)",
    0x82: "Linux swap",
    0x83: "Linux",
    0x8E: "Linux LVM",
    0xA5: "FreeBSD",
    0xAF: "HFS / HFS+",
    0xEE: "GPT protective",
    0xEF: "EFI System",
}


@dataclass(frozen=True)
class PartitionEntry:
    """MBR 파티션 테이블의 16바이트 엔트리 하나.

    Attributes:
        index: 테이블 내 위치(0~3).
        boot_flag: 부트 플래그 바이트(0x80 이면 활성/부팅 가능).
        type_code: 파티션 타입 코드(예: 0x07=NTFS).
        lba_start: 시작 LBA(섹터 단위).
        sector_count: 파티션 크기(섹터 수).
    """

    index: int
    boot_flag: int
    type_code: int
    lba_start: int
    sector_count: int

    @property
    def is_empty(self) -> bool:
        """타입 0x00 이고 크기 0 이면 빈 엔트리로 본다."""
        return self.type_code == 0x00 and self.sector_count == 0

    @property
    def is_bootable(self) -> bool:
        """부트 플래그가 0x80 이면 활성 파티션."""
        return self.boot_flag == 0x80

    @property
    def type_name(self) -> str:
        """타입 코드의 사람이 읽을 이름. 미상이면 ``Unknown (0x..)``."""
        return PARTITION_TYPES.get(self.type_code, f"Unknown (0x{self.type_code:02X})")

    @property
    def byte_offset(self) -> int:
        """시작 LBA 를 바이트 오프셋으로 환산한 값."""
        return self.lba_start * SECTOR_SIZE

    @property
    def byte_size(self) -> int:
        """섹터 수를 바이트 크기로 환산한 값."""
        return self.sector_count * SECTOR_SIZE


@dataclass(frozen=True)
class MasterBootRecord:
    """파싱된 MBR 부트 섹터 한 개."""

    partitions: tuple[PartitionEntry, ...]
    signature: bytes

    @property
    def is_valid(self) -> bool:
        """끝 2바이트가 0x55AA 부트 시그니처인지."""
        return self.signature == MBR_SIGNATURE

    @property
    def used_partitions(self) -> list[PartitionEntry]:
        """비어있지 않은 파티션 엔트리만 추린 목록."""
        return [p for p in self.partitions if not p.is_empty]


def parse_mbr(data: bytes) -> MasterBootRecord:
    """512바이트(이상) 버퍼에서 MBR 파티션 테이블을 파싱한다.

    버퍼 앞 512바이트만 사용하며, 디스크/파일에 쓰지 않는다.

    Args:
        data: MBR 을 포함한 바이트. 최소 512바이트여야 한다.

    Returns:
        파싱된 :class:`MasterBootRecord`.

    Raises:
        ValueError: 버퍼가 512바이트보다 짧을 때.
    """
    if len(data) < SECTOR_SIZE:
        raise ValueError(
            f"MBR 은 최소 {SECTOR_SIZE} 바이트가 필요합니다 (받은 크기: {len(data)})"
        )

    entries: list[PartitionEntry] = []
    for i in range(_ENTRY_COUNT):
        start = _PARTITION_TABLE_OFFSET + i * _ENTRY_SIZE
        chunk = data[start : start + _ENTRY_SIZE]
        # Boot(1) CHS_S(3) Type(1) CHS_E(3) LBA_S(4 LE) Size(4 LE)
        boot_flag, type_code, lba_start, sector_count = struct.unpack(
            "<B3xB3xII", chunk
        )
        entries.append(
            PartitionEntry(
                index=i,
                boot_flag=boot_flag,
                type_code=type_code,
                lba_start=lba_start,
                sector_count=sector_count,
            )
        )

    return MasterBootRecord(
        partitions=tuple(entries),
        signature=bytes(data[510:512]),
    )


def read_mbr(source: str | BinaryIO) -> MasterBootRecord:
    """파일 경로나 열린 이진 스트림에서 첫 512바이트를 읽어 파싱한다.

    경로 문자열을 주면 읽기 전용(``rb``)으로 열고, 스트림을 주면 현재
    위치에서 512바이트를 읽는다. 어느 경우에도 쓰기는 하지 않는다.

    Raises:
        ValueError: 512바이트를 다 읽지 못했을 때.
        FileNotFoundError: 경로가 없을 때.
    """
    if isinstance(source, str):
        with open(source, "rb") as f:
            data = f.read(SECTOR_SIZE)
    else:
        data = source.read(SECTOR_SIZE)
    return parse_mbr(data)
