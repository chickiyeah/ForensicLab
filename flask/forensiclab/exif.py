"""JPEG EXIF GPS 좌표 추출 코어 (순수 stdlib).

``/tools/gps`` 도구는 EXIF GPS 태그에서 위·경도를 뽑아 지도에 표시한다.
그 핵심 절차(JPEG APP1 세그먼트 → TIFF/IFD 파싱 → GPS IFD → DMS 유리수를
십진수 도(degree)로 환산)를 외부 의존성(Pillow 등) 없이 일반화한 모듈이다.

설계 원칙(:mod:`forensiclab.logparse`·:mod:`forensiclab.strings` 과 동일):
- 부작용 없음: 디스크 쓰기/표준출력 없이 순수 함수로 동작 (테스트 용이).
- stdlib 전용: :mod:`struct` 외 외부 의존성 없음.
- 안전: 입력 버퍼를 변형하지 않으며(읽기 전용), 파싱 실패는 예외 대신
  ``None`` 으로 보고한다.

GPS 외에 :func:`extract_metadata` 는 같은 IFD 파서를 재사용해 카메라/촬영
설정(제조사·기종·노출·조리개·ISO·초점거리 등)을 ``/tools/metadata`` 용으로
모은다. 지원 범위는 EXIF IFD0/SubIFD 와 GPS IFD 의 대표 태그 부분집합이며,
고도·메이커노트 등은 다루지 않는다.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

__all__ = [
    "GpsCoordinate",
    "CameraMetadata",
    "find_exif_tiff",
    "extract_gps",
    "extract_metadata",
    "dms_to_decimal",
]

# TIFF 필드 타입 코드 → 단위 바이트 크기 (EXIF 에서 쓰이는 부분집합).
_TYPE_SIZE = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 7: 1, 9: 4, 10: 8}

# IFD0 안에서 GPS IFD 의 시작 오프셋을 가리키는 포인터 태그.
_GPS_IFD_TAG = 0x8825

# IFD0 안에서 Exif SubIFD(촬영 설정) 의 시작 오프셋을 가리키는 포인터 태그.
_EXIF_IFD_TAG = 0x8769

# GPS IFD 내부 태그 번호.
_GPS_LAT_REF, _GPS_LAT = 1, 2
_GPS_LON_REF, _GPS_LON = 3, 4

# IFD0 의 카메라/소프트웨어 태그.
_TAG_MAKE = 0x010F
_TAG_MODEL = 0x0110
_TAG_ORIENTATION = 0x0112
_TAG_SOFTWARE = 0x0131
_TAG_DATETIME = 0x0132

# Exif SubIFD 의 촬영 설정 태그.
_TAG_EXPOSURE_TIME = 0x829A
_TAG_F_NUMBER = 0x829D
_TAG_ISO = 0x8827
_TAG_DATETIME_ORIGINAL = 0x9003
_TAG_FOCAL_LENGTH = 0x920A
_TAG_LENS_MODEL = 0xA434


@dataclass(frozen=True)
class GpsCoordinate:
    """EXIF 에서 환산한 십진수 위·경도.

    Attributes:
        latitude: 북위 양수, 남위 음수 (십진수 도).
        longitude: 동경 양수, 서경 음수 (십진수 도).
    """

    latitude: float
    longitude: float


@dataclass(frozen=True)
class CameraMetadata:
    """EXIF 에서 뽑은 카메라/촬영 설정 메타데이터.

    모든 필드는 선택적이다. 해당 태그가 없으면 ``None`` 으로 남는다.

    Attributes:
        make: 제조사 (예: ``Apple``).
        model: 기종 (예: ``iPhone 12``).
        orientation: TIFF 방향 코드 (1~8).
        software: 처리/저장 소프트웨어 문자열.
        datetime_original: 촬영 일시(없으면 IFD0 DateTime 대체).
        exposure_time: 노출 시간(초).
        f_number: 조리개 값(F).
        iso: ISO 감도.
        focal_length: 초점 거리(mm).
        lens_model: 렌즈 모델 문자열.
    """

    make: str | None = None
    model: str | None = None
    orientation: int | None = None
    software: str | None = None
    datetime_original: str | None = None
    exposure_time: float | None = None
    f_number: float | None = None
    iso: int | None = None
    focal_length: float | None = None
    lens_model: str | None = None

    def is_empty(self) -> bool:
        """추출된 태그가 하나도 없으면 ``True``."""
        return all(getattr(self, f) is None for f in self.__dataclass_fields__)


def dms_to_decimal(
    degrees: float, minutes: float, seconds: float, ref: str
) -> float:
    """도·분·초와 반구 기준(ref)을 부호 있는 십진수 도로 환산한다.

    Args:
        degrees: 도.
        minutes: 분.
        seconds: 초.
        ref: 반구 문자열. ``S`` 또는 ``W`` 이면 음수가 된다(대소문자 무시).

    Returns:
        십진수 도. 남위/서경은 음수.
    """
    value = degrees + minutes / 60.0 + seconds / 3600.0
    if ref.strip().upper().startswith(("S", "W")):
        value = -value
    return value


def find_exif_tiff(data: bytes) -> bytes | None:
    """JPEG 바이트에서 EXIF 의 TIFF 페이로드를 찾아 돌려준다.

    JPEG 마커를 순회하며 ``Exif\\x00\\x00`` 로 시작하는 APP1(0xFFE1)
    세그먼트를 찾고, 그 6바이트 헤더 뒤의 TIFF 데이터를 반환한다.

    Args:
        data: 파일 전체 바이트. 이미 TIFF(``II``/``MM`` 로 시작)인 경우
            그대로 반환한다.

    Returns:
        TIFF 페이로드 바이트. JPEG 가 아니거나 EXIF APP1 이 없으면 ``None``.
    """
    if data[:2] in (b"II", b"MM"):
        return data
    if data[:2] != b"\xff\xd8":  # SOI 마커가 아니면 JPEG 아님.
        return None

    pos = 2
    n = len(data)
    while pos + 4 <= n:
        if data[pos] != 0xFF:
            return None
        marker = data[pos + 1]
        if marker in (0xD8, 0xD9) or 0xD0 <= marker <= 0xD7:
            pos += 2  # 길이 없는 마커.
            continue
        if marker == 0xDA:  # SOS 이후는 압축 스캔 데이터 → 중단.
            return None
        seg_len = struct.unpack(">H", data[pos + 2 : pos + 4])[0]
        seg = data[pos + 4 : pos + 2 + seg_len]
        if marker == 0xE1 and seg[:6] == b"Exif\x00\x00":
            return seg[6:]
        pos += 2 + seg_len
    return None


def _read_ifd(tiff: bytes, offset: int, endian: str) -> dict[int, list]:
    """오프셋의 IFD 한 개를 읽어 ``태그 -> 값 목록`` 으로 돌려준다.

    범위를 벗어나거나 깨진 엔트리는 조용히 건너뛴다.
    """
    if offset + 2 > len(tiff):
        return {}
    (count,) = struct.unpack(endian + "H", tiff[offset : offset + 2])
    entries: dict[int, list] = {}
    base = offset + 2
    for i in range(count):
        eo = base + i * 12
        if eo + 12 > len(tiff):
            break
        tag, typ, num = struct.unpack(endian + "HHI", tiff[eo : eo + 8])
        size = _TYPE_SIZE.get(typ)
        if size is None:
            continue
        total = size * num
        if total <= 4:
            raw = tiff[eo + 8 : eo + 8 + total]
        else:
            (vo,) = struct.unpack(endian + "I", tiff[eo + 8 : eo + 12])
            raw = tiff[vo : vo + total]
        if len(raw) < total:
            continue
        entries[tag] = _decode(raw, typ, num, endian)
    return entries


def _decode(raw: bytes, typ: int, num: int, endian: str) -> list:
    """IFD 엔트리 원시 바이트를 파이썬 값 목록으로 변환한다."""
    if typ == 2:  # ASCII: 끝의 NUL 제거 후 한 문자열로.
        return [raw.split(b"\x00", 1)[0].decode("ascii", "replace")]
    if typ in (5, 10):  # (S)RATIONAL: (분자, 분모) 쌍.
        code = "ii" if typ == 10 else "II"
        out = []
        for k in range(num):
            n, d = struct.unpack(endian + code, raw[k * 8 : k * 8 + 8])
            out.append(n / d if d else 0.0)
        return out
    if typ == 3:  # SHORT
        return list(struct.unpack(endian + "H" * num, raw[: 2 * num]))
    if typ in (4, 9):  # LONG / SLONG
        code = "i" if typ == 9 else "I"
        return list(struct.unpack(endian + code * num, raw[: 4 * num]))
    return [raw]  # BYTE/UNDEFINED 등: 원시 바이트 보존.


def extract_gps(data: bytes) -> GpsCoordinate | None:
    """JPEG/TIFF 바이트에서 GPS 위·경도를 추출한다.

    Args:
        data: JPEG 파일 전체 바이트(또는 TIFF 페이로드).

    Returns:
        위도/경도가 모두 있으면 :class:`GpsCoordinate`, 그렇지 않으면 ``None``.
    """
    tiff = find_exif_tiff(data)
    if tiff is None or len(tiff) < 8:
        return None

    order = tiff[:2]
    if order == b"II":
        endian = "<"
    elif order == b"MM":
        endian = ">"
    else:
        return None

    (ifd0_off,) = struct.unpack(endian + "I", tiff[4:8])
    ifd0 = _read_ifd(tiff, ifd0_off, endian)
    gps_ptr = ifd0.get(_GPS_IFD_TAG)
    if not gps_ptr:
        return None

    gps = _read_ifd(tiff, int(gps_ptr[0]), endian)
    lat = gps.get(_GPS_LAT)
    lon = gps.get(_GPS_LON)
    lat_ref = gps.get(_GPS_LAT_REF, ["N"])
    lon_ref = gps.get(_GPS_LON_REF, ["E"])
    if not (lat and lon and len(lat) >= 3 and len(lon) >= 3):
        return None

    return GpsCoordinate(
        latitude=dms_to_decimal(lat[0], lat[1], lat[2], str(lat_ref[0])),
        longitude=dms_to_decimal(lon[0], lon[1], lon[2], str(lon_ref[0])),
    )


def _first(entries: dict[int, list], tag: int):
    """IFD 딕셔너리에서 태그의 첫 값을 돌려준다(없으면 ``None``)."""
    vals = entries.get(tag)
    return vals[0] if vals else None


def _clean_str(value) -> str | None:
    """ASCII 값을 다듬는다. 공백뿐이거나 비면 ``None``."""
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def extract_metadata(data: bytes) -> CameraMetadata | None:
    """JPEG/TIFF 바이트에서 카메라/촬영 설정 메타데이터를 추출한다.

    IFD0(제조사·기종·방향·소프트웨어·일시)와 Exif SubIFD(노출·조리개·ISO·
    초점거리·렌즈·촬영일시)를 함께 읽어 :class:`CameraMetadata` 로 모은다.
    GPS 추출(:func:`extract_gps`)과 동일한 IFD 파서를 재사용한다.

    Args:
        data: JPEG 파일 전체 바이트(또는 TIFF 페이로드).

    Returns:
        EXIF TIFF 를 찾지 못하면 ``None``. 찾았으나 알려진 태그가 하나도
        없으면 빈 :class:`CameraMetadata`(``is_empty() == True``).
    """
    tiff = find_exif_tiff(data)
    if tiff is None or len(tiff) < 8:
        return None

    order = tiff[:2]
    if order == b"II":
        endian = "<"
    elif order == b"MM":
        endian = ">"
    else:
        return None

    (ifd0_off,) = struct.unpack(endian + "I", tiff[4:8])
    ifd0 = _read_ifd(tiff, ifd0_off, endian)

    sub: dict[int, list] = {}
    exif_ptr = ifd0.get(_EXIF_IFD_TAG)
    if exif_ptr:
        sub = _read_ifd(tiff, int(exif_ptr[0]), endian)

    iso = _first(sub, _TAG_ISO)
    orientation = _first(ifd0, _TAG_ORIENTATION)
    return CameraMetadata(
        make=_clean_str(_first(ifd0, _TAG_MAKE)),
        model=_clean_str(_first(ifd0, _TAG_MODEL)),
        orientation=int(orientation) if orientation is not None else None,
        software=_clean_str(_first(ifd0, _TAG_SOFTWARE)),
        datetime_original=_clean_str(
            _first(sub, _TAG_DATETIME_ORIGINAL) or _first(ifd0, _TAG_DATETIME)
        ),
        exposure_time=_first(sub, _TAG_EXPOSURE_TIME),
        f_number=_first(sub, _TAG_F_NUMBER),
        iso=int(iso) if iso is not None else None,
        focal_length=_first(sub, _TAG_FOCAL_LENGTH),
        lens_model=_clean_str(_first(sub, _TAG_LENS_MODEL)),
    )
