"""JA3 TLS 클라이언트 핑거프린팅 코어.

:mod:`forensiclab.tls` 가 ClientHello 에서 뽑아 주는 SNI 는 "어떤 도메인에
붙으려는가" 를 알려 주지만, 멀웨어는 도메인·IP 를 수시로 바꾼다(C2 로테이션).
그래서 침해 분석은 *도메인과 무관한* 단서를 원한다.

**JA3** (Salesforce, 2017) 는 ClientHello 의 협상 파라미터 — TLS 버전, 제시한
암호 스위트, 확장 목록, 지원 곡선, 곡선 포인트 포맷 — 을 정해진 순서로 이어
붙여 만든 문자열을 MD5 한 값이다. 같은 TLS 라이브러리/빌드로 만든 핸드셰이크는
도메인·IP·인증서가 달라도 같은 JA3 를 낸다. 그래서 특정 멀웨어 패밀리나 툴
(예: 동일한 Go/OpenSSL 빌드로 컴파일된 비콘)을 도메인 차단망을 우회해도
묶어낼 수 있다 — IOC(침해 지표)로 널리 공유된다.

JA3 문자열 형식(쉼표 5필드, 각 필드는 ``-`` 로 이은 10진수)::

    SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats

빈 필드는 빈 문자열로 둔다(예: 확장이 없으면 ``771,4865,,,``). 그 문자열의
MD5 16진수 소문자가 JA3 해시다.

**GREASE 제거**: RFC 8701 의 GREASE 값(``0x0a0a``, ``0x1a1a`` … ``0xfafa``)은
구현이 "미지 값 무시" 를 강제하려고 무작위로 끼워 넣는 더미라, 같은 클라이언트도
핸드셰이크마다 다를 수 있다. JA3 정의는 cipher·extension·curve 에서 GREASE 를
모두 빼고 계산한다 — 그래야 핑거프린트가 안정적이다.

설계 원칙(:mod:`forensiclab.tls` 와 동일):
- 부작용 없음: 순수 함수. 디스크/표준출력 없음.
- stdlib 전용: 해시는 :mod:`hashlib` (MD5 는 JA3 정의가 못 박은 값).
- 안전: 입력 :class:`~forensiclab.tls.ClientHello` 를 변형하지 않는다.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Iterable, List

from forensiclab.tls import ClientHello

__all__ = [
    "is_grease",
    "ja3_string",
    "ja3_hash",
    "Ja3",
    "ja3",
]


def is_grease(value: int) -> bool:
    """RFC 8701 GREASE 값이면 ``True``.

    GREASE 값은 두 바이트가 같고 그 바이트의 하위 니블이 ``0xa`` 인
    16개(``0x0a0a``, ``0x1a1a`` … ``0xfafa``)뿐이다. 16비트 범위 밖의 값은
    GREASE 가 아니다.
    """
    return (value >> 8) == (value & 0xFF) and (value & 0x0F) == 0x0A


def _join(values: Iterable[int]) -> str:
    """GREASE 를 뺀 값들을 ``-`` 로 이은 10진수 문자열(비면 빈 문자열)."""
    return "-".join(str(v) for v in values if not is_grease(v))


def ja3_string(hello: ClientHello) -> str:
    """:class:`~forensiclab.tls.ClientHello` 의 JA3 문자열(해시 전 원본).

    필드 순서는 JA3 정의를 따른다:
    ``version,ciphers,extensions,curves,point_formats``. 각 목록에서 GREASE
    값은 제거한다. point_formats 에는 GREASE 가 정의되지 않지만 일관성을 위해
    같은 필터를 적용한다(실제 포맷 id 0·1·2 는 영향 없음).
    """
    return ",".join(
        (
            str(hello.legacy_version),
            _join(hello.cipher_suites),
            _join(hello.extensions),
            _join(hello.supported_groups),
            _join(hello.ec_point_formats),
        )
    )


def ja3_hash(hello: ClientHello) -> str:
    """JA3 문자열의 MD5 16진수(소문자) — 공유 가능한 JA3 핑거프린트."""
    return hashlib.md5(ja3_string(hello).encode("ascii")).hexdigest()


@dataclass(frozen=True)
class Ja3:
    """JA3 핑거프린트 결과(원본 문자열 + 해시)."""

    string: str
    hash: str


def ja3(hello: ClientHello) -> Ja3:
    """ClientHello 한 개의 JA3 (문자열 + 해시) 를 한 번에 돌려준다."""
    s = ja3_string(hello)
    return Ja3(string=s, hash=hashlib.md5(s.encode("ascii")).hexdigest())
