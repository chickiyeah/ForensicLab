"""JA3S TLS 서버 핑거프린팅 코어.

:mod:`forensiclab.ja3` 의 JA3 는 *클라이언트* 의 ClientHello 를 지문화해
"같은 툴/빌드로 만든 핸드셰이크" 를 도메인과 무관하게 묶어낸다. **JA3S**
(Salesforce, 2017) 는 그 짝으로, 서버가 보낸 *ServerHello* 를 지문화한다.

JA3 와 JA3S 를 한 쌍으로 보면 분석력이 커진다: 서버는 보통 클라이언트가
제시한 것에 *반응* 해 cipher·extension 을 고르므로, ServerHello 지문은
"이 서버가 이 클라이언트류에게 어떻게 응답하는가" 를 나타낸다. C2 인프라는
같은 서버 소프트웨어/설정을 재사용하는 경향이 있어, 도메인·인증서를 바꿔도
같은 JA3S 를 낸다 — JA3+JA3S 조합은 단일 JA3 보다 오탐이 적은 IOC 가 된다.

JA3S 문자열 형식(쉼표 3필드)::

    SSLVersion,Cipher,Extensions

- ``SSLVersion`` — ServerHello 의 server_version(10진수). 예: ``0x0303`` → ``771``.
- ``Cipher`` — 서버가 *선택한 단 하나* 의 암호 스위트(10진수). JA3 의 cipher 가
  목록인 것과 달리 JA3S 는 항상 단일 값이다.
- ``Extensions`` — ServerHello 에 등장한 확장 type id 를 등장 순서로 ``-`` 로
  이은 것. 비면 빈 문자열(예: ``771,49195,``).

그 문자열의 MD5 16진수 소문자가 JA3S 해시다.

**GREASE 제거**: :mod:`forensiclab.ja3` 와 동일하게 RFC 8701 GREASE 값을
extension 목록에서 뺀다. cipher 는 서버가 고른 실제 값이라 GREASE 가 올 수
없지만, 일관성을 위해 GREASE 면 필드를 비운다(정상 트래픽엔 영향 없음).

설계 원칙(:mod:`forensiclab.ja3` 와 동일):
- 부작용 없음: 순수 함수. 디스크/표준출력 없음.
- stdlib 전용: 해시는 :mod:`hashlib` (MD5 는 JA3S 정의가 못 박은 값).
- 안전: 입력 :class:`~forensiclab.tls.ServerHello` 를 변형하지 않는다.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from forensiclab.ja3 import is_grease
from forensiclab.tls import ServerHello

__all__ = [
    "ja3s_string",
    "ja3s_hash",
    "Ja3s",
    "ja3s",
]


def ja3s_string(hello: ServerHello) -> str:
    """:class:`~forensiclab.tls.ServerHello` 의 JA3S 문자열(해시 전 원본).

    필드 순서는 JA3S 정의를 따른다: ``version,cipher,extensions``. version 은
    ServerHello 의 ``legacy_version``(JA3 가 ClientHello 의 legacy_version 을
    쓰는 것과 같은 자리). extension 목록에서 GREASE 는 제거한다. cipher 가
    GREASE 면(정상적으론 없음) 빈 필드로 둔다.
    """
    cipher = "" if is_grease(hello.cipher_suite) else str(hello.cipher_suite)
    extensions = "-".join(
        str(e) for e in hello.extensions if not is_grease(e)
    )
    return ",".join((str(hello.legacy_version), cipher, extensions))


def ja3s_hash(hello: ServerHello) -> str:
    """JA3S 문자열의 MD5 16진수(소문자) — 공유 가능한 JA3S 핑거프린트."""
    return hashlib.md5(ja3s_string(hello).encode("ascii")).hexdigest()


@dataclass(frozen=True)
class Ja3s:
    """JA3S 핑거프린트 결과(원본 문자열 + 해시)."""

    string: str
    hash: str


def ja3s(hello: ServerHello) -> Ja3s:
    """ServerHello 한 개의 JA3S (문자열 + 해시) 를 한 번에 돌려준다."""
    s = ja3s_string(hello)
    return Ja3s(string=s, hash=hashlib.md5(s.encode("ascii")).hexdigest())
