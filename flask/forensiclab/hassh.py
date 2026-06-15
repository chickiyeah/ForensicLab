"""HASSH — SSH 핸드셰이크 핑거프린팅 코어 (SSH 판 JA3).

:mod:`forensiclab.ssh` 가 SSH 연결의 첫 평문 줄(버전 식별 배너)에서
softwareversion 을 뽑아 주지만, 배너 문자열은 클라이언트가 마음대로 위조할
수 있다(``paramiko`` 봇이 ``SSH-2.0-OpenSSH_8.9`` 를 사칭하는 식). 그래서
침해 분석은 *위조하기 어려운* 단서를 원한다.

**HASSH** (Salesforce, 2018) 는 JA3 의 SSH 판이다. 배너 직후 양쪽이 보내는
``SSH_MSG_KEXINIT`` (메시지 코드 20) 에 담긴 *제시한 알고리즘 목록* — 키 교환,
암호, MAC, 압축 — 을 정해진 순서로 이어 붙여 MD5 한 값이다. 이 목록의 구성과
순서는 SSH 라이브러리/빌드가 결정하므로, 같은 구현으로 만든 핸드셰이크는
배너를 어떻게 위장하든 같은 HASSH 를 낸다 — IOC(침해 지표)로 공유된다.

HASSH 문자열 형식(세미콜론 4필드, 각 필드는 ``,`` 로 이은 알고리즘 이름)::

    kex_algorithms;encryption_algorithms;mac_algorithms;compression_algorithms

- 클라이언트 HASSH 는 ``*_client_to_server`` 목록을,
- 서버 HASSH(HASSHServer)는 ``*_server_to_client`` 목록을 쓴다.

빈 목록은 빈 문자열로 둔다. 그 문자열의 MD5 16진수 소문자가 HASSH 해시다.
목록 *순서를 보존* 한다(JA3 처럼) — 순서 자체가 구현 지문의 일부다.

``SSH_MSG_KEXINIT`` 페이로드(RFC 4253 §7.1)::

    byte         20 (SSH_MSG_KEXINIT)
    byte[16]     cookie
    name-list    kex_algorithms
    name-list    server_host_key_algorithms
    name-list    encryption_algorithms_client_to_server
    name-list    encryption_algorithms_server_to_client
    name-list    mac_algorithms_client_to_server
    name-list    mac_algorithms_server_to_client
    name-list    compression_algorithms_client_to_server
    name-list    compression_algorithms_server_to_client
    name-list    languages_client_to_server
    name-list    languages_server_to_client
    boolean      first_kex_packet_follows
    uint32       0 (reserved)

각 ``name-list`` 는 ``uint32`` 길이 뒤에 그 길이만큼의 쉼표로 이은 US-ASCII
이름이다(RFC 4251 §5). KEXINIT 은 암호화·압축 이전이라 패킷에서 평문으로
보인다. 페이로드는 SSH 바이너리 패킷(RFC 4253 §6)에 감싸여 오므로::

    uint32   packet_length
    byte     padding_length
    byte[n]  payload   (n = packet_length - padding_length - 1)
    byte[p]  random padding

이 모듈은 바이너리 패킷 형태와 페이로드 단독 형태(코드 20 으로 시작) 모두
받아들인다.

설계 원칙(:mod:`forensiclab.ja3`·:mod:`forensiclab.ssh` 와 동일):
- 부작용 없음: 순수 함수. 디스크/표준출력 없음.
- stdlib 전용: 해시는 :mod:`hashlib` (MD5 는 HASSH 정의가 못 박은 값).
- 안전: 입력 바이트를 변형하지 않는다(읽기 전용).
- 견고: KEXINIT 이 아니거나 망가진 입력은 예외 대신 ``None``.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass
from typing import List, Optional

__all__ = [
    "SSH_MSG_KEXINIT",
    "KexInit",
    "parse_kexinit",
    "hassh_string",
    "hassh_server_string",
    "Hassh",
    "hassh",
    "hassh_server",
]

# KEXINIT 페이로드의 첫 바이트(메시지 코드). 페이로드는 이 값으로 시작한다.
SSH_MSG_KEXINIT = 20

# 16비트가 아닌 폭주 길이를 막는 상한. name-list 하나가 이보다 길면 손상으로
# 본다(현실의 알고리즘 목록은 수백 바이트 수준).
_MAX_NAMELIST = 64 * 1024


@dataclass(frozen=True)
class KexInit:
    """파싱된 ``SSH_MSG_KEXINIT`` 메시지.

    각 알고리즘 필드는 제시된 *순서를 보존한* 이름 리스트다(빈 목록은 ``[]``).
    HASSH 는 이 중 일부만 쓰지만, 분석에 쓸모 있는 전체를 구조화해 둔다.

    Attributes:
        cookie: 16바이트 난수 쿠키.
        kex_algorithms: 키 교환 알고리즘 목록.
        server_host_key_algorithms: 서버 호스트 키 알고리즘 목록.
        encryption_algorithms_c2s / _s2c: 암호 알고리즘(방향별).
        mac_algorithms_c2s / _s2c: MAC 알고리즘(방향별).
        compression_algorithms_c2s / _s2c: 압축 알고리즘(방향별).
        languages_c2s / _s2c: 언어 태그(방향별, 보통 비어 있음).
        first_kex_packet_follows: 추측 키 교환 패킷이 뒤따르는지.
    """

    cookie: bytes
    kex_algorithms: List[str]
    server_host_key_algorithms: List[str]
    encryption_algorithms_c2s: List[str]
    encryption_algorithms_s2c: List[str]
    mac_algorithms_c2s: List[str]
    mac_algorithms_s2c: List[str]
    compression_algorithms_c2s: List[str]
    compression_algorithms_s2c: List[str]
    languages_c2s: List[str]
    languages_s2c: List[str]
    first_kex_packet_follows: bool = False


def _extract_payload(data: bytes) -> Optional[bytes]:
    """원시 바이트에서 KEXINIT 페이로드(코드 20 으로 시작)를 끄집어낸다.

    페이로드 단독(첫 바이트가 20)이면 그대로, 아니면 SSH 바이너리 패킷
    프레이밍(RFC 4253 §6)으로 보고 ``packet_length``/``padding_length`` 를
    읽어 페이로드 구간만 떼어 낸다.
    """
    if not data:
        return None
    if data[0] == SSH_MSG_KEXINIT:
        return data
    if len(data) < 6:
        return None  # 바이너리 패킷 헤더(5) + 최소 페이로드 1바이트.
    packet_length = struct.unpack(">I", data[0:4])[0]
    padding_length = data[4]
    payload_len = packet_length - padding_length - 1
    if payload_len < 1 or 5 + payload_len > len(data):
        return None  # 길이가 버퍼를 벗어나면 손상으로 본다.
    payload = data[5:5 + payload_len]
    if not payload or payload[0] != SSH_MSG_KEXINIT:
        return None
    return payload


def _read_namelist(buf: bytes, off: int) -> Optional[tuple]:
    """``buf[off:]`` 에서 name-list 하나를 읽어 (이름 리스트, 다음 오프셋)."""
    if off + 4 > len(buf):
        return None
    length = struct.unpack(">I", buf[off:off + 4])[0]
    off += 4
    if length > _MAX_NAMELIST or off + length > len(buf):
        return None
    raw = buf[off:off + length]
    off += length
    if not raw:
        names: List[str] = []  # 길이 0 → 빈 목록.
    else:
        names = raw.decode("ascii", "replace").split(",")
    return names, off


def parse_kexinit(data: bytes) -> Optional[KexInit]:
    """원시 바이트에서 ``SSH_MSG_KEXINIT`` 을 파싱한다.

    Args:
        data: KEXINIT 을 담은 바이트. SSH 바이너리 패킷 전체이거나, 메시지
            코드 20 으로 시작하는 페이로드 단독 모두 받아들인다.

    Returns:
        :class:`KexInit`. KEXINIT 이 아니거나(코드 20 아님) name-list 가
        도중에 끊기는 등 손상이면 ``None``.
    """
    payload = _extract_payload(data)
    if payload is None or len(payload) < 17:
        return None  # 코드(1) + 쿠키(16) 최소.

    cookie = payload[1:17]
    off = 17
    lists: List[List[str]] = []
    for _ in range(10):  # 10개의 name-list.
        res = _read_namelist(payload, off)
        if res is None:
            return None
        names, off = res
        lists.append(names)

    # first_kex_packet_follows(boolean) 는 선택적으로 확인한다(있으면 읽고,
    # 잘려 있으면 기본 False — HASSH 계산엔 영향 없다).
    first_kex = bool(payload[off]) if off < len(payload) else False

    return KexInit(
        cookie=cookie,
        kex_algorithms=lists[0],
        server_host_key_algorithms=lists[1],
        encryption_algorithms_c2s=lists[2],
        encryption_algorithms_s2c=lists[3],
        mac_algorithms_c2s=lists[4],
        mac_algorithms_s2c=lists[5],
        compression_algorithms_c2s=lists[6],
        compression_algorithms_s2c=lists[7],
        languages_c2s=lists[8],
        languages_s2c=lists[9],
        first_kex_packet_follows=first_kex,
    )


def hassh_string(kex: KexInit) -> str:
    """클라이언트 HASSH 문자열(해시 전 원본).

    ``kex;enc_c2s;mac_c2s;comp_c2s`` 순서로, 각 목록은 제시된 순서대로 ``,`` 로
    잇는다. 빈 목록은 빈 문자열.
    """
    return ";".join(
        (
            ",".join(kex.kex_algorithms),
            ",".join(kex.encryption_algorithms_c2s),
            ",".join(kex.mac_algorithms_c2s),
            ",".join(kex.compression_algorithms_c2s),
        )
    )


def hassh_server_string(kex: KexInit) -> str:
    """서버 HASSHServer 문자열(해시 전 원본).

    클라이언트판과 같은 형식이되 ``*_server_to_client`` 목록을 쓴다:
    ``kex;enc_s2c;mac_s2c;comp_s2c``.
    """
    return ";".join(
        (
            ",".join(kex.kex_algorithms),
            ",".join(kex.encryption_algorithms_s2c),
            ",".join(kex.mac_algorithms_s2c),
            ",".join(kex.compression_algorithms_s2c),
        )
    )


@dataclass(frozen=True)
class Hassh:
    """HASSH 핑거프린트 결과(원본 문자열 + 해시)."""

    string: str
    hash: str


def hassh(kex: KexInit) -> Hassh:
    """클라이언트 KEXINIT 의 HASSH (문자열 + MD5) 를 한 번에 돌려준다."""
    s = hassh_string(kex)
    return Hassh(string=s, hash=hashlib.md5(s.encode("ascii")).hexdigest())


def hassh_server(kex: KexInit) -> Hassh:
    """서버 KEXINIT 의 HASSHServer (문자열 + MD5) 를 한 번에 돌려준다."""
    s = hassh_server_string(kex)
    return Hassh(string=s, hash=hashlib.md5(s.encode("ascii")).hexdigest())
