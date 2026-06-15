"""DHCP — 동적 호스트 구성 프로토콜 파싱 코어 (RFC 2131 / RFC 2132).

:mod:`forensiclab.netdissect` 가 식별한 UDP(포트 67/68) 페이로드는 DHCP
메시지 — BOOTP(RFC 951) 위에 옵션 필드를 얹은 형식 — 일 수 있다. 이 모듈이
그 본문을 해석한다(:mod:`forensiclab.dns` 가 UDP 53 페이로드를 다루는 것과
같은 위치).

DHCP 는 침해/사고 분석에서 **호스트 식별·자산 인벤토리** 단서로 쓸모 있다:

- 클라이언트가 보낸 hostname(옵션 12)·client-id(옵션 61)·요청 IP(옵션 50)
  로 어떤 장치가 언제 어떤 주소를 받았는지 복원한다(DHCP 임대 타임라인).
- vendor class identifier(옵션 60)와 parameter request list(옵션 55)의
  순서·조합은 OS/장치 종류를 드러내는 **DHCP 핑거프린트**(Fingerbank 류)다 —
  배너 위조와 무관하게 단말을 분류한다.
- chaddr(client hardware address)는 :mod:`forensiclab.arp` 의 MAC 과 짝지어
  IP↔MAC↔hostname 을 한 단말로 묶는 상관 분석의 축이 된다.

이 모듈은 단건 메시지 파싱만 하고, 임대 타임라인·핑거프린트 상관관계 판단은
호출자가 여러 :class:`Dhcp` 를 모아 수행한다.

BOOTP/DHCP 고정 헤더(RFC 2131 §2)::

    byte     op       1 = BOOTREQUEST(클라이언트→서버), 2 = BOOTREPLY
    byte     htype    하드웨어 타입 (1 = Ethernet)
    byte     hlen     하드웨어 주소 길이 (Ethernet = 6)
    byte     hops
    uint32   xid      트랜잭션 ID (요청/응답 짝맞춤)
    uint16   secs
    uint16   flags
    uint32   ciaddr   client IP (이미 가진 주소)
    uint32   yiaddr   "your" IP (서버가 배정한 주소)
    uint32   siaddr   next-server IP
    uint32   giaddr   relay agent IP
    byte[16] chaddr   client hardware address (앞 hlen 바이트가 MAC)
    byte[64] sname    서버 호스트명 (보통 0)
    byte[128] file    부트 파일명 (보통 0)
    uint32   magic    매직 쿠키 0x63825363 — 이후가 DHCP 옵션
    ...      options  TLV(type, len, value); 0=pad, 255=end

옵션은 type(1)·len(1)·value(len) 의 TLV 나열이다. type 0(pad)은 길이 없는
1바이트 패딩, type 255(end)는 옵션 종료다. 같은 type 이 여러 번 나오면
(RFC 3396 분할) 값을 이어 붙인다.

설계 원칙(:mod:`forensiclab.netdissect`·:mod:`forensiclab.arp`·:mod:`forensiclab.dns`
와 동일):
- 부작용 없음: 순수 함수. 디스크/표준출력/네트워크 없음.
- stdlib 전용.
- 안전: 입력 바이트를 변형하지 않는다(읽기 전용).
- 견고: 너무 짧거나 망가진 입력은 예외 대신 ``None``.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Dict, List, Optional

__all__ = [
    "BOOTREQUEST",
    "BOOTREPLY",
    "MAGIC_COOKIE",
    "OPT_PAD",
    "OPT_END",
    "OPT_REQUESTED_IP",
    "OPT_MESSAGE_TYPE",
    "OPT_PARAM_REQ_LIST",
    "OPT_VENDOR_CLASS",
    "OPT_HOSTNAME",
    "OPT_CLIENT_ID",
    "Dhcp",
    "parse_dhcp",
    "format_mac",
    "format_ipv4",
]

BOOTREQUEST = 1
BOOTREPLY = 2

MAGIC_COOKIE = 0x63825363

# 자주 쓰는 옵션 코드(RFC 2132).
OPT_PAD = 0
OPT_REQUESTED_IP = 50
OPT_MESSAGE_TYPE = 53
OPT_PARAM_REQ_LIST = 55
OPT_VENDOR_CLASS = 60
OPT_HOSTNAME = 12
OPT_CLIENT_ID = 61
OPT_END = 255

# 고정 헤더 길이: op..magic 까지.
#   op(1)+htype(1)+hlen(1)+hops(1)+xid(4)+secs(2)+flags(2)
#   +ciaddr(4)+yiaddr(4)+siaddr(4)+giaddr(4)+chaddr(16)+sname(64)+file(128)
#   +magic(4) = 240
_DHCP_FIXED_SIZE = 240

# DHCP 메시지 타입(옵션 53) 이름.
_MSG_TYPE_NAMES = {
    1: "DISCOVER",
    2: "OFFER",
    3: "REQUEST",
    4: "DECLINE",
    5: "ACK",
    6: "NAK",
    7: "RELEASE",
    8: "INFORM",
}


def format_mac(raw: bytes) -> str:
    """하드웨어 주소 바이트를 ``aa:bb:cc:dd:ee:ff`` 문자열로."""
    return ":".join(f"{b:02x}" for b in raw)


def format_ipv4(raw: bytes) -> str:
    """4바이트 IPv4 주소를 점표기 문자열로 (그 외 길이는 hex)."""
    if len(raw) == 4:
        return ".".join(str(b) for b in raw)
    return raw.hex()


def _parse_options(data: bytes, pos: int) -> Dict[int, bytes]:
    """매직 쿠키 다음 위치부터 TLV 옵션을 dict(code→value)로 모은다.

    type 0(pad)은 건너뛰고, type 255(end)에서 멈춘다. 같은 코드가 여러 번
    나오면(RFC 3396) 값을 이어 붙인다. 길이가 버퍼를 넘으면 거기서 멈춘다.
    """
    out: Dict[int, bytes] = {}
    n = len(data)
    while pos < n:
        code = data[pos]
        pos += 1
        if code == OPT_END:
            break
        if code == OPT_PAD:
            continue
        if pos >= n:
            break
        length = data[pos]
        pos += 1
        if pos + length > n:
            break
        value = data[pos:pos + length]
        pos += length
        if code in out:
            out[code] += value
        else:
            out[code] = value
    return out


@dataclass(frozen=True)
class Dhcp:
    """파싱된 DHCP/BOOTP 메시지.

    Attributes:
        op: 1 = BOOTREQUEST, 2 = BOOTREPLY.
        htype: 하드웨어 타입(1 = Ethernet).
        hlen: 하드웨어 주소 바이트 길이.
        hops: relay hop 카운트.
        xid: 트랜잭션 ID(요청/응답 짝맞춤).
        ciaddr: client IP 원본 4바이트.
        yiaddr: 서버가 배정한 IP 원본 4바이트.
        siaddr: next-server IP 원본 4바이트.
        giaddr: relay agent IP 원본 4바이트.
        chaddr: client hardware address 16바이트(앞 hlen 바이트가 유효).
        options: 옵션 코드 → 원본 값 바이트.
    """

    op: int
    htype: int
    hlen: int
    hops: int
    xid: int
    ciaddr: bytes
    yiaddr: bytes
    siaddr: bytes
    giaddr: bytes
    chaddr: bytes
    options: Dict[int, bytes]

    @property
    def client_mac(self) -> str:
        """client hardware address(chaddr 의 앞 hlen 바이트)의 MAC 표현."""
        n = self.hlen if 0 < self.hlen <= len(self.chaddr) else len(self.chaddr)
        return format_mac(self.chaddr[:n])

    @property
    def client_ip(self) -> str:
        """ciaddr 의 사람이 읽는 표현."""
        return format_ipv4(self.ciaddr)

    @property
    def your_ip(self) -> str:
        """yiaddr(서버가 배정한 주소)의 사람이 읽는 표현."""
        return format_ipv4(self.yiaddr)

    @property
    def message_type(self) -> Optional[int]:
        """DHCP 메시지 타입(옵션 53) 숫자값(없으면 ``None``)."""
        raw = self.options.get(OPT_MESSAGE_TYPE)
        if not raw:
            return None
        return raw[0]

    @property
    def message_type_name(self) -> Optional[str]:
        """메시지 타입의 이름(DISCOVER/OFFER/...; 미상이면 ``"type-<n>"``)."""
        mt = self.message_type
        if mt is None:
            return None
        return _MSG_TYPE_NAMES.get(mt, f"type-{mt}")

    @property
    def hostname(self) -> Optional[str]:
        """클라이언트가 알린 hostname(옵션 12; 없으면 ``None``)."""
        raw = self.options.get(OPT_HOSTNAME)
        if raw is None:
            return None
        return raw.split(b"\x00", 1)[0].decode("utf-8", "replace")

    @property
    def requested_ip(self) -> Optional[str]:
        """클라이언트가 요청한 IP(옵션 50; 없으면 ``None``)."""
        raw = self.options.get(OPT_REQUESTED_IP)
        if raw is None:
            return None
        return format_ipv4(raw)

    @property
    def vendor_class(self) -> Optional[str]:
        """vendor class identifier(옵션 60; 없으면 ``None``)."""
        raw = self.options.get(OPT_VENDOR_CLASS)
        if raw is None:
            return None
        return raw.decode("utf-8", "replace")

    @property
    def param_req_list(self) -> Optional[List[int]]:
        """parameter request list(옵션 55) 코드 순서 — DHCP 핑거프린트 축.

        DHCP 핑거프린트는 이 코드들의 *순서*에 의존하므로 정렬하지 않는다.
        없으면 ``None``.
        """
        raw = self.options.get(OPT_PARAM_REQ_LIST)
        if raw is None:
            return None
        return list(raw)


def parse_dhcp(data: bytes, offset: int = 0) -> Optional[Dhcp]:
    """원시 바이트에서 DHCP/BOOTP 메시지를 파싱한다.

    Args:
        data: DHCP 메시지를 담은 바이트. 보통 UDP 67/68 페이로드
            (:class:`forensiclab.netdissect` 의 ``payload_offset`` 부터)다.
        offset: 메시지가 시작하는 위치(기본 0).

    Returns:
        :class:`Dhcp`. 고정 헤더(240바이트)에 못 미치거나 매직 쿠키가
        0x63825363 이 아니면(= DHCP 가 아니거나 손상) ``None``.
    """
    if offset < 0 or offset + _DHCP_FIXED_SIZE > len(data):
        return None
    op, htype, hlen, hops = struct.unpack("BBBB", data[offset:offset + 4])
    xid = struct.unpack(">I", data[offset + 4:offset + 8])[0]
    # secs(2)+flags(2) 는 건너뛴다(offset+8 .. offset+12).
    ciaddr = data[offset + 12:offset + 16]
    yiaddr = data[offset + 16:offset + 20]
    siaddr = data[offset + 20:offset + 24]
    giaddr = data[offset + 24:offset + 28]
    chaddr = data[offset + 28:offset + 44]
    # sname(64): offset+44..108, file(128): offset+108..236.
    magic = struct.unpack(">I", data[offset + 236:offset + 240])[0]
    if magic != MAGIC_COOKIE:
        return None
    options = _parse_options(data, offset + _DHCP_FIXED_SIZE)
    return Dhcp(
        op=op,
        htype=htype,
        hlen=hlen,
        hops=hops,
        xid=xid,
        ciaddr=ciaddr,
        yiaddr=yiaddr,
        siaddr=siaddr,
        giaddr=giaddr,
        chaddr=chaddr,
        options=options,
    )
