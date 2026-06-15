"""SMS-TPDU — GSM 단문(SMS) 전송 계층 PDU 파싱 코어 (3GPP TS 23.040/23.038).

:mod:`forensiclab.map` 이 ``forwardSM``(``44 mo-forwardSM``·``46 mt-forwardSM``)
연산의 인자에서 **표적 가입자 신원(MSISDN/IMSI)** 을 뽑았을 때, *바로 그 같은
인자에 함께 실려 있는 것* 이 이 모듈이 푸는 대상 — **SMS 메시지 그 자체**(SM-RP-UI
필드의 SMS-TPDU)다. MAP 가 "누구의 SMS 인가"라면 SMS-TPDU 는 **"그 SMS 의 내용·
발신자·시각"**, 즉 SS7 SMS 가로채기(:mod:`forensiclab.tcap` 45 sendRoutingInfoForSM
→ 라우팅 확보 → 46 mt-forwardSM 주입)에서 *실제로 가로채지거나 위조되는 페이로드*
이다. MAP target_digits 가 "누구를"이라면 SMS-TPDU 는 "무슨 말을".

SMS-TPDU 는 SS7 의 BER/ASN.1 과 달리 **고정 위치 옥텟 스트림**(TS 23.040 §9.2)이라
MAP/TCAP 처럼 얕게 순회하지 않고 메시지 타입별 고정 필드를 순서대로 푼다. 포렌식
핵심 세 가지를 복원한다:

- **주소**(TP-OA 발신·TP-DA 착신): 길이 + type-of-address 옥텟 + swapped-BCD 반옥텟.
  :mod:`forensiclab.map` 의 :func:`~forensiclab.map.decode_tbcd` 와 동일한 반옥텟
  부호화(드리프트 차단 위해 재사용). alphanumeric TON(0x50)이면 주소가 GSM 7비트
  팩이라 :func:`decode_gsm7` 로 푼다.
- **시각**(TP-SCTS, SMS-DELIVER): 7옥텟 반옥텟-스왑 BCD(YY MM DD HH MM SS TZ),
  서비스 센터 수신 시각 — 메시지 타임라인(:mod:`forensiclab.timeline`)의 못.
- **본문**(TP-UD): TP-DCS(데이터 부호화)가 가리키는 부호로 디코드 — GSM 7비트
  기본 알파벳(septet 언팩)·8비트·UCS2(UTF-16BE). 가로채진/위조된 메시지 텍스트
  자체가 곧 증거(피싱 링크·스미싱·OTP 탈취).

설계 원칙(:mod:`forensiclab.map`·:mod:`forensiclab.isup` 와 동일):
- 부작용 없음·stdlib 전용·읽기 전용(입력 무변형).
- 메시지 타입(MTI)으로 갈라 필드를 *순서대로* 푼다(스키마 추측 없음). 절단되면
  풀 수 있는 필드까지만 채우고 나머지는 ``None``.
- 견고: 빈 입력·1옥텟 미만이면 ``None``(오탐 가드). TP-UDHI(헤더 지시) 가 서면
  UDH 옥텟을 분리하고 7비트 모드의 septet 정렬 패딩을 보정한다.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import List, Optional, Tuple

from forensiclab.map import decode_tbcd

__all__ = [
    "SmsAddress",
    "SmsTpdu",
    "decode_gsm7",
    "decode_scts",
    "decode_sms_address",
    "parse_sms_tpdu",
]

# TP-MTI (TS 23.040 §9.2.3.1) — SC→MS(방향에 따라 의미가 갈림). 여기선 SC→MS
# 해석(DELIVER/STATUS-REPORT)을 1차로 두고, SUBMIT 은 MS→SC 의 대표.
_MTI_NAMES = {
    0: "sms-deliver",        # SC→MS (수신 메시지) / MS→SC 면 deliver-report
    1: "sms-submit",         # MS→SC (발신 메시지) / SC→MS 면 submit-report
    2: "sms-status-report",  # SC→MS (상태 보고) / MS→SC 면 command
}

# GSM 7비트 기본 알파벳 (TS 23.038 §6.2.1) — 코드포인트 0x00..0x7F → 유니코드.
# 0x1B 는 확장 이스케이프(다음 septet 로 확장표 선택).
_GSM7_BASIC = (
    "@£$¥èéùìòÇ\nØø\rÅå"
    "Δ_ΦΓΛΩΠΨΣΘΞÆæßÉ"
    " !\"#¤%&'()*+,-./"
    "0123456789:;<=>?"
    "¡ABCDEFGHIJKLMNO"
    "PQRSTUVWXYZÄÖÑÜ§"
    "¿abcdefghijklmno"
    "pqrstuvwxyzäöñüà"
)

# GSM 7비트 확장표 (TS 23.038 §6.2.1.1) — 0x1B 다음 septet → 유니코드.
_GSM7_EXT = {
    0x0A: "",  # form feed
    0x14: "^",
    0x28: "{",
    0x29: "}",
    0x2F: "\\",
    0x3C: "[",
    0x3D: "~",
    0x3E: "]",
    0x40: "|",
    0x65: "€",  # €
}


def _unpack_septets(data: bytes, count: int) -> List[int]:
    """팩된 7비트 옥텟열을 ``count`` 개 septet(각 0..0x7F) 리스트로 푼다.

    각 옥텟의 비트를 하위부터 누적해 7비트씩 떼어낸다(TS 23.038 §6.1.2.1.1).
    데이터가 모자라면 가용분까지만 반환한다.
    """
    out: List[int] = []
    val = 0
    bits = 0
    for byte in data:
        val |= byte << bits
        bits += 8
        while bits >= 7 and len(out) < count:
            out.append(val & 0x7F)
            val >>= 7
            bits -= 7
        if len(out) >= count:
            break
    return out


def decode_gsm7(data: bytes, septet_count: int, skip_septets: int = 0) -> str:
    """GSM 7비트 기본 알파벳 팩(septet 언팩 + 알파벳 매핑)을 문자열로 푼다.

    Args:
        data: 팩된 사용자 데이터 옥텟(UDH 포함 가능 — ``skip_septets`` 로 건너뜀).
        septet_count: 풀어낼 총 septet 수(TP-UDL 의 7비트 의미).
        skip_septets: 선두에서 건너뛸 septet 수(UDH+패딩 정렬 보정).

    확장 이스케이프(0x1B)는 다음 septet 으로 확장표를 찾고, 미정의면 공백으로
    대체한다. 알 수 없는 코드포인트는 발생하지 않는다(표가 0x00..0x7F 전부 채움).
    """
    septets = _unpack_septets(data, septet_count)
    out: List[str] = []
    i = skip_septets
    while i < len(septets):
        code = septets[i]
        if code == 0x1B:
            i += 1
            if i < len(septets):
                out.append(_GSM7_EXT.get(septets[i], " "))
            else:
                out.append(" ")
        else:
            out.append(_GSM7_BASIC[code])
        i += 1
    return "".join(out)


def _dcs_encoding(dcs: int) -> str:
    """TP-DCS(TS 23.038 §4) → 부호화 식별자 ``"gsm7"``/``"8bit"``/``"ucs2"``.

    상위 코딩 그룹별로 본문 알파벳만 분류한다(메시지 클래스·압축 비트는 무시).
    """
    group = dcs >> 4
    if group <= 0x3:           # 일반 데이터 코딩(0x00..0x3F).
        alphabet = (dcs >> 2) & 0x03
        if alphabet == 0x01:
            return "8bit"
        if alphabet == 0x02:
            return "ucs2"
        return "gsm7"          # 00 또는 11(reserved) → GSM7.
    if group in (0xC, 0xD):    # 메시지 대기 표시(폐기/저장) — GSM7.
        return "gsm7"
    if group == 0xE:           # 메시지 대기 표시(UCS2 저장).
        return "ucs2"
    if group == 0xF:           # 데이터 코딩/메시지 클래스: bit2 = 0 GSM7·1 8bit.
        return "8bit" if (dcs & 0x04) else "gsm7"
    return "gsm7"


@dataclass(frozen=True)
class SmsAddress:
    """SMS-TPDU 의 주소 필드(TP-OA 발신 또는 TP-DA 착신).

    Attributes:
        digits: 디코드된 주소(전화번호 숫자열 또는 alphanumeric 텍스트).
        type_of_address: type-of-address 옥텟 원값(``None``=alphanumeric 아님 시도 전).
        ton: type of number(bits6-4) — 1 international·2 national·5 alphanumeric 등.
        npi: numbering plan id(bits3-0).
        is_alphanumeric: TON 이 alphanumeric(5)이라 주소가 7비트 텍스트인지.
        length: 헤더가 선언한 주소 길이(반옥텟 수).
        offset: 이 주소 필드(길이 옥텟)가 시작하는 절대 오프셋.
    """

    digits: str
    type_of_address: Optional[int]
    ton: Optional[int]
    npi: Optional[int]
    is_alphanumeric: bool
    length: int
    offset: int

    @property
    def is_international(self) -> bool:
        """TON 이 international(1) 여부."""
        return self.ton == 1


def decode_sms_address(data: bytes, pos: int, end: int) -> Optional[Tuple[SmsAddress, int]]:
    """``pos`` 의 SMS 주소 필드를 ``(SmsAddress, next_pos)`` 로 푼다(아니면 ``None``).

    구조(TS 23.040 §9.1.2.5): 길이(반옥텟 수, 1옥텟) + type-of-address(1옥텟) +
    주소 값(반옥텟 BCD, 반올림 옥텟). alphanumeric TON(5)이면 값이 GSM 7비트 팩.
    """
    if pos + 2 > end:
        return None
    addr_len = data[pos]            # 반옥텟(자릿수) 단위 길이.
    toa = data[pos + 1]
    nbytes = (addr_len + 1) // 2    # 주소 값 옥텟 수.
    val_start = pos + 2
    val_end = min(val_start + nbytes, end)
    raw = data[val_start:val_end]
    ton = (toa >> 4) & 0x07
    npi = toa & 0x0F
    if ton == 5:                    # alphanumeric → 7비트 텍스트.
        septets = (len(raw) * 8) // 7
        digits = decode_gsm7(raw, septets)
        is_alpha = True
    else:
        digits = decode_tbcd(raw)
        is_alpha = False
    addr = SmsAddress(
        digits=digits,
        type_of_address=toa,
        ton=ton,
        npi=npi,
        is_alphanumeric=is_alpha,
        length=addr_len,
        offset=pos,
    )
    return addr, val_start + nbytes


def decode_scts(raw: bytes) -> Optional[str]:
    """TP-SCTS 7옥텟(반옥텟-스왑 BCD)을 ``"YY-MM-DD HH:MM:SS ±TZ"`` 로 푼다.

    각 옥텟은 하위 nibble 이 먼저(swapped). 마지막 옥텟은 타임존(15분 단위, 최상위
    nibble bit3 이 부호). 7옥텟 미만이면 ``None``.
    """
    if len(raw) < 7:
        return None

    def two(b: int) -> int:
        return (b & 0x0F) * 10 + (b >> 4)

    yy, mm, dd, hh, mi, ss = (two(raw[i]) for i in range(6))
    tz_byte = raw[6]
    tz_sign = "-" if (tz_byte & 0x08) else "+"
    tz_quarters = (tz_byte & 0x07) * 10 + (tz_byte >> 4)
    tz_minutes = tz_quarters * 15
    tz = f"{tz_sign}{tz_minutes // 60:02d}:{tz_minutes % 60:02d}"
    return f"{yy:02d}-{mm:02d}-{dd:02d} {hh:02d}:{mi:02d}:{ss:02d} {tz}"


@dataclass(frozen=True)
class SmsTpdu:
    """파싱된 SMS-TPDU 한 개.

    Attributes:
        mti: TP-MTI(0 deliver·1 submit·2 status-report/command).
        message_type: MTI 이름.
        reply_path: TP-RP 비트.
        udh_present: TP-UDHI(사용자 데이터 헤더 존재) 비트.
        status_report: TP-SRI(deliver)/TP-SRR(submit) 비트.
        originating_address: TP-OA(SMS-DELIVER 발신 주소; 없으면 ``None``).
        destination_address: TP-DA(SMS-SUBMIT 착신 주소; 없으면 ``None``).
        message_reference: TP-MR(SMS-SUBMIT; 없으면 ``None``).
        protocol_id: TP-PID.
        data_coding: TP-DCS 원값.
        encoding: 본문 부호화 식별자(``"gsm7"``/``"8bit"``/``"ucs2"``).
        timestamp: TP-SCTS 디코드 문자열(SMS-DELIVER; 없으면 ``None``).
        user_data_length: TP-UDL 원값.
        user_data_header: UDH 옥텟(TP-UDHI 면; 아니면 ``None``).
        text: 디코드된 본문(부호화 실패/없으면 ``None``).
        payload_offset: TP-UD 내용이 시작하는 절대 오프셋.
    """

    mti: int
    message_type: str
    reply_path: bool
    udh_present: bool
    status_report: bool
    originating_address: Optional[SmsAddress]
    destination_address: Optional[SmsAddress]
    message_reference: Optional[int]
    protocol_id: Optional[int]
    data_coding: Optional[int]
    encoding: Optional[str]
    timestamp: Optional[str]
    user_data_length: Optional[int]
    user_data_header: Optional[bytes]
    text: Optional[str]
    payload_offset: int

    @property
    def is_deliver(self) -> bool:
        """SMS-DELIVER(수신 메시지) 여부."""
        return self.mti == 0

    @property
    def is_submit(self) -> bool:
        """SMS-SUBMIT(발신 메시지) 여부."""
        return self.mti == 1

    @property
    def is_concatenated(self) -> bool:
        """UDH 에 연결 메시지(IEI 0x00/0x08) 정보가 있는지(긴 SMS 조각)."""
        udh = self.user_data_header
        if not udh:
            return False
        i = 0
        while i + 2 <= len(udh):
            iei = udh[i]
            ielen = udh[i + 1]
            if iei in (0x00, 0x08):
                return True
            i += 2 + ielen
        return False

    @property
    def target_number(self) -> Optional[str]:
        """대표 상대 번호 — 착신(submit) 또는 발신(deliver)."""
        if self.destination_address is not None:
            return self.destination_address.digits
        if self.originating_address is not None:
            return self.originating_address.digits
        return None


def _decode_user_data(
    data: bytes,
    pos: int,
    end: int,
    udl: int,
    encoding: str,
    udhi: bool,
) -> Tuple[Optional[bytes], Optional[str], int]:
    """TP-UD 를 ``(udh, text, payload_offset)`` 로 푼다.

    7비트면 UDL 은 septet 수, 그 외엔 옥텟 수. UDHI 면 선두 UDH(길이 옥텟+내용)를
    분리하고, 7비트는 septet 정렬을 위해 패딩 septet 수만큼 건너뛴다.
    """
    payload_offset = pos
    if encoding == "gsm7":
        # 7비트: UD 옥텟 수 = ceil(UDL*7/8). UDH 가 있으면 옥텟 단위로 떼어낸다.
        ud_bytes = math.ceil(udl * 7 / 8)
        ud_end = min(pos + ud_bytes, end)
        raw = data[pos:ud_end]
        skip = 0
        udh = None
        if udhi and raw:
            udhl = raw[0]
            header_octets = udhl + 1
            udh = bytes(raw[1:min(header_octets, len(raw))])
            # 헤더+정렬을 위해 건너뛸 septet 수(올림).
            skip = math.ceil(header_octets * 8 / 7)
        text = decode_gsm7(raw, udl, skip)
        return udh, text, payload_offset
    # 8비트/UCS2: UDL 은 옥텟 수.
    ud_end = min(pos + udl, end)
    raw = data[pos:ud_end]
    udh = None
    if udhi and raw:
        udhl = raw[0]
        header_octets = udhl + 1
        udh = bytes(raw[1:min(header_octets, len(raw))])
        raw = raw[min(header_octets, len(raw)):]
    if encoding == "ucs2":
        try:
            text = raw.decode("utf-16-be")
        except (UnicodeDecodeError, ValueError):
            text = None
    else:  # 8bit
        text = raw.decode("latin-1")
    return udh, text, payload_offset


def parse_sms_tpdu(data: bytes, offset: int = 0) -> Optional[SmsTpdu]:
    """SMS-TPDU(SMS-DELIVER/SMS-SUBMIT)를 파싱한다.

    Args:
        data: TPDU 바이트. 보통 :mod:`forensiclab.map` ``mo/mt-forwardSM`` 인자의
            SM-RP-UI(OCTET STRING) 내용이다(서비스 센터 주소 SMSC 는 별도 필드).
        offset: TPDU 가 시작하는 위치(기본 0).

    Returns:
        :class:`SmsTpdu`. 첫 옥텟조차 없으면 ``None``(오탐 가드). 메시지 타입(MTI)
        으로 갈라 DELIVER/SUBMIT 의 고정 필드를 순서대로 푼다. STATUS-REPORT/COMMAND
        (MTI 2/3)는 헤더 플래그까지만 채우고 본문은 비운다. 절단되면 풀 수 있는
        필드까지만 채운다.

    한계: SC→MS / MS→SC 방향을 입력만으로 단정할 수 없어 MTI 의 1차 해석을 따른다
    (forwardSM 맥락에선 mt=deliver·mo=submit 이 일반적). TP-VP(유효 기간)는 길이만
    건너뛰고 값을 해석하지 않는다.
    """
    end = len(data)
    if offset < 0 or offset >= end:
        return None

    pos = offset
    first = data[pos]
    pos += 1
    mti = first & 0x03
    reply_path = bool(first & 0x80)
    udhi = bool(first & 0x40)
    # SRI(deliver, bit5)/SRR(submit, bit5) — 둘 다 비트5.
    status_report = bool(first & 0x20)
    message_type = _MTI_NAMES.get(mti, f"mti-{mti}")

    oa: Optional[SmsAddress] = None
    da: Optional[SmsAddress] = None
    mr: Optional[int] = None
    pid: Optional[int] = None
    dcs: Optional[int] = None
    encoding: Optional[str] = None
    scts: Optional[str] = None
    udl: Optional[int] = None
    udh: Optional[bytes] = None
    text: Optional[str] = None
    payload_offset = pos

    if mti == 0:  # SMS-DELIVER: OA, PID, DCS, SCTS, UDL, UD.
        res = decode_sms_address(data, pos, end)
        if res is not None:
            oa, pos = res
        if pos < end:
            pid = data[pos]
            pos += 1
        if pos < end:
            dcs = data[pos]
            pos += 1
            encoding = _dcs_encoding(dcs)
        if pos + 7 <= end:
            scts = decode_scts(data[pos:pos + 7])
            pos += 7
        elif pos < end:
            pos = min(pos + 7, end)
        if pos < end:
            udl = data[pos]
            pos += 1
            udh, text, payload_offset = _decode_user_data(
                data, pos, end, udl, encoding or "gsm7", udhi
            )
        else:
            payload_offset = pos
    elif mti == 1:  # SMS-SUBMIT: MR, DA, PID, DCS, VP, UDL, UD.
        if pos < end:
            mr = data[pos]
            pos += 1
        res = decode_sms_address(data, pos, end)
        if res is not None:
            da, pos = res
        if pos < end:
            pid = data[pos]
            pos += 1
        if pos < end:
            dcs = data[pos]
            pos += 1
            encoding = _dcs_encoding(dcs)
        # TP-VPF(첫 옥텟 bits4-3): 0 없음·2 상대(1옥텟)·1/3 7옥텟. 값은 건너뜀.
        vpf = (first >> 3) & 0x03
        if vpf == 2:
            pos = min(pos + 1, end)
        elif vpf in (1, 3):
            pos = min(pos + 7, end)
        if pos < end:
            udl = data[pos]
            pos += 1
            udh, text, payload_offset = _decode_user_data(
                data, pos, end, udl, encoding or "gsm7", udhi
            )
        else:
            payload_offset = pos
    else:
        payload_offset = pos

    return SmsTpdu(
        mti=mti,
        message_type=message_type,
        reply_path=reply_path,
        udh_present=udhi,
        status_report=status_report,
        originating_address=oa,
        destination_address=da,
        message_reference=mr,
        protocol_id=pid,
        data_coding=dcs,
        encoding=encoding,
        timestamp=scts,
        user_data_length=udl,
        user_data_header=udh,
        text=text,
        payload_offset=payload_offset,
    )
