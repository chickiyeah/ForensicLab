import os, io, struct, hashlib, hmac as _hmac_mod, zipfile, re, tempfile, subprocess, json as _json, stat
import email as _email_mod
from email.parser import BytesParser
from email import policy as _email_policy
from flask import Blueprint, render_template, request, send_file, session, jsonify, redirect, url_for

bp = Blueprint('tools', __name__, url_prefix='/tools')

MAX_UPLOAD = int(os.environ.get('MAX_UPLOAD_BYTES', 16 * 1024 * 1024 * 1024))  # 기본 16 GB (env MAX_UPLOAD_BYTES)

# ── 쓰기/특권 도구는 로그인 필요 ─────────────────────────────────────────────────
# 디스크에 기록(mbr-repair)하거나 서버 측 특권 작업(복호화 unlock, 이미지 마운트
# e01-mount)을 하는 도구는 인증된 사용자만 접근 가능. 새 도구는 prefix 만 추가.
WRITE_TOOL_PREFIXES = ('/tools/mbr-repair', '/tools/unlock', '/tools/e01-mount')


@bp.before_request
def _require_login_for_write_tools():
    path = request.path
    if any(path == p or path.startswith(p + '/') for p in WRITE_TOOL_PREFIXES):
        if not session.get('user_id'):
            session['next_url'] = path
            return redirect(url_for('main.login'))


@bp.app_context_processor
def _inject_tool_count():
    # 모든 템플릿(navbar 등)에서 실제 도구 수 사용
    try:
        return {'tool_count': len(_TOOL_CATALOG)}
    except Exception:
        return {'tool_count': 0}

# ── File signatures for carving ──────────────────────────────────────────────
SIGNATURES = {
    'gif': {
        'label': 'GIF',
        'headers': [b'\x47\x49\x46\x38\x39\x61', b'\x47\x49\x46\x38\x37\x61'],
        'footer': b'\x00\x3B',
        'ext': 'gif',
    },
    'jpeg': {
        'label': 'JPEG',
        'headers': [b'\xFF\xD8\xFF'],
        'footer': b'\xFF\xD9',
        'ext': 'jpg',
    },
    'png': {
        'label': 'PNG',
        'headers': [b'\x89\x50\x4E\x47\x0D\x0A\x1A\x0A'],
        'footer': b'\x49\x45\x4E\x44\xAE\x42\x60\x82',
        'ext': 'png',
    },
    'pdf': {
        'label': 'PDF',
        'headers': [b'\x25\x50\x44\x46'],
        'footer': b'\x25\x25\x45\x4F\x46',
        'ext': 'pdf',
    },
    'zip': {
        'label': 'ZIP',
        'headers': [b'\x50\x4B\x03\x04'],
        'footer': b'\x50\x4B\x05\x06',
        'ext': 'zip',
    },
}

PARTITION_TYPES = {
    0x00: 'Empty',        0x01: 'FAT12',           0x04: 'FAT16 <32MB',
    0x05: 'Extended',     0x06: 'FAT16',            0x07: 'NTFS / exFAT',
    0x0B: 'FAT32',        0x0C: 'FAT32 (LBA)',      0x0E: 'FAT16 (LBA)',
    0x0F: 'Extended (LBA)', 0x82: 'Linux Swap',     0x83: 'Linux',
    0x8E: 'Linux LVM',   0xEE: 'GPT Protective',   0xEF: 'EFI System',
}

ERROR_KEYWORDS = ['error', 'fail', 'critical', 'warn', 'denied', 'refused']
ATTACK_KEYWORDS = ['../', '..\\', 'etc/passwd', 'cmd.exe', 'powershell',
                   'wget ', 'curl ', '<script', 'union select', "' or '1'"]

# ── Size-based carving helpers ─────────────────────────────────────────────────

def _carve_size_pe(data, start):
    if start + 64 > len(data):
        return None
    pe_off = struct.unpack('<I', data[start + 0x3C:start + 0x40])[0]
    pe_abs = start + pe_off
    if pe_abs + 84 > len(data):
        return None
    if data[pe_abs:pe_abs + 4] != b'PE\x00\x00':
        return None
    opt_size = struct.unpack('<H', data[pe_abs + 20:pe_abs + 22])[0]
    if opt_size < 60:
        return None
    size_img = struct.unpack('<I', data[pe_abs + 80:pe_abs + 84])[0]
    if not (512 < size_img <= 200 * 1024 * 1024):
        return None
    return size_img


def _carve_size_mp4(data, start):
    cur = start
    while cur + 8 <= len(data):
        raw = struct.unpack('>I', data[cur:cur + 4])[0]
        if raw == 0:
            return cur - start
        if raw == 1:
            if cur + 16 > len(data):
                break
            box_size = struct.unpack('>Q', data[cur + 8:cur + 16])[0]
        else:
            box_size = raw
        if box_size < 8 or box_size > 2 * 1024 * 1024 * 1024:
            return (cur - start) if cur > start else None
        cur += box_size
    return (cur - start) if cur > start else None


def _carve_size_ole2(data, start):
    if start + 80 > len(data):
        return None
    if data[start:start + 8] != b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1':
        return None
    sector_shift = struct.unpack('<H', data[start + 30:start + 32])[0]
    sector_size = 1 << sector_shift
    num_fat = struct.unpack('<I', data[start + 44:start + 48])[0]
    size = (num_fat * (sector_size // 4) + 1) * sector_size
    return min(size, 50 * 1024 * 1024) if size > sector_size else None


SIGNATURES['exe'] = {
    'label': 'EXE/PE',
    'headers': [b'MZ'],
    'ext': 'exe',
    'size_func': _carve_size_pe,
}
SIGNATURES['doc'] = {
    'label': 'DOC/XLS/PPT (OLE2)',
    'headers': [b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1'],
    'ext': 'doc',
    'size_func': _carve_size_ole2,
}
SIGNATURES['mp4'] = {
    'label': 'MP4/MOV',
    'headers': [b'ftyp'],
    'header_offset': 4,
    'ext': 'mp4',
    'size_func': _carve_size_mp4,
}


# ── 추가 size-based carving helpers ─────────────────────────────────────────────

def _carve_size_bmp(data, start):
    if start + 6 > len(data) or data[start:start + 2] != b'BM':
        return None
    size = struct.unpack('<I', data[start + 2:start + 6])[0]
    return size if 64 < size <= 100 * 1024 * 1024 else None


def _riff_size(data, start, formtype):
    if start + 12 > len(data) or data[start:start + 4] != b'RIFF':
        return None
    if data[start + 8:start + 12] != formtype:
        return None
    size = struct.unpack('<I', data[start + 4:start + 8])[0] + 8
    return size if 12 < size <= 500 * 1024 * 1024 else None


def _carve_size_wav(data, start):
    return _riff_size(data, start, b'WAVE')


def _carve_size_avi(data, start):
    return _riff_size(data, start, b'AVI ')


def _carve_size_webp(data, start):
    return _riff_size(data, start, b'WEBP')


def _carve_size_sqlite(data, start):
    if start + 32 > len(data) or data[start:start + 16] != b'SQLite format 3\x00':
        return None
    page_size = struct.unpack('>H', data[start + 16:start + 18])[0]
    if page_size == 1:
        page_size = 65536
    if page_size < 512 or (page_size & (page_size - 1)) != 0:
        return None
    page_count = struct.unpack('>I', data[start + 28:start + 32])[0]
    size = page_size * page_count
    return size if 0 < size <= 500 * 1024 * 1024 else None


def _carve_size_7z(data, start):
    if start + 32 > len(data) or data[start:start + 6] != b'7z\xBC\xAF\x27\x1C':
        return None
    nh_off = struct.unpack('<Q', data[start + 12:start + 20])[0]
    nh_size = struct.unpack('<Q', data[start + 20:start + 28])[0]
    size = 32 + nh_off + nh_size
    return size if 32 < size <= 500 * 1024 * 1024 else None


def _carve_size_elf(data, start):
    if start + 64 > len(data) or data[start:start + 4] != b'\x7fELF':
        return None
    ei_class, ei_data = data[start + 4], data[start + 5]
    endi = '<' if ei_data == 1 else '>'
    try:
        if ei_class == 1:      # 32-bit
            e_shoff = struct.unpack(endi + 'I', data[start + 32:start + 36])[0]
            e_shentsize = struct.unpack(endi + 'H', data[start + 46:start + 48])[0]
            e_shnum = struct.unpack(endi + 'H', data[start + 48:start + 50])[0]
        elif ei_class == 2:    # 64-bit
            e_shoff = struct.unpack(endi + 'Q', data[start + 40:start + 48])[0]
            e_shentsize = struct.unpack(endi + 'H', data[start + 58:start + 60])[0]
            e_shnum = struct.unpack(endi + 'H', data[start + 60:start + 62])[0]
        else:
            return None
    except struct.error:
        return None
    size = e_shoff + e_shentsize * e_shnum
    return size if 64 < size <= 200 * 1024 * 1024 else None


SIGNATURES['bmp'] = {
    'label': 'BMP', 'headers': [b'BM'], 'ext': 'bmp', 'size_func': _carve_size_bmp,
}
SIGNATURES['wav'] = {
    'label': 'WAV', 'headers': [b'RIFF'], 'ext': 'wav', 'size_func': _carve_size_wav,
}
SIGNATURES['avi'] = {
    'label': 'AVI', 'headers': [b'RIFF'], 'ext': 'avi', 'size_func': _carve_size_avi,
}
SIGNATURES['webp'] = {
    'label': 'WebP', 'headers': [b'RIFF'], 'ext': 'webp', 'size_func': _carve_size_webp,
}
SIGNATURES['sqlite'] = {
    'label': 'SQLite DB', 'headers': [b'SQLite format 3\x00'], 'ext': 'sqlite',
    'size_func': _carve_size_sqlite,
}
SIGNATURES['7z'] = {
    'label': '7-Zip', 'headers': [b'7z\xBC\xAF\x27\x1C'], 'ext': '7z',
    'size_func': _carve_size_7z,
}
SIGNATURES['elf'] = {
    'label': 'ELF (Linux 실행)', 'headers': [b'\x7fELF'], 'ext': 'elf',
    'size_func': _carve_size_elf,
}

# ─────────────────────────────────────────────────────────────────────────────
# Tools index
# ─────────────────────────────────────────────────────────────────────────────
_TOOL_CATALOG = [
    # (url, name, desc, cat, color, icon, pro, keywords)
    ('/tools/hash',          '해시 검증',        'MD5·SHA1·SHA256·SHA512 계산·비교',           '기본',         '#00d4ff', 'bi-fingerprint',          False, 'hash md5 sha 무결성'),
    ('/tools/carve',         '파일 카빙',        '15종 시그니처 복구 (이미지·영상·실행·DB)',   '기본',         '#a78bfa', 'bi-file-earmark-binary',  False, 'carve recovery 복구 bmp wav avi webp sqlite 7z elf'),
    ('/tools/mbr',           'MBR 분석',         'MBR 파티션 테이블 + VBR 스캔',               '기본',         '#f59e0b', 'bi-hdd',                  False, 'mbr partition vbr'),
    ('/tools/mbr-repair',    'MBR 복구',         'VBR 스캔 후 MBR 재건',                       '기본',         '#ef4444', 'bi-hdd-stack',            False, 'mbr repair write'),
    ('/tools/strings',       '문자열 추출',      'ASCII·UTF-16 LE/BE·UTF-32·CJK',              '기본',         '#10b981', 'bi-braces',               False, 'strings ascii unicode utf8'),
    ('/tools/log',           '로그 분석',        'Apache·Nginx·IIS·syslog·journalctl·k8s',     '기본',         '#ef4444', 'bi-journal-text',         False, 'log apache nginx syslog journalctl'),
    ('/tools/gps',           'GPS 추출',         'EXIF GPS → Leaflet 지도',                    '기본',         '#00d4ff', 'bi-geo-alt',              False, 'gps exif map'),
    ('/tools/metadata',      '메타데이터 추출',  'EXIF·PDF·해시·카메라 정보',                  '기본',         '#a78bfa', 'bi-file-earmark-text',    False, 'metadata exif pdf'),
    ('/tools/timeline',      '타임라인 재구성',  'EXIF·PDF·LNK·Prefetch·EML·DOCX 통합',        '기본',         '#06b6d4', 'bi-clock-history',        False, 'timeline event'),
    ('/tools/pcap',          '패킷 분석',        'pcap 프로토콜·IP 통계',                      '기본',         '#06b6d4', 'bi-wifi',                 False, 'pcap network packet'),
    ('/tools/deep-pcap',     '딥 패킷 분석',     'ICS·IoT·DB 80여종 프로토콜 디섹터',          '기본',         '#06b6d4', 'bi-diagram-3',            False, 'deep pcap protocol ics scada iot modbus dnp3 s7comm dns tls mqtt'),
    ('/tools/email',         '이메일 분석',      'EML/MSG/MBOX·스푸핑·헤더',                   '기본',         '#f59e0b', 'bi-envelope-open',        False, 'email eml msg mbox'),
    ('/tools/zipcrack',      'ZIP 암호 해제',    '사전·브루트포스',                            '기본',         '#ef4444', 'bi-file-earmark-zip',     False, 'zip password crack'),
    ('/tools/encrypt',       '파일 암호화',      'AES-256-GCM + PBKDF2',                       '기본',         '#a78bfa', 'bi-shield-lock',          False, 'aes encrypt'),
    ('/tools/registry',      '레지스트리 분석',  'NTUSER·SAM·SYSTEM·하이브 · 50+ 디코더',      '기본',         '#10b981', 'bi-diagram-2',            False, 'registry hive ntuser sam'),
    # 실행파일·디스크
    ('/tools/pe',            'PE/ELF/Mach-O',    '섹션·임포트·의심 API·엔트로피',              '실행파일',     '#00d4ff', 'bi-cpu-fill',             False, 'pe elf macho exe dll'),
    ('/tools/entropy',       '엔트로피·시그',    'Shannon + 매직바이트 50+',                   '실행파일',     '#f59e0b', 'bi-bar-chart-line-fill',  False, 'entropy shannon magic'),
    ('/tools/decode',        '다중 디코더',      'Base64·Hex·ROT·Atbash·Vigenère·XOR·Morse',   '실행파일',     '#f59e0b', 'bi-translate',            False, 'decode base64 rot xor'),
    ('/tools/prefetch',      'Prefetch',          'SCCA·MAM 실행 추적',                         'Windows',      '#10b981', 'bi-fast-forward-fill',    False, 'prefetch scca windows'),
    ('/tools/lnk',           'LNK 바로가기',     'MAC 주소·볼륨·타임스탬프',                   'Windows',      '#00d4ff', 'bi-link-45deg',           False, 'lnk shortcut'),
    ('/tools/diskimg',       '디스크 이미지',    'E01·VHD·VHDX·VMDK·QCOW2·GPT',                '실행파일',     '#a78bfa', 'bi-hdd-network-fill',     False, 'disk image e01 vhd vmdk'),
    # Windows 아티팩트
    ('/tools/evtx',          'EVTX',              'Windows 이벤트 로그 풀 파싱',                'Windows',      '#06b6d4', 'bi-journal-text',         False, 'evtx event log windows'),
    ('/tools/jumplist',      'JumpList',          '.automaticDestinations-ms',                  'Windows',      '#a78bfa', 'bi-bookmark-fill',        False, 'jumplist destlist'),
    ('/tools/mft',           '$MFT 파서',        'NTFS Master File Table',                     'Windows',      '#f59e0b', 'bi-list-columns-reverse', False, 'mft ntfs'),
    ('/tools/esedb',         'ESE DB 헤더',      'SRUDB·Windows.edb',                          'Windows',      '#f59e0b', 'bi-database-fill',        False, 'ese srum esedb'),
    ('/tools/amcache',       'AmCache',           'InventoryApplicationFile',                  'Windows',      '#a78bfa', 'bi-app-indicator',        False, 'amcache inventory'),
    # 문서·DB
    ('/tools/sqlite',        'SQLite 브라우저', 'SELECT 쿼리·테이블 목록',                    '문서·DB',      '#00d4ff', 'bi-database',             False, 'sqlite db query'),
    ('/tools/oledump',       'VBA·OLE 추출',     'Office 매크로·의심 키워드',                  '문서·DB',      '#a78bfa', 'bi-file-earmark-word-fill', False, 'vba ole office macro'),
    ('/tools/pdfscan',       'PDF 악성 분석',    'JavaScript·OpenAction·EmbeddedFile',         '문서·DB',      '#ef4444', 'bi-file-earmark-pdf-fill', False, 'pdf javascript malware'),
    ('/tools/plist',         'Plist 파서',       'macOS bplist/XML',                           'macOS·모바일', '#10b981', 'bi-apple',                False, 'plist bplist macos apple'),
    ('/tools/spreadsheet',   'CSV/Excel 뷰어',   'CSV·TSV·XLSX',                                '유틸',         '#06b6d4', 'bi-table',                False, 'csv excel xlsx'),
    ('/tools/docker',        'Docker 이미지',    'tar 레이어·환경변수·이력',                   '클라우드',     '#3b82f6', 'bi-box-fill',             False, 'docker container image'),
    # 보안·암호
    ('/tools/jwt',           'JWT 디코더',       'Header·Payload·서명 검증·alg none',          '암호',         '#f59e0b', 'bi-key-fill',             False, 'jwt token alg'),
    ('/tools/cert',          'X.509 인증서',     'PEM·DER·PKCS12·SAN·만료',                    '암호',         '#22c55e', 'bi-shield-fill-check',    False, 'x509 cert pem der pkcs12'),
    ('/tools/yara',          'YARA 스캐너',      '문자열·헥스 패턴 매칭',                      '악성·위협',     '#ef4444', 'bi-search',               False, 'yara rule scan'),
    ('/tools/secrets',       'Secret 스캐너',    'AWS·GCP·GitHub·Slack 22종 패턴',              '암호',         '#ef4444', 'bi-shield-lock-fill',     False, 'secret api key aws gcp'),
    ('/tools/passwd',        '암호 강도',        'Shannon 엔트로피·크랙시간',                  '암호',         '#22c55e', 'bi-key',                  False, 'password strength entropy'),
    ('/tools/stego',         '스테가노그래피',   'LSB·EOI·임베디드 시그',                       '악성·위협',     '#a78bfa', 'bi-eye-fill',             False, 'stego steganography lsb'),
    ('/tools/hexdiff',       '헥스 비교',        '두 파일 바이트별 diff',                      '유틸',         '#f59e0b', 'bi-distribute-horizontal',False, 'hex diff binary compare'),
    # 네트워크·메일
    ('/tools/email-auth',    'SPF/DKIM/DMARC',   'DNS 조회 + 헤더 검증',                       '네트워크',     '#22c55e', 'bi-envelope-check-fill',  False, 'spf dkim dmarc email'),
    ('/tools/dns',           'DNS·DGA 탐지',     '도메인 → DGA 점수',                          '네트워크',     '#06b6d4', 'bi-broadcast',            False, 'dns dga domain'),
    ('/tools/whois',         'WHOIS·IP',         '도메인·IP 정보·RFC1918',                     '네트워크',     '#00d4ff', 'bi-globe-asia-australia', False, 'whois ip rir'),
    # 이미지·기타
    ('/tools/qr',            'QR/바코드',        'pyzbar QR/EAN/Code128',                      '이미지',       '#10b981', 'bi-qr-code-scan',         False, 'qr barcode'),
    ('/tools/ocr',           '이미지 OCR',       'tesseract 한·영·일·중',                       '이미지',       '#06b6d4', 'bi-card-text',            False, 'ocr tesseract text'),
    ('/tools/phash',         '이미지 유사도',    'aHash + Hamming 거리',                       '이미지',       '#a78bfa', 'bi-images',               False, 'phash similar image'),
    ('/tools/git',           'Git 저장소',       '.git ZIP → 커밋·blob·logs',                  '유틸',         '#f59e0b', 'bi-git',                  False, 'git repo commit'),
    # macOS·모바일
    ('/tools/heif',          'HEIC/HEIF',        'iOS 14+ 사진·EXIF',                          'macOS·모바일', '#10b981', 'bi-image-fill',           False, 'heic heif ios image'),
    ('/tools/ios-backup',    'iOS Manifest.db',  '백업 도메인·앱 분류',                        'macOS·모바일', '#a78bfa', 'bi-phone-fill',           False, 'ios manifest backup'),
    ('/tools/apk',           'APK 분석',         'manifest·permissions·인증서',                'macOS·모바일', '#22c55e', 'bi-android2',             False, 'apk android manifest'),
    ('/tools/whatsapp',      'WhatsApp DB',      'msgstore.db 평문/암호화',                    'macOS·모바일', '#22c55e', 'bi-whatsapp',             False, 'whatsapp msgstore'),
    ('/tools/telegram',      'Telegram tdata',   'Telegram Desktop 캐시',                      'macOS·모바일', '#06b6d4', 'bi-telegram',             False, 'telegram tdata'),
    ('/tools/pst',           'Outlook PST/OST',  '!BDN 헤더·암호화',                            'macOS·모바일', '#f59e0b', 'bi-envelope-fill',        False, 'outlook pst ost'),
    # 악성·위협
    ('/tools/amcache',       'AmCache',          'InventoryApplicationFile',                   '악성·위협',     '#a78bfa', 'bi-app-indicator',        False, 'amcache windows'),
    ('/tools/sigma',         'Sigma 규칙',       'YAML 룰 → JSON 이벤트 매칭',                 '악성·위협',     '#ef4444', 'bi-search-heart',         False, 'sigma rule detection'),
    ('/tools/psdeobf',       'PowerShell 디오브푸', 'Base64·char[]·연결 자동 펴기',           '악성·위협',     '#a78bfa', 'bi-arrow-clockwise',      False, 'powershell deobfuscate'),
    ('/tools/jsdeobf',       'JS 디오브푸',      'eval·\\xNN·atob·fromCharCode',                '악성·위협',     '#f59e0b', 'bi-filetype-js',          False, 'javascript deobfuscate eval'),
    ('/tools/ioc',           'IOC 추출기',       '15종 패턴 자동 추출',                        '악성·위협',     '#ef4444', 'bi-search',               False, 'ioc indicator extract'),
    ('/tools/cuckoo',        'Cuckoo/CAPE',      '샌드박스 리포트 JSON',                       '악성·위협',     '#ef4444', 'bi-bug-fill',             False, 'cuckoo cape sandbox'),
    ('/tools/memscan',       '메모리 IOC 스캔',  'RAW 덤프 → IOC 추출',                        '악성·위협',     '#a78bfa', 'bi-memory',               False, 'memory scan ioc'),
    ('/tools/cve',           'CVE 검색',         '내장 CVE DB',                                '악성·위협',     '#ef4444', 'bi-bug',                  False, 'cve vulnerability'),
    ('/tools/hashlookup',    '해시 룩업',        '알려진 양성/악성 DB',                        '악성·위협',     '#22c55e', 'bi-fingerprint',          False, 'hash lookup nsrl'),
    # 네트워크·로그
    ('/tools/har',           'HAR 분석',         '브라우저 캡처 파싱',                         '네트워크',     '#00d4ff', 'bi-globe2',               False, 'har browser'),
    ('/tools/dmesg',         'dmesg/journalctl', 'Linux 커널·systemd',                         '네트워크',     '#06b6d4', 'bi-terminal-fill',        False, 'dmesg journalctl linux'),
    ('/tools/cidr',          'CIDR 계산기',      '서브넷·사설/공용 분류',                      '네트워크',     '#06b6d4', 'bi-diagram-3',            False, 'cidr subnet ip'),
    # 유틸리티
    ('/tools/time',          '시간 변환기',      'Unix·FILETIME·Chrome·Cocoa·DOS·HFS',         '유틸',         '#00d4ff', 'bi-clock-history',        False, 'time epoch filetime'),
    ('/tools/magic',         '매직바이트 DB',    '100+ 시그니처 매칭',                          '유틸',         '#f59e0b', 'bi-tag-fill',             False, 'magic signature bytes'),
    ('/tools/hex',           'Hex Viewer',       '헥스 + ASCII + 검색',                        '유틸',         '#a78bfa', 'bi-code',                 False, 'hex viewer dump'),
    ('/tools/regex',         '정규식 테스터',    '매칭·그룹·치환',                             '유틸',         '#10b981', 'bi-regex',                False, 'regex pattern test'),
    ('/tools/convert',       'JSON/XML/YAML',    '형식 자동 감지 변환',                        '유틸',         '#06b6d4', 'bi-arrow-left-right',     False, 'json xml yaml convert'),
    ('/tools/textdiff',      '텍스트 Diff',      'Unified diff 비교',                          '유틸',         '#f59e0b', 'bi-file-diff',            False, 'diff text compare'),
    ('/tools/wordlist',      'Wordlist 생성',    'leet·연도·기호 변형',                         '유틸',         '#a78bfa', 'bi-list-ol',              False, 'wordlist password dictionary'),
    # 4차 추가
    ('/tools/httpsec',       'HTTP 보안 헤더',   'HSTS·CSP·X-Frame 검사',                      '네트워크·보안','#22c55e', 'bi-shield-check',         False, 'http header security csp hsts'),
    ('/tools/tls',           'TLS 인증서',       'host:port → 체인·SAN·만료',                  '네트워크·보안','#22c55e', 'bi-shield-lock-fill',     False, 'tls ssl certificate'),
    ('/tools/portscan',      '포트 스캐너',      '40+ 포트·배너 그래빙',                       '네트워크·보안','#ef4444', 'bi-ethernet',             False, 'port scan banner'),
    ('/tools/dnslookup',     'DNS 종합',         'A·AAAA·MX·NS·TXT·SPF',                        '네트워크·보안','#06b6d4', 'bi-broadcast',            False, 'dns lookup record'),
    ('/tools/geoip',         'GeoIP·IP 분류',    '사설/공용·RIR·역방향 DNS',                   '네트워크·보안','#00d4ff', 'bi-geo-alt-fill',         False, 'geoip ip rir'),
    ('/tools/cidrcompare',   'CIDR 다중 비교',   '여러 IP·CIDR 매칭',                          '네트워크·보안','#06b6d4', 'bi-diagram-3',            False, 'cidr multi ip subnet'),
    ('/tools/urlsafe',       'URL 안전 분석',    'Punycode·피싱·단축 탐지',                    '네트워크·보안','#f59e0b', 'bi-link',                 False, 'url phishing safety'),
    ('/tools/uaparse',       'User-Agent 파서',  '브라우저·OS·봇',                              '네트워크·보안','#06b6d4', 'bi-window',               False, 'user agent ua parse'),
    ('/tools/emaildeep',     '이메일 헤더 심층', '경유 IP·X-헤더·도메인 불일치',               '네트워크·보안','#22c55e', 'bi-envelope-fill',        False, 'email header deep'),
    ('/tools/multihash',     '다중 해시',        'MD5·SHA·BLAKE·CRC 동시',                      '암호·서명',    '#00d4ff', 'bi-fingerprint',          False, 'multi hash'),
    ('/tools/sign',          'HMAC/RSA/ECDSA',   '서명 검증·HMAC 계산',                        '암호·서명',    '#a78bfa', 'bi-pen-fill',             False, 'hmac rsa ecdsa signature'),
    ('/tools/jwe',           'JWE/JWS',          '5-part JWE 분해',                            '암호·서명',    '#f59e0b', 'bi-key-fill',             False, 'jwe jws jose'),
    ('/tools/pgp',           'PGP 메시지',       '패킷 태그 파싱',                             '암호·서명',    '#22c55e', 'bi-envelope-paper',       False, 'pgp gpg message'),
    ('/tools/pkcs7',         'PKCS#7/CMS',       '인증서 번들',                                 '암호·서명',    '#3b82f6', 'bi-collection',           False, 'pkcs7 cms certificate'),
    ('/tools/sshhosts',      'SSH known_hosts',  '호스트·해시·키 타입',                        '암호·서명',    '#06b6d4', 'bi-terminal',             False, 'ssh known hosts'),
    ('/tools/gpgkey',        'GPG 키 분석',      '패킷·UserID·서명',                           '암호·서명',    '#22c55e', 'bi-key',                  False, 'gpg pgp key'),
    # iOS
    ('/tools/ios-sms',       'iOS SMS',          'sms.db 메시지·iMessage',                     'iOS',          '#22c55e', 'bi-chat-dots-fill',       False, 'ios sms imessage'),
    ('/tools/ios-photos',    'iOS Photos',       'Photos.sqlite 메타',                         'iOS',          '#06b6d4', 'bi-camera-fill',          False, 'ios photos'),
    ('/tools/ios-calendar',  'iOS Calendar',     'Calendar.sqlitedb',                          'iOS',          '#a78bfa', 'bi-calendar-event-fill',  False, 'ios calendar'),
    ('/tools/ios-notes',     'iOS Notes',        'NoteStore.sqlite',                           'iOS',          '#f59e0b', 'bi-journal-text',         False, 'ios notes'),
    ('/tools/ios-health',    'iOS Health',       'healthdb_secure.sqlite',                      'iOS',          '#ef4444', 'bi-heart-pulse-fill',     False, 'ios health'),
    # Android
    ('/tools/android-contacts','Android 연락처', 'contacts2.db',                               'Android',      '#22c55e', 'bi-person-rolodex',       False, 'android contacts'),
    ('/tools/android-sms',   'Android SMS',      'mmssms.db',                                  'Android',      '#06b6d4', 'bi-chat-fill',            False, 'android sms mms'),
    ('/tools/android-calllog','Android 통화',    'calllog.db',                                 'Android',      '#a78bfa', 'bi-telephone-fill',       False, 'android calllog'),
    ('/tools/android-wifi',  'Android Wi-Fi',    'wpa_supplicant.conf',                        'Android',      '#f59e0b', 'bi-wifi',                 False, 'android wifi wpa'),
    # macOS
    ('/tools/fsevents',      'FSEvents',         '.fseventsd 로그',                            'macOS',        '#10b981', 'bi-eye-fill',             False, 'fsevents macos'),
    ('/tools/knowledgec',    'KnowledgeC.db',    '앱 사용·잠금 이력',                          'macOS',        '#06b6d4', 'bi-clock-fill',           False, 'knowledgec macos usage'),
    ('/tools/quarantine',    'Quarantine',       'Gatekeeper 격리 이력',                       'macOS',        '#ef4444', 'bi-shield-x',             False, 'quarantine gatekeeper macos'),
    ('/tools/spotlight',     'Spotlight',        'store.db 헤더',                              'macOS',        '#00d4ff', 'bi-search',               False, 'spotlight macos'),
    ('/tools/keychain',      'Keychain',         '.keychain · keychain-2.db',                   'macOS',        '#f59e0b', 'bi-key-fill',             False, 'keychain macos'),
    ('/tools/tcc',           'TCC.db',           '권한 부여 이력',                             'macOS',        '#ef4444', 'bi-shield-shaded',        False, 'tcc macos permission'),
    ('/tools/tracev3',       'tracev3',          'Unified Log 청크 구조',                      'macOS',        '#06b6d4', 'bi-journal-code',         False, 'tracev3 unified log macos'),
    # 브라우저
    ('/tools/chromecache',   'Chrome Cache',     'data_*·f_* 파싱',                            '브라우저',     '#3b82f6', 'bi-browser-chrome',       False, 'chrome cache'),
    ('/tools/firefoxcache',  'Firefox cache2',   '메타데이터 64B 푸터',                        '브라우저',     '#f59e0b', 'bi-browser-firefox',      False, 'firefox cache2'),
    ('/tools/localstorage',  'LocalStorage',     'SQLite/LevelDB',                              '브라우저',     '#06b6d4', 'bi-database',             False, 'localstorage browser'),
    ('/tools/indexeddb',     'IndexedDB',        'LevelDB 문자열',                              '브라우저',     '#a78bfa', 'bi-database-fill',        False, 'indexeddb browser'),
    # 클라우드
    ('/tools/dockerfile',    'Dockerfile 보안',  'USER·latest·하드코딩 검사',                  '클라우드',     '#3b82f6', 'bi-box-fill',             False, 'dockerfile security'),
    ('/tools/k8sec',         'Kubernetes 보안',  'privileged·root·capabilities',               '클라우드',     '#06b6d4', 'bi-diagram-3-fill',       False, 'kubernetes k8s security'),
    ('/tools/terraform',     'Terraform tfstate', '상태 파일 리소스',                          '클라우드',     '#a78bfa', 'bi-cloud-fill',           False, 'terraform tfstate'),
    ('/tools/cloudtrail',    'AWS CloudTrail',   'AWS 감사 로그',                              '클라우드',     '#f59e0b', 'bi-cloud-fill',           False, 'aws cloudtrail'),
    ('/tools/azureactivity', 'Azure Activity',   'Azure 활동 로그',                            '클라우드',     '#3b82f6', 'bi-cloud-fill',           False, 'azure activity'),
    ('/tools/gcpaudit',      'GCP Audit',        'GCP 감사 로그',                              '클라우드',     '#22c55e', 'bi-cloud-fill',           False, 'gcp audit'),
    ('/tools/k8saudit',      'K8s Audit',        'Kubernetes 감사 로그',                       '클라우드',     '#06b6d4', 'bi-cloud-fill',           False, 'kubernetes audit'),
    ('/tools/o365audit',     'O365 Audit',       'Office 365 활동',                            '클라우드',     '#3b82f6', 'bi-cloud-fill',           False, 'office365 o365 audit'),
    ('/tools/pkgvuln',       '패키지 취약점',    'package.json·requirements.txt',              '클라우드',     '#ef4444', 'bi-shield-exclamation',   False, 'package vuln cve npm pip'),
    # 악성 강화
    ('/tools/vbastomp',      'VBA Stomping',     'p-code vs 소스 비교',                        '악성·위협',     '#ef4444', 'bi-incognito',            False, 'vba stomping macro'),
    ('/tools/xlm',           'XLM 4.0 매크로',   'Excel 4.0 매크로',                           '악성·위협',     '#f59e0b', 'bi-file-spreadsheet',     False, 'xlm excel macro'),
    ('/tools/msi',           'MSI Installer',    'Windows Installer 분석',                     '악성·위협',     '#3b82f6', 'bi-windows',              False, 'msi windows installer'),
    ('/tools/msix',          'MSIX/UWP',         'AppxManifest·capabilities',                  '악성·위협',     '#06b6d4', 'bi-app',                  False, 'msix uwp appx'),
    ('/tools/chm',           'CHM Help',         'ITSF·script·URL',                            '악성·위협',     '#ef4444', 'bi-question-circle-fill', False, 'chm help malware'),
    ('/tools/gobin',         'Go/Rust 바이너리', 'buildinfo·모듈명',                           '실행파일',     '#22c55e', 'bi-filetype-exe',         False, 'go rust binary'),
    ('/tools/dotnet',        '.NET 어셈블리',    'BSJB·CIL 타입',                              '실행파일',     '#a78bfa', 'bi-cpu',                  False, 'dotnet cli assembly'),
    ('/tools/applocker',     'AppLocker',        'XML 정책 룰',                                '악성·위협',     '#22c55e', 'bi-shield-fill-check',    False, 'applocker policy'),
    # 압축·이미지
    ('/tools/iso',           'ISO 이미지',       'ISO9660 PVD',                                '압축',         '#06b6d4', 'bi-disc',                 False, 'iso 9660'),
    ('/tools/dmg',           'macOS DMG',        'koly 푸터',                                  '압축',         '#a78bfa', 'bi-hdd-fill',             False, 'dmg apple disk'),
    ('/tools/rar',           'RAR',              'RAR4/RAR5',                                  '압축',         '#f59e0b', 'bi-file-zip',             False, 'rar archive'),
    ('/tools/sevenz',        '7-Zip',            '7-Zip 헤더',                                 '압축',         '#3b82f6', 'bi-file-earmark-zip',     False, '7zip 7z'),
    ('/tools/tar',           'TAR',              'tar 멤버 메타',                              '압축',         '#06b6d4', 'bi-archive',              False, 'tar unix'),
    ('/tools/cab',           'CAB',              'Microsoft Cabinet',                           '압축',         '#f59e0b', 'bi-file-earmark-binary',  False, 'cab cabinet windows'),
    ('/tools/gzmeta',        'GZIP 메타',        'mtime·원본명·OS',                            '압축',         '#22c55e', 'bi-file-zip-fill',        False, 'gzip metadata'),
    # 자동·통합
    ('/tools/auto',          '자동 라우터',      '시그니처 → 도구 추천',                       '자동',         '#00d4ff', 'bi-magic',                False, 'auto router classify'),
    ('/tools/autoanalyze',   '자동 분석',        '시그+엔트로피+IOC 종합',                     '자동',         '#00d4ff', 'bi-magic',                False, 'auto analyze'),
    ('/tools/zipsearch',     'ZIP 내부 검색',    '키워드 검색',                                '자동',         '#f59e0b', 'bi-search',               False, 'zip search'),
    ('/tools/triage',        '트리아지 ZIP',     '통합 타임라인 + 12종 아티팩트',              '자동',         '#00d4ff', 'bi-box-seam-fill',        False, 'triage zip integrated'),
    ('/tools/triagediff',    '트리아지 비교',    '두 ZIP 차이 확인',                           '자동',         '#06b6d4', 'bi-files',                False, 'triage diff zip'),
    ('/tools/report-pdf',    'PDF 보고서',       '분석 이력 → PDF 가이드',                     '자동',         '#a78bfa', 'bi-file-earmark-pdf',     False, 'pdf report'),
    ('/tools/encoding',      '인코딩 변환',      'BOM·자동 감지·변환',                         '유틸',         '#06b6d4', 'bi-translate',            False, 'encoding utf8 bom'),
    ('/tools/markdown',      'Markdown 렌더',    '간단 마크다운 → HTML',                       '유틸',         '#a78bfa', 'bi-markdown',             False, 'markdown md'),
    # PRO (5차)
    ('/tools/vol-full',      'Volatility 풀',    '23개 플러그인 메모리 분석',                  '🏆 PRO',       '#ef4444', 'bi-cpu-fill',             True,  'volatility memory pslist malfind'),
    ('/tools/aleapp',        'ALEAPP Android',   '200+ 아티팩트 자동',                         '🏆 PRO',       '#22c55e', 'bi-android2',             True,  'aleapp android leapp'),
    ('/tools/ileapp',        'iLEAPP iOS',       '300+ 아티팩트 자동',                          '🏆 PRO',       '#06b6d4', 'bi-phone',                True,  'ileapp ios leapp'),
    ('/tools/e01-mount',     'E01 / EnCase',     'libewf 이미지 분석',                          '🏆 PRO',       '#a78bfa', 'bi-hdd-rack-fill',        True,  'e01 encase ewf'),
    ('/tools/mft-full',      'MFT 풀 파싱',      'pytsk3 파일시스템',                          '🏆 PRO',       '#f59e0b', 'bi-list-columns-reverse', True,  'mft pytsk full'),
    ('/tools/hashcat-job',   'Hashcat',          '30+ 모드 해시 크래킹',                       '🏆 PRO',       '#ef4444', 'bi-shield-lock',          True,  'hashcat crack hash'),
    ('/tools/unlock',        '암호화 해제',      'BitLocker·LUKS·VeraCrypt·ZIP/Office/PDF',    '🏆 PRO',       '#ef4444', 'bi-unlock-fill',          True,  'unlock decrypt bitlocker luks veracrypt zip office pdf crack'),
    ('/tools/honeytrap',     'AI 허니트랩',      'LLM 에이전트 탐지·차단·박제',                '🏆 PRO',       '#ef4444', 'bi-bug-fill',             True,  'honeytrap ai agent llm canary honeypot block defense'),
    ('/tools/llm-report',    'LLM 보고서',       'Claude API 자동 보고서',                     '🏆 PRO',       '#a78bfa', 'bi-robot',                True,  'llm claude ai report'),
    ('/tools/coc',           'Chain of Custody', 'SHA-256 해시 체인',                          '🏆 PRO',       '#00d4ff', 'bi-link-45deg',           True,  'chain custody coc'),
    ('/tools/jobs',          '백그라운드 작업',  '작업 큐 모니터링',                           '🏆 PRO',       '#3b82f6', 'bi-cpu',                  True,  'jobs queue background'),
    # 6차 엔터프라이즈
    ('/tools/case',          '사건 관리',        '사건·증거·발견 추적',                        '🏢 엔터프라이즈','#00d4ff', 'bi-folder-fill',          True,  'case management evidence'),
    ('/tools/search',        '전체 검색',        '풀텍스트 FTS5',                              '🏢 엔터프라이즈','#22c55e', 'bi-search',               True,  'search fulltext fts'),
    ('/tools/dashboard',     '대시보드',         '통계·그래프·최근활동',                       '🏢 엔터프라이즈','#06b6d4', 'bi-speedometer2',         True,  'dashboard stats'),
    ('/tools/attack',        'MITRE ATT&CK',     '기법 자동 매핑',                             '🏢 엔터프라이즈','#ef4444', 'bi-bullseye',             True,  'mitre attack technique'),
    ('/tools/threat-intel',  '위협 인텔',        'VirusTotal·AbuseIPDB',                       '🏢 엔터프라이즈','#f59e0b', 'bi-radar',                True,  'threat intel virustotal abuseipdb'),
    ('/tools/ai-classify',   'AI 자동 분류',     'OpenCV·시그·키워드 종합',                    '🏢 엔터프라이즈','#a78bfa', 'bi-robot',                True,  'ai classify opencv'),
    ('/tools/plaso',         'Plaso 슈퍼 타임라인','log2timeline·psort 자동',                  '🏢 엔터프라이즈','#06b6d4', 'bi-stack',                True,  'plaso log2timeline super'),
    ('/tools/ocr-index',     'OCR 인덱싱',       '이미지/PDF → 풀텍스트 검색',                 '🏢 엔터프라이즈','#22c55e', 'bi-search',               True,  'ocr index search'),
    ('/tools/face',          '얼굴 인식',        'OpenCV Haar 얼굴/눈 감지',                   '🏢 엔터프라이즈','#a78bfa', 'bi-person-bounding-box',  True,  'face recognition opencv'),
    # 다운로드 허브
    ('/tools/scripts',       '로컬 스크립트',    '9종 다운로드 (RAM·Vol3·USB·트리아지)',       '다운로드',     '#f59e0b', 'bi-download',             False, 'local script download volatility memory'),
    ('/tools/verify',        '체크섬 검증',      'SHA-256 일치 검사',                          '다운로드',     '#22c55e', 'bi-shield-check',         False, 'checksum verify'),
    ('/tools/history',       '분석 이력',        '내 분석 기록',                               '다운로드',     '#06b6d4', 'bi-archive',              False, 'history archive'),
]

def _build_tool_catalog():
    return [{'url': u, 'name': n, 'desc': d, 'cat': c, 'color': col,
             'icon': i, 'pro': p, 'keywords': k}
            for u, n, d, c, col, i, p, k in _TOOL_CATALOG]


@bp.route('/')
def index():
    return render_template('tools/index.html', tools=_build_tool_catalog())


# ─────────────────────────────────────────────────────────────────────────────
# DB logging helper
# ─────────────────────────────────────────────────────────────────────────────
def _save_log(tool, tool_label, filename, file_size, summary, result=None):
    try:
        from monitor import db as _db
        from monitor.models import AnalysisLog
        result_json = None
        if result is not None:
            try:
                result_json = _json.dumps(result, ensure_ascii=False, default=str)
                if len(result_json) > 400_000:
                    result_json = None
            except Exception:
                pass
        log = AnalysisLog(
            tool=tool, tool_label=tool_label,
            filename=filename, file_size=file_size,
            summary=summary, result_json=result_json,
            user_id=session.get('user_id'),
        )
        _db.session.add(log)
        _db.session.commit()
        return log.share_token
    except Exception:
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Hash calculator — 6 modes
# ─────────────────────────────────────────────────────────────────────────────
def _compute_hashes(data, algos):
    out = {}
    for algo in algos:
        h = hashlib.new(algo)
        h.update(data)
        out[algo.upper()] = h.hexdigest()
    return out


def _read_input(file_key, text_key):
    """파일 또는 텍스트 입력을 읽어 (data, name) 반환."""
    f = request.files.get(file_key)
    if f and f.filename:
        return f.read(MAX_UPLOAD), f.filename
    txt = request.form.get(text_key, '').strip()
    if txt:
        return txt.encode('utf-8'), '(직접 입력)'
    return None, None


@bp.route('/hash', methods=['GET', 'POST'])
def hash_tool():
    results = None
    error   = None
    share_token  = None
    active_mode  = 'single'

    if request.method == 'POST':
        active_mode = request.form.get('mode', 'single')
        algos = request.form.getlist('algos') or ['md5', 'sha1', 'sha256', 'sha512']

        try:
            # ── 1. 단일 계산 ──────────────────────────────────────
            if active_mode == 'single':
                data, name = _read_input('file', 'text')
                if data is None:
                    error = '파일 또는 텍스트를 입력하세요.'
                else:
                    hashes  = _compute_hashes(data, algos)
                    compare = request.form.get('compare', '').strip().lower()
                    match   = (compare in [v.lower() for v in hashes.values()]) if compare else None
                    results = {'mode': 'single', 'name': name, 'size': len(data),
                               'hashes': hashes, 'compare': compare, 'match': match}
                    summary = f"{name} | {len(data):,}B | MD5: {hashes.get('MD5','')[:16]}..."
                    share_token = _save_log('hash', '해시 검증', name, len(data), summary, results)

            # ── 2. 파일 vs 파일 ───────────────────────────────────
            elif active_mode == 'file_vs_file':
                f1 = request.files.get('file1')
                f2 = request.files.get('file2')
                if not (f1 and f1.filename and f2 and f2.filename):
                    error = '두 파일을 모두 선택하세요.'
                else:
                    d1, d2 = f1.read(MAX_UPLOAD), f2.read(MAX_UPLOAD)
                    h1, h2 = _compute_hashes(d1, algos), _compute_hashes(d2, algos)
                    match  = all(h1[a.upper()] == h2[a.upper()] for a in algos)
                    results = {'mode': 'file_vs_file',
                               'name1': f1.filename, 'size1': len(d1), 'hashes1': h1,
                               'name2': f2.filename, 'size2': len(d2), 'hashes2': h2,
                               'match': match}
                    summary = f"파일 비교: {f1.filename} vs {f2.filename} | {'일치' if match else '불일치'}"
                    share_token = _save_log('hash', '해시 비교(파일↔파일)',
                                            f1.filename, len(d1) + len(d2), summary, results)

            # ── 3. 텍스트 vs 텍스트 ──────────────────────────────
            elif active_mode == 'text_vs_text':
                t1 = request.form.get('text1', '').strip()
                t2 = request.form.get('text2', '').strip()
                if not t1 or not t2:
                    error = '두 텍스트를 모두 입력하세요.'
                else:
                    d1, d2 = t1.encode('utf-8'), t2.encode('utf-8')
                    h1, h2 = _compute_hashes(d1, algos), _compute_hashes(d2, algos)
                    match  = all(h1[a.upper()] == h2[a.upper()] for a in algos)
                    results = {'mode': 'text_vs_text',
                               'text1': t1[:300], 'size1': len(d1), 'hashes1': h1,
                               'text2': t2[:300], 'size2': len(d2), 'hashes2': h2,
                               'match': match}
                    summary = f"텍스트 비교 | {'일치' if match else '불일치'}"
                    share_token = _save_log('hash', '해시 비교(텍스트↔텍스트)',
                                            '(텍스트)', len(d1) + len(d2), summary, results)

            # ── 4. 텍스트 vs 파일 ────────────────────────────────
            elif active_mode == 'text_vs_file':
                txt = request.form.get('text', '').strip()
                f   = request.files.get('file')
                if not txt:
                    error = '텍스트를 입력하세요.'
                elif not (f and f.filename):
                    error = '파일을 선택하세요.'
                else:
                    d_t = txt.encode('utf-8')
                    d_f = f.read(MAX_UPLOAD)
                    h_t = _compute_hashes(d_t, algos)
                    h_f = _compute_hashes(d_f, algos)
                    match = all(h_t[a.upper()] == h_f[a.upper()] for a in algos)
                    results = {'mode': 'text_vs_file',
                               'text': txt[:300], 'size_t': len(d_t), 'hashes_t': h_t,
                               'filename': f.filename, 'size_f': len(d_f), 'hashes_f': h_f,
                               'match': match}
                    summary = f"텍스트↔파일({f.filename}) | {'일치' if match else '불일치'}"
                    share_token = _save_log('hash', '해시 비교(텍스트↔파일)',
                                            f.filename, len(d_f), summary, results)

            # ── 5. HMAC 계산 ──────────────────────────────────────
            elif active_mode == 'hmac':
                key      = request.form.get('hmac_key', '').strip()
                key_enc  = request.form.get('key_encoding', 'utf8')
                hmac_algo = request.form.get('hmac_algo', 'sha256')
                data, name = _read_input('file', 'text')

                if not key:
                    error = '비밀 키를 입력하세요.'
                elif data is None:
                    error = '파일 또는 텍스트를 입력하세요.'
                else:
                    if key_enc == 'hex':
                        try:
                            key_bytes = bytes.fromhex(key.replace(' ', ''))
                        except ValueError:
                            raise ValueError('키가 유효한 16진수 형식이 아닙니다.')
                    else:
                        key_bytes = key.encode('utf-8')

                    h = _hmac_mod.new(key_bytes, data, hmac_algo)
                    hmac_val = h.hexdigest()
                    compare  = request.form.get('compare', '').strip()
                    match    = (_hmac_mod.compare_digest(compare.lower(), hmac_val.lower())
                                if compare else None)
                    results = {'mode': 'hmac', 'name': name, 'size': len(data),
                               'algo': hmac_algo.upper(), 'hmac': hmac_val,
                               'compare': compare, 'match': match}
                    summary = f"HMAC-{hmac_algo.upper()} | {name} | {hmac_val[:16]}..."
                    share_token = _save_log('hash', 'HMAC 계산', name, len(data), summary,
                                            {'mode': 'hmac', 'algo': hmac_algo, 'hmac': hmac_val})

            # ── 6. 배치 해시 ──────────────────────────────────────
            elif active_mode == 'batch':
                files = [f for f in request.files.getlist('files') if f and f.filename]
                if not files:
                    error = '파일을 하나 이상 선택하세요.'
                else:
                    batch = []
                    for f in files:
                        data   = f.read(MAX_UPLOAD)
                        hashes = _compute_hashes(data, algos)
                        batch.append({'name': f.filename, 'size': len(data), 'hashes': hashes})

                    first_algo = algos[0].upper()
                    hash_groups: dict = {}
                    for item in batch:
                        h = item['hashes'][first_algo]
                        hash_groups.setdefault(h, []).append(item['name'])
                    duplicates = {h: names for h, names in hash_groups.items() if len(names) > 1}

                    results = {'mode': 'batch', 'algos': [a.upper() for a in algos],
                               'files': batch, 'duplicates': duplicates}
                    total_size = sum(f['size'] for f in batch)
                    summary = (f"배치 해시 | {len(batch)}개 파일 | "
                               f"중복 그룹 {len(duplicates)}개")
                    share_token = _save_log('hash', '배치 해시', f'{len(batch)}개 파일',
                                            total_size, summary,
                                            {'mode': 'batch', 'count': len(batch),
                                             'dup_groups': len(duplicates)})

        except Exception as e:
            error = str(e)

    return render_template('tools/hash.html', results=results, error=error,
                           share_token=share_token, active_mode=active_mode)


# ─────────────────────────────────────────────────────────────────────────────
# File carver
# ─────────────────────────────────────────────────────────────────────────────
def _carve(data, sig_key):
    sig = SIGNATURES[sig_key]
    size_func = sig.get('size_func')
    hdr_offset = sig.get('header_offset', 0)
    found = []
    pos = 0

    if size_func:
        while True:
            header_idx = -1
            for hdr in sig['headers']:
                idx = data.find(hdr, pos)
                if idx != -1 and (header_idx == -1 or idx < header_idx):
                    header_idx = idx
            if header_idx == -1:
                break
            file_start = header_idx - hdr_offset
            if file_start < 0:
                pos = header_idx + max(len(sig['headers'][0]), 4)
                continue
            size = size_func(data, file_start)
            if size and size >= 16:
                end = file_start + size
                content = data[file_start:min(end, len(data))]
                found.append({
                    'type': sig['label'], 'ext': sig['ext'],
                    'offset_dec': file_start, 'offset_hex': hex(file_start),
                    'sector': file_start // 512, 'size': len(content),
                    'data': content,
                })
                pos = end
            else:
                pos = header_idx + max(len(sig['headers'][0]), 4)
    else:
        while True:
            header_idx = -1
            for hdr in sig['headers']:
                idx = data.find(hdr, pos)
                if idx != -1 and (header_idx == -1 or idx < header_idx):
                    header_idx = idx
            if header_idx == -1:
                break
            footer_idx = data.find(sig['footer'], header_idx + 4)
            if footer_idx != -1:
                end = footer_idx + len(sig['footer'])
                content = data[header_idx:end]
                found.append({
                    'type': sig['label'], 'ext': sig['ext'],
                    'offset_dec': header_idx, 'offset_hex': hex(header_idx),
                    'sector': header_idx // 512, 'size': len(content),
                    'data': content,
                })
                pos = end
            else:
                pos = header_idx + 4
    return found


@bp.route('/carve', methods=['GET', 'POST'])
def carve_tool():
    results = None
    error = None
    download_id = None
    share_token = None

    if request.method == 'POST':
        try:
            f = request.files.get('file')
            if not f or not f.filename:
                error = '파일을 선택하세요.'
                return render_template('tools/carve.html', error=error,
                                       signatures=SIGNATURES)

            selected = request.form.getlist('types') or list(SIGNATURES.keys())
            data = f.read(MAX_UPLOAD)

            all_found = []
            for key in selected:
                if key in SIGNATURES:
                    all_found.extend(_carve(data, key))
            all_found.sort(key=lambda x: x['offset_dec'])

            if all_found:
                buf = io.BytesIO()
                with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:
                    for i, item in enumerate(all_found):
                        zf.writestr(f"carved_{i+1:04d}_{item['type']}.{item['ext']}",
                                    item['data'])
                buf.seek(0)
                tmp = tempfile.NamedTemporaryFile(delete=False, suffix='.zip',
                                                  dir='/tmp', prefix='carve_')
                tmp.write(buf.getvalue())
                tmp.close()
                download_id = os.path.basename(tmp.name)

            found_meta = [{k: v for k, v in item.items() if k != 'data'}
                          for item in all_found]
            results = {
                'filename': f.filename, 'size': len(data),
                'count': len(all_found),
                'found': found_meta,
            }
            type_counts = {}
            for item in all_found:
                type_counts[item['type']] = type_counts.get(item['type'], 0) + 1
            tc_str = ', '.join(f"{v}×{k}" for k, v in type_counts.items())
            summary = f"{f.filename} | {len(all_found)}개 복구 ({tc_str})"
            share_token = _save_log('carve', '파일 카빙', f.filename, len(data),
                                    summary, {'filename': f.filename, 'size': len(data),
                                              'count': len(all_found),
                                              'found': found_meta[:100]})

        except Exception as e:
            error = str(e)

    return render_template('tools/carve.html', results=results, error=error,
                           download_id=download_id, signatures=SIGNATURES,
                           share_token=share_token)


@bp.route('/carve/download/<fname>')
def carve_download(fname):
    if not re.match(r'^[\w.]+$', fname):
        return 'Invalid filename', 400
    path = f'/tmp/{fname}'
    if not os.path.exists(path):
        return 'File not found', 404
    return send_file(path, as_attachment=True, download_name='carved_files.zip')


# ─────────────────────────────────────────────────────────────────────────────
# MBR Analyzer
# ─────────────────────────────────────────────────────────────────────────────
def _parse_mbr(data):
    if len(data) < 512:
        return None

    is_valid = data[510:512] == b'\x55\xAA'
    partitions = []

    for i in range(4):
        off = 446 + i * 16
        entry = data[off:off + 16]
        if len(entry) < 16:
            break
        status   = entry[0]
        ptype    = entry[4]
        lba_s    = struct.unpack('<I', entry[8:12])[0]
        lba_sz   = struct.unpack('<I', entry[12:16])[0]
        if lba_s == 0 and lba_sz == 0:
            continue
        partitions.append({
            'slot': i + 1,
            'bootable': status == 0x80,
            'type_id': f'0x{ptype:02X}',
            'type_name': PARTITION_TYPES.get(ptype, f'Unknown (0x{ptype:02X})'),
            'lba_start': lba_s,
            'lba_size': lba_sz,
            'size_mb': round((lba_sz * 512) / (1024 * 1024), 2),
            'byte_offset': hex(lba_s * 512),
        })

    vbr_found = []
    scan = data[:100 * 1024 * 1024]
    for sig, name in [(b'MSDOS5.0', 'FAT32'), (b'NTFS    ', 'NTFS'),
                      (b'EXFAT   ', 'exFAT')]:
        pos = 0
        while True:
            idx = scan.find(sig, pos)
            if idx == -1:
                break
            vbr_start = idx - 3
            if vbr_start >= 0 and vbr_start % 512 == 0:
                sector = scan[vbr_start:vbr_start + 512]
                if len(sector) == 512 and sector[510:512] == b'\x55\xAA':
                    lba = vbr_start // 512
                    if not any(v['lba'] == lba for v in vbr_found):
                        vbr_found.append({'fs': name, 'lba': lba,
                                          'offset_hex': hex(vbr_start)})
            pos = idx + 1

    raw = data[:512]
    rows = []
    for r in range(0, 512, 16):
        chunk = raw[r:r + 16]
        hex_part = ' '.join(f'{b:02X}' for b in chunk)
        asc_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        rows.append({'offset': f'{r:04X}', 'hex': hex_part, 'ascii': asc_part,
                     'highlight': 446 <= r < 510})

    return {
        'valid': is_valid,
        'boot_sig': data[510:512].hex().upper(),
        'partitions': partitions,
        'vbr_found': sorted(vbr_found, key=lambda x: x['lba']),
        'hex_dump': rows,
    }


@bp.route('/mbr', methods=['GET', 'POST'])
def mbr_tool():
    result = None
    error = None
    share_token = None

    if request.method == 'POST':
        try:
            f = request.files.get('file')
            if not f or not f.filename:
                error = '파일을 선택하세요.'
                return render_template('tools/mbr.html', error=error)

            data = f.read(MAX_UPLOAD)
            if len(data) < 512:
                error = '파일이 너무 작습니다 (최소 512 바이트).'
                return render_template('tools/mbr.html', error=error)

            result = _parse_mbr(data)
            result['filename'] = f.filename
            result['size'] = len(data)

            summary = (f"{f.filename} | 부트: {result['boot_sig']} | "
                       f"파티션 {len(result['partitions'])}개")
            share_token = _save_log('mbr', 'MBR 분석', f.filename, len(data), summary, {
                'filename': f.filename, 'size': len(data),
                'valid': result['valid'], 'boot_sig': result['boot_sig'],
                'partitions': result['partitions'], 'vbr_found': result['vbr_found'],
            })

        except Exception as e:
            error = str(e)

    return render_template('tools/mbr.html', result=result, error=error,
                           share_token=share_token)


# ─────────────────────────────────────────────────────────────────────────────
# Strings extractor
# ─────────────────────────────────────────────────────────────────────────────
@bp.route('/strings', methods=['GET', 'POST'])
def strings_tool():
    results = None
    error = None
    share_token = None

    if request.method == 'POST':
        try:
            f = request.files.get('file')
            if not f or not f.filename:
                error = '파일을 선택하세요.'
                return render_template('tools/strings.html', error=error)

            min_len  = max(3, min(int(request.form.get('min_len', 4)), 32))
            enc      = request.form.get('encoding', 'ascii')
            keyword  = request.form.get('keyword', '').strip().lower()

            data = f.read(MAX_UPLOAD)
            strings_found = []
            ml_b = str(min_len).encode()

            # ASCII (Linux/Unix/macOS/Windows 공통)
            pat_ascii = re.compile(rb'[\x20-\x7E]{' + ml_b + rb',}')
            for m in pat_ascii.finditer(data):
                s = m.group().decode('ascii', errors='ignore')
                if not keyword or keyword in s.lower():
                    strings_found.append({
                        'offset_hex': hex(m.start()), 'offset_dec': m.start(),
                        'enc': 'ASCII', 'value': s[:300], 'length': len(s),
                    })

            # UTF-16 LE (Windows 기본)
            if enc in ('unicode', 'both', 'all'):
                pat_uni = re.compile(rb'(?:[\x20-\x7E]\x00){' + ml_b + rb',}')
                for m in pat_uni.finditer(data):
                    s = m.group().decode('utf-16-le', errors='ignore').strip()
                    if s and (not keyword or keyword in s.lower()):
                        strings_found.append({
                            'offset_hex': hex(m.start()), 'offset_dec': m.start(),
                            'enc': 'UTF-16 LE', 'value': s[:300], 'length': len(s),
                        })

            # UTF-16 BE (Mac/Java/네트워크)
            if enc in ('all', 'utf16be'):
                pat_be = re.compile(rb'(?:\x00[\x20-\x7E]){' + ml_b + rb',}')
                for m in pat_be.finditer(data):
                    s = m.group().decode('utf-16-be', errors='ignore').strip()
                    if s and (not keyword or keyword in s.lower()):
                        strings_found.append({
                            'offset_hex': hex(m.start()), 'offset_dec': m.start(),
                            'enc': 'UTF-16 BE', 'value': s[:300], 'length': len(s),
                        })

            # UTF-32 LE / BE
            if enc == 'all':
                pat_u32le = re.compile(rb'(?:[\x20-\x7E]\x00\x00\x00){' + ml_b + rb',}')
                for m in pat_u32le.finditer(data):
                    s = m.group().decode('utf-32-le', errors='ignore').strip('\x00')
                    if s and (not keyword or keyword in s.lower()):
                        strings_found.append({
                            'offset_hex': hex(m.start()), 'offset_dec': m.start(),
                            'enc': 'UTF-32 LE', 'value': s[:300], 'length': len(s),
                        })
                pat_u32be = re.compile(rb'(?:\x00\x00\x00[\x20-\x7E]){' + ml_b + rb',}')
                for m in pat_u32be.finditer(data):
                    s = m.group().decode('utf-32-be', errors='ignore').strip('\x00')
                    if s and (not keyword or keyword in s.lower()):
                        strings_found.append({
                            'offset_hex': hex(m.start()), 'offset_dec': m.start(),
                            'enc': 'UTF-32 BE', 'value': s[:300], 'length': len(s),
                        })

            # UTF-8 멀티바이트 (한국어/일본어/중국어 — Linux/macOS 기본)
            if enc in ('all', 'utf8', 'both'):
                # 한국어 한글 음절 + ASCII 혼합 (각 한글 음절은 UTF-8 3바이트 0xEA-0xED 시작)
                pat_utf8 = re.compile(
                    rb'(?:[\x20-\x7E]|[\xC2-\xDF][\x80-\xBF]|[\xE0-\xEF][\x80-\xBF]{2}'
                    rb'|[\xF0-\xF4][\x80-\xBF]{3}){' + ml_b + rb',}')
                seen_ascii = set()
                for s in strings_found:
                    seen_ascii.add(s['offset_dec'])
                for m in pat_utf8.finditer(data):
                    # ASCII-only 결과는 이미 캡처됨 — 중복 회피
                    if m.start() in seen_ascii: continue
                    try:
                        s = m.group().decode('utf-8', errors='ignore').strip()
                    except Exception: continue
                    if not s: continue
                    # 비 ASCII 문자가 하나라도 있어야 추가
                    if not any(ord(c) > 127 for c in s): continue
                    if not keyword or keyword in s.lower():
                        strings_found.append({
                            'offset_hex': hex(m.start()), 'offset_dec': m.start(),
                            'enc': 'UTF-8 (CJK)', 'value': s[:300], 'length': len(s),
                        })

            strings_found.sort(key=lambda x: x['offset_dec'])
            results = {
                'filename': f.filename, 'size': len(data),
                'count': len(strings_found),
                'strings': strings_found[:3000],
                'truncated': len(strings_found) > 3000,
            }
            summary = f"{f.filename} | {len(strings_found):,}개 문자열 (최소 {min_len}자)"
            share_token = _save_log('strings', '문자열 추출', f.filename, len(data), summary, {
                'filename': f.filename, 'size': len(data),
                'count': len(strings_found), 'strings': strings_found[:200],
            })

        except Exception as e:
            error = str(e)

    return render_template('tools/strings.html', results=results, error=error,
                           share_token=share_token)


# ─────────────────────────────────────────────────────────────────────────────
# Log analyzer
# ─────────────────────────────────────────────────────────────────────────────
_APACHE = re.compile(
    r'(\d+\.\d+\.\d+\.\d+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"([^"]*?)"\s+(\d+)\s+(\S+)')
_SYSLOG = re.compile(
    r'(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+([^:]+):\s+(.*)')
_WINLOG = re.compile(
    r'(\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?)\t?'
    r'(정보|경고|오류|위험|자세히|Information|Warning|Error|Critical)\t?'
    r'(\d+)?\t?([^\t]*)\t?([^\t]*)\t?(.*)')
# Linux journalctl text export: "Jun 01 12:34:56 hostname program[pid]: msg"
_JOURNAL = re.compile(
    r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s+(.*)')
# RFC 5424 syslog: "<13>1 2026-06-01T12:34:56.789Z host app procid msgid - msg"
_RFC5424 = re.compile(
    r'<(\d+)>(\d+)\s+(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2}))\s+'
    r'(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(.*)')
# Linux audit.log: "type=SYSCALL msg=audit(1717250000.123:456): syscall=...uid=..."
_AUDIT = re.compile(
    r'type=(\w+)\s+msg=audit\(([\d.]+):(\d+)\):\s+(.*)')
# Nginx error: "2026/06/01 12:34:56 [error] 1234#0: *5 client: ..."
_NGINX_ERR = re.compile(
    r'(\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})\s+\[(\w+)\]\s+(\d+)#\d+:\s+(.*)')
# IIS W3C: "2026-06-01 12:34:56 192.168.1.1 GET /path - 80 - 10.0.0.1 Mozilla/5.0 200 0 0 123"
_IIS = re.compile(
    r'(\d{4}-\d{2}-\d{2})\s+(\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\w+)\s+(\S+)\s+\S+\s+(\d+)\s+\S+\s+(\S+)')
# macOS unified log text: "2026-06-01 12:34:56.789+0900 0x12345 Default 0x0 1234 0 process: (subsystem) [category] msg"
_MACOS_LOG = re.compile(
    r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d+[+-]\d{4})\s+'
    r'0x[0-9a-f]+\s+(\w+)\s+0x[0-9a-f]+\s+\d+\s+\d+\s+([^:]+):\s+(.*)')
# macOS asl_log / ASL: "[Time YYYY.MM.DD HH:MM:SS] [Sender X] [PID Y] [Message Z]" / 단순 syslog 호환
# auth.log Linux: "Jun  1 12:34:56 host sshd[1234]: Failed password for user from 1.2.3.4 port 22 ssh2"
# (이미 _SYSLOG / _JOURNAL 패턴으로 캡처됨)
# AWS CloudTrail JSON (한 줄 또는 다중 줄) — 단순 키 매칭
_CT_JSON = re.compile(r'"eventTime"\s*:\s*"([^"]+)".*?"eventName"\s*:\s*"([^"]+)".*?'
                      r'"sourceIPAddress"\s*:\s*"([^"]+)"', re.S)
# JSON 한 줄 로그 (ELK/Loki 스타일): {"timestamp":"...","level":"...","msg":"..."}
_JSON_LOG = re.compile(
    r'"(?:timestamp|@timestamp|time|ts)"\s*:\s*"([^"]+)".*?'
    r'(?:"(?:level|severity)"\s*:\s*"([^"]+)")?.*?'
    r'"(?:msg|message|log)"\s*:\s*"([^"]+)"', re.S)
# Docker: "2026-06-01T12:34:56.789Z stdout F msg" or JSON
_DOCKER = re.compile(
    r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z)\s+(stdout|stderr)\s+[FP]\s+(.*)')
# Kubernetes klog: "I0601 12:34:56.789012   12345 file.go:42] msg"
_KLOG = re.compile(
    r'([IWEF])(\d{4})\s+(\d{2}:\d{2}:\d{2}\.\d+)\s+(\d+)\s+([^:]+:\d+)\]\s+(.*)')


def _parse_log(text):
    lines = text.splitlines()
    events, ip_cnt, status_cnt = [], {}, {}

    for i, line in enumerate(lines[:10000]):
        line = line.strip()
        if not line:
            continue
        ev = {'line': i + 1, 'raw': line[:400], 'fmt': 'generic', 'flags': []}
        low = line.lower()

        matched = False
        m = _APACHE.match(line)
        if m:
            ip, ts, req, status, sz = m.groups()
            ev.update({'fmt': 'apache', 'ip': ip, 'timestamp': ts,
                       'request': req, 'status': status, 'size': sz})
            ip_cnt[ip] = ip_cnt.get(ip, 0) + 1
            status_cnt[status] = status_cnt.get(status, 0) + 1
            if status.startswith(('4', '5')):
                ev['flags'].append('error-status')
            matched = True
        if not matched and (m := _RFC5424.match(line)):
            pri, ver, ts, host, app, pid, msgid, msg = m.groups()
            facility, severity = int(pri) // 8, int(pri) % 8
            ev.update({'fmt': 'rfc5424-syslog', 'timestamp': ts,
                       'host': host, 'process': app, 'message': msg,
                       'facility': facility, 'severity': severity, 'pid': pid})
            if severity <= 3:
                ev['flags'].append('error-status')
            matched = True
        if not matched and (m := _NGINX_ERR.match(line)):
            ts, lvl, pid, msg = m.groups()
            ev.update({'fmt': 'nginx-error', 'timestamp': ts,
                       'level': lvl, 'pid': pid, 'message': msg})
            if lvl in ('error', 'crit', 'alert', 'emerg'):
                ev['flags'].append('error-status')
            matched = True
        if not matched and (m := _IIS.match(line)):
            d, t, server_ip, method, uri, port, client_ip = m.groups()[:7]
            status = m.group(8) if m.lastindex >= 8 else ''
            ev.update({'fmt': 'iis-w3c', 'timestamp': f'{d} {t}',
                       'ip': client_ip, 'request': f'{method} {uri}',
                       'server_ip': server_ip})
            if client_ip:
                ip_cnt[client_ip] = ip_cnt.get(client_ip, 0) + 1
            matched = True
        if not matched and (m := _MACOS_LOG.match(line)):
            ts, lvl, proc, msg = m.groups()
            ev.update({'fmt': 'macos-log', 'timestamp': ts,
                       'level': lvl, 'process': proc, 'message': msg})
            if lvl in ('Error', 'Fault', 'Critical'):
                ev['flags'].append('error-status')
            matched = True
        if not matched and (m := _JOURNAL.match(line)):
            ts, host, proc, pid, msg = m.groups()
            ev.update({'fmt': 'journalctl', 'timestamp': ts,
                       'host': host, 'process': proc, 'pid': pid, 'message': msg})
            matched = True
        if not matched and (m := _SYSLOG.match(line)):
            ts, host, proc, msg = m.groups()
            ev.update({'fmt': 'syslog', 'timestamp': ts,
                       'host': host, 'process': proc, 'message': msg})
            matched = True
        if not matched and (m := _AUDIT.match(line)):
            typ, ts, sn, body = m.groups()
            ev.update({'fmt': 'auditd', 'timestamp': ts,
                       'audit_type': typ, 'serial': sn, 'message': body})
            if typ in ('AVC', 'USER_AUTH', 'USER_LOGIN'):
                ev['flags'].append('error-status')
            matched = True
        if not matched and (m := _DOCKER.match(line)):
            ts, stream, msg = m.groups()
            ev.update({'fmt': 'docker', 'timestamp': ts,
                       'stream': stream, 'message': msg})
            if stream == 'stderr':
                ev['flags'].append('error-status')
            matched = True
        if not matched and (m := _KLOG.match(line)):
            sev, mmdd, ts, pid, src, msg = m.groups()
            SEV = {'I':'Info','W':'Warning','E':'Error','F':'Fatal'}
            ev.update({'fmt': 'k8s-klog', 'timestamp': ts,
                       'level': SEV.get(sev,sev), 'process': src,
                       'pid': pid, 'message': msg})
            if sev in ('E', 'F'):
                ev['flags'].append('error-status')
            matched = True
        if not matched and (m := _WINLOG.match(line)):
            grps = m.groups()
            ts, level = grps[0], grps[1]
            evt_id = grps[2] or ''
            channel = grps[3] or ''
            computer = grps[4] or ''
            msg = grps[5] or ''
            ev.update({'fmt': 'windows', 'timestamp': ts,
                       'level': level, 'message': msg,
                       'event_id': evt_id, 'channel': channel,
                       'computer': computer})
            if level in ('Warning', 'Error', 'Critical', '경고', '오류', '위험'):
                ev['flags'].append('error-status')
            matched = True
        if not matched and (m := _JSON_LOG.search(line)):
            ts, lvl, msg = m.groups()
            ev.update({'fmt': 'json', 'timestamp': ts,
                       'level': lvl or '', 'message': msg})
            if lvl and lvl.lower() in ('error', 'fatal', 'critical'):
                ev['flags'].append('error-status')
            matched = True
        if not matched and (m := _CT_JSON.search(line)):
            ts, evt, src_ip = m.groups()
            ev.update({'fmt': 'aws-cloudtrail', 'timestamp': ts,
                       'message': evt, 'ip': src_ip})
            ip_cnt[src_ip] = ip_cnt.get(src_ip, 0) + 1
            matched = True

        for kw in ERROR_KEYWORDS:
            if kw in low:
                ev['flags'].append(kw)
        for kw in ATTACK_KEYWORDS:
            if kw.lower() in low:
                ev['flags'].append('suspicious')
                break

        events.append(ev)

    suspicious = [e for e in events
                  if 'suspicious' in e['flags'] or 'error-status' in e['flags']]
    return {
        'total': len(events),
        'events': events[:500],
        'suspicious_count': len(suspicious),
        'suspicious': suspicious[:100],
        'top_ips':     sorted(ip_cnt.items(),     key=lambda x: -x[1])[:10],
        'top_status':  sorted(status_cnt.items(), key=lambda x: -x[1])[:10],
    }


@bp.route('/log', methods=['GET', 'POST'])
def log_tool():
    results = None
    error = None
    share_token = None

    if request.method == 'POST':
        try:
            f = request.files.get('file')
            text_in = request.form.get('text', '').strip()
            fname = ''

            if f and f.filename:
                raw = f.read(10 * 1024 * 1024)
                fname = f.filename
                if raw[:8] == b'ElfFile\x00':
                    # Windows EVTX binary format
                    try:
                        import Evtx.Evtx as evtx_lib
                        import xml.etree.ElementTree as _ET
                        evtx_events = []
                        _evtx_path = None
                        _tmp = tempfile.NamedTemporaryFile(delete=False, suffix='.evtx')
                        _tmp.write(raw)
                        _tmp.flush()
                        _tmp.close()
                        _evtx_path = _tmp.name
                        try:
                            with evtx_lib.Evtx(_evtx_path) as evtx_log:
                                for record in evtx_log.records():
                                    try:
                                        xml_str = record.xml()
                                        root = _ET.fromstring(xml_str)
                                        ns = {'e': 'http://schemas.microsoft.com/win/2004/08/events/event'}
                                        sys_el = root.find('e:System', ns)
                                        level_code = sys_el.find('e:Level', ns)
                                        ts_el = sys_el.find('e:TimeCreated', ns)
                                        evt_id = sys_el.find('e:EventID', ns)
                                        channel = sys_el.find('e:Channel', ns)
                                        computer = sys_el.find('e:Computer', ns)
                                        evtdata_el = root.find('e:EventData', ns)
                                        level_map = {'0':'정보','1':'위험','2':'오류','3':'경고','4':'정보','5':'자세히'}
                                        lvl = level_map.get((level_code.text or '4') if level_code is not None else '4', '정보')
                                        data_items = []
                                        if evtdata_el is not None:
                                            for d in evtdata_el:
                                                name = d.get('Name', '')
                                                val = (d.text or '').strip()
                                                if val:
                                                    data_items.append(f'{name}: {val}' if name else val)
                                        msg = ' | '.join(data_items[:5])
                                        evtx_events.append(
                                            f"{ts_el.get('SystemTime','') if ts_el is not None else ''}\t"
                                            f"{lvl}\t"
                                            f"{evt_id.text if evt_id is not None else ''}\t"
                                            f"{channel.text if channel is not None else ''}\t"
                                            f"{computer.text if computer is not None else ''}\t"
                                            f"{msg}"
                                        )
                                    except Exception:
                                        continue
                        finally:
                            try:
                                os.unlink(_evtx_path)
                            except Exception:
                                pass
                        text_in = '\n'.join(evtx_events)
                    except ImportError:
                        text_in = raw.decode('utf-8', errors='replace')
                else:
                    # Try common encodings for text logs
                    for enc in ('utf-8', 'cp949', 'euc-kr', 'latin-1'):
                        try:
                            text_in = raw.decode(enc)
                            break
                        except UnicodeDecodeError:
                            continue
                    else:
                        text_in = raw.decode('utf-8', errors='replace')
            elif text_in:
                fname = '(직접 입력)'
            else:
                error = '파일 또는 텍스트를 입력하세요.'
                return render_template('tools/log.html', error=error)

            results = _parse_log(text_in)
            results['filename'] = fname

            summary = (f"{fname} | 이벤트 {results['total']:,}개 | "
                       f"의심 {results['suspicious_count']}개")
            share_token = _save_log('log', '로그 분석', fname,
                                    len(text_in.encode()), summary, {
                'filename': fname, 'total': results['total'],
                'suspicious_count': results['suspicious_count'],
                'top_ips': results['top_ips'],
                'top_status': results['top_status'],
                'suspicious': results['suspicious'][:20],
            })

        except Exception as e:
            error = str(e)

    return render_template('tools/log.html', results=results, error=error,
                           share_token=share_token)


# ─────────────────────────────────────────────────────────────────────────────
# GPS 추출
# ─────────────────────────────────────────────────────────────────────────────
_MAGIC = [
    (b'\xff\xd8\xff',                    'image/jpeg'),
    (b'\x89PNG\r\n\x1a\n',               'image/png'),
    (b'GIF89a',                          'image/gif'),
    (b'GIF87a',                          'image/gif'),
    (b'II*\x00',                         'image/tiff'),
    (b'MM\x00*',                         'image/tiff'),
    (b'%PDF',                            'application/pdf'),
    (b'PK\x03\x04',                      'application/zip'),
    (b'\x1f\x8b',                        'application/gzip'),
    (b'BM',                              'image/bmp'),
    (b'RIFF',                            'audio/x-wav or video/avi'),
    (b'\x00\x00\x01\x00',               'image/x-icon'),
    (b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1', 'application/msoffice'),
    (b'MZ',                              'application/x-dosexec'),
    (b'\x7fELF',                         'application/x-elf'),
    (b'Rar!\x1a\x07',                    'application/x-rar'),
    (b'7z\xbc\xaf\x27\x1c',             'application/x-7z'),
    (b'\x00\x00\x00\x0cjP  ',           'image/jp2'),
    (b'OggS',                            'audio/ogg'),
    (b'fLaC',                            'audio/flac'),
    (b'\x00\x00\x00\x14ftyp',           'video/mp4'),
    (b'\x00\x00\x00\x18ftyp',           'video/mp4'),
    (b'\x00\x00\x00\x20ftyp',           'video/mp4'),
    (b'ID3',                             'audio/mpeg'),
    (b'\xff\xfb',                        'audio/mpeg'),
    (b'\xff\xf3',                        'audio/mpeg'),
    (b'\xff\xf2',                        'audio/mpeg'),
    (b'webP',                            'image/webp'),
]

# extension → allowed mime types (tuple)
_EXT_MIME = {
    '.jpg':  ('image/jpeg',),
    '.jpeg': ('image/jpeg',),
    '.png':  ('image/png',),
    '.gif':  ('image/gif',),
    '.tif':  ('image/tiff',),
    '.tiff': ('image/tiff',),
    '.bmp':  ('image/bmp',),
    '.ico':  ('image/x-icon',),
    '.jp2':  ('image/jp2',),
    '.webp': ('image/webp',),
    '.pdf':  ('application/pdf',),
    '.zip':  ('application/zip',),
    '.gz':   ('application/gzip',),
    '.rar':  ('application/x-rar',),
    '.7z':   ('application/x-7z',),
    '.wav':  ('audio/x-wav or video/avi',),
    '.avi':  ('audio/x-wav or video/avi',),
    '.mp3':  ('audio/mpeg',),
    '.ogg':  ('audio/ogg',),
    '.flac': ('audio/flac',),
    '.mp4':  ('video/mp4',),
    '.m4a':  ('video/mp4',),
    '.m4v':  ('video/mp4',),
    '.exe':  ('application/x-dosexec',),
    '.dll':  ('application/x-dosexec',),
    '.sys':  ('application/x-dosexec',),
    '.elf':  ('application/x-elf',),
    '.doc':  ('application/msoffice',),
    '.xls':  ('application/msoffice',),
    '.ppt':  ('application/msoffice',),
    # Office Open XML — stored as ZIP internally
    '.docx': ('application/zip',),
    '.xlsx': ('application/zip',),
    '.pptx': ('application/zip',),
    '.jar':  ('application/zip',),
    '.apk':  ('application/zip',),
}

_MIME_LABEL = {
    'image/jpeg':              'JPEG 이미지',
    'image/png':               'PNG 이미지',
    'image/gif':               'GIF 이미지',
    'image/tiff':              'TIFF 이미지',
    'image/bmp':               'BMP 이미지',
    'image/x-icon':            'ICO 아이콘',
    'image/jp2':               'JPEG 2000',
    'image/webp':              'WebP 이미지',
    'application/pdf':         'PDF 문서',
    'application/zip':         'ZIP 아카이브',
    'application/gzip':        'GZIP 압축',
    'application/x-rar':       'RAR 아카이브',
    'application/x-7z':        '7-Zip 아카이브',
    'application/msoffice':    'MS Office (구형)',
    'application/x-dosexec':   'Windows 실행파일 (PE)',
    'application/x-elf':       'Linux 실행파일 (ELF)',
    'audio/x-wav or video/avi':'WAV/AVI',
    'audio/mpeg':              'MP3 오디오',
    'audio/ogg':               'OGG 오디오',
    'audio/flac':              'FLAC 오디오',
    'video/mp4':               'MP4 비디오',
    'application/octet-stream':'알 수 없는 바이너리',
}


def _detect_mime(data):
    if len(data) >= 12 and data[:4] == b'RIFF':
        sub = data[8:12]
        if sub == b'WAVE':
            return 'audio/x-wav'
        if sub == b'AVI ':
            return 'video/avi'
    if len(data) >= 12 and data[4:8] == b'webP':
        return 'image/webp'
    for sig, mime in _MAGIC:
        if data[:len(sig)] == sig:
            return mime
    return 'application/octet-stream'


def _detect_spoof(filename, detected_mime):
    import os as _os
    ext = _os.path.splitext(filename)[1].lower()
    label = _MIME_LABEL.get(detected_mime, detected_mime)

    if not ext:
        return {'status': 'no_ext', 'level': 'info',
                'detected': detected_mime, 'detected_label': label}

    if detected_mime == 'application/octet-stream':
        return {'status': 'unknown_type', 'level': 'info',
                'ext': ext, 'detected': detected_mime, 'detected_label': label}

    if ext not in _EXT_MIME:
        return {'status': 'unknown_ext', 'level': 'info',
                'ext': ext, 'detected': detected_mime, 'detected_label': label}

    if detected_mime in _EXT_MIME[ext]:
        return {'status': 'match', 'level': 'safe',
                'ext': ext, 'detected': detected_mime, 'detected_label': label}

    return {'status': 'mismatch', 'level': 'danger',
            'ext': ext, 'detected': detected_mime, 'detected_label': label,
            'expected': ', '.join(_EXT_MIME[ext])}


def _dms_to_dec(dms, ref):
    try:
        d, m, s = float(dms[0]), float(dms[1]), float(dms[2])
        v = d + m / 60 + s / 3600
        return round(-v if ref in ('S', 'W') else v, 8)
    except Exception:
        return None


def _dec_to_dms_str(dec):
    if dec is None:
        return ''
    d = int(abs(dec))
    m = int((abs(dec) - d) * 60)
    s = (abs(dec) - d - m / 60) * 3600
    return f"{d}° {m}' {s:.3f}\""


def _parse_image_exif(data):
    from PIL import Image as PilImage
    from PIL.ExifTags import TAGS, GPSTAGS
    img = PilImage.open(io.BytesIO(data))

    img_info = {
        'format':   img.format or '?',
        'mode':     img.mode,
        'width':    img.width,
        'height':   img.height,
    }

    raw = img._getexif() if hasattr(img, '_getexif') else None
    if not raw:
        try:
            raw_obj = img.getexif()
            raw = dict(raw_obj) if raw_obj else None
        except Exception:
            raw = None

    if not raw:
        return None, None, None, {}, img_info

    exif = {}
    gps_raw = None
    for tag_id, val in raw.items():
        tag = TAGS.get(tag_id, str(tag_id))
        if tag == 'GPSInfo':
            gps_raw = {GPSTAGS.get(k, str(k)): v for k, v in val.items()}
        else:
            try:
                exif[tag] = str(val)[:400]
            except Exception:
                exif[tag] = '(binary)'

    lat = lon = alt = None
    if gps_raw:
        if 'GPSLatitude' in gps_raw and 'GPSLatitudeRef' in gps_raw:
            lat = _dms_to_dec(gps_raw['GPSLatitude'], gps_raw['GPSLatitudeRef'])
        if 'GPSLongitude' in gps_raw and 'GPSLongitudeRef' in gps_raw:
            lon = _dms_to_dec(gps_raw['GPSLongitude'], gps_raw['GPSLongitudeRef'])
        if 'GPSAltitude' in gps_raw:
            try:
                alt = round(float(gps_raw['GPSAltitude']), 2)
            except Exception:
                pass
        gps_raw = {k: str(v) for k, v in gps_raw.items()}

    return lat, lon, alt, exif, img_info, gps_raw


@bp.route('/gps', methods=['GET', 'POST'])
def gps_tool():
    result = None
    error  = None
    share_token = None

    if request.method == 'POST':
        try:
            f = request.files.get('file')
            if not f or not f.filename:
                error = '이미지 파일을 선택하세요.'
                return render_template('tools/gps.html', error=error)

            data  = f.read(50 * 1024 * 1024)
            mime  = _detect_mime(data)

            if 'image' not in mime:
                error = f'이미지 파일만 지원합니다. 감지된 타입: {mime}'
                return render_template('tools/gps.html', error=error)

            ret = _parse_image_exif(data)
            if len(ret) == 5:
                lat, lon, alt, exif, img_info = ret
                gps_raw = None
            else:
                lat, lon, alt, exif, img_info, gps_raw = ret

            result = {
                'filename': f.filename,
                'size':     len(data),
                'mime':     mime,
                'img':      img_info,
                'lat':      lat,
                'lon':      lon,
                'alt':      alt,
                'lat_dms':  _dec_to_dms_str(lat),
                'lon_dms':  _dec_to_dms_str(lon),
                'gps_tags': gps_raw or {},
                'exif':     exif,
                'has_gps':  lat is not None and lon is not None,
            }
            gps_str = f"GPS: {lat}, {lon}" if lat else "GPS 없음"
            summary = f"{f.filename} | {gps_str}"
            share_token = _save_log('gps', 'GPS 추출', f.filename, len(data), summary, {
                'filename': f.filename, 'lat': lat, 'lon': lon, 'alt': alt,
                'img': img_info, 'gps_tags': gps_raw or {},
            })

        except ImportError:
            error = 'Pillow 라이브러리가 필요합니다.'
        except Exception as e:
            error = str(e)

    return render_template('tools/gps.html', result=result, error=error,
                           share_token=share_token)


# ─────────────────────────────────────────────────────────────────────────────
# 메타데이터 추출
# ─────────────────────────────────────────────────────────────────────────────
_EXIF_CAMERA = {'Make','Model','Software','LensModel','LensMake'}
_EXIF_SHOOT  = {'DateTime','DateTimeOriginal','DateTimeDigitized',
                'FNumber','ExposureTime','ISOSpeedRatings','FocalLength',
                'Flash','WhiteBalance','ExposureMode','MeteringMode',
                'ExposureBiasValue','MaxApertureValue','DigitalZoomRatio',
                'SceneCaptureType','SharpnessValue'}
_EXIF_IMAGE  = {'ImageWidth','ImageLength','XResolution','YResolution',
                'ResolutionUnit','ColorSpace','Orientation',
                'PixelXDimension','PixelYDimension','BitsPerSample',
                'Compression','PhotometricInterpretation'}


def _extract_metadata(data, filename):
    mime = _detect_mime(data)
    md = {
        'filename': filename, 'size': len(data), 'mime': mime,
        'hashes': {}, 'image': None, 'camera': {}, 'shoot': {},
        'exif_all': {}, 'gps': None, 'pdf': None,
        'lat': None, 'lon': None,
    }

    for algo in ('md5', 'sha1', 'sha256'):
        h = hashlib.new(algo)
        h.update(data)
        md['hashes'][algo.upper()] = h.hexdigest()

    if 'image' in mime:
        try:
            ret = _parse_image_exif(data)
            lat, lon, alt, exif, img_info = ret[0], ret[1], ret[2], ret[3], ret[4]
            gps_raw = ret[5] if len(ret) > 5 else None
            md['image']    = img_info
            md['exif_all'] = exif
            md['camera']   = {k: v for k, v in exif.items() if k in _EXIF_CAMERA}
            md['shoot']    = {k: v for k, v in exif.items() if k in _EXIF_SHOOT}
            md['lat']      = lat
            md['lon']      = lon
            if lat is not None and lon is not None:
                md['gps'] = {
                    'lat': lat, 'lon': lon, 'alt': alt,
                    'lat_dms': _dec_to_dms_str(lat),
                    'lon_dms': _dec_to_dms_str(lon),
                    'tags': gps_raw or {},
                }
        except Exception as e:
            md['exif_err'] = str(e)

    if mime == 'application/pdf':
        try:
            from pypdf import PdfReader
            reader = PdfReader(io.BytesIO(data))
            info   = reader.metadata or {}
            md['pdf'] = {
                'pages':    len(reader.pages),
                'title':    str(info.get('/Title',    '')),
                'author':   str(info.get('/Author',   '')),
                'subject':  str(info.get('/Subject',  '')),
                'creator':  str(info.get('/Creator',  '')),
                'producer': str(info.get('/Producer', '')),
                'created':  str(info.get('/CreationDate', '')),
                'modified': str(info.get('/ModDate',  '')),
                'encrypted': reader.is_encrypted,
            }
        except Exception as e:
            md['pdf'] = {'error': str(e)}

    md['magic_hex'] = data[:32].hex().upper()
    md['spoof'] = _detect_spoof(filename, mime)
    return md


@bp.route('/metadata', methods=['GET', 'POST'])
def metadata_tool():
    result = None
    error  = None
    share_token = None

    if request.method == 'POST':
        try:
            f = request.files.get('file')
            if not f or not f.filename:
                error = '파일을 선택하세요.'
                return render_template('tools/metadata.html', error=error)

            data   = f.read(MAX_UPLOAD)
            result = _extract_metadata(data, f.filename)

            cam = result['camera']
            cam_str = (cam.get('Make', '') + ' ' + cam.get('Model', '')).strip()
            summary = f"{f.filename} | {result['mime']} | 카메라: {cam_str or '없음'}"
            share_token = _save_log('metadata', '메타데이터 추출', f.filename, len(data),
                                    summary, {
                'filename': f.filename, 'size': len(data), 'mime': result['mime'],
                'hashes': result['hashes'], 'camera': result['camera'],
                'shoot': result['shoot'], 'pdf': result['pdf'], 'gps': result['gps'],
            })

        except Exception as e:
            error = str(e)

    return render_template('tools/metadata.html', result=result, error=error,
                           share_token=share_token)


# ─────────────────────────────────────────────────────────────────────────────
# MBR Repair
# ─────────────────────────────────────────────────────────────────────────────
_ALLOWED_DEV = re.compile(r'^/dev/[a-z][a-z0-9]+$')
_ALLOWED_TMP = re.compile(r'^/tmp/mbrfix_[\w]+$')


def _get_root_disks():
    roots = set()
    try:
        with open('/proc/mounts') as f:
            for line in f:
                parts = line.split()
                if not parts:
                    continue
                src = parts[0]
                if src.startswith('/dev/'):
                    disk = re.sub(r'(p\d+|\d+)$', '', src)
                    roots.add(disk)
    except Exception:
        pass
    return roots


def _fmt_bytes(b):
    b = int(b or 0)
    for u in ['B', 'KB', 'MB', 'GB', 'TB']:
        if b < 1024:
            return f'{b:.1f} {u}'
        b /= 1024
    return f'{b:.1f} PB'


def _validate_target(path):
    root_disks = _get_root_disks()
    if path in root_disks:
        raise ValueError(
            f'서버 OS 디스크({path})는 수정할 수 없습니다. '
            '외부 연결 장치만 사용 가능합니다.')
    if not os.path.exists(path):
        raise FileNotFoundError(f'장치를 찾을 수 없습니다: {path}')
    if not stat.S_ISBLK(os.stat(path).st_mode):
        raise ValueError(f'{path}는 블록 장치가 아닙니다.')


def _open_source(file_upload, device_path):
    if file_upload and file_upload.filename:
        tmp = tempfile.NamedTemporaryFile(
            delete=False, dir='/tmp', prefix='mbrfix_', suffix='.img')
        tmp.write(file_upload.read(MAX_UPLOAD))
        tmp.flush()
        tmp.seek(0)
        size = os.path.getsize(tmp.name)
        return tmp, file_upload.filename, tmp.name, size

    dp = device_path.strip()
    if dp:
        if not _ALLOWED_DEV.match(dp):
            raise ValueError('허용되지 않는 장치 경로 형식입니다.')
        _validate_target(dp)
        f = open(dp, 'rb')
        size = os.fstat(f.fileno()).st_size
        return f, dp, dp, size

    raise ValueError('파일을 업로드하거나 장치 경로를 입력하세요.')


def _smart_scan(f, file_size):
    partitions = []
    sector_size = 512
    chunk_size  = 10 * 1024 * 1024

    f.seek(0)
    offset = 0
    while offset < file_size and len(partitions) < 4:
        f.seek(offset)
        chunk = f.read(chunk_size + sector_size)
        if not chunk:
            break

        for sig, p_type, name in [
            (b'MSDOS5.0', 0x0C, 'FAT32'),
            (b'NTFS    ', 0x07, 'NTFS'),
        ]:
            si = 0
            while True:
                idx = chunk.find(sig, si)
                if idx == -1:
                    break
                vbr_abs = offset + idx - 3
                if vbr_abs >= 0 and vbr_abs % sector_size == 0:
                    lba = vbr_abs // sector_size
                    f.seek(vbr_abs)
                    sector = f.read(512)
                    if len(sector) == 512 and sector[510:512] == b'\x55\xAA':
                        if name == 'FAT32':
                            sz = struct.unpack('<I', sector[0x20:0x24])[0]
                        else:
                            sz = struct.unpack('<Q', sector[0x28:0x30])[0]
                        if 0 < sz < 0xFFFFFFFF:
                            is_backup = any(
                                (p['name'] == 'FAT32' and lba == p['lba'] + 6) or
                                (p['name'] == 'NTFS'  and abs(lba - (p['lba'] + p['size'])) <= 1)
                                for p in partitions)
                            if not is_backup and not any(p['lba'] == lba for p in partitions):
                                partitions.append({
                                    'name': name, 'type': p_type,
                                    'type_hex': f'0x{p_type:02X}',
                                    'lba': lba, 'size': sz,
                                    'size_mb': round((sz * 512) / (1024**2), 1),
                                    'byte_offset': hex(vbr_abs),
                                })
                si = idx + 1
        offset += chunk_size

    return sorted(partitions, key=lambda x: x['lba'])


def _read_current_parts(f):
    f.seek(0)
    mbr = f.read(512)
    if len(mbr) < 512:
        return None, []
    valid = mbr[510:512] == b'\x55\xAA'
    parts = []
    for i in range(4):
        e = mbr[446 + i*16: 446 + i*16 + 16]
        pt   = e[4]
        ls   = struct.unpack('<I', e[8:12])[0]
        lsz  = struct.unpack('<I', e[12:16])[0]
        if ls == 0 and lsz == 0:
            continue
        parts.append({
            'slot': i + 1,
            'type_hex': f'0x{pt:02X}',
            'type_name': PARTITION_TYPES.get(pt, f'Unknown (0x{pt:02X})'),
            'lba_start': ls, 'lba_size': lsz,
            'size_mb': round((lsz * 512) / (1024**2), 1),
        })
    return valid, parts


def _do_write(path, partitions):
    with open(path, 'rb+') as f:
        f.seek(446)
        f.write(b'\x00' * 64)
        for i, p in enumerate(partitions[:4]):
            f.seek(446 + i * 16)
            f.write(struct.pack('<B3sB3sII',
                                0x00, b'\x00\x00\x00',
                                p['type'], b'\x00\x00\x00',
                                p['lba'], p['size']))
        f.seek(510)
        f.write(b'\x55\xAA')


@bp.route('/mbr-repair/download-script')
def mbr_repair_script():
    path = os.path.join(os.path.dirname(__file__),
                        '..', 'static', 'tools', 'forensiclab_mbr_repair.py')
    path = os.path.abspath(path)
    return send_file(path, as_attachment=True,
                     download_name='forensiclab_mbr_repair.py',
                     mimetype='text/x-python')


@bp.route('/mbr-repair/devices')
def mbr_devices():
    try:
        r = subprocess.run(
            ['lsblk', '-J', '-b', '-d',
             '-o', 'NAME,SIZE,TYPE,MODEL,RM,TRAN,MOUNTPOINT'],
            capture_output=True, text=True, timeout=5)
        data = _json.loads(r.stdout)
        root_disks = _get_root_disks()

        devices = []
        for dev in data.get('blockdevices', []):
            if dev.get('type') != 'disk':
                continue
            path = f'/dev/{dev["name"]}'
            is_root = path in root_disks
            sz      = int(dev.get('size') or 0)
            tran    = (dev.get('tran') or '').strip().lower()
            rm      = str(dev.get('rm', '0')) == '1'
            model   = (dev.get('model') or '').strip() or 'Unknown'
            mount   = (dev.get('mountpoint') or '').strip()
            devices.append({
                'path': path, 'size_hr': _fmt_bytes(sz), 'size_bytes': sz,
                'model': model, 'tran': tran or '?',
                'removable': rm or tran == 'usb',
                'is_root': is_root, 'mounted': mount,
            })

        devices.sort(key=lambda d: (d['is_root'], not d['removable']))
        return jsonify({'devices': devices, 'root_disks': list(root_disks)})

    except FileNotFoundError:
        return jsonify({'error': 'lsblk를 찾을 수 없습니다.'}), 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@bp.route('/mbr-repair', methods=['GET', 'POST'])
def mbr_repair():
    preview = None
    error   = None
    success = None

    if request.method == 'POST':
        action = request.form.get('action', 'preview')

        try:
            if action == 'preview':
                f, label, write_path, fsize = _open_source(
                    request.files.get('file'),
                    request.form.get('device_path', ''))
                curr_valid, curr_parts = _read_current_parts(f)
                found = _smart_scan(f, fsize)
                f.close()
                preview = {
                    'label': label, 'write_path': write_path, 'size': fsize,
                    'curr_valid': curr_valid, 'curr_parts': curr_parts,
                    'found': found, 'can_repair': len(found) > 0,
                }

            elif action == 'repair':
                confirmed  = request.form.get('confirmed') == '1'
                write_path = request.form.get('write_path', '').strip()

                if not confirmed:
                    raise ValueError('경고 내용에 동의해야 복구를 진행할 수 있습니다.')
                if not (_ALLOWED_DEV.match(write_path) or _ALLOWED_TMP.match(write_path)):
                    raise ValueError('허용되지 않는 경로 형식입니다.')
                if _ALLOWED_DEV.match(write_path):
                    _validate_target(write_path)
                if not os.path.exists(write_path):
                    raise FileNotFoundError(f'경로를 찾을 수 없습니다: {write_path}')

                with open(write_path, 'rb') as f:
                    fsize = os.path.getsize(write_path)
                    found = _smart_scan(f, fsize)

                if not found:
                    raise ValueError('복구 가능한 파티션 시그니처를 찾지 못했습니다.')
                _do_write(write_path, found)
                success = {'path': write_path, 'count': len(found), 'parts': found}

        except PermissionError:
            error = '권한 오류: 이 경로에 대한 읽기/쓰기 권한이 없습니다.'
        except FileNotFoundError as e:
            error = f'파일/장치를 찾을 수 없습니다: {e}'
        except Exception as e:
            error = str(e)

    return render_template('tools/mbr_repair.html',
                           preview=preview, error=error, success=success)


# ─────────────────────────────────────────────────────────────────────────────
# 분석 이력 / 공유 링크 / PDF 리포트
# ─────────────────────────────────────────────────────────────────────────────
@bp.route('/history')
def history():
    try:
        from monitor.models import AnalysisLog
        logs = AnalysisLog.query.order_by(AnalysisLog.created.desc()).limit(200).all()
    except Exception:
        logs = []
    return render_template('tools/history.html', logs=logs)


@bp.route('/share/<token>')
def share_view(token):
    from monitor.models import AnalysisLog
    log = AnalysisLog.query.filter_by(share_token=token).first_or_404()
    result = None
    if log.result_json:
        try:
            result = _json.loads(log.result_json)
        except Exception:
            pass
    return render_template('tools/share.html', log=log, result=result)


@bp.route('/report/<token>')
def report(token):
    from monitor.models import AnalysisLog
    log = AnalysisLog.query.filter_by(share_token=token).first_or_404()
    result = None
    if log.result_json:
        try:
            result = _json.loads(log.result_json)
        except Exception:
            pass
    return render_template('tools/report.html', log=log, result=result)


# ─────────────────────────────────────────────────────────────────────────────
# 타임라인 재구성
# ─────────────────────────────────────────────────────────────────────────────
@bp.route('/timeline', methods=['GET', 'POST'])
def timeline_tool():
    events = None
    error = None
    share_token = None

    if request.method == 'POST':
        try:
            files = request.files.getlist('files')
            if not files or not files[0].filename:
                error = '파일을 하나 이상 선택하세요.'
                return render_template('tools/timeline.html', error=error)

            all_events = []
            for f in files:
                fname = f.filename
                data = f.read(50 * 1024 * 1024)
                mime = _detect_mime(data)

                if 'image' in mime:
                    try:
                        ret = _parse_image_exif(data)
                        exif = ret[3] if len(ret) >= 4 else {}
                        for field in ('DateTimeOriginal', 'DateTime', 'DateTimeDigitized'):
                            if field in exif:
                                all_events.append({
                                    'ts_str': exif[field], 'source': fname,
                                    'type': 'EXIF', 'detail': field,
                                })
                    except Exception:
                        pass

                elif mime == 'application/pdf':
                    try:
                        from pypdf import PdfReader
                        reader = PdfReader(io.BytesIO(data))
                        info = reader.metadata or {}
                        for key, label in [('/CreationDate', 'PDF 생성'),
                                           ('/ModDate', 'PDF 수정')]:
                            val = str(info.get(key, ''))
                            if val:
                                all_events.append({
                                    'ts_str': val, 'source': fname,
                                    'type': 'PDF', 'detail': label,
                                })
                    except Exception:
                        pass

                # LNK 바이너리 (Windows 바로가기)
                elif data[:4] == b'\x4C\x00\x00\x00':
                    try:
                        from monitor.views.tools_extra import _parse_lnk
                        r = _parse_lnk(data, fname)
                        for k, label in [('create_time','LNK 대상 생성'),
                                         ('write_time','LNK 대상 수정'),
                                         ('access_time','LNK 대상 접근')]:
                            t = r.get(k)
                            if t and t != '-' and not t.startswith('('):
                                all_events.append({
                                    'ts_str': t, 'source': fname, 'type': 'LNK',
                                    'detail': f'{label}: {(r.get("target") or "")[:80]}',
                                })
                    except Exception: pass

                # Prefetch (Windows 실행 추적)
                elif data[:3] == b'MAM' or data[4:8] == b'SCCA':
                    try:
                        from monitor.views.tools_extra import _parse_prefetch
                        r = _parse_prefetch(data, fname)
                        for t in r.get('last_runs', []):
                            all_events.append({
                                'ts_str': t, 'source': fname, 'type': 'PREFETCH',
                                'detail': f'{r.get("executable","?")} 실행 (#{r.get("run_count",0)})',
                            })
                    except Exception: pass

                # EML 이메일 (RFC 5322 Date 헤더)
                elif b'\nDate:' in data[:8192] or data.startswith(b'Date:'):
                    try:
                        import email as _email
                        msg = _email.message_from_bytes(data)
                        d = msg.get('Date')
                        if d:
                            all_events.append({
                                'ts_str': d, 'source': fname, 'type': 'EMAIL',
                                'detail': f'{msg.get("Subject","")[:80]} ← {msg.get("From","?")[:60]}',
                            })
                    except Exception: pass

                # ZIP / Office DOCX/XLSX/PPTX — 내부 [Content_Types].xml 시각
                elif data[:4] == b'PK\x03\x04':
                    try:
                        import zipfile as _zf
                        zf = _zf.ZipFile(io.BytesIO(data))
                        for zi in zf.infolist()[:20]:
                            y, mo, d, h, mi, s = zi.date_time
                            if y >= 1980:
                                all_events.append({
                                    'ts_str': f'{y:04d}-{mo:02d}-{d:02d} {h:02d}:{mi:02d}:{s:02d}',
                                    'source': fname, 'type': 'ZIP/DOCX',
                                    'detail': f'멤버 {zi.filename}',
                                })
                                break  # 첫 멤버만
                        # docProps/core.xml 검색
                        for n in zf.namelist():
                            if n.endswith('core.xml') or n.endswith('app.xml'):
                                try:
                                    xml = zf.read(n).decode('utf-8','replace')
                                    for tag in ('created','modified','lastPrinted'):
                                        m = re.search(rf'<[^:>]*:{tag}[^>]*>([^<]+)</', xml)
                                        if m:
                                            all_events.append({
                                                'ts_str': m.group(1), 'source': fname,
                                                'type': 'OFFICE',
                                                'detail': f'docProps/{tag}',
                                            })
                                except Exception: pass
                    except Exception: pass

                else:
                    try:
                        text = data.decode('utf-8', errors='replace')
                        parsed = _parse_log(text)
                        for ev in parsed['events'][:500]:
                            ts = ev.get('timestamp')
                            if ts:
                                all_events.append({
                                    'ts_str': ts, 'source': fname,
                                    'type': ev.get('fmt', 'LOG').upper(),
                                    'detail': (ev.get('request') or
                                               ev.get('message') or
                                               ev.get('raw', ''))[:120],
                                })
                    except Exception:
                        pass

            all_events.sort(key=lambda e: e.get('ts_str', ''))
            events = all_events[:2000]

            filenames = list({e['source'] for e in (events or [])})
            summary = f"{len(filenames)}개 파일 | {len(events)}개 이벤트"
            share_token = _save_log('timeline', '타임라인 재구성',
                                    ', '.join(filenames[:3]), None, summary,
                                    {'events': events[:200]})

        except Exception as e:
            error = str(e)

    return render_template('tools/timeline.html', events=events, error=error,
                           share_token=share_token)


# ─────────────────────────────────────────────────────────────────────────────
# 패킷 분석 (pcap)
# ─────────────────────────────────────────────────────────────────────────────
def _parse_pcap(data):
    import socket as _socket
    try:
        import dpkt
    except ImportError:
        raise ImportError('dpkt 라이브러리가 필요합니다. (pip install dpkt)')

    _PORT_NAMES = {
        20: 'FTP-data', 21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
        53: 'DNS', 80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS',
        445: 'SMB', 3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL',
        6379: 'Redis', 8080: 'HTTP-alt', 8443: 'HTTPS-alt',
    }

    stats = {
        'total': 0, 'protocols': {}, 'src_ips': {}, 'dst_ips': {},
        'dst_ports': {}, 'dns_queries': [], 'http_requests': [], 'suspicious': [],
    }

    try:
        pcap = dpkt.pcap.Reader(io.BytesIO(data))
    except Exception:
        try:
            pcap = dpkt.pcapng.Reader(io.BytesIO(data))
        except Exception as e:
            raise ValueError(f'pcap 파싱 실패: {e}')

    for ts, buf in pcap:
        stats['total'] += 1
        if stats['total'] > 100000:
            break
        try:
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data
            if not isinstance(ip, dpkt.ip.IP):
                continue

            src_ip = _socket.inet_ntoa(ip.src)
            dst_ip = _socket.inet_ntoa(ip.dst)
            stats['src_ips'][src_ip] = stats['src_ips'].get(src_ip, 0) + 1
            stats['dst_ips'][dst_ip] = stats['dst_ips'].get(dst_ip, 0) + 1

            proto_name = {6: 'TCP', 17: 'UDP', 1: 'ICMP'}.get(ip.p, f'Other({ip.p})')
            stats['protocols'][proto_name] = stats['protocols'].get(proto_name, 0) + 1

            if isinstance(ip.data, dpkt.tcp.TCP):
                tcp = ip.data
                stats['dst_ports'][tcp.dport] = stats['dst_ports'].get(tcp.dport, 0) + 1
                if (tcp.dport == 80 or tcp.sport == 80) and len(stats['http_requests']) < 50:
                    try:
                        if tcp.data:
                            http = dpkt.http.Request(tcp.data)
                            stats['http_requests'].append({
                                'src': src_ip, 'dst': dst_ip,
                                'method': http.method, 'uri': http.uri[:200],
                            })
                    except Exception:
                        pass

            elif isinstance(ip.data, dpkt.udp.UDP):
                udp = ip.data
                stats['dst_ports'][udp.dport] = stats['dst_ports'].get(udp.dport, 0) + 1
                if (udp.dport == 53 or udp.sport == 53) and len(stats['dns_queries']) < 200:
                    try:
                        dns = dpkt.dns.DNS(udp.data)
                        for q in dns.qd:
                            if q.name not in stats['dns_queries']:
                                stats['dns_queries'].append(q.name)
                    except Exception:
                        pass
        except Exception:
            continue

    stats['top_src_ips'] = sorted(stats['src_ips'].items(), key=lambda x: -x[1])[:10]
    stats['top_dst_ips'] = sorted(stats['dst_ips'].items(), key=lambda x: -x[1])[:10]
    stats['top_dst_ports'] = [
        {'port': p, 'count': c, 'service': _PORT_NAMES.get(p, '')}
        for p, c in sorted(stats['dst_ports'].items(), key=lambda x: -x[1])[:15]
    ]
    stats['protocol_dist'] = stats['protocols']

    for src, cnt in stats['top_src_ips']:
        if cnt > 500:
            stats['suspicious'].append(f'대량 패킷 발신: {src} ({cnt:,}개)')
    for item in stats['top_dst_ports']:
        if item['port'] in (23, 445, 3389) and item['count'] > 10:
            stats['suspicious'].append(
                f"민감 포트 접근: {item['service']} ({item['port']}) — {item['count']}회")

    return stats


@bp.route('/pcap', methods=['GET', 'POST'])
def pcap_tool():
    result = None
    error = None
    share_token = None

    if request.method == 'POST':
        try:
            f = request.files.get('file')
            if not f or not f.filename:
                error = '파일을 선택하세요.'
                return render_template('tools/pcap.html', error=error)

            data = f.read(100 * 1024 * 1024)
            result = _parse_pcap(data)
            result['filename'] = f.filename
            result['file_size'] = len(data)

            summary = (f"{f.filename} | {result['total']:,}개 패킷 | "
                       f"프로토콜 {len(result['protocol_dist'])}종")
            share_token = _save_log('pcap', '패킷 분석', f.filename, len(data), summary, {
                'filename': f.filename, 'total': result['total'],
                'protocol_dist': result['protocol_dist'],
                'top_src_ips': result['top_src_ips'],
                'top_dst_ips': result['top_dst_ips'],
                'top_dst_ports': result['top_dst_ports'],
                'dns_queries': result['dns_queries'][:50],
                'suspicious': result['suspicious'],
            })

        except ImportError as e:
            error = str(e)
        except Exception as e:
            error = str(e)

    return render_template('tools/pcap.html', result=result, error=error,
                           share_token=share_token)


# ─────────────────────────────────────────────────────────────────────────────
# 이메일 분석
# ─────────────────────────────────────────────────────────────────────────────
def _build_email_result(msg_obj):
    """RFC 2822 email.message.Message 객체 → 결과 dict."""
    def _hdr(key):
        v = msg_obj.get(key)
        return str(v) if v else ''

    all_headers = [(k, str(v)) for k, v in msg_obj.items()]
    received = [str(h) for h in (msg_obj.get_all('Received') or [])]

    body_text = body_html = ''
    attachments = []

    if msg_obj.is_multipart():
        for part in msg_obj.walk():
            ct = part.get_content_type()
            disp = str(part.get_content_disposition() or '')
            fname_part = part.get_filename()
            if fname_part:
                payload = part.get_payload(decode=True) or b''
                attachments.append({'name': fname_part, 'type': ct, 'size': len(payload)})
            elif ct == 'text/plain' and 'attachment' not in disp and not body_text:
                try:
                    body_text = part.get_content()
                except Exception:
                    body_text = (part.get_payload(decode=True) or b'').decode('utf-8', errors='replace')
            elif ct == 'text/html' and 'attachment' not in disp and not body_html:
                try:
                    body_html = part.get_content()
                except Exception:
                    body_html = (part.get_payload(decode=True) or b'').decode('utf-8', errors='replace')
    else:
        ct = msg_obj.get_content_type()
        try:
            content = msg_obj.get_content()
        except Exception:
            content = (msg_obj.get_payload(decode=True) or b'').decode('utf-8', errors='replace')
        if ct == 'text/html':
            body_html = content
        else:
            body_text = content

    links = list(dict.fromkeys(re.findall(r'https?://[^\s<>"\'\)\]]+', body_html + body_text)))

    spf = _hdr('Received-SPF') or _hdr('Authentication-Results')
    dkim_sig = _hdr('DKIM-Signature')
    x_ip = _hdr('X-Originating-IP') or _hdr('X-Sender-IP')
    reply_to = _hdr('Reply-To')
    from_addr = _hdr('From')

    spoof_hint = None
    if reply_to and from_addr:
        m_from = re.search(r'@([\w.-]+)', from_addr)
        m_reply = re.search(r'@([\w.-]+)', reply_to)
        if m_from and m_reply and m_from.group(1).lower() != m_reply.group(1).lower():
            spoof_hint = f'From 도메인({m_from.group(1)})과 Reply-To 도메인({m_reply.group(1)})이 다릅니다.'

    hops = []
    for rcv in received:
        ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', rcv)
        ts_m = re.search(r';\s*(.+)$', rcv)
        hops.append({'raw': rcv[:200], 'ips': ips,
                     'timestamp': ts_m.group(1).strip() if ts_m else ''})

    return {
        'subject': _hdr('Subject'), 'sender': from_addr,
        'to': _hdr('To'), 'cc': _hdr('Cc'), 'bcc': _hdr('Bcc'),
        'date': _hdr('Date'), 'message_id': _hdr('Message-ID'),
        'reply_to': reply_to, 'all_headers': all_headers, 'hops': hops,
        'attachments': attachments, 'links': links,
        'body_text': body_text, 'body_html': body_html,
        'spf': spf, 'dkim': '있음' if dkim_sig else '없음',
        'x_originating_ip': x_ip, 'spoof_hint': spoof_hint,
    }


def _parse_eml(data: bytes) -> dict:
    msg = BytesParser(policy=_email_policy.compat32).parsebytes(data)
    return _build_email_result(msg)


def _parse_emlx(data: bytes) -> dict:
    # emlx = [byte_count]\n[RFC2822 message]\n[Apple plist XML]
    text = data.decode('utf-8', errors='replace')
    parts = text.split('\n', 1)
    body = parts[1] if len(parts) > 1 else text
    # Strip Apple plist at the end
    for marker in ('\n<?xml', '\n<plist'):
        idx = body.rfind(marker)
        if idx > 0:
            body = body[:idx]
    return _parse_eml(body.encode('utf-8'))


def _parse_msg(data: bytes) -> dict:
    import extract_msg
    _path = None
    try:
        msg = extract_msg.openMsg(io.BytesIO(data))
    except Exception:
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix='.msg')
        tmp.write(data)
        tmp.flush()
        tmp.close()
        _path = tmp.name
        msg = extract_msg.openMsg(_path)

    try:
        atts = []
        for att in (msg.attachments or []):
            atts.append({
                'name': getattr(att, 'longFilename', None) or getattr(att, 'shortFilename', 'attachment'),
                'type': getattr(att, 'mimetype', 'application/octet-stream') or 'application/octet-stream',
                'size': len(att.data or b''),
            })

        body_text = str(msg.body or '')
        body_html = str(msg.htmlBody or (b'' if isinstance(msg.htmlBody, bytes) else '')).strip()
        if isinstance(msg.htmlBody, bytes):
            body_html = msg.htmlBody.decode('utf-8', errors='replace')

        links = list(dict.fromkeys(re.findall(r'https?://[^\s<>"\'\)\]]+', body_html + body_text)))

        from_addr = str(msg.sender or '')
        reply_to  = str(msg.replyTo or '')
        spoof_hint = None
        if reply_to and from_addr:
            mf = re.search(r'@([\w.-]+)', from_addr)
            mr = re.search(r'@([\w.-]+)', reply_to)
            if mf and mr and mf.group(1).lower() != mr.group(1).lower():
                spoof_hint = f'From 도메인({mf.group(1)})과 Reply-To 도메인({mr.group(1)})이 다릅니다.'

        headers_raw = getattr(msg, 'header', None) or getattr(msg, 'headerDict', {})
        if isinstance(headers_raw, dict):
            all_headers = list(headers_raw.items())
        else:
            all_headers = [(str(k), str(v)) for k, v in getattr(msg, 'header', {}).items()]

        received = [v for k, v in all_headers if k.lower() == 'received']
        hops = []
        for rcv in received:
            ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', rcv)
            ts_m = re.search(r';\s*(.+)$', rcv)
            hops.append({'raw': str(rcv)[:200], 'ips': ips,
                         'timestamp': ts_m.group(1).strip() if ts_m else ''})

        auth = ''
        dkim = ''
        x_ip = ''
        for k, v in all_headers:
            kl = k.lower()
            if 'authentication' in kl or 'spf' in kl:
                auth = str(v)
            if 'dkim' in kl:
                dkim = str(v)
            if 'originating-ip' in kl or 'sender-ip' in kl:
                x_ip = str(v)

        return {
            'subject': str(msg.subject or ''),
            'sender': from_addr,
            'to': str(msg.to or ''),
            'cc': str(msg.cc or ''),
            'bcc': str(getattr(msg, 'bcc', '') or ''),
            'date': str(msg.date or ''),
            'message_id': '',
            'reply_to': reply_to,
            'all_headers': all_headers,
            'hops': hops,
            'attachments': atts,
            'links': links,
            'body_text': body_text,
            'body_html': body_html,
            'spf': auth,
            'dkim': '있음' if dkim else '없음',
            'x_originating_ip': x_ip,
            'spoof_hint': spoof_hint,
        }
    finally:
        msg.close()
        if _path:
            try:
                os.unlink(_path)
            except Exception:
                pass


def _parse_mbox(data: bytes) -> list:
    import mailbox as _mailbox
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix='.mbox', mode='wb')
    tmp.write(data)
    tmp.flush()
    tmp.close()
    results = []
    try:
        mbox = _mailbox.mbox(tmp.name)
        for msg in mbox:
            try:
                results.append(_build_email_result(msg))
            except Exception:
                continue
    finally:
        try:
            os.unlink(tmp.name)
        except Exception:
            pass
    return results


def _parse_email(data: bytes, filename: str = '') -> dict:
    ext = os.path.splitext(filename)[1].lower()
    if ext == '.msg':
        return _parse_msg(data)
    elif ext == '.emlx':
        return _parse_emlx(data)
    elif ext == '.mbox' or ext == '.mbx':
        msgs = _parse_mbox(data)
        if not msgs:
            return _parse_eml(data)
        return {
            'mbox_mode': True,
            'mbox_count': len(msgs),
            'mbox_all': msgs,
        }
    elif not ext:
        # 확장자 없으면 mbox 여부 heuristic (From_ 행으로 시작)
        first = data[:200].decode('utf-8', errors='replace').lstrip()
        if first.startswith('From '):
            msgs = _parse_mbox(data)
            if msgs:
                return {'mbox_mode': True, 'mbox_count': len(msgs), 'mbox_all': msgs}
    else:  # .eml, .txt, unknown
        return _parse_eml(data)


@bp.route('/email', methods=['GET', 'POST'])
def email_tool():
    result = None
    error = None
    share_token = None

    if request.method == 'POST':
        try:
            f = request.files.get('file')
            if not f or not f.filename:
                error = '이메일 파일을 선택하세요.'
                return render_template('tools/email.html', error=error)
            data = f.read(50 * 1024 * 1024)
            result = _parse_email(data, f.filename)
            if result and not result.get('mbox_mode'):
                summary = (f"{f.filename} | From: {result.get('sender','')} | "
                           f"첨부 {len(result.get('attachments',[]))}개 | 링크 {len(result.get('links',[]))}개")
                share_token = _save_log('email', '이메일 분석', f.filename, len(data), summary, {
                    'filename': f.filename,
                    'subject': result.get('subject', ''),
                    'sender': result.get('sender', ''),
                    'to': result.get('to', ''),
                    'spoof_hint': result.get('spoof_hint', ''),
                })
            elif result and result.get('mbox_mode'):
                summary = f"{f.filename} | MBOX {result['mbox_count']}개 메일"
                share_token = _save_log('email', '이메일 분석(MBOX)', f.filename, len(data), summary, {
                    'filename': f.filename, 'mbox_count': result['mbox_count'],
                })
        except Exception as e:
            error = str(e)

    return render_template('tools/email.html', result=result, error=error,
                           share_token=share_token)


# ─────────────────────────────────────────────────────────────────────────────
# ZIP 암호 해제
# ─────────────────────────────────────────────────────────────────────────────
_COMMON_PASSWORDS = [
    '', '123456', 'password', '12345678', 'qwerty', '123456789', '12345',
    '1234', '111111', '1234567', '123123', 'abc123', 'admin', 'welcome',
    'login', 'master', 'passw0rd', 'hello', 'test', '000000', '123',
    '1234567890', 'password1', 'iloveyou', 'sunshine', 'princess', 'dragon',
    'letmein', 'shadow', 'monkey', 'football', 'pass', 'secret', '654321',
    'superman', 'batman', 'qwerty123', 'pass123', 'user', 'guest',
    'samsung', 'korea', '2024', '2023', '1111', '0000', '9999', '1212',
]


def _try_zip_password(zf, first_file, password):
    try:
        pw_bytes = password.encode('utf-8', errors='ignore') if isinstance(password, str) else password
        zf.read(first_file, pwd=pw_bytes)
        return True
    except Exception:
        return False


@bp.route('/zipcrack', methods=['GET', 'POST'])
def zipcrack_tool():
    result = None
    error = None
    share_token = None

    if request.method == 'POST':
        try:
            f = request.files.get('file')
            if not f or not f.filename:
                error = 'ZIP 파일을 선택하세요.'
                return render_template('tools/zipcrack.html', error=error)

            data = f.read(MAX_UPLOAD)
            try:
                zf = zipfile.ZipFile(io.BytesIO(data))
            except zipfile.BadZipFile:
                error = '유효한 ZIP 파일이 아닙니다.'
                return render_template('tools/zipcrack.html', error=error)

            names = zf.namelist()
            if not names:
                error = 'ZIP 파일이 비어있습니다.'
                return render_template('tools/zipcrack.html', error=error)

            first_file = next((n for n in names if not n.endswith('/')), names[0])

            # Check if actually encrypted
            try:
                zf.read(first_file)
                result = {
                    'status': 'no_password',
                    'message': '이 ZIP 파일은 암호가 설정되어 있지 않습니다.',
                    'files': names[:50],
                    'file_count': len(names),
                    'tried': 0,
                }
                return render_template('tools/zipcrack.html', result=result, error=error)
            except RuntimeError:
                pass  # encrypted

            mode = request.form.get('mode', 'common')
            passwords = list(_COMMON_PASSWORDS)

            # Wordlist from upload
            wf = request.files.get('wordlist')
            if wf and wf.filename:
                wl_data = wf.read(10 * 1024 * 1024)
                for enc in ('utf-8', 'cp949', 'euc-kr', 'latin-1'):
                    try:
                        wl_text = wl_data.decode(enc)
                        break
                    except UnicodeDecodeError:
                        continue
                else:
                    wl_text = wl_data.decode('utf-8', errors='ignore')
                passwords += [l.strip() for l in wl_text.splitlines() if l.strip()]

            # Brute force
            if mode == 'bruteforce':
                import itertools, string as _str
                charset = request.form.get('charset', 'digits')
                max_len = min(int(request.form.get('bf_max_len', '4')), 6)
                charsets = {
                    'digits':   _str.digits,
                    'lower':    _str.ascii_lowercase,
                    'alphanum': _str.digits + _str.ascii_lowercase,
                }
                chars = charsets.get(charset, _str.digits)
                for length in range(1, max_len + 1):
                    for combo in itertools.product(chars, repeat=length):
                        passwords.append(''.join(combo))

            MAX_TRY = 30_000
            TIME_LIMIT = 8.0  # seconds
            found = None
            tried = 0
            import time as _time
            t_start = _time.monotonic()

            for pw in passwords[:MAX_TRY]:
                tried += 1
                if _try_zip_password(zf, first_file, pw):
                    found = pw
                    break
                if tried % 500 == 0 and (_time.monotonic() - t_start) > TIME_LIMIT:
                    break

            result = {
                'status': 'found' if found else 'not_found',
                'password': found if found else None,
                'tried': tried,
                'files': names[:50],
                'file_count': len(names),
                'filename': f.filename,
            }

            summary = (f"{f.filename} | {'성공: ' + repr(found) if found else '실패'} | "
                       f"{tried:,}개 시도")
            share_token = _save_log('zipcrack', 'ZIP 암호 해제', f.filename, len(data), summary, {
                'filename': f.filename, 'status': result['status'],
                'password': found, 'tried': tried,
            })

        except Exception as e:
            error = str(e)

    return render_template('tools/zipcrack.html', result=result, error=error,
                           share_token=share_token)


# ─────────────────────────────────────────────────────────────────────────────
# 파일 암호화 / 복호화 (AES-256-GCM + PBKDF2)
# ─────────────────────────────────────────────────────────────────────────────
_ENCRYPT_MAGIC = b'FLAB\x01\x00'   # 6-byte magic + version


def _derive_key(password: str, salt: bytes) -> bytes:
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes as _hashes
    kdf = PBKDF2HMAC(algorithm=_hashes.SHA256(), length=32, salt=salt, iterations=100_000)
    return kdf.derive(password.encode('utf-8'))


def _aes_gcm_encrypt(data: bytes, password: str) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = _derive_key(password, salt)
    ct = AESGCM(key).encrypt(nonce, data, None)
    return _ENCRYPT_MAGIC + salt + nonce + ct


def _aes_gcm_decrypt(data: bytes, password: str) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    if data[:6] != _ENCRYPT_MAGIC:
        raise ValueError('ForensicLab 암호화 파일 형식이 아닙니다.')
    salt = data[6:22]
    nonce = data[22:34]
    ct = data[34:]
    key = _derive_key(password, salt)
    try:
        return AESGCM(key).decrypt(nonce, ct, None)
    except Exception:
        raise ValueError('비밀번호가 틀리거나 파일이 손상되었습니다.')


@bp.route('/encrypt', methods=['GET', 'POST'])
def encrypt_tool():
    result = None
    error = None
    download_data = None
    download_name = None

    if request.method == 'POST':
        try:
            mode = request.form.get('mode', 'encrypt')
            password = request.form.get('password', '')
            f = request.files.get('file')

            if not f or not f.filename:
                error = '파일을 선택하세요.'
                return render_template('tools/encrypt.html', error=error)
            if not password:
                error = '비밀번호를 입력하세요.'
                return render_template('tools/encrypt.html', error=error)

            data = f.read(MAX_UPLOAD)

            if mode == 'encrypt':
                out = _aes_gcm_encrypt(data, password)
                download_name = f.filename + '.flab'
                result = {
                    'mode': 'encrypt',
                    'original_name': f.filename,
                    'original_size': len(data),
                    'encrypted_size': len(out),
                    'output_name': download_name,
                    'algorithm': 'AES-256-GCM',
                    'kdf': 'PBKDF2-HMAC-SHA256 (600,000 iterations)',
                }
                _save_log('encrypt', '파일 암호화', f.filename, len(data),
                          f'{f.filename} → {download_name} | AES-256-GCM', {
                              'mode': 'encrypt', 'filename': f.filename,
                              'original_size': len(data), 'encrypted_size': len(out),
                          })
                buf = io.BytesIO(out)
                buf.seek(0)
                return send_file(buf, as_attachment=True,
                                 download_name=download_name,
                                 mimetype='application/octet-stream')

            else:  # decrypt
                out = _aes_gcm_decrypt(data, password)
                # Recover original filename
                orig_name = f.filename
                if orig_name.endswith('.flab'):
                    orig_name = orig_name[:-5]
                else:
                    orig_name = 'decrypted_' + orig_name
                _save_log('encrypt', '파일 복호화', f.filename, len(data),
                          f'{f.filename} → {orig_name}', {
                              'mode': 'decrypt', 'filename': f.filename,
                              'decrypted_size': len(out),
                          })
                buf = io.BytesIO(out)
                buf.seek(0)
                return send_file(buf, as_attachment=True,
                                 download_name=orig_name,
                                 mimetype='application/octet-stream')

        except Exception as e:
            error = str(e)

    return render_template('tools/encrypt.html', result=result, error=error)


# ─────────────────────────────────────────────────────────────────────────────
# 레지스트리 분석
# ─────────────────────────────────────────────────────────────────────────────

_FORENSIC_REG_PATHS = [
    ('persistence',      '자동실행',     'high',
     'Software\\Microsoft\\Windows\\CurrentVersion\\Run',
     '부팅 시 자동 실행되는 프로그램 목록 — 악성코드 지속성 핵심 확인 포인트'),
    ('persistence_once', '자동실행(Once)', 'high',
     'Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce',
     '다음 부팅 시 한 번만 실행되는 프로그램'),
    ('winlogon',         '로그온훅',     'high',
     'Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon',
     'Userinit·Shell 값 위조 시 악성코드 지속성 — 정상값: userinit.exe / explorer.exe'),
    ('userassist',       '실행이력',     'high',
     'Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist',
     '실행된 프로그램과 횟수 (ROT13 인코딩)'),
    ('muicache',         'MUI캐시',      'medium',
     'Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\MuiCache',
     '실행 파일 표시 이름 캐시 — 파일 삭제 후에도 흔적 남음'),
    ('recent',           '최근문서',     'medium',
     'Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs',
     '최근에 열었던 파일 목록 (MRU 순서)'),
    ('typed_paths',      '입력경로',     'medium',
     'Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedPaths',
     '탐색기 주소창에 직접 입력한 경로 이력'),
    ('search',           '검색이력',     'medium',
     'Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\WordWheelQuery',
     '탐색기 검색창 입력 키워드 이력'),
    ('shellbags',        '폴더접근',     'medium',
     'Software\\Microsoft\\Windows\\Shell\\BagMRU',
     'ShellBags — 탐색한 폴더 이력 (네트워크·외장 드라이브 포함)'),
    ('ie_typed',         'IE URL이력',   'medium',
     'Software\\Microsoft\\Internet Explorer\\TypedURLs',
     'Internet Explorer 주소창 직접 입력 URL'),
    ('usb',              'USB장치',      'high',
     'System\\CurrentControlSet\\Enum\\USBSTOR',
     '연결된 USB 저장장치 이력 — 장치명·시리얼·연결 시각'),
    ('usb_cs1',          'USB장치(CS1)', 'high',
     'System\\ControlSet001\\Enum\\USBSTOR',
     'USB 저장장치 이력 (ControlSet001)'),
    ('network',          '네트워크이력', 'info',
     'Software\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Profiles',
     '연결된 네트워크 이름 및 최초·최후 접속 시각'),
    ('services',         '서비스',       'medium',
     'System\\CurrentControlSet\\Services',
     '등록된 서비스 목록 — 악성 서비스 확인'),
    ('timezone',         '타임존',       'info',
     'System\\CurrentControlSet\\Control\\TimeZoneInformation',
     '시스템 타임존 — 이벤트 로그 시각 해석에 필수'),
    ('computername',     '컴퓨터명',     'info',
     'System\\CurrentControlSet\\Control\\ComputerName\\ComputerName',
     '호스트명'),
    ('os_version',       'OS버전',       'info',
     'Software\\Microsoft\\Windows NT\\CurrentVersion',
     'Windows 버전·설치일·빌드번호'),
    ('profiles',         '사용자프로필', 'info',
     'Software\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList',
     '로그인 기록이 있는 사용자 SID 및 홈 디렉터리'),
]


def _reg_val_str(val):
    try:
        vt = val.value_type()
        v  = val.value()
        if vt in (1, 2):
            return str(v)
        if vt == 4:
            return f'{v}  (0x{v:08X})'
        if vt == 11:
            return f'{v}  (0x{v:016X})'
        if vt == 7:
            return ' | '.join(str(x) for x in v) if isinstance(v, list) else str(v)
        if vt == 3:
            return v.hex().upper()[:400] if isinstance(v, bytes) else str(v)[:400]
        return str(v)[:500]
    except Exception:
        return '(읽기 오류)'


def _walk_reg_key(key, counter, parent_path='', max_keys=200000):
    counter[0] += 1
    if counter[0] > max_keys:
        return None
    my_path = (parent_path + '\\' + key.name()).lstrip('\\')
    vals = []
    try:
        for v in key.values():
            try:
                vals.append({'n': v.name() or '(기본값)',
                             't': v.value_type_str(),
                             'v': _reg_val_str(v)})
            except Exception:
                pass
    except Exception:
        pass
    kids = []
    trunc = False
    try:
        for sub in key.subkeys():
            ch = _walk_reg_key(sub, counter, my_path, max_keys)
            if ch is None:
                trunc = True
                break
            kids.append(ch)
    except Exception:
        pass
    node = {'n': key.name(), 'p': my_path,
            'ts': str(key.timestamp())[:19], 'vals': vals, 'kids': kids}
    if trunc:
        node['trunc'] = True
    return node


def _parse_reg_hive(data: bytes, filename: str) -> dict:
    try:
        from Registry import Registry as _Reg
    except ImportError:
        raise ImportError('python-registry 패키지가 필요합니다.')

    tmp = tempfile.NamedTemporaryFile(delete=False, suffix='.hive')
    tmp.write(data); tmp.flush(); tmp.close()
    try:
        reg = _Reg.Registry(tmp.name)
        root = reg.root()
        root_name = root.name()

        findings = []
        for cat, cat_ko, sev, rel_path, desc in _FORENSIC_REG_PATHS:
            try:
                key = reg.open(rel_path)
                vals = []
                try:
                    for v in key.values():
                        vals.append({'n': v.name() or '(기본값)',
                                     't': v.value_type_str(),
                                     'v': _reg_val_str(v)[:300]})
                except Exception:
                    pass
                subkeys = []
                try:
                    for sk in key.subkeys():
                        sk_vals = []
                        try:
                            for sv in sk.values():
                                sk_vals.append({'n': sv.name() or '(기본값)',
                                                't': sv.value_type_str(),
                                                'v': _reg_val_str(sv)[:200]})
                        except Exception:
                            pass
                        subkeys.append({'name': sk.name(),
                                        'ts': str(sk.timestamp())[:19],
                                        'vals': sk_vals[:30]})
                        if len(subkeys) >= 200:
                            break
                except Exception:
                    pass
                findings.append({'category': cat, 'category_ko': cat_ko,
                                 'severity': sev, 'description': desc,
                                 'key_path': rel_path,
                                 'values': vals[:80], 'subkeys': subkeys})
            except Exception:
                pass

        counter = [0]
        tree = _walk_reg_key(root, counter)
        total_keys = counter[0]

        def _cnt(n):
            c = len(n.get('vals', []))
            for k in n.get('kids', []): c += _cnt(k)
            return c

        total_values = _cnt(tree) if tree else 0
    finally:
        try: os.unlink(tmp.name)
        except Exception: pass

    return {
        'filename': filename, 'format': 'hive', 'root_name': root_name,
        'total_keys': total_keys, 'total_values': total_values,
        'truncated': total_keys >= 200000, 'tree': tree, 'findings': findings,
    }


def _hex_decode_reg(hex_str: str) -> str:
    try:
        raw = bytes.fromhex(
            hex_str.replace(',', '').replace('\\', '').replace('\n', '').replace(' ', '')
        )
        return raw.decode('utf-16-le', errors='replace').rstrip('\x00')
    except Exception:
        return hex_str[:200]


def _parse_reg_text(data: bytes, filename: str) -> dict:
    text = ''
    for enc in ('utf-16-le', 'utf-8', 'cp1252', 'latin-1'):
        try:
            t = data.decode(enc).lstrip('﻿')
            if 'Windows Registry Editor' in t[:300] or '[HKEY' in t[:1000]:
                text = t
                break
        except Exception:
            continue
    if not text:
        text = data.decode('utf-8', errors='replace')

    keys = {}
    current = None
    buf = ''

    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        if buf:
            buf = buf.rstrip('\\') + line.strip()
            if not line.endswith('\\'):
                line = buf
                buf = ''
            else:
                continue
        elif line.endswith('\\') and not line.startswith(';') and not line.startswith('['):
            buf = line
            continue

        if not line or line.startswith(';'):
            continue

        km = re.match(r'^\[(-?)([^\]]+)\]$', line.strip())
        if km:
            current = km.group(2)
            if current not in keys:
                keys[current] = {'vals': []}
            continue

        if not current:
            continue

        dm = re.match(r'^@=(.+)$', line.strip())
        vm = re.match(r'^"((?:[^"\\]|\\.)*)"=(.*)$', line.strip()) if not dm else None

        if dm:
            vname, vdata = '(기본값)', dm.group(1)
        elif vm:
            vname = vm.group(1).replace('\\"', '"').replace('\\\\', '\\')
            vdata = vm.group(2)
        else:
            continue

        vdata = vdata.strip()
        if vdata.startswith('"') and vdata.endswith('"'):
            vtype = 'REG_SZ'
            vval = vdata[1:-1].replace('\\"', '"').replace('\\\\', '\\')
        elif vdata.lower().startswith('dword:'):
            try:
                n = int(vdata[6:], 16)
                vtype, vval = 'REG_DWORD', f'{n}  (0x{n:08X})'
            except Exception:
                vtype, vval = 'REG_DWORD', vdata
        elif vdata.lower().startswith('hex(2):'):
            vtype, vval = 'REG_EXPAND_SZ', _hex_decode_reg(vdata[7:])
        elif vdata.lower().startswith('hex(7):'):
            vtype, vval = 'REG_MULTI_SZ', _hex_decode_reg(vdata[7:])
        elif vdata.lower().startswith('hex:'):
            vtype, vval = 'REG_BINARY', vdata[4:].replace(',', ' ').upper()[:300]
        elif vdata.lower().startswith('hex('):
            vtype, vval = 'REG_HEX', vdata[:200]
        else:
            vtype, vval = 'REG_SZ', vdata

        keys[current]['vals'].append({'n': vname, 't': vtype, 'v': str(vval)[:500]})

    def build_node(path, depth=0):
        if depth > 50:
            return {'n': path.split('\\')[-1], 'p': path, 'ts': '',
                    'vals': keys.get(path, {'vals': []})['vals'], 'kids': []}
        prefix = path + '\\'
        seen, direct = set(), []
        for p in keys:
            if p.startswith(prefix):
                rel = p[len(prefix):]
                child_name = rel.split('\\')[0]
                cp = prefix + child_name
                if cp not in seen:
                    seen.add(cp)
                    direct.append(cp)
        direct.sort()
        kdata = keys.get(path, {'vals': []})
        return {
            'n': path.split('\\')[-1] or path,
            'p': path, 'ts': '',
            'vals': kdata['vals'],
            'kids': [build_node(cp, depth+1) for cp in direct[:300]],
        }

    top_keys = sorted(set(p.split('\\')[0] for p in keys))
    tree = {
        'n': filename, 'p': '', 'ts': '', 'vals': [],
        'kids': [build_node(r) for r in top_keys],
    }

    findings = []
    for cat, cat_ko, sev, rel_path, desc in _FORENSIC_REG_PATHS:
        rel_lo = rel_path.lower()
        matched = [(p, d) for p, d in keys.items() if rel_lo in p.lower()]
        for path, kdata in matched[:3]:
            findings.append({
                'category': cat, 'category_ko': cat_ko, 'severity': sev,
                'description': desc, 'key_path': path,
                'values': kdata['vals'][:80], 'subkeys': [],
            })

    total_keys = len(keys)
    total_values = sum(len(d['vals']) for d in keys.values())
    return {
        'filename': filename, 'format': 'reg_text', 'root_name': filename,
        'total_keys': total_keys, 'total_values': total_values,
        'truncated': False, 'tree': tree, 'findings': findings,
    }


def _parse_registry(data: bytes, filename: str) -> dict:
    if data[:4] == b'regf':
        return _parse_reg_hive(data, filename)
    for enc in ('utf-16-le', 'utf-8', 'cp1252', 'latin-1'):
        try:
            t = data.decode(enc).lstrip('﻿')
            if 'Windows Registry Editor' in t[:300] or '[HKEY' in t[:1000]:
                return _parse_reg_text(data, filename)
        except Exception:
            continue
    raise ValueError('인식할 수 없는 레지스트리 형식입니다. (.reg 텍스트 또는 바이너리 하이브 파일)')


@bp.route('/registry', methods=['GET', 'POST'])
def registry_tool():
    result = error = share_token = None
    if request.method == 'POST':
        try:
            f = request.files.get('file')
            if not f or not f.filename:
                error = '파일을 선택하세요.'
            else:
                data = f.read(200 * 1024 * 1024)
                result = _parse_registry(data, f.filename)
                summary = (f"{f.filename} | {result['total_keys']:,}개 키 | "
                           f"포렌식 발견 {len(result['findings'])}항목")
                share_token = _save_log('registry', '레지스트리 분석', f.filename,
                                        len(data), summary, {
                    'filename': f.filename, 'format': result['format'],
                    'total_keys': result['total_keys'],
                    'findings_count': len(result['findings']),
                })
        except ImportError as e:
            error = str(e)
        except ValueError as e:
            error = str(e)
        except Exception as e:
            error = f'분석 오류: {e}'
    return render_template('tools/registry.html', result=result, error=error,
                           share_token=share_token)


# 확장 분석 도구 (별도 모듈로 분리)
# PE/ELF/Mach-O · 엔트로피 · 다중 디코더 · Prefetch · LNK · 디스크 이미지 · 스크립트 허브
from monitor.views import tools_extra  # noqa: E402, F401
# 추가 20종 도구 (EVTX·SQLite·JumpList·VBA·PDF·JWT·X509·YARA·HexDiff·Secret·ESEDB·
#                   MFT·EmailAuth·DNS·Stego·QR·OCR·WHOIS·Passwd·Git)
from monitor.views import tools_extra2  # noqa: E402, F401
# 3차 확장 30종 (Plist·AmCache·HAR·Sigma·PSDeobf·IOC·시간·APK·해시룩업·HEIF·MemScan·
# Cuckoo·Vol·Magic·Docker·Hex·CIDR·Convert·Regex·JSDeobf·Wordlist·Spreadsheet·
# TextDiff·CVE·PHash·dmesg·iOS·WhatsApp·Telegram·PST)
from monitor.views import tools_extra3  # noqa: E402, F401
# 4차 확장 71종 (HTTP보안·TLS·포트스캔·DNS·다중해시·서명·자동라우터·PDF·모바일11·브라우저캐시·macOS7·클라우드10·악성8·압축7·암호5·유틸9)
from monitor.views import tools_extra4  # noqa: E402, F401
# 5차: 유료 도구 대결 — Volatility·CoC·LLM·백그라운드·Hashcat·ALEAPP·iLEAPP·E01·MFT
from monitor.views import tools_extra5  # noqa: E402, F401
# 6차: 엔터프라이즈 — 사건관리·검색·대시보드·PDF·ATT&CK·위협인텔·AI·Plaso·OCR인덱싱·얼굴인식
from monitor.views import tools_extra6  # noqa: E402, F401
# 7차: 도구별 도움말·사용법 + 컨텍스트 프로세서
from monitor.views import tools_extra7  # noqa: E402, F401
# 8차: 포렌식 가이드 — 핵심 경로·초보자 시나리오·용어집
from monitor.views import tools_extra8  # noqa: E402, F401
# 9차: 암호화 해제 — BitLocker·LUKS·VeraCrypt·암호 ZIP/Office/PDF 복호화 + 크래킹
from monitor.views import tools_extra9  # noqa: E402, F401
# 10차: AI 침입자 허니트랩 — LLM 에이전트 탐지·차단·박제 (프롬프트 인젝션 카나리)
from monitor.views import tools_extra10  # noqa: E402, F401
# 딥 패킷 분석 — forensiclab 라이브러리 기반 80여종 프로토콜 디섹터(ICS/SCADA·IoT·DB·VoIP)
from monitor.views import tools_deep_pcap  # noqa: E402, F401
