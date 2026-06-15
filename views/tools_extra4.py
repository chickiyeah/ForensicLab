"""ForensicLab 4차 확장 — 71개 신규 도구"""
import base64
import datetime as _dt
import gzip
import hashlib
import hmac
import io
import json
import os
import re
import socket
import ssl
import struct
import sqlite3
import tempfile
import urllib.parse
import urllib.request
import zipfile
import zlib
from collections import Counter, defaultdict
from pathlib import Path

from flask import request, render_template, jsonify
from monitor.views.tools import bp, _save_log
from monitor.views.tools_extra3 import get_files, _extract_iocs


# ====================================================================
# 1. /tools/httpsec — HTTP 보안 헤더 검사
# ====================================================================
_SEC_HEADERS = {
    'strict-transport-security': ('HSTS', '클라이언트 HTTPS 강제'),
    'content-security-policy': ('CSP', 'XSS/리소스 로드 정책'),
    'x-frame-options': ('Frame', '클릭재킹 방어'),
    'x-content-type-options': ('Type', 'MIME 스니핑 차단 (nosniff)'),
    'referrer-policy': ('Referrer', 'Referer 헤더 정책'),
    'permissions-policy': ('Permissions', '브라우저 기능 정책'),
    'cross-origin-embedder-policy': ('COEP', 'Cross-origin 격리'),
    'cross-origin-opener-policy': ('COOP', 'Cross-origin 격리'),
    'cross-origin-resource-policy': ('CORP', 'Cross-origin 자원 정책'),
    'x-xss-protection': ('XSS', 'XSS 필터 (구식, 비권장)'),
}

@bp.route('/httpsec', methods=['GET','POST'])
def httpsec_tool():
    result = error = None
    if request.method == 'POST':
        url = (request.form.get('url') or '').strip()
        if not url: error = 'URL 입력'
        else:
            if not url.startswith(('http://','https://')): url = 'https://' + url
            try:
                req = urllib.request.Request(url, headers={'User-Agent': 'ForensicLab/1.0'})
                with urllib.request.urlopen(req, timeout=10) as r:
                    headers = {k.lower(): v for k, v in r.headers.items()}
                    status = r.status
                checks = []
                score = 0
                for h, (name, desc) in _SEC_HEADERS.items():
                    present = h in headers
                    val = headers.get(h, '')
                    checks.append({'header': h, 'name': name, 'desc': desc,
                                   'present': present, 'value': val[:200]})
                    if present: score += 10
                # Cookies 검사
                cookies = headers.get('set-cookie', '')
                cookie_flags = []
                if cookies:
                    if 'secure' in cookies.lower(): cookie_flags.append('Secure')
                    if 'httponly' in cookies.lower(): cookie_flags.append('HttpOnly')
                    if 'samesite' in cookies.lower(): cookie_flags.append('SameSite')
                grade = 'A+' if score >= 90 else 'A' if score >= 70 else 'B' if score >= 50 else 'C' if score >= 30 else 'F'
                result = {'url': url, 'status': status, 'score': score,
                          'grade': grade, 'checks': checks,
                          'server': headers.get('server',''),
                          'cookie_flags': cookie_flags,
                          'all_headers': dict(headers)}
            except Exception as e: error = str(e)
    return render_template('tools/httpsec.html', result=result, error=error)


# ====================================================================
# 2. /tools/tls — TLS 인증서 체인 검증
# ====================================================================
@bp.route('/tls', methods=['GET','POST'])
def tls_tool():
    result = error = None
    if request.method == 'POST':
        target = (request.form.get('target') or '').strip()
        if not target: error = 'host:port 입력'
        else:
            try:
                if ':' in target: host, port = target.rsplit(':', 1); port = int(port)
                else: host, port = target, 443
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                with socket.create_connection((host, port), timeout=10) as sock:
                    with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                        cipher = ssock.cipher()
                        version = ssock.version()
                        der = ssock.getpeercert(binary_form=True)
                        cert_info = ssock.getpeercert()
                # 인증서 파싱
                from cryptography import x509
                from cryptography.hazmat.primitives import hashes
                cert = x509.load_der_x509_certificate(der)
                warnings = []
                now = _dt.datetime.now(_dt.timezone.utc)
                days_left = (cert.not_valid_after_utc - now).days
                if days_left < 0: warnings.append(f'⚠️ 만료됨 ({-days_left}일 전)')
                elif days_left < 30: warnings.append(f'⚠️ 만료 임박 ({days_left}일 남음)')
                if cert.subject == cert.issuer: warnings.append('ℹ️ 자가 서명')
                sig_alg = cert.signature_algorithm_oid._name
                if 'sha1' in sig_alg.lower() or 'md5' in sig_alg.lower():
                    warnings.append(f'⚠️ 취약한 서명 알고리즘: {sig_alg}')
                if version in ('TLSv1', 'TLSv1.1', 'SSLv3', 'SSLv2'):
                    warnings.append(f'⚠️ 취약한 TLS 버전: {version}')
                if cipher and any(w in cipher[0] for w in ['RC4','DES','MD5','EXPORT','NULL']):
                    warnings.append(f'⚠️ 취약한 cipher: {cipher[0]}')
                try:
                    san = cert.extensions.get_extension_for_oid(
                        x509.OID_SUBJECT_ALTERNATIVE_NAME)
                    sans = [n.value for n in san.value]
                except Exception: sans = []
                result = {
                    'host': host, 'port': port,
                    'tls_version': version,
                    'cipher': cipher[0] if cipher else '',
                    'cipher_bits': cipher[2] if cipher else 0,
                    'subject': cert.subject.rfc4514_string(),
                    'issuer': cert.issuer.rfc4514_string(),
                    'serial': hex(cert.serial_number),
                    'not_before': cert.not_valid_before_utc.isoformat(),
                    'not_after': cert.not_valid_after_utc.isoformat(),
                    'days_left': days_left,
                    'signature_algorithm': sig_alg,
                    'sha256': cert.fingerprint(hashes.SHA256()).hex(),
                    'sans': sans,
                    'warnings': warnings,
                }
            except Exception as e: error = str(e)
    return render_template('tools/tls.html', result=result, error=error)


# ====================================================================
# 3. /tools/portscan — 안전 포트 스캐너 (제한적)
# ====================================================================
_COMMON_PORTS = {
    21:'FTP',22:'SSH',23:'Telnet',25:'SMTP',53:'DNS',80:'HTTP',110:'POP3',
    111:'RPC',135:'MSRPC',139:'NetBIOS',143:'IMAP',389:'LDAP',443:'HTTPS',
    445:'SMB',465:'SMTPS',587:'SMTP',636:'LDAPS',993:'IMAPS',995:'POP3S',
    1433:'MSSQL',1521:'Oracle',1723:'PPTP',3306:'MySQL',3389:'RDP',5060:'SIP',
    5432:'PostgreSQL',5900:'VNC',5985:'WinRM',5986:'WinRM-S',6379:'Redis',
    8000:'HTTP-alt',8080:'HTTP-Proxy',8443:'HTTPS-alt',9000:'Various',
    27017:'MongoDB',9200:'Elasticsearch',11211:'Memcached',
}

@bp.route('/portscan', methods=['GET','POST'])
def portscan_tool():
    result = error = None
    if request.method == 'POST':
        host = (request.form.get('host') or '').strip()
        if not host: error = '호스트 입력'
        # 안전 차단: 사설 IP 또는 localhost 만, 또는 사용자 확인된 호스트
        else:
            try:
                import time
                # 호스트 해석
                ip = socket.gethostbyname(host)
                # 사설/공용 분류
                octets = list(map(int, ip.split('.')))
                is_private = (octets[0] == 10 or octets[0] == 127 or
                              (octets[0] == 172 and 16 <= octets[1] <= 31) or
                              (octets[0] == 192 and octets[1] == 168))
                open_ports = []
                closed = 0
                t0 = time.time()
                for port, svc in _COMMON_PORTS.items():
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(0.5)
                    try:
                        r = sock.connect_ex((ip, port))
                        if r == 0:
                            # 배너 시도
                            banner = ''
                            try:
                                sock.settimeout(1)
                                sock.send(b'\r\n')
                                banner = sock.recv(256).decode('latin1', errors='replace').strip()
                            except Exception: pass
                            open_ports.append({'port': port, 'service': svc, 'banner': banner[:200]})
                        else: closed += 1
                    except Exception: closed += 1
                    finally: sock.close()
                result = {
                    'host': host, 'ip': ip, 'is_private': is_private,
                    'open_ports': open_ports, 'closed_count': closed,
                    'total_scanned': len(_COMMON_PORTS),
                    'duration': round(time.time() - t0, 2),
                }
            except Exception as e: error = str(e)
    return render_template('tools/portscan.html', result=result, error=error)


# ====================================================================
# 4. /tools/dnslookup — DNS 종합 조회
# ====================================================================
@bp.route('/dnslookup', methods=['GET','POST'])
def dnslookup_tool():
    result = error = None
    if request.method == 'POST':
        domain = (request.form.get('domain') or '').strip()
        if not domain: error = '도메인 입력'
        else:
            try:
                import dns.resolver
                resolver = dns.resolver.Resolver()
                resolver.timeout = 3; resolver.lifetime = 5
                records = {}
                for rtype in ['A','AAAA','MX','NS','TXT','SOA','CAA','CNAME','SRV','PTR']:
                    try:
                        ans = resolver.resolve(domain, rtype)
                        records[rtype] = [str(r) for r in ans]
                    except Exception: records[rtype] = []
                # DMARC / SPF / DKIM
                spf_dmarc = {}
                for sub, rtype in [('', 'TXT'), ('_dmarc.', 'TXT')]:
                    try:
                        ans = resolver.resolve(f'{sub}{domain}', 'TXT')
                        for r in ans:
                            for s in r.strings:
                                t = s.decode('utf-8',errors='replace')
                                if t.startswith('v=spf1'): spf_dmarc['SPF'] = t
                                if t.startswith('v=DMARC1'): spf_dmarc['DMARC'] = t
                                if t.startswith('v=DKIM1'): spf_dmarc.setdefault('DKIM', []).append(t)
                    except Exception: pass
                result = {'domain': domain, 'records': records, 'email_auth': spf_dmarc}
            except ImportError:
                error = 'dnspython 미설치'
            except Exception as e: error = str(e)
    return render_template('tools/dnslookup.html', result=result, error=error)


# ====================================================================
# 5. /tools/multihash — 다중 해시
# ====================================================================
@bp.route('/multihash', methods=['GET','POST'])
def multihash_tool():
    result = error = None
    if request.method == 'POST':
        files = get_files()
        text = (request.form.get('text') or '').strip()
        items = []
        if files:
            for f in files:
                d = f.read()
                items.append({'name': f.filename, 'data': d})
        if text:
            items.append({'name': '(텍스트)', 'data': text.encode('utf-8')})
        if not items: error = '파일 또는 텍스트 필요'
        else:
            results = []
            for it in items:
                d = it['data']
                h = {'name': it['name'], 'size': len(d)}
                for alg in ['md5','sha1','sha256','sha384','sha512',
                            'sha3_256','sha3_512','blake2b','blake2s']:
                    try: h[alg] = hashlib.new(alg, d).hexdigest()
                    except ValueError: pass
                # CRC32
                h['crc32'] = f'{zlib.crc32(d):08x}'
                # Adler32
                h['adler32'] = f'{zlib.adler32(d):08x}'
                results.append(h)
            result = {'files': results}
    return render_template('tools/multihash.html', result=result, error=error)


# ====================================================================
# 6. /tools/sign — HMAC / RSA / ECDSA 서명 검증
# ====================================================================
@bp.route('/sign', methods=['GET','POST'])
def sign_tool():
    result = error = None
    if request.method == 'POST':
        algo = request.form.get('algo', 'hmac')
        data = (request.form.get('data') or '').encode('utf-8')
        key = (request.form.get('key') or '').strip()
        sig = (request.form.get('signature') or '').strip()
        action = request.form.get('action', 'verify')
        try:
            if algo == 'hmac':
                hash_name = request.form.get('hash', 'sha256')
                h = hmac.new(key.encode('utf-8'), data, getattr(hashlib, hash_name)).hexdigest()
                if action == 'compute':
                    result = {'algo': f'HMAC-{hash_name}', 'computed': h}
                else:
                    result = {'algo': f'HMAC-{hash_name}', 'computed': h,
                              'provided': sig, 'valid': hmac.compare_digest(h, sig)}
            elif algo in ('rsa', 'ecdsa', 'ed25519'):
                from cryptography.hazmat.primitives import hashes as _h
                from cryptography.hazmat.primitives.serialization import load_pem_public_key
                from cryptography.hazmat.primitives.asymmetric import padding, ec, rsa, ed25519
                pubkey = load_pem_public_key(key.encode())
                try:
                    sig_bytes = base64.b64decode(sig)
                except Exception:
                    sig_bytes = bytes.fromhex(sig)
                try:
                    if isinstance(pubkey, rsa.RSAPublicKey):
                        pubkey.verify(sig_bytes, data, padding.PKCS1v15(), _h.SHA256())
                        result = {'algo': 'RSA-PKCS1v15-SHA256', 'valid': True}
                    elif isinstance(pubkey, ec.EllipticCurvePublicKey):
                        pubkey.verify(sig_bytes, data, ec.ECDSA(_h.SHA256()))
                        result = {'algo': 'ECDSA-SHA256', 'valid': True}
                    elif isinstance(pubkey, ed25519.Ed25519PublicKey):
                        pubkey.verify(sig_bytes, data)
                        result = {'algo': 'Ed25519', 'valid': True}
                    else:
                        error = '지원하지 않는 키 유형'
                except Exception as e:
                    result = {'algo': algo, 'valid': False, 'reason': str(e)}
        except Exception as e: error = str(e)
    return render_template('tools/sign.html', result=result, error=error)


# ====================================================================
# 7. /tools/auto — 자동 분류 라우터
# ====================================================================
_AUTO_ROUTER = [
    (b'MZ', 'pe', 'PE 실행파일'),
    (b'\x7fELF', 'pe', 'ELF 실행파일'),
    (b'\xCF\xFA\xED\xFE', 'pe', 'Mach-O 64-bit'),
    (b'%PDF', 'pdfscan', 'PDF'),
    (b'\xD0\xCF\x11\xE0', 'oledump', 'OLE2 Office'),
    (b'PK\x03\x04', 'oledump', 'ZIP/Office/APK/JAR'),
    (b'regf', 'registry', 'Registry Hive'),
    (b'ElfFile\x00', 'evtx', 'EVTX'),
    (b'SCCA', 'prefetch', 'Prefetch SCCA'),
    (b'MAM\x84', 'prefetch', 'Prefetch MAM'),
    (b'\x4C\x00\x00\x00\x01\x14\x02', 'lnk', 'LNK 바로가기'),
    (b'SQLite format 3\x00', 'sqlite', 'SQLite DB'),
    (b'\xEF\xCD\xAB\x89', 'esedb', 'ESE DB'),
    (b'bplist00', 'plist', 'macOS Binary Plist'),
    (b'<?xml', 'convert', 'XML'),
    (b'{', 'convert', 'JSON 가능성'),
    (b'\xFF\xD8\xFF', 'metadata', 'JPEG'),
    (b'\x89PNG\r\n\x1a\n', 'metadata', 'PNG'),
    (b'\x00\x00\x00', 'heif', 'HEIC/HEIF/MP4 가능성'),
    (b'-----BEGIN', 'cert', 'PEM 인증서/키'),
    (b'FILE', 'mft', '$MFT FILE 레코드'),
    (b'eyJ', 'jwt', 'JWT 가능성 (base64 헤더)'),
    (b'!BDN', 'pst', 'Outlook PST/OST'),
    (b'EVF\x09\x0D\x0A\xFF\x00', 'diskimg', 'EnCase E01'),
    (b'vhdxfile', 'diskimg', 'VHDX'),
    (b'TDF$', 'telegram', 'Telegram tdata'),
]

@bp.route('/auto', methods=['GET','POST'])
def auto_tool():
    result = error = None
    if request.method == 'POST':
        files = get_files()
        if not files: error = '파일 필요'
        else:
            results = []
            for f in files:
                head = f.read(64)
                matches = []
                for sig, tool, label in _AUTO_ROUTER:
                    if head.startswith(sig):
                        matches.append({'tool': tool, 'label': label,
                                        'url': f'/tools/{tool}'})
                f.seek(0)
                full = f.read()
                results.append({
                    'filename': f.filename, 'size': len(full),
                    'matches': matches,
                    'hex': head.hex()[:64],
                    'sha256': hashlib.sha256(full).hexdigest(),
                })
            result = {'files': results}
    return render_template('tools/auto.html', result=result, error=error)


# ====================================================================
# 8. /tools/report-pdf — 통합 보고서 안내 (기존 report.html 활용)
# ====================================================================
@bp.route('/report-pdf', methods=['GET'])
def report_pdf_tool():
    return render_template('tools/report_pdf.html')


# ====================================================================
# 모바일 SQLite 공용 도구
# ====================================================================
def _sqlite_summary(data: bytes, expected_tables: list = None) -> dict:
    if data[:16] != b'SQLite format 3\x00':
        return {'error': 'SQLite 시그니처 없음'}
    tf = tempfile.NamedTemporaryFile(delete=False, suffix='.db')
    tf.write(data); tf.close()
    try:
        con = sqlite3.connect(f'file:{tf.name}?mode=ro', uri=True)
        cur = con.cursor()
        tables = [r[0] for r in cur.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")]
        table_info = []
        for t in tables[:50]:
            try:
                cnt = cur.execute(f'SELECT COUNT(*) FROM "{t}"').fetchone()[0]
                cols = [r[1] for r in cur.execute(f'PRAGMA table_info("{t}")')]
                table_info.append({'name': t, 'rows': cnt, 'cols': cols})
            except Exception: pass
        return {'tables': table_info, 'cur': cur, 'con': con, 'tf': tf.name}
    except Exception as e:
        return {'error': str(e)}

def _close_sqlite(meta):
    if 'con' in meta:
        try: meta['con'].close()
        except Exception: pass
    if 'tf' in meta:
        try: os.unlink(meta['tf'])
        except Exception: pass

def _convert_chrome_time(ts):
    if not ts: return ''
    try:
        return (_dt.datetime(1601,1,1) + _dt.timedelta(microseconds=int(ts))).isoformat()
    except Exception: return str(ts)
def _convert_cocoa_time(ts):
    if not ts: return ''
    try:
        return (_dt.datetime(2001,1,1) + _dt.timedelta(seconds=float(ts))).isoformat()
    except Exception: return str(ts)
def _convert_unix(ts, divisor=1):
    if not ts: return ''
    try:
        return _dt.datetime.utcfromtimestamp(int(ts)/divisor).isoformat()
    except Exception: return str(ts)


# ====================================================================
# 9-13. iOS 모바일 (sms, photos, calendar, notes, health)
# ====================================================================
def _mobile_sqlite_route(name, parser_fn):
    def view():
        result = error = None
        if request.method == 'POST':
            f = request.files.get('file')
            if not f or not f.filename: return render_template(f'tools/{name}.html', error='파일 필요')
            data = f.read()
            try:
                result = parser_fn(data)
                if result and 'error' not in result:
                    result['filename'] = f.filename
                    result['size'] = len(data)
                elif result:
                    error = result['error']; result = None
            except Exception as e: error = str(e)
        return render_template(f'tools/{name}.html', result=result, error=error)
    view.__name__ = f'{name}_view'
    return view

def _parse_ios_sms(data):
    meta = _sqlite_summary(data)
    if 'error' in meta: return meta
    try:
        cur = meta['cur']
        msgs = list(cur.execute(
            "SELECT m.ROWID, m.date, m.text, m.is_from_me, h.id "
            "FROM message m LEFT JOIN handle h ON m.handle_id = h.ROWID "
            "ORDER BY m.date DESC LIMIT 200"))
        return {'messages': [
            {'id': m[0], 'time': _convert_cocoa_time(m[1]/1e9 if m[1] and m[1] > 1e15 else m[1]),
             'text': (m[2] or '')[:500], 'from_me': bool(m[3]),
             'contact': m[4] or ''} for m in msgs],
            'tables': meta['tables']}
    finally: _close_sqlite(meta)

bp.add_url_rule('/ios-sms', view_func=_mobile_sqlite_route('ios_sms', _parse_ios_sms),
                methods=['GET','POST'])


def _parse_ios_photos(data):
    meta = _sqlite_summary(data)
    if 'error' in meta: return meta
    try:
        cur = meta['cur']
        # ZGENERICASSET 테이블 (Photos.sqlite iOS 13+)
        photos = []
        try:
            for r in cur.execute("SELECT Z_PK, ZFILENAME, ZDATECREATED, ZWIDTH, ZHEIGHT, ZDIRECTORY "
                                 "FROM ZASSET LIMIT 200"):
                photos.append({'id': r[0], 'filename': r[1] or '',
                               'date': _convert_cocoa_time(r[2]),
                               'size': f'{r[3]}x{r[4]}', 'dir': r[5] or ''})
        except sqlite3.Error: pass
        return {'photos': photos, 'tables': meta['tables']}
    finally: _close_sqlite(meta)
bp.add_url_rule('/ios-photos', view_func=_mobile_sqlite_route('ios_photos', _parse_ios_photos),
                methods=['GET','POST'])


def _parse_ios_calendar(data):
    meta = _sqlite_summary(data)
    if 'error' in meta: return meta
    try:
        cur = meta['cur']
        events = []
        try:
            for r in cur.execute("SELECT ROWID, summary, description, start_date, end_date, location "
                                 "FROM CalendarItem LIMIT 200"):
                events.append({'id': r[0], 'summary': r[1] or '', 'desc': (r[2] or '')[:200],
                               'start': _convert_cocoa_time(r[3]),
                               'end': _convert_cocoa_time(r[4]),
                               'location': r[5] or ''})
        except sqlite3.Error: pass
        return {'events': events, 'tables': meta['tables']}
    finally: _close_sqlite(meta)
bp.add_url_rule('/ios-calendar', view_func=_mobile_sqlite_route('ios_calendar', _parse_ios_calendar),
                methods=['GET','POST'])


def _parse_ios_notes(data):
    meta = _sqlite_summary(data)
    if 'error' in meta: return meta
    try:
        cur = meta['cur']
        notes = []
        try:
            for r in cur.execute("SELECT Z_PK, ZTITLE1, ZSNIPPET, ZCREATIONDATE1, ZMODIFICATIONDATE1 "
                                 "FROM ZICCLOUDSYNCINGOBJECT WHERE ZTITLE1 IS NOT NULL LIMIT 200"):
                notes.append({'id': r[0], 'title': r[1] or '',
                              'snippet': (r[2] or '')[:300],
                              'created': _convert_cocoa_time(r[3]),
                              'modified': _convert_cocoa_time(r[4])})
        except sqlite3.Error: pass
        return {'notes': notes, 'tables': meta['tables']}
    finally: _close_sqlite(meta)
bp.add_url_rule('/ios-notes', view_func=_mobile_sqlite_route('ios_notes', _parse_ios_notes),
                methods=['GET','POST'])


def _parse_ios_health(data):
    meta = _sqlite_summary(data)
    if 'error' in meta: return meta
    try:
        cur = meta['cur']
        samples = []
        types = []
        try:
            for r in cur.execute("SELECT name FROM hd_data_provenances LIMIT 50"):
                types.append(r[0])
        except sqlite3.Error: pass
        try:
            for r in cur.execute("SELECT data_type, MIN(start_date), MAX(end_date), COUNT(*) "
                                 "FROM samples GROUP BY data_type LIMIT 50"):
                samples.append({'type': r[0], 'first': _convert_cocoa_time(r[1]),
                                'last': _convert_cocoa_time(r[2]), 'count': r[3]})
        except sqlite3.Error: pass
        return {'samples': samples, 'sources': types, 'tables': meta['tables']}
    finally: _close_sqlite(meta)
bp.add_url_rule('/ios-health', view_func=_mobile_sqlite_route('ios_health', _parse_ios_health),
                methods=['GET','POST'])


# ====================================================================
# 14-17. Android 모바일
# ====================================================================
def _parse_android_contacts(data):
    meta = _sqlite_summary(data)
    if 'error' in meta: return meta
    try:
        cur = meta['cur']
        contacts = []
        try:
            for r in cur.execute("SELECT _id, display_name, last_time_contacted, times_contacted, "
                                 "starred FROM contacts LIMIT 200"):
                contacts.append({'id': r[0], 'name': r[1] or '',
                                 'last_contact': _convert_unix(r[2], 1000) if r[2] else '',
                                 'times': r[3] or 0, 'starred': bool(r[4])})
        except sqlite3.Error: pass
        return {'contacts': contacts, 'tables': meta['tables']}
    finally: _close_sqlite(meta)
bp.add_url_rule('/android-contacts',
                view_func=_mobile_sqlite_route('android_contacts', _parse_android_contacts),
                methods=['GET','POST'])


def _parse_android_sms(data):
    meta = _sqlite_summary(data)
    if 'error' in meta: return meta
    try:
        cur = meta['cur']
        msgs = []
        try:
            for r in cur.execute("SELECT _id, address, body, date, type, read FROM sms "
                                 "ORDER BY date DESC LIMIT 200"):
                msgs.append({'id': r[0], 'address': r[1] or '',
                             'body': (r[2] or '')[:300],
                             'date': _convert_unix(r[3], 1000),
                             'type': {1:'수신', 2:'발신', 3:'초안'}.get(r[4], r[4]),
                             'read': bool(r[5])})
        except sqlite3.Error: pass
        return {'messages': msgs, 'tables': meta['tables']}
    finally: _close_sqlite(meta)
bp.add_url_rule('/android-sms',
                view_func=_mobile_sqlite_route('android_sms', _parse_android_sms),
                methods=['GET','POST'])


def _parse_android_calllog(data):
    meta = _sqlite_summary(data)
    if 'error' in meta: return meta
    try:
        cur = meta['cur']
        calls = []
        try:
            for r in cur.execute("SELECT _id, number, date, duration, type, name FROM calls "
                                 "ORDER BY date DESC LIMIT 200"):
                calls.append({'id': r[0], 'number': r[1] or '',
                              'date': _convert_unix(r[2], 1000),
                              'duration': r[3] or 0,
                              'type': {1:'수신', 2:'발신', 3:'부재중', 5:'거절', 6:'차단'}.get(r[4], r[4]),
                              'name': r[5] or ''})
        except sqlite3.Error: pass
        return {'calls': calls, 'tables': meta['tables']}
    finally: _close_sqlite(meta)
bp.add_url_rule('/android-calllog',
                view_func=_mobile_sqlite_route('android_calllog', _parse_android_calllog),
                methods=['GET','POST'])


# Android Wi-Fi - 텍스트 파일 분석
@bp.route('/android-wifi', methods=['GET','POST'])
def android_wifi_tool():
    result = error = None
    if request.method == 'POST':
        f = request.files.get('file')
        if not f or not f.filename: error = 'wpa_supplicant.conf 또는 WifiConfigStore.xml 필요'
        else:
            data = f.read().decode('utf-8', errors='replace')
            networks = []
            # wpa_supplicant.conf
            for m in re.finditer(r'network=\{([^}]+)\}', data, re.S):
                block = m.group(1)
                net = {}
                for line in block.split('\n'):
                    line = line.strip()
                    if '=' in line:
                        k, v = line.split('=', 1)
                        net[k.strip()] = v.strip().strip('"')
                if net: networks.append(net)
            # WifiConfigStore.xml
            for m in re.finditer(r'<Network>(.+?)</Network>', data, re.S):
                block = m.group(1)
                net = {'format': 'XML'}
                ssid = re.search(r'name="SSID"[^>]*>([^<]+)', block)
                psk = re.search(r'name="PreSharedKey"[^>]*>([^<]+)', block)
                if ssid: net['ssid'] = ssid.group(1).strip('&quot;')
                if psk: net['psk'] = psk.group(1).strip('&quot;')
                if net: networks.append(net)
            result = {'networks': networks, 'count': len(networks)}
    return render_template('tools/android_wifi.html', result=result, error=error)


# ====================================================================
# 18-23. macOS 추가 (FSEvents, KnowledgeC, Quarantine, Spotlight, Keychain, TCC)
# ====================================================================
def _parse_fsevents(data):
    """FSEvents .fseventsd/*.gz 파싱"""
    if data[:2] == b'\x1f\x8b':
        data = gzip.decompress(data)
    if data[:4] not in (b'1SLD', b'2SLD', b'3SLD'):
        return {'error': '1SLD/2SLD/3SLD 시그니처 없음'}
    version = data[:4].decode()
    unknown = struct.unpack('<I', data[4:8])[0]
    ending_eid = struct.unpack('<Q', data[8:16])[0]
    events = []
    pos = 16
    while pos < len(data):
        null = data.find(b'\x00', pos)
        if null < 0: break
        path = data[pos:null].decode('utf-8', errors='replace')
        pos = null + 1
        if pos + 12 > len(data): break
        event_id = struct.unpack('<Q', data[pos:pos+8])[0]
        flags = struct.unpack('<I', data[pos+8:pos+12])[0]
        pos += 12
        if version >= '2SLD':
            if pos + 8 > len(data): break
            node_id = struct.unpack('<Q', data[pos:pos+8])[0]
            pos += 8
        else: node_id = 0
        flag_names = []
        for bit, name in [(1,'생성'),(2,'삭제'),(4,'inode 메타'),(8,'이름변경'),
                          (0x10,'수정'),(0x20,'교환'),(0x40,'FinderInfo'),
                          (0x80,'폴더생성'),(0x100,'권한변경')]:
            if flags & bit: flag_names.append(name)
        events.append({'event_id': event_id, 'path': path[:300],
                       'flags': flag_names, 'node_id': node_id})
        if len(events) > 5000: break
    return {'version': version, 'ending_eid': ending_eid,
            'events': events[:1000], 'total': len(events)}

@bp.route('/fsevents', methods=['GET','POST'])
def fsevents_tool():
    result = error = None
    if request.method == 'POST':
        f = request.files.get('file')
        if not f or not f.filename: error = 'FSEvents 파일 (gz) 필요'
        else:
            try:
                result = _parse_fsevents(f.read())
                if 'error' in result: error = result['error']; result = None
                else: result['filename'] = f.filename
            except Exception as e: error = str(e)
    return render_template('tools/fsevents.html', result=result, error=error)


def _parse_knowledgec(data):
    meta = _sqlite_summary(data)
    if 'error' in meta: return meta
    try:
        cur = meta['cur']
        usage = []
        try:
            for r in cur.execute(
                "SELECT ZSTREAMNAME, ZVALUESTRING, ZSTARTDATE, ZENDDATE "
                "FROM ZOBJECT ORDER BY ZSTARTDATE DESC LIMIT 200"):
                usage.append({'stream': r[0] or '', 'value': r[1] or '',
                              'start': _convert_cocoa_time(r[2]),
                              'end': _convert_cocoa_time(r[3])})
        except sqlite3.Error as e: meta['error'] = str(e)
        return {'usage': usage, 'tables': meta.get('tables', [])}
    finally: _close_sqlite(meta)
bp.add_url_rule('/knowledgec',
                view_func=_mobile_sqlite_route('knowledgec', _parse_knowledgec),
                methods=['GET','POST'])


def _parse_quarantine(data):
    meta = _sqlite_summary(data)
    if 'error' in meta: return meta
    try:
        cur = meta['cur']
        events = []
        try:
            for r in cur.execute(
                "SELECT LSQuarantineEventIdentifier, LSQuarantineTimeStamp, "
                "LSQuarantineAgentName, LSQuarantineDataURLString, LSQuarantineSenderName "
                "FROM LSQuarantineEvent ORDER BY LSQuarantineTimeStamp DESC LIMIT 200"):
                events.append({'id': r[0], 'time': _convert_cocoa_time(r[1]),
                               'agent': r[2] or '', 'url': r[3] or '',
                               'sender': r[4] or ''})
        except sqlite3.Error: pass
        return {'events': events, 'tables': meta['tables']}
    finally: _close_sqlite(meta)
bp.add_url_rule('/quarantine',
                view_func=_mobile_sqlite_route('quarantine', _parse_quarantine),
                methods=['GET','POST'])


@bp.route('/spotlight', methods=['GET','POST'])
def spotlight_tool():
    result = error = None
    if request.method == 'POST':
        f = request.files.get('file')
        if not f or not f.filename: error = 'store.db (Spotlight) 파일 필요'
        else:
            data = f.read()
            r = {'filename': f.filename, 'size': len(data),
                 'hex_preview': data[:32].hex().upper()}
            if data[:8] == b'8tibdM1S':
                r['format'] = 'Sierra+ Spotlight store.db'
            elif data[:4] == b'\x39\x49\x84\x6B':
                r['format'] = 'Legacy Spotlight'
            else:
                r['format'] = '알 수 없음'
            r['note'] = 'Spotlight 풀 파싱은 libmetastore / mac_apt 필요'
            result = r
    return render_template('tools/spotlight.html', result=result, error=error)


@bp.route('/keychain', methods=['GET','POST'])
def keychain_tool():
    result = error = None
    if request.method == 'POST':
        f = request.files.get('file')
        if not f or not f.filename: error = '.keychain 파일 필요'
        else:
            data = f.read()
            r = {'filename': f.filename, 'size': len(data)}
            if data[:4] == b'kych':
                r['format'] = '구 macOS Binary Keychain (kych)'
                r['version'] = struct.unpack('>I', data[4:8])[0]
            elif data[:16] == b'SQLite format 3\x00':
                r['format'] = '신 keychain-2.db (SQLite, AES-CBC 암호화 블롭)'
                meta = _sqlite_summary(data)
                if 'tables' in meta: r['tables'] = meta['tables']
                _close_sqlite(meta)
            else:
                r['format'] = '알 수 없음'
            r['note'] = '복호화는 사용자 패스워드 또는 시스템 키 필요'
            result = r
    return render_template('tools/keychain.html', result=result, error=error)


def _parse_tcc(data):
    meta = _sqlite_summary(data)
    if 'error' in meta: return meta
    try:
        cur = meta['cur']
        perms = []
        try:
            for r in cur.execute("SELECT service, client, allowed, last_modified FROM access "
                                 "ORDER BY last_modified DESC LIMIT 200"):
                perms.append({'service': r[0], 'client': r[1],
                              'allowed': bool(r[2]),
                              'modified': _convert_unix(r[3])})
        except sqlite3.Error: pass
        return {'permissions': perms, 'tables': meta['tables']}
    finally: _close_sqlite(meta)
bp.add_url_rule('/tcc', view_func=_mobile_sqlite_route('tcc', _parse_tcc),
                methods=['GET','POST'])


@bp.route('/tracev3', methods=['GET','POST'])
def tracev3_tool():
    result = error = None
    if request.method == 'POST':
        f = request.files.get('file')
        if not f or not f.filename: error = '.tracev3 파일 필요'
        else:
            data = f.read()
            chunks = []
            pos = 0
            while pos + 16 <= len(data) and len(chunks) < 1000:
                tag = struct.unpack('<I', data[pos:pos+4])[0]
                sub = struct.unpack('<I', data[pos+4:pos+8])[0]
                size = struct.unpack('<Q', data[pos+8:pos+16])[0]
                TAG_NAMES = {0x1000:'Header',0x6001:'Firehose',0x6002:'Oversize',
                             0x6003:'StateDump',0x6004:'SimpleDump',0x600B:'Catalog',
                             0x600D:'Chunkset (LZ4)'}
                chunks.append({'offset': pos, 'tag': hex(tag), 'name': TAG_NAMES.get(tag, '?'),
                               'sub': sub, 'size': size})
                if size == 0 or size > len(data): break
                pos += 16 + size
            result = {'filename': f.filename, 'size': len(data),
                      'chunks': chunks, 'total': len(chunks)}
    return render_template('tools/tracev3.html', result=result, error=error)


# ====================================================================
# 24-31. 브라우저 캐시 / 스토리지
# ====================================================================
@bp.route('/chromecache', methods=['GET','POST'])
def chromecache_tool():
    result = error = None
    if request.method == 'POST':
        f = request.files.get('file')
        if not f or not f.filename: error = '캐시 파일 필요'
        else:
            data = f.read()
            r = {'filename': f.filename, 'size': len(data),
                 'hex_preview': data[:32].hex().upper()}
            if data[:4] == b'\xC1\x03\xCA\xC3':
                r['format'] = 'Chrome simple cache entry'
            elif data[:4] == b'\x30\x5C\x72\xA7':
                r['format'] = 'Chrome cache block file (data_*)'
            elif data[:4] == b'\xC3\xCA\x03\xC1':
                r['format'] = 'Chrome simple index'
            elif b'http://' in data[:1024] or b'https://' in data[:1024]:
                r['format'] = '캐시 페이로드 (응답 본문)'
                urls = re.findall(rb'https?://[\x20-\x7e]{4,200}', data[:8192])
                r['urls'] = [u.decode('latin1', errors='replace') for u in urls][:20]
            else:
                r['format'] = '알 수 없음'
            result = r
    return render_template('tools/chromecache.html', result=result, error=error)


@bp.route('/firefoxcache', methods=['GET','POST'])
def firefoxcache_tool():
    result = error = None
    if request.method == 'POST':
        f = request.files.get('file')
        if not f or not f.filename: error = 'Firefox cache2 파일 필요'
        else:
            data = f.read()
            r = {'filename': f.filename, 'size': len(data)}
            # cache2 entries: 마지막 64바이트가 메타데이터
            if len(data) >= 64:
                tail = data[-64:]
                version = struct.unpack('>I', tail[:4])[0]
                fetch_count = struct.unpack('>I', tail[4:8])[0]
                last_fetch = struct.unpack('>I', tail[8:12])[0]
                last_modified = struct.unpack('>I', tail[12:16])[0]
                expires = struct.unpack('>I', tail[16:20])[0]
                key_size = struct.unpack('>I', tail[20:24])[0]
                r['version'] = version
                r['fetch_count'] = fetch_count
                r['last_fetch'] = _convert_unix(last_fetch)
                r['last_modified'] = _convert_unix(last_modified)
                r['expires'] = _convert_unix(expires)
                r['key_size'] = key_size
                # URL key는 메타 직전
                if key_size > 0 and key_size < 4096 and len(data) > 64 + key_size:
                    r['url_key'] = data[-64-key_size:-64].decode('utf-8', errors='replace')
            result = r
    return render_template('tools/firefoxcache.html', result=result, error=error)


@bp.route('/localstorage', methods=['GET','POST'])
def localstorage_tool():
    result = error = None
    if request.method == 'POST':
        f = request.files.get('file')
        if not f or not f.filename: error = '.localstorage 또는 leveldb 파일 필요'
        else:
            data = f.read()
            r = {'filename': f.filename, 'size': len(data)}
            # SQLite localstorage (Firefox 구버전)
            if data[:16] == b'SQLite format 3\x00':
                r['format'] = 'SQLite LocalStorage'
                meta = _sqlite_summary(data)
                try:
                    cur = meta.get('cur')
                    items = []
                    for table in ['ItemTable', 'webappsstore2']:
                        try:
                            for row in cur.execute(f'SELECT * FROM "{table}" LIMIT 200'):
                                items.append({'table': table, 'data': list(row)})
                        except Exception: pass
                    r['items'] = items
                finally: _close_sqlite(meta)
            elif data[:8] == b'\x01\x00\x00\x00\x01\x00\x00\x00':
                r['format'] = 'LevelDB (Chrome localStorage)'
                # 문자열 추출
                strings = re.findall(rb'[\x20-\x7E]{4,200}', data)
                r['strings'] = [s.decode('latin1') for s in strings[:50]]
            else:
                r['format'] = '알 수 없음'
                strings = re.findall(rb'[\x20-\x7E]{4,200}', data)
                r['strings'] = [s.decode('latin1') for s in strings[:50]]
            result = r
    return render_template('tools/localstorage.html', result=result, error=error)


@bp.route('/indexeddb', methods=['GET','POST'])
def indexeddb_tool():
    result = error = None
    if request.method == 'POST':
        files = get_files()
        if not files: error = 'IndexedDB leveldb 파일 필요'
        else:
            results = []
            for f in files:
                data = f.read()
                strings = re.findall(rb'[\x20-\x7E]{6,200}', data)
                results.append({
                    'filename': f.filename, 'size': len(data),
                    'strings': [s.decode('latin1') for s in strings[:100]],
                })
            result = {'files': results}
    return render_template('tools/indexeddb.html', result=result, error=error)


# ====================================================================
# 32-41. 클라우드·DevOps
# ====================================================================
@bp.route('/dockerfile', methods=['GET','POST'])
def dockerfile_tool():
    result = error = None
    if request.method == 'POST':
        f = request.files.get('file')
        text = (request.form.get('text') or '').strip()
        if not text and f and f.filename:
            text = f.read().decode('utf-8', errors='replace')
        if not text: error = 'Dockerfile 텍스트/파일 필요'
        else:
            issues = []
            lines = text.splitlines()
            has_user = False
            for i, line in enumerate(lines, 1):
                line_s = line.strip()
                if line_s.startswith('#') or not line_s: continue
                lo = line_s.lower()
                if lo.startswith('user '):
                    has_user = True
                    if 'root' in lo: issues.append({'line': i, 'sev': 'high', 'msg': 'USER root 명시 — 권한 분리 위반'})
                if lo.startswith('from ') and ':latest' in lo:
                    issues.append({'line': i, 'sev': 'medium', 'msg': 'FROM latest 태그 — 빌드 재현성 깨짐'})
                if 'add ' in lo and 'http' in lo:
                    issues.append({'line': i, 'sev': 'medium', 'msg': 'ADD URL — COPY 권장 (체크섬 검증 안됨)'})
                if 'apt-get install' in lo and '--no-install-recommends' not in lo:
                    issues.append({'line': i, 'sev': 'low', 'msg': 'apt-get install — --no-install-recommends 권장'})
                if 'curl ' in lo and 'sudo' in lo:
                    issues.append({'line': i, 'sev': 'high', 'msg': 'curl ... | sudo bash 패턴 — 검증되지 않은 스크립트 실행'})
                if 'wget ' in lo and ' http://' in lo:
                    issues.append({'line': i, 'sev': 'medium', 'msg': 'HTTP wget — HTTPS 사용 권장'})
                if 'chmod 777' in lo: issues.append({'line': i, 'sev': 'high', 'msg': 'chmod 777 — 과도한 권한'})
                if re.search(r'(password|secret|token|api_key)\s*=', lo) and '=""' not in lo:
                    issues.append({'line': i, 'sev': 'high', 'msg': '하드코딩된 비밀 가능성'})
                if lo.startswith('expose ') and (' 22' in lo or ' 2222' in lo):
                    issues.append({'line': i, 'sev': 'medium', 'msg': 'SSH 포트 EXPOSE — 컨테이너에 SSH 불필요'})
            if not has_user:
                issues.append({'line': 0, 'sev': 'high', 'msg': 'USER 지시어 없음 — root로 실행됨'})
            severity_score = sum({'high':30,'medium':10,'low':3}.get(i['sev'], 0) for i in issues)
            grade = 'A' if severity_score == 0 else 'B' if severity_score < 20 else 'C' if severity_score < 50 else 'F'
            result = {'lines': len(lines), 'issues': issues,
                      'score': severity_score, 'grade': grade}
    return render_template('tools/dockerfile.html', result=result, error=error)


@bp.route('/k8sec', methods=['GET','POST'])
def k8sec_tool():
    result = error = None
    if request.method == 'POST':
        text = (request.form.get('text') or '').strip()
        f = request.files.get('file')
        if not text and f and f.filename: text = f.read().decode('utf-8', errors='replace')
        if not text: error = 'YAML 입력 필요'
        else:
            issues = []
            try:
                import yaml as _yaml
                docs = list(_yaml.safe_load_all(text))
            except Exception as e: docs = [{'_parse_error': str(e)}]
            for doc in docs:
                if not isinstance(doc, dict): continue
                kind = doc.get('kind', '')
                spec = doc.get('spec', {})
                template = (spec.get('template') or {}).get('spec', {})
                containers = template.get('containers', spec.get('containers', []))
                sec_ctx = template.get('securityContext', {})
                for c in containers:
                    name = c.get('name', '?')
                    csec = c.get('securityContext', {})
                    if csec.get('privileged'): issues.append({'kind': kind, 'msg': f'컨테이너 {name}: privileged=true — 매우 위험', 'sev': 'critical'})
                    if csec.get('runAsUser') == 0: issues.append({'kind': kind, 'msg': f'컨테이너 {name}: runAsUser=0 (root)', 'sev': 'high'})
                    if not csec.get('readOnlyRootFilesystem'): issues.append({'kind': kind, 'msg': f'컨테이너 {name}: readOnlyRootFilesystem=false', 'sev': 'medium'})
                    if csec.get('allowPrivilegeEscalation', True): issues.append({'kind': kind, 'msg': f'컨테이너 {name}: allowPrivilegeEscalation 미차단', 'sev': 'medium'})
                    caps = csec.get('capabilities', {})
                    if 'ALL' in caps.get('add', []): issues.append({'kind': kind, 'msg': f'컨테이너 {name}: capabilities ADD ALL', 'sev': 'high'})
                    if 'ALL' not in caps.get('drop', []): issues.append({'kind': kind, 'msg': f'컨테이너 {name}: capabilities DROP ALL 권장', 'sev': 'low'})
                    image = c.get('image', '')
                    if ':latest' in image or ':' not in image: issues.append({'kind': kind, 'msg': f'컨테이너 {name}: 이미지 latest 태그', 'sev': 'medium'})
                if template.get('hostNetwork'): issues.append({'kind': kind, 'msg': 'hostNetwork=true — 호스트 네트워크 공유', 'sev': 'high'})
                if template.get('hostPID'): issues.append({'kind': kind, 'msg': 'hostPID=true', 'sev': 'high'})
                if template.get('hostIPC'): issues.append({'kind': kind, 'msg': 'hostIPC=true', 'sev': 'high'})
            score = sum({'critical':50,'high':20,'medium':5,'low':1}.get(i['sev'], 0) for i in issues)
            result = {'docs_count': len(docs), 'issues': issues, 'score': score}
    return render_template('tools/k8sec.html', result=result, error=error)


def _generic_json_log_view(name):
    def view():
        result = error = None
        if request.method == 'POST':
            f = request.files.get('file')
            if not f or not f.filename: return render_template(f'tools/{name}.html', error='파일 필요')
            text = f.read().decode('utf-8', errors='replace')
            try:
                # 한 줄에 한 JSON 또는 단일 배열
                events = []
                if text.strip().startswith('['):
                    events = json.loads(text)
                else:
                    for line in text.splitlines():
                        line = line.strip()
                        if line and line.startswith('{'):
                            try: events.append(json.loads(line))
                            except Exception: pass
                result = {
                    'filename': f.filename, 'count': len(events),
                    'events': events[:200],
                    'first': events[0] if events else None,
                    'last': events[-1] if events else None,
                }
            except Exception as e: error = str(e)
        return render_template(f'tools/{name}.html', result=result, error=error)
    view.__name__ = f'{name}_view'
    return view

bp.add_url_rule('/terraform', view_func=_generic_json_log_view('terraform'), methods=['GET','POST'])
bp.add_url_rule('/cloudtrail', view_func=_generic_json_log_view('cloudtrail'), methods=['GET','POST'])
bp.add_url_rule('/azureactivity', view_func=_generic_json_log_view('azureactivity'), methods=['GET','POST'])
bp.add_url_rule('/gcpaudit', view_func=_generic_json_log_view('gcpaudit'), methods=['GET','POST'])
bp.add_url_rule('/k8saudit', view_func=_generic_json_log_view('k8saudit'), methods=['GET','POST'])
bp.add_url_rule('/o365audit', view_func=_generic_json_log_view('o365audit'), methods=['GET','POST'])


_PKG_VULNS = {
    'lodash':{'4.17.20':'Prototype pollution (CVE-2020-8203)'},
    'log4j-core':{'2.0-2.14.1':'Log4Shell (CVE-2021-44228)'},
    'jquery':{'<3.5.0':'XSS in jQuery.htmlPrefilter (CVE-2020-11023)'},
    'django':{'<3.2.13':'Multiple CVEs'},
    'flask':{'<2.0.3':'Cookie 처리 취약점'},
    'pillow':{'<8.3.2':'Multiple buffer overflow CVEs'},
    'requests':{'<2.20.0':'CVE-2018-18074'},
    'urllib3':{'<1.24.2':'CRLF injection CVE-2019-11324'},
    'pyyaml':{'<5.4':'Arbitrary code execution CVE-2020-14343'},
    'tensorflow':{'<2.5.0':'다수 CVE'},
}

@bp.route('/pkgvuln', methods=['GET','POST'])
def pkgvuln_tool():
    result = error = None
    if request.method == 'POST':
        text = (request.form.get('text') or '').strip()
        f = request.files.get('file')
        if not text and f and f.filename: text = f.read().decode('utf-8', errors='replace')
        if not text: error = '입력 필요'
        else:
            findings = []
            # package.json
            try:
                data = json.loads(text)
                deps = {}
                deps.update(data.get('dependencies', {}))
                deps.update(data.get('devDependencies', {}))
                for name, ver in deps.items():
                    if name in _PKG_VULNS:
                        for vuln_ver, desc in _PKG_VULNS[name].items():
                            findings.append({'package': name, 'version': ver, 'vuln': desc})
            except Exception:
                # requirements.txt
                for line in text.splitlines():
                    line = line.strip()
                    if line and not line.startswith('#'):
                        m = re.match(r'([A-Za-z0-9_\-\.]+)([=<>!~]+)([\d.]+)', line)
                        if m:
                            name = m.group(1).lower()
                            if name in _PKG_VULNS:
                                for vuln_ver, desc in _PKG_VULNS[name].items():
                                    findings.append({'package': name, 'version': line, 'vuln': desc})
            result = {'findings': findings, 'count': len(findings),
                      'db_size': len(_PKG_VULNS)}
    return render_template('tools/pkgvuln.html', result=result, error=error)


# ====================================================================
# 42-49. 악성코드 강화 (VBA Stomping, XLM 매크로, MSI, MSIX, CHM, Go, Rust, .NET)
# ====================================================================
@bp.route('/vbastomp', methods=['GET','POST'])
def vbastomp_tool():
    result = error = None
    if request.method == 'POST':
        f = request.files.get('file')
        if not f or not f.filename: error = 'Office 파일 필요'
        else:
            data = f.read()
            r = {'filename': f.filename, 'size': len(data)}
            try:
                if data[:4] == b'PK\x03\x04':
                    zf = zipfile.ZipFile(io.BytesIO(data))
                    has_pcode = False
                    has_source = False
                    for n in zf.namelist():
                        if 'vbaProject.bin' in n:
                            has_pcode = True
                            vba = zf.read(n)
                            # PerformanceCache 검색 (컴파일된 p-code)
                            if b'PerformanceCache' in vba: r['performance_cache'] = True
                            # CompressedSourceCode 검색
                            if b'CompressedSourceCode' in vba: has_source = True
                    r['has_pcode'] = has_pcode; r['has_source'] = has_source
                    if has_pcode and not has_source:
                        r['stomping'] = '🚨 VBA Stomping 의심 — p-code만 있고 소스 없음'
                    elif has_pcode and has_source:
                        r['stomping'] = '정상 — 소스와 p-code 모두 존재'
            except Exception as e: r['error'] = str(e)
            result = r
    return render_template('tools/vbastomp.html', result=result, error=error)


@bp.route('/xlm', methods=['GET','POST'])
def xlm_tool():
    result = error = None
    if request.method == 'POST':
        f = request.files.get('file')
        if not f or not f.filename: error = 'XLS/XLSM 파일 필요'
        else:
            data = f.read()
            r = {'filename': f.filename, 'size': len(data), 'macro_sheets': []}
            try:
                if data[:4] == b'PK\x03\x04':
                    zf = zipfile.ZipFile(io.BytesIO(data))
                    # workbook.xml에서 sheet 정보
                    if 'xl/workbook.xml' in zf.namelist():
                        wb = zf.read('xl/workbook.xml').decode('utf-8', errors='replace')
                        if 'macrosheet' in wb.lower(): r['has_xlm'] = True
                        sheets = re.findall(r'<sheet[^>]*name="([^"]+)"[^>]*sheetId="(\d+)"', wb)
                        r['sheets'] = [{'name': s[0], 'id': s[1]} for s in sheets]
                    # macrosheet 파일
                    for n in zf.namelist():
                        if 'macrosheets/' in n.lower():
                            content = zf.read(n).decode('utf-8', errors='replace')
                            # Excel 4.0 함수들
                            funcs = re.findall(r'(CALL|EXEC|REGISTER|FOPEN|FWRITE|GET\.WORKSPACE)\(', content)
                            r['macro_sheets'].append({
                                'name': n,
                                'functions': list(set(funcs)),
                                'size': len(content),
                            })
                elif data[:8] == b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1':
                    r['format'] = 'OLE2 - XLM 매크로는 Workbook 스트림 내부'
                    r['note'] = 'XLM 4.0 매크로 추출에 olevba 권장'
            except Exception as e: r['error'] = str(e)
            result = r
    return render_template('tools/xlm.html', result=result, error=error)


@bp.route('/msi', methods=['GET','POST'])
def msi_tool():
    result = error = None
    if request.method == 'POST':
        f = request.files.get('file')
        if not f or not f.filename: error = '.msi 파일 필요'
        else:
            data = f.read()
            r = {'filename': f.filename, 'size': len(data)}
            if data[:8] == b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1':
                r['format'] = 'OLE2 Compound Document (Windows Installer)'
                try:
                    import olefile
                    ole = olefile.OleFileIO(io.BytesIO(data))
                    streams = []
                    suspicious = []
                    for s in ole.listdir():
                        name = '/'.join(s)
                        sz = ole.get_size(s)
                        streams.append({'name': name[:80], 'size': sz})
                        if 'CustomAction' in name or 'Binary' in name:
                            suspicious.append(name)
                    r['streams'] = streams
                    r['custom_actions'] = suspicious
                    ole.close()
                except Exception as e: r['error'] = str(e)
            result = r
    return render_template('tools/msi.html', result=result, error=error)


@bp.route('/msix', methods=['GET','POST'])
def msix_tool():
    result = error = None
    if request.method == 'POST':
        f = request.files.get('file')
        if not f or not f.filename: error = '.msix 또는 .appx 필요'
        else:
            data = f.read()
            r = {'filename': f.filename, 'size': len(data)}
            try:
                if data[:4] == b'PK\x03\x04':
                    zf = zipfile.ZipFile(io.BytesIO(data))
                    r['files'] = [{'name': zi.filename, 'size': zi.file_size}
                                  for zi in zf.infolist()[:100]]
                    if 'AppxManifest.xml' in zf.namelist():
                        manifest = zf.read('AppxManifest.xml').decode('utf-8', errors='replace')
                        r['manifest'] = manifest[:3000]
                        ident = re.search(r'<Identity\s+Name="([^"]+)"[^>]*Publisher="([^"]+)"', manifest)
                        if ident:
                            r['name'] = ident.group(1)
                            r['publisher'] = ident.group(2)
                        caps = re.findall(r'<Capability\s+Name="([^"]+)"', manifest)
                        r['capabilities'] = caps
            except Exception as e: r['error'] = str(e)
            result = r
    return render_template('tools/msix.html', result=result, error=error)


@bp.route('/chm', methods=['GET','POST'])
def chm_tool():
    result = error = None
    if request.method == 'POST':
        f = request.files.get('file')
        if not f or not f.filename: error = '.chm 파일 필요'
        else:
            data = f.read()
            r = {'filename': f.filename, 'size': len(data)}
            if data[:4] == b'ITSF':
                r['format'] = 'Microsoft CHM (ITSF)'
                r['version'] = struct.unpack('<I', data[4:8])[0]
                # URL 추출 단서
                urls = re.findall(rb'https?://[\x20-\x7e]{4,200}', data)
                r['urls'] = [u.decode('latin1', errors='replace') for u in urls][:30]
                # script 단서
                scripts = re.findall(rb'<script[^>]*>([^<]{1,500})</script>', data, re.I)
                r['scripts'] = [s.decode('latin1', errors='replace')[:200] for s in scripts][:10]
            result = r
    return render_template('tools/chm.html', result=result, error=error)


@bp.route('/gobin', methods=['GET','POST'])
def gobin_tool():
    result = error = None
    if request.method == 'POST':
        f = request.files.get('file')
        if not f or not f.filename: error = '바이너리 파일 필요'
        else:
            data = f.read()
            r = {'filename': f.filename, 'size': len(data)}
            # Go 매직: go.buildinfo
            buildinfo = data.find(b'\xff Go buildinf:')
            r['is_go'] = buildinfo >= 0
            if buildinfo >= 0:
                r['buildinfo_offset'] = buildinfo
                # 다음 256바이트에서 모듈 정보 추출
                chunk = data[buildinfo:buildinfo+4096]
                r['buildinfo'] = chunk.decode('latin1', errors='replace')[:2000]
            # Go 함수명 추출 (보통 main.* / runtime.*)
            funcs = re.findall(rb'(?:main\.|runtime\.|net/http\.|crypto/)[\x20-\x7e]{3,100}', data)
            r['functions'] = list(set(f.decode('latin1') for f in funcs))[:50]
            # Rust 단서
            r['is_rust'] = (b'rustc_version' in data or b'__rustc' in data
                            or b'rust_panic' in data or b'core::panic' in data)
            if r['is_rust']:
                rust_strings = re.findall(rb'[\x20-\x7e]{4,150}\.rs', data)
                r['rust_sources'] = list(set(s.decode('latin1') for s in rust_strings))[:30]
            result = r
    return render_template('tools/gobin.html', result=result, error=error)


@bp.route('/dotnet', methods=['GET','POST'])
def dotnet_tool():
    result = error = None
    if request.method == 'POST':
        f = request.files.get('file')
        if not f or not f.filename: error = '.NET PE 파일 필요'
        else:
            data = f.read()
            r = {'filename': f.filename, 'size': len(data)}
            # CLI 헤더 검색 (BSJB 메타데이터 시그니처)
            bsjb = data.find(b'BSJB')
            r['is_dotnet'] = bsjb >= 0
            if bsjb >= 0:
                r['metadata_offset'] = bsjb
                # 버전 문자열
                ver_len = struct.unpack('<I', data[bsjb+12:bsjb+16])[0]
                if 0 < ver_len < 256:
                    r['runtime_version'] = data[bsjb+16:bsjb+16+ver_len].decode('latin1', errors='replace').rstrip('\x00')
                # .NET 타입 이름 추출
                types = re.findall(rb'[A-Z][A-Za-z0-9_]{2,80}\.[A-Z][A-Za-z0-9_]{2,80}', data)
                r['types'] = list(set(t.decode('latin1') for t in types))[:50]
                # 의심 API
                sus = []
                for kw in [b'System.Reflection', b'CreateObject', b'WScript', b'Process.Start',
                           b'WebClient', b'DownloadString', b'Invoke', b'Assembly.Load']:
                    if kw in data: sus.append(kw.decode('latin1'))
                r['suspicious_api'] = sus
            result = r
    return render_template('tools/dotnet.html', result=result, error=error)


@bp.route('/applocker', methods=['GET','POST'])
def applocker_tool():
    result = error = None
    if request.method == 'POST':
        f = request.files.get('file')
        text = (request.form.get('text') or '').strip()
        if not text and f and f.filename: text = f.read().decode('utf-8', errors='replace')
        if not text: error = 'AppLocker XML 입력 필요'
        else:
            try:
                import xml.etree.ElementTree as ET
                root = ET.fromstring(text)
                rules = []
                for rc in root.iter():
                    if rc.tag.endswith('FileHashRule') or rc.tag.endswith('FilePathRule') or rc.tag.endswith('FilePublisherRule'):
                        rules.append({
                            'type': rc.tag.split('}')[-1],
                            'action': rc.get('Action', ''),
                            'name': rc.get('Name', ''),
                            'id': rc.get('Id', ''),
                            'user_sid': rc.get('UserOrGroupSid', ''),
                        })
                result = {'rules': rules, 'count': len(rules)}
            except Exception as e: error = str(e)
    return render_template('tools/applocker.html', result=result, error=error)


# ====================================================================
# 50-56. 압축·이미지 추가
# ====================================================================
@bp.route('/iso', methods=['GET','POST'])
def iso_tool():
    result = error = None
    if request.method == 'POST':
        f = request.files.get('file')
        if not f or not f.filename: error = '.iso 파일 필요'
        else:
            # 32KB부터 ISO9660 PVD (Primary Volume Descriptor)
            f.seek(32768)
            pvd = f.read(2048)
            r = {'filename': f.filename}
            if len(pvd) >= 2048 and pvd[1:6] == b'CD001':
                vol_id = pvd[40:72].decode('latin1', errors='replace').strip()
                vol_size_blocks = struct.unpack('<I', pvd[80:84])[0]
                logical_block_size = struct.unpack('<H', pvd[128:130])[0]
                r['format'] = 'ISO9660'
                r['volume_id'] = vol_id
                r['blocks'] = vol_size_blocks
                r['block_size'] = logical_block_size
                r['total_size'] = vol_size_blocks * logical_block_size
                # Creation date
                date = pvd[813:830].decode('latin1', errors='replace')
                r['creation_date'] = date
                # 응용 ID
                r['app_id'] = pvd[574:702].decode('latin1', errors='replace').strip()
                r['publisher'] = pvd[318:446].decode('latin1', errors='replace').strip()
            else:
                r['format'] = 'ISO9660 아님 (32768+1 에 CD001 시그니처 없음)'
            result = r
    return render_template('tools/iso.html', result=result, error=error)


@bp.route('/dmg', methods=['GET','POST'])
def dmg_tool():
    result = error = None
    if request.method == 'POST':
        f = request.files.get('file')
        if not f or not f.filename: error = '.dmg 파일 필요'
        else:
            f.seek(0, 2); size = f.tell()
            f.seek(max(0, size - 512))
            footer = f.read(512)
            r = {'filename': f.filename, 'size': size}
            if footer[:4] == b'koly':
                r['format'] = 'Apple Disk Image (DMG, koly footer)'
                r['version'] = struct.unpack('>I', footer[4:8])[0]
                r['header_size'] = struct.unpack('>I', footer[8:12])[0]
                r['flags'] = hex(struct.unpack('>I', footer[12:16])[0])
                running_data_fork_offset = struct.unpack('>Q', footer[16:24])[0]
                xml_offset = struct.unpack('>Q', footer[160:168])[0]
                xml_length = struct.unpack('>Q', footer[168:176])[0]
                r['xml_offset'] = xml_offset
                r['xml_length'] = xml_length
            else:
                r['format'] = 'koly 푸터 없음 — 다른 포맷일 수 있음'
            result = r
    return render_template('tools/dmg.html', result=result, error=error)


@bp.route('/rar', methods=['GET','POST'])
def rar_tool():
    result = error = None
    if request.method == 'POST':
        f = request.files.get('file')
        if not f or not f.filename: error = '.rar 파일 필요'
        else:
            data = f.read()
            r = {'filename': f.filename, 'size': len(data)}
            if data[:7] == b'Rar!\x1A\x07\x00':
                r['format'] = 'RAR 4.x'
            elif data[:8] == b'Rar!\x1A\x07\x01\x00':
                r['format'] = 'RAR 5.x'
            else:
                r['format'] = 'RAR 아님'
            # 암호화 헤더 마커
            if b'\x73\x00\x80' in data[:200]: r['encrypted_files'] = True
            # 파일명 추출 (간단)
            strings = re.findall(rb'[\x20-\x7E]{4,200}', data)
            r['strings_sample'] = list(set(s.decode('latin1') for s in strings[:100]))[:30]
            result = r
    return render_template('tools/rar.html', result=result, error=error)


@bp.route('/sevenz', methods=['GET','POST'])
def sevenz_tool():
    result = error = None
    if request.method == 'POST':
        f = request.files.get('file')
        if not f or not f.filename: error = '.7z 파일 필요'
        else:
            data = f.read()
            r = {'filename': f.filename, 'size': len(data)}
            if data[:6] == b'7z\xBC\xAF\x27\x1C':
                r['format'] = '7-Zip'
                r['version_major'] = data[6]
                r['version_minor'] = data[7]
                next_header_offset = struct.unpack('<Q', data[12:20])[0]
                next_header_size = struct.unpack('<Q', data[20:28])[0]
                r['next_header_offset'] = next_header_offset
                r['next_header_size'] = next_header_size
            result = r
    return render_template('tools/sevenz.html', result=result, error=error)


@bp.route('/tar', methods=['GET','POST'])
def tar_tool():
    result = error = None
    if request.method == 'POST':
        f = request.files.get('file')
        if not f or not f.filename: error = '.tar 파일 필요'
        else:
            try:
                import tarfile
                tf = tarfile.open(fileobj=io.BytesIO(f.read()))
                members = []
                for ti in tf.getmembers()[:500]:
                    members.append({
                        'name': ti.name, 'size': ti.size,
                        'mode': oct(ti.mode), 'uid': ti.uid, 'gid': ti.gid,
                        'uname': ti.uname, 'gname': ti.gname,
                        'mtime': _convert_unix(ti.mtime),
                        'type': {'0':'파일','5':'디렉터리','2':'심볼릭링크',
                                 '1':'하드링크','3':'문자장치','4':'블록장치'}.get(
                                     ti.type.decode() if isinstance(ti.type, bytes) else ti.type, '?'),
                    })
                result = {'members': members, 'count': len(members)}
                tf.close()
            except Exception as e: error = str(e)
    return render_template('tools/tar.html', result=result, error=error)


@bp.route('/cab', methods=['GET','POST'])
def cab_tool():
    result = error = None
    if request.method == 'POST':
        f = request.files.get('file')
        if not f or not f.filename: error = '.cab 파일 필요'
        else:
            data = f.read()
            r = {'filename': f.filename, 'size': len(data)}
            if data[:4] == b'MSCF':
                r['format'] = 'Microsoft Cabinet'
                cb_cabinet = struct.unpack('<I', data[8:12])[0]
                co_files = struct.unpack('<H', data[28:30])[0]
                cb_cffolder = struct.unpack('<H', data[26:28])[0]
                r['total_size'] = cb_cabinet
                r['file_count'] = co_files
                r['folder_count'] = cb_cffolder
                version_minor = data[24]
                version_major = data[25]
                r['version'] = f'{version_major}.{version_minor}'
            result = r
    return render_template('tools/cab.html', result=result, error=error)


@bp.route('/gzmeta', methods=['GET','POST'])
def gzmeta_tool():
    result = error = None
    if request.method == 'POST':
        f = request.files.get('file')
        if not f or not f.filename: error = '.gz 파일 필요'
        else:
            data = f.read()
            r = {'filename': f.filename, 'size': len(data)}
            if data[:2] == b'\x1f\x8b':
                r['format'] = 'GZIP'
                r['compression_method'] = data[2]
                flags = data[3]
                r['mtime'] = _convert_unix(struct.unpack('<I', data[4:8])[0])
                r['xfl'] = data[8]
                r['os'] = {0:'FAT', 3:'Unix', 7:'Macintosh', 10:'NTFS', 11:'OpenVMS'}.get(data[9], data[9])
                pos = 10
                if flags & 0x08:  # FNAME
                    end = data.find(b'\x00', pos)
                    r['original_filename'] = data[pos:end].decode('latin1', errors='replace')
                    pos = end + 1
                if flags & 0x10:  # FCOMMENT
                    end = data.find(b'\x00', pos)
                    r['comment'] = data[pos:end].decode('latin1', errors='replace')
                # 마지막 4바이트: 원본 크기 (mod 2^32)
                if len(data) >= 4:
                    r['original_size_mod32'] = struct.unpack('<I', data[-4:])[0]
                    r['crc32_stored'] = hex(struct.unpack('<I', data[-8:-4])[0])
            result = r
    return render_template('tools/gzmeta.html', result=result, error=error)


# ====================================================================
# 57-61. 암호 강화 (JWE/JWS, PGP, PKCS7, SSH, GPG)
# ====================================================================
@bp.route('/jwe', methods=['GET','POST'])
def jwe_tool():
    result = error = None
    token = request.form.get('token', '') if request.method == 'POST' else ''
    if request.method == 'POST' and token:
        parts = token.split('.')
        try:
            def b64d(s): return base64.urlsafe_b64decode(s + '=' * (-len(s) % 4))
            if len(parts) == 5:
                # JWE: protected.encrypted_key.iv.ciphertext.tag
                header = json.loads(b64d(parts[0]))
                result = {
                    'format': 'JWE (5-part Compact)',
                    'header': header,
                    'encrypted_key_b64': parts[1],
                    'iv_hex': b64d(parts[2]).hex(),
                    'ciphertext_len': len(b64d(parts[3])),
                    'auth_tag_hex': b64d(parts[4]).hex(),
                    'alg': header.get('alg',''), 'enc': header.get('enc',''),
                }
            elif len(parts) == 3:
                # JWS (JWT와 동일 구조)
                header = json.loads(b64d(parts[0]))
                payload = json.loads(b64d(parts[1]))
                result = {'format': 'JWS (3-part — JWT 동일)',
                          'header': header, 'payload': payload,
                          'redirect_jwt': '/tools/jwt'}
            else: error = 'JWE는 5개, JWS는 3개 점(.) 구분 필요'
        except Exception as e: error = str(e)
    return render_template('tools/jwe.html', result=result, error=error, token=token)


@bp.route('/pgp', methods=['GET','POST'])
def pgp_tool():
    result = error = None
    if request.method == 'POST':
        text = (request.form.get('text') or '').strip()
        f = request.files.get('file')
        if not text and f and f.filename: text = f.read().decode('utf-8', errors='replace')
        if not text: error = 'PGP 메시지/키 입력 필요'
        else:
            r = {}
            if '-----BEGIN PGP MESSAGE-----' in text: r['type'] = 'PGP Message (암호화)'
            elif '-----BEGIN PGP SIGNATURE-----' in text: r['type'] = 'PGP Signature'
            elif '-----BEGIN PGP PUBLIC KEY BLOCK-----' in text: r['type'] = 'PGP Public Key'
            elif '-----BEGIN PGP PRIVATE KEY BLOCK-----' in text: r['type'] = 'PGP Private Key'
            else: r['type'] = '알 수 없음'
            # base64 디코드 시도
            m = re.search(r'-----BEGIN PGP[^-]+-----\s*(?:Version[^\n]*\n)?(.+?)-----END',
                          text, re.S)
            if m:
                body = re.sub(r'[\s=]', '', m.group(1))
                try:
                    raw = base64.b64decode(body + '===')
                    r['raw_size'] = len(raw)
                    r['first_packet'] = hex(raw[0]) if raw else ''
                    # 패킷 태그 (RFC 4880)
                    if raw[0] & 0x80:
                        if raw[0] & 0x40:
                            tag = raw[0] & 0x3F  # New format
                        else:
                            tag = (raw[0] >> 2) & 0x0F  # Old format
                        TAGS = {1:'PublicKeyEncrypted',2:'Signature',5:'SecretKey',
                                6:'PublicKey',7:'SecretSubKey',8:'Compressed',
                                9:'Encrypted',11:'LiteralData',14:'PublicSubKey'}
                        r['packet_tag'] = f'{tag} ({TAGS.get(tag, "?")})'
                except Exception: pass
            result = r
    return render_template('tools/pgp.html', result=result, error=error)


@bp.route('/pkcs7', methods=['GET','POST'])
def pkcs7_tool():
    result = error = None
    if request.method == 'POST':
        f = request.files.get('file')
        if not f or not f.filename: error = 'PKCS#7 파일 필요'
        else:
            data = f.read()
            r = {'filename': f.filename, 'size': len(data)}
            try:
                from cryptography.hazmat.primitives.serialization import pkcs7
                if b'-----BEGIN PKCS7-----' in data or b'-----BEGIN CMS-----' in data:
                    certs = pkcs7.load_pem_pkcs7_certificates(data)
                else:
                    certs = pkcs7.load_der_pkcs7_certificates(data)
                cert_info = []
                for cert in certs:
                    cert_info.append({
                        'subject': cert.subject.rfc4514_string(),
                        'issuer': cert.issuer.rfc4514_string(),
                        'serial': hex(cert.serial_number),
                    })
                r['certificates'] = cert_info
                r['cert_count'] = len(certs)
            except Exception as e: r['error'] = str(e)
            result = r
    return render_template('tools/pkcs7.html', result=result, error=error)


@bp.route('/sshhosts', methods=['GET','POST'])
def sshhosts_tool():
    result = error = None
    if request.method == 'POST':
        text = (request.form.get('text') or '').strip()
        f = request.files.get('file')
        if not text and f and f.filename: text = f.read().decode('utf-8', errors='replace')
        if not text: error = 'known_hosts 텍스트 필요'
        else:
            hosts = []
            for line in text.splitlines():
                line = line.strip()
                if not line or line.startswith('#'): continue
                parts = line.split(' ', 2)
                if len(parts) < 3: continue
                host_part = parts[0]
                hashed = host_part.startswith('|1|')
                key_type = parts[1]
                key_data = parts[2][:200]
                hosts.append({'host': host_part if not hashed else '(SHA-1 해시됨)',
                              'hashed': hashed, 'type': key_type, 'key_preview': key_data})
            result = {'hosts': hosts, 'count': len(hosts)}
    return render_template('tools/sshhosts.html', result=result, error=error)


@bp.route('/gpgkey', methods=['GET','POST'])
def gpgkey_tool():
    result = error = None
    if request.method == 'POST':
        f = request.files.get('file')
        if not f or not f.filename: error = '.gpg 또는 PGP 키 파일 필요'
        else:
            data = f.read()
            r = {'filename': f.filename, 'size': len(data)}
            # PGP 패킷 파싱 (간단)
            pos = 0; packets = []
            while pos < len(data) and len(packets) < 50:
                if pos >= len(data): break
                tag_byte = data[pos]
                if not (tag_byte & 0x80): break
                new_format = bool(tag_byte & 0x40)
                if new_format:
                    tag = tag_byte & 0x3F
                    pos += 1
                    if pos >= len(data): break
                    first = data[pos]; pos += 1
                    if first < 192: length = first
                    elif first < 224:
                        if pos >= len(data): break
                        length = ((first - 192) << 8) + data[pos] + 192; pos += 1
                    elif first == 255:
                        if pos + 4 > len(data): break
                        length = struct.unpack('>I', data[pos:pos+4])[0]; pos += 4
                    else: break
                else:
                    tag = (tag_byte >> 2) & 0x0F
                    length_type = tag_byte & 3
                    pos += 1
                    if length_type == 0: length = data[pos]; pos += 1
                    elif length_type == 1:
                        length = struct.unpack('>H', data[pos:pos+2])[0]; pos += 2
                    elif length_type == 2:
                        length = struct.unpack('>I', data[pos:pos+4])[0]; pos += 4
                    else: break
                TAGS = {2:'Signature',6:'PublicKey',7:'SecretSubKey',13:'UserID',
                        14:'PublicSubKey',17:'UserAttribute'}
                packets.append({'tag': tag, 'name': TAGS.get(tag, '?'), 'length': length,
                                'offset': pos - 1})
                # UserID 추출
                if tag == 13 and pos + length <= len(data):
                    uid = data[pos:pos+length].decode('utf-8', errors='replace')
                    packets[-1]['userid'] = uid
                pos += length
            r['packets'] = packets
            result = r
    return render_template('tools/gpgkey.html', result=result, error=error)


# ====================================================================
# 62-71. 유틸리티 추가
# ====================================================================
@bp.route('/cidrcompare', methods=['GET','POST'])
def cidrcompare_tool():
    result = error = None
    if request.method == 'POST':
        cidrs_text = (request.form.get('cidrs') or '').strip()
        ip_text = (request.form.get('ips') or '').strip()
        if not cidrs_text or not ip_text: error = 'CIDR 목록과 IP 목록 모두 입력'
        else:
            try:
                import ipaddress
                cidrs = []
                for line in cidrs_text.splitlines():
                    line = line.strip()
                    if line:
                        try: cidrs.append(ipaddress.ip_network(line, strict=False))
                        except Exception: pass
                ips = [line.strip() for line in ip_text.splitlines() if line.strip()]
                results = []
                for ip in ips:
                    try:
                        ip_obj = ipaddress.ip_address(ip)
                        matches = [str(c) for c in cidrs if ip_obj in c]
                        results.append({'ip': ip, 'matches': matches,
                                        'in_any': bool(matches)})
                    except Exception: results.append({'ip': ip, 'error': '잘못된 IP'})
                result = {'cidrs': [str(c) for c in cidrs], 'ips': results}
            except Exception as e: error = str(e)
    return render_template('tools/cidrcompare.html', result=result, error=error)


@bp.route('/urlsafe', methods=['GET','POST'])
def urlsafe_tool():
    result = error = None
    if request.method == 'POST':
        url = (request.form.get('url') or '').strip()
        if not url: error = 'URL 입력'
        else:
            decoded = urllib.parse.unquote_plus(url)
            parsed = urllib.parse.urlparse(decoded)
            warnings = []
            # Punycode 검사
            try:
                host = parsed.hostname or ''
                if host.startswith('xn--'): warnings.append('Punycode 도메인 (IDN 호모그래프 가능성)')
                if any(ord(c) > 127 for c in host): warnings.append('비ASCII 문자 도메인')
            except Exception: pass
            # 의심 패턴
            if '@' in (parsed.netloc or ''): warnings.append('사용자명@호스트 형식 (피싱 가능성)')
            if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', parsed.netloc or ''):
                warnings.append('IP 주소 직접 사용 (피싱 의심)')
            if parsed.port and parsed.port not in (80, 443, 8080, 8443):
                warnings.append(f'비표준 포트 {parsed.port}')
            shorteners = ['bit.ly','tinyurl.com','goo.gl','t.co','ow.ly','is.gd',
                          'buff.ly','tiny.cc','shortener','short','rebrand.ly']
            if any(s in (parsed.netloc or '').lower() for s in shorteners):
                warnings.append('URL 단축 서비스 사용')
            if (parsed.scheme or '').lower() == 'http':
                warnings.append('HTTP (비암호화)')
            # 인코딩된 문자 분석
            encoded_count = url.count('%')
            if encoded_count > 5: warnings.append(f'URL 인코딩 과다 ({encoded_count}개 %)')
            result = {
                'original': url, 'decoded': decoded,
                'scheme': parsed.scheme, 'host': parsed.hostname or '',
                'port': parsed.port or '', 'path': parsed.path,
                'query': dict(urllib.parse.parse_qsl(parsed.query)),
                'fragment': parsed.fragment,
                'warnings': warnings,
                'safety_score': max(0, 100 - len(warnings) * 20),
            }
    return render_template('tools/urlsafe.html', result=result, error=error)


@bp.route('/emaildeep', methods=['GET','POST'])
def emaildeep_tool():
    result = error = None
    if request.method == 'POST':
        text = (request.form.get('headers') or '').strip()
        f = request.files.get('file')
        if not text and f and f.filename: text = f.read().decode('utf-8', errors='replace')
        if not text: error = '이메일 헤더 또는 .eml 필요'
        else:
            headers = {}
            for line in text.split('\n'):
                if ': ' in line:
                    k, v = line.split(': ', 1)
                    headers[k.strip()] = v.strip()
            r = {'headers': headers}
            # Received 헤더 모두 추출 → 경유 경로
            received = [v for k, v in headers.items() if k.lower().startswith('received')]
            received_lines = re.findall(r'Received:\s*(.+?)(?=\n[A-Z]|\Z)', text, re.S)
            r['received_hops'] = [h.replace('\n', ' ').strip()[:300] for h in received_lines]
            # 발신 IP 추출
            ips = re.findall(r'\[(\d+\.\d+\.\d+\.\d+)\]', text)
            r['hop_ips'] = list(set(ips))
            # X- 헤더 (벤더 특화)
            r['x_headers'] = {k: v for k, v in headers.items() if k.startswith('X-')}
            # 검증 결과
            auth_results = headers.get('Authentication-Results', '')
            r['spf'] = 'spf=pass' in auth_results.lower()
            r['dkim'] = 'dkim=pass' in auth_results.lower()
            r['dmarc'] = 'dmarc=pass' in auth_results.lower()
            r['authres_raw'] = auth_results
            # 발신 도메인 vs 본문 도메인 불일치 검사
            from_addr = headers.get('From', '')
            return_path = headers.get('Return-Path', '')
            from_domain = re.search(r'@([^\s>]+)', from_addr)
            rp_domain = re.search(r'@([^\s>]+)', return_path)
            if from_domain and rp_domain and from_domain.group(1) != rp_domain.group(1):
                r['domain_mismatch'] = f'From({from_domain.group(1)}) ≠ Return-Path({rp_domain.group(1)})'
            result = r
    return render_template('tools/emaildeep.html', result=result, error=error)


@bp.route('/zipsearch', methods=['GET','POST'])
def zipsearch_tool():
    result = error = None
    if request.method == 'POST':
        f = request.files.get('file')
        keyword = (request.form.get('keyword') or '').strip()
        if not f or not f.filename or not keyword: error = 'ZIP 파일과 검색어 모두 필요'
        else:
            data = f.read()
            try:
                zf = zipfile.ZipFile(io.BytesIO(data))
                matches = []
                kw_bytes = keyword.encode('utf-8')
                kw_lower = keyword.lower().encode('utf-8')
                for zi in zf.infolist():
                    if zi.is_dir() or zi.file_size > 50*1024*1024: continue
                    try:
                        content = zf.read(zi.filename)
                        if kw_bytes in content or kw_lower in content.lower():
                            # 컨텍스트 추출
                            idx = content.lower().find(kw_lower)
                            ctx = content[max(0,idx-40):idx+len(kw_bytes)+40]
                            matches.append({
                                'file': zi.filename,
                                'size': zi.file_size,
                                'context': ctx.decode('latin1', errors='replace')[:200],
                                'count': content.lower().count(kw_lower),
                            })
                    except Exception: pass
                    if len(matches) >= 200: break
                result = {'matches': matches, 'keyword': keyword,
                          'total_files': len(zf.infolist())}
            except Exception as e: error = str(e)
    return render_template('tools/zipsearch.html', result=result, error=error)


@bp.route('/autoanalyze', methods=['GET','POST'])
def autoanalyze_tool():
    """자동 분석 — 시그니처 인식 후 자동으로 적절한 분석"""
    result = error = None
    if request.method == 'POST':
        files = get_files()
        if not files: error = '파일 필요'
        else:
            results = []
            for f in files:
                data = f.read()
                r = {'filename': f.filename, 'size': len(data),
                     'sha256': hashlib.sha256(data).hexdigest(),
                     'recommendations': []}
                # 시그니처 기반 추천
                for sig, tool, label in _AUTO_ROUTER:
                    if data.startswith(sig):
                        r['recommendations'].append({'tool': tool, 'label': label,
                                                     'url': f'/tools/{tool}'})
                # 추가 분석: 엔트로피
                from monitor.views.tools_extra import _shannon_entropy
                ent = _shannon_entropy(data)
                r['entropy'] = round(ent, 3)
                if ent > 7.5:
                    r['recommendations'].append({'tool': 'entropy', 'label': '암호화/패킹 의심 → 엔트로피 분석',
                                                 'url': '/tools/entropy'})
                # IOC 자동 추출 시도
                try:
                    text = data.decode('utf-8', errors='replace')[:1000000]
                    iocs = _extract_iocs(text)
                    r['ioc_count'] = sum(len(v) for v in iocs.values())
                    if r['ioc_count'] > 5:
                        r['recommendations'].append({'tool': 'ioc', 'label': 'IOC 다수 발견 → IOC 추출',
                                                     'url': '/tools/ioc'})
                except Exception: pass
                results.append(r)
            result = {'files': results}
    return render_template('tools/autoanalyze.html', result=result, error=error)


# GeoIP - 간단한 룩업 (오프라인 DB 없이 기본 클래스 분류)
@bp.route('/geoip', methods=['GET','POST'])
def geoip_tool():
    result = error = None
    if request.method == 'POST':
        ips_text = (request.form.get('ips') or '').strip()
        if not ips_text: error = 'IP 입력'
        else:
            results = []
            for line in ips_text.splitlines():
                ip = line.strip()
                if not ip: continue
                try:
                    socket.inet_aton(ip)
                    octets = list(map(int, ip.split('.')))
                    info = {'ip': ip}
                    # 분류
                    if octets[0] == 10 or (octets[0]==172 and 16<=octets[1]<=31) or (octets[0]==192 and octets[1]==168):
                        info['class'] = '사설 (RFC1918)'
                    elif octets[0] == 127:
                        info['class'] = '루프백'
                    elif octets[0] == 169 and octets[1] == 254:
                        info['class'] = 'Link-local (APIPA)'
                    elif octets[0] >= 224 and octets[0] <= 239:
                        info['class'] = '멀티캐스트'
                    elif octets[0] >= 240:
                        info['class'] = '예약'
                    else:
                        info['class'] = '공용'
                        # RIR 추정
                        if octets[0] in range(1, 60): info['rir_estimate'] = 'APNIC (아시아·태평양)'
                        elif octets[0] in range(60, 130): info['rir_estimate'] = 'ARIN (북미)'
                        elif octets[0] in range(130, 200): info['rir_estimate'] = 'RIPE NCC (유럽)'
                        elif octets[0] in range(200, 220): info['rir_estimate'] = 'LACNIC (남미)'
                        elif octets[0] in range(196, 197): info['rir_estimate'] = 'AfriNIC (아프리카)'
                    # 역방향 DNS
                    try: info['hostname'] = socket.gethostbyaddr(ip)[0]
                    except Exception: pass
                    results.append(info)
                except Exception:
                    results.append({'ip': ip, 'error': '잘못된 IP'})
            result = {'ips': results, 'count': len(results)}
    return render_template('tools/geoip.html', result=result, error=error)


@bp.route('/uaparse', methods=['GET','POST'])
def uaparse_tool():
    result = error = None
    if request.method == 'POST':
        ua = (request.form.get('ua') or '').strip()
        if not ua: error = 'User-Agent 입력'
        else:
            r = {'ua': ua}
            # 브라우저
            if 'Edg/' in ua: r['browser'] = 'Microsoft Edge'
            elif 'OPR/' in ua or 'Opera' in ua: r['browser'] = 'Opera'
            elif 'Brave' in ua: r['browser'] = 'Brave'
            elif 'Chrome/' in ua and 'Edge' not in ua: r['browser'] = 'Chrome'
            elif 'Firefox/' in ua: r['browser'] = 'Firefox'
            elif 'Safari/' in ua and 'Chrome' not in ua: r['browser'] = 'Safari'
            elif 'MSIE' in ua or 'Trident' in ua: r['browser'] = 'Internet Explorer'
            else: r['browser'] = '알 수 없음'
            # OS
            if 'Windows NT 10' in ua: r['os'] = 'Windows 10/11'
            elif 'Windows NT 6.3' in ua: r['os'] = 'Windows 8.1'
            elif 'Windows NT 6.2' in ua: r['os'] = 'Windows 8'
            elif 'Windows NT 6.1' in ua: r['os'] = 'Windows 7'
            elif 'iPhone' in ua: r['os'] = 'iOS (iPhone)'
            elif 'iPad' in ua: r['os'] = 'iPadOS'
            elif 'Mac OS X' in ua:
                m = re.search(r'Mac OS X (\d+[._]\d+(?:[._]\d+)?)', ua)
                r['os'] = f'macOS {m.group(1).replace("_",".")}' if m else 'macOS'
            elif 'Android' in ua:
                m = re.search(r'Android (\d+(?:\.\d+)?)', ua)
                r['os'] = f'Android {m.group(1)}' if m else 'Android'
            elif 'Linux' in ua: r['os'] = 'Linux'
            elif 'CrOS' in ua: r['os'] = 'ChromeOS'
            else: r['os'] = '알 수 없음'
            # 디바이스 타입
            if 'Mobile' in ua: r['device'] = 'Mobile'
            elif 'Tablet' in ua or 'iPad' in ua: r['device'] = 'Tablet'
            elif 'Bot' in ua or 'bot' in ua or 'crawler' in ua.lower(): r['device'] = 'Bot/Crawler'
            else: r['device'] = 'Desktop'
            # 버전 추출
            versions = {}
            for browser in ['Chrome', 'Firefox', 'Safari', 'Edg', 'Opera', 'OPR']:
                m = re.search(rf'{browser}[/\s](\d+(?:\.\d+)*)', ua)
                if m: versions[browser] = m.group(1)
            r['versions'] = versions
            # 의심 패턴
            warnings = []
            if 'curl' in ua.lower() or 'wget' in ua.lower(): warnings.append('CLI 도구 (curl/wget)')
            if 'Python' in ua or 'requests' in ua.lower(): warnings.append('Python 라이브러리')
            if 'java' in ua.lower() and 'Java/' in ua: warnings.append('Java HTTP 클라이언트')
            if any(b in ua.lower() for b in ['bot','spider','crawler','scraper']): warnings.append('자동화 봇 가능성')
            if 'Headless' in ua: warnings.append('Headless 브라우저')
            r['warnings'] = warnings
            result = r
    return render_template('tools/uaparse.html', result=result, error=error)


@bp.route('/encoding', methods=['GET','POST'])
def encoding_tool():
    result = error = None
    if request.method == 'POST':
        f = request.files.get('file')
        text = (request.form.get('text') or '')
        target_enc = request.form.get('target', 'utf-8')
        if f and f.filename: data = f.read()
        elif text: data = text.encode('latin1')
        else: error = '파일 또는 텍스트 필요'; data = None
        if data is not None:
            # BOM 감지
            bom_map = {b'\xEF\xBB\xBF':'UTF-8',b'\xFE\xFF':'UTF-16 BE',
                       b'\xFF\xFE':'UTF-16 LE',b'\x00\x00\xFE\xFF':'UTF-32 BE',
                       b'\xFF\xFE\x00\x00':'UTF-32 LE'}
            bom_detected = None
            for bom, enc_name in bom_map.items():
                if data.startswith(bom):
                    bom_detected = enc_name
                    data_no_bom = data[len(bom):]
                    break
            else: data_no_bom = data
            # chardet 가능하면 사용
            try:
                import chardet
                det = chardet.detect(data[:10000])
                detected = det['encoding']
                confidence = det['confidence']
            except ImportError:
                detected, confidence = None, 0
                # 기본 휴리스틱
                try: data.decode('utf-8'); detected = 'utf-8'; confidence = 1.0
                except UnicodeDecodeError: pass
                if not detected:
                    try: data.decode('euc-kr'); detected = 'euc-kr'; confidence = 0.8
                    except UnicodeDecodeError: pass
                if not detected:
                    try: data.decode('cp949'); detected = 'cp949'; confidence = 0.8
                    except UnicodeDecodeError: pass
            # 변환
            converted = None; preview = None
            if detected and target_enc:
                try:
                    text_decoded = data.decode(detected, errors='replace')
                    converted = text_decoded.encode(target_enc, errors='replace')
                    preview = text_decoded[:1000]
                except Exception as e: error = str(e)
            result = {
                'bom_detected': bom_detected,
                'detected_encoding': detected,
                'confidence': round(confidence * 100, 1) if confidence else 0,
                'preview': preview,
                'converted_size': len(converted) if converted else 0,
                'target': target_enc,
            }
    return render_template('tools/encoding.html', result=result, error=error)


@bp.route('/markdown', methods=['GET','POST'])
def markdown_tool():
    result = error = None
    if request.method == 'POST':
        text = (request.form.get('text') or '')
        if not text: error = 'Markdown 텍스트 입력'
        else:
            html = text
            # 매우 간단한 마크다운 → HTML 변환
            html = re.sub(r'^### (.+)$', r'<h3>\1</h3>', html, flags=re.M)
            html = re.sub(r'^## (.+)$', r'<h2>\1</h2>', html, flags=re.M)
            html = re.sub(r'^# (.+)$', r'<h1>\1</h1>', html, flags=re.M)
            html = re.sub(r'\*\*([^\*]+)\*\*', r'<strong>\1</strong>', html)
            html = re.sub(r'\*([^\*]+)\*', r'<em>\1</em>', html)
            html = re.sub(r'`([^`]+)`', r'<code>\1</code>', html)
            html = re.sub(r'\[([^\]]+)\]\(([^)]+)\)', r'<a href="\2">\1</a>', html)
            html = re.sub(r'^- (.+)$', r'<li>\1</li>', html, flags=re.M)
            html = re.sub(r'(<li>.+</li>\n?)+', lambda m: f'<ul>{m.group(0)}</ul>', html)
            # 코드 블록
            html = re.sub(r'```(\w*)\n(.+?)```', r'<pre><code>\2</code></pre>', html, flags=re.S)
            # 줄바꿈
            html = html.replace('\n\n', '</p><p>')
            html = f'<p>{html}</p>'
            result = {'original': text, 'html': html,
                      'words': len(text.split()),
                      'lines': len(text.splitlines())}
    return render_template('tools/markdown.html', result=result, error=error)


@bp.route('/triagediff', methods=['GET','POST'])
def triagediff_tool():
    """두 트리아지 ZIP 비교"""
    result = error = None
    if request.method == 'POST':
        fa = request.files.get('file_a')
        fb = request.files.get('file_b')
        if not fa or not fb or not fa.filename or not fb.filename:
            error = '두 ZIP 모두 필요'
        else:
            try:
                za = zipfile.ZipFile(io.BytesIO(fa.read()))
                zb = zipfile.ZipFile(io.BytesIO(fb.read()))
                names_a = set(za.namelist())
                names_b = set(zb.namelist())
                only_a = sorted(names_a - names_b)
                only_b = sorted(names_b - names_a)
                common = sorted(names_a & names_b)
                # 공통 파일의 차이
                differs = []
                for n in common[:500]:
                    da = za.read(n); db = zb.read(n)
                    if hashlib.sha256(da).digest() != hashlib.sha256(db).digest():
                        differs.append({'name': n, 'size_a': len(da), 'size_b': len(db)})
                result = {
                    'only_a': only_a[:200],'only_b': only_b[:200],
                    'common_count': len(common),
                    'differs': differs,
                    'name_a': fa.filename, 'name_b': fb.filename,
                }
                za.close(); zb.close()
            except Exception as e: error = str(e)
    return render_template('tools/triagediff.html', result=result, error=error)
