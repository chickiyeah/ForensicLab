"""
ForensicLab 확장 도구 세트 2
============================
20개 신규 분석 도구를 한 모듈에 정의.

라우트:
  /tools/evtx       Windows EVTX 이벤트 로그
  /tools/sqlite     SQLite 브라우저 (Chrome/iOS/WhatsApp 등)
  /tools/jumplist   JumpList .automaticDestinations-ms
  /tools/oledump    VBA 매크로·OLE 스트림
  /tools/pdfscan    PDF 악성 분석
  /tools/jwt        JWT 디코더
  /tools/cert       X.509 인증서
  /tools/yara       YARA-lite 패턴 스캐너
  /tools/hexdiff    파일 헥스 diff
  /tools/secrets    Secret/API 키 스캐너
  /tools/esedb      ESE DB (Windows.edb)
  /tools/mft        NTFS $MFT 파서
  /tools/email-auth SPF/DKIM/DMARC 검증
  /tools/dns        DNS 쿼리/도메인 분석
  /tools/stego      스테가노그래피
  /tools/qr         QR/바코드 디코더
  /tools/ocr        이미지 OCR
  /tools/whois      WHOIS/IP 지리정보
  /tools/passwd     암호 강도
  /tools/git        Git 저장소 분석
"""
import base64
import binascii
import datetime as _dt
import hashlib
import io
import json
import os
import re
import socket
import struct
import zipfile
import zlib
from collections import Counter
from pathlib import Path

from flask import request, render_template, jsonify

from monitor.views.tools import bp, _save_log


# ============================================================
# /tools/evtx — Windows EVTX 이벤트 로그
# ============================================================
def _parse_evtx(data: bytes) -> dict:
    if data[:8] != b'ElfFile\x00':
        raise ValueError('EVTX 시그니처 아님 (ElfFile)')
    try:
        from Evtx.Evtx import Evtx
        import tempfile
        tf = tempfile.NamedTemporaryFile(delete=False, suffix='.evtx')
        tf.write(data); tf.close()
        events = []
        eid_counter = Counter()
        with Evtx(tf.name) as log:
            for i, rec in enumerate(log.records()):
                if i >= 5000: break
                try:
                    xml = rec.xml()
                    eid = re.search(r'<EventID[^>]*>(\d+)', xml)
                    ts = re.search(r"SystemTime='([^']+)'", xml)
                    ch = re.search(r'<Channel>([^<]+)', xml)
                    comp = re.search(r'<Computer>([^<]+)', xml)
                    lvl = re.search(r'<Level>(\d+)', xml)
                    if eid: eid_counter[eid.group(1)] += 1
                    events.append({
                        'rid': rec.record_num(),
                        'eid': eid.group(1) if eid else '?',
                        'ts': ts.group(1) if ts else '',
                        'channel': ch.group(1) if ch else '',
                        'computer': comp.group(1) if comp else '',
                        'level': lvl.group(1) if lvl else '',
                        'xml': xml[:5000],
                    })
                except Exception: pass
        os.unlink(tf.name)
        return {
            'total': len(events),
            'top_eids': eid_counter.most_common(20),
            'events': events[:500],
        }
    except ImportError:
        raise ValueError('python-evtx 라이브러리 필요')


@bp.route('/evtx', methods=['GET','POST'])
def evtx_tool():
    result = error = None; share_token = None
    if request.method == 'POST':
        f = request.files.get('file')
        if not f or not f.filename: error = '파일 필요'
        else:
            data = f.read()
            try:
                result = _parse_evtx(data)
                result['filename'] = f.filename; result['file_size'] = len(data)
                share_token = _save_log('evtx', 'EVTX 분석', f.filename, len(data),
                                        f"{result['total']}개 이벤트", result)
            except Exception as e: error = str(e)
    return render_template('tools/evtx.html', result=result, error=error,
                           share_token=share_token)


# ============================================================
# /tools/sqlite — SQLite 브라우저
# ============================================================
import sqlite3 as _sqlite3
import tempfile

@bp.route('/sqlite', methods=['GET','POST'])
def sqlite_tool():
    result = error = None
    table_data = None
    if request.method == 'POST':
        f = request.files.get('file')
        action = request.form.get('action', 'list')
        sql = request.form.get('sql', '').strip()
        if not f or not f.filename: error = '파일 필요'
        else:
            data = f.read()
            if data[:16] != b'SQLite format 3\x00':
                error = 'SQLite 시그니처 없음'
            else:
                tf = tempfile.NamedTemporaryFile(delete=False, suffix='.db')
                tf.write(data); tf.close()
                try:
                    con = _sqlite3.connect(f'file:{tf.name}?mode=ro', uri=True)
                    cur = con.cursor()
                    tables = [r[0] for r in cur.execute(
                        "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")]
                    info = []
                    for t in tables:
                        try:
                            cnt = cur.execute(f'SELECT COUNT(*) FROM "{t}"').fetchone()[0]
                            cols = [r[1] for r in cur.execute(f'PRAGMA table_info("{t}")')]
                            info.append({'name': t, 'rows': cnt, 'cols': cols})
                        except Exception: info.append({'name': t, 'rows': '?', 'cols': []})
                    rows = headers = None
                    if action == 'query' and sql:
                        if not sql.lower().lstrip().startswith(('select','pragma','with','explain')):
                            error = '읽기 전용 쿼리만 허용 (SELECT/PRAGMA/WITH/EXPLAIN)'
                        else:
                            try:
                                cur.execute(sql)
                                headers = [d[0] for d in cur.description] if cur.description else []
                                rows = [list(r) for r in cur.fetchmany(1000)]
                            except Exception as e: error = f'쿼리 오류: {e}'
                    result = {
                        'filename': f.filename, 'file_size': len(data),
                        'tables': info, 'rows': rows, 'headers': headers,
                        'sql': sql,
                    }
                    con.close()
                except Exception as e: error = str(e)
                finally: os.unlink(tf.name)
    return render_template('tools/sqlite.html', result=result, error=error)


# ============================================================
# /tools/jumplist — .automaticDestinations-ms DestList
# ============================================================
def _parse_jumplist(data: bytes) -> dict:
    if data[:8] != b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1':
        raise ValueError('OLECF 시그니처 아님')
    try:
        import olefile
        ole = olefile.OleFileIO(io.BytesIO(data))
        streams = ole.listdir()
        result = {'streams': [], 'entries': []}
        for s in streams:
            name = '/'.join(s)
            try:
                sz = ole.get_size(s)
                result['streams'].append({'name': name, 'size': sz})
            except Exception: pass
        # DestList 스트림 파싱
        if ole.exists('DestList'):
            dl = ole.openstream('DestList').read()
            if len(dl) >= 0x20:
                ver, n_entries, n_pinned = struct.unpack('<III', dl[:12])
                result['version'] = ver
                result['n_entries'] = n_entries
                result['n_pinned'] = n_pinned
                off = 0x20 if ver >= 3 else 0x10
                idx = 0
                while off < len(dl) and idx < 200:
                    try:
                        if ver >= 3:
                            if off + 0x82 > len(dl): break
                            entry_id = struct.unpack('<I', dl[off+0x58:off+0x5C])[0]
                            ft = struct.unpack('<Q', dl[off+0x64:off+0x6C])[0]
                            access_cnt = struct.unpack('<f', dl[off+0x78:off+0x7C])[0]
                            path_len = struct.unpack('<H', dl[off+0x84:off+0x86])[0]
                            path = dl[off+0x86:off+0x86+path_len*2].decode('utf-16-le','replace')
                            ts = ''
                            if ft > 0:
                                try:
                                    ts = (_dt.datetime(1601,1,1,tzinfo=_dt.timezone.utc)
                                          + _dt.timedelta(microseconds=ft//10)).isoformat()
                                except Exception: pass
                            host_off = off + 0x48
                            host = dl[host_off:host_off+16].split(b'\x00',1)[0].decode('latin1','replace')
                            result['entries'].append({
                                'idx': idx, 'entry_id': entry_id,
                                'last_access': ts, 'access_count': int(access_cnt) if access_cnt < 1e10 else 0,
                                'hostname': host, 'path': path,
                            })
                            # 다음 엔트리로
                            off += 0x86 + path_len*2 + 4  # 4 = trailer 0xBABFFBAB
                            idx += 1
                        else:
                            break
                    except Exception: break
        return result
    except ImportError:
        raise ValueError('olefile 라이브러리 필요')


@bp.route('/jumplist', methods=['GET','POST'])
def jumplist_tool():
    result = error = None; share_token = None
    if request.method == 'POST':
        f = request.files.get('file')
        if not f or not f.filename: error = '파일 필요'
        else:
            data = f.read()
            try:
                result = _parse_jumplist(data)
                result['filename'] = f.filename; result['file_size'] = len(data)
                share_token = _save_log('jumplist', 'JumpList', f.filename, len(data),
                    f"{len(result.get('entries', []))}개 엔트리", result)
            except Exception as e: error = str(e)
    return render_template('tools/jumplist.html', result=result, error=error,
                           share_token=share_token)


# ============================================================
# /tools/oledump — VBA·OLE 스트림 추출
# ============================================================
def _parse_oledump(data: bytes, filename: str) -> dict:
    # ZIP (Office 2007+) 또는 OLE (Office 97-2003)
    if data[:4] == b'PK\x03\x04':
        # OOXML
        result = {'format': 'OOXML (Office 2007+)', 'streams': [],
                  'macros': [], 'suspicious': []}
        try:
            zf = zipfile.ZipFile(io.BytesIO(data))
            for zi in zf.infolist():
                result['streams'].append({'name': zi.filename, 'size': zi.file_size})
                if 'vbaProject.bin' in zi.filename:
                    # vbaProject.bin은 OLE 컨테이너
                    vba = zf.read(zi.filename)
                    result['macros'].append({
                        'source': zi.filename,
                        'size': len(vba),
                        'note': 'OLE 컨테이너 — 매크로 코드가 압축되어 있습니다',
                    })
            # 의심 키워드
            for zi in zf.infolist():
                try:
                    content = zf.read(zi.filename)
                    for kw in [b'AutoOpen', b'Document_Open', b'Auto_Exec',
                               b'Shell.Application', b'WScript.Shell',
                               b'powershell', b'cmd.exe', b'http://', b'https://']:
                        if kw in content:
                            result['suspicious'].append({
                                'stream': zi.filename,
                                'keyword': kw.decode('latin1', errors='ignore'),
                            })
                except Exception: pass
            zf.close()
        except Exception as e:
            result['error'] = str(e)
        return result
    if data[:8] == b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1':
        result = {'format': 'OLE2 (Office 97-2003)', 'streams': [], 'macros': [], 'suspicious': []}
        try:
            import olefile
            ole = olefile.OleFileIO(io.BytesIO(data))
            for s in ole.listdir():
                name = '/'.join(s)
                try:
                    sz = ole.get_size(s)
                    is_macro = any(p in name.lower() for p in ['vba', 'macros', 'module'])
                    result['streams'].append({'name': name, 'size': sz, 'macro': is_macro})
                    if is_macro and sz < 1024*1024:
                        content = ole.openstream(s).read()
                        # ASCII strings within macro stream
                        strings = re.findall(rb'[\x20-\x7E]{5,200}', content)
                        result['macros'].append({
                            'stream': name, 'size': sz,
                            'strings': [s.decode('latin1') for s in strings[:30]],
                        })
                except Exception: pass
            # 의심 키워드
            for s in ole.listdir():
                try:
                    c = ole.openstream(s).read()
                    for kw in [b'AutoOpen', b'Document_Open', b'Shell', b'powershell',
                               b'cmd.exe', b'http://', b'https://', b'WScript',
                               b'ActiveXObject', b'Scripting.FileSystemObject']:
                        if kw in c:
                            result['suspicious'].append({
                                'stream': '/'.join(s),
                                'keyword': kw.decode('latin1', errors='ignore'),
                            })
                except Exception: pass
            ole.close()
        except ImportError:
            result['error'] = 'olefile 라이브러리 필요'
        return result
    raise ValueError('Office 파일 시그니처 없음 (OOXML/OLE2 아님)')


@bp.route('/oledump', methods=['GET','POST'])
def oledump_tool():
    result = error = None; share_token = None
    if request.method == 'POST':
        f = request.files.get('file')
        if not f or not f.filename: error = '파일 필요'
        else:
            data = f.read()
            try:
                result = _parse_oledump(data, f.filename)
                result['filename'] = f.filename; result['file_size'] = len(data)
                share_token = _save_log('oledump', 'OLE/VBA 추출', f.filename, len(data),
                    f"매크로 {len(result.get('macros',[]))} · 의심 {len(result.get('suspicious',[]))}", result)
            except Exception as e: error = str(e)
    return render_template('tools/oledump.html', result=result, error=error,
                           share_token=share_token)


# ============================================================
# /tools/pdfscan — PDF 악성 분석
# ============================================================
def _scan_pdf(data: bytes) -> dict:
    if data[:5] != b'%PDF-':
        raise ValueError('PDF 시그니처 없음')
    version = data[5:8].decode('latin1', errors='ignore')
    text = data.decode('latin1', errors='replace')
    counts = {}
    for tag in ['/JavaScript', '/JS', '/OpenAction', '/AA', '/Launch',
                '/EmbeddedFile', '/RichMedia', '/SubmitForm', '/URI',
                '/GoToR', '/GoToE', '/ImportData', '/XFA', '/AcroForm']:
        counts[tag] = text.count(tag)
    # /Names 인덱스
    n_obj = len(re.findall(r'\b\d+\s+\d+\s+obj\b', text))
    n_stream = text.count('stream\n')
    n_filter = text.count('/Filter')
    suspicious = []
    if counts['/JavaScript'] or counts['/JS']:
        suspicious.append('JavaScript 내장 — 악성 PDF 가능성')
    if counts['/OpenAction']:
        suspicious.append('/OpenAction — 문서 열 때 자동 실행')
    if counts['/AA']:
        suspicious.append('/AA (Additional Action) — 이벤트 트리거 실행')
    if counts['/Launch']:
        suspicious.append('/Launch — 외부 프로그램 실행 (Acrobat 7+에서 차단)')
    if counts['/EmbeddedFile']:
        suspicious.append('/EmbeddedFile — 첨부 파일 포함')
    if counts['/RichMedia']:
        suspicious.append('/RichMedia — Flash/멀티미디어 (Adobe 보안 권고 대상)')
    # URL 추출
    urls = re.findall(r'https?://[^\s<>\\"\']{4,200}', text)[:30]
    return {
        'version': version, 'object_count': n_obj,
        'stream_count': n_stream, 'filter_count': n_filter,
        'counts': counts, 'suspicious': suspicious,
        'urls': list(set(urls)),
        'verdict': '의심' if suspicious else '정상 패턴',
    }


@bp.route('/pdfscan', methods=['GET','POST'])
def pdfscan_tool():
    result = error = None; share_token = None
    if request.method == 'POST':
        f = request.files.get('file')
        if not f or not f.filename: error = '파일 필요'
        else:
            data = f.read()
            try:
                result = _scan_pdf(data)
                result['filename'] = f.filename; result['file_size'] = len(data)
                share_token = _save_log('pdfscan','PDF 악성 분석', f.filename, len(data),
                    f"{result['verdict']} | 의심 {len(result['suspicious'])}건", result)
            except Exception as e: error = str(e)
    return render_template('tools/pdfscan.html', result=result, error=error,
                           share_token=share_token)


# ============================================================
# /tools/jwt — JWT 디코더
# ============================================================
@bp.route('/jwt', methods=['GET','POST'])
def jwt_tool():
    result = error = None
    token = ''
    if request.method == 'POST':
        token = (request.form.get('token') or '').strip()
        if not token: error = 'JWT 입력 필요'
        else:
            try:
                parts = token.split('.')
                if len(parts) != 3:
                    error = 'JWT는 header.payload.signature 형식이어야 합니다'
                else:
                    def b64d(s):
                        return base64.urlsafe_b64decode(s + '=' * (-len(s) % 4))
                    header = json.loads(b64d(parts[0]))
                    payload = json.loads(b64d(parts[1]))
                    sig = b64d(parts[2])
                    # 시각 필드 변환
                    payload_pretty = dict(payload)
                    for k in ('iat', 'exp', 'nbf', 'auth_time'):
                        if k in payload and isinstance(payload[k], int):
                            try:
                                payload_pretty[f'{k} (해석)'] = _dt.datetime.fromtimestamp(
                                    payload[k], _dt.timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
                            except Exception: pass
                    # 만료 검증
                    warnings = []
                    if header.get('alg', '').lower() == 'none':
                        warnings.append('⚠️ alg=none — 서명 없음 (취약점)')
                    if header.get('alg') in ('HS256', 'HS384', 'HS512') and 'kid' not in header:
                        warnings.append('ℹ️ HMAC 서명 — 비밀키 무차별 시도 가능')
                    if 'exp' in payload:
                        now = _dt.datetime.now(_dt.timezone.utc).timestamp()
                        if payload['exp'] < now:
                            warnings.append(f'⚠️ 만료됨 (exp={payload["exp"]})')
                        else:
                            warnings.append(f'✓ 유효 (만료까지 {int((payload["exp"]-now)/60)}분)')
                    result = {
                        'header': header, 'payload': payload_pretty,
                        'signature_hex': sig.hex(),
                        'signature_len': len(sig),
                        'alg': header.get('alg', '?'),
                        'typ': header.get('typ', '?'),
                        'kid': header.get('kid', ''),
                        'warnings': warnings,
                        'token_parts': [len(p) for p in parts],
                    }
            except Exception as e: error = f'디코딩 오류: {e}'
    return render_template('tools/jwt.html', result=result, error=error, token=token)


# ============================================================
# /tools/cert — X.509 인증서
# ============================================================
def _parse_cert(data: bytes) -> dict:
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives.serialization import pkcs12
        from cryptography.hazmat.primitives import hashes
        cert = None
        # PEM
        if b'-----BEGIN CERTIFICATE-----' in data:
            cert = x509.load_pem_x509_certificate(data)
        # DER
        else:
            try:
                cert = x509.load_der_x509_certificate(data)
            except Exception:
                # PKCS#12
                try:
                    pwd = b''
                    p12 = pkcs12.load_key_and_certificates(data, pwd)
                    cert = p12[1]
                except Exception as e:
                    raise ValueError(f'PEM/DER/PKCS12 모두 파싱 실패: {e}')
        info = {
            'subject': cert.subject.rfc4514_string(),
            'issuer': cert.issuer.rfc4514_string(),
            'serial': hex(cert.serial_number),
            'version': cert.version.name,
            'not_before': cert.not_valid_before_utc.isoformat(),
            'not_after': cert.not_valid_after_utc.isoformat(),
            'signature_algorithm': cert.signature_algorithm_oid._name,
            'fingerprint_sha256': cert.fingerprint(hashes.SHA256()).hex(),
            'fingerprint_sha1': cert.fingerprint(hashes.SHA1()).hex(),
            'public_key_size': cert.public_key().key_size if hasattr(cert.public_key(), 'key_size') else '?',
        }
        # SAN
        try:
            san = cert.extensions.get_extension_for_oid(x509.OID_SUBJECT_ALTERNATIVE_NAME)
            info['san'] = [n.value for n in san.value]
        except Exception: info['san'] = []
        # 자가 서명 / 만료 / 약한 알고리즘
        warnings = []
        now = _dt.datetime.now(_dt.timezone.utc)
        if cert.not_valid_after_utc < now:
            warnings.append('⚠️ 만료됨')
        elif (cert.not_valid_after_utc - now).days < 30:
            warnings.append(f'⚠️ 만료 임박 ({(cert.not_valid_after_utc - now).days}일 남음)')
        if cert.subject == cert.issuer:
            warnings.append('ℹ️ 자가 서명 인증서 (Self-signed)')
        sig_alg = info['signature_algorithm'].lower()
        if 'sha1' in sig_alg or 'md5' in sig_alg:
            warnings.append(f'⚠️ 취약한 서명 알고리즘: {info["signature_algorithm"]}')
        info['warnings'] = warnings
        return info
    except ImportError:
        raise ValueError('cryptography 라이브러리 필요')


@bp.route('/cert', methods=['GET','POST'])
def cert_tool():
    result = error = None; share_token = None
    if request.method == 'POST':
        f = request.files.get('file')
        text = request.form.get('pem', '').strip()
        data = b''
        if f and f.filename: data = f.read()
        elif text: data = text.encode('latin1')
        if not data: error = '파일 또는 PEM 텍스트 필요'
        else:
            try:
                result = _parse_cert(data)
                result['filename'] = f.filename if f and f.filename else 'PEM-text'
                share_token = _save_log('cert','X509 인증서', result['filename'], len(data),
                    f"{result['subject'][:60]}", result)
            except Exception as e: error = str(e)
    return render_template('tools/cert.html', result=result, error=error,
                           share_token=share_token)


# ============================================================
# /tools/yara — YARA-lite 패턴 스캐너
# ============================================================
def _yara_lite_match(data: bytes, rules_text: str) -> list:
    """간소화 YARA 패턴: rule NAME { strings: $a = "..." ... condition: any of them }
    문자열 패턴만 지원 (정규식 X, hex string ✓)"""
    matches = []
    # 규칙 블록 파싱
    rule_pattern = re.compile(
        r'rule\s+(\w+)[^{]*\{([^}]+)\}', re.DOTALL)
    for m in rule_pattern.finditer(rules_text):
        name = m.group(1)
        body = m.group(2)
        # strings 섹션
        strings_section = re.search(r'strings:\s*(.+?)(?=condition:|$)', body, re.DOTALL)
        if not strings_section: continue
        str_defs = re.findall(r'\$(\w+)\s*=\s*("([^"]+)"|{([0-9a-fA-F\s\?]+)})', strings_section.group(1))
        hits = []
        for var, full, ascii_s, hex_s in str_defs:
            if ascii_s:
                # 텍스트 패턴
                pat = ascii_s.encode('latin1', errors='ignore')
                offsets = []
                start = 0
                while True:
                    idx = data.find(pat, start)
                    if idx < 0: break
                    offsets.append(idx)
                    start = idx + 1
                    if len(offsets) >= 20: break
                if offsets:
                    hits.append({'var': var, 'type': 'ascii', 'pattern': ascii_s[:80],
                                 'offsets': offsets})
            elif hex_s:
                # 헥스 패턴
                hex_clean = re.sub(r'\s+', '', hex_s)
                try:
                    pat = bytes.fromhex(hex_clean.replace('?', '0'))
                    offsets = []
                    start = 0
                    while True:
                        idx = data.find(pat, start)
                        if idx < 0: break
                        offsets.append(idx)
                        start = idx + 1
                        if len(offsets) >= 20: break
                    if offsets:
                        hits.append({'var': var, 'type': 'hex', 'pattern': hex_clean[:80],
                                     'offsets': offsets})
                except ValueError: pass
        if hits:
            matches.append({'rule': name, 'hits': hits})
    return matches


@bp.route('/yara', methods=['GET','POST'])
def yara_tool():
    result = error = None; share_token = None
    rules_text = ''
    if request.method == 'POST':
        f = request.files.get('file')
        rules_text = request.form.get('rules', '').strip()
        if not f or not f.filename: error = '검사할 파일 필요'
        elif not rules_text: error = 'YARA 규칙 입력 필요'
        else:
            data = f.read()
            try:
                matches = _yara_lite_match(data, rules_text)
                result = {
                    'filename': f.filename, 'file_size': len(data),
                    'matches': matches,
                    'match_count': sum(len(m['hits']) for m in matches),
                }
                share_token = _save_log('yara','YARA 스캔', f.filename, len(data),
                    f"{len(matches)}개 규칙 매칭", result)
            except Exception as e: error = str(e)
    return render_template('tools/yara.html', result=result, error=error,
                           rules=rules_text)


# ============================================================
# /tools/hexdiff — 두 파일 헥스 비교
# ============================================================
def _hex_diff(a: bytes, b: bytes, max_diff: int = 1000) -> dict:
    diffs = []
    min_len = min(len(a), len(b))
    for i in range(min_len):
        if a[i] != b[i]:
            diffs.append({'offset': i, 'a': f'{a[i]:02X}', 'b': f'{b[i]:02X}'})
            if len(diffs) >= max_diff: break
    return {
        'size_a': len(a), 'size_b': len(b),
        'diffs': diffs,
        'identical': len(diffs) == 0 and len(a) == len(b),
        'sha256_a': hashlib.sha256(a).hexdigest(),
        'sha256_b': hashlib.sha256(b).hexdigest(),
    }


@bp.route('/hexdiff', methods=['GET','POST'])
def hexdiff_tool():
    result = error = None
    if request.method == 'POST':
        fa = request.files.get('file_a')
        fb = request.files.get('file_b')
        if not fa or not fb or not fa.filename or not fb.filename:
            error = '두 파일 모두 선택'
        else:
            try:
                a = fa.read(); b = fb.read()
                result = _hex_diff(a, b)
                result['name_a'] = fa.filename; result['name_b'] = fb.filename
            except Exception as e: error = str(e)
    return render_template('tools/hexdiff.html', result=result, error=error)


# ============================================================
# /tools/secrets — Secret/API 키 스캐너
# ============================================================
_SECRET_PATTERNS = [
    ('AWS Access Key',       r'AKIA[0-9A-Z]{16}'),
    ('AWS Secret Key',       r'(?:aws_secret_access_key|aws.secret)["\'\s:=]+([A-Za-z0-9/+=]{40})'),
    ('GCP API Key',          r'AIza[0-9A-Za-z\-_]{35}'),
    ('GCP Service Account',  r'"type":\s*"service_account"'),
    ('Azure Subscription ID',r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'),
    ('GitHub Token',         r'gh[pousr]_[A-Za-z0-9]{36}'),
    ('GitLab Token',         r'glpat-[A-Za-z0-9_\-]{20,}'),
    ('Slack Token',          r'xox[baprs]-[A-Za-z0-9\-]{10,}'),
    ('Slack Webhook',        r'https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+'),
    ('Stripe Key',           r'(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{24,}'),
    ('JWT 토큰',             r'eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+'),
    ('Private Key',          r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----'),
    ('SSH Key',              r'ssh-(?:rsa|ed25519|dss) [A-Za-z0-9+/=]+'),
    ('PGP Key',              r'-----BEGIN PGP (?:PRIVATE|PUBLIC) KEY BLOCK-----'),
    ('DB 비밀번호',          r'(?:password|passwd|pwd|db_pass)["\'\s:=]+["\']([^"\']{4,40})["\']'),
    ('하드코딩 비밀번호',    r'(?:password|secret|api_key|token)\s*=\s*["\']([A-Za-z0-9_\-!@#$%^&*]{6,40})["\']'),
    ('Discord Webhook',      r'https://discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_\-]+'),
    ('Discord Token',        r'(?:mfa\.)?[A-Za-z0-9_\-]{24,40}\.[A-Za-z0-9_\-]{6}\.[A-Za-z0-9_\-]{27,40}'),
    ('SendGrid',             r'SG\.[A-Za-z0-9_\-]{16,32}\.[A-Za-z0-9_\-]{16,64}'),
    ('Mailgun',              r'key-[A-Za-z0-9]{32}'),
    ('Twilio AccountSID',    r'AC[a-f0-9]{32}'),
    ('Twilio Auth Token',    r'SK[a-f0-9]{32}'),
    ('Heroku',               r'[hH]eroku[a-z_]*[\s=:]+[\'"]?[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}'),
    ('Generic API',          r'(?:api[_-]?key|apikey|access[_-]?token)["\']?\s*[:=]\s*["\']([A-Za-z0-9_\-]{16,80})["\']'),
]

def _scan_secrets(data: bytes) -> list:
    findings = []
    try:
        text = data.decode('utf-8', errors='replace')
    except Exception:
        text = data.decode('latin1', errors='replace')
    for label, pat in _SECRET_PATTERNS:
        for m in re.finditer(pat, text):
            val = m.group(0)
            findings.append({
                'type': label,
                'offset': m.start(),
                'value': val[:100],
                'context': text[max(0, m.start()-20):m.end()+20].replace('\n',' ')[:120],
            })
            if len(findings) > 500: return findings
    return findings


@bp.route('/secrets', methods=['GET','POST'])
def secrets_tool():
    result = error = None; share_token = None
    if request.method == 'POST':
        f = request.files.get('file')
        text = request.form.get('text', '').strip()
        if f and f.filename:
            data = f.read()
            src = f.filename
        elif text:
            data = text.encode('utf-8'); src = 'pasted'
        else:
            error = '파일 또는 텍스트 필요'
            data = None
        if data is not None:
            findings = _scan_secrets(data)
            type_counter = Counter(f['type'] for f in findings)
            result = {
                'filename': src, 'file_size': len(data),
                'findings': findings[:200],
                'total': len(findings),
                'by_type': type_counter.most_common(),
            }
            share_token = _save_log('secrets','Secret 스캔', src, len(data),
                f"{len(findings)}건 발견", {'total':len(findings),'by_type':list(type_counter.items())})
    return render_template('tools/secrets.html', result=result, error=error)


# ============================================================
# /tools/esedb — ESE 데이터베이스 (Windows.edb 등)
# ============================================================
def _parse_esedb(data: bytes) -> dict:
    # ESE 헤더: 시그니처 0x89ABCDEF at offset 4
    if len(data) < 668: raise ValueError('ESE 헤더 너무 작음')
    sig = struct.unpack('<I', data[4:8])[0]
    if sig != 0x89ABCDEF: raise ValueError(f'ESE 시그니처 불일치: {hex(sig)}')
    file_format = struct.unpack('<I', data[8:12])[0]
    file_type = struct.unpack('<I', data[12:16])[0]
    log_pos = struct.unpack('<Q', data[16:24])[0]
    consistent_pos = struct.unpack('<Q', data[24:32])[0]
    db_state = struct.unpack('<I', data[52:56])[0]
    page_size = struct.unpack('<I', data[236:240])[0]
    STATES = {1:'JustCreated',2:'DirtyShutdown',3:'CleanShutdown',
              4:'BeingConverted',5:'ForceDetach'}
    TYPES = {0:'Database',1:'StreamingFile'}
    return {
        'signature': f'0x{sig:08X}',
        'file_format_version': file_format,
        'file_type': TYPES.get(file_type, f'Unknown({file_type})'),
        'page_size': page_size,
        'db_state': STATES.get(db_state, f'Unknown({db_state})'),
        'log_position': log_pos,
        'consistent_position': consistent_pos,
        'note': 'ESE는 복잡한 B-tree DB — 헤더만 파싱. 전체 분석은 libesedb / EsentUtl / SrumECmd 권장',
    }


@bp.route('/esedb', methods=['GET','POST'])
def esedb_tool():
    result = error = None
    if request.method == 'POST':
        f = request.files.get('file')
        if not f or not f.filename: error = '파일 필요'
        else:
            data = f.read(64*1024)  # 헤더만
            try:
                result = _parse_esedb(data)
                result['filename'] = f.filename
            except Exception as e: error = str(e)
    return render_template('tools/esedb.html', result=result, error=error)


# ============================================================
# /tools/mft — NTFS $MFT 파서
# ============================================================
def _parse_mft(data: bytes) -> dict:
    if data[:4] not in (b'FILE', b'BAAD'):
        raise ValueError('FILE/BAAD 시그니처 없음 — $MFT 아님')
    records = []
    rec_size = 1024
    for i in range(min(len(data) // rec_size, 5000)):
        off = i * rec_size
        rec = data[off:off+rec_size]
        if rec[:4] != b'FILE': continue
        try:
            seq_num = struct.unpack('<H', rec[0x10:0x12])[0]
            hard_link = struct.unpack('<H', rec[0x12:0x14])[0]
            first_attr = struct.unpack('<H', rec[0x14:0x16])[0]
            flags = struct.unpack('<H', rec[0x16:0x18])[0]
            used_sz = struct.unpack('<I', rec[0x18:0x1C])[0]
            in_use = bool(flags & 1)
            is_dir = bool(flags & 2)
            filename = ''
            ts = {}
            # 속성 순회
            pos = first_attr
            while pos < min(used_sz, rec_size - 8):
                atype = struct.unpack('<I', rec[pos:pos+4])[0]
                if atype == 0xFFFFFFFF: break
                alen = struct.unpack('<I', rec[pos+4:pos+8])[0]
                if alen == 0: break
                non_res = rec[pos+8] == 1
                attr_body = rec[pos+24:pos+alen] if not non_res else None
                if atype == 0x10 and attr_body and len(attr_body) >= 48:  # $STANDARD_INFO
                    ft_c, ft_m, ft_e, ft_a = struct.unpack('<QQQQ', attr_body[:32])
                    for k, v in [('created',ft_c),('modified',ft_m),
                                 ('entry_changed',ft_e),('accessed',ft_a)]:
                        if v > 0:
                            try:
                                ts[k] = (_dt.datetime(1601,1,1,tzinfo=_dt.timezone.utc)
                                         + _dt.timedelta(microseconds=v//10)).isoformat()
                            except Exception: pass
                if atype == 0x30 and attr_body and len(attr_body) >= 0x42:  # $FILE_NAME
                    name_len = attr_body[0x40]
                    namespace = attr_body[0x41]
                    if 0x42 + name_len * 2 <= len(attr_body):
                        try:
                            filename = attr_body[0x42:0x42 + name_len * 2].decode(
                                'utf-16-le', errors='replace')
                        except Exception: pass
                pos += alen
            records.append({
                'rec_num': i, 'seq': seq_num, 'links': hard_link,
                'in_use': in_use, 'is_dir': is_dir,
                'filename': filename, 'timestamps': ts,
            })
        except Exception: continue
    return {
        'total': len(records),
        'records': records[:1000],
        'deleted': sum(1 for r in records if not r['in_use']),
        'dirs': sum(1 for r in records if r['is_dir']),
    }


@bp.route('/mft', methods=['GET','POST'])
def mft_tool():
    result = error = None; share_token = None
    if request.method == 'POST':
        f = request.files.get('file')
        if not f or not f.filename: error = '파일 필요'
        else:
            data = f.read(50*1024*1024)
            try:
                result = _parse_mft(data)
                result['filename'] = f.filename; result['file_size'] = len(data)
                share_token = _save_log('mft','$MFT 파싱', f.filename, len(data),
                    f"{result['total']}개 레코드 (삭제 {result['deleted']})", result)
            except Exception as e: error = str(e)
    return render_template('tools/mft.html', result=result, error=error,
                           share_token=share_token)


# ============================================================
# /tools/email-auth — SPF / DKIM / DMARC
# ============================================================
@bp.route('/email-auth', methods=['GET','POST'])
def email_auth_tool():
    result = error = None
    if request.method == 'POST':
        domain = (request.form.get('domain') or '').strip()
        headers = (request.form.get('headers') or '').strip()
        if not domain and not headers:
            error = '도메인 또는 헤더 입력 필요'
        else:
            r = {'domain': domain, 'headers_provided': bool(headers)}
            # DNS 조회 (가능하면)
            try:
                import dns.resolver
                resolver = dns.resolver.Resolver()
                resolver.timeout = 3; resolver.lifetime = 3
                if domain:
                    # SPF
                    try:
                        ans = resolver.resolve(domain, 'TXT')
                        for rd in ans:
                            for s in rd.strings:
                                t = s.decode('utf-8',errors='replace')
                                if t.startswith('v=spf1'):
                                    r['spf'] = t
                                if t.startswith('v=DMARC1'):
                                    r['dmarc'] = t
                    except Exception: pass
                    # DMARC
                    try:
                        ans = resolver.resolve(f'_dmarc.{domain}', 'TXT')
                        for rd in ans:
                            for s in rd.strings:
                                t = s.decode('utf-8',errors='replace')
                                if t.startswith('v=DMARC1'):
                                    r['dmarc'] = t
                    except Exception: pass
                    # MX
                    try:
                        mx = resolver.resolve(domain, 'MX')
                        r['mx'] = [f'{m.preference} {m.exchange}' for m in mx]
                    except Exception: pass
            except ImportError:
                r['note'] = 'dnspython 미설치 — DNS 조회 불가, 헤더만 분석'
            # 헤더 분석
            if headers:
                auth_results = re.search(r'Authentication-Results:\s*(.+?)(?=\n\S|\Z)', headers, re.S)
                if auth_results:
                    r['auth_results'] = auth_results.group(1).strip()
                    r['spf_pass']   = 'spf=pass' in r['auth_results'].lower()
                    r['dkim_pass']  = 'dkim=pass' in r['auth_results'].lower()
                    r['dmarc_pass'] = 'dmarc=pass' in r['auth_results'].lower()
                # 발신 IP 추출
                received = re.findall(r'Received: from .+?\[(\d+\.\d+\.\d+\.\d+)\]', headers)
                r['hop_ips'] = received[:10]
            result = r
    return render_template('tools/email_auth.html', result=result, error=error)


# ============================================================
# /tools/dns — DNS 분석 / DGA 탐지
# ============================================================
def _dga_score(domain: str) -> dict:
    """간단한 DGA 휴리스틱: 엔트로피, 자모 비율, 길이"""
    name = domain.split('.')[0].lower()
    if not name: return {'score': 0, 'verdict': 'invalid'}
    L = len(name)
    consonants = sum(1 for c in name if c in 'bcdfghjklmnpqrstvwxz')
    vowels = sum(1 for c in name if c in 'aeiou')
    digits = sum(1 for c in name if c.isdigit())
    import math as _math
    counts = Counter(name)
    entropy = -sum((c/L) * _math.log2(c/L) for c in counts.values()) if L else 0
    # 점수 계산
    score = 0
    if entropy > 3.5: score += 30
    if L > 15: score += 20
    if L > 25: score += 20
    if consonants > 0 and vowels > 0:
        ratio = consonants / max(vowels, 1)
        if ratio > 3 or ratio < 0.3: score += 20
    if digits > L * 0.3: score += 10
    # 자모 시퀀스 (3연속 자음)
    if re.search(r'[bcdfghjklmnpqrstvwxz]{4,}', name): score += 20
    verdict = ('정상' if score < 20 else
               '의심' if score < 50 else
               'DGA 강력 의심')
    return {
        'name': name, 'length': L, 'entropy': round(entropy, 3),
        'consonants': consonants, 'vowels': vowels, 'digits': digits,
        'score': min(score, 100), 'verdict': verdict,
    }


@bp.route('/dns', methods=['GET','POST'])
def dns_tool():
    result = error = None
    if request.method == 'POST':
        text = (request.form.get('text') or '').strip()
        if not text: error = '도메인 목록 입력 필요'
        else:
            domains = re.findall(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b',
                                 text)
            domains = list(dict.fromkeys(domains))[:500]
            scored = []
            for d in domains:
                s = _dga_score(d)
                s['domain'] = d
                scored.append(s)
            scored.sort(key=lambda x: -x['score'])
            result = {
                'total': len(scored),
                'domains': scored,
                'suspicious': [d for d in scored if d['score'] >= 50],
            }
    return render_template('tools/dns.html', result=result, error=error)


# ============================================================
# /tools/stego — 스테가노그래피 탐지
# ============================================================
def _detect_stego(data: bytes, filename: str) -> dict:
    r = {'filename': filename, 'file_size': len(data), 'findings': []}
    # 파일 끝 부가 데이터 (대표적 신호 — JPEG의 FFD9, PNG의 IEND)
    if data[:3] == b'\xFF\xD8\xFF':
        # JPEG
        eoi = data.rfind(b'\xFF\xD9')
        if eoi >= 0 and eoi < len(data) - 4:
            r['findings'].append({
                'type': 'JPEG EOI 이후 데이터',
                'offset': eoi + 2,
                'size': len(data) - eoi - 2,
                'preview': data[eoi+2:eoi+50].hex(),
            })
    elif data[:8] == b'\x89PNG\r\n\x1a\n':
        # PNG: IEND 청크 이후
        iend = data.rfind(b'IEND')
        if iend >= 0 and iend + 8 < len(data):
            r['findings'].append({
                'type': 'PNG IEND 이후 데이터',
                'offset': iend + 8,
                'size': len(data) - iend - 8,
                'preview': data[iend+8:iend+50].hex(),
            })
    # LSB 분석 (이미지만)
    try:
        from PIL import Image
        img = Image.open(io.BytesIO(data))
        if img.mode in ('RGB','RGBA','L'):
            pixels = list(img.getdata())
            lsbs = []
            for p in pixels[:10000]:
                if isinstance(p, int):
                    lsbs.append(p & 1)
                else:
                    for c in p[:3]:
                        lsbs.append(c & 1)
            # LSB 0/1 비율 (50%에서 멀면 평이한 이미지)
            ones = sum(lsbs)
            total = len(lsbs)
            ratio = ones / max(total, 1)
            r['lsb_analysis'] = {
                'ratio': round(ratio, 4),
                'sample_size': total,
                'verdict': ('정상 분포' if 0.45 < ratio < 0.55 else
                            'LSB 편향 — 스테가노그래피 의심'),
            }
            # LSB를 ASCII로 추출 시도
            if total >= 800:
                msg = ''
                for i in range(0, total - 8, 8):
                    byte = 0
                    for j in range(8):
                        byte = (byte << 1) | lsbs[i+j]
                    if 32 <= byte < 127:
                        msg += chr(byte)
                    elif byte == 0 and len(msg) > 5:
                        break
                    else:
                        msg = ''
                if len(msg) >= 10 and msg.isprintable():
                    r['lsb_message'] = msg[:200]
                    r['findings'].append({
                        'type': 'LSB ASCII 메시지 추정', 'offset': 0, 'size': len(msg),
                        'preview': msg[:80],
                    })
            # 이미지 메타데이터
            r['image_format'] = img.format
            r['image_size'] = f'{img.width}x{img.height}'
            r['image_mode'] = img.mode
    except Exception: pass
    # 헥스 더하기 추가 — 의심 매직바이트 (ZIP/RAR/PE 등이 데이터 내에 묻혀있는지)
    embedded = []
    for sig, label in [(b'PK\x03\x04','ZIP'),(b'Rar!','RAR'),(b'\x37\x7A\xBC\xAF','7Z'),
                       (b'MZ','PE'),(b'%PDF','PDF'),(b'\x1F\x8B','GZIP')]:
        idx = data.find(sig, 100)  # 첫 100바이트 이후
        while idx > 0:
            embedded.append({'sig': sig.hex(), 'label': label, 'offset': idx})
            idx = data.find(sig, idx + 1)
            if len(embedded) > 20: break
    r['embedded_signatures'] = embedded
    return r


@bp.route('/stego', methods=['GET','POST'])
def stego_tool():
    result = error = None
    if request.method == 'POST':
        f = request.files.get('file')
        if not f or not f.filename: error = '파일 필요'
        else:
            data = f.read()
            try:
                result = _detect_stego(data, f.filename)
            except Exception as e: error = str(e)
    return render_template('tools/stego.html', result=result, error=error)


# ============================================================
# /tools/qr — QR / 바코드 디코더
# ============================================================
@bp.route('/qr', methods=['GET','POST'])
def qr_tool():
    result = error = None
    if request.method == 'POST':
        f = request.files.get('file')
        if not f or not f.filename: error = '이미지 필요'
        else:
            data = f.read()
            try:
                # pyzbar 시도
                try:
                    from PIL import Image
                    from pyzbar.pyzbar import decode
                    img = Image.open(io.BytesIO(data))
                    decoded = decode(img)
                    result = {
                        'filename': f.filename, 'codes': [],
                        'image_size': f'{img.width}x{img.height}',
                    }
                    for c in decoded:
                        result['codes'].append({
                            'type': c.type,
                            'data': c.data.decode('utf-8', errors='replace'),
                            'rect': f'{c.rect.left},{c.rect.top} {c.rect.width}x{c.rect.height}',
                        })
                    if not result['codes']:
                        result['note'] = 'QR/바코드 미발견'
                except ImportError:
                    error = 'pyzbar 라이브러리가 설치되어 있지 않습니다 (libzbar 시스템 패키지 필요)'
            except Exception as e: error = str(e)
    return render_template('tools/qr.html', result=result, error=error)


# ============================================================
# /tools/ocr — 이미지 OCR
# ============================================================
@bp.route('/ocr', methods=['GET','POST'])
def ocr_tool():
    result = error = None
    if request.method == 'POST':
        f = request.files.get('file')
        lang = request.form.get('lang', 'eng+kor')
        if not f or not f.filename: error = '이미지 필요'
        else:
            data = f.read()
            try:
                from PIL import Image
                try:
                    import pytesseract
                    img = Image.open(io.BytesIO(data))
                    text = pytesseract.image_to_string(img, lang=lang)
                    result = {
                        'filename': f.filename,
                        'image_size': f'{img.width}x{img.height}',
                        'text': text,
                        'word_count': len(text.split()),
                        'char_count': len(text),
                    }
                except ImportError:
                    error = 'pytesseract 라이브러리 미설치 (tesseract 시스템 패키지 필요)'
                except Exception as e:
                    error = f'OCR 실패: {e}'
            except Exception as e: error = str(e)
    return render_template('tools/ocr.html', result=result, error=error)


# ============================================================
# /tools/whois — WHOIS / IP 지리정보
# ============================================================
def _whois_query(target: str) -> dict:
    """raw WHOIS 프로토콜 (포트 43)"""
    target = target.strip().lower()
    # IP 또는 도메인 자동 판별
    is_ip = bool(re.match(r'^\d+\.\d+\.\d+\.\d+$', target))
    if is_ip:
        # IP 분류
        octets = list(map(int, target.split('.')))
        # 사설 / 예약 / 공용 분류
        cls = '공용'
        if octets[0] == 10: cls = '사설 (RFC1918 10.0.0.0/8)'
        elif octets[0] == 172 and 16 <= octets[1] <= 31: cls = '사설 (RFC1918 172.16.0.0/12)'
        elif octets[0] == 192 and octets[1] == 168: cls = '사설 (RFC1918 192.168.0.0/16)'
        elif octets[0] == 127: cls = '루프백 (127.0.0.0/8)'
        elif octets[0] == 169 and octets[1] == 254: cls = 'Link-local (APIPA)'
        elif octets[0] >= 224 and octets[0] <= 239: cls = '멀티캐스트 (Class D)'
        elif octets[0] >= 240: cls = '예약 (Class E)'
        server = 'whois.arin.net' if octets[0] < 100 else \
                 'whois.ripe.net' if octets[0] in range(100, 130) else \
                 'whois.apnic.net' if octets[0] in range(130, 220) else \
                 'whois.arin.net'
    else:
        cls = '도메인'
        tld = target.split('.')[-1]
        server_map = {
            'com':'whois.verisign-grs.com', 'net':'whois.verisign-grs.com',
            'org':'whois.publicinterestregistry.org',
            'kr':'whois.kr', 'jp':'whois.jprs.jp', 'cn':'whois.cnnic.cn',
            'io':'whois.nic.io', 'co':'whois.nic.co',
        }
        server = server_map.get(tld, 'whois.iana.org')
    # WHOIS 쿼리
    raw = ''
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((server, 43))
        s.sendall(f'{target}\r\n'.encode())
        chunks = []
        while True:
            try:
                d = s.recv(4096)
            except socket.timeout: break
            if not d: break
            chunks.append(d)
        s.close()
        raw = b''.join(chunks).decode('utf-8', errors='replace')
    except Exception as e:
        raw = f'(WHOIS 서버 연결 실패: {e})'
    # 키 정보 추출
    extracted = {}
    for key, label in [('Registrar','registrar'),('Registry','registry'),
                       ('Creation Date','created'),('Created','created'),
                       ('Updated Date','updated'),('Expir','expires'),
                       ('Registrant','registrant'),('Country','country'),
                       ('OrgName','org'),('NetRange','net_range'),
                       ('CIDR','cidr'),('Name Server','ns'),
                       ('netname','net_name')]:
        for m in re.finditer(rf'{re.escape(key)}[^:]*:\s*(.+)', raw, re.IGNORECASE):
            v = m.group(1).strip()
            if v and not v.startswith('REDACTED'):
                extracted.setdefault(label, v[:200])
                break
    return {
        'target': target,
        'is_ip': is_ip,
        'classification': cls,
        'whois_server': server,
        'raw': raw[:8000],
        'extracted': extracted,
    }


@bp.route('/whois', methods=['GET','POST'])
def whois_tool():
    result = error = None
    if request.method == 'POST':
        target = (request.form.get('target') or '').strip()
        if not target: error = '도메인 또는 IP 입력'
        else:
            try: result = _whois_query(target)
            except Exception as e: error = str(e)
    return render_template('tools/whois.html', result=result, error=error)


# ============================================================
# /tools/passwd — 암호 강도 측정
# ============================================================
def _password_strength(pwd: str) -> dict:
    L = len(pwd)
    classes = 0
    has_lower = any(c.islower() for c in pwd); classes += has_lower
    has_upper = any(c.isupper() for c in pwd); classes += has_upper
    has_digit = any(c.isdigit() for c in pwd); classes += has_digit
    has_sym = any(not c.isalnum() and not c.isspace() for c in pwd); classes += has_sym
    # 엔트로피 추정
    pool = 0
    if has_lower: pool += 26
    if has_upper: pool += 26
    if has_digit: pool += 10
    if has_sym: pool += 32
    import math as _math
    bits = L * _math.log2(pool) if pool else 0
    # 크랙 시간 추정 (오프라인 10억 회/초)
    combinations = pool ** L if pool else 0
    seconds = combinations / 1e9
    def fmt_time(s):
        if s < 1: return '즉시'
        if s < 60: return f'{s:.1f}초'
        if s < 3600: return f'{s/60:.1f}분'
        if s < 86400: return f'{s/3600:.1f}시간'
        if s < 31536000: return f'{s/86400:.1f}일'
        if s < 31536000 * 1000: return f'{s/31536000:.1f}년'
        return f'{s/31536000:.2e}년'
    # 일반적 약점
    weakness = []
    common = ['password','123456','qwerty','admin','letmein','welcome',
              '12345678','1q2w3e','abc123','iloveyou','monkey','dragon']
    if pwd.lower() in common: weakness.append('일반 비밀번호 사전 매칭')
    if re.match(r'^\d+$', pwd): weakness.append('숫자만 사용')
    if re.match(r'^[a-zA-Z]+$', pwd): weakness.append('문자만 사용')
    if L < 8: weakness.append(f'길이 부족 ({L}자, 최소 8자 권장)')
    if re.search(r'(.)\1{2,}', pwd): weakness.append('동일 문자 3회 이상 반복')
    if re.search(r'(?:0123|1234|2345|3456|4567|5678|6789|abcd|qwer|asdf)', pwd.lower()):
        weakness.append('연속된 문자열 포함')
    # 등급
    if bits < 28: grade, color = '매우 약함', '#ef4444'
    elif bits < 36: grade, color = '약함', '#f59e0b'
    elif bits < 60: grade, color = '보통', '#3b82f6'
    elif bits < 80: grade, color = '강함', '#22c55e'
    else: grade, color = '매우 강함', '#10b981'
    return {
        'length': L, 'classes': classes,
        'has_lower': has_lower, 'has_upper': has_upper,
        'has_digit': has_digit, 'has_symbol': has_sym,
        'pool_size': pool, 'entropy_bits': round(bits, 2),
        'combinations': f'{combinations:.2e}' if combinations else '0',
        'crack_time_offline': fmt_time(seconds),
        'crack_time_online': fmt_time(seconds * 1e6),  # 1000 attempts/sec
        'grade': grade, 'grade_color': color,
        'weakness': weakness,
    }


@bp.route('/passwd', methods=['GET','POST'])
def passwd_tool():
    result = error = None
    pwd_input = ''
    if request.method == 'POST':
        pwd_input = request.form.get('password', '')
        if not pwd_input: error = '비밀번호 입력'
        else:
            result = _password_strength(pwd_input)
            result['masked'] = '*' * len(pwd_input)
    return render_template('tools/passwd.html', result=result, error=error)


# ============================================================
# /tools/git — Git 저장소 분석 (.git 디렉터리 ZIP)
# ============================================================
def _parse_git_object(content: bytes):
    """git object (zlib 압축 풀린 raw blob/tree/commit)"""
    null = content.find(b'\x00')
    if null < 0: return None
    header = content[:null].decode('latin1', errors='replace')
    typ, size = header.split(' ', 1)
    body = content[null+1:]
    return typ, int(size), body


def _analyze_git_zip(data: bytes) -> dict:
    result = {'objects': 0, 'commits': [], 'branches': [], 'tags': [],
              'config': '', 'logs': [], 'deleted_blobs': [], 'pack_files': []}
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
        names = zf.namelist()
        # .git/config
        for n in names:
            if n.endswith('.git/config') or n == 'config':
                result['config'] = zf.read(n).decode('utf-8', errors='replace')[:3000]
                break
        # HEAD, refs/heads, refs/tags
        for n in names:
            if '/refs/heads/' in n or n.endswith('refs/heads/master') or n.endswith('refs/heads/main'):
                branch = n.split('refs/heads/')[-1]
                try:
                    h = zf.read(n).decode('latin1').strip()
                    result['branches'].append({'name': branch, 'commit': h})
                except Exception: pass
            elif '/refs/tags/' in n:
                tag = n.split('refs/tags/')[-1]
                try:
                    h = zf.read(n).decode('latin1').strip()
                    result['tags'].append({'name': tag, 'commit': h})
                except Exception: pass
        # logs/HEAD — 모든 활동 이력
        for n in names:
            if n.endswith('logs/HEAD') or '/logs/refs/' in n:
                try:
                    log = zf.read(n).decode('utf-8', errors='replace')
                    for line in log.splitlines()[:100]:
                        result['logs'].append(line)
                except Exception: pass
        # objects 디렉터리
        obj_count = 0
        for n in names:
            if '/objects/' in n and not n.endswith('/'):
                # /xx/yyyy... 형식 — 압축된 객체
                m = re.search(r'/objects/([0-9a-f]{2})/([0-9a-f]{38})', n)
                if m:
                    obj_count += 1
                    if obj_count <= 50:
                        try:
                            blob = zf.read(n)
                            decomp = zlib.decompress(blob)
                            r = _parse_git_object(decomp)
                            if r:
                                typ, sz, body = r
                                sha = m.group(1) + m.group(2)
                                if typ == 'commit':
                                    body_str = body.decode('utf-8', errors='replace')
                                    author = re.search(r'author (.+)', body_str)
                                    msg = body_str.split('\n\n', 1)[-1][:200] if '\n\n' in body_str else ''
                                    result['commits'].append({
                                        'sha': sha, 'size': sz,
                                        'author': author.group(1) if author else '',
                                        'message': msg,
                                    })
                                elif typ == 'blob' and sz > 0:
                                    # 인쇄가능 텍스트 미리보기
                                    try:
                                        preview = body[:200].decode('utf-8', errors='replace')
                                        if all(c.isprintable() or c in '\n\t\r' for c in preview):
                                            result['deleted_blobs'].append({
                                                'sha': sha, 'size': sz,
                                                'preview': preview[:120],
                                            })
                                    except Exception: pass
                        except Exception: pass
            elif '/objects/pack/' in n and n.endswith('.pack'):
                result['pack_files'].append(n)
        result['objects'] = obj_count
        zf.close()
    except Exception as e:
        result['error'] = str(e)
    return result


@bp.route('/git', methods=['GET','POST'])
def git_tool():
    result = error = None; share_token = None
    if request.method == 'POST':
        f = request.files.get('file')
        if not f or not f.filename: error = '.git ZIP 파일 필요'
        else:
            data = f.read()
            try:
                result = _analyze_git_zip(data)
                result['filename'] = f.filename; result['file_size'] = len(data)
                share_token = _save_log('git','Git 저장소 분석', f.filename, len(data),
                    f"{result['objects']}개 객체 · {len(result['commits'])}개 커밋", result)
            except Exception as e: error = str(e)
    return render_template('tools/git.html', result=result, error=error,
                           share_token=share_token)
