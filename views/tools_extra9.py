"""ForensicLab 9차 확장 — 암호화 해제 (Decryption / Unlock) 통합 도구

/tools/unlock — 암호화된 볼륨·문서를 복호화하여 내부 파일을 추출.

지원 포맷
  · BitLocker (Windows)      — dislocker-file (복구키 48자리 / 사용자암호 / BEK)
  · LUKS1 / LUKS2 (Linux)    — losetup + cryptsetup open
  · VeraCrypt / TrueCrypt    — cryptsetup open --type tcrypt --veracrypt
  · 암호 ZIP                  — pyzipper(AES) / zipfile(ZipCrypto)
  · 암호 Office (97~2016)     — msoffcrypto-tool
  · 암호 PDF                  — pypdf

두 가지 동작
  · unlock  : 암호/키를 알 때 → 복호화 + 파일 목록/다운로드
  · crack   : 암호를 모를 때 → 사전 공격
              - 문서(zip/office/pdf): 순수 파이썬 사전 대입
              - 볼륨(bitlocker/luks/veracrypt): *2john 해시 추출 → john 크래킹

복호화된 볼륨은 커널 마운트 없이 pytsk3로 직접 파싱한다.
"""
import os
import io
import re
import uuid
import time
import shutil
import zipfile
import datetime as _dt
import subprocess
import threading
from pathlib import Path

from flask import request, render_template, jsonify, send_file, abort

from hospital.views.tools import bp, _save_log
from hospital.views.tools_extra5 import _new_job, _job_log, _coc_record


# ════════════════════════════════════════════════════════════════════
# 작업 디렉터리 / 아티팩트 저장소
# ════════════════════════════════════════════════════════════════════
_UNLOCK_DIR = Path('/tmp/forensiclab_unlock')
_UNLOCK_DIR.mkdir(exist_ok=True)

# token -> {'created': ts, 'image': path, 'kind': str, 'cleanup': callable}
_SESS = {}
_SESS_LOCK = threading.Lock()
_SESS_TTL = 1800  # 30분


def _new_sess():
    token = uuid.uuid4().hex[:16]
    d = _UNLOCK_DIR / token
    d.mkdir(parents=True, exist_ok=True)
    with _SESS_LOCK:
        _SESS[token] = {'created': time.time(), 'dir': str(d)}
    _gc_sessions()
    return token, str(d)


def _gc_sessions():
    now = time.time()
    dead = [t for t, s in list(_SESS.items()) if now - s['created'] > _SESS_TTL]
    for t in dead:
        s = _SESS.pop(t, None)
        if not s:
            continue
        try:
            for fn in s.get('on_clean', []):
                try:
                    fn()
                except Exception:
                    pass
            shutil.rmtree(s['dir'], ignore_errors=True)
        except Exception:
            pass


# ════════════════════════════════════════════════════════════════════
# 포맷 탐지
# ════════════════════════════════════════════════════════════════════
def _detect_crypto(head: bytes, name: str) -> dict:
    name_l = (name or '').lower()
    if len(head) >= 11 and head[3:11] == b'-FVE-FS-':
        return {'type': 'bitlocker', 'label': 'BitLocker 암호화 볼륨', 'family': 'volume'}
    if b'-FVE-FS-' in head[:1024]:
        return {'type': 'bitlocker', 'label': 'BitLocker 암호화 볼륨', 'family': 'volume'}
    # BitLocker To Go (FAT OEM 'MSWIN4.1') — 부트섹터의 BitLocker 식별 GUID
    #   {4967D63B-2E29-4AD8-8399-F6A339E3D001} (혼합 엔디안 바이트열)
    if b'\x3b\xd6\x67\x49\x29\x2e\xd8\x4a\x83\x99\xf6\xa3\x39\xe3\xd0\x01' in head[:512]:
        return {'type': 'bitlocker', 'label': 'BitLocker To Go 볼륨', 'family': 'volume'}
    # libbde 시그니처 검사 (가장 권위 있는 판정)
    try:
        import pybde
        import io as _io
        if pybde.check_volume_signature_file_object(_io.BytesIO(head)):
            return {'type': 'bitlocker', 'label': 'BitLocker 암호화 볼륨', 'family': 'volume'}
    except Exception:
        pass
    if head[:6] == b'LUKS\xba\xbe':
        ver = int.from_bytes(head[6:8], 'big') if len(head) >= 8 else 1
        return {'type': 'luks', 'label': f'LUKS{ver} 암호화 볼륨', 'family': 'volume'}
    if head[:4] in (b'PK\x03\x04', b'PK\x05\x06', b'PK\x07\x08'):
        # docx/xlsx/pptx 도 PK지만 OOXML 암호화는 OLE로 저장됨 → 여긴 일반 ZIP
        return {'type': 'zip', 'label': 'ZIP 아카이브', 'family': 'archive'}
    if head[:8] == b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1':
        return {'type': 'office', 'label': 'MS Office (OLE / 암호화 OOXML 컨테이너)', 'family': 'document'}
    if head[:5] == b'%PDF-':
        return {'type': 'pdf', 'label': 'PDF 문서', 'family': 'document'}
    if name_l.endswith(('.hc', '.tc', '.vc')):
        return {'type': 'veracrypt', 'label': 'VeraCrypt/TrueCrypt 컨테이너 (확장자 추정)', 'family': 'volume'}
    # 시그니처 없음: VeraCrypt/TrueCrypt 는 의도적으로 매직이 없음
    return {'type': 'veracrypt', 'label': '시그니처 없음 — VeraCrypt/TrueCrypt 가능성', 'family': 'volume',
            'guess': True}


def _which(*names):
    """PATH + john 공통 설치 경로에서 실행파일 탐색"""
    search_dirs = ['/usr/sbin', '/usr/bin', '/usr/local/bin',
                   '/usr/share/john', '/usr/lib/john', '/opt/john/run']
    for n in names:
        p = shutil.which(n)
        if p:
            return p
        for d in search_dirs:
            cand = os.path.join(d, n)
            if os.path.exists(cand):
                return cand
    return None


# ════════════════════════════════════════════════════════════════════
# pytsk3 — 복호화된 이미지/블록장치 파일 목록
# ════════════════════════════════════════════════════════════════════
def _tsk_list(target: str, limit: int = 3000) -> dict:
    out = {'files': [], 'fs': None, 'partitions': None, 'total': 0}
    try:
        import pytsk3
    except ImportError:
        out['error'] = 'pytsk3 미설치'
        return out
    try:
        img = pytsk3.Img_Info(target)
    except Exception as e:
        out['error'] = f'이미지 열기 실패: {e}'
        return out

    fs = None
    try:
        fs = pytsk3.FS_Info(img)
    except Exception:
        try:
            vol = pytsk3.Volume_Info(img)
            parts = []
            for part in vol:
                desc = part.desc.decode('latin1', 'replace') if isinstance(part.desc, bytes) else str(part.desc)
                parts.append({'addr': part.addr, 'desc': desc,
                              'start': part.start, 'len': part.len})
                if fs is None and part.len > 4 and 'Unallocated' not in desc:
                    try:
                        fs = pytsk3.FS_Info(img, offset=part.start * 512)
                    except Exception:
                        pass
            out['partitions'] = parts
        except Exception as e:
            out['error'] = f'파일시스템 인식 실패: {e}'
            return out

    if fs is None:
        return out

    out['fs'] = str(fs.info.ftype)
    files = []

    def walk(path, depth=0):
        if depth > 6 or len(files) >= limit:
            return
        try:
            directory = fs.open_dir(path=path)
        except Exception:
            return
        for entry in directory:
            if len(files) >= limit:
                break
            nm = entry.info.name.name
            if not nm:
                continue
            nm = nm.decode('utf-8', 'replace')
            if nm in ('.', '..'):
                continue
            meta = entry.info.meta
            ftype = '?'
            try:
                if meta:
                    ftype = {1: '파일', 2: '디렉터리', 5: '링크'}.get(int(meta.type), '?')
            except Exception:
                pass
            full = (path.rstrip('/') + '/' + nm) if path != '/' else '/' + nm
            files.append({
                'name': nm, 'path': full, 'type': ftype,
                'size': meta.size if meta else 0,
                'mtime': _dt.datetime.utcfromtimestamp(meta.mtime).isoformat()
                if meta and meta.mtime else '',
            })
            if ftype == '디렉터리' and depth < 6 and len(files) < limit:
                walk(full, depth + 1)

    walk('/')
    out['files'] = files
    out['total'] = len(files)
    return out


def _tsk_extract(target: str, path: str) -> bytes:
    import pytsk3
    img = pytsk3.Img_Info(target)
    try:
        fs = pytsk3.FS_Info(img)
    except Exception:
        vol = pytsk3.Volume_Info(img)
        fs = None
        for part in vol:
            desc = part.desc.decode('latin1', 'replace') if isinstance(part.desc, bytes) else str(part.desc)
            if part.len > 4 and 'Unallocated' not in desc:
                try:
                    fs = pytsk3.FS_Info(img, offset=part.start * 512)
                    break
                except Exception:
                    pass
        if fs is None:
            raise RuntimeError('파일시스템 없음')
    f = fs.open(path)
    size = f.info.meta.size
    return f.read_random(0, size) if size else b''


# ════════════════════════════════════════════════════════════════════
# 볼륨 복호화 — BitLocker
# ════════════════════════════════════════════════════════════════════
def _bde_apply_credential(v, cred_type: str, cred: str):
    """pybde 볼륨에 자격증명 적용"""
    if cred_type == 'recovery':
        v.set_recovery_password(cred)
    elif cred_type == 'bek':
        v.read_startup_key(cred)        # cred = .bek 파일 경로
    else:                                # password / fvek 폴백
        v.set_password(cred)


def _unlock_bitlocker(img_path: str, cred_type: str, cred: str, workdir: str) -> dict:
    # 1순위: pybde(libbde) — in-process, FUSE 불필요, BitLocker To Go 포함 폭넓게 지원
    try:
        import pybde
        v = pybde.volume()
        _bde_apply_credential(v, cred_type, cred)
        v.open(img_path)
        if v.is_locked():
            try:
                v.close()
            except Exception:
                pass
            return {'ok': False, 'error': '자격증명 불일치 — 잠금 해제 실패'}
        size = v.get_size()
        out_img = os.path.join(workdir, 'decrypted.img')
        with open(out_img, 'wb') as f:
            v.seek_offset(0, 0)
            rem = size
            while rem > 0:
                chunk = v.read_buffer(min(8 * 1024 * 1024, rem))
                if not chunk:
                    break
                f.write(chunk)
                rem -= len(chunk)
        try:
            v.close()
        except Exception:
            pass
        return {'ok': True, 'image': out_img, 'size': size, 'engine': 'libbde'}
    except ImportError:
        pass
    except Exception as e:
        # pybde 실패 시 dislocker 폴백 시도
        bde_err = str(e)
    else:
        bde_err = None

    # 2순위: dislocker-file 폴백
    if not _which('dislocker-file'):
        return {'ok': False, 'error': 'BitLocker 복호화 실패 (libbde 오류, dislocker 미설치)'}
    out_img = os.path.join(workdir, 'decrypted.ntfs')
    flag = {'recovery': '-p', 'password': '-u', 'bek': '-f', 'fvek': '-K'}.get(cred_type, '-p')
    cmd = ['dislocker-file', '-V', img_path, flag + cred, '--', out_img]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=900)
    except subprocess.TimeoutExpired:
        return {'ok': False, 'error': 'dislocker 시간 초과(15분)'}
    if p.returncode != 0 or not os.path.exists(out_img):
        return {'ok': False, 'error': (p.stderr or p.stdout or '복호화 실패')[-1800:],
                'cmd': 'dislocker-file -V <img> %s*** -- decrypted.ntfs' % flag}
    return {'ok': True, 'image': out_img, 'engine': 'dislocker'}


# ════════════════════════════════════════════════════════════════════
# 볼륨 복호화 — LUKS / VeraCrypt (cryptsetup + losetup)
# ════════════════════════════════════════════════════════════════════
def _losetup_attach(img_path: str) -> str:
    p = subprocess.run(['losetup', '--find', '--show', img_path],
                       capture_output=True, text=True, timeout=60)
    if p.returncode != 0:
        raise RuntimeError('losetup 실패: ' + (p.stderr or ''))
    return p.stdout.strip()


def _unlock_cryptsetup(img_path: str, password: str, *, kind: str, workdir: str) -> dict:
    if not _which('cryptsetup'):
        return {'ok': False, 'error': 'cryptsetup 미설치'}
    name = 'fl_' + uuid.uuid4().hex[:10]
    loop = None
    try:
        loop = _losetup_attach(img_path)
        if kind == 'veracrypt':
            cmd = ['cryptsetup', 'open', '--type', 'tcrypt', '--veracrypt', loop, name]
        else:
            cmd = ['cryptsetup', 'open', '--type', 'luks', loop, name]
        p = subprocess.run(cmd, input=(password or '') + '\n',
                           capture_output=True, text=True, timeout=180)
        if p.returncode != 0:
            _detach(loop)
            return {'ok': False, 'error': (p.stderr or '암호 불일치/헤더 인식 실패')[-1800:], 'loop': None}
        mapper = '/dev/mapper/' + name
        # 커널 마운트 없이 매퍼 장치를 그대로 이미지로 사용 가능 크기 산정 후
        # 작은 볼륨은 파일로 떠서 세션에 보관(추출용), 큰 볼륨은 매퍼 유지
        size = 0
        try:
            size = int(subprocess.run(['blockdev', '--getsize64', mapper],
                                      capture_output=True, text=True, timeout=30).stdout.strip() or 0)
        except Exception:
            pass
        if 0 < size <= 1_073_741_824:  # 1GB 이하면 파일로 복사 후 정리
            out_img = os.path.join(workdir, 'decrypted.img')
            subprocess.run(['dd', f'if={mapper}', f'of={out_img}', 'bs=4M'],
                           capture_output=True, timeout=600)
            _close_mapper(name)
            _detach(loop)
            return {'ok': True, 'image': out_img, 'size': size}
        # 큰 볼륨: 매퍼 유지 (세션 정리 시 닫음)
        return {'ok': True, 'image': mapper, 'size': size, 'mapper': name, 'loop': loop}
    except Exception as e:
        if loop:
            _detach(loop)
        return {'ok': False, 'error': str(e)}


def _close_mapper(name):
    try:
        subprocess.run(['cryptsetup', 'close', name], capture_output=True, timeout=60)
    except Exception:
        pass


def _detach(loop):
    try:
        subprocess.run(['losetup', '-d', loop], capture_output=True, timeout=60)
    except Exception:
        pass


# ════════════════════════════════════════════════════════════════════
# 문서 복호화 — ZIP
# ════════════════════════════════════════════════════════════════════
def _zip_open(data: bytes):
    bio = io.BytesIO(data)
    try:
        import pyzipper
        return pyzipper.AESZipFile(bio)
    except ImportError:
        return zipfile.ZipFile(bio)
    except Exception:
        bio.seek(0)
        return zipfile.ZipFile(bio)


def _zip_encrypted_entries(z):
    enc = []
    for zi in z.infolist():
        if zi.is_dir():
            continue
        if zi.flag_bits & 0x1:
            enc.append(zi)
    return enc


def _zip_try_password(data: bytes, pw: str) -> bool:
    try:
        z = _zip_open(data)
    except Exception:
        return False
    enc = _zip_encrypted_entries(z)
    targets = enc or [zi for zi in z.infolist() if not zi.is_dir()]
    if not targets:
        return False
    targets.sort(key=lambda zi: zi.file_size)
    try:
        z.setpassword(pw.encode('utf-8', 'replace'))
        with z.open(targets[0]) as fh:
            fh.read()  # CRC/HMAC 검증까지 완료
        return True
    except (RuntimeError, zipfile.BadZipFile, Exception):
        return False


def _unlock_zip(data: bytes, pw: str, workdir: str) -> dict:
    z = _zip_open(data)
    enc = _zip_encrypted_entries(z)
    if not enc:
        info = {'ok': True, 'encrypted': False,
                'entries': [{'name': zi.filename, 'size': zi.file_size} for zi in z.infolist()[:500]]}
        return info
    if not _zip_try_password(data, pw):
        return {'ok': False, 'error': '암호 불일치'}
    # 평문 ZIP 으로 재패키징
    out_zip = os.path.join(workdir, 'decrypted.zip')
    z = _zip_open(data)
    z.setpassword(pw.encode('utf-8', 'replace'))
    entries = []
    with zipfile.ZipFile(out_zip, 'w', zipfile.ZIP_DEFLATED) as zo:
        for zi in z.infolist():
            if zi.is_dir():
                continue
            try:
                content = z.read(zi.filename)
            except Exception:
                content = b''
            zo.writestr(zi.filename, content)
            entries.append({'name': zi.filename, 'size': zi.file_size})
    return {'ok': True, 'encrypted': True, 'download': 'decrypted.zip',
            'entries': entries[:500], 'count': len(entries)}


# ════════════════════════════════════════════════════════════════════
# 문서 복호화 — Office / PDF
# ════════════════════════════════════════════════════════════════════
def _office_try_password(data: bytes, pw: str) -> bool:
    try:
        import msoffcrypto
        off = msoffcrypto.OfficeFile(io.BytesIO(data))
        if not off.is_encrypted():
            return True
        off.load_key(password=pw)
        off.decrypt(io.BytesIO())
        return True
    except Exception:
        return False


def _unlock_office(data: bytes, pw: str, workdir: str) -> dict:
    try:
        import msoffcrypto
    except ImportError:
        return {'ok': False, 'error': 'msoffcrypto-tool 미설치'}
    off = msoffcrypto.OfficeFile(io.BytesIO(data))
    if not off.is_encrypted():
        return {'ok': True, 'encrypted': False}
    try:
        off.load_key(password=pw)
        out_path = os.path.join(workdir, 'decrypted.office')
        with open(out_path, 'wb') as fo:
            off.decrypt(fo)
    except Exception as e:
        return {'ok': False, 'error': '암호 불일치 (%s)' % type(e).__name__}
    return {'ok': True, 'encrypted': True, 'download': 'decrypted.office',
            'size': os.path.getsize(out_path)}


def _pdf_try_password(data: bytes, pw: str) -> bool:
    try:
        import pypdf
        r = pypdf.PdfReader(io.BytesIO(data))
        if not r.is_encrypted:
            return True
        return r.decrypt(pw) != 0
    except Exception:
        return False


def _unlock_pdf(data: bytes, pw: str, workdir: str) -> dict:
    try:
        import pypdf
    except ImportError:
        return {'ok': False, 'error': 'pypdf 미설치'}
    r = pypdf.PdfReader(io.BytesIO(data))
    if not r.is_encrypted:
        return {'ok': True, 'encrypted': False, 'pages': len(r.pages)}
    if r.decrypt(pw) == 0:
        return {'ok': False, 'error': '암호 불일치'}
    out_path = os.path.join(workdir, 'decrypted.pdf')
    w = pypdf.PdfWriter()
    for p in r.pages:
        w.add_page(p)
    with open(out_path, 'wb') as fo:
        w.write(fo)
    return {'ok': True, 'encrypted': True, 'download': 'decrypted.pdf',
            'pages': len(r.pages), 'size': os.path.getsize(out_path)}


_DOC_TRY = {'zip': _zip_try_password, 'office': _office_try_password, 'pdf': _pdf_try_password}

# 사전 최대 후보 수 (메모리 보호 — rockyou 등 초대형 파일 방어)
_MAX_WORDS = 5_000_000


def _build_wordlist(text: str, upload) -> dict:
    """textarea 텍스트 + 업로드 사전 파일을 합쳐 후보 목록 생성 (순서 보존·중복 제거)"""
    seen = set()
    words = []
    truncated = False

    def add(w):
        nonlocal truncated
        if not w:
            return
        if len(words) >= _MAX_WORDS:
            truncated = True
            return
        if w not in seen:
            seen.add(w)
            words.append(w)

    # 1) textarea (분석가가 직접 입력한 우선 후보)
    for line in re.split(r'[\r\n]+', text or ''):
        add(line.strip())

    # 2) 업로드 사전 파일 (대형 공개 사전 등) — 바이트 단위로 라인 분할
    if upload is not None and getattr(upload, 'filename', ''):
        raw = upload.read()
        for line in raw.split(b'\n'):
            if len(words) >= _MAX_WORDS:
                truncated = True
                break
            line = line.rstrip(b'\r')
            if not line:
                continue
            try:
                w = line.decode('utf-8')
            except UnicodeDecodeError:
                w = line.decode('latin1', 'replace')  # rockyou 등 비 UTF-8 사전 대응
            add(w)

    return {'words': words, 'truncated': truncated}


# ════════════════════════════════════════════════════════════════════
# 크래킹 — 문서 (순수 파이썬 사전 대입)
# ════════════════════════════════════════════════════════════════════
def _doc_crack_job(kind: str, data: bytes, words: list, _job_id=None) -> dict:
    tryfn = _DOC_TRY[kind]
    total = len(words)
    _job_log(_job_id, f'{kind.upper()} 사전 공격 시작 — 후보 {total}개', 2)
    step = max(1, total // 200)
    for i, pw in enumerate(words):
        if i % step == 0:
            _job_log(_job_id, f'[{i}/{total}] 시도 중: {pw[:24]}', min(99, int(i / max(total, 1) * 100)))
        if tryfn(data, pw):
            _job_log(_job_id, f'✅ 비밀번호 발견: {pw}', 100)
            return {'found': True, 'password': pw, 'tried': i + 1, 'total': total}
    _job_log(_job_id, f'❌ {total}개 모두 실패', 100)
    return {'found': False, 'tried': total, 'total': total}


# ════════════════════════════════════════════════════════════════════
# 크래킹 — 볼륨 (외부 추출기 없이 cryptsetup/dislocker 직접 시도)
#   · LUKS/VeraCrypt : cryptsetup --test-passphrase (정답 rc=0 / 오답 rc≠0)
#   · BitLocker      : dislocker-fuse 마운트 테스트 (VMK 검증, 전체복호화 불필요)
# ════════════════════════════════════════════════════════════════════
def _cs_test_passphrase(dev: str, pw: str, *, veracrypt: bool) -> bool:
    cmd = ['cryptsetup', 'open', '--test-passphrase']
    if veracrypt:
        cmd += ['--type', 'tcrypt', '--veracrypt']
    else:
        cmd += ['--type', 'luks']
    cmd += [dev]
    try:
        p = subprocess.run(cmd, input=(pw or '') + '\n',
                           capture_output=True, text=True, timeout=180)
        return p.returncode == 0
    except Exception:
        return False


def _bl_test_password(img_path: str, pw: str, cred_type: str = 'password') -> bool:
    """pybde 로 암호 후보 1건 검증 (키 유도만 — 전체 복호화 없이 빠름)"""
    try:
        import pybde
    except ImportError:
        raise RuntimeError('libbde(pybde) 미설치 — BitLocker 크래킹 불가')
    v = pybde.volume()
    try:
        if cred_type == 'recovery':
            v.set_recovery_password(pw)
        else:
            v.set_password(pw)
        v.open(img_path)
        locked = v.is_locked()
        return not locked
    except Exception:
        return False
    finally:
        try:
            v.close()
        except Exception:
            pass


def _vol_crack_job(kind: str, img_path: str, words: list,
                   cred_type: str = 'password', _job_id=None) -> dict:
    total = len(words)
    _job_log(_job_id, f'{kind.upper()} 사전 공격 시작 — 후보 {total}개', 3)
    step = max(1, total // 100)
    if kind in ('luks', 'veracrypt'):
        if not _which('cryptsetup'):
            return {'error': 'cryptsetup 미설치'}
        try:
            loop = _losetup_attach(img_path)
        except Exception as e:
            return {'error': str(e)}
        try:
            for i, pw in enumerate(words):
                if i % step == 0:
                    _job_log(_job_id, f'[{i}/{total}] 시도 중: {pw[:24]}',
                             min(99, int(i / max(total, 1) * 100)))
                if _cs_test_passphrase(loop, pw, veracrypt=(kind == 'veracrypt')):
                    _job_log(_job_id, f'✅ 비밀번호 발견: {pw}', 100)
                    return {'found': True, 'password': pw, 'tried': i + 1, 'total': total}
        finally:
            _detach(loop)
        _job_log(_job_id, f'❌ {total}개 모두 실패', 100)
        return {'found': False, 'tried': total, 'total': total}

    elif kind == 'bitlocker':
        try:
            for i, pw in enumerate(words):
                if i % step == 0:
                    _job_log(_job_id, f'[{i}/{total}] 시도 중: {pw[:24]}',
                             min(99, int(i / max(total, 1) * 100)))
                if _bl_test_password(img_path, pw, cred_type):
                    _job_log(_job_id, f'✅ 비밀번호 발견: {pw}', 100)
                    return {'found': True, 'password': pw, 'tried': i + 1, 'total': total}
        except RuntimeError as e:
            return {'error': str(e)}
        _job_log(_job_id, f'❌ {total}개 모두 실패', 100)
        return {'found': False, 'tried': total, 'total': total}

    return {'error': f'크래킹 미지원 볼륨: {kind}'}


# ════════════════════════════════════════════════════════════════════
# 메인 라우트
# ════════════════════════════════════════════════════════════════════
_VOLUME_TYPES = ('bitlocker', 'luks', 'veracrypt')
_DOC_TYPES = ('zip', 'office', 'pdf')


@bp.route('/unlock', methods=['GET', 'POST'])
def unlock_tool():
    result = error = job = None
    detected = None
    if request.method == 'POST':
        f = request.files.get('file')
        op = request.form.get('op', 'unlock')
        fmt = request.form.get('fmt', 'auto')
        cred_type = request.form.get('cred_type', 'password')
        password = request.form.get('password', '')
        bekfile = request.files.get('bekfile')
        wordlist_text = request.form.get('wordlist', '')
        wordlist_file = request.files.get('wordlist_file')

        if not f or not f.filename:
            error = '암호화된 파일을 업로드하세요.'
        else:
            data = f.read()
            head = data[:2048]
            det = _detect_crypto(head, f.filename)
            detected = det
            kind = det['type'] if fmt == 'auto' else fmt
            import hashlib
            dhash = hashlib.sha256(data).hexdigest()
            _coc_record('unlock_intake', dhash,
                        {'filename': f.filename, 'size': len(data), 'detected': kind, 'op': op})

            token, workdir = _new_sess()

            # ── 크래킹 (암호 모름) ──
            if op == 'crack':
                wl = _build_wordlist(wordlist_text, wordlist_file)
                words = wl['words']
                if not words:
                    error = '사전(후보 비밀번호 목록)을 입력하거나 사전 파일을 업로드하세요.'
                elif kind in _DOC_TYPES:
                    job_id = _new_job(f'Unlock-crack {kind}: {f.filename} (후보 {len(words)})',
                                      _doc_crack_job, kind, data, words)
                    job = {'job_id': job_id, 'redirect': f'/tools/jobs/{job_id}',
                           'words': len(words), 'truncated': wl['truncated']}
                elif kind in _VOLUME_TYPES:
                    img_path = os.path.join(workdir, 'volume.img')
                    with open(img_path, 'wb') as fo:
                        fo.write(data)
                    job_id = _new_job(f'Unlock-crack {kind}: {f.filename} (후보 {len(words)})',
                                      _vol_crack_job, kind, img_path, words, cred_type)
                    job = {'job_id': job_id, 'redirect': f'/tools/jobs/{job_id}',
                           'words': len(words), 'truncated': wl['truncated']}
                else:
                    error = f'크래킹 미지원 포맷: {kind}'

            # ── 복호화 (암호 알고 있음) ──
            else:
                try:
                    if kind == 'zip':
                        result = _unlock_zip(data, password, workdir)
                    elif kind == 'office':
                        result = _unlock_office(data, password, workdir)
                    elif kind == 'pdf':
                        result = _unlock_pdf(data, password, workdir)
                    elif kind in _VOLUME_TYPES:
                        img_path = os.path.join(workdir, 'volume.img')
                        with open(img_path, 'wb') as fo:
                            fo.write(data)
                        if kind == 'bitlocker':
                            cred = password
                            if cred_type == 'bek' and bekfile and bekfile.filename:
                                bp_path = os.path.join(workdir, 'key.bek')
                                bekfile.save(bp_path)
                                cred = bp_path
                            r = _unlock_bitlocker(img_path, cred_type, cred, workdir)
                        else:
                            r = _unlock_cryptsetup(img_path, password, kind=kind, workdir=workdir)
                        if not r.get('ok'):
                            result = r
                        else:
                            # 매퍼 유지 시 세션 정리 등록
                            if r.get('mapper'):
                                mn, lp = r['mapper'], r.get('loop')
                                with _SESS_LOCK:
                                    _SESS[token]['on_clean'] = [
                                        lambda mn=mn: _close_mapper(mn),
                                        lambda lp=lp: _detach(lp) if lp else None,
                                    ]
                            listing = _tsk_list(r['image'])
                            with _SESS_LOCK:
                                _SESS[token]['image'] = r['image']
                                _SESS[token]['kind'] = kind
                            result = {'ok': True, 'family': 'volume', 'token': token,
                                      'fs': listing.get('fs'), 'partitions': listing.get('partitions'),
                                      'files': listing.get('files', []), 'total': listing.get('total', 0),
                                      'list_error': listing.get('error'),
                                      'image_size': r.get('size')}
                    else:
                        error = f'미지원 포맷: {kind}'
                    if result and result.get('ok') and result.get('download'):
                        with _SESS_LOCK:
                            _SESS[token]['download'] = result['download']
                        result['token'] = token
                except Exception as e:
                    error = f'복호화 오류: {e}'

            if result and isinstance(result, dict) and result.get('ok'):
                _save_log('unlock', '암호화 해제', f.filename, len(data),
                          f"{det['label']} 복호화 성공", {'kind': kind})

    return render_template('tools/unlock.html', result=result, error=error,
                           job=job, detected=detected)


@bp.route('/unlock/download/<token>')
def unlock_download(token):
    with _SESS_LOCK:
        s = _SESS.get(token)
    if not s or 'download' not in s:
        abort(404)
    fp = os.path.join(s['dir'], s['download'])
    if not os.path.exists(fp):
        abort(404)
    names = {'decrypted.zip': 'decrypted.zip', 'decrypted.pdf': 'decrypted.pdf',
             'decrypted.office': 'decrypted_office'}
    return send_file(fp, as_attachment=True, download_name=names.get(s['download'], 'decrypted.bin'))


@bp.route('/unlock/file/<token>')
def unlock_extract_file(token):
    path = request.args.get('path', '')
    with _SESS_LOCK:
        s = _SESS.get(token)
    if not s or 'image' not in s or not path:
        abort(404)
    try:
        content = _tsk_extract(s['image'], path)
    except Exception as e:
        return jsonify({'error': str(e)}), 400
    name = path.rstrip('/').split('/')[-1] or 'file'
    return send_file(io.BytesIO(content), as_attachment=True, download_name=name)


# ════════════════════════════════════════════════════════════════════
# 도움말 등록
# ════════════════════════════════════════════════════════════════════
try:
    from hospital.views.tools_extra7 import _TOOL_HELP
    _TOOL_HELP['unlock'] = {
        'what': '암호화 볼륨·문서를 복호화 — BitLocker·LUKS·VeraCrypt·암호 ZIP/Office/PDF.',
        'how': '1) 파일 업로드 → 2) 포맷 자동탐지 → 3) [암호 알 때] 암호/복구키 입력 후 복호화 '
               '/ [암호 모를 때] 사전 파일 업로드(또는 직접 입력) 후 크래킹',
        'input': 'BitLocker 볼륨·LUKS/VeraCrypt 컨테이너·암호 ZIP/Office/PDF / 사전: rockyou·SecLists 등 .txt',
        'output': '볼륨: 파일 트리 + 개별 추출 / 문서: 복호화 파일 다운로드 / 크래킹: 복구된 비밀번호',
        'tips': 'BitLocker 복구키는 48자리(6자리×8). 크래킹 엔진 — 문서는 순수 파이썬(~500/s), '
                'LUKS/VeraCrypt는 cryptsetup, BitLocker는 libbde(~3초/시도로 느려 소규모 타깃 사전 권장). '
                '사전은 파일+직접입력 합쳐 중복 제거. 복호화 산출물은 30분 후 자동 삭제.',
    }
except Exception:
    pass
