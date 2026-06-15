"""
ForensicLab 확장 분석 도구
- /tools/pe       PE/ELF/Mach-O 헤더 분석
- /tools/entropy  엔트로피·시그니처
- /tools/decode   다중 암호 디코더
- /tools/prefetch Windows .pf 파서
- /tools/lnk      LNK 바로가기 파서
- /tools/diskimg  디스크 이미지 헤더 인식
- /tools/scripts  로컬 스크립트 다운로드 허브
"""
import os
import re
import math
import struct
import datetime as _dt
from collections import Counter
from flask import request, render_template, send_from_directory, abort

from monitor.views.tools import bp, _save_log


# ============================================================
# 공용
# ============================================================
def _shannon_entropy(data: bytes) -> float:
    if not data: return 0.0
    counts = Counter(data); L = len(data)
    return -sum((c/L) * math.log2(c/L) for c in counts.values())


def _ft2str(ft: int) -> str:
    if ft == 0: return '-'
    try:
        return (_dt.datetime(1601,1,1,tzinfo=_dt.timezone.utc)
                + _dt.timedelta(microseconds=ft//10)).strftime('%Y-%m-%d %H:%M:%S UTC')
    except Exception:
        return f'(잘못된값 {ft})'


# ============================================================
# PE / ELF / Mach-O
# ============================================================
def _parse_pe(data: bytes) -> dict:
    if len(data) < 0x40 or data[:2] != b'MZ': return None
    try:
        pe_off = struct.unpack('<I', data[0x3C:0x40])[0]
        if pe_off + 24 > len(data) or data[pe_off:pe_off+4] != b'PE\x00\x00': return None
        machine, num_sect, ts, _ptbl, _nsym, opt_size, char = struct.unpack(
            '<HHIIIHH', data[pe_off+4:pe_off+24])
    except Exception:
        return None
    MACHINE = {0x014c:'x86 (32-bit)',0x8664:'x64 (AMD64)',0xaa64:'ARM64',
               0x01c0:'ARM',0x01c4:'ARMv7',0x0200:'IA-64',0x5032:'RISC-V 32',0x5064:'RISC-V 64'}
    chars = []
    for bit, name in [(0x0001,'NO_RELOC'),(0x0002,'EXECUTABLE'),(0x0020,'LARGE_ADDR'),
                      (0x0100,'32BIT'),(0x0200,'NO_DEBUG'),(0x1000,'SYSTEM'),(0x2000,'DLL')]:
        if char & bit: chars.append(name)
    opt_off = pe_off + 24
    magic = struct.unpack('<H', data[opt_off:opt_off+2])[0] if opt_off+2 <= len(data) else 0
    is_64 = (magic == 0x20b)
    subsys_off = opt_off + 0x44
    try:
        subsystem = struct.unpack('<H', data[subsys_off:subsys_off+2])[0]
    except Exception:
        subsystem = 0
    SUBSYS = {1:'NATIVE (드라이버)',2:'WINDOWS_GUI',3:'WINDOWS_CUI (콘솔)',5:'OS/2_CUI',
              7:'POSIX_CUI',9:'WINCE_GUI',10:'EFI_APP',11:'EFI_BOOT_DRV',
              12:'EFI_RUNTIME_DRV',13:'EFI_ROM',14:'XBOX',16:'WINBOOT_APP'}
    sect_off = opt_off + opt_size
    sections = []
    for i in range(min(num_sect, 32)):
        s_off = sect_off + i*40
        if s_off + 40 > len(data): break
        try:
            name = data[s_off:s_off+8].rstrip(b'\x00').decode('latin1','replace')
            v_size, v_addr, r_size, r_off = struct.unpack('<IIII', data[s_off+8:s_off+24])
            s_char = struct.unpack('<I', data[s_off+36:s_off+40])[0]
        except Exception:
            break
        ent = (_shannon_entropy(data[r_off:r_off+r_size])
               if (r_off+r_size <= len(data) and r_size > 0) else 0)
        s_flags = []
        if s_char & 0x20000000: s_flags.append('실행')
        if s_char & 0x40000000: s_flags.append('읽기')
        if s_char & 0x80000000: s_flags.append('쓰기')
        sections.append({
            'name': name, 'v_size': v_size, 'v_addr': f'0x{v_addr:08X}',
            'r_size': r_size, 'r_off': f'0x{r_off:08X}',
            'entropy': round(ent, 3), 'high_entropy': ent > 7.0,
            'flags': ' / '.join(s_flags) or '-',
        })
    imports = sorted(set(m.group(0).decode('latin1','replace')
                         for m in re.finditer(rb'[A-Za-z0-9_\-]{2,30}\.[Dd][Ll][Ll]', data)))[:50]
    apis = []
    seen = set()
    SUS_PREFIX = ('Create','Read','Write','Virtual','Reg','Internet','Crypt','Wsa','Nt','Zw',
                  'Wow64','Load','Free','Heap','URLDownload','Shell','WinExec','Connect',
                  'Send','Recv','HTTP','FTP','Socket','Process','Thread','Open')
    for m in re.finditer(rb'[A-Z][A-Za-z0-9_]{4,40}', data):
        s = m.group(0).decode('latin1','replace')
        if any(s.startswith(p) for p in SUS_PREFIX):
            if s not in seen and len(seen) < 80:
                seen.add(s); apis.append(s)
    SUS_API = {'VirtualAlloc','VirtualProtect','WriteProcessMemory','CreateRemoteThread',
               'LoadLibraryA','LoadLibraryW','GetProcAddress','URLDownloadToFile','WinExec',
               'ShellExecuteA','ShellExecuteW','RegSetValueExA','RegSetValueExW','CryptEncrypt',
               'InternetOpenA','InternetOpenW','Wow64DisableWow64FsRedirection',
               'NtUnmapViewOfSection','SetWindowsHookExA','SetWindowsHookExW','OpenProcess',
               'CreateProcessA','CreateProcessW','HttpSendRequestA','WSASocketA'}
    suspicious = [a for a in apis if a in SUS_API]
    try:
        ts_str = _dt.datetime.fromtimestamp(ts, _dt.timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
    except Exception:
        ts_str = f'(잘못된값 {ts})'
    return {
        'type':'PE', 'machine': MACHINE.get(machine, f'알수없음(0x{machine:04X})'),
        'bitness': 64 if is_64 else 32, 'compile_time': ts_str,
        'subsystem': SUBSYS.get(subsystem, str(subsystem)),
        'characteristics': chars, 'num_sections': num_sect,
        'sections': sections, 'imports': imports, 'apis': apis[:50],
        'suspicious_apis': suspicious, 'overall_entropy': round(_shannon_entropy(data),3),
    }


def _parse_elf(data: bytes) -> dict:
    if len(data) < 0x40 or data[:4] != b'\x7fELF': return None
    is_64 = data[4] == 2
    is_le = data[5] == 1
    pack = '<' if is_le else '>'
    osabi = data[7]
    try:
        e_type, e_machine = struct.unpack(pack+'HH', data[16:20])
        if is_64:
            e_entry = struct.unpack(pack+'Q', data[24:32])[0]
        else:
            e_entry = struct.unpack(pack+'I', data[24:28])[0]
    except Exception:
        return None
    MACHINE = {0x03:'Intel 80386',0x3e:'x86-64',0x28:'ARM',0xb7:'AArch64',0xf3:'RISC-V',
               0x32:'PA-RISC',0x14:'PowerPC',0x15:'PowerPC64',0x16:'S390',0x08:'MIPS',0x2a:'SuperH'}
    TYPE = {1:'REL (재배치)',2:'EXEC (실행)',3:'DYN (공유 객체/PIE)',4:'CORE (덤프)'}
    OSABI = {0:'System V',1:'HP-UX',2:'NetBSD',3:'Linux',6:'Solaris',7:'AIX',8:'IRIX',
             9:'FreeBSD',10:'TRU64',11:'Modesto',12:'OpenBSD'}
    return {
        'type':'ELF', 'bitness': 64 if is_64 else 32,
        'endian': 'Little Endian' if is_le else 'Big Endian',
        'machine': MACHINE.get(e_machine, f'알수없음(0x{e_machine:04X})'),
        'file_type': TYPE.get(e_type, str(e_type)),
        'osabi': OSABI.get(osabi, str(osabi)),
        'entry_point': f'0x{e_entry:016X}' if is_64 else f'0x{e_entry:08X}',
        'overall_entropy': round(_shannon_entropy(data),3),
    }


def _parse_macho(data: bytes) -> dict:
    if len(data) < 32: return None
    magic = data[:4]
    if magic == b'\xCF\xFA\xED\xFE': is_64, pack = True, '<'
    elif magic == b'\xCE\xFA\xED\xFE': is_64, pack = False, '<'
    elif magic == b'\xFE\xED\xFA\xCF': is_64, pack = True, '>'
    elif magic == b'\xFE\xED\xFA\xCE': is_64, pack = False, '>'
    elif magic == b'\xCA\xFE\xBA\xBE':
        return {'type':'Mach-O Universal/FAT', 'note':'다중 아키텍처 번들 (FAT magic)',
                'overall_entropy': round(_shannon_entropy(data),3)}
    else:
        return None
    try:
        cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags = struct.unpack(
            pack+'IIIIII', data[4:28])
    except Exception:
        return None
    CPU = {7:'x86',0x01000007:'x86_64',12:'ARM',0x0100000c:'ARM64',
           18:'PowerPC',0x01000012:'PowerPC64'}
    TYPE = {1:'OBJECT',2:'EXECUTE',3:'FVMLIB',4:'CORE',5:'PRELOAD',
            6:'DYLIB',7:'DYLINKER',8:'BUNDLE',9:'DYLIB_STUB',10:'DSYM',11:'KEXT_BUNDLE'}
    return {
        'type':'Mach-O', 'bitness': 64 if is_64 else 32,
        'cpu': CPU.get(cputype, f'알수없음(0x{cputype:08X})'),
        'file_type': TYPE.get(filetype, str(filetype)),
        'num_commands': ncmds, 'cmd_size': sizeofcmds,
        'overall_entropy': round(_shannon_entropy(data),3),
    }


@bp.route('/pe', methods=['GET','POST'])
def pe_tool():
    result = error = None; share_token = None
    if request.method == 'POST':
        f = request.files.get('file')
        if not f or not f.filename:
            error = '파일을 선택하세요'
        else:
            data = f.read()
            if not data:
                error = '빈 파일'
            else:
                r = _parse_pe(data) or _parse_elf(data) or _parse_macho(data)
                if not r:
                    error = '인식되지 않는 실행 파일 형식 (PE/ELF/Mach-O 아님)'
                else:
                    result = r; result['filename'] = f.filename; result['file_size'] = len(data)
                    share_token = _save_log(
                        'pe', 'PE/ELF/Mach-O 분석', f.filename, len(data),
                        f"{r.get('type','?')} | {r.get('machine') or r.get('cpu','')}", r)
    return render_template('tools/pe.html', result=result, error=error, share_token=share_token)


# ============================================================
# 엔트로피 / 시그니처
# ============================================================
_FILE_SIGS = [
    (b'\x4D\x5A',                            'PE/EXE/DLL (MZ)'),
    (b'\x7F\x45\x4C\x46',                    'ELF (Linux 실행)'),
    (b'\xCF\xFA\xED\xFE',                    'Mach-O 64-bit (macOS)'),
    (b'\xCE\xFA\xED\xFE',                    'Mach-O 32-bit (macOS)'),
    (b'\xCA\xFE\xBA\xBE',                    'Mach-O Universal / Java class'),
    (b'\x50\x4B\x03\x04',                    'ZIP / DOCX / XLSX / APK / JAR'),
    (b'\x50\x4B\x05\x06',                    'ZIP (빈 아카이브)'),
    (b'\x52\x61\x72\x21\x1A\x07',            'RAR'),
    (b'\x37\x7A\xBC\xAF\x27\x1C',            '7-Zip'),
    (b'\x1F\x8B',                            'GZIP'),
    (b'\x42\x5A\x68',                        'BZIP2'),
    (b'\xFD\x37\x7A\x58\x5A',                'XZ'),
    (b'\x25\x50\x44\x46',                    'PDF'),
    (b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1',    'MS Office OLE2 (DOC/XLS/PPT 구버전)'),
    (b'\xFF\xD8\xFF',                        'JPEG'),
    (b'\x89\x50\x4E\x47',                    'PNG'),
    (b'\x47\x49\x46\x38',                    'GIF'),
    (b'\x42\x4D',                            'BMP'),
    (b'\x49\x49\x2A\x00',                    'TIFF (Little Endian)'),
    (b'\x4D\x4D\x00\x2A',                    'TIFF (Big Endian)'),
    (b'\x52\x49\x46\x46',                    'RIFF (AVI / WAV / WEBP)'),
    (b'\x1A\x45\xDF\xA3',                    'Matroska / WEBM'),
    (b'\xFF\xFB',                            'MP3'),
    (b'\x49\x44\x33',                        'MP3 (ID3 태그)'),
    (b'\x4F\x67\x67\x53',                    'OGG'),
    (b'\x66\x4C\x61\x43',                    'FLAC'),
    (b'\x53\x51\x4C\x69\x74\x65\x20\x66',    'SQLite Database'),
    (b'regf',                                'Windows Registry Hive'),
    (b'\x65\x6C\x66\x66',                    'Windows Event Log (legacy)'),
    (b'ElfFile',                             'EVTX (Windows Event Log XML)'),
    (b'SCCA',                                'Prefetch (Vista+ 비압축)'),
    (b'MAM\x84',                             'Prefetch 압축 (Win10+)'),
    (b'\x4C\x00\x00\x00\x01\x14\x02\x00',    'LNK 바로가기'),
    (b'-----BEGIN',                          'PEM 인증서/키'),
    (b'\x30\x82',                            'DER 인증서/ASN.1'),
    (b'EVF\x09\x0D\x0A\xFF\x00',             'EnCase E01 (포렌식 이미지)'),
    (b'EVF2',                                'EnCase Ex01 (E01 v2)'),
    (b'AFF',                                 'AFF 포렌식 이미지'),
    (b'AFF4',                                'AFF4 포렌식 이미지'),
    (b'vhdxfile',                            'VHDX (Hyper-V)'),
    (b'KDMV',                                'VMDK Sparse (VMware)'),
    (b'QFI\xFB',                             'QCOW2 (QEMU)'),
    (b'\xEB\x52\x90NTFS    ',                'NTFS 부트 섹터'),
    (b'\xEB\x3C\x90',                        'FAT 부트 섹터'),
    (b'BMR1',                                'BitLocker FVE 메타데이터'),
    (b'LUKS\xBA\xBE',                        'LUKS 암호화 볼륨'),
    (b'\x00\x61\x73\x6D',                    'WebAssembly (.wasm)'),
    (b'\xCE\xFA\xED\xFE',                    'Mach-O 32-bit'),
    (b'<!DOCTYPE',                           'HTML/XML'),
    (b'<?xml',                               'XML'),
    (b'#!',                                  'Shell/Python 스크립트'),
]


def _detect_signature(data: bytes) -> list:
    matches = []
    head = data[:64]
    for sig, label in _FILE_SIGS:
        if head.startswith(sig):
            matches.append({'sig': sig.hex().upper(), 'label': label})
    if len(data) >= 512 and data[-512:-504] == b'conectix':
        matches.append({'sig':'636F6E6563746978','label':'VHD (파일 끝 푸터)'})
    return matches


def _entropy_windows(data: bytes, window: int = 4096) -> list:
    out = []
    step = max(window, len(data) // 200 or 1)
    for off in range(0, len(data), step):
        chunk = data[off:off+window]
        if len(chunk) < 64: break
        out.append([off, round(_shannon_entropy(chunk), 3)])
    return out


@bp.route('/entropy', methods=['GET','POST'])
def entropy_tool():
    result = error = None; share_token = None
    if request.method == 'POST':
        f = request.files.get('file')
        if not f or not f.filename:
            error = '파일 선택 필요'
        else:
            data = f.read()
            if not data:
                error = '빈 파일'
            else:
                overall = _shannon_entropy(data)
                sigs = _detect_signature(data)
                wins = _entropy_windows(data)
                hi = sum(1 for _,e in wins if e > 7.5)
                lo = sum(1 for _,e in wins if e < 2.0)
                verdict = ('암호화/압축 의심 (전체 엔트로피 매우 높음)' if overall > 7.5 else
                           '실행파일/패킹 가능성'  if overall > 6.8 else
                           '텍스트/구조화 데이터'  if overall < 5.0 else
                           '일반 바이너리')
                result = {
                    'filename': f.filename, 'file_size': len(data),
                    'overall_entropy': round(overall, 4), 'verdict': verdict,
                    'signatures': sigs, 'windows': wins,
                    'high_windows': hi, 'low_windows': lo, 'window_size': 4096,
                }
                share_token = _save_log(
                    'entropy', '엔트로피·시그니처', f.filename, len(data),
                    f"엔트로피 {overall:.3f} | {verdict}",
                    {'overall':overall,'verdict':verdict,'signatures':sigs})
    return render_template('tools/entropy.html', result=result, error=error,
                           share_token=share_token)


# ============================================================
# 다중 암호 디코더
# ============================================================
def _try_base64(s):
    import base64
    try:
        pad = (-len(s)) % 4
        return base64.b64decode(s + '='*pad).decode('utf-8','replace')
    except Exception: return None

def _try_base32(s):
    import base64
    try:
        pad = (-len(s)) % 8
        return base64.b32decode(s + '='*pad, casefold=True).decode('utf-8','replace')
    except Exception: return None

def _try_base85(s):
    import base64
    try: return base64.b85decode(s).decode('utf-8','replace')
    except Exception: return None

def _try_hex(s):
    try:
        return bytes.fromhex(s.replace(' ','').replace('0x','').replace(',','')
                             ).decode('utf-8','replace')
    except Exception: return None

def _try_url(s):
    from urllib.parse import unquote
    try:
        r = unquote(s); return r if r != s else None
    except Exception: return None

def _try_rot(s, n):
    out = []
    for c in s:
        if 'a'<=c<='z': out.append(chr((ord(c)-97+n)%26+97))
        elif 'A'<=c<='Z': out.append(chr((ord(c)-65+n)%26+65))
        else: out.append(c)
    return ''.join(out)

def _try_atbash(s):
    out = []
    for c in s:
        if 'a'<=c<='z': out.append(chr(122-(ord(c)-97)))
        elif 'A'<=c<='Z': out.append(chr(90-(ord(c)-65)))
        else: out.append(c)
    return ''.join(out)

def _try_vigenere(s, key, decrypt=True):
    if not key: return None
    out=[]; ki=0
    for c in s:
        if 'a'<=c<='z':
            shift=(ord(key[ki%len(key)].lower())-97)
            if decrypt: shift=-shift
            out.append(chr((ord(c)-97+shift)%26+97)); ki+=1
        elif 'A'<=c<='Z':
            shift=(ord(key[ki%len(key)].lower())-97)
            if decrypt: shift=-shift
            out.append(chr((ord(c)-65+shift)%26+65)); ki+=1
        else: out.append(c)
    return ''.join(out)

def _try_xor(s, key):
    if not key: return None
    try:
        if all(c in '0123456789abcdefABCDEF ' for c in s):
            data = bytes.fromhex(s.replace(' ',''))
        else:
            data = s.encode('latin1')
        k = key.encode('utf-8')
        return bytes(b ^ k[i%len(k)] for i,b in enumerate(data)).decode('utf-8','replace')
    except Exception: return None

_MORSE = {'.-':'A','-...':'B','-.-.':'C','-..':'D','.':'E','..-.':'F','--.':'G','....':'H',
          '..':'I','.---':'J','-.-':'K','.-..':'L','--':'M','-.':'N','---':'O','.--.':'P',
          '--.-':'Q','.-.':'R','...':'S','-':'T','..-':'U','...-':'V','.--':'W','-..-':'X',
          '-.--':'Y','--..':'Z','-----':'0','.----':'1','..---':'2','...--':'3','....-':'4',
          '.....':'5','-....':'6','--...':'7','---..':'8','----.':'9','/':' '}

def _try_morse(s):
    try:
        words = s.replace('  ',' / ').split(' ')
        return ''.join(_MORSE.get(c,'') for c in words)
    except Exception: return None

def _try_binary(s):
    bits = s.replace(' ','').replace('\n','')
    try:
        return ''.join(chr(int(bits[i:i+8],2))
                       for i in range(0,len(bits),8) if i+8<=len(bits))
    except Exception: return None

def _try_decimal(s):
    try:
        return ''.join(chr(int(x)) for x in s.replace(',',' ').split()
                       if x.isdigit() and 0<int(x)<128)
    except Exception: return None


@bp.route('/decode', methods=['GET','POST'])
def decode_tool():
    result = error = None
    text = key = ''
    if request.method == 'POST':
        text = (request.form.get('text') or '').strip()
        key = (request.form.get('key') or '').strip()
        if not text:
            error = '디코드할 텍스트 입력'
        else:
            results = []
            def add(name, val):
                if val and val != text and len(val) < 100000:
                    printable = sum(1 for c in val if c.isprintable() or c in '\n\r\t')
                    score = printable / max(len(val),1)
                    results.append({'name': name, 'value': val[:5000],
                                    'score': round(score*100, 1)})
            add('Base64', _try_base64(text))
            add('Base32', _try_base32(text))
            add('Base85', _try_base85(text))
            add('Hex', _try_hex(text))
            add('URL 디코드', _try_url(text))
            for r in [13,1,3,5,7,11,17,19,23,25]:
                v = _try_rot(text, r)
                if v != text: add(f'ROT-{r} / Caesar(+{r})', v)
            add('Atbash', _try_atbash(text))
            add('Morse', _try_morse(text))
            add('이진수 → ASCII', _try_binary(text))
            add('10진수 → ASCII', _try_decimal(text))
            if key:
                add(f'Vigenère (키: {key})', _try_vigenere(text, key))
                add(f'XOR (키: {key})', _try_xor(text, key))
            results.sort(key=lambda x: -x['score'])
            result = {'input': text[:1000], 'results': results, 'count': len(results)}
    return render_template('tools/decode.html', result=result, error=error,
                           text=text, key=key)


# ============================================================
# Prefetch (.pf)
# ============================================================
def _parse_prefetch(data: bytes, filename: str) -> dict:
    if len(data) < 84: raise ValueError('파일이 너무 작음')
    if data[:3] == b'MAM':
        try:
            import pyscca
            import io
            scca = pyscca.file()
            scca.open_file_object(io.BytesIO(data))
            exe = scca.executable_filename
            run_count = scca.run_count
            files = []
            for i in range(min(scca.number_of_filenames, 200)):
                files.append(scca.get_filename(i))
            vols = []
            for i in range(scca.number_of_volumes):
                v = scca.get_volume_information(i)
                vols.append({
                    'device_path': v.device_path,
                    'creation_time': str(v.creation_time),
                    'serial': hex(v.serial_number),
                })
            last_runs = []
            for i in range(8):
                try:
                    t = scca.get_last_run_time(i)
                    if t: last_runs.append(str(t))
                except Exception: break
            scca.close()
            return {
                'filename': filename, 'format': 'Prefetch (MAM 압축 해제됨)',
                'executable': exe, 'run_count': run_count,
                'last_runs': last_runs, 'files': files, 'volumes': vols,
            }
        except ImportError:
            raise ValueError('MAM 압축 프리페치 파싱에 libscca-python 라이브러리 필요 '
                             '(pip install libscca-python)')
    if data[4:8] != b'SCCA':
        raise ValueError('SCCA 시그니처 없음')
    version = struct.unpack('<I', data[:4])[0]
    file_size = struct.unpack('<I', data[12:16])[0]
    exe_name = data[16:76].decode('utf-16-le','replace').rstrip('\x00')
    pf_hash = struct.unpack('<I', data[76:80])[0]
    VERSIONS = {17:'Windows XP/2003', 23:'Windows Vista/7',
                26:'Windows 8.1', 30:'Windows 10/11', 31:'Windows 10/11'}
    if version == 23: run_off, lr_off, lr_n = 0x98, 0x80, 1
    elif version in (26, 30, 31): run_off, lr_off, lr_n = 0xD0, 0x80, 8
    elif version == 17: run_off, lr_off, lr_n = 0x90, 0x78, 1
    else: run_off, lr_off, lr_n = 0x98, 0x80, 1
    run_count = (struct.unpack('<I', data[run_off:run_off+4])[0]
                 if run_off+4 <= len(data) else 0)
    last_runs = []
    for i in range(lr_n):
        off = lr_off + i*8
        if off+8 > len(data): break
        ft = struct.unpack('<Q', data[off:off+8])[0]
        if ft == 0: continue
        s = _ft2str(ft)
        if s != '-' and not s.startswith('('): last_runs.append(s)
    files = []
    for m in re.finditer(rb'(?:[A-Z]\x00:\x00|\\\x00D\x00E\x00V\x00I\x00C\x00E\x00)'
                         rb'[\x20-\x7e\x00]{8,400}?\x00\x00\x00', data):
        try:
            s = m.group(0).decode('utf-16-le','replace').rstrip('\x00')
            if '.' in s and s not in files and len(files) < 200:
                files.append(s)
        except Exception: pass
    return {
        'filename': filename, 'format': 'Prefetch (SCCA 비압축)',
        'version': VERSIONS.get(version, f'알수없음(v{version})'),
        'version_num': version, 'pf_size': file_size,
        'executable': exe_name, 'hash': f'0x{pf_hash:08X}',
        'run_count': run_count, 'last_runs': last_runs, 'files': files[:200],
    }


@bp.route('/prefetch', methods=['GET','POST'])
def prefetch_tool():
    result = error = None; share_token = None
    if request.method == 'POST':
        f = request.files.get('file')
        if not f or not f.filename:
            error = '파일 선택 필요'
        else:
            data = f.read()
            try:
                result = _parse_prefetch(data, f.filename)
                result['file_size'] = len(data)
                share_token = _save_log(
                    'prefetch', 'Prefetch 분석', f.filename, len(data),
                    f"{result.get('executable','?')} | {result.get('run_count',0)}회 실행",
                    result)
            except Exception as e:
                error = f'파싱 오류: {e}'
    return render_template('tools/prefetch.html', result=result, error=error,
                           share_token=share_token)


# ============================================================
# LNK
# ============================================================
def _parse_lnk(data: bytes, filename: str) -> dict:
    if len(data) < 76 or data[:4] != b'\x4C\x00\x00\x00':
        raise ValueError('LNK 시그니처 아님')
    clsid = data[4:20].hex()
    if clsid != '0114020000000000c000000000000046':
        raise ValueError(f'LNK CLSID 불일치 ({clsid})')
    flags = struct.unpack('<I', data[20:24])[0]
    attrs = struct.unpack('<I', data[24:28])[0]
    create_ft = struct.unpack('<Q', data[28:36])[0]
    access_ft = struct.unpack('<Q', data[36:44])[0]
    write_ft  = struct.unpack('<Q', data[44:52])[0]
    file_size = struct.unpack('<I', data[52:56])[0]
    HasLinkTargetIDList = bool(flags & 0x01)
    HasLinkInfo         = bool(flags & 0x02)
    HasName             = bool(flags & 0x04)
    HasRelativePath     = bool(flags & 0x08)
    HasWorkingDir       = bool(flags & 0x10)
    HasArguments        = bool(flags & 0x20)
    HasIconLocation     = bool(flags & 0x40)
    IsUnicode           = bool(flags & 0x80)
    attr_flags = []
    for bit, name in [(1,'읽기전용'),(2,'숨김'),(4,'시스템'),(0x10,'디렉터리'),(0x20,'아카이브'),
                      (0x40,'장치'),(0x80,'일반'),(0x100,'임시'),(0x200,'스파스'),
                      (0x400,'재분석점'),(0x800,'압축'),(0x1000,'오프라인'),
                      (0x2000,'미인덱스'),(0x4000,'암호화')]:
        if attrs & bit: attr_flags.append(name)
    pos = 76
    if HasLinkTargetIDList and pos+2 <= len(data):
        sz = struct.unpack('<H', data[pos:pos+2])[0]
        pos += 2 + sz
    local_path = network_path = volume_label = drive_serial = drive_type = None
    if HasLinkInfo and pos+28 <= len(data):
        li_start = pos
        li_size = struct.unpack('<I', data[pos:pos+4])[0]
        li_flags = struct.unpack('<I', data[pos+8:pos+12])[0]
        vol_off  = struct.unpack('<I', data[pos+12:pos+16])[0]
        lbp_off  = struct.unpack('<I', data[pos+16:pos+20])[0]
        ns_off   = struct.unpack('<I', data[pos+20:pos+24])[0]
        if (li_flags & 1) and vol_off > 0:
            vp = li_start + vol_off
            if vp+16 <= len(data):
                dt_v = struct.unpack('<I', data[vp+4:vp+8])[0]
                drive_serial = f'0x{struct.unpack("<I", data[vp+8:vp+12])[0]:08X}'
                vl_off = struct.unpack('<I', data[vp+12:vp+16])[0]
                DT = {0:'알수없음',1:'마운트없음',2:'이동식',3:'고정',
                      4:'원격',5:'CD-ROM',6:'RAM디스크'}
                drive_type = DT.get(dt_v, str(dt_v))
                lp = vp + vl_off
                end = data.find(b'\x00', lp, lp+260)
                if end > lp:
                    volume_label = data[lp:end].decode('latin1','replace')
        if (li_flags & 1) and lbp_off > 0:
            lp = li_start + lbp_off
            end = data.find(b'\x00', lp, lp+520)
            if end > lp:
                local_path = data[lp:end].decode('latin1','replace')
        if (li_flags & 2) and ns_off > 0:
            nsp = li_start + ns_off
            if nsp+12 <= len(data):
                name_off = struct.unpack('<I', data[nsp+8:nsp+12])[0]
                np = nsp + name_off
                end = data.find(b'\x00', np, np+520)
                if end > np:
                    network_path = data[np:end].decode('latin1','replace')
        pos = li_start + li_size
    def read_str():
        nonlocal pos
        if pos+2 > len(data): return None
        ln = struct.unpack('<H', data[pos:pos+2])[0]
        pos += 2
        if IsUnicode:
            s = data[pos:pos+ln*2].decode('utf-16-le','replace'); pos += ln*2
        else:
            s = data[pos:pos+ln].decode('latin1','replace'); pos += ln
        return s
    name_str = read_str() if HasName else None
    rel_path = read_str() if HasRelativePath else None
    work_dir = read_str() if HasWorkingDir else None
    args = read_str() if HasArguments else None
    icon_loc = read_str() if HasIconLocation else None
    mac = machine_id = droid_birth = None
    idx = data.find(b'\x60\x00\x00\x00\x03\x00\x00\xa0')
    if idx > 0 and idx + 0x60 <= len(data):
        try:
            machine_id = data[idx+0x10:idx+0x30].split(b'\x00',1)[0].decode('latin1','replace')
            droid_birth = data[idx+0x40:idx+0x50].hex().upper()
            mac_raw = data[idx+0x40+10:idx+0x40+16]
            mac = ':'.join(f'{b:02X}' for b in mac_raw)
        except Exception: pass
    return {
        'filename': filename,
        'target': local_path or network_path or rel_path or '(없음)',
        'local_path': local_path, 'network_path': network_path,
        'volume_label': volume_label, 'drive_serial': drive_serial,
        'drive_type': drive_type,
        'name': name_str, 'relative_path': rel_path, 'working_dir': work_dir,
        'arguments': args, 'icon_location': icon_loc,
        'create_time': _ft2str(create_ft), 'access_time': _ft2str(access_ft),
        'write_time': _ft2str(write_ft), 'target_size': file_size,
        'attributes': ' / '.join(attr_flags) or '-',
        'unicode': IsUnicode, 'has_arguments': HasArguments,
        'mac_address': mac, 'machine_id': machine_id, 'droid_birth': droid_birth,
        'flags_raw': f'0x{flags:08X}',
    }


@bp.route('/lnk', methods=['GET','POST'])
def lnk_tool():
    result = error = None; share_token = None
    if request.method == 'POST':
        f = request.files.get('file')
        if not f or not f.filename:
            error = '파일 선택 필요'
        else:
            data = f.read()
            try:
                result = _parse_lnk(data, f.filename)
                result['file_size'] = len(data)
                share_token = _save_log(
                    'lnk', 'LNK 바로가기 분석', f.filename, len(data),
                    f"{(result.get('target') or '?')[:60]}", result)
            except Exception as e:
                error = f'LNK 파싱 오류: {e}'
    return render_template('tools/lnk.html', result=result, error=error,
                           share_token=share_token)


# ============================================================
# 디스크 이미지 헤더 분석
# ============================================================
def _analyze_disk_image(data: bytes, filename: str, file_size: int) -> dict:
    head = data[:4096]
    info = {'filename': filename, 'file_size': file_size,
            'formats': [], 'partitions': [], 'notes': []}
    if head[:8] == b'EVF\x09\x0D\x0A\xFF\x00' or head[:3] == b'EVF':
        info['formats'].append('EnCase E01 (Expert Witness Format)')
        info['notes'].append('libewf로 마운트하여 raw 디스크처럼 접근 가능')
    if head[:4] == b'EVF2': info['formats'].append('EnCase Ex01 (E01 v2)')
    if head[:3] == b'AFF': info['formats'].append('AFF 포렌식 이미지')
    if head[:4] == b'AFF4': info['formats'].append('AFF4 (PyAFF4)')
    if file_size >= 512 and len(data) >= 512 and data[-512:-504] == b'conectix':
        info['formats'].append('VHD (Microsoft Virtual Hard Disk, 푸터 발견)')
    if head[:8] == b'vhdxfile': info['formats'].append('VHDX (Hyper-V 신규 형식)')
    if head[:4] == b'KDMV': info['formats'].append('VMDK Sparse (VMware)')
    if head[:21] == b'# Disk DescriptorFile': info['formats'].append('VMDK Descriptor (텍스트 헤더)')
    if head[:4] == b'QFI\xFB':
        ver = struct.unpack('>I', head[4:8])[0]
        info['formats'].append(f'QCOW2 v{ver} (QEMU/KVM)')
    if head[40:44] == b'\x7F\x10\xDA\xBE':
        info['formats'].append('VDI (VirtualBox)')
    if b'<<< Oracle VM VirtualBox Disk Image >>>' in head:
        info['formats'].append('VDI (VirtualBox 텍스트 헤더)')
    if len(head) >= 512 and head[510:512] == b'\x55\xAA':
        info['formats'].append('MBR 또는 부트 섹터 포함')
        PT = {0x01:'FAT12',0x04:'FAT16 <32MB',0x05:'확장 CHS',0x06:'FAT16',
              0x07:'NTFS / exFAT / HPFS',0x0B:'FAT32 CHS',0x0C:'FAT32 LBA',
              0x0E:'FAT16 LBA',0x0F:'확장 LBA',0x82:'Linux swap',0x83:'Linux',
              0x84:'OS/2 Hibernate',0x8E:'Linux LVM',0xA5:'FreeBSD',0xA6:'OpenBSD',
              0xA9:'NetBSD',0xAF:'macOS HFS+',0xEE:'GPT 보호',0xEF:'EFI 시스템',
              0xFD:'Linux RAID'}
        for i in range(4):
            off = 446 + i*16
            entry = head[off:off+16]
            if entry[0] not in (0x00, 0x80): continue
            ptype = entry[4]
            if ptype == 0: continue
            lba = struct.unpack('<I', entry[8:12])[0]
            sects = struct.unpack('<I', entry[12:16])[0]
            info['partitions'].append({
                'idx': i+1,
                'type': f'0x{ptype:02X} {PT.get(ptype,"")}',
                'boot': '*' if entry[0]==0x80 else '',
                'lba': lba, 'size_mb': sects//2048,
            })
    if len(data) >= 1024 and data[512:520] == b'EFI PART':
        info['formats'].append('GPT (GUID Partition Table)')
        rev = data[520:524].hex()
        info['notes'].append(f'GPT 헤더 리비전 0x{rev}')
    if head[3:11] == b'NTFS    ': info['formats'].append('NTFS 볼륨')
    if head[82:90] == b'FAT32   ': info['formats'].append('FAT32 볼륨')
    if head[54:62] == b'FAT16   ': info['formats'].append('FAT16 볼륨')
    if head[54:62] == b'FAT12   ': info['formats'].append('FAT12 볼륨')
    if head[3:11] == b'EXFAT   ': info['formats'].append('exFAT 볼륨')
    if len(data) >= 1080 and data[1080:1082] == b'\x53\xEF':
        info['formats'].append('ext2 / ext3 / ext4 슈퍼블록')
    if len(data) >= 1026 and data[1024:1026] == b'H+':
        info['formats'].append('HFS+ 슈퍼블록 (macOS 구버전)')
    if len(data) >= 64 and data[32:36] == b'NXSB':
        info['formats'].append('APFS 컨테이너 (macOS 신버전)')
    if data[0:4] == b'\x00\x00\x00\x00' and data[8:12] == b'\x0b\xb0\xc5\x21':
        info['formats'].append('ZFS 라벨')
    if head[:6] == b'LUKS\xBA\xBE':
        info['formats'].append('LUKS 암호화 볼륨 (Linux)')
    if head[:4] == b'BMR1':
        info['formats'].append('BitLocker 메타데이터 (Windows)')
    if not info['formats']:
        info['formats'].append('인식 안 됨 — 시그니처 없는 RAW 데이터')
    info['hex_preview'] = ' '.join(f'{b:02X}' for b in head[:64])
    info['ascii_preview'] = ''.join(chr(b) if 32<=b<127 else '.' for b in head[:64])
    return info


@bp.route('/diskimg', methods=['GET','POST'])
def diskimg_tool():
    result = error = None; share_token = None
    if request.method == 'POST':
        f = request.files.get('file')
        if not f or not f.filename:
            error = '파일 선택 필요'
        else:
            head = f.read(8192)
            f.seek(0, 2); file_size = f.tell()
            tail = b''
            if file_size > 8192:
                f.seek(max(0, file_size - 4096))
                tail = f.read(4096)
            combined = head + b'\x00'*max(0, 4096 - len(head)) + tail
            try:
                result = _analyze_disk_image(combined, f.filename, file_size)
                share_token = _save_log(
                    'diskimg','디스크 이미지 분석', f.filename, file_size,
                    f"{', '.join(result['formats'][:3])}", result)
            except Exception as e:
                error = f'분석 오류: {e}'
    return render_template('tools/diskimg.html', result=result, error=error,
                           share_token=share_token)


# ============================================================
# 로컬 스크립트 허브
# ============================================================
_SCRIPTS_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    'static', 'tools')


@bp.route('/scripts')
def scripts_hub():
    return render_template('tools/scripts.html')


# ============================================================
# 트리아지 ZIP 통합 분석
# ============================================================
import zipfile
import tempfile

# 알려진 아티팩트 종류
_TRIAGE_KINDS = [
    ('registry_hive',    '레지스트리 하이브 (SYSTEM/SOFTWARE/SAM/SECURITY 등)',  'bi-diagram-2-fill', '#f59e0b'),
    ('registry_ntuser',  '사용자 NTUSER.DAT',                                   'bi-person-fill',    '#00d4ff'),
    ('registry_usrclass','UsrClass.dat (ShellBag·MUICache)',                    'bi-folder-fill',    '#10b981'),
    ('amcache',          'Amcache.hve (실행파일 인벤토리)',                      'bi-app-indicator',  '#a78bfa'),
    ('eventlog',         'EVTX 이벤트 로그',                                    'bi-journal-text',   '#06b6d4'),
    ('prefetch',         'Prefetch (.pf)',                                      'bi-fast-forward-fill','#10b981'),
    ('lnk',              'LNK 바로가기',                                        'bi-link-45deg',     '#00d4ff'),
    ('jumplist',         'JumpList (.automaticDestinations-ms)',                'bi-bookmark-fill',  '#a78bfa'),
    ('usb_log',          'setupapi.dev.log (USB 연결 이력)',                    'bi-usb-symbol',     '#3b82f6'),
    ('powershell',       'PowerShell ConsoleHost_history.txt',                  'bi-terminal-fill',  '#ef4444'),
    ('mft',              '$MFT NTFS Master File Table',                         'bi-hdd-fill',       '#f59e0b'),
    ('usnjrnl',          '$UsnJrnl 변경 저널',                                  'bi-clock-history',  '#06b6d4'),
]


# ============================================================
# 트리아지 IOC·LOLBin·MITRE 매핑 (LOLBAS + MITRE ATT&CK 기반)
# ============================================================
# LOLBins: Living Off The Land Binaries (Microsoft 서명된 합법 도구가
# 공격자에 의해 악용되는 사례). LOLBAS 프로젝트 + MITRE ATT&CK 기준.
_LOLBINS = {
    'mshta.exe':       ('T1218.005', 'high',     'HTA 스크립트 실행 — 악성 HTML/JScript 다운로드·실행 (FIN7 등 사용)'),
    'rundll32.exe':    ('T1218.011', 'medium',   'DLL 함수 직접 호출 — 악성 DLL 실행 우회'),
    'regsvr32.exe':    ('T1218.010', 'high',     'COM 등록 우회 (Squiblydoo) — 원격 .sct 스크립트 실행'),
    'wmic.exe':        ('T1047',     'medium',   'WMI 명령 실행 — Ryuk 랜섬웨어가 횡적 이동에 사용'),
    'certutil.exe':    ('T1140',     'high',     'Base64/HEX 디코딩 + 원격 파일 다운로드 — 가장 빈번히 악용되는 LOLBin'),
    'bitsadmin.exe':   ('T1197',     'high',     'BITS 백그라운드 전송 — 악성코드 다운로드 은닉'),
    'psexec.exe':      ('T1569.002', 'high',     'Sysinternals 원격 실행 — 횡적 이동 표준 도구'),
    'paexec.exe':      ('T1569.002', 'high',     'PsExec 오픈소스 클론 — 원격 실행'),
    'powershell.exe':  ('T1059.001', 'info',     'PowerShell 명령/스크립트 실행 — 가장 흔한 공격 벡터 (정상도 흔함)'),
    'pwsh.exe':        ('T1059.001', 'info',     'PowerShell Core 실행'),
    'cmd.exe':         ('T1059.003', 'info',     'Windows 명령 셸 (정상도 흔함)'),
    'cscript.exe':     ('T1059.005', 'medium',   'VBScript 실행 엔진'),
    'wscript.exe':     ('T1059.005', 'medium',   'VBScript/JScript 실행 엔진'),
    'schtasks.exe':    ('T1053.005', 'medium',   '예약 작업 — 지속성·권한 상승'),
    'at.exe':          ('T1053.002', 'medium',   '예약 작업 (구버전) — 지속성'),
    'mimikatz.exe':    ('T1003',     'critical', 'Mimikatz — 자격증명 덤프 (악성 도구)'),
    'procdump.exe':    ('T1003.001', 'high',     'Sysinternals ProcDump — LSASS 메모리 덤프 대상 빈번'),
    'sdelete.exe':     ('T1070.004', 'high',     'Sysinternals SDelete — 안티 포렌식 파일 영구 삭제'),
    'cipher.exe':      ('T1070.004', 'medium',   'cipher /w — 슬랙 공간 와이핑 (안티 포렌식)'),
    'ntdsutil.exe':    ('T1003.003', 'critical', 'NTDS.dit 도메인 자격증명 덤프'),
    'vssadmin.exe':    ('T1490',     'high',     'Volume Shadow Copy 제어 — 랜섬웨어가 백업 삭제에 사용'),
    'wbadmin.exe':     ('T1490',     'high',     'Windows Backup — 랜섬웨어가 백업 삭제에 사용'),
    'bcdedit.exe':     ('T1490',     'high',     'BCD 부팅 설정 변경 — 복구 모드 비활성 (랜섬웨어 흔적)'),
    'taskkill.exe':    ('T1489',     'low',      '프로세스 종료 (보안 도구 종료 패턴 확인 필요)'),
    'net.exe':         ('T1087',     'low',      '계정·공유·네트워크 정찰'),
    'net1.exe':        ('T1087',     'low',      'net.exe 별칭 — 정찰'),
    'nltest.exe':      ('T1018',     'low',      '도메인 컨트롤러 정찰'),
    'whoami.exe':      ('T1033',     'info',     '현재 사용자/권한 확인 (정찰)'),
    'systeminfo.exe':  ('T1082',     'low',      '시스템 정보 정찰'),
    'tasklist.exe':    ('T1057',     'low',      '프로세스 목록 정찰'),
    'arp.exe':         ('T1018',     'low',      'ARP 캐시 — 네트워크 정찰'),
    'route.exe':       ('T1016',     'low',      '라우팅 테이블 — 네트워크 정찰'),
    'ipconfig.exe':    ('T1016',     'info',     '네트워크 설정 확인'),
    'reg.exe':         ('T1112',     'medium',   '레지스트리 수정 — 지속성·환경 변경'),
    'msbuild.exe':     ('T1127.001', 'high',     'MSBuild — XML 내 C# 코드 컴파일·실행'),
    'installutil.exe': ('T1218.004', 'high',     '.NET 어셈블리 등록 — 임의 코드 실행'),
    'odbcconf.exe':    ('T1218.008', 'high',     'ODBC 구성 — DLL 로딩 우회'),
    'forfiles.exe':    ('T1059',     'medium',   'forfiles /c — 명령 실행 우회'),
    'wsmprovhost.exe': ('T1021.006', 'high',     'WinRM 원격 실행 (PSRemoting)'),
}

# PowerShell 명령 IOC 패턴 — 정규식 + (제목, MITRE, 심각도, 설명)
_PS_IOC_PATTERNS = [
    (r'(?i)-e(?:c|nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{40,}', 'Base64 인코딩 명령', 'T1027', 'high',
     'PowerShell -EncodedCommand로 난독화된 Base64 페이로드 — 다운로드 크래들·Mimikatz 로더·랜섬웨어에 빈번. /tools/strings로 디코딩 분석 권장.'),
    (r'(?i)FromBase64String', 'Base64 디코딩 함수 호출', 'T1027', 'medium',
     '런타임 Base64 디코딩 — 페이로드 난독화 전형 패턴.'),
    (r'(?i)\bIEX\b|Invoke-Expression', 'IEX 동적 코드 실행', 'T1059.001', 'high',
     'Invoke-Expression — 문자열을 코드로 실행. 다운로드 크래들의 핵심 구성요소.'),
    (r'(?i)DownloadString|DownloadFile|WebClient|Invoke-WebRequest|iwr\s|curl\s+-', '원격 다운로드 크래들', 'T1105', 'high',
     '원격 URL에서 페이로드 다운로드 — 전형적 stager. http(s):// URL 확인 필요.'),
    (r'(?i)-w(?:indow)?(?:style)?\s+hidden|-noni\b|-nop\b', '숨김/비대화형 실행 플래그', 'T1564.003', 'medium',
     '창 숨김 + Non-Interactive + NoProfile — 백그라운드 은닉 실행 전형.'),
    (r'(?i)-e(?:xecutionpolicy)?\s+bypass|-ep\s+bypass|set-executionpolicy.*bypass', '실행정책 우회', 'T1059.001', 'medium',
     'ExecutionPolicy Bypass — 서명 검증 없이 스크립트 실행.'),
    (r'(?i)amsi(?:utils|initfail|context|scanbuffer)|amsi\.dll|System\.Management\.Automation\.AmsiUtils', 'AMSI 우회 시도', 'T1562.001', 'critical',
     'AMSI(Antimalware Scan Interface) 우회 — Defender 시그니처 회피.'),
    (r'(?i)Mimikatz|Invoke-Mimikatz|sekurlsa|kerberos::|lsadump|logonpasswords', 'Mimikatz 자격증명 덤프', 'T1003', 'critical',
     'Mimikatz 사용 — 메모리에서 평문 비밀번호·NTLM·Kerberos 티켓 추출.'),
    (r'(?i)Reflective\w*Load|Add-Type.+System\.Reflection|\[Reflection\.Assembly\]', '리플렉티브 어셈블리 로딩', 'T1620', 'high',
     '디스크에 파일 없이 메모리에서 .NET 어셈블리 로드 — 파일리스 공격.'),
    (r'(?i)New-Object\s+Net\.Sockets\.TCPClient|Net\.TcpListener', '소켓 직접 생성', 'T1059.001', 'critical',
     'TCP 소켓 직접 생성 — 역방향 셸 / C2 통신 의심.'),
    (r'(?i)\b(?:nc|ncat|netcat)\.exe', 'Netcat 사용', 'T1071.001', 'high',
     'Netcat — 포트 리스닝/연결 도구, 백도어·C2에 자주 사용.'),
    (r'(?i)Set-MpPreference.+(?:Disable|Exclusion)|Add-MpPreference.+Exclusion', 'Defender 무력화/예외 추가', 'T1562.001', 'critical',
     'Windows Defender 비활성화 또는 경로 예외 추가 — 보안 도구 손상.'),
    (r'(?i)New-Service|sc(?:\.exe)?\s+create', '서비스 생성 (지속성)', 'T1543.003', 'high',
     '서비스 등록 — 재부팅 후에도 유지되는 지속성 메커니즘.'),
    (r'(?i)schtasks(?:\.exe)?\s+/create|Register-ScheduledTask', '예약 작업 생성 (지속성)', 'T1053.005', 'medium',
     '예약 작업 생성 — 부팅/로그온 시 자동 실행.'),
    (r'(?i)reg(?:\.exe)?\s+add.+(?:Run|RunOnce|Winlogon|Image File Execution)', '레지스트리 Run/IFEO 키 수정', 'T1547.001', 'high',
     '레지스트리 자동실행 키 또는 IFEO 디버거 등록 — 지속성·실행 가로채기.'),
    (r'(?i)vssadmin.+delete.+shadows|wmic.+shadowcopy.+delete|wbadmin.+delete|bcdedit.+(?:bootstatuspolicy|recoveryenabled)\s+(?:ignoreallfailures|no)', '백업·복구 비활성화', 'T1490', 'critical',
     'Shadow Copy/복구 모드 삭제 — 랜섬웨어 직전 신호.'),
    (r'(?i)Compress-Archive|7z(?:\.exe)?\s+a\s|rar(?:\.exe)?\s+a\s|tar.+(?:-c|--create)', '데이터 압축 (반출 준비)', 'T1560.001', 'medium',
     '대량 압축 — 외부 반출 준비 단계 가능성.'),
    (r'(?i)Invoke-WebRequest.+(?:Method\s+POST|UploadFile|UploadString)|ftp.+put|curl.+(?:-T|--upload-file)', '데이터 외부 업로드', 'T1041', 'high',
     '외부로 데이터 업로드 — 데이터 유출 가능성.'),
    (r'(?i)clear-eventlog|wevtutil\s+cl\s|Remove-EventLog', '이벤트 로그 삭제', 'T1070.001', 'critical',
     '이벤트 로그 삭제 — 흔적 인멸 (안티 포렌식).'),
    (r'(?i)cipher\s+/w|sdelete', '파일 영구 삭제', 'T1070.004', 'high',
     '와이핑 도구 사용 — 복구 불가능한 삭제 (안티 포렌식).'),
    (r'(?i)Get-ADUser|Get-ADComputer|Get-ADGroup|Get-DomainUser|Get-DomainController', 'Active Directory 정찰', 'T1087.002', 'medium',
     'AD 사용자/컴퓨터/그룹 열거 — PowerView·BloodHound 정찰 패턴.'),
]

# 아티팩트 종류별 교육 콘텐츠 (이게 뭐고 왜 중요한가)
_ARTIFACT_EXPLAIN = {
    'registry_hive': {
        'what': 'Windows 시스템 설정 데이터베이스. SYSTEM(드라이버·서비스·USB), SOFTWARE(설치 프로그램), SAM(로컬 계정), SECURITY(보안 정책) 등.',
        'why':  '"시스템에 무엇이 설치·연결됐는가"의 기준점. USB 시리얼·서비스 등록·자동실행·계정 SID·마지막 로그온 시각 등을 담고 있어 거의 모든 사건의 출발점.',
        'where':'C:\\Windows\\System32\\config\\',
    },
    'registry_ntuser': {
        'what': '사용자별 레지스트리 하이브. 각 사용자 프로필마다 1개.',
        'why':  '해당 사용자가 무엇을 실행했는지(UserAssist·RecentDocs), 어떤 폴더를 열었는지(MUICache), 어떤 SW를 설치했는지를 추적할 수 있음.',
        'where':'C:\\Users\\<user>\\NTUSER.DAT',
    },
    'registry_usrclass': {
        'what': '사용자별 COM 등록·셸 확장 + ShellBags (탐색기에서 연 폴더의 위치·시각·정렬방식).',
        'why':  '삭제된 폴더라도 ShellBag에 남아있어 "그 사용자가 이 폴더를 본 적이 있다"를 증명. USB 외장 디스크 탐색 흔적도 여기.',
        'where':'C:\\Users\\<user>\\AppData\\Local\\Microsoft\\Windows\\UsrClass.dat',
    },
    'amcache': {
        'what': 'Windows가 자동 수집하는 PE 파일 실행 인벤토리 (SHA-1 해시 포함).',
        'why':  '"이 시스템에서 한 번이라도 실행된 실행파일"의 데이터베이스. 삭제된 악성코드 흔적도 해시로 남음. 화이트리스팅·VirusTotal 조회의 핵심 소스.',
        'where':'C:\\Windows\\AppCompat\\Programs\\Amcache.hve',
    },
    'eventlog': {
        'what': 'Windows 이벤트 로그 (.evtx) — Security/System/Application/PowerShell/Sysmon 등.',
        'why':  '4624(로그온)·4625(실패)·4688(프로세스 생성)·4104(PowerShell 스크립트 블록)·7045(서비스 생성)·1102(로그 삭제) 등 핵심 이벤트의 원천. 침해의 "공식 기록".',
        'where':'C:\\Windows\\System32\\winevt\\Logs\\',
    },
    'prefetch': {
        'what': 'Windows가 자주 쓰이는 프로그램을 빠르게 로드하기 위해 만드는 캐시 파일 (.pf).',
        'why':  '실행 시각·횟수·참조 파일 목록이 들어있어 "언제 무엇을 실행했나"의 1차 증거. 삭제된 악성코드도 .pf만 남아있으면 실행 흔적 확인 가능.',
        'where':'C:\\Windows\\Prefetch\\',
    },
    'lnk': {
        'what': 'Windows 바로가기 파일. 만든 시점의 원본 파일 메타데이터를 그대로 박아 보관.',
        'why':  '원본 파일이 삭제·이동되어도 LNK에 MAC 타임스탬프·NetBIOS 이름·MAC 주소·볼륨 시리얼이 남음. "어떤 외장 디스크에서 어떤 파일을 열었는가"의 결정적 증거.',
        'where':'C:\\Users\\<user>\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\',
    },
    'jumplist': {
        'what': '작업표시줄/시작메뉴 점프 목록. 각 응용프로그램별 최근 사용 항목.',
        'why':  '응용프로그램이 최근 연 파일 목록 — 워드/엑셀/한글 등에서 어떤 문서를 열었는지 추적. AppID로 어떤 프로그램이었는지 식별 가능.',
        'where':'C:\\Users\\<user>\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\AutomaticDestinations\\',
    },
    'usb_log': {
        'what': 'Windows 장치 설치 로그. USB·디스크가 처음 꽂혔을 때 드라이버 설치 기록.',
        'why':  '"몇 시 몇 분에 어떤 USB가 처음 꽂혔는가"의 시간 기록. SYSTEM 레지스트리의 USBSTOR과 교차 검증.',
        'where':'C:\\Windows\\INF\\setupapi.dev.log',
    },
    'powershell': {
        'what': 'PowerShell 콘솔 명령 히스토리 (대화형 입력 기록).',
        'why':  '사용자/공격자가 직접 친 명령이 평문으로 남음. 인코딩된 PowerShell·다운로드 크래들·Mimikatz 등이 여기서 가장 먼저 발견됨.',
        'where':'C:\\Users\\<user>\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt',
    },
    'mft': {
        'what': 'NTFS 파일시스템의 마스터 파일 테이블. 모든 파일의 메타데이터.',
        'why':  '삭제된 파일도 MFT에 항목이 남아있어 "있었다"를 증명. $STANDARD_INFORMATION vs $FILE_NAME 시각 비교로 타임스톰핑(시각 조작) 탐지.',
        'where':'볼륨 루트의 $MFT (숨김)',
    },
    'usnjrnl': {
        'what': 'NTFS 변경 저널. 파일 생성·삭제·수정의 시간 순 로그.',
        'why':  '단기간(보통 수일~수주)이지만 "정확히 무엇이 언제 만들어지고 삭제됐는가"의 마이크로 단위 기록. 안티포렌식 흔적 추적에 결정적.',
        'where':'볼륨 루트의 $Extend\\$UsnJrnl:$J',
    },
}


def _detect_ps_iocs(commands: list, source_file: str) -> list:
    """PowerShell 명령 목록에서 IOC 패턴 탐지"""
    findings = []
    for line_no, cmd in enumerate(commands, 1):
        for pat, title, mitre, sev, detail in _PS_IOC_PATTERNS:
            try:
                m = re.search(pat, cmd)
            except re.error:
                continue
            if m:
                findings.append({
                    'severity': sev, 'title': title, 'mitre': mitre,
                    'detail': detail,
                    'evidence': cmd[:200] + ('…' if len(cmd) > 200 else ''),
                    'source': f'{source_file}:{line_no}',
                    'category': 'PowerShell IOC',
                })
                break  # 한 명령에 여러 패턴이 잡혀도 첫 매치만
    return findings


def _detect_prefetch_lolbins(parsed_pf: list) -> list:
    """Prefetch 결과에서 LOLBin 사용 탐지"""
    findings = []
    for pf in parsed_pf:
        exe = (pf.get('executable') or '').lower()
        if exe in _LOLBINS:
            mitre, sev, desc = _LOLBINS[exe]
            if sev == 'info': continue  # 너무 흔한 건 제외
            findings.append({
                'severity': sev, 'title': f'{exe} 실행 (LOLBin)', 'mitre': mitre,
                'detail': desc,
                'evidence': f'{pf.get("executable")} — {pf.get("run_count","?")}회 실행, 마지막: {(pf.get("last_runs") or ["?"])[0]}',
                'source': f'Prefetch/{pf.get("filename","?")}',
                'category': 'LOLBin 실행',
            })
    return findings


def _compute_triage_insights(parsed, timeline, inventory, total_files, total_size):
    """파싱 결과로부터 한눈에 보기·통계·의심행위 도출"""
    findings = []
    # PowerShell IOC
    for ps in parsed.get('powershell', []):
        if ps.get('commands'):
            findings += _detect_ps_iocs(ps['commands'], ps.get('filename','PS'))
    # Prefetch LOLBin
    findings += _detect_prefetch_lolbins(parsed.get('prefetch', []))

    # 통계: Prefetch 상위 실행파일
    top_exes = []
    pf_total_runs = 0
    for pf in parsed.get('prefetch', []):
        exe = pf.get('executable')
        rc = pf.get('run_count') or 0
        if exe and isinstance(rc, int):
            top_exes.append((exe, rc))
            pf_total_runs += rc
    top_exes.sort(key=lambda x: -x[1])
    top_exes = top_exes[:10]

    # 통계: USB 고유 장치
    usb_devices = set()
    for ul in parsed.get('usb_log', []):
        for ue in ul.get('usb_events', []):
            usb_devices.add(ue.get('device','')[:120])

    # 통계: 사용자 수 (NTUSER 갯수)
    user_count = len(inventory.get('registry_ntuser', []))

    # 시간범위
    time_range = {'start': None, 'end': None, 'span_text': '-'}
    if timeline:
        # timeline 은 이미 역순 정렬됨 (최신→옛날)
        valid_times = [e['time'] for e in timeline if e.get('time') and not e['time'].startswith('(')]
        if valid_times:
            time_range['start'] = valid_times[-1][:19]
            time_range['end']   = valid_times[0][:19]
            try:
                t0 = _dt.datetime.fromisoformat(time_range['start'].replace(' ','T')[:19])
                t1 = _dt.datetime.fromisoformat(time_range['end'].replace(' ','T')[:19])
                delta = t1 - t0
                if delta.days > 0:
                    time_range['span_text'] = f'{delta.days}일 {delta.seconds//3600}시간'
                elif delta.seconds >= 3600:
                    time_range['span_text'] = f'{delta.seconds//3600}시간 {(delta.seconds%3600)//60}분'
                else:
                    time_range['span_text'] = f'{delta.seconds//60}분 {delta.seconds%60}초'
            except Exception:
                pass

    # 심각도별 카운트
    sev_count = {'critical':0,'high':0,'medium':0,'low':0,'info':0}
    for f in findings:
        sev_count[f['severity']] = sev_count.get(f['severity'],0) + 1
    findings.sort(key=lambda f: {'critical':0,'high':1,'medium':2,'low':3,'info':4}[f['severity']])

    # 한 줄 요약 자동 생성
    bits = []
    if sev_count['critical']: bits.append(f'⚠️ 치명적 {sev_count["critical"]}건')
    if sev_count['high']:     bits.append(f'고위험 {sev_count["high"]}건')
    if sev_count['medium']:   bits.append(f'중간 {sev_count["medium"]}건')
    if pf_total_runs:         bits.append(f'프로그램 실행 {pf_total_runs}회')
    if usb_devices:           bits.append(f'USB 장치 {len(usb_devices)}대')
    if user_count:            bits.append(f'사용자 {user_count}명')
    if time_range['span_text'] != '-':
        bits.append(f'활동 범위 {time_range["span_text"]}')
    summary = ' · '.join(bits) if bits else '의심 활동 없음 — 정상 시스템 가능성'

    return {
        'summary_sentence': summary,
        'findings': findings,
        'severity_counts': sev_count,
        'top_executables': top_exes,
        'pf_total_runs': pf_total_runs,
        'unique_usb_devices': len(usb_devices),
        'usb_device_list': sorted(usb_devices)[:30],
        'user_count': user_count,
        'time_range': time_range,
    }


# ============================================================
# 사람이 읽기 좋은 트리아지 요약 (자연어 + 일별 사건 일지)
# ============================================================
_WEEKDAYS_KO = ['월','화','수','목','금','토','일']


def _humanize_time(iso_time: str) -> str:
    """ISO 시간 → '2024년 3월 15일(금) 오후 2:23' 한국어 포맷"""
    if not iso_time or iso_time.startswith('('): return '시간 불명'
    try:
        s = str(iso_time).replace(' UTC','').replace('Z','').replace('/','-')
        s = s.replace(' ','T')[:19]
        dt = _dt.datetime.fromisoformat(s)
        ampm = '오전' if dt.hour < 12 else '오후'
        h12 = dt.hour % 12
        if h12 == 0: h12 = 12
        return f'{dt.year}년 {dt.month}월 {dt.day}일({_WEEKDAYS_KO[dt.weekday()]}) {ampm} {h12}:{dt.minute:02d}'
    except Exception:
        return str(iso_time)[:19]


def _humanize_date(iso_time: str) -> str:
    """ISO 시간 → '2024년 3월 15일(금)'"""
    if not iso_time: return '시간 불명'
    try:
        s = str(iso_time).replace(' UTC','').replace('Z','').replace('/','-')
        s = s.replace(' ','T')[:19]
        dt = _dt.datetime.fromisoformat(s)
        return f'{dt.year}년 {dt.month}월 {dt.day}일({_WEEKDAYS_KO[dt.weekday()]})'
    except Exception:
        return str(iso_time)[:10]


def _humanize_clock(iso_time: str) -> str:
    """ISO 시간 → '오후 2:23'"""
    if not iso_time: return ''
    try:
        s = str(iso_time).replace(' UTC','').replace('Z','').replace('/','-')
        s = s.replace(' ','T')[:19]
        dt = _dt.datetime.fromisoformat(s)
        ampm = '오전' if dt.hour < 12 else '오후'
        h12 = dt.hour % 12
        if h12 == 0: h12 = 12
        return f'{ampm} {h12}:{dt.minute:02d}'
    except Exception:
        return str(iso_time)[11:16]


def _build_human_summary(insights: dict, parsed: dict, timeline: list) -> dict:
    """사건을 한국어 서술 + 일별 사건일지 + 종합판단으로 가공"""
    sc = insights.get('severity_counts', {})
    tr = insights.get('time_range', {})
    pf_runs = insights.get('pf_total_runs', 0)
    usb = insights.get('unique_usb_devices', 0)
    users = insights.get('user_count', 0)
    tops = insights.get('top_executables', [])

    # ---------- 1) 자연어 서술 (HTML 조각 리스트) ----------
    narrative = []
    if tr.get('start') and tr.get('end'):
        narrative.append({
            'icon': 'bi-calendar-range', 'color': '#00d4ff',
            'text': f'분석 대상 활동은 <b>{_humanize_time(tr["start"])}</b>부터 '
                    f'<b>{_humanize_time(tr["end"])}</b>까지, 약 <b style="color:#00d4ff">{tr["span_text"]}</b>'
                    f' 동안의 흔적입니다.'
        })
    else:
        narrative.append({
            'icon': 'bi-calendar-x', 'color': '#6b7280',
            'text': '시간 정보가 있는 아티팩트를 찾지 못했습니다. '
                    '레지스트리·이벤트 로그 등 추가 수집이 필요합니다.'
        })

    if pf_runs > 0:
        if pf_runs >= 1000:
            scale = '활발히 사용된 PC'
        elif pf_runs >= 100:
            scale = '평범한 일상 사용'
        else:
            scale = '사용량이 적은 시스템'
        narrative.append({
            'icon': 'bi-fast-forward-fill', 'color': '#10b981',
            'text': f'이 기간 동안 시스템에서 프로그램이 <b>총 {pf_runs:,}회</b> 실행되었습니다 — {scale}.'
        })

    if usb > 0:
        warn = ' 자료 반출 가능성을 함께 검토하세요.' if usb >= 3 else ''
        narrative.append({
            'icon': 'bi-usb-symbol', 'color': '#3b82f6',
            'text': f'외부 저장장치 / USB가 <b>{usb}대</b> 연결된 흔적이 있습니다.{warn}'
        })

    if users >= 2:
        narrative.append({
            'icon': 'bi-people-fill', 'color': '#a78bfa',
            'text': f'이 시스템에는 <b>{users}개</b>의 사용자 프로필이 존재합니다 — 공유 PC 또는 다중 사용자 환경입니다.'
        })
    elif users == 1:
        narrative.append({
            'icon': 'bi-person-fill', 'color': '#a78bfa',
            'text': '사용자 프로필이 <b>1개</b>로 단독 사용자 시스템입니다.'
        })

    if sc.get('critical', 0) > 0:
        narrative.append({
            'icon': 'bi-exclamation-octagon-fill', 'color': '#dc2626',
            'text': f'<b style="color:#dc2626">치명적 위협 {sc["critical"]}건</b>이 발견되었습니다. '
                    f'자격증명 탈취·랜섬웨어·로그 삭제 등 적극적 침해 행위의 흔적입니다. '
                    f'시스템 격리와 정식 디스크 이미징을 권고합니다.'
        })
    elif sc.get('high', 0) > 0:
        narrative.append({
            'icon': 'bi-shield-exclamation', 'color': '#ef4444',
            'text': f'<b style="color:#ef4444">고위험 행위 {sc["high"]}건</b>이 탐지되었습니다. '
                    f'LOLBin 악용·원격 다운로드·암호화 도구 사용 등 침해 가능성이 높습니다.'
        })
    elif sc.get('medium', 0) > 0:
        narrative.append({
            'icon': 'bi-info-circle-fill', 'color': '#f59e0b',
            'text': f'<b style="color:#f59e0b">중간 위험 {sc["medium"]}건</b> — 정상 시스템에서도 발생 가능한 활동입니다. '
                    f'사용자 면담·맥락 확인 후 판단하세요.'
        })
    else:
        narrative.append({
            'icon': 'bi-shield-check', 'color': '#22c55e',
            'text': '<b style="color:#22c55e">알려진 의심 패턴은 발견되지 않았습니다.</b> '
                    '다만 표적·내부자 공격은 자동 탐지를 우회하므로 수동 검토를 권장합니다.'
        })

    if tops:
        top3 = ', '.join(
            f'<code style="color:var(--accent)">{e}</code>(<b>{c:,}회</b>)'
            for e, c in tops[:3]
        )
        narrative.append({
            'icon': 'bi-trophy-fill', 'color': '#fbbf24',
            'text': f'가장 자주 실행된 프로그램: {top3}'
        })

    # ---------- 2) 종합 판단 ----------
    crit = sc.get('critical', 0); high = sc.get('high', 0); med = sc.get('medium', 0)
    if crit >= 3:
        verdict = {'level':'critical','color':'#dc2626','title':'🚨 즉각 대응 필요',
                   'message': f'다수의 치명적 침해 지표({crit}건)가 동시 발견. 시스템 격리·전체 디스크 이미징·CSIRT 보고를 권장합니다.'}
    elif crit > 0:
        verdict = {'level':'critical','color':'#dc2626','title':'🚨 침해 가능성 매우 높음',
                   'message': f'치명적 IOC가 {crit}건 탐지되었습니다. 추가 정밀 분석과 격리를 권장합니다.'}
    elif high >= 5:
        verdict = {'level':'high','color':'#ef4444','title':'⚠️ 침해 의심',
                   'message': f'고위험 행위가 {high}건 누적되었습니다. 시간순 맥락 검토 후 격리 여부를 결정하세요.'}
    elif high > 0:
        verdict = {'level':'high','color':'#ef4444','title':'⚠️ 주의 필요',
                   'message': f'고위험 행위 {high}건이 발견되었습니다. 사용자 면담 등으로 정상/비정상을 확인하세요.'}
    elif med > 0:
        verdict = {'level':'medium','color':'#f59e0b','title':'ℹ️ 추가 검토 권장',
                   'message': '의심 가능 패턴이 일부 발견되었지만 정상 시스템에서도 흔히 나타납니다. 사용자 행동 맥락과 함께 판단하세요.'}
    else:
        verdict = {'level':'safe','color':'#22c55e','title':'✅ 명백한 침해 흔적 없음',
                   'message': '자동 탐지 룰에 잡히는 패턴은 없습니다. 다만 표적공격·내부자 위협은 수동 검토가 필요할 수 있습니다.'}

    # ---------- 3) 핵심 사건 (사람용 표) ----------
    key_events = []

    # 3-a) Prefetch LOLBin 실행 — 시간이 있는 경우만
    for pf in parsed.get('prefetch', []):
        exe = (pf.get('executable') or '').lower()
        if exe in _LOLBINS:
            mitre, sev, desc = _LOLBINS[exe]
            if sev == 'info': continue
            for t in (pf.get('last_runs') or [])[:3]:
                key_events.append({
                    'time_iso': t, 'time_human': _humanize_time(t),
                    'date_ko': _humanize_date(t), 'clock_ko': _humanize_clock(t),
                    'category_ko': '프로그램 실행 (의심)',
                    'severity': sev, 'icon': 'bi-fast-forward-fill',
                    'title_ko': f'{exe} 실행',
                    'description': desc,
                    'mitre': mitre,
                    'evidence': f'Prefetch에 기록 ({pf.get("run_count","?")}회 누적)',
                })

    # 3-b) USB 연결
    for ul in parsed.get('usb_log', []):
        for ue in ul.get('usb_events', [])[:50]:
            t = (ue.get('time','') or '').replace('/','-')[:19]
            key_events.append({
                'time_iso': t, 'time_human': _humanize_time(t),
                'date_ko': _humanize_date(t), 'clock_ko': _humanize_clock(t),
                'category_ko': 'USB 연결',
                'severity': 'medium', 'icon': 'bi-usb-symbol',
                'title_ko': 'USB/저장장치 처음 연결',
                'description': (ue.get('device','') or '')[:160],
                'mitre': '', 'evidence': 'setupapi.dev.log',
            })

    # 3-c) LNK 파일 접근
    for lnk in parsed.get('lnk', []):
        t = lnk.get('write_time') or lnk.get('access_time') or lnk.get('create_time')
        if not t or t == '-' or str(t).startswith('('): continue
        key_events.append({
            'time_iso': t, 'time_human': _humanize_time(t),
            'date_ko': _humanize_date(t), 'clock_ko': _humanize_clock(t),
            'category_ko': '파일 접근',
            'severity': 'low', 'icon': 'bi-link-45deg',
            'title_ko': '바로가기로 파일 접근',
            'description': f'대상: {(lnk.get("target") or "?")[:120]}',
            'mitre': '',
            'evidence': lnk.get('filename','LNK'),
        })

    # 3-d) PowerShell IOC — 시간 정보는 없지만 발견 자체가 중요
    for f in insights.get('findings', []):
        if f.get('category') == 'PowerShell IOC':
            key_events.append({
                'time_iso': '', 'time_human': '시간 불명 (콘솔 히스토리)',
                'date_ko': '시간 불명', 'clock_ko': '',
                'category_ko': 'PowerShell 의심 명령',
                'severity': f['severity'], 'icon': 'bi-terminal-fill',
                'title_ko': f['title'],
                'description': f['detail'],
                'mitre': f.get('mitre',''),
                'evidence': f['evidence'][:200],
            })

    # 시간순 정렬 (시간 있는 것 먼저 오래된 순, 시간 없는 건 뒤로)
    def tk(e):
        if not e.get('time_iso'): return (1, _dt.datetime.max)
        try:
            return (0, _dt.datetime.fromisoformat(str(e['time_iso']).replace(' ','T')[:19]))
        except Exception:
            return (1, _dt.datetime.max)
    key_events.sort(key=tk)

    # ---------- 4) 일별 그룹 ----------
    daily = {}
    for e in key_events:
        d = e['date_ko']
        daily.setdefault(d, []).append(e)
    daily_groups = []
    for d, evs in daily.items():
        sev_order = {'critical':4,'high':3,'medium':2,'low':1,'info':0}
        worst = max(evs, key=lambda x: sev_order.get(x['severity'], 0))['severity']
        cat_cnt = {}
        for e in evs:
            cat_cnt[e['category_ko']] = cat_cnt.get(e['category_ko'], 0) + 1
        cat_summary = ', '.join(f'{k} {v}건' for k, v in cat_cnt.items())
        daily_groups.append({
            'date_ko': d, 'count': len(evs), 'worst_severity': worst,
            'category_summary': cat_summary, 'events': evs[:30],
        })
    # 시간 불명은 맨 뒤
    daily_groups.sort(key=lambda g: (g['date_ko'] == '시간 불명', g['date_ko']))

    return {
        'narrative': narrative,
        'verdict': verdict,
        'key_events': key_events[:200],
        'daily_groups': daily_groups,
        'key_event_count': len(key_events),
    }


def _try_parse_pf(data, name):
    try:
        return _parse_prefetch(data, name)
    except Exception as e:
        return {'filename': name, 'error': str(e)}


def _try_parse_lnk(data, name):
    try:
        return _parse_lnk(data, name)
    except Exception as e:
        return {'filename': name, 'error': str(e)}


def _classify_zip_member(filename: str) -> str:
    """ZIP 멤버 경로를 아티팩트 종류로 분류"""
    lo = filename.lower().replace('\\', '/')
    base = lo.rsplit('/', 1)[-1]
    if 'amcache' in base: return 'amcache'
    if base.endswith('.hive') and any(h in base.upper() for h in
            ('SYSTEM','SOFTWARE','SAM','SECURITY','DEFAULT','COMPONENTS','HARDWARE','BCD')):
        return 'registry_hive'
    if base.startswith('ntuser') or base == 'ntuser.dat': return 'registry_ntuser'
    if base.startswith('usrclass') or base == 'usrclass.dat': return 'registry_usrclass'
    if base.endswith('.evtx'): return 'eventlog'
    if base.endswith('.pf'): return 'prefetch'
    if base.endswith('.lnk'): return 'lnk'
    if base.endswith('.automaticdestinations-ms') or base.endswith('.customdestinations-ms'):
        return 'jumplist'
    if 'setupapi' in base and base.endswith('.log'): return 'usb_log'
    if 'consolehost_history' in base or (base.endswith('.txt') and 'powershell' in lo):
        return 'powershell'
    if base == '$mft' or base.lower() == 'mft': return 'mft'
    if '$j' in base or 'usnjrnl' in base: return 'usnjrnl'
    return None


def _analyze_triage_zip(zip_data: bytes, filename: str, progress_cb=None) -> dict:
    """업로드된 ZIP에서 모든 아티팩트 종류를 분류하고 가능한 한 파싱
    progress_cb(current_idx, total, current_filename, current_kind): 진행 콜백
    """
    import io
    inventory = {kind: [] for kind, *_ in _TRIAGE_KINDS}
    parsed = {kind: [] for kind, *_ in _TRIAGE_KINDS}
    timeline = []
    total_files = 0
    total_size = 0
    parse_errors = []

    try:
        zf = zipfile.ZipFile(io.BytesIO(zip_data))
    except zipfile.BadZipFile:
        raise ValueError('잘못된 ZIP 파일')

    all_members = [i for i in zf.infolist() if not i.is_dir() and i.file_size > 0]
    total_count = len(all_members)

    for idx, info in enumerate(all_members, 1):
        total_files += 1
        total_size += info.file_size
        kind = _classify_zip_member(info.filename)
        if progress_cb:
            progress_cb(idx, total_count, info.filename, kind or '미분류')
        if not kind: continue
        inventory[kind].append({
            'path': info.filename,
            'size': info.file_size,
        })
        # 파싱 시도 (개별 파일 100MB 제한)
        if info.file_size > 100 * 1024 * 1024:
            parse_errors.append(f'{info.filename} (>100MB, 파싱 스킵)')
            continue
        try:
            data = zf.read(info.filename)
        except Exception as e:
            parse_errors.append(f'{info.filename}: 압축 해제 실패 — {e}')
            continue
        base = info.filename.rsplit('/', 1)[-1].rsplit('\\', 1)[-1]
        if kind == 'prefetch':
            r = _try_parse_pf(data, base)
            parsed['prefetch'].append(r)
            if 'last_runs' in r:
                for t in r.get('last_runs', []):
                    timeline.append({'time': t, 'source': 'Prefetch',
                                     'event': f'{r.get("executable","?")} 실행', 'icon': 'bi-fast-forward-fill'})
        elif kind == 'lnk':
            r = _try_parse_lnk(data, base)
            parsed['lnk'].append(r)
            for tkey, label in [('write_time','수정'),('create_time','생성'),('access_time','접근')]:
                t = r.get(tkey)
                if t and t != '-' and not t.startswith('('):
                    timeline.append({'time': t, 'source': 'LNK',
                                     'event': f'{label}: {r.get("target","?")[:60]}', 'icon':'bi-link-45deg'})
        elif kind == 'registry_hive' or kind == 'registry_ntuser' or kind == 'registry_usrclass' or kind == 'amcache':
            # registry는 _parse_registry 사용
            try:
                from monitor.views.tools import _parse_registry
                r = _parse_registry(data, base)
                summary = {
                    'filename': base, 'size': info.file_size,
                    'total_keys': r.get('total_keys', 0),
                    'total_values': r.get('total_values', 0),
                    'findings': len(r.get('findings', [])),
                    'format': r.get('format', '?'),
                }
                parsed[kind].append(summary)
                # 포렌식 발견사항 중 시각 필드가 있으면 타임라인에 추가
                for f in r.get('findings', [])[:50]:
                    for v in f.get('values', []):
                        if v.get('t') in ('REG_QWORD','RegBin') and any(
                            k in v.get('n','').lower() for k in
                            ('time','date','lastwrite','installed','firstconn','lastconn')):
                            timeline.append({
                                'time': v.get('v','')[:30],
                                'source': f'Registry/{base}',
                                'event': f'{f.get("category_ko","?")}: {v.get("n","?")}',
                                'icon': 'bi-diagram-2-fill',
                            })
                    if f.get('ts'):
                        timeline.append({
                            'time': f['ts'], 'source': f'Registry/{base}',
                            'event': f.get('category_ko','?') + ' 키 마지막 수정',
                            'icon':'bi-diagram-2-fill',
                        })
            except Exception as e:
                parsed[kind].append({'filename': base, 'error': str(e)})
                parse_errors.append(f'{base}: {e}')
        elif kind == 'eventlog':
            # EVTX 파싱은 python-evtx 필요 - 헤더만 인식
            evtx_count = data.count(b'ElfChnk\x00')
            parsed['eventlog'].append({
                'filename': base, 'size': info.file_size,
                'estimated_chunks': evtx_count,
                'note': 'EVTX 헤더 인식됨 (전체 파싱은 python-evtx 필요)',
            })
        elif kind == 'usb_log':
            # setupapi.dev.log 텍스트 파싱
            text = data.decode('utf-16', errors='replace')
            if 'USB' not in text and 'STORAGE' not in text.upper():
                text = data.decode('latin1', errors='replace')
            usb_events = []
            for m in re.finditer(
                    r'>>>\s*\[(.+?)\]\s*\n>>>\s*Section start (\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}\.\d+)',
                    text):
                dev, ts = m.group(1).strip(), m.group(2)
                if 'USB' in dev.upper() or 'STORAGE' in dev.upper() or 'DISK' in dev.upper():
                    usb_events.append({'device': dev, 'time': ts})
                    timeline.append({'time': ts.replace('/','-')[:19], 'source':'setupapi',
                                     'event': f'USB 장치 설치: {dev[:60]}', 'icon':'bi-usb-symbol'})
            parsed['usb_log'].append({
                'filename': base, 'size': info.file_size,
                'usb_events': usb_events[:100], 'event_count': len(usb_events),
            })
        elif kind == 'powershell':
            text = data.decode('utf-8', errors='replace')
            lines = [l.strip() for l in text.splitlines() if l.strip()]
            parsed['powershell'].append({
                'filename': base, 'size': info.file_size,
                'command_count': len(lines),
                'commands': lines[:200],
            })
        elif kind == 'jumplist':
            parsed['jumplist'].append({
                'filename': base, 'size': info.file_size,
                'note': 'OLECF 컨테이너 — DestList 스트림 파싱은 별도 도구 필요',
            })
        elif kind == 'mft' or kind == 'usnjrnl':
            parsed[kind].append({
                'filename': base, 'size': info.file_size,
                'note': '대용량 — /tools/diskimg 헥스 미리보기 사용 권장',
            })

    # 타임라인 정렬
    def time_key(e):
        t = e.get('time', '')
        try:
            return _dt.datetime.fromisoformat(t.replace(' UTC','').replace(' ','T')[:19])
        except Exception:
            return _dt.datetime.min
    timeline.sort(key=time_key, reverse=True)

    # 의심 행위·통계·요약 산출
    insights = _compute_triage_insights(parsed, timeline, inventory, total_files, total_size)

    # 타임라인 항목에 severity 표시 (LOLBin 실행/IOC 발견 사항을 시각 매칭)
    finding_evidence = set()
    for f in insights['findings']:
        finding_evidence.add(f.get('evidence','')[:80])
    for e in timeline:
        e['severity'] = 'info'
        ev = e.get('event','')[:80]
        # Prefetch 이벤트가 LOLBin인지
        exe_match = re.match(r'^(\S+\.exe)\s', ev, re.I)
        if exe_match and exe_match.group(1).lower() in _LOLBINS:
            mitre, sev, _ = _LOLBINS[exe_match.group(1).lower()]
            if sev != 'info':
                e['severity'] = sev
                e['mitre'] = mitre

    human_summary = _build_human_summary(insights, parsed, timeline)

    return {
        'filename': filename,
        'file_size': len(zip_data),
        'total_files': total_files,
        'total_uncompressed': total_size,
        'kinds': [(k, label, icon, color, len(inventory[k])) for k, label, icon, color in _TRIAGE_KINDS],
        'inventory': inventory,
        'parsed': parsed,
        'timeline': timeline[:500],
        'timeline_total': len(timeline),
        'parse_errors': parse_errors[:50],
        'insights': insights,
        'artifact_explain': _ARTIFACT_EXPLAIN,
        'human_summary': human_summary,
    }


def _triage_job(data, filename, _job_id=None):
    """트리아지 ZIP 백그라운드 분석"""
    from monitor.views.tools_extra5 import _job_log
    _job_log(_job_id, f'ZIP 압축 해제 시작 ({len(data)//1024} KB)', 2)
    try:
        def cb(idx, total, fname, kind):
            pct = int((idx / max(total, 1)) * 90) + 5
            _job_log(_job_id, f'[{idx}/{total}] {fname[-60:]}  ({kind})', pct)
        result = _analyze_triage_zip(data, filename, progress_cb=cb)
        present = [k for k, *_, c in result['kinds'] if c > 0]
        _job_log(_job_id, f'✅ 완료: {len(present)}/{len(result["kinds"])} 종류, 타임라인 {len(result["timeline"])}건', 100)
        _save_log('triage','트리아지 ZIP 분석', filename, len(data),
                  f"발견 {len(present)}/{len(result['kinds'])} 종류, 타임라인 {len(result['timeline'])}건",
                  {'kinds': len(present), 'timeline_count': len(result['timeline'])})
        return result
    except Exception as e:
        return {'error': f'분석 오류: {e}'}


@bp.route('/triage/result/<job_id>')
def triage_result(job_id):
    """백그라운드로 처리된 트리아지 결과를 triage.html 사람용 화면으로 표시"""
    from monitor.views.tools_extra5 import _JOB_STORE, _JOB_LOCK
    from flask import redirect
    with _JOB_LOCK:
        j = _JOB_STORE.get(job_id)
    if not j:
        return redirect('/tools/triage')
    if j['status'] != 'completed' or not j.get('result'):
        # 아직 진행 중이거나 실패 → 잡 상세로
        return redirect(f'/tools/jobs/{job_id}')
    res = j['result']
    if isinstance(res, dict) and res.get('error'):
        return render_template('tools/triage.html', result=None, error=res['error'])
    return render_template('tools/triage.html', result=res, error=None)


@bp.route('/triage', methods=['GET','POST'])
def triage_tool():
    result = error = None; share_token = None
    if request.method == 'POST':
        f = request.files.get('file')
        if not f or not f.filename:
            error = '파일 선택 필요 (트리아지 ZIP)'
        else:
            data = f.read()
            # 작은 ZIP(<5MB)은 동기, 큰 것은 백그라운드
            if len(data) < 5 * 1024 * 1024 and request.form.get('mode') != 'background':
                try:
                    result = _analyze_triage_zip(data, f.filename)
                    present = [k for k, *_, c in result['kinds'] if c > 0]
                    share_token = _save_log(
                        'triage','트리아지 ZIP 분석', f.filename, len(data),
                        f"발견 {len(present)}/{len(result['kinds'])} 종류, 타임라인 {len(result['timeline'])}건",
                        {'kinds': len(present), 'timeline_count': len(result['timeline'])})
                except Exception as e:
                    error = f'분석 오류: {e}'
            else:
                # 백그라운드 작업 등록
                from monitor.views.tools_extra5 import _new_job
                job_id = _new_job(f'Triage: {f.filename} ({len(data)//1024}KB)',
                                  _triage_job, data, f.filename)
                from flask import redirect
                return redirect(f'/tools/jobs/{job_id}')
    return render_template('tools/triage.html', result=result, error=error,
                           share_token=share_token)


# ============================================================
# 로컬 스크립트 체크섬 비교
# ============================================================
import hashlib as _hashlib

# 마스터 체크섬 테이블 (파일 변경 시 함께 업데이트)
_KNOWN_CHECKSUMS = {
    'forensiclab_ram_dumper.py':         ('B0D916E64B7FEE5EC91313E598C67EB189CDAE248E394C3D44A7C9EE650576DB', 5625),
    'forensiclab_triage_collector.py':   ('3E1CF0AAAD5BE877F56664CDDF548FC04F3B86E2B9992A9B74341587B5207145', 7203),
    'forensiclab_browser_artifacts.py':  ('CC833EF297CE521525281D8C8816636EC4498CE6BD45CAAFCE70DD5FAA31B671', 8708),
    'forensiclab_registry_collector.py': ('623221B8AF7C56473D818D9F55E01DE3B3607FA1F9D91D13ABC374822C34EBAB', 4918),
    'forensiclab_disk_imager.py':        ('77D5B72C4BFD01DEEFED5B3289B2F55A6A6C3992A2CF97E8C18FCE85485058F3', 4020),
    'forensiclab_usb_history.py':        ('51349E375B210FDC7CD206A027E83BEB3B1EAB66842D35A3608367CD05DB361F', 6111),
    'forensiclab_eventlog_collector.py': ('084CC30E9C85CC7EFC10103F633128730CF4BD41725FFC8676FF917A48FAC63E', 5256),
    'forensiclab_mbr_repair.py':         ('A32AF73503E2BBAD977C5D9E44397290A7D68672E37F8C1DC87DDB3B1FBB4B04', 15589),
}


@bp.route('/verify', methods=['GET','POST'])
def verify_tool():
    """업로드된 스크립트의 SHA-256을 마스터 테이블과 비교"""
    result = error = None
    if request.method == 'POST':
        f = request.files.get('file')
        manual_hash = (request.form.get('manual_hash') or '').strip().upper()
        if not f or not f.filename:
            error = '검증할 스크립트 파일 선택 필요'
        else:
            data = f.read()
            sha256 = _hashlib.sha256(data).hexdigest().upper()
            md5    = _hashlib.md5(data).hexdigest().upper()
            sha1   = _hashlib.sha1(data).hexdigest().upper()
            size   = len(data)
            # 마스터 테이블 조회 (파일명 + 해시 둘 다 확인)
            known = _KNOWN_CHECKSUMS.get(f.filename)
            expected_sha = expected_size = None
            matched_filename = matched_hash = False
            verdict = '알 수 없음'
            verdict_color = 'gray'
            if known:
                expected_sha, expected_size = known[0].upper(), known[1]
                matched_filename = True
                if sha256 == expected_sha and size == expected_size:
                    matched_hash = True
                    verdict = '검증 성공 — 변조되지 않은 원본 스크립트'
                    verdict_color = 'green'
                else:
                    verdict = '경고 — 파일명은 일치하나 해시가 다름 (변조 또는 버전 불일치)'
                    verdict_color = 'red'
            else:
                # 파일명으로는 못 찾았지만 해시로 역추적
                for known_name, (known_sha, known_size) in _KNOWN_CHECKSUMS.items():
                    if known_sha.upper() == sha256:
                        verdict = f'해시 일치 — 이 파일은 원래 {known_name} (이름이 변경됨)'
                        verdict_color = 'amber'
                        expected_sha = known_sha
                        expected_size = known_size
                        matched_hash = True
                        break
                else:
                    verdict = '미등록 파일 — 마스터 체크섬 테이블에 없습니다'
                    verdict_color = 'gray'
            # 수동 해시 비교
            manual_match = None
            if manual_hash:
                manual_norm = manual_hash.replace(' ', '').replace(':', '').upper()
                manual_match = (manual_norm == sha256 or manual_norm == md5 or manual_norm == sha1)
            result = {
                'filename': f.filename, 'size': size,
                'sha256': sha256, 'md5': md5, 'sha1': sha1,
                'expected_sha': expected_sha, 'expected_size': expected_size,
                'matched_filename': matched_filename, 'matched_hash': matched_hash,
                'verdict': verdict, 'verdict_color': verdict_color,
                'manual_hash': manual_hash, 'manual_match': manual_match,
                'known_list': sorted(_KNOWN_CHECKSUMS.keys()),
            }
    return render_template('tools/verify.html', result=result, error=error,
                           known_checksums=_KNOWN_CHECKSUMS)


@bp.route('/scripts/<name>')
def download_script(name):
    allowed = {
        'forensiclab_ram_dumper.py',
        'forensiclab_triage_collector.py',
        'forensiclab_browser_artifacts.py',
        'forensiclab_registry_collector.py',
        'forensiclab_disk_imager.py',
        'forensiclab_usb_history.py',
        'forensiclab_eventlog_collector.py',
        'forensiclab_mbr_repair.py',
        'checksums.txt',
    }
    if name not in allowed:
        abort(404)
    return send_from_directory(_SCRIPTS_DIR, name, as_attachment=True)
