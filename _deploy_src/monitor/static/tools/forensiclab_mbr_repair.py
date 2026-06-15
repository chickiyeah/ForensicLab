#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════════════════════════╗
║         ForensicLab — MBR 복구 스크립트 v1.0                   ║
║         https://github.com/forensiclab                          ║
╠══════════════════════════════════════════════════════════════════╣
║  ※ 면책 조항 (Disclaimer)                                       ║
║                                                                  ║
║  이 스크립트의 사용으로 인해 발생하는 데이터 손실, 파일 시스템  ║
║  손상, 운영체제 부팅 불가, 하드웨어 손상 등 모든 직·간접적      ║
║  손해에 대한 법적·도의적 책임은 전적으로 사용자 본인에게        ║
║  있습니다. ForensicLab 및 스크립트 제공자는 어떠한 책임도       ║
║  지지 않습니다.                                                  ║
║                                                                  ║
║  사용 전 반드시 디스크 전체 이미지를 백업하세요.                ║
╚══════════════════════════════════════════════════════════════════╝

[사용법]
  Windows (반드시 관리자 권한):
    python forensiclab_mbr_repair.py

  Linux / macOS (반드시 root 권한):
    sudo python3 forensiclab_mbr_repair.py

[필요 조건]
  Python 3.6 이상, 표준 라이브러리만 사용 (별도 설치 없음)
"""

import os, sys, struct, re, platform, subprocess, json

IS_WIN = platform.system() == 'Windows'

# ── ANSI 색상 ────────────────────────────────────────────────────────────────
def _init_color():
    if IS_WIN:
        try:
            import ctypes
            ctypes.windll.kernel32.SetConsoleMode(
                ctypes.windll.kernel32.GetStdHandle(-11), 7)
            return True
        except Exception:
            return False
    return True

USE_COLOR = _init_color()

def c(code, text):
    return f'\033[{code}m{text}\033[0m' if USE_COLOR else text

RED    = lambda t: c('91', t)
YELLOW = lambda t: c('93', t)
GREEN  = lambda t: c('92', t)
CYAN   = lambda t: c('96', t)
DIM    = lambda t: c('90', t)
BOLD   = lambda t: c('1',  t)

# ── 파티션 타입 테이블 ────────────────────────────────────────────────────────
PTYPES = {
    0x00:'Empty',    0x01:'FAT12',        0x04:'FAT16 <32M', 0x05:'Extended',
    0x06:'FAT16',    0x07:'NTFS/exFAT',   0x0B:'FAT32',      0x0C:'FAT32(LBA)',
    0x0E:'FAT16(LBA)',0x0F:'Ext(LBA)',    0x82:'Linux Swap', 0x83:'Linux',
    0x8E:'Linux LVM',0xEE:'GPT Prot.',    0xEF:'EFI System',
}

def fmt_bytes(b):
    b = int(b or 0)
    for u in ['B','KB','MB','GB','TB']:
        if b < 1024:
            return f'{b:.1f} {u}'
        b /= 1024
    return f'{b:.1f} PB'

# ── 디스크 목록 ──────────────────────────────────────────────────────────────
def list_disks():
    if IS_WIN:
        return _list_disks_win()
    return _list_disks_linux()

def _list_disks_win():
    disks = []
    try:
        r = subprocess.run(
            ['wmic', 'diskdrive', 'get',
             'Index,DeviceID,Size,Model,MediaType', '/format:csv'],
            capture_output=True, text=True, timeout=10)
        for line in r.stdout.strip().splitlines():
            cols = line.strip().split(',')
            # csv 헤더: Node,DeviceID,Index,MediaType,Model,Size
            if len(cols) < 5 or not cols[1].startswith('\\\\.\\'):
                continue
            try:
                disks.append({
                    'path':  cols[1].strip(),
                    'model': cols[4].strip() if len(cols) > 4 else '',
                    'size':  int(cols[5].strip()) if len(cols) > 5 and cols[5].strip().isdigit() else 0,
                    'media': cols[3].strip() if len(cols) > 3 else '',
                })
            except Exception:
                continue
    except Exception:
        pass

    # fallback: PhysicalDrive0..9 순서로 열려보기
    if not disks:
        for i in range(10):
            path = f'\\\\.\\PhysicalDrive{i}'
            try:
                with open(path, 'rb') as f:
                    f.read(512)
                disks.append({'path': path, 'model': f'PhysicalDrive{i}',
                               'size': 0, 'media': ''})
            except PermissionError:
                disks.append({'path': path, 'model': f'PhysicalDrive{i} (권한없음)',
                               'size': 0, 'media': ''})
            except OSError:
                break
    return disks

def _list_disks_linux():
    disks = []
    try:
        r = subprocess.run(
            ['lsblk', '-J', '-b', '-d',
             '-o', 'NAME,SIZE,MODEL,RM,TRAN'],
            capture_output=True, text=True, timeout=5)
        data = json.loads(r.stdout)
        for dev in data.get('blockdevices', []):
            disks.append({
                'path':      f'/dev/{dev["name"]}',
                'model':     (dev.get('model') or '').strip() or 'Unknown',
                'size':      int(dev.get('size') or 0),
                'removable': str(dev.get('rm', '0')) == '1',
                'tran':      (dev.get('tran') or '?').strip(),
            })
    except Exception:
        import glob
        for p in sorted(glob.glob('/dev/sd?') + glob.glob('/dev/vd?') + glob.glob('/dev/hd?')):
            disks.append({'path': p, 'model': '', 'size': 0, 'removable': False, 'tran': '?'})
    return disks

def get_system_disk():
    """OS가 올라간 디스크 경로 반환."""
    if IS_WIN:
        # 간단히 PhysicalDrive0 을 시스템 디스크로 가정
        # (더 정확하게는 C: 드라이브 → 물리 디스크 매핑 필요)
        return '\\\\.\\PhysicalDrive0'
    try:
        with open('/proc/mounts') as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 2 and parts[1] == '/':
                    src = parts[0]
                    if src.startswith('/dev/'):
                        return re.sub(r'(p?\d+)$', '', src)
    except Exception:
        pass
    return '/dev/sda'

# ── MBR / VBR 스캔 ──────────────────────────────────────────────────────────
def read_current_mbr(f):
    f.seek(0)
    mbr = f.read(512)
    if len(mbr) < 512:
        return None, []
    valid = mbr[510:512] == b'\x55\xAA'
    parts = []
    for i in range(4):
        e = mbr[446 + i*16: 462 + i*16]
        pt  = e[4]
        ls  = struct.unpack('<I', e[8:12])[0]
        lsz = struct.unpack('<I', e[12:16])[0]
        if ls == 0 and lsz == 0:
            continue
        parts.append({
            'slot': i + 1,
            'type': PTYPES.get(pt, f'Unknown(0x{pt:02X})'),
            'lba_start': ls, 'lba_size': lsz,
            'size_mb': round((lsz * 512) / (1024 ** 2), 1),
        })
    return valid, parts

def smart_scan(f, file_size):
    """VBR 시그니처 스캔 — 백업 섹터 필터링 포함."""
    partitions = []
    chunk_size  = 10 * 1024 * 1024
    f.seek(0)
    offset = 0

    while offset < file_size and len(partitions) < 4:
        f.seek(offset)
        chunk = f.read(chunk_size + 512)
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
                if vbr_abs >= 0 and vbr_abs % 512 == 0:
                    lba = vbr_abs // 512
                    f.seek(vbr_abs)
                    sector = f.read(512)
                    if len(sector) == 512 and sector[510:512] == b'\x55\xAA':
                        sz = (struct.unpack('<I', sector[0x20:0x24])[0]
                              if name == 'FAT32'
                              else struct.unpack('<Q', sector[0x28:0x30])[0])
                        if 0 < sz < 0xFFFFFFFF:
                            is_bak = any(
                                (p['name'] == 'FAT32' and lba == p['lba'] + 6) or
                                (p['name'] == 'NTFS'  and abs(lba - (p['lba'] + p['size'])) <= 1)
                                for p in partitions)
                            if not is_bak and not any(p['lba'] == lba for p in partitions):
                                partitions.append({
                                    'name': name, 'type': p_type,
                                    'lba': lba, 'size': sz,
                                    'size_mb': round((sz * 512) / (1024 ** 2), 1),
                                })
                si = idx + 1
        offset += chunk_size

    return sorted(partitions, key=lambda x: x['lba'])

def write_mbr(path, partitions):
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

def get_file_size(path):
    try:
        return os.path.getsize(path)
    except OSError:
        # Windows 물리 드라이브는 getsize 불가 → 끝까지 스캔
        return 2 ** 40  # 1 TB 상한

# ── 메인 ─────────────────────────────────────────────────────────────────────
def main():
    # 헤더
    print(CYAN(BOLD('╔══════════════════════════════════════════════════════════╗')))
    print(CYAN(BOLD('║      ForensicLab — MBR 복구 스크립트 v1.0               ║')))
    print(CYAN(BOLD('╚══════════════════════════════════════════════════════════╝')))
    print()
    print(RED(BOLD('⚠  면책 조항')))
    print(RED('이 스크립트 사용으로 인한 모든 데이터 손실·시스템 손상의'))
    print(RED('책임은 전적으로 사용자 본인에게 있습니다.'))
    print()

    # 디스크 목록
    print(CYAN('[*] 디스크 탐색 중...'))
    disks     = list_disks()
    sys_disk  = get_system_disk()

    if not disks:
        print(RED('[-] 디스크를 찾을 수 없습니다. 관리자/root 권한으로 실행하세요.'))
        sys.exit(1)

    print()
    print(f"  {'#':<4} {'경로':<28} {'크기':<10} 모델")
    print(f"  {'-' * 65}")
    for i, d in enumerate(disks):
        is_sys   = d['path'] == sys_disk
        size_str = fmt_bytes(d['size']) if d.get('size') else '알수없음'
        sys_flag = RED('  ← SYSTEM (선택 불가)') if is_sys else ''
        print(f"  {i:<4} {d['path']:<28} {size_str:<10} {d.get('model','')}{sys_flag}")
    print()

    # 디스크 선택
    while True:
        sel = input(YELLOW('대상 디스크 번호 또는 경로 직접 입력 (q=종료): ')).strip()
        if sel.lower() == 'q':
            print(DIM('종료합니다.'))
            sys.exit(0)

        if sel.isdigit() and 0 <= int(sel) < len(disks):
            target = disks[int(sel)]['path']
        else:
            target = sel

        if target == sys_disk:
            print(RED('[-] 시스템 디스크는 수정할 수 없습니다. 다시 선택하세요.'))
            continue
        break

    print()
    print(CYAN(f'[*] 대상: {target}'))
    print(CYAN('[*] MBR 스캔 중 (시간이 걸릴 수 있습니다)...'))

    try:
        fsize = get_file_size(target)
        with open(target, 'rb') as f:
            curr_valid, curr_parts = read_current_mbr(f)
            found = smart_scan(f, fsize)
    except PermissionError:
        print(RED('[-] 권한 오류: 관리자(Windows) 또는 sudo(Linux)로 실행하세요.'))
        sys.exit(1)
    except FileNotFoundError:
        print(RED(f'[-] 장치를 찾을 수 없습니다: {target}'))
        sys.exit(1)
    except Exception as e:
        print(RED(f'[-] 스캔 오류: {e}'))
        sys.exit(1)

    # 현재 MBR 상태
    sig_str = GREEN('유효 ✓') if curr_valid else RED('손상 ✗')
    print()
    print(YELLOW(f'[현재 MBR] Boot Signature: {sig_str}'))
    if curr_parts:
        print(f"  {'슬롯':<5} {'타입':<20} {'LBA 시작':>12} {'LBA 크기':>12} {'용량':>10}")
        print(f"  {'-'*65}")
        for p in curr_parts:
            print(f"  {p['slot']:<5} {p['type']:<20} {p['lba_start']:>12,} {p['lba_size']:>12,} {p['size_mb']:>9} MB")
    else:
        print(DIM('  파티션 테이블 비어있음 또는 손상됨'))

    # 스캔 결과
    print()
    print(CYAN(f'[VBR 스캔] {len(found)}개 파티션 발견'))
    if not found:
        print(RED('[-] 복구 가능한 파티션 시그니처를 찾지 못했습니다.'))
        print(DIM('    파일 시스템이 심각하게 손상되었거나 지원되지 않는 형식입니다.'))
        sys.exit(0)

    print(f"  {'#':<4} {'파일시스템':<12} {'LBA 시작':>12} {'LBA 크기':>12} {'용량':>10}")
    print(f"  {'-'*55}")
    for i, p in enumerate(found):
        print(f"  {i+1:<4} {p['name']:<12} {p['lba']:>12,} {p['size']:>12,} {p['size_mb']:>9} MB")

    # 최종 경고 및 확인
    print()
    print(RED(BOLD('══ 최종 경고 ═══════════════════════════════════════════')))
    print(RED(f'위 파티션 정보를 [{target}] 의 MBR에 기록합니다.'))
    print(RED('이 작업은 되돌릴 수 없으며 모든 책임은 사용자에게 있습니다.'))
    print(RED('═' * 55))
    print()
    confirm = input(YELLOW("진행하려면 'YES' 를 정확히 입력하세요 (그 외 입력 시 취소): ")).strip()

    if confirm != 'YES':
        print(DIM('[취소됨] 디스크가 변경되지 않았습니다.'))
        sys.exit(0)

    # 쓰기
    try:
        write_mbr(target, found)
        print()
        print(GREEN(f'[✓] MBR 복구 완료 — {len(found)}개 파티션을 재건했습니다.'))
        print(DIM(f'    대상: {target}'))
    except PermissionError:
        print(RED('[-] 쓰기 권한 오류: 관리자/sudo 권한이 필요합니다.'))
        sys.exit(1)
    except Exception as e:
        print(RED(f'[-] 쓰기 오류: {e}'))
        sys.exit(1)

if __name__ == '__main__':
    main()
