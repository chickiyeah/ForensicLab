#!/usr/bin/env python3
"""
ForensicLab RAM Dumper
======================
실행 중인 시스템의 물리 메모리를 덤프합니다.

지원 OS:
  - Windows : WinPmem 자동 다운로드 권장 (관리자 권한 필요)
  - Linux   : /proc/kcore 또는 LiME 모듈 활용 (root 권한 필요)
  - macOS   : osxpmem (kext 서명 필요 — Big Sur 이전 권장)

사용:
  python forensiclab_ram_dumper.py --output ./mem.raw
  python forensiclab_ram_dumper.py --output ./mem.lime --format lime  (Linux 전용)

면책:
  본 스크립트는 본인 소유 또는 위임받은 시스템에서만 사용하세요.
  메모리 덤프에는 비밀번호·암호화 키·세션 데이터가 평문으로 포함됩니다.
"""
import argparse
import os
import sys
import platform
import subprocess
import shutil
import urllib.request
import hashlib
import time
from pathlib import Path


WINPMEM_URL = 'https://github.com/Velocidex/WinPmem/releases/download/v4.0.rc1/winpmem_mini_x64_rc2.exe'


def banner():
    print('=' * 70)
    print('  ForensicLab RAM Dumper v1.0')
    print('  ForensicLab @ http://10.8.0.17:405')
    print('=' * 70)


def confirm():
    print()
    print('  ⚠️ 메모리 덤프에는 비밀번호·암호화 키·세션 토큰이 평문으로 포함됩니다.')
    print('  ⚠️ 본인 소유 또는 위임받은 시스템에서만 실행하세요.')
    print()
    ans = input('  계속하려면 YES 를 정확히 입력하세요: ')
    return ans == 'YES'


def dump_windows(out_path: Path):
    if not _is_admin_windows():
        print('  ✗ 관리자 권한이 필요합니다. 우클릭 → 관리자 권한으로 실행.')
        return False
    work = Path(os.environ.get('TEMP', '.')) / 'forensiclab_winpmem.exe'
    if not work.exists():
        print(f'  → WinPmem 다운로드 중... ({WINPMEM_URL})')
        try:
            urllib.request.urlretrieve(WINPMEM_URL, work)
        except Exception as e:
            print(f'  ✗ 다운로드 실패: {e}')
            print('  수동 다운로드: https://github.com/Velocidex/WinPmem/releases')
            return False
    print(f'  → 덤프 시작: {out_path}')
    rc = subprocess.call([str(work), str(out_path)])
    return rc == 0


def dump_linux(out_path: Path, fmt: str = 'raw'):
    if os.geteuid() != 0:
        print('  ✗ root 권한이 필요합니다. sudo로 재실행하세요.')
        return False
    if fmt == 'lime':
        lime = shutil.which('insmod')
        print('  → LiME 모듈 사용을 권장합니다 (https://github.com/504ensicsLabs/LiME).')
        print('     git clone https://github.com/504ensicsLabs/LiME')
        print('     cd LiME/src && make')
        print('     sudo insmod lime-$(uname -r).ko "path={} format=lime"'.format(out_path))
        return False
    # /proc/kcore 또는 /dev/mem 시도
    sources = ['/proc/kcore', '/dev/mem', '/dev/fmem']
    src = next((s for s in sources if os.path.exists(s) and os.access(s, os.R_OK)), None)
    if not src:
        print('  ✗ /proc/kcore · /dev/mem · /dev/fmem 모두 접근 불가.')
        print('  LiME 커널 모듈 또는 AVML(https://github.com/microsoft/avml)을 사용하세요.')
        return False
    print(f'  → {src} → {out_path}')
    h = hashlib.sha256()
    total = 0
    t0 = time.time()
    with open(src, 'rb') as r, open(out_path, 'wb') as w:
        while True:
            try:
                chunk = r.read(4 * 1024 * 1024)
            except Exception:
                break
            if not chunk:
                break
            w.write(chunk)
            h.update(chunk)
            total += len(chunk)
            if total % (256 * 1024 * 1024) < 4 * 1024 * 1024:
                mbps = (total / 1024 / 1024) / max(time.time() - t0, 1)
                print(f'    {total // 1024 // 1024} MB 누적 ({mbps:.1f} MB/s)')
    print(f'  ✓ 완료: {total:,} bytes')
    print(f'    SHA256: {h.hexdigest()}')
    return True


def dump_macos(out_path: Path):
    print('  → macOS는 osxpmem.app 사용을 권장합니다.')
    print('    1. https://github.com/google/rekall/releases 에서 osxpmem 다운로드')
    print('    2. xattr -dr com.apple.quarantine osxpmem.app')
    print('    3. sudo osxpmem.app/osxpmem -o ' + str(out_path))
    print()
    print('  macOS Big Sur 이상은 시스템 무결성 보호로 kext 로드가 제한됩니다.')
    return False


def _is_admin_windows():
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def main():
    banner()
    p = argparse.ArgumentParser()
    p.add_argument('--output', '-o', default='memory_dump.raw',
                   help='출력 파일 (기본: memory_dump.raw)')
    p.add_argument('--format', '-f', choices=['raw', 'lime'], default='raw',
                   help='출력 포맷 (Linux LiME 전용)')
    p.add_argument('--yes', action='store_true', help='면책 확인 자동 동의')
    args = p.parse_args()
    if not args.yes and not confirm():
        print('  취소됨.')
        return 1
    out = Path(args.output).resolve()
    out.parent.mkdir(parents=True, exist_ok=True)
    osname = platform.system()
    print(f'\n  플랫폼: {osname} {platform.release()}')
    ok = False
    if osname == 'Windows':
        ok = dump_windows(out)
    elif osname == 'Linux':
        ok = dump_linux(out, args.format)
    elif osname == 'Darwin':
        ok = dump_macos(out)
    else:
        print(f'  ✗ 지원하지 않는 OS: {osname}')
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main())
