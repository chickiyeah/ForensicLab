#!/usr/bin/env python3
"""
ForensicLab Volatility 3 Collector
==================================
실행 중인 시스템의 물리 메모리를 수집한 뒤, Volatility 3 가 설치돼 있으면
표준 플러그인 세트를 자동 실행해 결과를 한 폴더에 저장합니다.

지원 OS:
  - Windows : WinPmem 자동 다운로드 (관리자 권한 필요)
  - Linux   : AVML 자동 다운로드 또는 /proc/kcore (root 권한 필요)
  - macOS   : osxpmem 안내 (kext 서명 제약)

사용:
  # 수집 + 자동 분석
  python forensiclab_vol3_collector.py --output ./mem.raw --out-dir ./vol3_out
  # 이미 있는 덤프만 분석
  python forensiclab_vol3_collector.py --analyze ./mem.raw --out-dir ./vol3_out
  # Volatility 실행 파일 경로 지정
  python forensiclab_vol3_collector.py --analyze mem.raw --vol "python -m volatility3"

면책:
  본인 소유 또는 위임받은 시스템에서만 사용하세요. 메모리 덤프에는
  비밀번호·암호화 키·세션 토큰이 평문으로 포함됩니다.
"""
import argparse
import hashlib
import os
import platform
import shutil
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

WINPMEM_URL = 'https://github.com/Velocidex/WinPmem/releases/download/v4.0.rc1/winpmem_mini_x64_rc2.exe'
AVML_URL = 'https://github.com/microsoft/avml/releases/download/v0.14.0/avml'

# OS 별 Volatility 3 표준 플러그인 세트
PLUGINS = {
    'windows': [
        'windows.info', 'windows.pslist', 'windows.pstree', 'windows.psscan',
        'windows.cmdline', 'windows.dlllist', 'windows.netscan', 'windows.netstat',
        'windows.svcscan', 'windows.malfind', 'windows.registry.hivelist',
    ],
    'linux': [
        'linux.pslist', 'linux.pstree', 'linux.psscan', 'linux.bash',
        'linux.lsof', 'linux.check_syscall', 'linux.malfind',
    ],
    'mac': [
        'mac.pslist', 'mac.pstree', 'mac.netstat', 'mac.lsof', 'mac.malfind',
    ],
}


def banner():
    print('=' * 70)
    print('  ForensicLab Volatility 3 Collector v1.0')
    print('  ForensicLab @ https://forensic.jvision.org')
    print('=' * 70)


def confirm():
    print()
    print('  ⚠️ 메모리 덤프에는 비밀번호·암호화 키·세션 토큰이 평문으로 포함됩니다.')
    print('  ⚠️ 본인 소유 또는 위임받은 시스템에서만 실행하세요.')
    print()
    return input('  계속하려면 YES 를 정확히 입력하세요: ') == 'YES'


def _is_admin_windows():
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def _sha256(path: Path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(4 * 1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


# ── 수집 ───────────────────────────────────────────────────────────────────────

def acquire_windows(out: Path):
    if not _is_admin_windows():
        print('  ✗ 관리자 권한 필요. 우클릭 → 관리자 권한으로 실행.')
        return False
    tool = Path(os.environ.get('TEMP', '.')) / 'forensiclab_winpmem.exe'
    if not tool.exists():
        print(f'  → WinPmem 다운로드: {WINPMEM_URL}')
        try:
            urllib.request.urlretrieve(WINPMEM_URL, tool)
        except Exception as e:
            print(f'  ✗ 다운로드 실패: {e} — 수동: https://github.com/Velocidex/WinPmem/releases')
            return False
    print(f'  → 덤프: {out}')
    return subprocess.call([str(tool), str(out)]) == 0


def acquire_linux(out: Path):
    if os.geteuid() != 0:
        print('  ✗ root 권한 필요. sudo 로 재실행하세요.')
        return False
    tool = Path('/tmp/forensiclab_avml')
    if not tool.exists():
        print(f'  → AVML 다운로드: {AVML_URL}')
        try:
            urllib.request.urlretrieve(AVML_URL, tool)
            tool.chmod(0o755)
        except Exception as e:
            print(f'  ✗ AVML 다운로드 실패: {e}')
            tool = None
    if tool and tool.exists():
        print(f'  → AVML 덤프: {out}')
        if subprocess.call([str(tool), str(out)]) == 0:
            return True
    # 폴백: /proc/kcore
    src = next((s for s in ['/proc/kcore', '/dev/mem'] if os.path.exists(s) and os.access(s, os.R_OK)), None)
    if not src:
        print('  ✗ AVML 실패 + /proc/kcore·/dev/mem 접근 불가. LiME 모듈을 사용하세요.')
        return False
    print(f'  → {src} → {out} (폴백)')
    total = 0
    with open(src, 'rb') as r, open(out, 'wb') as w:
        while True:
            try:
                chunk = r.read(4 * 1024 * 1024)
            except Exception:
                break
            if not chunk:
                break
            w.write(chunk)
            total += len(chunk)
    print(f'  ✓ {total:,} bytes')
    return total > 0


def acquire_macos(out: Path):
    print('  → macOS는 osxpmem 사용:')
    print('    1. https://github.com/google/rekall/releases 에서 osxpmem 다운로드')
    print('    2. xattr -dr com.apple.quarantine osxpmem.app')
    print(f'    3. sudo osxpmem.app/osxpmem -o {out}')
    return False


# ── Volatility 3 분석 ───────────────────────────────────────────────────────────

def find_vol():
    for cand in ('vol', 'vol.py', 'volatility3'):
        if shutil.which(cand):
            return [cand]
    # python 모듈 형태
    try:
        subprocess.run([sys.executable, '-m', 'volatility3', '-h'],
                       capture_output=True, timeout=30)
        return [sys.executable, '-m', 'volatility3']
    except Exception:
        return None


def os_family():
    s = platform.system()
    return {'Windows': 'windows', 'Linux': 'linux', 'Darwin': 'mac'}.get(s, 'windows')


def analyze(dump: Path, out_dir: Path, vol_cmd, fam):
    out_dir.mkdir(parents=True, exist_ok=True)
    print(f'\n  덤프 SHA256: {_sha256(dump)}')
    if vol_cmd is None:
        vol_cmd = find_vol()
    if vol_cmd is None:
        print('\n  ⚠️ Volatility 3 미설치 — 아래 명령을 직접 실행하세요:')
        print('     pip install volatility3')
        for p in PLUGINS.get(fam, []):
            print(f'     vol -f "{dump}" {p}')
        return False
    print(f'\n  Volatility: {" ".join(vol_cmd)}  |  플러그인 {len(PLUGINS[fam])}종')
    for p in PLUGINS.get(fam, []):
        out_file = out_dir / f'{p}.txt'
        print(f'  → {p} ...', end=' ', flush=True)
        t0 = time.time()
        try:
            r = subprocess.run(vol_cmd + ['-f', str(dump), p],
                               capture_output=True, text=True, timeout=1800)
            out_file.write_text((r.stdout or '') + (r.stderr or ''), encoding='utf-8')
            print(f'OK ({time.time() - t0:.0f}s) -> {out_file.name}')
        except subprocess.TimeoutExpired:
            print('TIMEOUT (30분 초과, skip)')
        except Exception as e:
            print(f'ERR {e}')
    print(f'\n  ✓ 결과 저장: {out_dir.resolve()}')
    return True


def main():
    banner()
    p = argparse.ArgumentParser()
    p.add_argument('--output', '-o', default='memory_dump.raw', help='수집 덤프 출력 경로')
    p.add_argument('--analyze', '-a', help='이미 있는 덤프 분석(수집 생략)')
    p.add_argument('--out-dir', '-d', default='vol3_out', help='분석 결과 폴더')
    p.add_argument('--vol', help='Volatility 실행 명령 (예: "python -m volatility3")')
    p.add_argument('--os', choices=['windows', 'linux', 'mac'], help='분석 OS (기본: 현재 OS)')
    p.add_argument('--yes', action='store_true', help='면책 자동 동의')
    args = p.parse_args()

    if not args.yes and not confirm():
        print('  취소됨.')
        return 1

    fam = args.os or os_family()
    vol_cmd = args.vol.split() if args.vol else None

    if args.analyze:
        dump = Path(args.analyze)
        if not dump.exists():
            print(f'  ✗ 덤프 없음: {dump}')
            return 1
    else:
        dump = Path(args.output).resolve()
        dump.parent.mkdir(parents=True, exist_ok=True)
        osname = platform.system()
        print(f'\n  플랫폼: {osname} {platform.release()}  |  수집 시작')
        ok = (acquire_windows(dump) if osname == 'Windows'
              else acquire_linux(dump) if osname == 'Linux'
              else acquire_macos(dump) if osname == 'Darwin'
              else False)
        if not ok:
            print('  ✗ 메모리 수집 실패 — 분석을 건너뜁니다.')
            return 1

    analyze(dump, Path(args.out_dir), vol_cmd, fam)
    return 0


if __name__ == '__main__':
    sys.exit(main())
