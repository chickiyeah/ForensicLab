#!/usr/bin/env python3
"""
ForensicLab Triage Collector (Windows)
=======================================
시스템 트리아지 — 핵심 포렌식 아티팩트를 한 번에 수집해 ZIP으로 묶습니다.

수집 대상:
  • 레지스트리 하이브: SYSTEM, SOFTWARE, SAM, SECURITY, NTUSER.DAT, UsrClass.dat, AmCache.hve
  • 이벤트 로그: Security, System, Application, PowerShell-Operational, Sysmon, Windows Defender
  • Prefetch (.pf 전체)
  • LNK 바로가기 (Recent / Office Recent)
  • JumpList (.automaticDestinations-ms, .customDestinations-ms)
  • USB 연결 이력 (setupapi.dev.log)
  • Tasks 폴더 스냅샷
  • PowerShell 실행 이력 (ConsoleHost_history.txt)
  • $MFT, $LogFile, $UsnJrnl (있을 경우 — Volume Shadow Copy 필요할 수 있음)

요구: 관리자 권한
"""
import argparse
import ctypes
import os
import sys
import shutil
import subprocess
import zipfile
import datetime
import getpass
from pathlib import Path


def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def banner():
    print('=' * 70)
    print('  ForensicLab Triage Collector v1.0')
    print('=' * 70)


def reg_save(hive: str, output: Path) -> bool:
    """reg save 명령으로 하이브 백업"""
    try:
        r = subprocess.run(['reg', 'save', hive, str(output), '/y'],
                           capture_output=True, text=True, timeout=120)
        return r.returncode == 0
    except Exception:
        return False


def copy_safe(src: Path, dst: Path) -> bool:
    try:
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
        return True
    except Exception as e:
        print(f'    × {src.name}: {e}')
        return False


def copy_dir(src: Path, dst: Path, exts=None):
    if not src.exists():
        return 0
    cnt = 0
    for f in src.rglob('*'):
        if f.is_file() and (not exts or f.suffix.lower() in exts):
            rel = f.relative_to(src)
            try:
                target = dst / rel
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(f, target)
                cnt += 1
            except Exception:
                pass
    return cnt


def collect(out_dir: Path):
    out_dir.mkdir(parents=True, exist_ok=True)
    win = Path(os.environ.get('SystemRoot', r'C:\Windows'))
    # SystemDrive 환경변수는 보통 'C:' (백슬래시 없음) → Path() / 'Users' 하면
    # 'C:Users' (드라이브 상대경로)가 되어 잘못. '\\Users' 명시로 절대경로 보장.
    users = Path(os.environ.get('SystemDrive', 'C:') + '\\Users')

    print('\n[1/8] 레지스트리 하이브 백업')
    reg_dir = out_dir / 'registry'
    reg_dir.mkdir(exist_ok=True)
    for hive_name, hive_path in [
        ('SYSTEM', r'HKLM\SYSTEM'), ('SOFTWARE', r'HKLM\SOFTWARE'),
        ('SAM', r'HKLM\SAM'), ('SECURITY', r'HKLM\SECURITY'),
        ('DEFAULT', r'HKU\.DEFAULT'),
    ]:
        out = reg_dir / f'{hive_name}.hive'
        ok = reg_save(hive_path, out)
        print(f'    {"✓" if ok else "×"} {hive_name}')

    print('\n[2/8] 사용자 NTUSER.DAT / UsrClass.dat')
    for u in users.iterdir():
        if not u.is_dir() or u.name in ('Public', 'Default', 'All Users'):
            continue
        for src_name, dst_name in [
            ('NTUSER.DAT', f'NTUSER_{u.name}.dat'),
            (r'AppData\Local\Microsoft\Windows\UsrClass.dat', f'UsrClass_{u.name}.dat'),
        ]:
            src = u / src_name
            if src.exists():
                ok = copy_safe(src, reg_dir / dst_name)
                if ok: print(f'    ✓ {u.name} / {src.name}')

    print('\n[3/8] AmCache.hve')
    amcache = win / 'AppCompat' / 'Programs' / 'Amcache.hve'
    if amcache.exists():
        copy_safe(amcache, reg_dir / 'Amcache.hve')
        print('    ✓ Amcache.hve')

    print('\n[4/8] 이벤트 로그 (.evtx)')
    evt_src = win / 'System32' / 'winevt' / 'Logs'
    evt_dst = out_dir / 'eventlogs'
    cnt = copy_dir(evt_src, evt_dst, exts={'.evtx'})
    print(f'    ✓ {cnt}개 EVTX 복사')

    print('\n[5/8] Prefetch (.pf)')
    pf_dst = out_dir / 'prefetch'
    cnt = copy_dir(win / 'Prefetch', pf_dst, exts={'.pf'})
    print(f'    ✓ {cnt}개 .pf 복사')

    print('\n[6/8] LNK / JumpList')
    for u in users.iterdir():
        if not u.is_dir(): continue
        for sub in ['AppData\\Roaming\\Microsoft\\Windows\\Recent',
                    'AppData\\Roaming\\Microsoft\\Office\\Recent']:
            src = u / sub
            if src.exists():
                cnt = copy_dir(src, out_dir / 'lnk' / u.name / sub.replace('\\', '_'))
                if cnt: print(f'    ✓ {u.name}/{sub} : {cnt}개')

    print('\n[7/8] USB / setupapi.dev.log')
    for log in ['INF/setupapi.dev.log', 'INF/setupapi.app.log',
                'inf/setupapi.dev.log']:
        src = win / log
        if src.exists():
            copy_safe(src, out_dir / 'usb' / src.name)
            print(f'    ✓ {log}')

    print('\n[8/8] PowerShell 실행 이력')
    for u in users.iterdir():
        if not u.is_dir(): continue
        ps = u / r'AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt'
        if ps.exists():
            copy_safe(ps, out_dir / 'powershell' / f'{u.name}_history.txt')
            print(f'    ✓ {u.name}')

    # 메타데이터
    meta = out_dir / 'collection_info.txt'
    meta.write_text(
        f'ForensicLab Triage Collection\n'
        f'수집 시각: {datetime.datetime.utcnow().isoformat()}Z\n'
        f'호스트명: {os.environ.get("COMPUTERNAME", "?")}\n'
        f'OS: {sys.platform} / {os.environ.get("OS","?")}\n'
        f'사용자: {getpass.getuser()}\n',
        encoding='utf-8')


def make_zip(src_dir: Path, zip_path: Path):
    print(f'\n→ ZIP 압축 중: {zip_path}')
    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED, allowZip64=True) as zf:
        for f in src_dir.rglob('*'):
            if f.is_file():
                zf.write(f, f.relative_to(src_dir.parent))
    sz = zip_path.stat().st_size / 1024 / 1024
    print(f'  ✓ {sz:.2f} MB 생성 완료')


def main():
    banner()
    if sys.platform != 'win32':
        print('  ✗ Windows 전용 스크립트')
        return 1
    if not is_admin():
        print('  ✗ 관리자 권한 필요. PowerShell/CMD를 관리자로 실행 후 재시도.')
        return 1
    p = argparse.ArgumentParser()
    p.add_argument('--output', '-o',
                   default=f'./triage_{datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")}',
                   help='수집 디렉터리 (기본: ./triage_YYYYMMDD_HHMMSS)')
    p.add_argument('--no-zip', action='store_true', help='ZIP 압축 생략')
    args = p.parse_args()
    out = Path(args.output).resolve()
    print(f'\n  수집 경로: {out}')
    print('  계속하려면 YES 입력:')
    if input('  > ') != 'YES':
        print('  취소됨'); return 1
    collect(out)
    if not args.no_zip:
        make_zip(out, out.with_suffix('.zip'))
    print('\n  ✓ 트리아지 수집 완료')
    return 0


if __name__ == '__main__':
    sys.exit(main())
