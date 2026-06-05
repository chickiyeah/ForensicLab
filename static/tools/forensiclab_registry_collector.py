#!/usr/bin/env python3
"""
ForensicLab Live Registry Hive Collector (Windows)
==================================================
reg save 명령으로 라이브 시스템에서 레지스트리 하이브를 백업합니다.

수집 대상:
  - HKLM\SYSTEM, SOFTWARE, SAM, SECURITY, DEFAULT
  - 모든 사용자 NTUSER.DAT, UsrClass.dat
  - AmCache.hve
  - HKLM\COMPONENTS, HKLM\HARDWARE (메모리에만 존재 — reg save로 추출)

요구: 관리자 권한
"""
import ctypes
import os
import shutil
import subprocess
import sys
import datetime
import zipfile
from pathlib import Path


def is_admin():
    try: return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception: return False


def reg_save(hive, output):
    try:
        r = subprocess.run(['reg', 'save', hive, str(output), '/y'],
                           capture_output=True, text=True, timeout=180)
        return r.returncode == 0, (r.stderr or r.stdout).strip()
    except Exception as e:
        return False, str(e)


def main():
    print('=' * 70)
    print('  ForensicLab Live Registry Hive Collector v1.0')
    print('=' * 70)
    if sys.platform != 'win32':
        print('  ✗ Windows 전용'); return 1
    if not is_admin():
        print('  ✗ 관리자 권한 필요'); return 1
    print('\n  본인 또는 위임받은 시스템에서만 실행하세요.')
    if input('  계속하려면 YES 입력: ') != 'YES':
        return 1

    out = Path(f'./reg_hives_{datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")}').resolve()
    out.mkdir(parents=True, exist_ok=True)
    print(f'\n  출력: {out}\n')

    # 시스템 하이브
    hives = [
        ('HKLM_SYSTEM',     r'HKLM\SYSTEM'),
        ('HKLM_SOFTWARE',   r'HKLM\SOFTWARE'),
        ('HKLM_SAM',        r'HKLM\SAM'),
        ('HKLM_SECURITY',   r'HKLM\SECURITY'),
        ('HKLM_DEFAULT',    r'HKU\.DEFAULT'),
        ('HKLM_COMPONENTS', r'HKLM\COMPONENTS'),
        ('HKLM_HARDWARE',   r'HKLM\HARDWARE'),
        ('HKLM_BCD',        r'HKLM\BCD00000000'),
    ]
    for label, path in hives:
        target = out / f'{label}.hive'
        ok, msg = reg_save(path, target)
        print(f'  {"✓" if ok else "×"} {label:18} ({path}){"" if ok else " — " + msg[:80]}')

    # AmCache
    win = Path(os.environ.get('SystemRoot', r'C:\Windows'))
    amcache = win / 'AppCompat' / 'Programs' / 'Amcache.hve'
    if amcache.exists():
        try:
            shutil.copy2(amcache, out / 'Amcache.hve')
            print(f'  ✓ Amcache.hve')
        except Exception as e:
            print(f'  × Amcache.hve: {e}')

    # 모든 유저 NTUSER.DAT / UsrClass.dat
    # SystemDrive='C:' + Path /'Users' = 'C:Users' (잘못된 드라이브 상대경로) → '\\Users' 명시
    users = Path(os.environ.get('SystemDrive', 'C:') + '\\Users')
    if users.exists():
        for u in users.iterdir():
            if not u.is_dir() or u.name in ('Public', 'Default', 'All Users', 'Default User'):
                continue
            for src_rel, dst_name in [
                ('NTUSER.DAT', f'NTUSER_{u.name}.dat'),
                (r'AppData\Local\Microsoft\Windows\UsrClass.dat', f'UsrClass_{u.name}.dat'),
            ]:
                src = u / src_rel
                if src.exists():
                    try:
                        shutil.copy2(src, out / dst_name)
                        print(f'  ✓ {dst_name}')
                    except PermissionError:
                        # 활성 사용자 하이브는 락 — reg save로 우회
                        if 'NTUSER' in dst_name:
                            sid_proc = subprocess.run(['wmic', 'useraccount', 'where',
                                                       f"name='{u.name}'", 'get', 'sid'],
                                                      capture_output=True, text=True)
                            sids = [l.strip() for l in sid_proc.stdout.splitlines() if l.startswith('S-')]
                            if sids:
                                ok, _ = reg_save(f'HKU\\{sids[0]}', out / dst_name)
                                if ok: print(f'  ✓ {dst_name} (reg save via SID)')
                                else: print(f'  × {dst_name}')
                            else:
                                print(f'  × {dst_name} (SID 조회 실패)')
                    except Exception as e:
                        print(f'  × {dst_name}: {e}')

    # ZIP 압축
    zip_path = out.with_suffix('.zip')
    print(f'\n  → ZIP 압축: {zip_path}')
    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED, allowZip64=True) as zf:
        for f in out.rglob('*'):
            if f.is_file():
                zf.write(f, f.relative_to(out.parent))
    print(f'  ✓ {zip_path.stat().st_size / 1024 / 1024:.2f} MB')
    print(f'\n  완료. ForensicLab의 /tools/registry 에서 분석 가능.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
