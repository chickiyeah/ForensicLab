#!/usr/bin/env python3
"""
ForensicLab Event Log Collector (Windows)
==========================================
EVTX 파일을 복사하고, 포렌식 핵심 이벤트(로그온/프로세스 생성/서비스 설치 등)를
wevtutil로 추출해 CSV로 저장합니다.

핵심 이벤트 ID:
  Security:
    4624 로그온 성공          4625 로그온 실패
    4634 로그오프             4648 명시적 자격 로그온
    4672 특권 할당            4688 프로세스 생성
    4720 사용자 생성          4732 그룹 추가
    4768/4769 Kerberos        4776 NTLM 인증
  System:
    7045 서비스 설치          1102 보안 로그 삭제
    104  로그 삭제            6005/6006 부팅/종료
  Sysmon (Microsoft-Windows-Sysmon/Operational):
    1 ProcessCreate  3 NetworkConnect  7 ImageLoad  10 ProcessAccess
    11 FileCreate  13 RegSetValue  22 DnsQuery  23 FileDelete

요구: 관리자 권한
"""
import ctypes
import datetime
import os
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path


def is_admin():
    try: return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception: return False


def main():
    print('=' * 70)
    print('  ForensicLab Event Log Collector v1.0')
    print('=' * 70)
    if sys.platform != 'win32':
        print('  ✗ Windows 전용'); return 1
    if not is_admin():
        print('  ✗ 관리자 권한 필요'); return 1
    if input('\n  계속하려면 YES 입력: ') != 'YES':
        return 1

    out = Path(f'./eventlogs_{datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")}').resolve()
    (out / 'raw').mkdir(parents=True, exist_ok=True)
    (out / 'extracted').mkdir(parents=True, exist_ok=True)
    print(f'\n  출력: {out}\n')

    # 1. EVTX 원본 복사
    print('[1/2] EVTX 원본 복사')
    src = Path(os.environ.get('SystemRoot', r'C:\Windows')) / 'System32' / 'winevt' / 'Logs'
    target_logs = [
        'Security.evtx', 'System.evtx', 'Application.evtx',
        'Microsoft-Windows-PowerShell%4Operational.evtx',
        'Windows PowerShell.evtx',
        'Microsoft-Windows-Sysmon%4Operational.evtx',
        'Microsoft-Windows-Windows Defender%4Operational.evtx',
        'Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx',
        'Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx',
        'Microsoft-Windows-TaskScheduler%4Operational.evtx',
        'Microsoft-Windows-WMI-Activity%4Operational.evtx',
        'Microsoft-Windows-AppLocker%4EXE and DLL.evtx',
        'Microsoft-Windows-AppLocker%4MSI and Script.evtx',
    ]
    copied = 0
    for name in target_logs:
        s = src / name
        if s.exists():
            try:
                shutil.copy2(s, out / 'raw' / name)
                copied += 1
                print(f'    ✓ {name}')
            except Exception as e:
                print(f'    × {name}: {e}')
    print(f'    → {copied}개 EVTX 복사')

    # 2. 핵심 이벤트 추출 (wevtutil)
    print('\n[2/2] 핵심 이벤트 추출 (wevtutil)')
    queries = [
        ('Security_4624_logons.csv', 'Security',
         "*[System[(EventID=4624 or EventID=4625 or EventID=4634 or EventID=4648)]]"),
        ('Security_4688_processes.csv', 'Security',
         "*[System[(EventID=4688)]]"),
        ('Security_4720_users.csv', 'Security',
         "*[System[(EventID=4720 or EventID=4722 or EventID=4724 or EventID=4732 or EventID=4738)]]"),
        ('System_7045_services.csv', 'System',
         "*[System[(EventID=7045 or EventID=7036 or EventID=104 or EventID=1102)]]"),
        ('PowerShell_operational.csv',
         'Microsoft-Windows-PowerShell/Operational',
         "*[System[(EventID=4103 or EventID=4104 or EventID=4105 or EventID=4106)]]"),
        ('Sysmon_processes.csv',
         'Microsoft-Windows-Sysmon/Operational',
         "*[System[(EventID=1 or EventID=3 or EventID=7 or EventID=8 or EventID=10 or EventID=11 or EventID=22)]]"),
    ]
    for csv_name, channel, query in queries:
        cmd = ['wevtutil', 'qe', channel,
               f'/q:{query}', '/f:text', '/c:5000']
        try:
            r = subprocess.run(cmd, capture_output=True, text=True,
                               encoding='utf-8', errors='replace', timeout=180)
            content = r.stdout
            if not content.strip():
                print(f'    · {csv_name}: 결과 없음'); continue
            (out / 'extracted' / csv_name.replace('.csv', '.txt')).write_text(
                content, encoding='utf-8')
            event_count = content.count('Event[')
            print(f'    ✓ {csv_name}: ~{event_count}건')
        except subprocess.TimeoutExpired:
            print(f'    × {csv_name}: 시간 초과')
        except Exception as e:
            print(f'    × {csv_name}: {e}')

    # ZIP
    zip_path = out.with_suffix('.zip')
    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED, allowZip64=True) as zf:
        for f in out.rglob('*'):
            if f.is_file():
                zf.write(f, f.relative_to(out.parent))
    print(f'\n  → ZIP 생성: {zip_path} ({zip_path.stat().st_size / 1024 / 1024:.2f} MB)')
    print('\n  ✓ 완료')
    return 0


if __name__ == '__main__':
    sys.exit(main())
