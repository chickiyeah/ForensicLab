"""ForensicLab 전체 배포 — 분석 도구 + 트리아지 분석 + 다운로드 스크립트"""
import paramiko
from pathlib import Path

HOST, USER, PASS = '10.8.0.17', 'ruddls030', 'dlstn0722'
REMOTE_BASE = '/home/ruddls030/forensic/flask/hospital'
LOCAL_BASE = Path(r'E:\forensic')

uploads = [
    ('views/tools.py',                 f'{REMOTE_BASE}/views/tools.py'),
    ('views/tools_extra.py',           f'{REMOTE_BASE}/views/tools_extra.py'),
    ('templates/navbar.html',          f'{REMOTE_BASE}/templates/navbar.html'),
    ('templates/tools/index.html',     f'{REMOTE_BASE}/templates/tools/index.html'),
    ('templates/tools/pe.html',        f'{REMOTE_BASE}/templates/tools/pe.html'),
    ('templates/tools/entropy.html',   f'{REMOTE_BASE}/templates/tools/entropy.html'),
    ('templates/tools/decode.html',    f'{REMOTE_BASE}/templates/tools/decode.html'),
    ('templates/tools/prefetch.html',  f'{REMOTE_BASE}/templates/tools/prefetch.html'),
    ('templates/tools/lnk.html',       f'{REMOTE_BASE}/templates/tools/lnk.html'),
    ('templates/tools/diskimg.html',   f'{REMOTE_BASE}/templates/tools/diskimg.html'),
    ('templates/tools/scripts.html',   f'{REMOTE_BASE}/templates/tools/scripts.html'),
    ('templates/tools/triage.html',    f'{REMOTE_BASE}/templates/tools/triage.html'),
    ('static/tools/forensiclab_ram_dumper.py',         f'{REMOTE_BASE}/static/tools/forensiclab_ram_dumper.py'),
    ('static/tools/forensiclab_triage_collector.py',   f'{REMOTE_BASE}/static/tools/forensiclab_triage_collector.py'),
    ('static/tools/forensiclab_browser_artifacts.py',  f'{REMOTE_BASE}/static/tools/forensiclab_browser_artifacts.py'),
    ('static/tools/forensiclab_registry_collector.py', f'{REMOTE_BASE}/static/tools/forensiclab_registry_collector.py'),
    ('static/tools/forensiclab_disk_imager.py',        f'{REMOTE_BASE}/static/tools/forensiclab_disk_imager.py'),
    ('static/tools/forensiclab_usb_history.py',        f'{REMOTE_BASE}/static/tools/forensiclab_usb_history.py'),
    ('static/tools/forensiclab_eventlog_collector.py', f'{REMOTE_BASE}/static/tools/forensiclab_eventlog_collector.py'),
]

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect(HOST, username=USER, password=PASS)
sftp = ssh.open_sftp()

# 디렉터리 보장
for d in ['views', 'templates/tools', 'static/tools']:
    parts = d.split('/')
    cur = REMOTE_BASE
    for part in parts:
        cur = f'{cur}/{part}'
        try: sftp.stat(cur)
        except IOError: sftp.mkdir(cur)

ok = err = 0
for local_rel, remote in uploads:
    local = LOCAL_BASE / local_rel
    if not local.exists():
        print(f'  X [missing] {local_rel}'); err += 1; continue
    try:
        sftp.put(str(local), remote)
        print(f'  OK {local_rel}')
        ok += 1
    except Exception as e:
        print(f'  X {local_rel}: {e}'); err += 1

sftp.close()
print(f'\n  upload: {ok} OK, {err} fail')
print('  restarting container...')
_, stdout, stderr = ssh.exec_command('docker restart forensic-flask')
print(stdout.read().decode().strip())
e2 = stderr.read().decode().strip()
if e2: print('  stderr:', e2)

import time; time.sleep(6)
_, stdout, _ = ssh.exec_command('docker logs --tail 30 forensic-flask 2>&1')
print('\n--- container logs ---')
print(stdout.read().decode())
ssh.close()
print('\n  done')
