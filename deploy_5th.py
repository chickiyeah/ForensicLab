"""5차 확장 + Docker 재빌드 배포 (시스템 패키지 + 새 라이브러리)"""
import paramiko, time
from pathlib import Path

HOST, USER, PASS = '10.8.0.17', 'ruddls030', 'dlstn0722'
REMOTE = '/home/ruddls030/forensic/flask/hospital'
REMOTE_ROOT = '/home/ruddls030/forensic/flask'
COMPOSE_DIR = '/home/ruddls030/forensic'
LOCAL = Path(r'E:\forensic')

uploads = [
    ('views/tools.py', f'{REMOTE}/views/tools.py'),
    ('views/tools_extra5.py', f'{REMOTE}/views/tools_extra5.py'),
    ('requirements.txt', f'{REMOTE_ROOT}/requirements.txt'),
    ('Dockerfile', f'{REMOTE_ROOT}/Dockerfile'),
    ('templates/navbar.html', f'{REMOTE}/templates/navbar.html'),
]
for t in ['jobs','job_detail','coc','vol_full','llm_report','hashcat_job',
          'aleapp','ileapp','e01_mount','mft_full']:
    uploads.append((f'templates/tools/{t}.html', f'{REMOTE}/templates/tools/{t}.html'))

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect(HOST, username=USER, password=PASS)
sftp = ssh.open_sftp()
ok = err = 0
for r, t in uploads:
    src = LOCAL / r
    if not src.exists():
        print(f'  X [missing] {r}'); err += 1; continue
    try:
        sftp.put(str(src), t); ok += 1
        print(f'  OK {r}')
    except Exception as e:
        print(f'  X {r}: {e}'); err += 1
sftp.close()
print(f'\nupload: {ok} OK / {err} fail')

# Docker 재빌드 + 재시작
print('\n  Docker 재빌드 시작...')
cmd = f'cd {COMPOSE_DIR} && docker compose down 2>&1 | tail -5 && docker compose build flask 2>&1 | tail -50 && docker compose up -d 2>&1 | tail -10'
_, out, err_s = ssh.exec_command(cmd, timeout=900)
print(out.read().decode(errors='replace'))
es = err_s.read().decode(errors='replace')
if es: print('STDERR:', es[:1000])

time.sleep(10)
_, out, _ = ssh.exec_command('docker logs --tail 30 forensic-flask 2>&1')
print('\n--- container logs ---')
print(out.read().decode(errors='replace'))
ssh.close()
print('\ndone')
