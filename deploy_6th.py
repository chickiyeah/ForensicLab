"""6차 확장 배포 + Docker 재빌드 (reportlab·opencv 추가)"""
import paramiko, time
from pathlib import Path

HOST, USER, PASS = '10.8.0.17', 'ruddls030', 'dlstn0722'
REMOTE = '/home/ruddls030/forensic/flask/hospital'
REMOTE_ROOT = '/home/ruddls030/forensic/flask'
COMPOSE_DIR = '/home/ruddls030/forensic'
LOCAL = Path(r'E:\forensic')

uploads = [
    ('views/tools.py', f'{REMOTE}/views/tools.py'),
    ('views/tools_extra6.py', f'{REMOTE}/views/tools_extra6.py'),
    ('requirements.txt', f'{REMOTE_ROOT}/requirements.txt'),
    ('templates/navbar.html', f'{REMOTE}/templates/navbar.html'),
    ('templates/tools/index.html', f'{REMOTE}/templates/tools/index.html'),
]
for t in ['case','case_detail','search','dashboard','attack','threat_intel',
          'ai_classify','plaso','ocr_index','face']:
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
print(f'upload: {ok} OK / {err} fail')

print('\n  Docker 재빌드 (reportlab·opencv 추가)...')
cmd = f'cd {COMPOSE_DIR} && docker compose down 2>&1 | tail -3 && docker compose build flask 2>&1 | tail -30 && docker compose up -d 2>&1 | tail -5'
_, out, errs = ssh.exec_command(cmd, timeout=900)
print(out.read().decode(errors='replace'))
es = errs.read().decode(errors='replace')
if es: print('STDERR:', es[:500])

time.sleep(8)
_, out, _ = ssh.exec_command('docker logs --tail 20 forensic-flask 2>&1')
print('\n--- container logs ---')
print(out.read().decode(errors='replace'))
ssh.close()
print('\ndone')
