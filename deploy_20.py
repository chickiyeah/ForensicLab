"""20개 신규 도구 + 라이브러리 추가 배포 (Docker 이미지 재빌드)"""
import paramiko, time
from pathlib import Path

HOST, USER, PASS = '10.8.0.17', 'ruddls030', 'dlstn0722'
REMOTE = '/home/ruddls030/forensic/flask/hospital'
REMOTE_ROOT = '/home/ruddls030/forensic/flask'
LOCAL = Path(r'E:\forensic')

uploads = [
    # 백엔드
    ('views/tools.py',              f'{REMOTE}/views/tools.py'),
    ('views/tools_extra2.py',       f'{REMOTE}/views/tools_extra2.py'),
    ('requirements.txt',            f'{REMOTE_ROOT}/requirements.txt'),
    # navbar
    ('templates/navbar.html',       f'{REMOTE}/templates/navbar.html'),
]
# 20개 신규 템플릿
tool_templates = ['evtx','sqlite','jumplist','oledump','pdfscan','jwt','cert',
                  'yara','hexdiff','secrets','esedb','mft','email_auth','dns',
                  'stego','qr','ocr','whois','passwd','git']
for t in tool_templates:
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
        sftp.put(str(src), t)
        print(f'  OK {r}'); ok += 1
    except Exception as e:
        print(f'  X {r}: {e}'); err += 1
sftp.close()
print(f'\n  upload: {ok} OK, {err} fail')

# 라이브러리 변경 → Docker 이미지 재빌드 필요
print('\n  docker compose: 재빌드 + 재시작 (오래 걸림)...')
cmd = 'cd /home/ruddls030/forensic && docker compose down && docker compose build flask && docker compose up -d'
_, stdout, stderr = ssh.exec_command(cmd, get_pty=True)
# 빌드 진행 상황 실시간 출력
for line in iter(stdout.readline, ''):
    if line: print('  ', line.rstrip()[:200])
err_out = stderr.read().decode()
if err_out: print('  stderr:', err_out[:500])

time.sleep(8)
_, stdout, _ = ssh.exec_command('docker logs --tail 25 forensic-flask 2>&1')
print('\n--- container logs ---')
print(stdout.read().decode())
ssh.close()
print('\n  done')
