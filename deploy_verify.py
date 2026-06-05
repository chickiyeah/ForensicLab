"""체크섬 검증 페이지 배포"""
import paramiko
from pathlib import Path

HOST, USER, PASS = '10.8.0.17', 'ruddls030', 'dlstn0722'
REMOTE = '/home/ruddls030/forensic/flask/hospital'
LOCAL = Path(r'E:\forensic')

uploads = [
    ('views/tools_extra.py',         f'{REMOTE}/views/tools_extra.py'),
    ('templates/navbar.html',        f'{REMOTE}/templates/navbar.html'),
    ('templates/tools/scripts.html', f'{REMOTE}/templates/tools/scripts.html'),
    ('templates/tools/verify.html',  f'{REMOTE}/templates/tools/verify.html'),
    ('static/tools/checksums.txt',   f'{REMOTE}/static/tools/checksums.txt'),
]

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect(HOST, username=USER, password=PASS)
sftp = ssh.open_sftp()
for r, t in uploads:
    sftp.put(str(LOCAL / r), t)
    print(f'  OK {r}')
sftp.close()
_, out, _ = ssh.exec_command('docker restart forensic-flask')
print(out.read().decode().strip())
ssh.close()
print('  done')
