"""OS 지원 확장 배포: tools.py + strings.html"""
import paramiko
from pathlib import Path

HOST, USER, PASS = '10.8.0.17', 'ruddls030', 'dlstn0722'
REMOTE = '/home/ruddls030/forensic/flask/hospital'
LOCAL = Path(r'E:\forensic')

uploads = [
    ('views/tools.py',                f'{REMOTE}/views/tools.py'),
    ('templates/tools/strings.html',  f'{REMOTE}/templates/tools/strings.html'),
]

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect(HOST, username=USER, password=PASS)
sftp = ssh.open_sftp()
for local_rel, remote in uploads:
    sftp.put(str(LOCAL / local_rel), remote)
    print(f'  OK {local_rel}')
sftp.close()
_, out, err = ssh.exec_command('docker restart forensic-flask')
print(out.read().decode().strip())
import time; time.sleep(5)
_, out, _ = ssh.exec_command('docker logs --tail 15 forensic-flask 2>&1')
print('\n--- logs ---')
print(out.read().decode())
ssh.close()
print('  done')
