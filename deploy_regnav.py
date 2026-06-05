"""레지스트리 무제한 + 경로 자동 이동 배포"""
import paramiko, time
ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect('10.8.0.17', username='ruddls030', password='dlstn0722')
sftp = ssh.open_sftp()
files = [
    (r'E:\forensic\views\tools.py', '/home/ruddls030/forensic/flask/hospital/views/tools.py'),
    (r'E:\forensic\templates\tools\registry.html', '/home/ruddls030/forensic/flask/hospital/templates/tools/registry.html'),
    (r'E:\forensic\templates\base.html', '/home/ruddls030/forensic/flask/hospital/templates/base.html'),
]
for src, dst in files:
    sftp.put(src, dst); print(f'  OK {src.split(chr(92))[-1]}')
sftp.close()
_, out, _ = ssh.exec_command('docker restart forensic-flask')
print(out.read().decode().strip())
time.sleep(5)
ssh.close()
print('done')
