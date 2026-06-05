"""포렌식 가이드 + plaso 페이지 배포"""
import paramiko, time
ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect('10.8.0.17', username='ruddls030', password='dlstn0722')
sftp = ssh.open_sftp()
files = [
    (r'E:\forensic\views\tools.py', '/home/ruddls030/forensic/flask/hospital/views/tools.py'),
    (r'E:\forensic\views\tools_extra8.py', '/home/ruddls030/forensic/flask/hospital/views/tools_extra8.py'),
    (r'E:\forensic\templates\navbar.html', '/home/ruddls030/forensic/flask/hospital/templates/navbar.html'),
    (r'E:\forensic\templates\tools\index.html', '/home/ruddls030/forensic/flask/hospital/templates/tools/index.html'),
    (r'E:\forensic\templates\tools\forensic_paths.html', '/home/ruddls030/forensic/flask/hospital/templates/tools/forensic_paths.html'),
    (r'E:\forensic\templates\tools\beginner.html', '/home/ruddls030/forensic/flask/hospital/templates/tools/beginner.html'),
    (r'E:\forensic\templates\tools\glossary.html', '/home/ruddls030/forensic/flask/hospital/templates/tools/glossary.html'),
    (r'E:\forensic\templates\tools\plaso.html', '/home/ruddls030/forensic/flask/hospital/templates/tools/plaso.html'),
]
for src, dst in files:
    sftp.put(src, dst); print(f'  OK {src.split(chr(92))[-1]}')
sftp.close()
_, out, _ = ssh.exec_command('docker restart forensic-flask')
print(out.read().decode().strip())
time.sleep(4)
ssh.close()
print('done')
