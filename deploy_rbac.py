"""사건 RBAC + plaso 안내 배포"""
import paramiko, time
ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect('10.8.0.17', username='ruddls030', password='dlstn0722')
sftp = ssh.open_sftp()
files = [
    (r'E:\forensic\views\tools_extra6.py',
     '/home/ruddls030/forensic/flask/hospital/views/tools_extra6.py'),
    (r'E:\forensic\templates\tools\case.html',
     '/home/ruddls030/forensic/flask/hospital/templates/tools/case.html'),
    (r'E:\forensic\templates\tools\case_detail.html',
     '/home/ruddls030/forensic/flask/hospital/templates/tools/case_detail.html'),
    (r'E:\forensic\templates\tools\case_no_access.html',
     '/home/ruddls030/forensic/flask/hospital/templates/tools/case_no_access.html'),
    (r'E:\forensic\templates\tools\plaso.html',
     '/home/ruddls030/forensic/flask/hospital/templates/tools/plaso.html'),
]
for src, dst in files:
    sftp.put(src, dst)
    print(f'  OK {src.split(chr(92))[-1]}')
sftp.close()
_, out, _ = ssh.exec_command('docker restart forensic-flask')
print(out.read().decode().strip())
time.sleep(5)
_, out, _ = ssh.exec_command('docker logs --tail 8 forensic-flask 2>&1')
print(out.read().decode(errors='replace'))
ssh.close()
print('done')
