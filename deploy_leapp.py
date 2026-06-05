"""ALEAPP/iLEAPP 경로 수정 배포"""
import paramiko, time
ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect('10.8.0.17', username='ruddls030', password='dlstn0722')
sftp = ssh.open_sftp()
sftp.put(r'E:\forensic\views\tools_extra5.py',
         '/home/ruddls030/forensic/flask/hospital/views/tools_extra5.py')
sftp.close()
_, out, _ = ssh.exec_command('docker restart forensic-flask')
print(out.read().decode().strip())
time.sleep(5)
ssh.close()
print('done')
