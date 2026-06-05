"""인라인 도움말 배포"""
import paramiko, time
ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect('10.8.0.17', username='ruddls030', password='dlstn0722')
sftp = ssh.open_sftp()
sftp.put(r'E:\forensic\templates\base.html',
         '/home/ruddls030/forensic/flask/hospital/templates/base.html')
sftp.close()
_, out, _ = ssh.exec_command('docker restart forensic-flask')
print(out.read().decode().strip())
time.sleep(4)
ssh.close()
print('done')
