import paramiko

HOST, USER, PASS = '10.8.0.17', 'ruddls030', 'dlstn0722'
ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect(HOST, username=USER, password=PASS)
sftp = ssh.open_sftp()

sftp.put(
    r'E:\forensic\templates\tools\registry.html',
    '/home/ruddls030/forensic/flask/hospital/templates/tools/registry.html'
)
sftp.close()

_, out, err = ssh.exec_command('docker restart forensic-flask')
print(out.read().decode())
print(err.read().decode())
ssh.close()
print('Done')
