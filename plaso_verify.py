import paramiko
ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect('10.8.0.17', username='ruddls030', password='dlstn0722')
cmd = 'docker exec forensic-flask bash -c "python -c \\"import plaso; print(plaso.__version__)\\" && which log2timeline.py psort.py pinfo.py && log2timeline.py --version 2>&1 | head -2"'
_, out, _ = ssh.exec_command(cmd, timeout=60)
print(out.read().decode(errors='replace'))
ssh.close()
