import paramiko
ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect('10.8.0.17', username='ruddls030', password='dlstn0722')
cmd = 'docker exec forensic-flask bash -c "ls /opt/plaso/ && echo --- && find /opt/plaso -maxdepth 2 -name *.py | grep -E \\"log2timeline|psort|pinfo\\" | head -10 && echo --- && cat /opt/plaso/pyproject.toml | head -30"'
_, out, _ = ssh.exec_command(cmd, timeout=60)
print(out.read().decode(errors='replace'))
ssh.close()
