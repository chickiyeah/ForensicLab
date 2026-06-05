import paramiko, time
ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect('10.8.0.17', username='ruddls030', password='dlstn0722')
cmd = 'cd /home/ruddls030/forensic && docker compose down 2>&1 | tail -5 && docker compose build flask 2>&1 | tail -30 && docker compose up -d 2>&1 | tail -10'
_, out, err = ssh.exec_command(cmd, timeout=600)
print(out.read().decode(errors='replace'))
print('STDERR:', err.read().decode(errors='replace')[:500])
time.sleep(8)
_, out, _ = ssh.exec_command('docker logs --tail 30 forensic-flask 2>&1')
print('\n--- logs ---')
print(out.read().decode(errors='replace'))
ssh.close()
