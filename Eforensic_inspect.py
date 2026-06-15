import paramiko
HOST, USER, PASS = '10.8.0.17', 'ruddls030', 'dlstn0722'
ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect(HOST, username=USER, password=PASS)

def run(cmd):
    _, o, e = ssh.exec_command(cmd)
    return o.read().decode(), e.read().decode()

base = '/home/ruddls030/forensic/flask'
print('=== ls flask ===')
print(run(f'ls -la {base}')[0])
print('=== ls hospital ===')
print(run(f'ls -R {base}/hospital | head -80')[0])
print('=== hospital references (py only) ===')
out,_ = run(f"grep -rl 'hospital' {base} --include='*.py' | sed 's#{base}/##'")
print(out)
print('=== docker-compose command/CMD ===')
print(run('cat /home/ruddls030/forensic/docker-compose.yml')[0])
print('=== gunicorn.conf.py ===')
print(run(f'cat {base}/gunicorn.conf.py')[0])
print('=== running container ===')
print(run('docker ps --format "{{.Names}} {{.Image}} {{.Status}}"')[0])
ssh.close()
