"""plaso 본체 설치 — 백그라운드 실행 (nohup)"""
import paramiko, time
ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect('10.8.0.17', username='ruddls030', password='dlstn0722')

# 1. nohup으로 백그라운드 실행
cmd1 = '''docker exec -d forensic-flask bash -c "
pip install --no-cache-dir plaso > /tmp/plaso_install.log 2>&1
echo 'DONE' >> /tmp/plaso_install.log
"
'''
_, out, _ = ssh.exec_command(cmd1)
print('백그라운드 시작')
out.read()

# 2. 폴링 (최대 25분)
for i in range(50):
    time.sleep(30)
    _, out, _ = ssh.exec_command(
        'docker exec forensic-flask bash -c "grep -c DONE /tmp/plaso_install.log 2>/dev/null || echo 0; tail -1 /tmp/plaso_install.log 2>/dev/null"')
    text = out.read().decode(errors='replace').strip()
    lines = text.split('\n')
    done = lines[0] if lines else '0'
    last = lines[1] if len(lines) > 1 else ''
    print(f'[{(i+1)*30}s] DONE={done} | {last[:100]}')
    if done == '1':
        break

# 3. 최종 결과
print('\n=== 최종 결과 ===')
_, out, _ = ssh.exec_command(
    'docker exec forensic-flask bash -c "tail -30 /tmp/plaso_install.log && echo --- && python -c \'import plaso; print(plaso.__version__)\' 2>&1; which log2timeline.py psort.py"')
print(out.read().decode(errors='replace'))
ssh.close()
