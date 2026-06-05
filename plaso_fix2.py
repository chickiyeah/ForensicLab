"""plaso 직접 호출 검증 + 심볼릭 링크"""
import paramiko
ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect('10.8.0.17', username='ruddls030', password='dlstn0722')
cmd = '''docker exec forensic-flask bash -c "
echo '=== 1. /usr/local/bin 내용 ==='
ls -la /usr/local/bin/log2* /usr/local/bin/psort* /usr/local/bin/pinfo* 2>&1
echo
echo '=== 2. \$PATH ==='
echo \$PATH
echo
echo '=== 3. 직접 경로 실행 ==='
/usr/local/bin/log2timeline 2>&1 | head -2 || true
echo '---'
/usr/local/bin/log2timeline.py 2>&1 | head -2 || true
echo '---'
python /usr/local/bin/log2timeline.py --version 2>&1 | head -3 || true
echo '---'
python -m plaso.scripts.log2timeline --version 2>&1 | head -3 || true
echo
echo '=== 4. chmod + 심볼릭 링크 추가 ==='
chmod +x /usr/local/bin/log2timeline* /usr/local/bin/psort* /usr/local/bin/pinfo* 2>&1 || true
ls -la /usr/local/bin/log2timeline* 2>&1
"
'''
_, out, _ = ssh.exec_command(cmd, timeout=60)
print(out.read().decode(errors='replace'))
ssh.close()
