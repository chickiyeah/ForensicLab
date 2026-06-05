"""plaso 본체 설치 + 검증"""
import paramiko
ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect('10.8.0.17', username='ruddls030', password='dlstn0722')

cmd = '''docker exec forensic-flask bash -c "
echo '=== plaso 설치 ==='
pip install --no-cache-dir plaso 2>&1 | tail -8
echo
echo '=== 설치 검증 ==='
python -c 'import plaso; print(\"plaso:\", plaso.__version__)' 2>&1
echo
echo '=== 명령어 확인 ==='
which log2timeline.py psort.py pinfo.py 2>&1
log2timeline.py --version 2>&1 | head -3
psort.py --version 2>&1 | head -3
echo
echo '=== plaso entry points ==='
pip show plaso 2>&1 | grep -E 'Location|Version' | head -5
"
'''
_, out, _ = ssh.exec_command(cmd, timeout=600)
print(out.read().decode(errors='replace'))
ssh.close()
