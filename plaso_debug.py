"""plaso 빌드 정확한 에러 진단"""
import paramiko
ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect('10.8.0.17', username='ruddls030', password='dlstn0722')

cmd = '''docker exec forensic-flask bash -c "
echo '=== 현재 환경 ==='
python --version
pip --version
pip show Cython setuptools wheel 2>&1 | grep -E 'Name|Version'

echo
echo '=== 단일 libyal 패키지 빌드 정확한 에러 ==='
pip install --no-cache-dir libfsntfs-python 2>&1 | tail -40
"
'''
_, out, _ = ssh.exec_command(cmd, timeout=300)
print(out.read().decode(errors='replace'))
ssh.close()
