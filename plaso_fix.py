"""plaso 빌드 — pkg-config + autotools 설치 후 재시도"""
import paramiko
ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect('10.8.0.17', username='ruddls030', password='dlstn0722')

cmd = '''docker exec forensic-flask bash -c "
set -e
echo '=== 1단계: 빌드 도구 설치 ==='
apt-get install -y --no-install-recommends \
    pkg-config autoconf automake libtool m4 gettext \
    zlib1g-dev libssl-dev libffi-dev libxml2-dev \
    2>&1 | tail -3

echo
echo '=== 2단계: pkg-config 확인 ==='
pkg-config --version
echo

echo '=== 3단계: 단일 libyal 테스트 (libfsntfs-python) ==='
pip install --no-cache-dir libfsntfs-python 2>&1 | tail -5
echo

echo '=== 4단계: plaso의 빌드 실패 6종 일괄 설치 ==='
pip install --no-cache-dir libevtx-python libfsext-python libfsfat-python libfsntfs-python libmodi-python libvhdi-python 2>&1 | tail -10
"
'''
_, out, _ = ssh.exec_command(cmd, timeout=900)
print(out.read().decode(errors='replace'))
ssh.close()
