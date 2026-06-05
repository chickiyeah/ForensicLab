"""plaso 강제 설치 — Cython 다운그레이드 + pre-built libyal wheels 시도"""
import paramiko
ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect('10.8.0.17', username='ruddls030', password='dlstn0722')

# 방법 1: Cython<3 + setuptools 다운그레이드 + 재시도
cmd = '''docker exec forensic-flask bash -c "
set -e
echo '=== 1단계: Cython 다운그레이드 ==='
pip install --no-cache-dir 'Cython<3' 'setuptools<70' wheel 2>&1 | tail -3

echo '=== 2단계: libyal 시스템 라이브러리 + dev 헤더 추가 ==='
apt-get update 2>&1 | tail -2
apt-get install -y --no-install-recommends \
    libfsapfs-dev libfsext-dev libfsfat-dev libfshfs-dev libfsntfs-dev libfsxfs-dev \
    libphdi-dev libvhdi-dev libvmdk-dev libluksde-dev libbde-dev libmodi-dev \
    libsmraw-dev libqcow-dev libfvde-dev libsigscan-dev libsmdev-dev libevtx-dev \
    2>&1 | tail -3 || true

echo '=== 3단계: plaso 직접 설치 (소스에서 빌드) ==='
pip install --no-cache-dir --no-build-isolation plaso 2>&1 | tail -10
"
'''
_, out, _ = ssh.exec_command(cmd, timeout=900)
print(out.read().decode(errors='replace')[-4000:])

# 결과 확인
print('\n=== 설치 검증 ===')
_, out, _ = ssh.exec_command(
    'docker exec forensic-flask bash -c "python -c \\"import plaso; print(plaso.__version__)\\" 2>&1; command -v log2timeline.py; command -v psort.py"')
print(out.read().decode(errors='replace'))
ssh.close()
