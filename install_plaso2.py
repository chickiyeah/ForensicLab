"""plaso 강제 설치 — 두 번째 시도: apt + git clone"""
import paramiko
ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect('10.8.0.17', username='ruddls030', password='dlstn0722')

# Step 1: Debian python3-plaso 패키지 시도
cmd1 = '''docker exec forensic-flask bash -c "
echo '=== apt 패키지 시도 ==='
apt-get install -y --no-install-recommends python3-plaso plaso-tools 2>&1 | tail -5 || true
echo '---'
command -v log2timeline.py 2>&1
"
'''
_, out, _ = ssh.exec_command(cmd1, timeout=180)
print(out.read().decode(errors='replace'))

# Step 2: 안 되면 git clone 후 직접 설치
cmd2 = '''docker exec forensic-flask bash -c "
if ! command -v log2timeline.py > /dev/null; then
    echo '=== git clone 시도 ==='
    cd /opt
    rm -rf plaso 2>/dev/null
    git clone --depth 1 https://github.com/log2timeline/plaso.git 2>&1 | tail -3
    cd plaso
    pip install --no-cache-dir --no-build-isolation -r requirements.txt 2>&1 | tail -10
    python setup.py install 2>&1 | tail -10
fi
echo
echo '=== 최종 검증 ==='
command -v log2timeline.py
command -v psort.py
python -c 'import plaso; print(\"plaso\", plaso.__version__)' 2>&1
"
'''
_, out, _ = ssh.exec_command(cmd2, timeout=600)
print(out.read().decode(errors='replace'))
ssh.close()
