"""plaso 최종 설치 — pyproject.toml editable install"""
import paramiko
ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect('10.8.0.17', username='ruddls030', password='dlstn0722')

cmd = '''docker exec forensic-flask bash -c "
cd /opt/plaso
ls *.toml *.cfg requirements*.txt setup.py 2>&1 | head -5
echo '--- tools 디렉터리 ---'
ls tools/*.py 2>&1 | head -10
echo '--- editable 설치 시도 ---'
pip install --no-cache-dir --no-build-isolation -e . 2>&1 | tail -15
echo '--- 직접 실행 시도 (PYTHONPATH 통해) ---'
PYTHONPATH=/opt/plaso python /opt/plaso/tools/log2timeline.py --version 2>&1 | head -3
echo '--- 심볼릭 링크 + 환경변수 ---'
ln -sf /opt/plaso/tools/log2timeline.py /usr/local/bin/log2timeline.py 2>&1
ln -sf /opt/plaso/tools/psort.py /usr/local/bin/psort.py 2>&1
chmod +x /opt/plaso/tools/log2timeline.py /opt/plaso/tools/psort.py 2>&1
echo 'export PYTHONPATH=/opt/plaso:\$PYTHONPATH' >> /etc/profile
echo '--- 최종 검증 ---'
command -v log2timeline.py
PYTHONPATH=/opt/plaso log2timeline.py --version 2>&1 | head -5
"
'''
_, out, _ = ssh.exec_command(cmd, timeout=600)
print(out.read().decode(errors='replace'))
ssh.close()
