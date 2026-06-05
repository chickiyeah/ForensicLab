import paramiko
ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect('10.8.0.17', username='ruddls030', password='dlstn0722')
cmd = '''docker exec forensic-flask bash -c "
echo '=== entry points ==='
python -c 'from importlib.metadata import entry_points; [print(e) for e in entry_points().get(\"console_scripts\", []) if \"log2\" in str(e).lower() or \"plaso\" in str(e).lower() or \"psort\" in str(e).lower() or \"pinfo\" in str(e).lower()]'
echo
echo '=== bin 디렉터리 ==='
find /usr/local/bin /usr/bin -name '*log2*' -o -name 'psort*' -o -name 'pinfo*' 2>/dev/null
echo
echo '=== plaso 패키지 위치 ==='
python -c 'import plaso; print(plaso.__file__)'
echo
echo '=== plaso/scripts 모듈 ==='
python -c 'import plaso.scripts; import os; print(os.listdir(os.path.dirname(plaso.scripts.__file__)))' 2>&1
echo
echo '=== pip show plaso ==='
pip show plaso 2>&1 | head -15
"
'''
_, out, _ = ssh.exec_command(cmd, timeout=60)
print(out.read().decode(errors='replace'))
ssh.close()
