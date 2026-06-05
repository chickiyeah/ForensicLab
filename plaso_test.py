"""plaso 실제 작동 검증"""
import paramiko
ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect('10.8.0.17', username='ruddls030', password='dlstn0722')
cmd = '''docker exec forensic-flask bash -c "
echo '=== log2timeline.py 버전 ==='
log2timeline.py --version 2>&1 | head -5
echo
echo '=== psort.py 버전 ==='
psort.py --version 2>&1 | head -5
echo
echo '=== plaso 파서 목록 (상위 30개) ==='
log2timeline.py --parsers list 2>&1 | head -40
echo
echo '=== 작동 테스트: 작은 EVTX 분석 ==='
echo 'ElfFile' > /tmp/test.evtx
mkdir -p /tmp/plaso_test
log2timeline.py --storage_file /tmp/plaso_test/out.plaso /tmp/test.evtx --status_view none 2>&1 | tail -10
ls -la /tmp/plaso_test/
"
'''
_, out, _ = ssh.exec_command(cmd, timeout=120)
print(out.read().decode(errors='replace'))
ssh.close()
