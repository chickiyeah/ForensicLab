"""plaso 최종 정리"""
import paramiko
ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect('10.8.0.17', username='ruddls030', password='dlstn0722')
cmd = '''docker exec forensic-flask bash -c "
echo '=== 깨진 심볼릭 링크 제거 ==='
rm -f /usr/local/bin/log2timeline.py /usr/local/bin/psort.py
echo
echo '=== 새 entry point 심볼릭 (.py 별칭) ==='
ln -sf /usr/local/bin/log2timeline /usr/local/bin/log2timeline.py
ln -sf /usr/local/bin/psort /usr/local/bin/psort.py
ln -sf /usr/local/bin/pinfo /usr/local/bin/pinfo.py
ls -la /usr/local/bin/log2timeline* /usr/local/bin/psort* /usr/local/bin/pinfo* 2>&1
echo
echo '=== 작동 검증 ==='
log2timeline --version 2>&1 | head -2
log2timeline.py --version 2>&1 | head -2
psort --version 2>&1 | head -2
echo
echo '=== 파서 개수 ==='
log2timeline --parsers list 2>&1 | grep -c '^'
echo
echo '=== 실제 mini 테스트 ==='
mkdir -p /tmp/plaso_test
printf 'ElfFile\\x00' > /tmp/plaso_test/in.evtx
log2timeline --storage_file /tmp/plaso_test/out.plaso /tmp/plaso_test/in.evtx --quiet 2>&1 | tail -5
ls -la /tmp/plaso_test/
"
'''
_, out, _ = ssh.exec_command(cmd, timeout=120)
print(out.read().decode(errors='replace'))
ssh.close()
