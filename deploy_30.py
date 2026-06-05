"""30개 신규 도구 + 다중파일 지원 배포"""
import paramiko, time
from pathlib import Path

HOST, USER, PASS = '10.8.0.17', 'ruddls030', 'dlstn0722'
REMOTE = '/home/ruddls030/forensic/flask/hospital'
LOCAL = Path(r'E:\forensic')

uploads = [
    ('views/tools.py',                 f'{REMOTE}/views/tools.py'),
    ('views/tools_extra3.py',          f'{REMOTE}/views/tools_extra3.py'),
    ('templates/navbar.html',          f'{REMOTE}/templates/navbar.html'),
]
new_templates = ['plist','amcache','har','sigma','psdeobf','ioc','time','apk',
                 'hashlookup','heif','memscan','cuckoo','vol','magic','docker',
                 'hex','cidr','convert','regex','jsdeobf','wordlist','spreadsheet',
                 'textdiff','cve','phash','dmesg','ios_backup','whatsapp',
                 'telegram','pst']
for t in new_templates:
    uploads.append((f'templates/tools/{t}.html', f'{REMOTE}/templates/tools/{t}.html'))

# multi-file 패치된 기존 템플릿들도 재업로드
patched = ['carve','cert','diskimg','email','entropy','esedb','evtx','git','gps',
           'hash','jumplist','lnk','log','mbr','metadata','mft','ocr','oledump',
           'pcap','pdfscan','pe','prefetch','qr','registry','secrets','stego',
           'strings','triage','yara','zipcrack']
for t in patched:
    uploads.append((f'templates/tools/{t}.html', f'{REMOTE}/templates/tools/{t}.html'))

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect(HOST, username=USER, password=PASS)
sftp = ssh.open_sftp()
ok = err = 0
for r, t in uploads:
    src = LOCAL / r
    if not src.exists():
        print(f'  X [missing] {r}'); err += 1; continue
    try:
        sftp.put(str(src), t)
        ok += 1
    except Exception as e:
        print(f'  X {r}: {e}'); err += 1
sftp.close()
print(f'upload: {ok} OK, {err} fail')
_, out, _ = ssh.exec_command('docker restart forensic-flask')
print(out.read().decode().strip())
time.sleep(6)
_, out, _ = ssh.exec_command('docker logs --tail 15 forensic-flask 2>&1')
print(out.read().decode(errors='replace'))
ssh.close()
print('done')
