"""71개 신규 도구 배포"""
import paramiko, time
from pathlib import Path

HOST, USER, PASS = '10.8.0.17', 'ruddls030', 'dlstn0722'
REMOTE = '/home/ruddls030/forensic/flask/hospital'
LOCAL = Path(r'E:\forensic')

uploads = [
    ('views/tools.py', f'{REMOTE}/views/tools.py'),
    ('views/tools_extra4.py', f'{REMOTE}/views/tools_extra4.py'),
    ('templates/navbar.html', f'{REMOTE}/templates/navbar.html'),
]
templates_71 = [
    'httpsec','tls','portscan','dnslookup','multihash','sign','auto','report_pdf',
    'ios_sms','ios_photos','ios_calendar','ios_notes','ios_health',
    'android_contacts','android_sms','android_calllog','android_wifi',
    'fsevents','knowledgec','quarantine','spotlight','keychain','tcc','tracev3',
    'chromecache','firefoxcache','localstorage','indexeddb',
    'dockerfile','k8sec','terraform','cloudtrail','azureactivity','gcpaudit',
    'k8saudit','o365audit','pkgvuln',
    'vbastomp','xlm','msi','msix','chm','gobin','dotnet','applocker',
    'iso','dmg','rar','sevenz','tar','cab','gzmeta',
    'jwe','pgp','pkcs7','sshhosts','gpgkey',
    'cidrcompare','urlsafe','emaildeep','zipsearch','autoanalyze','geoip',
    'uaparse','encoding','markdown','triagediff',
]
for t in templates_71:
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
        sftp.put(str(src), t); ok += 1
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
