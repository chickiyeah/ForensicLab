"""의존성 + 시스템 도구 점검"""
import paramiko
ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect('10.8.0.17', username='ruddls030', password='dlstn0722')

# Python 라이브러리
py_cmd = '''docker exec forensic-flask python -c "
libs = [
  ('olefile',None),('oletools',None),('dns.resolver','dnspython'),
  ('volatility3',None),('anthropic',None),('cryptography',None),
  ('Evtx','python-evtx'),('Registry','python-registry'),
  ('reportlab',None),('cv2','opencv-python-headless'),('numpy',None),
  ('requests',None),('PIL','Pillow'),('pypdf',None),('dpkt',None),
  ('chardet',None),('openpyxl',None),('markdown2',None),
  ('pytsk3',None),('pyewf','libewf-python'),('pyscca','libscca-python'),
  ('plaso',None),('aleapp','ALEAPP'),('ileapp','iLEAPP'),
  ('pyzbar',None),('pytesseract',None),('pillow_heif','pillow-heif'),
  ('face_recognition',None),('yaml','pyyaml')
]
for mod, pkg in libs:
    try:
        __import__(mod)
        print('  OK ' + mod)
    except Exception as e:
        print('  X  ' + mod + ' (pip ' + (pkg or mod) + ')')
"'''
_, out, _ = ssh.exec_command(py_cmd)
print('=== Python 라이브러리 ===')
print(out.read().decode(errors='replace'))

# 시스템 도구
sys_cmd = '''docker exec forensic-flask bash -c "
for c in hashcat tesseract log2timeline.py psort.py vol vol3 ffmpeg expand.exe; do
  if command -v \\$c > /dev/null 2>&1; then
    echo '  OK '\\$c' ('\\$(command -v \\$c)')'
  else
    echo '  X  '\\$c
  fi
done"'''
_, out, _ = ssh.exec_command(sys_cmd)
print('=== 시스템 도구 ===')
print(out.read().decode(errors='replace'))
ssh.close()
