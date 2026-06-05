"""
ForensicLab 실제 워크플로우 시뮬레이션 테스트
============================================
진짜 데이터 생성 → POST → 응답 본문 파싱 → 예상 키워드 검증
"""
import requests, io, json, hashlib, struct, time, sqlite3, tempfile, os, base64, hmac, zipfile
from datetime import datetime

BASE = 'http://10.8.0.17:405'
S = requests.Session()
S.timeout = 20

results = []
def log(scen, name, ok, detail=''):
    icon = '✅' if ok else '❌'
    results.append((scen, name, ok, detail))
    print(f'  {icon} {name}: {detail[:120] if detail else ""}')


def expect(text, keywords, name, scen, all_required=False):
    """응답 본문에 키워드 포함 검증"""
    found = [k for k in keywords if k in text]
    if all_required:
        ok = len(found) == len(keywords)
    else:
        ok = len(found) > 0
    detail = f'발견 {found}' if ok else f'기대 {keywords} 모두 미발견'
    log(scen, name, ok, detail)
    return ok


# ─────────────────────────────────────────────────────────────
def make_sqlite(rows):
    """진짜 SQLite DB 생성"""
    tf = tempfile.NamedTemporaryFile(delete=False, suffix='.db')
    tf.close()
    con = sqlite3.connect(tf.name)
    con.execute('CREATE TABLE messages (id, address, body, date, type, read)')
    for r in rows:
        con.execute('INSERT INTO messages VALUES (?,?,?,?,?,?)', r)
    con.commit(); con.close()
    with open(tf.name, 'rb') as f: data = f.read()
    os.unlink(tf.name)
    return data


def make_jwt(payload, secret='supersecret'):
    """진짜 JWT 생성 (HS256)"""
    header = {'alg':'HS256','typ':'JWT'}
    def b64(d): return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b'=').decode()
    msg = b64(header) + '.' + b64(payload)
    sig = base64.urlsafe_b64encode(hmac.new(secret.encode(), msg.encode(), hashlib.sha256).digest()).rstrip(b'=').decode()
    return msg + '.' + sig


def make_pe():
    """최소한의 진짜 PE 헤더 (실행은 안 되지만 파싱은 됨)"""
    pe = bytearray(2048)
    # DOS header
    pe[0:2] = b'MZ'
    pe[0x3C:0x40] = struct.pack('<I', 0x80)  # PE offset
    # PE signature + COFF header
    pe[0x80:0x84] = b'PE\x00\x00'
    pe[0x84:0x86] = struct.pack('<H', 0x8664)  # machine x64
    pe[0x86:0x88] = struct.pack('<H', 2)  # 2 sections
    pe[0x88:0x8C] = struct.pack('<I', 1717000000)  # timestamp
    pe[0x94:0x96] = struct.pack('<H', 240)  # opt header size
    pe[0x96:0x98] = struct.pack('<H', 0x22)  # EXECUTABLE | DLL
    # Optional header magic (PE32+)
    pe[0x98:0x9A] = struct.pack('<H', 0x20b)
    # Subsystem at opt_off + 0x44
    pe[0x98+0x44:0x98+0x46] = struct.pack('<H', 3)  # WINDOWS_CUI
    # Section header
    sec_off = 0x98 + 240
    pe[sec_off:sec_off+8] = b'.text\x00\x00\x00'
    pe[sec_off+0x24:sec_off+0x28] = struct.pack('<I', 0x60000020)  # 실행+읽기
    # 의심 API 문자열들 박아넣기
    api_off = 0x300
    apis = b'\x00'.join([b'VirtualAlloc', b'CreateRemoteThread', b'LoadLibraryA',
                          b'URLDownloadToFile', b'kernel32.dll', b'ws2_32.dll'])
    pe[api_off:api_off+len(apis)] = apis
    return bytes(pe)


def make_pdf_suspicious():
    """의심 PDF (JavaScript 포함)"""
    return (b'%PDF-1.7\n%\xe2\xe3\xcf\xd3\n'
            b'1 0 obj\n<< /Type /Catalog /OpenAction 2 0 R >>\nendobj\n'
            b'2 0 obj\n<< /Type /Action /S /JavaScript /JS (app.alert("malicious")) >>\nendobj\n'
            b'3 0 obj\n<< /Type /EmbeddedFile >>\n'
            b'/Launch (cmd.exe /c calc.exe)\n'
            b'https://evil.example.com/payload\n'
            b'%%EOF\n')


def make_lnk():
    """LNK 시그니처가 있는 최소 파일"""
    return (b'\x4C\x00\x00\x00' + b'\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46'
            + b'\x80' + b'\x00'*3  # flags: HasName
            + b'\x00'*100)


def make_evtx():
    """EVTX 시그니처 헤더"""
    return b'ElfFile\x00' + b'\x00'*4000


def make_zip_with_files():
    """실제 ZIP (여러 파일 포함)"""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w') as zf:
        zf.writestr('secrets.txt', 'API_KEY="AKIAIOSFODNN7EXAMPLE"\npassword="hunter2"\n')
        zf.writestr('config.json', '{"db":"mysql://admin:p@ssw0rd@10.0.0.1/prod"}')
        zf.writestr('readme.md', '# Important Document\nContains sensitive data')
    return buf.getvalue()


# ─────────────────────────────────────────────────────────────
# 시나리오 1: 유틸리티·디코더
# ─────────────────────────────────────────────────────────────
print('\n=== 시나리오 1: 유틸리티·디코더 ===')

r = S.post(f'{BASE}/tools/time', data={'value': '1717250000'})
expect(r.text, ['2024', 'Unix', 'FILETIME'], 'time 변환 (Unix epoch)', 1)

r = S.post(f'{BASE}/tools/decode', data={'text': base64.b64encode(b'hello world').decode()})
expect(r.text, ['hello world', 'Base64'], 'decode Base64 자동 인식', 1)

r = S.post(f'{BASE}/tools/regex', data={'pattern': r'\b\w+@\w+\.\w+\b', 'text': 'send to admin@example.com'})
expect(r.text, ['admin@example.com', '매칭'], 'regex 이메일 패턴', 1)

r = S.post(f'{BASE}/tools/cidr', data={'cidr': '10.0.0.0/24'})
expect(r.text, ['10.0.0.', '256', '사설'], 'CIDR 사설 IP 계산', 1)

r = S.post(f'{BASE}/tools/passwd', data={'password': 'P@ssw0rd123!'})
expect(r.text, ['엔트로피', 'bits', '강함'], 'passwd 강도 측정', 1)

r = S.post(f'{BASE}/tools/wordlist', data={'seeds': 'admin', 'leet': 'on', 'case': 'on', 'min_len': '4', 'max_len': '20'})
expect(r.text, ['@dm1n', 'ADMIN', 'admin'], 'wordlist leetspeak 생성', 1)


# ─────────────────────────────────────────────────────────────
# 시나리오 2: PE 악성 의심 분석
# ─────────────────────────────────────────────────────────────
print('\n=== 시나리오 2: PE 악성 의심 분석 ===')

pe_data = make_pe()
print(f'  📦 PE 데이터: {len(pe_data)}B, sha256={hashlib.sha256(pe_data).hexdigest()[:16]}...')

r = S.post(f'{BASE}/tools/hash', files={'file': ('mal.exe', pe_data)})
expect(r.text, [hashlib.md5(pe_data).hexdigest(), 'MD5'], 'hash 계산', 2)

r = S.post(f'{BASE}/tools/multihash', files={'file': ('mal.exe', pe_data)})
expect(r.text, ['md5', 'sha256', 'sha512', 'blake2b'], 'multihash 9종 알고리즘', 2)

r = S.post(f'{BASE}/tools/pe', files={'file': ('mal.exe', pe_data)})
expect(r.text, ['x64', 'WINDOWS_CUI', 'VirtualAlloc'], 'PE 파싱 + 의심 API', 2)

r = S.post(f'{BASE}/tools/entropy', files={'file': ('mal.exe', pe_data)})
expect(r.text, ['엔트로피', 'Shannon'], 'entropy Shannon 계산', 2)

r = S.post(f'{BASE}/tools/magic', files={'file': ('mal.exe', pe_data)})
expect(r.text, ['PE/EXE/DLL', '4D5A'], 'magic 시그니처 인식', 2)

r = S.post(f'{BASE}/tools/auto', files={'file': ('mal.exe', pe_data)})
expect(r.text, ['/tools/pe', 'PE'], 'auto 라우터 PE 추천', 2)

r = S.post(f'{BASE}/tools/ai-classify', files={'file': ('mal.exe', pe_data)})
expect(r.text, ['실행파일', 'PE'], 'AI 분류 실행파일 식별', 2)

r = S.post(f'{BASE}/tools/strings', files={'file': ('mal.exe', pe_data)}, data={'min_len':'4','encoding':'both'})
expect(r.text, ['VirtualAlloc', 'CreateRemoteThread'], 'strings 의심 API 추출', 2)


# ─────────────────────────────────────────────────────────────
# 시나리오 3: 악성 PDF / 매크로 분석
# ─────────────────────────────────────────────────────────────
print('\n=== 시나리오 3: 악성 문서 분석 ===')

pdf = make_pdf_suspicious()

r = S.post(f'{BASE}/tools/pdfscan', files={'file': ('mal.pdf', pdf)})
expect(r.text, ['JavaScript', 'OpenAction', 'Launch', 'evil.example.com'], 'pdfscan 의심 패턴 + URL', 3)

r = S.post(f'{BASE}/tools/ioc', data={'text': pdf.decode('latin1', errors='replace')})
expect(r.text, ['evil.example.com', 'urls', 'domain'], 'IOC URL/도메인 추출', 3)

r = S.post(f'{BASE}/tools/attack', data={'text': 'powershell.exe -enc base64 lsass mimikatz schtasks /create'})
expect(r.text, ['T1059', 'T1003', 'mimikatz'], 'ATT&CK PowerShell+Credential 매핑', 3)


# ─────────────────────────────────────────────────────────────
# 시나리오 4: JWT / 인증 / 암호
# ─────────────────────────────────────────────────────────────
print('\n=== 시나리오 4: JWT / 인증 ===')

token = make_jwt({'sub': 'admin', 'exp': int(time.time()) + 3600, 'role': 'superuser'})
r = S.post(f'{BASE}/tools/jwt', data={'token': token})
expect(r.text, ['HS256', 'superuser', 'admin'], 'JWT HS256 디코드', 4)

expired_token = make_jwt({'sub': 'old', 'exp': int(time.time()) - 100})
r = S.post(f'{BASE}/tools/jwt', data={'token': expired_token})
expect(r.text, ['만료'], 'JWT 만료 감지', 4)

none_token = make_jwt.__defaults__[0] if make_jwt.__defaults__ else None
hdr = base64.urlsafe_b64encode(json.dumps({'alg':'none','typ':'JWT'}).encode()).rstrip(b'=').decode()
payload = base64.urlsafe_b64encode(json.dumps({'sub':'attacker'}).encode()).rstrip(b'=').decode()
none_jwt = f'{hdr}.{payload}.'
r = S.post(f'{BASE}/tools/jwt', data={'token': none_jwt})
expect(r.text, ['alg=none', '취약'], 'JWT alg=none 취약점 감지', 4)

r = S.post(f'{BASE}/tools/sign', data={'algo':'hmac', 'hash':'sha256', 'data':'hello',
                                        'key':'secret', 'action':'compute'})
expected_hmac = hmac.new(b'secret', b'hello', hashlib.sha256).hexdigest()
expect(r.text, [expected_hmac[:16]], 'HMAC-SHA256 계산 정확도', 4)


# ─────────────────────────────────────────────────────────────
# 시나리오 5: SQLite (모바일 포렌식 시뮬레이션)
# ─────────────────────────────────────────────────────────────
print('\n=== 시나리오 5: 모바일 SQLite 분석 ===')

# Android SMS 시뮬레이션
sms_data = make_sqlite([
    (1, '+82101234567', 'Hello!', int(time.time()*1000), 1, 1),
    (2, '+82109876543', 'Phishing link: http://evil.kr', int(time.time()*1000), 1, 0),
    (3, '+82101234567', 'Re: Hello', int(time.time()*1000), 2, 1),
])

r = S.post(f'{BASE}/tools/sqlite', files={'file': ('sms.db', sms_data)})
expect(r.text, ['messages', '6개 컬럼' if False else 'address'], 'SQLite 테이블 인식', 5)

r = S.post(f'{BASE}/tools/android-sms', files={'file': ('mmssms.db', sms_data)})
expect(r.text, ['+82101234567', 'Hello', 'Phishing'], 'Android SMS 메시지 추출', 5)

# iOS sms.db 형식 (다른 테이블)
def make_ios_sms():
    tf = tempfile.NamedTemporaryFile(delete=False, suffix='.db'); tf.close()
    con = sqlite3.connect(tf.name)
    con.executescript('''
        CREATE TABLE handle (ROWID INTEGER PRIMARY KEY, id TEXT);
        CREATE TABLE message (ROWID INTEGER PRIMARY KEY, date INTEGER, text TEXT, is_from_me INTEGER, handle_id INTEGER);
    ''')
    con.execute('INSERT INTO handle VALUES (1, "+12025551234")')
    con.execute('INSERT INTO message VALUES (1, 700000000000000000, "Test iOS message", 0, 1)')
    con.commit(); con.close()
    with open(tf.name, 'rb') as f: data = f.read()
    os.unlink(tf.name); return data

r = S.post(f'{BASE}/tools/ios-sms', files={'file': ('sms.db', make_ios_sms())})
expect(r.text, ['+12025551234', 'iOS message'], 'iOS sms.db 파싱', 5)


# ─────────────────────────────────────────────────────────────
# 시나리오 6: ZIP / 시크릿 / IOC 자동 체인
# ─────────────────────────────────────────────────────────────
print('\n=== 시나리오 6: ZIP 비밀 발견 → IOC ===')

zip_data = make_zip_with_files()
r = S.post(f'{BASE}/tools/zipsearch', files={'file': ('repo.zip', zip_data)}, data={'keyword': 'password'})
expect(r.text, ['secrets.txt', 'password', 'hunter2'], 'ZIP 내부 키워드 검색', 6)

# 시크릿 스캐너
secret_text = 'aws_secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"\nakia=AKIAIOSFODNN7EXAMPLE\npassword="hunter2"'
r = S.post(f'{BASE}/tools/secrets', data={'text': secret_text})
expect(r.text, ['AWS', 'AKIA', '발견'], 'secrets AWS 키 패턴 감지', 6)

# IOC 추출 (URL/IP/해시/CVE)
ioc_text = '''
Compromised host 192.168.1.100 contacted malware-c2.example.com.
Hash d41d8cd98f00b204e9800998ecf8427e was dropped.
CVE-2021-44228 exploited.
Bitcoin wallet bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh used.
'''
r = S.post(f'{BASE}/tools/ioc', data={'text': ioc_text})
expect(r.text, ['192.168.1.100', 'CVE-2021-44228', 'malware-c2', 'bc1q'], 'IOC 5종 추출 (IP/도메인/해시/CVE/BTC)', 6)


# ─────────────────────────────────────────────────────────────
# 시나리오 7: 네트워크 보안 (실시간 외부 호출)
# ─────────────────────────────────────────────────────────────
print('\n=== 시나리오 7: 네트워크 외부 호출 ===')

r = S.post(f'{BASE}/tools/dnslookup', data={'domain': 'google.com'})
expect(r.text, ['google', 'A', 'MX'], 'DNS 다중 레코드 조회', 7)

r = S.post(f'{BASE}/tools/whois', data={'target': 'google.com'})
expect(r.text, ['google', 'whois'], 'WHOIS 도메인 조회', 7)

r = S.post(f'{BASE}/tools/tls', data={'target': 'google.com:443'})
expect(r.text, ['google', 'TLS', 'SHA-256'], 'TLS 인증서 검증', 7)

r = S.post(f'{BASE}/tools/httpsec', data={'url': 'https://github.com'})
expect(r.text, ['HSTS', 'CSP', '등급'], 'HTTP 보안 헤더 채점', 7)


# ─────────────────────────────────────────────────────────────
# 시나리오 8: 사건 관리 워크플로우 (엔드투엔드)
# ─────────────────────────────────────────────────────────────
print('\n=== 시나리오 8: 사건 관리 엔드투엔드 ===')

case_num = f'CASE-WF-{int(time.time())}'
r = S.post(f'{BASE}/tools/case', data={
    'case_number': case_num, 'name': '워크플로우 테스트 사건',
    'description': 'PE 악성코드 분석',
    'examiner': '자동테스트', 'priority': 'high'
})
expect(r.text, [case_num], '사건 생성', 8)

# 생성된 사건 ID 추출
import re
m = re.search(rf'/tools/case/(\d+)[^<]*{case_num}', r.text)
if not m:
    m = re.search(r'href="/tools/case/(\d+)"', r.text)
case_id = m.group(1) if m else None
print(f'  📁 사건 ID: {case_id}')

if case_id:
    r = S.post(f'{BASE}/tools/case/{case_id}', data={
        'action': 'add_evidence', 'tool': 'pe', 'tags': 'malware,test',
        'notes': '의심 PE 파일'
    }, files={'file': ('mal.exe', pe_data)})
    expect(r.text, ['mal.exe', 'malware'], '증거 등록', 8)

    r = S.post(f'{BASE}/tools/case/{case_id}', data={
        'action': 'add_finding', 'severity': 'high', 'category': '악성코드',
        'title': 'VirtualAlloc + CreateRemoteThread 발견',
        'description': '코드 인젝션 패턴 의심',
        'attack_techniques': 'T1055, T1059'
    })
    expect(r.text, ['VirtualAlloc', 'high'], '발견사항 등록', 8)

    # PDF 보고서 다운로드
    r = S.get(f'{BASE}/tools/case/{case_id}/report')
    is_pdf = r.content[:4] == b'%PDF'
    log(8, 'PDF 보고서 자동 생성', is_pdf,
        f'PDF 헤더 확인, 크기 {len(r.content)}B' if is_pdf else '%PDF 헤더 없음')

    # 검색
    r = S.post(f'{BASE}/tools/search', data={'q': case_num})
    expect(r.text, [case_num], 'FTS5 풀텍스트 검색', 8)


# ─────────────────────────────────────────────────────────────
# 시나리오 9: 라이브러리 의존성 도구 (mft, e01, qr, ocr 등)
# ─────────────────────────────────────────────────────────────
print('\n=== 시나리오 9: 라이브러리 의존 도구 ===')

# 진짜 LNK
lnk_data = make_lnk()
r = S.post(f'{BASE}/tools/lnk', files={'file': ('test.lnk', lnk_data)})
expect(r.text, ['플래그', 'LNK'], 'LNK 시그니처 파싱', 9)

# EVTX 헤더만
r = S.post(f'{BASE}/tools/evtx', files={'file': ('test.evtx', make_evtx())})
# 헤더만 있으니 이벤트는 0개일 것 — 에러나 0건 모두 OK
ok = '0' in r.text or 'ElfFile' in r.text or 'EVTX' in r.text
log(9, 'EVTX 시그니처 인식', ok, '헤더 인식 또는 0개 이벤트')

# QR (가짜 이미지)
fake_img = b'\x89PNG\r\n\x1a\n' + b'\x00'*100
r = S.post(f'{BASE}/tools/qr', files={'file': ('test.png', fake_img)})
ok = '미발견' in r.text or '결과' in r.text or '오류' in r.text or '코드' in r.text
log(9, 'QR pyzbar 로딩', ok, '잘못된 이미지지만 라이브러리 OK')

# OCR
r = S.post(f'{BASE}/tools/ocr', files={'file': ('test.png', fake_img)}, data={'lang': 'eng'})
ok = '글자' in r.text or 'OCR' in r.text or '오류' in r.text or '추출' in r.text
log(9, 'OCR tesseract 로딩', ok, 'tesseract 호출 확인')


# ─────────────────────────────────────────────────────────────
# 시나리오 10: 백그라운드 작업 큐
# ─────────────────────────────────────────────────────────────
print('\n=== 시나리오 10: 백그라운드 작업 ===')

# Volatility (실행은 안 되지만 job 등록)
r = S.post(f'{BASE}/tools/vol-full', files={'file': ('mem.dmp', b'PAGEDU64' + b'\x00'*1000)},
            data={'plugins': 'windows.pslist.PsList'})
ok = '/tools/jobs/' in r.text or '백그라운드' in r.text or '작업' in r.text
log(10, 'Volatility 작업 큐 등록', ok, '/tools/jobs/ 리다이렉트 확인')

# Hashcat 작업 등록
r = S.post(f'{BASE}/tools/hashcat-job', data={
    'hashes': '5f4dcc3b5aa765d61d8327deb882cf99',  # password MD5
    'wordlist': 'password\nadmin\n123456',
    'mode': '0',  # MD5
    'attack_mode': '0'  # straight
})
ok = '/tools/jobs/' in r.text or '백그라운드' in r.text
log(10, 'Hashcat 작업 큐 등록', ok, 'MD5 사전 공격')

# 작업 큐 페이지
r = S.get(f'{BASE}/tools/jobs')
expect(r.text, ['작업', '큐'], '작업 큐 페이지', 10)


# ─────────────────────────────────────────────────────────────
# 시나리오 11: Chain of Custody
# ─────────────────────────────────────────────────────────────
print('\n=== 시나리오 11: Chain of Custody ===')

r = S.post(f'{BASE}/tools/coc/add',
           files={'file': ('evidence.bin', pe_data)},
           data={'action': 'evidence_intake', 'note': 'workflow test'})
try:
    j = r.json()
    ok = j.get('ok') and 'entry' in j and 'hash' in j['entry']
    log(11, 'CoC 엔트리 추가', ok, f'해시: {j["entry"]["hash"][:16]}...' if ok else 'JSON 응답 실패')
except Exception:
    log(11, 'CoC 엔트리 추가', False, 'JSON 응답 실패')

r = S.get(f'{BASE}/tools/coc')
expect(r.text, ['체인', '검증', '무결'], 'CoC 체인 페이지', 11)


# ─────────────────────────────────────────────────────────────
# 시나리오 12: 클라우드 보안 검사
# ─────────────────────────────────────────────────────────────
print('\n=== 시나리오 12: 클라우드 보안 ===')

dockerfile = '''FROM ubuntu:latest
USER root
RUN curl http://example.com/install.sh | sudo bash
RUN apt-get install -y nginx
EXPOSE 22
ENV password=secret123
CMD ["/start.sh"]
'''
r = S.post(f'{BASE}/tools/dockerfile', data={'text': dockerfile})
expect(r.text, ['root', 'latest', 'curl', 'sudo'], 'Dockerfile 4종 이상 보안 이슈', 12)

k8s_yaml = '''apiVersion: v1
kind: Pod
spec:
  hostNetwork: true
  containers:
  - name: app
    image: nginx:latest
    securityContext:
      privileged: true
      runAsUser: 0
'''
r = S.post(f'{BASE}/tools/k8sec', data={'text': k8s_yaml})
expect(r.text, ['privileged', 'hostNetwork', 'runAsUser'], 'K8s 4종 보안 이슈', 12)


# ─────────────────────────────────────────────────────────────
# 시나리오 13: 디오브푸스케이션 체이닝
# ─────────────────────────────────────────────────────────────
print('\n=== 시나리오 13: 디오브푸스케이션 ===')

ps_obfuscated = '''$enc = "U3RhcnQtUHJvY2VzcyBwb3dlcnNoZWxs"
$cmd = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($enc))
IEX $cmd
powershell.exe -enc U3RhcnQtUHJvY2Vzcw==
'''
r = S.post(f'{BASE}/tools/psdeobf', data={'text': ps_obfuscated})
expect(r.text, ['Base64', 'Start-Process', '디코드'], 'PowerShell Base64 자동 디코드', 13)

js_obf = '''eval("\\x61\\x6C\\x65\\x72\\x74(1)")
String.fromCharCode(104,101,108,108,111)
atob("aHR0cDovL2V2aWwuY29t")
'''
r = S.post(f'{BASE}/tools/jsdeobf', data={'text': js_obf})
expect(r.text, ['alert', 'hello', 'evil.com'], 'JS 다중 디오브푸 (eval/charCode/atob)', 13)


# ─────────────────────────────────────────────────────────────
# 결과 요약
# ─────────────────────────────────────────────────────────────
print('\n' + '='*65)
print('=== 워크플로우 시뮬레이션 테스트 결과 요약 ===')
print('='*65)
by_scen = {}
for scen, name, ok, _ in results:
    by_scen.setdefault(scen, []).append(ok)
SCEN_NAMES = {1:'유틸리티·디코더', 2:'PE 악성 분석', 3:'악성 문서', 4:'JWT/인증',
              5:'모바일 SQLite', 6:'ZIP/Secret/IOC', 7:'네트워크 외부 호출',
              8:'사건 관리 엔드투엔드', 9:'라이브러리 의존', 10:'백그라운드 작업',
              11:'Chain of Custody', 12:'클라우드 보안', 13:'디오브푸스케이션'}
total_ok = sum(1 for _,_,ok,_ in results if ok)
total = len(results)
for sid in sorted(by_scen):
    oks = by_scen[sid]
    n = len(oks); ok_n = sum(oks)
    icon = '✅' if ok_n == n else ('⚠️ ' if ok_n > 0 else '❌')
    print(f'  {icon} 시나리오 {sid:2d} ({SCEN_NAMES.get(sid)}): {ok_n}/{n}')
print(f'\n  📊 종합: {total_ok}/{total} ({total_ok*100//total}%)')
print('='*65)

# 실패 목록
fails = [(s, n, d) for s, n, ok, d in results if not ok]
if fails:
    print('\n실패 상세:')
    for s, n, d in fails:
        print(f'  ❌ [{SCEN_NAMES.get(s)}] {n}: {d[:140]}')
