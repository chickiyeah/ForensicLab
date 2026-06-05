"""실제 POST 데이터로 핵심 도구 검증"""
import requests, io, json, hashlib

BASE = 'http://10.8.0.17:405'

results = []

def t(name, **kwargs):
    """라우트 테스트 후 결과 기록"""
    try:
        r = requests.post(f'{BASE}/tools/{name}', timeout=15, **kwargs)
        ok = r.status_code == 200
        # 결과 페이지에 "오류"나 "라이브러리 필요" 같은 키워드 검사
        text = r.text
        err_kws = ['alert-error','라이브러리 필요','미설치','installed','ImportError','TraceBack']
        err_found = next((kw for kw in err_kws if kw in text and 'alert-error mb-3' in text), None)
        if not ok:
            status = f'HTTP {r.status_code}'
        elif err_found:
            # 에러 메시지 추출
            import re
            m = re.search(r'alert-error[^>]*>([^<]+)', text)
            status = f'OK 200, 에러표시: {m.group(1).strip()[:80] if m else err_found}'
        else:
            status = 'OK 200 (정상)'
        results.append((name, status))
    except Exception as e:
        results.append((name, f'예외: {e}'))


# 1. 단순 텍스트 입력 도구
t('time', data={'value': '1717250000'})
t('jwt', data={'token': 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.x'})
t('decode', data={'text': 'aGVsbG8gd29ybGQ='})
t('passwd', data={'password': 'Test1234!'})
t('regex', data={'pattern': r'\d+', 'text': 'abc 123 def'})
t('cidr', data={'cidr': '192.168.1.0/24'})
t('ioc', data={'text': '1.2.3.4 https://example.com d41d8cd98f00b204e9800998ecf8427e'})
t('uaparse', data={'ua': 'Mozilla/5.0 (Windows NT 10.0) Chrome/120.0'})
t('cve', data={'query': 'log4j'})
t('attack', data={'text': 'powershell -enc encoded mimikatz lsass'})
t('dns', data={'text': 'google.com\nxkjqvzlmpoiu.xyz'})
t('urlsafe', data={'url': 'http://example.com?a=1'})
t('wordlist', data={'seeds': 'admin', 'leet': 'on'})
t('convert', data={'text': '{"a":1}', 'mode': 'yaml'})
t('markdown', data={'text': '# Title\n**bold**'})
t('textdiff', data={'text_a': 'hello\nworld', 'text_b': 'hello\nthere'})
t('psdeobf', data={'text': 'powershell -enc aGVsbG8='})
t('jsdeobf', data={'text': 'eval("alert(1)")'})

# 2. 파일 업로드 도구
fake_zip = b'PK\x03\x04' + b'\x00'*30
fake_pe = b'MZ\x90\x00' + b'\x00'*60 + b'PE\x00\x00' + b'\x00'*20
fake_sqlite = b'SQLite format 3\x00' + b'\x00'*100
fake_evtx = b'ElfFile\x00' + b'\x00'*100
fake_pdf = b'%PDF-1.7\n%\xe2\xe3\xcf\xd3\n' + b'1 0 obj\n<< /Type /Catalog >>\nendobj\n'
fake_lnk = b'\x4C\x00\x00\x00' + b'\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46' + b'\x00'*70

t('hash', files={'file': ('a.txt', b'hello')})
t('pe', files={'file': ('a.exe', fake_pe)})
t('entropy', files={'file': ('a.bin', b'\x00'*1000 + b'hello world'*100)})
t('strings', files={'file': ('a.bin', b'AAAAhello world this is test 12345' + b'\x00'*100)})
t('magic', files={'file': ('a.dat', b'\xFF\xD8\xFF' + b'\x00'*100)})
t('hex', files={'file': ('a.bin', b'AAAA'*100)}, data={'offset': 0, 'length': 32})
t('multihash', files={'file': ('a.txt', b'test')})
t('hexdiff', files={'file_a': ('a', b'hello'), 'file_b': ('b', b'world')})
t('sqlite', files={'file': ('a.db', fake_sqlite)})
t('lnk', files={'file': ('a.lnk', fake_lnk)})
t('evtx', files={'file': ('a.evtx', fake_evtx)})
t('pdfscan', files={'file': ('a.pdf', fake_pdf)})

print('=== 도구 POST 검증 결과 ===')
for name, status in results:
    icon = '✅' if 'OK 200 (정상)' in status else '⚠️ ' if '에러표시' in status else '❌'
    print(f'  {icon} /tools/{name}: {status}')
print(f'\n총 {len(results)}개 / 정상 {sum(1 for _,s in results if "OK 200 (정상)" in s)}개 / 입력에러 표시 {sum(1 for _,s in results if "에러표시" in s)}개')
