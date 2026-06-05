"""ForensicLab 전체 기능 시뮬레이션 테스트"""
import io, struct, requests, json, hashlib

BASE = 'http://10.8.0.17:405'
session = requests.Session()
OK = '\033[92m[OK]\033[0m'
NG = '\033[91m[NG]\033[0m'
WN = '\033[93m[WN]\033[0m'

def check(label, r, expect=200, keyword=None):
    status = r.status_code
    body   = r.text
    ok     = (status == expect)
    if ok and keyword:
        ok = keyword in body
    tag = OK if ok else NG
    detail = ''
    if not ok:
        detail = f'  status={status}'
        if keyword and keyword not in body:
            detail += f'  missing={keyword!r}'
        # 에러 힌트
        for kw in ['error', 'Error', 'Traceback', 'Internal Server']:
            idx = body.find(kw)
            if idx != -1:
                detail += f'\n       hint: ...{body[idx:idx+200].strip()}...'
                break
    print(f'  {tag} {label}{detail}')
    return ok

results = []

# ── 1. 정적 페이지 ────────────────────────────────────
print('\n[1] 정적 페이지')
r = check('GET /',       session.get(f'{BASE}/'),      keyword='ForensicLab')
r2= check('GET /intro',  session.get(f'{BASE}/intro'),  keyword='소개')
r3= check('GET /tools/', session.get(f'{BASE}/tools/'), keyword='분석 도구')
results += [r, r2, r3]

# ── 2. 로그인 / 회원가입 ──────────────────────────────
print('\n[2] 로그인 / 회원가입')
results.append(check('GET /login',  session.get(f'{BASE}/login'),  keyword='로그인'))
results.append(check('GET /signup', session.get(f'{BASE}/signup'), keyword='시작하기'))

# 회원가입
rv = session.post(f'{BASE}/signup', data={
    'username': 'testuser', 'email': 'test@test.com',
    'password': 'test1234', 'confirm': 'test1234'
})
results.append(check('POST /signup (new user)', rv, keyword='ForensicLab'))

# 로그아웃 후 로그인
session.get(f'{BASE}/logout')
rv = session.post(f'{BASE}/login', data={'username': 'testuser', 'password': 'test1234'})
results.append(check('POST /login (correct)', rv, keyword='ForensicLab'))

# 잘못된 로그인
session.get(f'{BASE}/logout')
rv = session.post(f'{BASE}/login', data={'username': 'testuser', 'password': 'wrong'})
results.append(check('POST /login (wrong pw)', rv, keyword='올바르지 않습니다'))

session.get(f'{BASE}/logout')

# ── 3. 해시 검증 ──────────────────────────────────────
print('\n[3] 해시 검증 (/tools/hash)')
results.append(check('GET', session.get(f'{BASE}/tools/hash'), keyword='해시 검증'))

# 텍스트 해시
rv = session.post(f'{BASE}/tools/hash', data={
    'text': 'hello world', 'algos': ['md5', 'sha256']
})
expected_md5 = hashlib.md5(b'hello world').hexdigest()
results.append(check('POST text hash', rv, keyword=expected_md5))

# 파일 해시
fake_file = io.BytesIO(b'binary test data 12345')
rv = session.post(f'{BASE}/tools/hash',
    data={'algos': ['sha256']},
    files={'file': ('test.bin', fake_file, 'application/octet-stream')})
results.append(check('POST file hash', rv, keyword='SHA256'))

# 해시 비교 (일치)
compare_hash = hashlib.md5(b'match me').hexdigest()
rv = session.post(f'{BASE}/tools/hash',
    data={'text': 'match me', 'algos': ['md5'], 'compare': compare_hash})
results.append(check('POST hash compare match', rv, keyword='일치'))

# 해시 비교 (불일치)
rv = session.post(f'{BASE}/tools/hash',
    data={'text': 'match me', 'algos': ['md5'], 'compare': 'aabbccdd'})
results.append(check('POST hash compare mismatch', rv, keyword='일치하지 않습니다'))

# ── 4. 파일 카빙 ──────────────────────────────────────
print('\n[4] 파일 카빙 (/tools/carve)')
results.append(check('GET', session.get(f'{BASE}/tools/carve'), keyword='파일 카빙'))

# GIF + JPEG 포함 바이너리 생성
buf  = b'\x00' * 100
buf += b'GIF89a' + b'\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00!' \
       + b'\xf9\x04\x00\x00\x00\x00\x00,' + b'\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00' \
       + b'\x00;'
buf += b'\x00' * 200
buf += b'\xff\xd8\xff\xe0' + b'\x00' * 50 + b'\xff\xd9'
buf += b'\x00' * 100

rv = session.post(f'{BASE}/tools/carve',
    data={'types': ['gif', 'jpeg']},
    files={'file': ('test.bin', io.BytesIO(buf), 'application/octet-stream')})
results.append(check('POST carve (GIF+JPEG)', rv, keyword='복구'))

# 카빙 결과 없음
rv = session.post(f'{BASE}/tools/carve',
    data={'types': ['pdf']},
    files={'file': ('empty.bin', io.BytesIO(b'\x00' * 512), 'application/octet-stream')})
results.append(check('POST carve (no result)', rv, keyword='0'))

# ── 5. MBR 분석 ───────────────────────────────────────
print('\n[5] MBR 분석 (/tools/mbr)')
results.append(check('GET', session.get(f'{BASE}/tools/mbr'), keyword='MBR 분석'))

# 유효한 MBR 생성
mbr = bytearray(512)
mbr[510] = 0x55
mbr[511] = 0xAA
# FAT32 파티션 엔트리
mbr[446] = 0x80      # bootable
mbr[446+4] = 0x0C    # FAT32 LBA
struct.pack_into('<I', mbr, 446+8, 2048)    # LBA start
struct.pack_into('<I', mbr, 446+12, 204800)  # LBA size

rv = session.post(f'{BASE}/tools/mbr',
    files={'file': ('disk.img', io.BytesIO(bytes(mbr)), 'application/octet-stream')})
results.append(check('POST MBR valid', rv, keyword='55AA'))
results.append(check('POST MBR partition FAT32', rv, keyword='FAT32'))

# 잘못된 MBR
bad_mbr = bytearray(512)
rv = session.post(f'{BASE}/tools/mbr',
    files={'file': ('bad.img', io.BytesIO(bytes(bad_mbr)), 'application/octet-stream')})
results.append(check('POST MBR invalid', rv, keyword='0000'))

# ── 6. 문자열 추출 ────────────────────────────────────
print('\n[6] 문자열 추출 (/tools/strings)')
results.append(check('GET', session.get(f'{BASE}/tools/strings'), keyword='문자열 추출'))

# ASCII 문자열 포함 바이너리
data = b'\x00\x01\x02' + b'Hello, ForensicLab!' + b'\x00' * 10 \
     + b'http://example.com' + b'\x00\x00' + b'password123456' + b'\x00' * 5
rv = session.post(f'{BASE}/tools/strings',
    data={'min_len': '4', 'encoding': 'ascii'},
    files={'file': ('test.bin', io.BytesIO(data), 'application/octet-stream')})
results.append(check('POST strings ASCII', rv, keyword='ForensicLab'))

# 키워드 필터
rv = session.post(f'{BASE}/tools/strings',
    data={'min_len': '4', 'encoding': 'ascii', 'keyword': 'password'},
    files={'file': ('test.bin', io.BytesIO(data), 'application/octet-stream')})
results.append(check('POST strings keyword filter', rv, keyword='password'))

# Unicode
uni_data = b'\x00' * 10 + 'Hello'.encode('utf-16-le') + b'\x00\x00' * 5
rv = session.post(f'{BASE}/tools/strings',
    data={'min_len': '4', 'encoding': 'unicode'},
    files={'file': ('uni.bin', io.BytesIO(uni_data), 'application/octet-stream')})
results.append(check('POST strings Unicode', rv, keyword='Unicode'))

# ── 7. 로그 분석 ──────────────────────────────────────
print('\n[7] 로그 분석 (/tools/log)')
results.append(check('GET', session.get(f'{BASE}/tools/log'), keyword='로그 분석'))

apache_log = (
    '192.168.1.1 - - [01/Jun/2026:12:00:00 +0000] "GET / HTTP/1.1" 200 1234\n'
    '10.0.0.5 - - [01/Jun/2026:12:01:00 +0000] "GET /../etc/passwd HTTP/1.1" 404 512\n'
    '10.0.0.5 - - [01/Jun/2026:12:02:00 +0000] "POST /login HTTP/1.1" 401 256\n'
    '10.0.0.5 - - [01/Jun/2026:12:03:00 +0000] "GET /shell?cmd=id HTTP/1.1" 500 0\n'
)

# 파일 업로드
rv = session.post(f'{BASE}/tools/log',
    files={'file': ('access.log', io.BytesIO(apache_log.encode()), 'text/plain')})
results.append(check('POST log file (Apache)', rv, keyword='192.168.1.1'))
results.append(check('POST log suspicious detect', rv, keyword='이상 이벤트'))

# 텍스트 직접 입력
rv = session.post(f'{BASE}/tools/log', data={'text': apache_log})
results.append(check('POST log text input', rv, keyword='이벤트'))

# syslog
syslog = 'Jun  1 12:00:00 server sshd: Failed password for root from 1.2.3.4 port 22\n' * 5
rv = session.post(f'{BASE}/tools/log', data={'text': syslog})
results.append(check('POST log syslog', rv, keyword='syslog'))

# ── 8. GPS 추출 ───────────────────────────────────────
print('\n[8] GPS 추출 (/tools/gps)')
results.append(check('GET', session.get(f'{BASE}/tools/gps'), keyword='GPS 추출'))

# JPEG with GPS EXIF (실제 GPS 데이터 포함 이미지)
import urllib.request
try:
    # 공개 GPS 이미지 다운로드
    url = 'https://upload.wikimedia.org/wikipedia/commons/thumb/b/b9/Above_Gotham.jpg/320px-Above_Gotham.jpg'
    with urllib.request.urlopen(url, timeout=5) as resp:
        gps_img = resp.read()
    rv = session.post(f'{BASE}/tools/gps',
        files={'file': ('gps.jpg', io.BytesIO(gps_img), 'image/jpeg')})
    results.append(check('POST gps (real JPEG w/ EXIF)', rv, keyword='GPS'))
except Exception as e:
    print(f'  {WN} GPS test skipped (network): {e}')
    results.append(True)  # skip

# GPS 없는 일반 JPEG (최소 유효 JPEG)
minimal_jpeg = (b'\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00'
                b'\xff\xdb\x00C\x00\x08\x06\x06\x07\x06\x05\x08\x07\x07\x07\t\t'
                b'\x08\n\x0c\x14\r\x0c\x0b\x0b\x0c\x19\x12\x13\x0f\x14\x1d\x1a'
                b'\x1f\x1e\x1d\x1a\x1c\x1c $.\' ",#\x1c\x1c(7),01444\x1f\'9=82<.342\x87\xff\xd9')
rv = session.post(f'{BASE}/tools/gps',
    files={'file': ('nogps.jpg', io.BytesIO(minimal_jpeg), 'image/jpeg')})
results.append(check('POST gps (no GPS data)', rv, keyword='GPS'))

# 비이미지 파일 거부
rv = session.post(f'{BASE}/tools/gps',
    files={'file': ('test.txt', io.BytesIO(b'not an image'), 'text/plain')})
results.append(check('POST gps (non-image reject)', rv, keyword='이미지'))

# ── 9. 메타데이터 추출 ────────────────────────────────
print('\n[9] 메타데이터 추출 (/tools/metadata)')
results.append(check('GET', session.get(f'{BASE}/tools/metadata'), keyword='메타데이터'))

rv = session.post(f'{BASE}/tools/metadata',
    files={'file': ('test.bin', io.BytesIO(b'test data ' * 100), 'application/octet-stream')})
results.append(check('POST metadata (binary)', rv, keyword='MD5'))

# JPEG 메타데이터
rv = session.post(f'{BASE}/tools/metadata',
    files={'file': ('test.jpg', io.BytesIO(minimal_jpeg), 'image/jpeg')})
results.append(check('POST metadata (JPEG)', rv, keyword='JPEG'))

# ── 10. 타임라인 재구성 ───────────────────────────────
print('\n[10] 타임라인 재구성 (/tools/timeline)')
results.append(check('GET', session.get(f'{BASE}/tools/timeline'), keyword='타임라인'))

log_with_ts = (
    '192.168.1.1 - - [01/Jun/2026:08:00:00 +0000] "GET / HTTP/1.1" 200 512\n'
    '192.168.1.2 - - [01/Jun/2026:09:30:00 +0000] "POST /login HTTP/1.1" 200 128\n'
    '10.0.0.1 - - [01/Jun/2026:10:15:00 +0000] "GET /admin HTTP/1.1" 403 0\n'
)
rv = session.post(f'{BASE}/tools/timeline',
    files={'files': ('access.log', io.BytesIO(log_with_ts.encode()), 'text/plain')})
results.append(check('POST timeline (log)', rv, keyword='이벤트'))

# ── 11. 패킷 분석 ─────────────────────────────────────
print('\n[11] 패킷 분석 (/tools/pcap)')
results.append(check('GET', session.get(f'{BASE}/tools/pcap'), keyword='패킷 분석'))

# 유효한 pcap 파일 생성 (최소 구조)
import struct as _s
pcap_global = _s.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)  # magic, ver, thiszone, sigfigs, snaplen, linktype
# 빈 pcap (헤더만)
rv = session.post(f'{BASE}/tools/pcap',
    files={'file': ('empty.pcap', io.BytesIO(pcap_global), 'application/octet-stream')})
results.append(check('POST pcap (empty)', rv, keyword='패킷'))

# dpkt 없는 경우 대비 - txt 파일로 에러 처리 확인
rv = session.post(f'{BASE}/tools/pcap',
    files={'file': ('bad.pcap', io.BytesIO(b'not a pcap file'), 'application/octet-stream')})
results.append(check('POST pcap (invalid file)', rv, keyword='pcap'))

# ── 12. MBR 복구 ──────────────────────────────────────
print('\n[12] MBR 복구 (/tools/mbr-repair)')
results.append(check('GET', session.get(f'{BASE}/tools/mbr-repair'), keyword='MBR 복구'))

# 장치 목록 API
rv = session.get(f'{BASE}/tools/mbr-repair/devices')
results.append(check('GET /devices API', rv, keyword='devices'))
try:
    dj = rv.json()
    print(f'       -> devices: {[d["path"] for d in dj.get("devices", [])]}')
except:
    pass

# 복구 미리보기 - NTFS VBR이 포함된 소형 이미지 (512KB)
# 섹터 2048에 NTFS VBR 삽입 (2048 * 512 = 1MB -> 512KB로 축소해서 섹터 100에 배치)
repair_img = bytearray(600 * 512)  # ~300KB
vbr_sec = 100  # LBA 100
vbr_off = vbr_sec * 512
repair_img[vbr_off + 3 : vbr_off + 11] = b'NTFS    '
repair_img[vbr_off + 510] = 0x55
repair_img[vbr_off + 511] = 0xAA
struct.pack_into('<Q', repair_img, vbr_off + 0x28, 204800)
rv = session.post(f'{BASE}/tools/mbr-repair',
    data={'action': 'preview'},
    files={'file': ('repair.img', io.BytesIO(bytes(repair_img)), 'application/octet-stream')})
results.append(check('POST mbr-repair preview', rv, keyword='미리보기'))

# ── 13. 분석 이력 ─────────────────────────────────────
print('\n[13] 분석 이력 (/tools/history)')
rv = session.get(f'{BASE}/tools/history')
results.append(check('GET /tools/history', rv, keyword='분석 이력'))
# 이력이 있는지 (이전 테스트들이 로그 저장했을 것)
if '분석 이력' in rv.text:
    count = rv.text.count('hash') + rv.text.count('carve') + rv.text.count('log')
    print(f'       -> 이력 항목 검출: {count}건 이상')

# ── 14. 공유 링크 ─────────────────────────────────────
print('\n[14] 공유 링크 / 리포트')
# 해시 분석 결과에서 share_token 추출
rv = session.post(f'{BASE}/tools/hash', data={'text': 'share test', 'algos': ['md5']})
import re
token_m = re.search(r"/tools/report/([0-9a-f-]{36})|copyShareLink\('([0-9a-f-]{36})'", rv.text)
if token_m:
    token = token_m.group(1) or token_m.group(2)
    results.append(check(f'GET /tools/share/{token[:8]}...', session.get(f'{BASE}/tools/share/{token}'), keyword='해시'))
    results.append(check(f'GET /tools/report/{token[:8]}...', session.get(f'{BASE}/tools/report/{token}'), keyword='ForensicLab'))
    print(f'       -> token: {token}')
else:
    print(f'  {WN} share_token not found in response (DB logging may have failed)')
    results += [False, False]

# ── 15. 센서 모니터링 ─────────────────────────────────
print('\n[15] 센서 모니터링 (/monitor/sensor)')
results.append(check('GET /monitor/sensor', session.get(f'{BASE}/monitor/sensor'), keyword='센서'))

rv = session.post(f'{BASE}/monitor/sensor/data', data={'part': 'temp_sensor_1', 'data': '36.5'})
results.append(check('POST sensor data', rv, keyword='true'))

rv = session.get(f'{BASE}/monitor/sensor/api')
results.append(check('GET sensor api', rv, keyword='temp_sensor_1'))
try:
    sj = rv.json()
    print(f'       -> {len(sj)}개 센서 레코드')
except:
    pass

# ── 결과 요약 ─────────────────────────────────────────
print('\n' + '='*55)
passed = sum(1 for r in results if r)
total  = len(results)
failed = total - passed
print(f'  결과: {passed}/{total} 통과  |  실패: {failed}건')
print('='*55)
