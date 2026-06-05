# -*- coding: utf-8 -*-
"""71개 도구 템플릿 일괄 생성 — 압축된 통일 형식"""
from pathlib import Path
T = Path(r'E:\forensic\templates\tools')

HEADER = '''{% extends 'base.html' %}{% block content %}
<div class="page-hero"><div class="container">
<div class="d-flex align-items-center gap-3 mb-2"><a href="/" class="text-dim text-decoration-none small"><i class="bi bi-house me-1"></i>홈</a><i class="bi bi-chevron-right text-dim small"></i><a href="/tools" class="text-dim text-decoration-none small">분석 도구</a><i class="bi bi-chevron-right text-dim small"></i><span class="text-accent small">__TITLE__</span></div>
<h1 class="page-title"><i class="bi __ICON__ me-2 text-accent"></i>__TITLE__</h1>
<p class="page-sub">__SUB__</p></div></div>
'''

def hdr(t, s, i='bi-tools'):
    return HEADER.replace('__TITLE__', t).replace('__SUB__', s).replace('__ICON__', i)

def w(name, content):
    (T / name).write_text(content, encoding='utf-8')

# 공통 단일 파일 폼
def upload_form(accept='', extra='', multi=True):
    mult = ' multiple' if multi else ''
    return f'''<form method="POST" enctype="multipart/form-data">
<input type="file" name="file" class="form-control mb-3"{mult} {accept} required>
{extra}<button class="btn btn-accent w-100"><i class="bi bi-search me-1"></i>분석</button></form>'''

# 텍스트만 받는 폼
def text_form(rows=8, name='text', placeholder=''):
    return f'''<form method="POST"><textarea name="{name}" class="form-control mb-3" rows="{rows}" style="font-family:monospace; font-size:.78rem;" placeholder="{placeholder}"></textarea>
<button class="btn btn-accent w-100"><i class="bi bi-play me-1"></i>실행</button></form>'''


# 1. HTTPSEC
w('httpsec.html', hdr('HTTP 보안 헤더','URL → HSTS·CSP·X-Frame·X-Content-Type 등 보안 헤더 채점.','bi-shield-check') + '''
<div class="container pb-5">{% if error %}<div class="alert-error mb-3">{{ error }}</div>{% endif %}
<div class="row justify-content-center"><div class="col-lg-7"><div class="tool-panel mb-3"><form method="POST">
<input type="text" name="url" class="form-control mb-3" placeholder="https://example.com" autofocus required>
<button class="btn btn-accent w-100"><i class="bi bi-shield-check me-1"></i>검사</button>
</form></div>
{% if result %}<div class="tool-panel mb-3" style="border:2px solid var(--accent);">
<div class="text-center"><div style="font-size:3rem; font-weight:700; color:{% if result.grade == 'A+' or result.grade == 'A' %}#22c55e{% elif result.grade == 'B' %}#f59e0b{% else %}#ef4444{% endif %};">{{ result.grade }}</div>
<div class="text-dim small">점수 {{ result.score }}/100 · HTTP {{ result.status }}</div></div></div>
<div class="tool-panel mb-2"><h6 class="panel-title">보안 헤더</h6>
<table class="table table-sm" style="font-size:.82rem;"><tbody>
{% for c in result.checks %}<tr>
<td style="width:30px;">{% if c.present %}<i class="bi bi-check-circle-fill text-success"></i>{% else %}<i class="bi bi-x-circle text-danger"></i>{% endif %}</td>
<td><strong>{{ c.name }}</strong><br><span class="text-dim small">{{ c.desc }}</span></td>
<td><code style="font-size:.72rem; word-break:break-all;">{{ c.value or '(없음)' }}</code></td>
</tr>{% endfor %}</tbody></table></div>
{% if result.cookie_flags %}<div class="tool-panel"><strong>쿠키 플래그:</strong>
{% for f in result.cookie_flags %}<span class="tag me-1">{{ f }}</span>{% endfor %}</div>{% endif %}
{% endif %}
</div></div></div>{% endblock %}''')

# 2. TLS
w('tls.html', hdr('TLS 인증서 검증','host:port → 체인·SAN·만료·취약 cipher.','bi-shield-lock-fill') + '''
<div class="container pb-5">{% if error %}<div class="alert-error mb-3">{{ error }}</div>{% endif %}
<div class="row justify-content-center"><div class="col-lg-7"><div class="tool-panel mb-3"><form method="POST">
<input type="text" name="target" class="form-control mb-3" placeholder="example.com:443" autofocus required>
<button class="btn btn-accent w-100"><i class="bi bi-shield-lock me-1"></i>검증</button>
</form></div>
{% if result %}{% if result.warnings %}<div class="tool-panel mb-2">
{% for w in result.warnings %}<div>{{ w }}</div>{% endfor %}</div>{% endif %}
<div class="tool-panel"><table class="table table-sm" style="font-size:.84rem;">
<tr><td class="text-dim">호스트</td><td>{{ result.host }}:{{ result.port }}</td></tr>
<tr><td class="text-dim">TLS 버전</td><td><code>{{ result.tls_version }}</code></td></tr>
<tr><td class="text-dim">Cipher</td><td><code>{{ result.cipher }}</code> ({{ result.cipher_bits }}-bit)</td></tr>
<tr><td class="text-dim">Subject</td><td><code>{{ result.subject }}</code></td></tr>
<tr><td class="text-dim">Issuer</td><td><code>{{ result.issuer }}</code></td></tr>
<tr><td class="text-dim">시리얼</td><td><code>{{ result.serial }}</code></td></tr>
<tr><td class="text-dim">유효 시작</td><td>{{ result.not_before }}</td></tr>
<tr><td class="text-dim">유효 만료</td><td>{{ result.not_after }} <strong style="color:{% if result.days_left < 30 %}#ef4444{% else %}#22c55e{% endif %};">({{ result.days_left }}일)</strong></td></tr>
<tr><td class="text-dim">서명</td><td><code>{{ result.signature_algorithm }}</code></td></tr>
<tr><td class="text-dim">SHA-256</td><td><code style="font-size:.7rem; word-break:break-all;">{{ result.sha256 }}</code></td></tr>
{% if result.sans %}<tr><td class="text-dim">SAN</td><td>{% for s in result.sans %}<code class="me-2">{{ s }}</code>{% endfor %}</td></tr>{% endif %}
</table></div>{% endif %}
</div></div></div>{% endblock %}''')

# 3. PORTSCAN
w('portscan.html', hdr('포트 스캐너','단일 호스트 흔한 40+ 포트 검사 (안전 모드).','bi-ethernet') + '''
<div class="container pb-5">{% if error %}<div class="alert-error mb-3">{{ error }}</div>{% endif %}
<div class="alert mb-3" style="background:rgba(245,158,11,.08); border:1px solid rgba(245,158,11,.3); padding:.75rem 1rem; border-radius:.4rem;">
<i class="bi bi-shield-exclamation me-2"></i><strong>주의:</strong> 본인 소유 또는 위임받은 호스트만 스캔하세요.</div>
<div class="row justify-content-center"><div class="col-lg-7"><div class="tool-panel mb-3"><form method="POST">
<input type="text" name="host" class="form-control mb-3" placeholder="example.com 또는 IP" autofocus required>
<button class="btn btn-accent w-100"><i class="bi bi-ethernet me-1"></i>스캔</button>
</form></div>
{% if result %}<div class="tool-panel">
<h6 class="panel-title">{{ result.host }} ({{ result.ip }}) — {% if result.is_private %}사설{% else %}공용{% endif %}</h6>
<div class="text-dim small mb-2">{{ result.open_ports|length }}개 열림 / {{ result.closed_count }}개 닫힘 / {{ result.total_scanned }}개 스캔 / {{ result.duration }}초</div>
<table class="table table-sm" style="font-size:.85rem;">
<thead><tr class="text-dim"><th>포트</th><th>서비스</th><th>배너</th></tr></thead><tbody>
{% for p in result.open_ports %}<tr><td><strong style="color:#22c55e">{{ p.port }}</strong></td>
<td>{{ p.service }}</td>
<td style="font-family:monospace; font-size:.72rem; word-break:break-all;">{{ p.banner }}</td>
</tr>{% endfor %}</tbody></table></div>{% endif %}
</div></div></div>{% endblock %}''')

# 4. DNSLOOKUP
w('dnslookup.html', hdr('DNS 종합 조회','A·AAAA·MX·NS·TXT·SOA·CAA·SPF·DMARC 한 번에.','bi-broadcast') + '''
<div class="container pb-5">{% if error %}<div class="alert-error mb-3">{{ error }}</div>{% endif %}
<div class="row justify-content-center"><div class="col-lg-7"><div class="tool-panel mb-3"><form method="POST">
<input type="text" name="domain" class="form-control mb-3" placeholder="example.com" autofocus required>
<button class="btn btn-accent w-100"><i class="bi bi-broadcast me-1"></i>조회</button>
</form></div>
{% if result %}
{% for rtype, recs in result.records.items() %}{% if recs %}
<div class="tool-panel mb-2"><h6 class="panel-title">{{ rtype }} ({{ recs|length }})</h6>
{% for r in recs %}<div style="font-family:monospace; font-size:.82rem; word-break:break-all;">{{ r }}</div>{% endfor %}
</div>{% endif %}{% endfor %}
{% if result.email_auth %}<div class="tool-panel mb-2"><h6 class="panel-title">이메일 인증</h6>
{% for k, v in result.email_auth.items() %}<div><strong>{{ k }}:</strong> <code style="font-size:.78rem; word-break:break-all;">{{ v }}</code></div>{% endfor %}
</div>{% endif %}{% endif %}
</div></div></div>{% endblock %}''')

# 5. MULTIHASH
w('multihash.html', hdr('다중 해시','MD5·SHA1·SHA256·SHA512·SHA3·BLAKE2·CRC32·Adler32 한 번에.','bi-fingerprint') + '''
<div class="container pb-5">{% if error %}<div class="alert-error mb-3">{{ error }}</div>{% endif %}
{% if not result %}<div class="row justify-content-center"><div class="col-lg-6"><div class="tool-panel"><form method="POST" enctype="multipart/form-data">
<input type="file" name="file" class="form-control mb-2" multiple>
<textarea name="text" class="form-control mb-3" rows="6" placeholder="또는 텍스트"></textarea>
<button class="btn btn-accent w-100"><i class="bi bi-fingerprint me-1"></i>계산</button>
</form></div></div></div>
{% else %}{% for h in result.files %}<div class="tool-panel mb-3">
<h6 class="panel-title">{{ h.name }} — {{ "{:,}".format(h.size) }} B</h6>
<table class="table table-sm" style="font-size:.78rem;"><tbody>
{% for alg, val in h.items() %}{% if alg not in ('name','size') %}
<tr><td class="text-dim" style="width:120px;">{{ alg.upper() }}</td><td><code style="font-size:.7rem; word-break:break-all;">{{ val }}</code></td></tr>
{% endif %}{% endfor %}
</tbody></table></div>{% endfor %}
{% endif %}</div>{% endblock %}''')

# 6. SIGN
w('sign.html', hdr('HMAC / RSA / ECDSA 서명','데이터 + 키 + 서명 → 검증, 또는 HMAC 계산.','bi-pen-fill') + '''
<div class="container pb-5">{% if error %}<div class="alert-error mb-3">{{ error }}</div>{% endif %}
<div class="row justify-content-center"><div class="col-lg-8"><div class="tool-panel"><form method="POST">
<label class="form-label-sm">알고리즘</label>
<select name="algo" class="form-select mb-2">
<option value="hmac">HMAC</option><option value="rsa">RSA</option>
<option value="ecdsa">ECDSA</option><option value="ed25519">Ed25519</option></select>
<label class="form-label-sm">HMAC 해시 (HMAC 사용 시)</label>
<select name="hash" class="form-select mb-2">
<option>sha256</option><option>sha1</option><option>sha512</option><option>md5</option></select>
<label class="form-label-sm">데이터</label>
<textarea name="data" class="form-control mb-2" rows="3"></textarea>
<label class="form-label-sm">키 (HMAC: 시크릿 / RSA·ECDSA: PEM 공개키)</label>
<textarea name="key" class="form-control mb-2" rows="6" style="font-family:monospace; font-size:.7rem;"></textarea>
<label class="form-label-sm">서명 (검증 시, Base64 또는 hex)</label>
<input type="text" name="signature" class="form-control mb-2" style="font-family:monospace; font-size:.7rem;">
<select name="action" class="form-select mb-3">
<option value="verify">검증</option><option value="compute">HMAC 계산</option></select>
<button class="btn btn-accent w-100"><i class="bi bi-pen me-1"></i>실행</button>
</form></div>
{% if result %}<div class="tool-panel mt-3" style="border-left:3px solid {% if result.valid %}#22c55e{% else %}#ef4444{% endif %};">
<h6 class="panel-title">{{ result.algo }}</h6>
{% if result.computed %}<div><strong>계산:</strong> <code style="font-size:.7rem; word-break:break-all;">{{ result.computed }}</code></div>{% endif %}
{% if result.valid is defined %}<div class="mt-2"><strong>검증 결과:</strong>
{% if result.valid %}<span class="text-success">✓ 유효</span>{% else %}<span class="text-danger">✗ 불일치</span>{% endif %}
{% if result.reason %} <span class="text-dim small">({{ result.reason }})</span>{% endif %}</div>{% endif %}
</div>{% endif %}
</div></div></div>{% endblock %}''')

# 7. AUTO 라우터
w('auto.html', hdr('자동 분류 라우터','파일 시그니처 → 가장 적합한 분석 도구 자동 안내.','bi-magic') + '''
<div class="container pb-5">{% if error %}<div class="alert-error mb-3">{{ error }}</div>{% endif %}
{% if not result %}<div class="row justify-content-center"><div class="col-lg-6"><div class="tool-panel"><form method="POST" enctype="multipart/form-data">
<input type="file" name="file" multiple class="form-control mb-3" required>
<button class="btn btn-accent w-100"><i class="bi bi-magic me-1"></i>자동 분류</button>
</form></div></div></div>
{% else %}{% for r in result.files %}<div class="tool-panel mb-3">
<h6 class="panel-title">{{ r.filename }}</h6>
<div class="text-dim small mb-2">{{ "{:,}".format(r.size) }} B · SHA256 <code style="font-size:.7rem;">{{ r.sha256[:32] }}...</code></div>
{% if r.matches %}<div class="mb-2"><strong>추천 도구</strong>
{% for m in r.matches %}<div class="d-flex align-items-center gap-2 p-2 mb-1" style="background:var(--bg); border-radius:.3rem;">
<a href="{{ m.url }}" class="btn btn-sm btn-accent">{{ m.tool }}</a>
<span>{{ m.label }}</span></div>{% endfor %}</div>{% else %}<div class="text-dim">시그니처 매칭 없음</div>{% endif %}
<div class="text-dim small">헥스 헤더: <code>{{ r.hex }}</code></div>
</div>{% endfor %}{% endif %}</div>{% endblock %}''')

# 8. REPORT-PDF
w('report_pdf.html', hdr('PDF 통합 보고서','분석 이력 → 통합 PDF 보고서 생성 안내.','bi-file-earmark-pdf') + '''
<div class="container pb-5"><div class="row justify-content-center"><div class="col-lg-7"><div class="tool-panel">
<h6 class="panel-title">분석 이력 통합 PDF</h6>
<p class="text-dim">개별 분석 결과는 각 도구의 결과 페이지에서 <code>/tools/report/&lt;token&gt;</code>으로 PDF 미리보기 가능합니다.</p>
<ol style="font-size:.88rem; line-height:1.8;">
<li><a href="/tools/history" class="text-accent">분석 이력</a>에서 원하는 분석들 확인</li>
<li>각 항목의 "PDF 저장" 버튼 클릭</li>
<li>여러 보고서를 통합하려면 브라우저의 "여러 페이지를 PDF로 인쇄" 기능 사용</li>
</ol>
<a href="/tools/history" class="btn btn-accent"><i class="bi bi-archive me-1"></i>분석 이력 보기</a>
</div></div></div></div>{% endblock %}''')

# 모바일 SQLite — 통일 템플릿 생성기
def mobile_sqlite_template(name, title, sub, icon, item_keys, item_field='items', mobile_path=''):
    return hdr(title, sub, icon) + '''
<div class="container pb-5">{% if error %}<div class="alert-error mb-3">{{ error }}</div>{% endif %}
{% if not result %}<div class="row justify-content-center"><div class="col-lg-6"><div class="tool-panel"><form method="POST" enctype="multipart/form-data">
<input type="file" name="file" class="form-control mb-3" required>
''' + (f'<div class="form-hint mb-3">{mobile_path}</div>' if mobile_path else '') + '''
<button class="btn btn-accent w-100"><i class="bi bi-search me-1"></i>분석</button>
</form></div></div></div>
{% else %}<div class="d-flex gap-3 mb-3"><strong>{{ result.filename }}</strong>
<span class="text-dim small">{{ "{:,}".format(result.size) }} B</span></div>
{% if result.tables %}<div class="tool-panel mb-3"><h6 class="panel-title">테이블 ({{ result.tables|length }})</h6>
{% for t in result.tables[:30] %}<span class="tag me-1 mb-1 d-inline-block">{{ t.name }} ({{ t.rows }})</span>{% endfor %}
</div>{% endif %}
{% if result.''' + item_field + ''' %}<div class="tool-panel"><h6 class="panel-title">데이터 ({{ result.''' + item_field + '''|length }})</h6>
<div style="max-height:600px; overflow-y:auto;"><table class="table table-sm" style="font-size:.78rem;">
<thead><tr class="text-dim">''' + ''.join(f'<th>{k}</th>' for k in item_keys) + '''</tr></thead>
<tbody>{% for item in result.''' + item_field + ''' %}<tr>''' + ''.join('<td>{{ item.' + k.lower().replace(' ','_') + ' }}</td>' for k in item_keys) + '''</tr>{% endfor %}
</tbody></table></div></div>{% endif %}
{% endif %}</div>{% endblock %}'''

# 9-13. iOS
w('ios_sms.html', mobile_sqlite_template('ios_sms','iOS SMS / iMessage','sms.db 메시지·발신자 추출','bi-chat-dots-fill',['ID','TIME','TEXT','CONTACT'],'messages','/private/var/mobile/Library/SMS/sms.db'))
w('ios_photos.html', mobile_sqlite_template('ios_photos','iOS Photos','Photos.sqlite 사진 메타데이터','bi-camera-fill',['ID','FILENAME','DATE','SIZE','DIR'],'photos','iOS Photos.sqlite'))
w('ios_calendar.html', mobile_sqlite_template('ios_calendar','iOS Calendar','Calendar.sqlitedb 일정','bi-calendar-event-fill',['ID','SUMMARY','START','END','LOCATION'],'events','Calendar.sqlitedb'))
w('ios_notes.html', mobile_sqlite_template('ios_notes','iOS Notes','NoteStore.sqlite 메모','bi-journal-text',['ID','TITLE','SNIPPET','CREATED','MODIFIED'],'notes','NoteStore.sqlite'))
w('ios_health.html', mobile_sqlite_template('ios_health','iOS Health','healthdb_secure.sqlite 건강 데이터','bi-heart-pulse-fill',['TYPE','FIRST','LAST','COUNT'],'samples','healthdb_secure.sqlite'))

# 14-17. Android
w('android_contacts.html', mobile_sqlite_template('android_contacts','Android 연락처','contacts2.db','bi-person-rolodex',['ID','NAME','LAST_CONTACT','TIMES','STARRED'],'contacts','/data/data/com.android.providers.contacts/databases/contacts2.db'))
w('android_sms.html', mobile_sqlite_template('android_sms','Android SMS','mmssms.db','bi-chat-fill',['ID','ADDRESS','BODY','DATE','TYPE','READ'],'messages','/data/data/com.android.providers.telephony/databases/mmssms.db'))
w('android_calllog.html', mobile_sqlite_template('android_calllog','Android 통화 기록','calllog.db','bi-telephone-fill',['ID','NUMBER','DATE','DURATION','TYPE','NAME'],'calls','/data/data/com.android.providers.contacts/databases/calllog.db'))

# Android WiFi
w('android_wifi.html', hdr('Android Wi-Fi 비밀번호','wpa_supplicant.conf · WifiConfigStore.xml','bi-wifi') + '''
<div class="container pb-5">{% if error %}<div class="alert-error mb-3">{{ error }}</div>{% endif %}
{% if not result %}<div class="row justify-content-center"><div class="col-lg-6"><div class="tool-panel"><form method="POST" enctype="multipart/form-data">
<input type="file" name="file" class="form-control mb-3" required>
<button class="btn btn-accent w-100"><i class="bi bi-wifi me-1"></i>분석</button></form></div></div></div>
{% else %}<div class="tool-panel"><h6 class="panel-title">{{ result.count }}개 네트워크</h6>
{% for n in result.networks %}<div class="p-2 mb-2" style="background:var(--bg); border-radius:.4rem;">
{% for k, v in n.items() %}<div><strong>{{ k }}:</strong> <code style="word-break:break-all;">{{ v }}</code></div>{% endfor %}
</div>{% endfor %}</div>{% endif %}</div>{% endblock %}''')

# macOS
w('fsevents.html', hdr('FSEvents 파서','.fseventsd 로그 파일 분석','bi-eye-fill') + '''
<div class="container pb-5">{% if error %}<div class="alert-error mb-3">{{ error }}</div>{% endif %}
{% if not result %}<div class="row justify-content-center"><div class="col-lg-6"><div class="tool-panel"><form method="POST" enctype="multipart/form-data">
<input type="file" name="file" class="form-control mb-3" required>
<button class="btn btn-accent w-100"><i class="bi bi-eye me-1"></i>분석</button>
</form></div></div></div>
{% else %}<div class="tool-panel">
<h6 class="panel-title">{{ result.filename }} — {{ result.version }} · {{ result.total }}건</h6>
<div style="max-height:600px; overflow-y:auto;"><table class="table table-sm" style="font-size:.78rem;">
<thead><tr class="text-dim"><th>EID</th><th>경로</th><th>플래그</th></tr></thead><tbody>
{% for e in result.events %}<tr><td>{{ e.event_id }}</td>
<td style="word-break:break-all;"><code>{{ e.path }}</code></td>
<td>{% for f in e.flags %}<span class="tag me-1" style="font-size:.7rem">{{ f }}</span>{% endfor %}</td>
</tr>{% endfor %}</tbody></table></div></div>{% endif %}</div>{% endblock %}''')

w('knowledgec.html', mobile_sqlite_template('knowledgec','KnowledgeC.db','macOS 앱 사용·잠금 이력','bi-clock-fill',['STREAM','VALUE','START','END'],'usage','~/Library/Application Support/Knowledge/knowledgeC.db'))
w('quarantine.html', mobile_sqlite_template('quarantine','QuarantineEventsV2','macOS Gatekeeper 격리','bi-shield-x',['TIME','AGENT','URL','SENDER'],'events','~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2'))

w('spotlight.html', hdr('Spotlight 메타스토어','store.db 헤더 인식','bi-search') + '''
<div class="container pb-5">{% if error %}<div class="alert-error mb-3">{{ error }}</div>{% endif %}
{% if not result %}<div class="row justify-content-center"><div class="col-lg-6"><div class="tool-panel"><form method="POST" enctype="multipart/form-data">
<input type="file" name="file" class="form-control mb-3" required><button class="btn btn-accent w-100">분석</button></form></div></div></div>
{% else %}<div class="tool-panel"><h6 class="panel-title">{{ result.filename }}</h6>
<div><strong>포맷:</strong> {{ result.format }}</div>
<div><strong>크기:</strong> {{ "{:,}".format(result.size) }} B</div>
<div><strong>헥스:</strong> <code>{{ result.hex_preview }}</code></div>
<div class="text-dim small mt-2">{{ result.note }}</div></div>{% endif %}</div>{% endblock %}''')

w('keychain.html', hdr('macOS Keychain','.keychain 또는 keychain-2.db 분석','bi-key-fill') + '''
<div class="container pb-5">{% if error %}<div class="alert-error mb-3">{{ error }}</div>{% endif %}
{% if not result %}<div class="row justify-content-center"><div class="col-lg-6"><div class="tool-panel"><form method="POST" enctype="multipart/form-data">
<input type="file" name="file" class="form-control mb-3" required><button class="btn btn-accent w-100">분석</button></form></div></div></div>
{% else %}<div class="tool-panel"><h6 class="panel-title">{{ result.filename }}</h6>
<div><strong>포맷:</strong> {{ result.format }}</div>
{% if result.version %}<div><strong>버전:</strong> {{ result.version }}</div>{% endif %}
{% if result.tables %}<div class="mt-2"><strong>테이블:</strong> {% for t in result.tables %}<code class="me-1">{{ t.name }}</code>{% endfor %}</div>{% endif %}
<div class="text-dim small mt-2">{{ result.note }}</div></div>{% endif %}</div>{% endblock %}''')

w('tcc.html', mobile_sqlite_template('tcc','macOS TCC.db','Transparency, Consent, Control 권한 이력','bi-shield-shaded',['SERVICE','CLIENT','ALLOWED','MODIFIED'],'permissions','/Library/Application Support/com.apple.TCC/TCC.db'))

w('tracev3.html', hdr('macOS Unified Log','.tracev3 청크 구조','bi-journal-code') + '''
<div class="container pb-5">{% if error %}<div class="alert-error mb-3">{{ error }}</div>{% endif %}
{% if not result %}<div class="row justify-content-center"><div class="col-lg-6"><div class="tool-panel"><form method="POST" enctype="multipart/form-data">
<input type="file" name="file" class="form-control mb-3" accept=".tracev3" required><button class="btn btn-accent w-100">분석</button></form></div></div></div>
{% else %}<div class="tool-panel"><h6 class="panel-title">{{ result.filename }} — {{ result.total }}개 청크</h6>
<div style="max-height:500px; overflow-y:auto;"><table class="table table-sm" style="font-size:.78rem;">
<thead><tr class="text-dim"><th>오프셋</th><th>태그</th><th>이름</th><th>크기</th></tr></thead><tbody>
{% for c in result.chunks %}<tr><td>{{ c.offset }}</td><td><code>{{ c.tag }}</code></td>
<td><strong>{{ c.name }}</strong></td><td>{{ c.size }}</td></tr>{% endfor %}
</tbody></table></div></div>{% endif %}</div>{% endblock %}''')

# 브라우저 캐시
for name, title, sub, icon in [
    ('chromecache','Chrome Cache','data_*·f_* 캐시 파일','bi-browser-chrome'),
    ('firefoxcache','Firefox cache2','메타데이터 64바이트 푸터','bi-browser-firefox'),
    ('localstorage','LocalStorage','SQLite 또는 LevelDB','bi-database'),
]:
    w(f'{name}.html', hdr(title, sub, icon) + '''
<div class="container pb-5">{% if error %}<div class="alert-error mb-3">{{ error }}</div>{% endif %}
{% if not result %}<div class="row justify-content-center"><div class="col-lg-6"><div class="tool-panel"><form method="POST" enctype="multipart/form-data">
<input type="file" name="file" class="form-control mb-3" required><button class="btn btn-accent w-100">분석</button></form></div></div></div>
{% else %}<div class="tool-panel"><h6 class="panel-title">{{ result.filename }}</h6>
<div><strong>크기:</strong> {{ "{:,}".format(result.size) }} B</div>
{% if result.format %}<div><strong>포맷:</strong> {{ result.format }}</div>{% endif %}
{% if result.version %}<div><strong>버전:</strong> {{ result.version }}</div>{% endif %}
{% if result.fetch_count %}<div><strong>fetch:</strong> {{ result.fetch_count }}</div>{% endif %}
{% if result.last_fetch %}<div><strong>마지막 fetch:</strong> {{ result.last_fetch }}</div>{% endif %}
{% if result.url_key %}<div><strong>URL key:</strong> <code style="word-break:break-all;">{{ result.url_key }}</code></div>{% endif %}
{% if result.urls %}<div class="mt-2"><strong>URL:</strong><br>{% for u in result.urls %}<code class="d-block" style="font-size:.72rem; word-break:break-all;">{{ u }}</code>{% endfor %}</div>{% endif %}
{% if result.strings %}<div class="mt-2"><strong>문자열:</strong>
<div style="max-height:300px; overflow-y:auto; font-family:monospace; font-size:.72rem; background:var(--bg); padding:.4rem;">
{% for s in result.strings %}<div>{{ s }}</div>{% endfor %}</div></div>{% endif %}
</div>{% endif %}</div>{% endblock %}''')

w('indexeddb.html', hdr('IndexedDB','LevelDB 기반 IndexedDB 문자열 추출','bi-database-fill') + '''
<div class="container pb-5">{% if error %}<div class="alert-error mb-3">{{ error }}</div>{% endif %}
{% if not result %}<div class="row justify-content-center"><div class="col-lg-6"><div class="tool-panel"><form method="POST" enctype="multipart/form-data">
<input type="file" name="file" multiple class="form-control mb-3" required><button class="btn btn-accent w-100">분석</button></form></div></div></div>
{% else %}{% for r in result.files %}<div class="tool-panel mb-2"><h6 class="panel-title">{{ r.filename }} — {{ r.size }} B</h6>
<div style="max-height:300px; overflow-y:auto; font-family:monospace; font-size:.72rem; background:var(--bg); padding:.4rem;">
{% for s in r.strings %}<div>{{ s }}</div>{% endfor %}</div></div>{% endfor %}{% endif %}</div>{% endblock %}''')

# 클라우드 / DevOps
w('dockerfile.html', hdr('Dockerfile 보안 검사','베스트 프랙티스 + 보안 규칙 채점','bi-box-fill') + '''
<div class="container pb-5">{% if error %}<div class="alert-error mb-3">{{ error }}</div>{% endif %}
<div class="row g-3"><div class="col-lg-6"><div class="tool-panel"><form method="POST" enctype="multipart/form-data">
<textarea name="text" class="form-control mb-2" rows="14" style="font-family:monospace; font-size:.74rem;" placeholder="FROM ubuntu:20.04..."></textarea>
<input type="file" name="file" class="form-control mb-3">
<button class="btn btn-accent w-100"><i class="bi bi-shield-check me-1"></i>검사</button>
</form></div></div>
<div class="col-lg-6">{% if result %}
<div class="tool-panel mb-2"><div class="d-flex align-items-center gap-3">
<div style="font-size:3rem; color:{% if result.grade == 'A' %}#22c55e{% elif result.grade == 'B' %}#3b82f6{% elif result.grade == 'C' %}#f59e0b{% else %}#ef4444{% endif %};">{{ result.grade }}</div>
<div><div><strong>총 {{ result.issues|length }}개 이슈</strong></div>
<div class="text-dim small">감점 {{ result.score }} · 라인 {{ result.lines }}개</div></div></div></div>
<div class="tool-panel">{% for i in result.issues %}
<div class="p-2 mb-1" style="background:var(--bg); border-left:3px solid {% if i.sev=='high' %}#ef4444{% elif i.sev=='medium' %}#f59e0b{% else %}#6b7280{% endif %};">
<span class="text-dim small">L{{ i.line }} [{{ i.sev }}]</span> {{ i.msg }}</div>{% endfor %}</div>
{% endif %}</div></div></div>{% endblock %}''')

w('k8sec.html', hdr('Kubernetes YAML 보안','privileged·hostNetwork·root·capabilities 검사','bi-diagram-3-fill') + '''
<div class="container pb-5">{% if error %}<div class="alert-error mb-3">{{ error }}</div>{% endif %}
<div class="row g-3"><div class="col-lg-6"><div class="tool-panel"><form method="POST" enctype="multipart/form-data">
<textarea name="text" class="form-control mb-2" rows="16" style="font-family:monospace; font-size:.74rem;"></textarea>
<input type="file" name="file" class="form-control mb-3" accept=".yaml,.yml">
<button class="btn btn-accent w-100"><i class="bi bi-shield-check me-1"></i>검사</button>
</form></div></div>
<div class="col-lg-6">{% if result %}<div class="tool-panel">
<h6 class="panel-title">{{ result.docs_count }}개 문서 · {{ result.issues|length }}개 이슈 · 점수 {{ result.score }}</h6>
{% for i in result.issues %}<div class="p-2 mb-1" style="background:var(--bg); border-left:3px solid {% if i.sev=='critical' %}#dc2626{% elif i.sev=='high' %}#ef4444{% elif i.sev=='medium' %}#f59e0b{% else %}#6b7280{% endif %};">
<span class="tag me-2">{{ i.kind }}</span><span class="text-dim small">[{{ i.sev }}]</span> {{ i.msg }}</div>{% endfor %}
</div>{% endif %}</div></div></div>{% endblock %}''')

# JSON 로그 통일 (terraform/cloudtrail/azure/gcp/k8saudit/o365)
def json_log_tmpl(title, sub):
    return hdr(title, sub, 'bi-cloud-fill') + '''
<div class="container pb-5">{% if error %}<div class="alert-error mb-3">{{ error }}</div>{% endif %}
{% if not result %}<div class="row justify-content-center"><div class="col-lg-6"><div class="tool-panel"><form method="POST" enctype="multipart/form-data">
<input type="file" name="file" class="form-control mb-3" accept=".json" required>
<button class="btn btn-accent w-100">분석</button></form></div></div></div>
{% else %}<div class="tool-panel">
<h6 class="panel-title">{{ result.filename }} — {{ result.count }}개 이벤트</h6>
<div style="max-height:600px; overflow-y:auto;">
{% for ev in result.events %}<details class="mb-1"><summary class="text-dim small" style="cursor:pointer;">이벤트 {{ loop.index }}</summary>
<pre style="background:var(--bg); padding:.4rem; font-size:.7rem; max-height:300px; overflow:auto;">{{ ev | tojson(indent=2) }}</pre></details>{% endfor %}
</div></div>{% endif %}</div>{% endblock %}'''

w('terraform.html', json_log_tmpl('Terraform tfstate','상태 파일 리소스·outputs·메타'))
w('cloudtrail.html', json_log_tmpl('AWS CloudTrail','이벤트 별 source IP·사용자·작업'))
w('azureactivity.html', json_log_tmpl('Azure Activity Log','구독·리소스 그룹 활동'))
w('gcpaudit.html', json_log_tmpl('GCP Audit Log','Cloud Audit Logs JSON'))
w('k8saudit.html', json_log_tmpl('Kubernetes Audit','API 서버 감사 로그'))
w('o365audit.html', json_log_tmpl('Office 365 Activity','Office 365 통합 감사 로그'))

w('pkgvuln.html', hdr('패키지 취약점','package.json / requirements.txt → CVE 매칭','bi-shield-exclamation') + '''
<div class="container pb-5">{% if error %}<div class="alert-error mb-3">{{ error }}</div>{% endif %}
<div class="row g-3"><div class="col-lg-5"><div class="tool-panel"><form method="POST" enctype="multipart/form-data">
<textarea name="text" class="form-control mb-2" rows="10" style="font-family:monospace; font-size:.74rem;"></textarea>
<input type="file" name="file" class="form-control mb-3">
<button class="btn btn-accent w-100"><i class="bi bi-shield-exclamation me-1"></i>검사</button>
</form><div class="text-dim small mt-2">내장 DB: {{ result.db_size if result else 0 }}개 패키지</div></div></div>
<div class="col-lg-7">{% if result %}<div class="tool-panel">
<h6 class="panel-title">{{ result.count }}개 취약점</h6>
{% for f in result.findings %}<div class="p-2 mb-1" style="background:var(--bg); border-left:3px solid #ef4444;">
<strong>{{ f.package }}</strong> <code>{{ f.version }}</code>
<div class="small">{{ f.vuln }}</div></div>{% endfor %}
{% if not result.findings %}<div class="text-dim">취약점 발견 안됨 (DB가 작거나 안전한 버전)</div>{% endif %}
</div>{% endif %}</div></div></div>{% endblock %}''')

# 악성코드
def malware_tmpl(title, sub, icon, accept=''):
    return hdr(title, sub, icon) + '''
<div class="container pb-5">{% if error %}<div class="alert-error mb-3">{{ error }}</div>{% endif %}
{% if not result %}<div class="row justify-content-center"><div class="col-lg-6"><div class="tool-panel"><form method="POST" enctype="multipart/form-data">
<input type="file" name="file" class="form-control mb-3" ''' + accept + ''' required>
<button class="btn btn-accent w-100">분석</button></form></div></div></div>
{% else %}<div class="tool-panel"><h6 class="panel-title">{{ result.filename }}</h6>
{% for k, v in result.items() %}{% if k not in ('filename','strings','urls','scripts','rust_sources','functions','types','suspicious_api','streams','capabilities','files','custom_actions') %}
<div><strong>{{ k }}:</strong>
{% if v is mapping %}<pre style="font-size:.72rem; background:var(--bg); padding:.4rem; margin:.2rem 0;">{{ v | tojson(indent=2) }}</pre>
{% elif v is iterable and v is not string %}{% for x in v %}<code class="me-1">{{ x }}</code>{% endfor %}
{% else %}<code style="word-break:break-all;">{{ v }}</code>{% endif %}</div>{% endif %}{% endfor %}
{% if result.urls %}<div class="mt-2"><strong>URLs:</strong>
<div style="max-height:200px; overflow-y:auto;">{% for u in result.urls %}<code class="d-block" style="font-size:.72rem; word-break:break-all;">{{ u }}</code>{% endfor %}</div></div>{% endif %}
{% if result.suspicious_api %}<div class="mt-2 p-2" style="background:rgba(239,68,68,.08); border-radius:.4rem;"><strong class="text-danger">의심 API:</strong>
{% for a in result.suspicious_api %}<code class="me-1">{{ a }}</code>{% endfor %}</div>{% endif %}
{% if result.functions %}<div class="mt-2"><strong>함수:</strong><div style="max-height:200px; overflow-y:auto;">{% for f in result.functions %}<code class="me-1 mb-1 d-inline-block" style="font-size:.7rem;">{{ f }}</code>{% endfor %}</div></div>{% endif %}
{% if result.types %}<div class="mt-2"><strong>타입:</strong><div style="max-height:200px; overflow-y:auto;">{% for t in result.types %}<code class="me-1 mb-1 d-inline-block" style="font-size:.7rem;">{{ t }}</code>{% endfor %}</div></div>{% endif %}
{% if result.streams %}<div class="mt-2"><strong>스트림:</strong><table class="table table-sm" style="font-size:.74rem;">
{% for s in result.streams %}<tr><td><code>{{ s.name }}</code></td><td>{{ s.size }}</td></tr>{% endfor %}</table></div>{% endif %}
</div>{% endif %}</div>{% endblock %}'''

w('vbastomp.html', malware_tmpl('VBA Stomping 탐지','p-code vs 소스 비교로 stomping 탐지','bi-incognito'))
w('xlm.html', malware_tmpl('Excel 4.0 XLM 매크로','매크로 시트·CALL/EXEC 함수 탐지','bi-file-spreadsheet'))
w('msi.html', malware_tmpl('MSI Windows Installer','OLE2 스트림·CustomAction 추출','bi-windows'))
w('msix.html', malware_tmpl('MSIX / UWP 패키지','AppxManifest·capabilities','bi-app'))
w('chm.html', malware_tmpl('CHM Help 파일','ITSF·임베디드 script·URL','bi-question-circle-fill'))
w('gobin.html', malware_tmpl('Go / Rust 바이너리','buildinfo·moduledata·소스 파일 추출','bi-filetype-exe'))
w('dotnet.html', malware_tmpl('.NET 어셈블리','BSJB 메타데이터·CIL 타입 추출','bi-cpu'))
w('applocker.html', hdr('AppLocker 정책','XML 정책 룰 파싱','bi-shield-fill-check') + '''
<div class="container pb-5">{% if error %}<div class="alert-error mb-3">{{ error }}</div>{% endif %}
<div class="row g-3"><div class="col-lg-5"><div class="tool-panel"><form method="POST" enctype="multipart/form-data">
<textarea name="text" class="form-control mb-2" rows="10" style="font-family:monospace; font-size:.74rem;"></textarea>
<input type="file" name="file" class="form-control mb-3" accept=".xml">
<button class="btn btn-accent w-100">분석</button></form></div></div>
<div class="col-lg-7">{% if result %}<div class="tool-panel">
<h6 class="panel-title">규칙 {{ result.count }}개</h6>
<table class="table table-sm" style="font-size:.78rem;">
<thead><tr class="text-dim"><th>타입</th><th>액션</th><th>이름</th><th>SID</th></tr></thead><tbody>
{% for r in result.rules %}<tr><td>{{ r.type }}</td><td><strong>{{ r.action }}</strong></td>
<td>{{ r.name }}</td><td><code style="font-size:.7rem;">{{ r.user_sid }}</code></td></tr>{% endfor %}
</tbody></table></div>{% endif %}</div></div></div>{% endblock %}''')

# 압축·이미지
def archive_tmpl(title, sub, icon, accept=''):
    return hdr(title, sub, icon) + '''
<div class="container pb-5">{% if error %}<div class="alert-error mb-3">{{ error }}</div>{% endif %}
{% if not result %}<div class="row justify-content-center"><div class="col-lg-6"><div class="tool-panel"><form method="POST" enctype="multipart/form-data">
<input type="file" name="file" class="form-control mb-3" ''' + accept + ''' required>
<button class="btn btn-accent w-100">분석</button></form></div></div></div>
{% else %}<div class="tool-panel"><h6 class="panel-title">{{ result.filename }}</h6>
<table class="table table-sm" style="font-size:.84rem;"><tbody>
{% for k, v in result.items() %}{% if k != 'filename' and not (v is mapping) and not (v is iterable and v is not string) %}
<tr><td class="text-dim">{{ k }}</td><td><code style="word-break:break-all;">{{ v }}</code></td></tr>
{% endif %}{% endfor %}</tbody></table>
{% if result.strings_sample %}<div class="mt-2"><strong>문자열:</strong>
<div style="max-height:200px; overflow-y:auto; font-family:monospace; font-size:.72rem; background:var(--bg); padding:.4rem;">
{% for s in result.strings_sample %}<div>{{ s }}</div>{% endfor %}</div></div>{% endif %}
</div>{% endif %}</div>{% endblock %}'''

w('iso.html', archive_tmpl('ISO 이미지','ISO9660 볼륨 메타데이터','bi-disc'))
w('dmg.html', archive_tmpl('macOS DMG','Apple Disk Image (koly 푸터)','bi-hdd-fill'))
w('rar.html', archive_tmpl('RAR 분석','RAR4/RAR5 헤더 + 암호화 마커','bi-file-zip'))
w('sevenz.html', archive_tmpl('7-Zip 분석','7-Zip 헤더 메타데이터','bi-file-earmark-zip'))
w('cab.html', archive_tmpl('Microsoft CAB','Cabinet 파일 헤더','bi-file-earmark-binary'))
w('gzmeta.html', archive_tmpl('GZIP 메타데이터','mtime·원본 파일명·OS','bi-file-zip-fill'))

w('tar.html', hdr('TAR 메타데이터','tar 멤버별 mode·uid·gid·mtime 추출','bi-archive') + '''
<div class="container pb-5">{% if error %}<div class="alert-error mb-3">{{ error }}</div>{% endif %}
{% if not result %}<div class="row justify-content-center"><div class="col-lg-6"><div class="tool-panel"><form method="POST" enctype="multipart/form-data">
<input type="file" name="file" class="form-control mb-3" required><button class="btn btn-accent w-100">분석</button></form></div></div></div>
{% else %}<div class="tool-panel"><h6 class="panel-title">{{ result.count }}개 멤버</h6>
<div style="max-height:600px; overflow-y:auto;"><table class="table table-sm" style="font-size:.76rem;">
<thead><tr class="text-dim"><th>이름</th><th>크기</th><th>mode</th><th>UID</th><th>GID</th><th>mtime</th><th>타입</th></tr></thead><tbody>
{% for m in result.members %}<tr><td style="word-break:break-all;">{{ m.name }}</td>
<td>{{ m.size }}</td><td><code>{{ m.mode }}</code></td><td>{{ m.uid }} ({{ m.uname }})</td>
<td>{{ m.gid }} ({{ m.gname }})</td><td>{{ m.mtime }}</td><td>{{ m.type }}</td>
</tr>{% endfor %}</tbody></table></div></div>{% endif %}</div>{% endblock %}''')

# 암호
w('jwe.html', hdr('JWE / JWS 디코더','5-part JWE 또는 3-part JWS 분해','bi-key-fill') + '''
<div class="container pb-5">{% if error %}<div class="alert-error mb-3">{{ error }}</div>{% endif %}
<div class="row justify-content-center"><div class="col-lg-8"><div class="tool-panel"><form method="POST">
<textarea name="token" class="form-control mb-3" rows="8" style="font-family:monospace; font-size:.74rem;" placeholder="eyJ...">{{ token }}</textarea>
<button class="btn btn-accent w-100">디코드</button></form></div>
{% if result %}<div class="tool-panel mt-3"><h6 class="panel-title">{{ result.format }}</h6>
{% for k, v in result.items() %}{% if k != 'format' %}
<div><strong>{{ k }}:</strong>{% if v is mapping %}<pre style="background:var(--bg); padding:.4rem; font-size:.72rem;">{{ v | tojson(indent=2) }}</pre>
{% else %} <code style="word-break:break-all;">{{ v }}</code>{% endif %}</div>{% endif %}{% endfor %}
</div>{% endif %}</div></div></div>{% endblock %}''')

w('pgp.html', hdr('PGP 메시지·키','PGP 패킷 헤더 파싱','bi-envelope-paper') + '''
<div class="container pb-5">{% if error %}<div class="alert-error mb-3">{{ error }}</div>{% endif %}
<div class="row g-3"><div class="col-lg-5"><div class="tool-panel"><form method="POST" enctype="multipart/form-data">
<textarea name="text" class="form-control mb-2" rows="10" style="font-family:monospace; font-size:.7rem;"></textarea>
<input type="file" name="file" class="form-control mb-3">
<button class="btn btn-accent w-100">분석</button></form></div></div>
<div class="col-lg-7">{% if result %}<div class="tool-panel">
{% for k, v in result.items() %}<div><strong>{{ k }}:</strong> <code style="word-break:break-all;">{{ v }}</code></div>{% endfor %}
</div>{% endif %}</div></div></div>{% endblock %}''')

w('pkcs7.html', hdr('PKCS#7 / CMS','인증서 번들·서명된 메시지','bi-collection') + '''
<div class="container pb-5">{% if error %}<div class="alert-error mb-3">{{ error }}</div>{% endif %}
{% if not result %}<div class="row justify-content-center"><div class="col-lg-6"><div class="tool-panel"><form method="POST" enctype="multipart/form-data">
<input type="file" name="file" class="form-control mb-3" required><button class="btn btn-accent w-100">분석</button></form></div></div></div>
{% else %}<div class="tool-panel"><h6 class="panel-title">{{ result.filename }} — {{ result.cert_count }}개 인증서</h6>
{% for c in result.certificates %}<div class="p-2 mb-1" style="background:var(--bg);">
<div><strong>Subject:</strong> <code>{{ c.subject }}</code></div>
<div><strong>Issuer:</strong> <code>{{ c.issuer }}</code></div>
<div><strong>Serial:</strong> <code>{{ c.serial }}</code></div>
</div>{% endfor %}</div>{% endif %}</div>{% endblock %}''')

w('sshhosts.html', hdr('SSH known_hosts','호스트·해시 여부·키 타입','bi-terminal') + '''
<div class="container pb-5">{% if error %}<div class="alert-error mb-3">{{ error }}</div>{% endif %}
<div class="row g-3"><div class="col-lg-5"><div class="tool-panel"><form method="POST" enctype="multipart/form-data">
<textarea name="text" class="form-control mb-2" rows="10" style="font-family:monospace; font-size:.74rem;"></textarea>
<input type="file" name="file" class="form-control mb-3">
<button class="btn btn-accent w-100">분석</button></form></div></div>
<div class="col-lg-7">{% if result %}<div class="tool-panel"><h6 class="panel-title">{{ result.count }}개 호스트</h6>
<table class="table table-sm" style="font-size:.78rem;"><thead><tr class="text-dim"><th>호스트</th><th>해시</th><th>타입</th></tr></thead><tbody>
{% for h in result.hosts %}<tr><td><code>{{ h.host }}</code></td>
<td>{% if h.hashed %}예{% else %}아니오{% endif %}</td>
<td><code>{{ h.type }}</code></td></tr>{% endfor %}
</tbody></table></div>{% endif %}</div></div></div>{% endblock %}''')

w('gpgkey.html', hdr('GPG 키 분석','PGP 패킷 태그·UserID·서명','bi-key') + '''
<div class="container pb-5">{% if error %}<div class="alert-error mb-3">{{ error }}</div>{% endif %}
{% if not result %}<div class="row justify-content-center"><div class="col-lg-6"><div class="tool-panel"><form method="POST" enctype="multipart/form-data">
<input type="file" name="file" class="form-control mb-3" required><button class="btn btn-accent w-100">분석</button></form></div></div></div>
{% else %}<div class="tool-panel"><h6 class="panel-title">{{ result.filename }}</h6>
<table class="table table-sm" style="font-size:.78rem;"><thead><tr class="text-dim"><th>오프셋</th><th>태그</th><th>이름</th><th>길이</th><th>UserID</th></tr></thead><tbody>
{% for p in result.packets %}<tr><td>{{ p.offset }}</td><td>{{ p.tag }}</td>
<td><strong>{{ p.name }}</strong></td><td>{{ p.length }}</td><td>{{ p.userid or '' }}</td>
</tr>{% endfor %}</tbody></table></div>{% endif %}</div>{% endblock %}''')

# 유틸리티
w('cidrcompare.html', hdr('CIDR 다중 비교','여러 IP가 어떤 CIDR에 속하는지 확인','bi-diagram-3') + '''
<div class="container pb-5">{% if error %}<div class="alert-error mb-3">{{ error }}</div>{% endif %}
<div class="row g-3"><div class="col-lg-5"><div class="tool-panel"><form method="POST">
<label class="form-label-sm">CIDR 목록 (줄바꿈)</label>
<textarea name="cidrs" class="form-control mb-2" rows="6" style="font-family:monospace; font-size:.74rem;" placeholder="192.168.1.0/24
10.0.0.0/8"></textarea>
<label class="form-label-sm">IP 목록</label>
<textarea name="ips" class="form-control mb-3" rows="8" style="font-family:monospace; font-size:.74rem;"></textarea>
<button class="btn btn-accent w-100">확인</button></form></div></div>
<div class="col-lg-7">{% if result %}<div class="tool-panel">
<h6 class="panel-title">결과</h6>
<table class="table table-sm" style="font-size:.82rem;"><thead><tr class="text-dim"><th>IP</th><th>매칭 CIDR</th></tr></thead><tbody>
{% for r in result.ips %}<tr><td><code>{{ r.ip }}</code></td>
<td>{% if r.matches %}{% for m in r.matches %}<code class="me-1">{{ m }}</code>{% endfor %}
{% elif r.error %}<span class="text-danger">{{ r.error }}</span>
{% else %}<span class="text-dim">매칭 없음</span>{% endif %}</td></tr>{% endfor %}
</tbody></table></div>{% endif %}</div></div></div>{% endblock %}''')

w('urlsafe.html', hdr('URL 안전 분석','Punycode·피싱·HTTP·단축 URL 탐지','bi-link') + '''
<div class="container pb-5">{% if error %}<div class="alert-error mb-3">{{ error }}</div>{% endif %}
<div class="row justify-content-center"><div class="col-lg-8"><div class="tool-panel"><form method="POST">
<input type="text" name="url" class="form-control mb-3" placeholder="https://example.com/path?q=1" required>
<button class="btn btn-accent w-100">분석</button></form></div>
{% if result %}<div class="tool-panel mt-3"><h6 class="panel-title">결과 (안전도 {{ result.safety_score }}/100)</h6>
<table class="table table-sm" style="font-size:.84rem;">
<tr><td class="text-dim">원본</td><td><code style="word-break:break-all;">{{ result.original }}</code></td></tr>
<tr><td class="text-dim">디코드</td><td><code style="word-break:break-all;">{{ result.decoded }}</code></td></tr>
<tr><td class="text-dim">호스트</td><td>{{ result.host }}</td></tr>
<tr><td class="text-dim">스키마</td><td>{{ result.scheme }}</td></tr>
<tr><td class="text-dim">포트</td><td>{{ result.port }}</td></tr>
<tr><td class="text-dim">경로</td><td><code>{{ result.path }}</code></td></tr>
{% if result.query %}<tr><td class="text-dim">쿼리</td><td>{% for k, v in result.query.items() %}<code class="me-2">{{ k }}={{ v }}</code>{% endfor %}</td></tr>{% endif %}
</table>{% if result.warnings %}<div class="mt-2 p-2" style="background:rgba(245,158,11,.08); border-radius:.4rem;">
{% for w in result.warnings %}<div>⚠️ {{ w }}</div>{% endfor %}</div>{% endif %}
</div>{% endif %}</div></div></div>{% endblock %}''')

w('emaildeep.html', hdr('이메일 헤더 심층','경유 IP·X-헤더·도메인 불일치·인증 결과','bi-envelope-fill') + '''
<div class="container pb-5">{% if error %}<div class="alert-error mb-3">{{ error }}</div>{% endif %}
<div class="row g-3"><div class="col-lg-5"><div class="tool-panel"><form method="POST" enctype="multipart/form-data">
<textarea name="headers" class="form-control mb-2" rows="12" style="font-family:monospace; font-size:.7rem;"></textarea>
<input type="file" name="file" class="form-control mb-3" accept=".eml,.txt">
<button class="btn btn-accent w-100">분석</button></form></div></div>
<div class="col-lg-7">{% if result %}
{% if result.domain_mismatch %}<div class="alert alert-warning">{{ result.domain_mismatch }}</div>{% endif %}
<div class="tool-panel mb-2"><h6 class="panel-title">인증</h6>
<span class="tag" style="background:{% if result.spf %}rgba(34,197,94,.15);color:#22c55e{% else %}rgba(239,68,68,.15);color:#ef4444{% endif %};">SPF</span>
<span class="tag" style="background:{% if result.dkim %}rgba(34,197,94,.15);color:#22c55e{% else %}rgba(239,68,68,.15);color:#ef4444{% endif %};">DKIM</span>
<span class="tag" style="background:{% if result.dmarc %}rgba(34,197,94,.15);color:#22c55e{% else %}rgba(239,68,68,.15);color:#ef4444{% endif %};">DMARC</span>
</div>
{% if result.hop_ips %}<div class="tool-panel mb-2"><h6 class="panel-title">경유 IP</h6>
{% for ip in result.hop_ips %}<code class="d-block">{{ ip }}</code>{% endfor %}</div>{% endif %}
{% if result.received_hops %}<div class="tool-panel mb-2"><h6 class="panel-title">Received 경로</h6>
{% for h in result.received_hops %}<div class="small p-1" style="background:var(--bg); margin-bottom:.2rem;">{{ h }}</div>{% endfor %}</div>{% endif %}
{% if result.x_headers %}<div class="tool-panel mb-2"><h6 class="panel-title">X-* 헤더</h6>
{% for k, v in result.x_headers.items() %}<div><strong>{{ k }}:</strong> <code style="font-size:.72rem; word-break:break-all;">{{ v }}</code></div>{% endfor %}</div>{% endif %}
{% endif %}</div></div></div>{% endblock %}''')

w('zipsearch.html', hdr('ZIP 내부 검색','ZIP 내 모든 파일에서 키워드 검색','bi-search') + '''
<div class="container pb-5">{% if error %}<div class="alert-error mb-3">{{ error }}</div>{% endif %}
{% if not result %}<div class="row justify-content-center"><div class="col-lg-6"><div class="tool-panel"><form method="POST" enctype="multipart/form-data">
<input type="file" name="file" class="form-control mb-3" accept=".zip" required>
<input type="text" name="keyword" class="form-control mb-3" placeholder="검색어" required>
<button class="btn btn-accent w-100">검색</button></form></div></div></div>
{% else %}<div class="tool-panel"><h6 class="panel-title">'{{ result.keyword }}' — {{ result.matches|length }}개 파일</h6>
{% for m in result.matches %}<div class="p-2 mb-1" style="background:var(--bg);">
<strong>{{ m.file }}</strong> <span class="text-dim small">{{ m.size }} B · {{ m.count }}회</span>
<pre style="font-size:.72rem; margin:.2rem 0;">{{ m.context }}</pre></div>{% endfor %}
</div>{% endif %}</div>{% endblock %}''')

w('autoanalyze.html', hdr('자동 분석','파일 → 시그니처·엔트로피·IOC 자동 검사 후 추천','bi-magic') + '''
<div class="container pb-5">{% if error %}<div class="alert-error mb-3">{{ error }}</div>{% endif %}
{% if not result %}<div class="row justify-content-center"><div class="col-lg-6"><div class="tool-panel"><form method="POST" enctype="multipart/form-data">
<input type="file" name="file" multiple class="form-control mb-3" required>
<button class="btn btn-accent w-100"><i class="bi bi-magic me-1"></i>자동 분석</button>
</form></div></div></div>
{% else %}{% for r in result.files %}<div class="tool-panel mb-3">
<h6 class="panel-title">{{ r.filename }} <span class="text-dim small">— 엔트로피 {{ r.entropy }} · IOC {{ r.ioc_count or 0 }}건</span></h6>
<div class="text-dim small mb-2"><code>{{ r.sha256[:32] }}...</code></div>
{% for m in r.recommendations %}<div class="d-flex gap-2 mb-1 p-2" style="background:var(--bg); border-radius:.3rem;">
<a href="{{ m.url }}" class="btn btn-sm btn-accent">{{ m.tool }}</a><span>{{ m.label }}</span></div>{% endfor %}
</div>{% endfor %}{% endif %}</div>{% endblock %}''')

w('geoip.html', hdr('GeoIP / IP 분류','IP → 사설/공용·RIR·역방향 DNS','bi-geo-alt-fill') + '''
<div class="container pb-5">{% if error %}<div class="alert-error mb-3">{{ error }}</div>{% endif %}
<div class="row g-3"><div class="col-lg-5"><div class="tool-panel"><form method="POST">
<textarea name="ips" class="form-control mb-3" rows="10" placeholder="8.8.8.8&#10;192.168.1.1"></textarea>
<button class="btn btn-accent w-100"><i class="bi bi-geo-alt me-1"></i>조회</button></form></div></div>
<div class="col-lg-7">{% if result %}<div class="tool-panel">
<table class="table table-sm" style="font-size:.84rem;"><thead><tr class="text-dim"><th>IP</th><th>분류</th><th>RIR</th><th>호스트명</th></tr></thead><tbody>
{% for ip in result.ips %}<tr><td><code>{{ ip.ip }}</code></td><td>{{ ip.class or '' }}</td>
<td>{{ ip.rir_estimate or '' }}</td><td><code>{{ ip.hostname or '' }}</code></td></tr>{% endfor %}
</tbody></table></div>{% endif %}</div></div></div>{% endblock %}''')

w('uaparse.html', hdr('User-Agent 파서','브라우저·OS·디바이스 식별 + 봇 탐지','bi-window') + '''
<div class="container pb-5">{% if error %}<div class="alert-error mb-3">{{ error }}</div>{% endif %}
<div class="row justify-content-center"><div class="col-lg-8"><div class="tool-panel"><form method="POST">
<input type="text" name="ua" class="form-control mb-3" placeholder="Mozilla/5.0..." style="font-family:monospace; font-size:.78rem;" required>
<button class="btn btn-accent w-100">분석</button></form></div>
{% if result %}<div class="tool-panel mt-3"><h6 class="panel-title">결과</h6>
<table class="table table-sm" style="font-size:.84rem;">
<tr><td class="text-dim">UA</td><td><code style="word-break:break-all;">{{ result.ua }}</code></td></tr>
<tr><td class="text-dim">브라우저</td><td>{{ result.browser }}</td></tr>
<tr><td class="text-dim">OS</td><td>{{ result.os }}</td></tr>
<tr><td class="text-dim">디바이스</td><td>{{ result.device }}</td></tr>
{% if result.versions %}<tr><td class="text-dim">버전</td><td>{% for k, v in result.versions.items() %}<code class="me-2">{{ k }}: {{ v }}</code>{% endfor %}</td></tr>{% endif %}
{% if result.warnings %}<tr><td class="text-dim">경고</td><td>{% for w in result.warnings %}<div>{{ w }}</div>{% endfor %}</td></tr>{% endif %}
</table></div>{% endif %}</div></div></div>{% endblock %}''')

w('encoding.html', hdr('인코딩 감지·변환','BOM 감지 + 자동 인코딩 추정 + 변환','bi-translate') + '''
<div class="container pb-5">{% if error %}<div class="alert-error mb-3">{{ error }}</div>{% endif %}
<div class="row g-3"><div class="col-lg-5"><div class="tool-panel"><form method="POST" enctype="multipart/form-data">
<input type="file" name="file" class="form-control mb-2">
<textarea name="text" class="form-control mb-2" rows="6"></textarea>
<label class="form-label-sm">대상 인코딩</label>
<select name="target" class="form-select mb-3">
<option>utf-8</option><option>utf-16</option><option>cp949</option>
<option>euc-kr</option><option>latin1</option><option>ascii</option>
</select><button class="btn btn-accent w-100">분석</button></form></div></div>
<div class="col-lg-7">{% if result %}<div class="tool-panel">
<table class="table table-sm" style="font-size:.84rem;">
{% if result.bom_detected %}<tr><td class="text-dim">BOM</td><td><strong>{{ result.bom_detected }}</strong></td></tr>{% endif %}
<tr><td class="text-dim">감지된 인코딩</td><td><strong>{{ result.detected_encoding }}</strong> ({{ result.confidence }}%)</td></tr>
<tr><td class="text-dim">대상</td><td>{{ result.target }}</td></tr>
<tr><td class="text-dim">변환 크기</td><td>{{ result.converted_size }} bytes</td></tr>
</table>{% if result.preview %}<div class="mt-2"><strong>미리보기:</strong>
<pre style="background:var(--bg); padding:.4rem; font-size:.78rem; max-height:300px; overflow:auto;">{{ result.preview }}</pre></div>{% endif %}
</div>{% endif %}</div></div></div>{% endblock %}''')

w('markdown.html', hdr('Markdown 렌더링','간단한 Markdown → HTML 미리보기','bi-markdown') + '''
<div class="container pb-5">{% if error %}<div class="alert-error mb-3">{{ error }}</div>{% endif %}
<div class="row g-3"><div class="col-lg-6"><div class="tool-panel"><form method="POST">
<textarea name="text" class="form-control mb-3" rows="16" style="font-family:monospace; font-size:.78rem;"></textarea>
<button class="btn btn-accent w-100">렌더</button></form></div></div>
<div class="col-lg-6">{% if result %}<div class="tool-panel">
<h6 class="panel-title">렌더링 ({{ result.words }} 단어 · {{ result.lines }}줄)</h6>
<div style="background:var(--bg); padding:1rem; border-radius:.4rem;">{{ result.html|safe }}</div>
</div>{% endif %}</div></div></div>{% endblock %}''')

w('triagediff.html', hdr('트리아지 ZIP 비교','두 ZIP의 멤버 차이·해시 변경 확인','bi-files') + '''
<div class="container pb-5">{% if error %}<div class="alert-error mb-3">{{ error }}</div>{% endif %}
{% if not result %}<div class="row justify-content-center"><div class="col-lg-6"><div class="tool-panel"><form method="POST" enctype="multipart/form-data">
<label class="form-label-sm">ZIP A</label><input type="file" name="file_a" class="form-control mb-3" accept=".zip" required>
<label class="form-label-sm">ZIP B</label><input type="file" name="file_b" class="form-control mb-3" accept=".zip" required>
<button class="btn btn-accent w-100">비교</button></form></div></div></div>
{% else %}<div class="d-flex gap-3 mb-3"><strong>{{ result.name_a }} vs {{ result.name_b }}</strong>
<span class="text-dim small">공통 {{ result.common_count }} · 차이 {{ result.differs|length }}</span></div>
{% if result.differs %}<div class="tool-panel mb-2"><h6 class="panel-title">변경된 공통 파일 ({{ result.differs|length }})</h6>
{% for d in result.differs %}<div class="d-flex gap-3"><code>{{ d.name }}</code><span class="text-dim small">{{ d.size_a }} → {{ d.size_b }}</span></div>{% endfor %}
</div>{% endif %}
<div class="row g-3"><div class="col-md-6"><div class="tool-panel">
<h6 class="panel-title">A에만 ({{ result.only_a|length }})</h6>
<div style="max-height:300px; overflow-y:auto; font-family:monospace; font-size:.72rem;">
{% for n in result.only_a %}<div>{{ n }}</div>{% endfor %}</div></div></div>
<div class="col-md-6"><div class="tool-panel">
<h6 class="panel-title">B에만 ({{ result.only_b|length }})</h6>
<div style="max-height:300px; overflow-y:auto; font-family:monospace; font-size:.72rem;">
{% for n in result.only_b %}<div>{{ n }}</div>{% endfor %}</div></div></div></div>
{% endif %}</div>{% endblock %}''')

print('=== 71개 템플릿 생성 완료 ===')
