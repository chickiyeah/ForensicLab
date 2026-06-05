# -*- coding: utf-8 -*-
"""30개 도구 템플릿 일괄 생성 — 충돌 회피용 직접 문자열"""
from pathlib import Path
T = Path(r'E:\forensic\templates\tools')

def w(name, content):
    (T / name).write_text(content, encoding='utf-8')
    print(f'  OK {name}')


HEADER = '''{% extends 'base.html' %}{% block content %}
<div class="page-hero"><div class="container">
<div class="d-flex align-items-center gap-3 mb-2"><a href="/" class="text-dim text-decoration-none small"><i class="bi bi-house me-1"></i>홈</a><i class="bi bi-chevron-right text-dim small"></i><a href="/tools" class="text-dim text-decoration-none small">분석 도구</a><i class="bi bi-chevron-right text-dim small"></i><span class="text-accent small">__TITLE__</span></div>
<h1 class="page-title"><i class="bi __ICON__ me-2 text-accent"></i>__TITLE__</h1>
<p class="page-sub">__SUB__</p></div></div>
'''

def hdr(t, s, i='bi-tools'):
    return HEADER.replace('__TITLE__', t).replace('__SUB__', s).replace('__ICON__', i)

MULTI = '''<form method="POST" enctype="multipart/form-data">
<input type="file" name="file" class="form-control mb-3" multiple required>
<div class="form-hint mb-3"><i class="bi bi-info-circle me-1"></i>여러 파일 동시 업로드 가능</div>
<button class="btn btn-accent w-100"><i class="bi bi-search me-1"></i>분석</button></form>'''

# PLIST
w('plist.html', hdr('Plist 파서','macOS bplist 바이너리·XML plist 파싱. LaunchAgents·앱 설정·Quarantine 분석.','bi-apple') + '''
<div class="container pb-5">{% if error %}<div class="alert-error mb-3">{{ error }}</div>{% endif %}
{% if not result %}<div class="row justify-content-center"><div class="col-lg-6"><div class="tool-panel">''' + MULTI + '''</div></div></div>
{% else %}{% for r in result.files %}<div class="tool-panel mb-3">
<h6 class="panel-title"><i class="bi bi-file me-2"></i>{{ r.filename }}{% if r.format %} <span class="text-dim small">— {{ r.format }}</span>{% endif %}</h6>
{% if r.error %}<div class="text-danger">{{ r.error }}</div>
{% else %}<pre style="background:var(--bg); padding:.6rem; border-radius:.4rem; font-size:.78rem; max-height:500px; overflow:auto; margin:0;">{{ r.data_json | tojson(indent=2) }}</pre>
{% endif %}</div>{% endfor %}
<a href="/tools/plist" class="btn btn-sm btn-outline-secondary"><i class="bi bi-arrow-left me-1"></i>새 파일</a>
{% endif %}</div>{% endblock %}''')

# AMCACHE
w('amcache.html', hdr('AmCache 파서','Amcache.hve의 InventoryApplicationFile (실행파일 SHA1·LinkDate·제품명·크기).','bi-app-indicator') + '''
<div class="container pb-5">{% if error %}<div class="alert-error mb-3">{{ error }}</div>{% endif %}
{% if not result %}<div class="row justify-content-center"><div class="col-lg-6"><div class="tool-panel">''' + MULTI + '''<div class="form-hint">C:\\Windows\\AppCompat\\Programs\\Amcache.hve</div></div></div></div>
{% else %}{% for r in result.files %}<div class="tool-panel mb-3">
<h6 class="panel-title">{{ r.filename }}{% if r.modern_count is defined %} — Modern {{ r.modern_count }}, Legacy {{ r.legacy_count }}{% endif %}</h6>
{% if r.error %}<div class="text-danger">{{ r.error }}</div>{% else %}
{% if r.modern %}<div style="max-height:500px; overflow-y:auto;"><table class="table table-sm" style="font-size:.78rem;">
<thead><tr class="text-dim"><th>키</th><th>FileId</th><th>Path</th><th>LinkDate</th><th>Size</th></tr></thead><tbody>
{% for a in r.modern[:200] %}<tr><td><code style="font-size:.72rem;">{{ a.subkey[:30] }}</code></td>
<td><code style="font-size:.7rem; word-break:break-all;">{{ a.get('FileId','')[:50] }}</code></td>
<td style="word-break:break-all;">{{ a.get('LowerCaseLongPath','') }}</td>
<td>{{ a.get('LinkDate','') }}</td><td>{{ a.get('Size','') }}</td></tr>{% endfor %}
</tbody></table></div>{% endif %}
{% endif %}</div>{% endfor %}
{% endif %}</div>{% endblock %}''')

# HAR
w('har.html', hdr('HAR 분석','브라우저 HAR 캡처 → 요청·응답·시간·도메인 통계.','bi-globe2') + '''
<div class="container pb-5">{% if error %}<div class="alert-error mb-3">{{ error }}</div>{% endif %}
{% if not result %}<div class="row justify-content-center"><div class="col-lg-6"><div class="tool-panel">''' + MULTI + '''</div></div></div>
{% else %}{% for r in result.files %}
<div class="tool-panel mb-3"><h6 class="panel-title">{{ r.filename }}{% if r.total %} — {{ r.total }}개 요청{% endif %}</h6>
{% if r.error %}<div class="text-danger">{{ r.error }}</div>{% else %}
<div class="row mb-2"><div class="col-md-4"><strong>메서드</strong>
{% for m, c in r.methods %}<div class="d-flex justify-content-between"><code>{{ m }}</code><span>{{ c }}</span></div>{% endfor %}</div>
<div class="col-md-4"><strong>상태</strong>
{% for s, c in r.statuses %}<div class="d-flex justify-content-between"><code>{{ s }}</code><span>{{ c }}</span></div>{% endfor %}</div>
<div class="col-md-4"><strong>상위 호스트</strong>
{% for h, c in r.top_hosts %}<div class="d-flex justify-content-between"><code style="font-size:.72rem;">{{ h }}</code><span>{{ c }}</span></div>{% endfor %}</div></div>
<div style="max-height:400px; overflow-y:auto;"><table class="table table-sm" style="font-size:.76rem;">
<thead><tr class="text-dim"><th>메서드</th><th>URL</th><th>상태</th><th>크기</th><th>시간</th></tr></thead><tbody>
{% for req in r.requests %}<tr><td><code>{{ req.method }}</code></td><td style="word-break:break-all; max-width:400px;">{{ req.url }}</td>
<td>{% if req.status >= 400 %}<span style="color:#ef4444">{{ req.status }}</span>{% elif req.status >= 300 %}<span style="color:#f59e0b">{{ req.status }}</span>{% else %}<span style="color:#22c55e">{{ req.status }}</span>{% endif %}</td>
<td>{{ req.size }}</td><td>{{ req.duration }}</td></tr>{% endfor %}
</tbody></table></div>{% endif %}</div>{% endfor %}
{% endif %}</div>{% endblock %}''')

# SIGMA
w('sigma.html', hdr('Sigma 규칙 매처','Sigma YAML → JSON 이벤트 매칭.','bi-search-heart') + '''
<div class="container pb-5">{% if error %}<div class="alert-error mb-3">{{ error }}</div>{% endif %}
<div class="row g-3"><div class="col-lg-6"><div class="tool-panel"><form method="POST">
<label class="form-label-sm">Sigma 규칙 (YAML)</label>
<textarea name="sigma" class="form-control mb-3" rows="12" style="font-family:monospace; font-size:.74rem;" placeholder="title: Suspicious PowerShell&#10;level: high&#10;detection:&#10;    selection:&#10;        EventID: 4688&#10;        CommandLine: powershell&#10;    condition: selection"></textarea>
<label class="form-label-sm">JSON 이벤트 배열</label>
<textarea name="events" class="form-control mb-3" rows="6" style="font-family:monospace; font-size:.74rem;"></textarea>
<button class="btn btn-accent w-100"><i class="bi bi-play me-1"></i>매칭</button></form></div></div>
<div class="col-lg-6">{% if result %}{% for m in result.matches %}
<div class="tool-panel mb-2">
<h6 class="panel-title">{{ m.rule }} <span class="tag ms-2">{{ m.level }}</span></h6>
<p class="text-dim small">{{ m.description }}</p>
<strong>{{ m.match_count }}건 매칭</strong>
{% for item in m.matches[:30] %}<pre style="background:var(--bg); padding:.4rem; font-size:.72rem; margin-top:.3rem;">{{ item.event | tojson(indent=2) }}</pre>{% endfor %}
</div>{% endfor %}{% endif %}</div></div></div>{% endblock %}''')

# PSDEOBF
w('psdeobf.html', hdr('PowerShell 디오브푸스케이션','Base64·-EncodedCommand·문자열 연결·char[] 자동 펴기 + IOC.','bi-arrow-clockwise') + '''
<div class="container pb-5">{% if error %}<div class="alert-error mb-3">{{ error }}</div>{% endif %}
<div class="row g-3"><div class="col-lg-5"><div class="tool-panel"><form method="POST" enctype="multipart/form-data">
<textarea name="text" class="form-control mb-2" rows="12" style="font-family:monospace; font-size:.74rem;">{{ text }}</textarea>
<input type="file" name="file" class="form-control mb-3" accept=".ps1,.txt">
<button class="btn btn-accent w-100"><i class="bi bi-arrow-clockwise me-1"></i>디오브푸스케이트</button>
</form></div></div>
<div class="col-lg-7">{% if result %}
<div class="tool-panel mb-2"><h6 class="panel-title">결과 ({{ result.reduction }})</h6>
<pre style="background:var(--bg); padding:.6rem; font-size:.78rem; max-height:400px; overflow:auto; margin:0; white-space:pre-wrap; word-break:break-all;">{{ result.result }}</pre></div>
{% if result.steps %}<div class="tool-panel mb-2"><h6 class="panel-title">변환 단계</h6>
{% for s in result.steps %}<div class="small">→ {{ s.step }}{% if s.after %}: <code>{{ s.after }}</code>{% endif %}</div>{% endfor %}</div>{% endif %}
{% if result.iocs %}<div class="tool-panel"><h6 class="panel-title">IOC</h6>
{% for k, vs in result.iocs.items() %}{% if vs %}<div><strong>{{ k }}:</strong> {% for v in vs %}<code class="me-1">{{ v }}</code>{% endfor %}</div>{% endif %}{% endfor %}
</div>{% endif %}{% endif %}</div></div></div>{% endblock %}''')

# IOC
w('ioc.html', hdr('IOC 추출기','IP·도메인·해시·CVE·BTC·이메일·CIDR·MAC·경로·레지스트리 키 자동 추출.','bi-search') + '''
<div class="container pb-5">{% if error %}<div class="alert-error mb-3">{{ error }}</div>{% endif %}
<div class="row g-3"><div class="col-lg-5"><div class="tool-panel"><form method="POST" enctype="multipart/form-data">
<label class="form-label-sm">텍스트</label>
<textarea name="text" class="form-control mb-2" rows="10" style="font-family:monospace; font-size:.74rem;"></textarea>
<label class="form-label-sm">또는 파일들 (다중)</label>
<input type="file" name="file" class="form-control mb-3" multiple>
<button class="btn btn-accent w-100"><i class="bi bi-search me-1"></i>추출</button>
</form></div></div>
<div class="col-lg-7">{% if result %}<div class="tool-panel">
<h6 class="panel-title">총 {{ result.total }}건</h6>
{% for k, vs in result.iocs.items() %}{% if vs %}<div class="mb-3">
<strong style="color:var(--accent); text-transform:uppercase;">{{ k }} ({{ vs|length }})</strong>
<div style="font-family:monospace; font-size:.78rem; max-height:200px; overflow-y:auto; margin-top:.3rem; background:var(--bg); padding:.4rem; border-radius:.3rem;">
{% for v in vs %}<div style="padding:.1rem 0; word-break:break-all;">{{ v }}</div>{% endfor %}
</div></div>{% endif %}{% endfor %}
</div>{% endif %}</div></div></div>{% endblock %}''')

# TIME
w('time.html', hdr('시간 변환기','Unix·FILETIME·Chrome·Cocoa·DOS·HFS·Mozilla 등 모든 포렌식 타임스탬프 변환.','bi-clock-history') + '''
<div class="container pb-5">{% if error %}<div class="alert-error mb-3">{{ error }}</div>{% endif %}
<div class="row justify-content-center"><div class="col-lg-7"><div class="tool-panel mb-3"><form method="POST">
<label class="form-label-sm">시각 값 (정수 또는 ISO 날짜)</label>
<input type="text" name="value" class="form-control mb-3" placeholder="1717250000 또는 2026-06-01 12:34:56" autofocus required>
<button class="btn btn-accent w-100"><i class="bi bi-arrow-left-right me-1"></i>변환</button>
</form></div>
{% if result %}<div class="tool-panel"><h6 class="panel-title">입력 <code>{{ result.input }}</code> — {{ result.results|length }}개</h6>
<table class="table table-sm" style="font-size:.85rem;"><tbody>
{% for r in result.results %}<tr><td class="text-dim">{{ r.format }}</td><td><code>{{ r.value }}</code></td></tr>{% endfor %}
</tbody></table></div>{% endif %}
</div></div></div>{% endblock %}''')

# APK
w('apk.html', hdr('APK 분석기','Android APK manifest·permissions·인증서·DEX 정보.','bi-android2') + '''
<div class="container pb-5">{% if error %}<div class="alert-error mb-3">{{ error }}</div>{% endif %}
{% if not result %}<div class="row justify-content-center"><div class="col-lg-6"><div class="tool-panel">''' + MULTI + '''</div></div></div>
{% else %}{% for r in result.files %}
<div class="tool-panel mb-3"><h6 class="panel-title">{{ r.filename }}</h6>
{% if r.error %}<div class="text-danger">{{ r.error }}</div>{% else %}
<div class="text-dim small mb-2">파일 {{ r.file_count }} · {% if r.meta.dex %}{{ r.meta.dex }}{% endif %}</div>
{% if r.permissions %}<div class="mb-2"><strong>권한 ({{ r.permissions|length }})</strong>
{% for p in r.permissions %}<code class="me-1 mb-1 d-inline-block" style="font-size:.72rem;">{{ p }}</code>{% endfor %}</div>{% endif %}
{% if r.activities %}<div class="mb-2"><strong>Activities ({{ r.activities|length }})</strong>
{% for a in r.activities[:30] %}<code class="me-1 mb-1 d-inline-block" style="font-size:.7rem;">{{ a }}</code>{% endfor %}</div>{% endif %}
{% if r.services %}<div class="mb-2"><strong>Services:</strong>
{% for s in r.services %}<code class="me-1" style="font-size:.7rem;">{{ s }}</code>{% endfor %}</div>{% endif %}
{% if r.certs %}<div><strong>서명 인증서:</strong>
{% for c in r.certs %}<div class="mt-1"><code style="font-size:.72rem;">{{ c.name }}</code> <span class="text-dim small">{{ c.size }}B</span> <code style="font-size:.7rem; word-break:break-all;">{{ c.sha256 }}</code></div>{% endfor %}</div>{% endif %}
{% endif %}</div>{% endfor %}
{% endif %}</div>{% endblock %}''')

# HASHLOOKUP
w('hashlookup.html', hdr('해시 룩업','파일 또는 해시 → 알려진 양성/악성 DB 조회.','bi-fingerprint') + '''
<div class="container pb-5">{% if error %}<div class="alert-error mb-3">{{ error }}</div>{% endif %}
<div class="row g-3"><div class="col-lg-5"><div class="tool-panel"><form method="POST" enctype="multipart/form-data">
<label class="form-label-sm">파일 (다중)</label>
<input type="file" name="file" class="form-control mb-3" multiple>
<label class="form-label-sm">또는 해시 직접 입력</label>
<textarea name="hashes" class="form-control mb-3" rows="6" style="font-family:monospace; font-size:.74rem;"></textarea>
<button class="btn btn-accent w-100"><i class="bi bi-search me-1"></i>조회</button>
</form></div></div>
<div class="col-lg-7">{% if result %}<div class="tool-panel">
<div class="text-dim small mb-2">DB 크기: {{ result.known_db_size }}</div>
<table class="table table-sm" style="font-size:.78rem;"><thead><tr class="text-dim"><th>파일</th><th>해시</th><th>상태</th></tr></thead><tbody>
{% for h in result.hashes %}<tr><td>{{ h.filename }}</td>
<td><code style="font-size:.7rem; word-break:break-all;">{{ h.sha256 or h.sha1 or h.md5 }}</code></td>
<td>{% if h.known == 'benign' %}<span class="tag" style="background:rgba(34,197,94,.15);color:#22c55e">정상</span>
{% elif h.known == 'malicious' %}<span class="tag" style="background:rgba(239,68,68,.15);color:#ef4444">악성</span>
{% else %}<span class="tag" style="background:rgba(107,114,128,.15);color:#9ca3af">미상</span>{% endif %}
{% if h.description %}<div class="text-dim small">{{ h.description }}</div>{% endif %}</td>
</tr>{% endfor %}</tbody></table></div>{% endif %}</div></div></div>{% endblock %}''')

# HEIF
w('heif.html', hdr('HEIC / HEIF 분석','iOS 14+ HEIC 사진의 EXIF·박스 구조.','bi-image-fill') + '''
<div class="container pb-5">{% if error %}<div class="alert-error mb-3">{{ error }}</div>{% endif %}
{% if not result %}<div class="row justify-content-center"><div class="col-lg-6"><div class="tool-panel">''' + MULTI + '''</div></div></div>
{% else %}{% for r in result.files %}
<div class="tool-panel mb-3"><h6 class="panel-title">{{ r.filename }}{% if r.format %} <span class="tag">{{ r.format }}</span>{% endif %}</h6>
{% if r.image_size %}<div class="text-dim small">{{ r.image_size }}</div>{% endif %}
{% if r.exif %}<div class="mt-2"><strong>EXIF</strong>
<pre style="background:var(--bg); padding:.5rem; font-size:.72rem; max-height:300px; overflow:auto;">{{ r.exif | tojson(indent=2) }}</pre></div>{% endif %}
{% if r.boxes %}<div class="mt-2"><strong>박스 ({{ r.boxes|length }})</strong>
<table class="table table-sm" style="font-size:.76rem;"><tbody>
{% for b in r.boxes %}<tr><td><code>{{ b.offset }}</code></td><td><code>{{ b.type }}</code></td><td>{{ b.size }}</td></tr>{% endfor %}
</tbody></table></div>{% endif %}
</div>{% endfor %}
{% endif %}</div>{% endblock %}''')

# MEMSCAN
w('memscan.html', hdr('메모리 덤프 IOC 스캔','RAW 메모리 덤프에서 URL·프로세스·자격증명·경로·IOC 추출.','bi-memory') + '''
<div class="container pb-5">{% if error %}<div class="alert-error mb-3">{{ error }}</div>{% endif %}
{% if not result %}<div class="row justify-content-center"><div class="col-lg-6"><div class="tool-panel">''' + MULTI + '''</div></div></div>
{% else %}{% for r in result.files %}
<div class="tool-panel mb-3"><h6 class="panel-title">{{ r.filename }}{% if r.format %} — <span class="text-dim">{{ r.format }}</span>{% endif %}</h6>
{% if r.urls %}<div class="mb-2"><strong>URLs ({{ r.urls|length }})</strong>
<div style="max-height:200px; overflow-y:auto; font-size:.72rem; background:var(--bg); padding:.4rem;">
{% for u in r.urls %}<div style="word-break:break-all;">{{ u }}</div>{% endfor %}</div></div>{% endif %}
{% if r.processes %}<div class="mb-2"><strong>프로세스 ({{ r.processes|length }})</strong>
<div>{% for p in r.processes[:40] %}<code class="me-1 mb-1 d-inline-block" style="font-size:.72rem;">{{ p }}</code>{% endfor %}</div></div>{% endif %}
{% if r.paths %}<div class="mb-2"><strong>경로 ({{ r.paths|length }})</strong>
<div style="max-height:150px; overflow-y:auto; font-size:.72rem; background:var(--bg); padding:.4rem;">
{% for p in r.paths %}<div style="word-break:break-all;">{{ p }}</div>{% endfor %}</div></div>{% endif %}
{% if r.creds %}<div class="mb-2" style="border-left:3px solid #ef4444; padding-left:.5rem;">
<strong class="text-danger">자격증명 단서 ({{ r.creds|length }})</strong>
{% for c in r.creds %}<div style="font-family:monospace; font-size:.72rem; word-break:break-all;">{{ c }}</div>{% endfor %}</div>{% endif %}
</div>{% endfor %}
{% endif %}</div>{% endblock %}''')

# CUCKOO
w('cuckoo.html', hdr('Cuckoo / CAPE 리포트','샌드박스 JSON 리포트 파싱 — 시그니처·프로세스·네트워크.','bi-bug-fill') + '''
<div class="container pb-5">{% if error %}<div class="alert-error mb-3">{{ error }}</div>{% endif %}
{% if not result %}<div class="row justify-content-center"><div class="col-lg-6"><div class="tool-panel">''' + MULTI + '''</div></div></div>
{% else %}{% for r in result.files %}
<div class="tool-panel mb-3">
<h6 class="panel-title">{{ r.filename }}{% if r.score is defined %} — 점수 {{ r.score }}/10{% endif %}</h6>
{% if r.error %}<div class="text-danger">{{ r.error }}</div>{% else %}
<table class="table table-sm" style="font-size:.82rem;">
<tr><td class="text-dim">샘플</td><td><strong>{{ r.sample }}</strong></td></tr>
<tr><td class="text-dim">MD5</td><td><code>{{ r.md5 }}</code></td></tr>
<tr><td class="text-dim">SHA256</td><td><code style="font-size:.7rem; word-break:break-all;">{{ r.sha256 }}</code></td></tr>
<tr><td class="text-dim">시작</td><td>{{ r.started }}</td></tr>
<tr><td class="text-dim">지속시간</td><td>{{ r.duration }}초</td></tr>
</table>
{% if r.signatures %}<div class="mb-3"><h6 class="panel-title">시그니처 ({{ r.signatures|length }})</h6>
{% for s in r.signatures %}<div class="p-2 mb-1" style="background:var(--bg); border-left:3px solid #ef4444;">
<strong>{{ s.name }}</strong> <span class="text-dim small">sev={{ s.severity }}</span>
<div class="small">{{ s.description }}</div></div>{% endfor %}</div>{% endif %}
{% if r.domains %}<div class="mb-2"><strong>도메인</strong>
{% for d in r.domains %}<code class="me-1 d-inline-block">{{ d }}</code>{% endfor %}</div>{% endif %}
{% if r.hosts %}<div class="mb-2"><strong>호스트</strong>
{% for h in r.hosts %}<code class="me-1 d-inline-block">{{ h }}</code>{% endfor %}</div>{% endif %}
{% endif %}</div>{% endfor %}
{% endif %}</div>{% endblock %}''')

# VOL
w('vol.html', hdr('Volatility 메모리 분석','volatility3 기반 (대용량 → 로컬 실행 권장).','bi-cpu-fill') + '''
<div class="container pb-5">{% if error %}<div class="alert-error mb-3">{{ error }}</div>{% endif %}
<div class="row justify-content-center"><div class="col-lg-7"><div class="tool-panel">
<h6 class="panel-title">Volatility 3 메모리 분석</h6>
<p class="text-dim">대용량 메모리 덤프는 서버 리소스를 많이 사용합니다. 권장 방법:</p>
<ol style="font-size:.88rem; line-height:1.7;">
<li><code>pip install volatility3</code></li>
<li><code>vol -f memory.dmp windows.pslist</code></li>
<li>결과를 <a href="/tools/memscan" class="text-accent">/tools/memscan</a>으로 분석</li>
</ol>
</div></div></div></div>{% endblock %}''')

# MAGIC
w('magic.html', hdr('MIME 시그니처 DB','100+ 매직바이트 매칭.','bi-tag-fill') + '''
<div class="container pb-5">{% if error %}<div class="alert-error mb-3">{{ error }}</div>{% endif %}
{% if not result %}<div class="row justify-content-center"><div class="col-lg-6"><div class="tool-panel">''' + MULTI + '''</div></div></div>
{% else %}<div class="text-dim small mb-2">DB: {{ result.db_size }}개</div>
{% for r in result.files %}<div class="tool-panel mb-2">
<h6 class="panel-title">{{ r.filename }}</h6>
{% if r.matches %}{% for m in r.matches %}<div class="p-2 mb-1" style="background:var(--bg); border-left:3px solid var(--accent);">
<code>{{ m.sig }}</code> <strong>{{ m.label }}</strong> <span class="text-dim small">{{ m.mime }}</span>
</div>{% endfor %}{% else %}<div class="text-dim">매칭 없음</div>{% endif %}
<div class="mt-2 text-dim small">헥스: <code style="font-size:.7rem; word-break:break-all;">{{ r.hex_preview }}</code></div>
</div>{% endfor %}
{% endif %}</div>{% endblock %}''')

# DOCKER
w('docker.html', hdr('Docker 이미지 분석','docker save .tar → manifest·config·레이어·환경변수.','bi-box-fill') + '''
<div class="container pb-5">{% if error %}<div class="alert-error mb-3">{{ error }}</div>{% endif %}
{% if not result %}<div class="row justify-content-center"><div class="col-lg-6"><div class="tool-panel">''' + MULTI + '''
<div class="form-hint mt-2">docker save IMAGE -o image.tar 로 생성</div></div></div></div>
{% else %}{% for r in result.files %}
<div class="tool-panel mb-3"><h6 class="panel-title">{{ r.filename }}</h6>
{% if r.error %}<div class="text-danger">{{ r.error }}</div>{% else %}
<table class="table table-sm" style="font-size:.84rem;">
<tr><td class="text-dim">멤버 수</td><td>{{ r.member_count }}</td></tr>
<tr><td class="text-dim">레이어</td><td>{{ r.layers|length }}</td></tr>
{% if r.os %}<tr><td class="text-dim">OS</td><td>{{ r.os }}</td></tr>{% endif %}
{% if r.architecture %}<tr><td class="text-dim">아키텍처</td><td>{{ r.architecture }}</td></tr>{% endif %}
{% if r.cmd %}<tr><td class="text-dim">CMD</td><td><code>{{ r.cmd|join(' ') }}</code></td></tr>{% endif %}
{% if r.entrypoint %}<tr><td class="text-dim">ENTRYPOINT</td><td><code>{{ r.entrypoint|join(' ') }}</code></td></tr>{% endif %}
{% if r.exposed_ports %}<tr><td class="text-dim">포트</td><td>{% for p in r.exposed_ports %}<span class="tag me-1">{{ p }}</span>{% endfor %}</td></tr>{% endif %}
</table>
{% if r.env %}<div class="mb-2"><strong>환경변수 ({{ r.env|length }})</strong>
<div style="max-height:200px; overflow-y:auto; font-family:monospace; font-size:.72rem; background:var(--bg); padding:.5rem;">
{% for e in r.env %}<div style="word-break:break-all;">{{ e }}</div>{% endfor %}</div></div>{% endif %}
{% if r.config_history %}<div><strong>레이어 빌드 이력</strong>
{% for h in r.config_history %}<div class="p-2 mb-1 small" style="background:var(--bg);">
<div class="text-dim">{{ h.created }}</div>
<code style="word-break:break-all;">{{ h.created_by }}</code></div>{% endfor %}</div>{% endif %}
{% endif %}</div>{% endfor %}
{% endif %}</div>{% endblock %}''')

# HEX
w('hex.html', hdr('Hex Viewer','파일 헥스 + ASCII 표시 및 패턴 검색.','bi-code') + '''
<div class="container pb-5">{% if error %}<div class="alert-error mb-3">{{ error }}</div>{% endif %}
{% if not result %}<div class="row justify-content-center"><div class="col-lg-6"><div class="tool-panel"><form method="POST" enctype="multipart/form-data">
<input type="file" name="file" class="form-control mb-3" required>
<div class="row"><div class="col-6"><label class="form-label-sm">오프셋</label><input type="number" name="offset" class="form-control mb-3" value="0"></div>
<div class="col-6"><label class="form-label-sm">길이</label><input type="number" name="length" class="form-control mb-3" value="1024"></div></div>
<input type="text" name="search" class="form-control mb-3" placeholder="검색 (MZ 또는 0x4D5A)">
<button class="btn btn-accent w-100"><i class="bi bi-code me-1"></i>표시</button>
</form></div></div></div>
{% else %}
<div class="d-flex gap-3 mb-2"><strong>{{ result.filename }}</strong>
<span class="text-dim small">{{ "{:,}".format(result.file_size) }} B · 오프셋 {{ result.offset }}</span>
<a href="/tools/hex" class="btn btn-sm btn-outline-secondary ms-auto"><i class="bi bi-arrow-left me-1"></i>새 파일</a></div>
{% if result.search_results %}<div class="tool-panel mb-2">
<h6 class="panel-title">검색 결과 ({{ result.search_results|length }})</h6>
<div style="max-height:200px; overflow-y:auto; font-family:monospace; font-size:.74rem;">
{% for s in result.search_results %}<div><code style="color:var(--accent)">{{ s.offset }}</code> <code>{{ s.context }}</code></div>{% endfor %}
</div></div>{% endif %}
<div class="tool-panel"><pre style="background:var(--bg); padding:.5rem; font-family:monospace; font-size:.78rem; line-height:1.4; margin:0; overflow:auto;">{% for l in result.lines %}<span style="color:var(--accent)">{{ l.offset }}</span>  {{ l.hex }}  <span style="color:#94a3b8">{{ l.ascii }}</span>
{% endfor %}</pre></div>
{% endif %}</div>{% endblock %}''')

# CIDR
w('cidr.html', hdr('CIDR 계산기','서브넷 범위·호스트 수·사설/공용 IP 분류.','bi-diagram-3') + '''
<div class="container pb-5">{% if error %}<div class="alert-error mb-3">{{ error }}</div>{% endif %}
<div class="row justify-content-center"><div class="col-lg-7"><div class="tool-panel mb-3"><form method="POST">
<input type="text" name="cidr" class="form-control mb-3" placeholder="192.168.1.0/24" autofocus required>
<button class="btn btn-accent w-100"><i class="bi bi-diagram-3 me-1"></i>계산</button>
</form></div>
{% if result %}<div class="tool-panel"><table class="table table-sm" style="font-size:.86rem;">
<tr><td class="text-dim">입력</td><td><code>{{ result.input }}</code></td></tr>
<tr><td class="text-dim">네트워크</td><td><code>{{ result.network }}</code></td></tr>
<tr><td class="text-dim">서브넷마스크</td><td><code>{{ result.netmask }}</code></td></tr>
{% if result.broadcast %}<tr><td class="text-dim">브로드캐스트</td><td><code>{{ result.broadcast }}</code></td></tr>{% endif %}
{% if result.first %}<tr><td class="text-dim">첫 호스트</td><td><code>{{ result.first }}</code></td></tr>{% endif %}
{% if result.last %}<tr><td class="text-dim">마지막 호스트</td><td><code>{{ result.last }}</code></td></tr>{% endif %}
<tr><td class="text-dim">총 주소</td><td><strong>{{ "{:,}".format(result.total) }}</strong></td></tr>
<tr><td class="text-dim">사용 가능</td><td><strong>{{ "{:,}".format(result.usable) }}</strong></td></tr>
<tr><td class="text-dim">버전</td><td>IPv{{ result.version }}</td></tr>
<tr><td class="text-dim">분류</td><td>
{% if result.is_private %}<span class="tag" style="background:rgba(245,158,11,.15);color:#f59e0b">사설</span>{% endif %}
{% if result.is_global %}<span class="tag" style="background:rgba(34,197,94,.15);color:#22c55e">공용</span>{% endif %}
{% if result.is_loopback %}<span class="tag">루프백</span>{% endif %}
{% if result.is_multicast %}<span class="tag">멀티캐스트</span>{% endif %}
</td></tr>
{% if result.sample_hosts %}<tr><td class="text-dim">샘플</td><td>
{% for h in result.sample_hosts %}<code class="me-2">{{ h }}</code>{% endfor %}</td></tr>{% endif %}
</table></div>{% endif %}
</div></div></div>{% endblock %}''')

# CONVERT
w('convert.html', hdr('JSON / XML / YAML 변환','형식 자동 감지 + 들여쓰기 + 상호 변환.','bi-arrow-left-right') + '''
<div class="container pb-5">{% if error %}<div class="alert-error mb-3">{{ error }}</div>{% endif %}
<div class="row g-3"><div class="col-lg-5"><div class="tool-panel"><form method="POST">
<label class="form-label-sm">입력 (자동 감지)</label>
<textarea name="text" class="form-control mb-2" rows="14" style="font-family:monospace; font-size:.74rem;">{{ text }}</textarea>
<label class="form-label-sm">출력 형식</label>
<select name="mode" class="form-select mb-3">
<option value="pretty_json">JSON 들여쓰기</option>
<option value="compact_json">JSON 압축</option>
<option value="yaml">YAML</option>
</select>
<button class="btn btn-accent w-100"><i class="bi bi-arrow-right me-1"></i>변환</button>
</form></div></div>
<div class="col-lg-7">{% if result %}<div class="tool-panel">
<h6 class="panel-title">{{ result.input_format }} → {{ result.mode }}</h6>
<pre style="background:var(--bg); padding:.6rem; font-size:.78rem; max-height:600px; overflow:auto; margin:0;">{{ result.output }}</pre>
</div>{% endif %}</div></div></div>{% endblock %}''')

# REGEX
w('regex.html', hdr('정규식 테스터','매칭·그룹·치환 미리보기 + 플래그.','bi-regex') + '''
<div class="container pb-5">{% if error %}<div class="alert-error mb-3">{{ error }}</div>{% endif %}
<div class="row g-3"><div class="col-lg-5"><div class="tool-panel"><form method="POST">
<input type="text" name="pattern" class="form-control mb-2" style="font-family:monospace;" value="{{ pattern }}" placeholder="패턴">
<div class="d-flex gap-2 mb-2 small">
<label><input type="checkbox" name="flags" value="i" {% if 'i' in flags %}checked{% endif %}> i</label>
<label><input type="checkbox" name="flags" value="m" {% if 'm' in flags %}checked{% endif %}> m</label>
<label><input type="checkbox" name="flags" value="s" {% if 's' in flags %}checked{% endif %}> s</label>
</div>
<textarea name="text" class="form-control mb-2" rows="10" style="font-family:monospace; font-size:.74rem;">{{ text }}</textarea>
<input type="text" name="replace" class="form-control mb-3" style="font-family:monospace;" placeholder="치환 (\\1, \\2 사용)">
<button class="btn btn-accent w-100"><i class="bi bi-play me-1"></i>실행</button>
</form></div></div>
<div class="col-lg-7">{% if result %}
<div class="tool-panel mb-2"><h6 class="panel-title">매칭 {{ result.match_count }}건</h6>
<div style="max-height:400px; overflow-y:auto;">{% for m in result.matches %}
<div class="p-2 mb-1" style="background:var(--bg); font-size:.78rem;">
<code style="color:var(--accent)">{{ m.match }}</code> <span class="text-dim small">@ {{ m.span[0] }}-{{ m.span[1] }}</span>
{% if m.groups %}<div class="text-dim small">그룹: {% for g in m.groups %}<code class="me-2">{{ g }}</code>{% endfor %}</div>{% endif %}
</div>{% endfor %}</div></div>
{% if result.substituted %}<div class="tool-panel"><h6 class="panel-title">치환 결과</h6>
<pre style="background:var(--bg); padding:.5rem; font-size:.78rem; max-height:300px; overflow:auto;">{{ result.substituted }}</pre></div>{% endif %}
{% endif %}</div></div></div>{% endblock %}''')

# JSDEOBF
w('jsdeobf.html', hdr('JS 디오브푸스케이션','eval·\\xNN·\\uNNNN·atob·fromCharCode·문자열 연결.','bi-filetype-js') + '''
<div class="container pb-5">{% if error %}<div class="alert-error mb-3">{{ error }}</div>{% endif %}
<div class="row g-3"><div class="col-lg-5"><div class="tool-panel"><form method="POST" enctype="multipart/form-data">
<textarea name="text" class="form-control mb-2" rows="12" style="font-family:monospace; font-size:.74rem;">{{ text }}</textarea>
<input type="file" name="file" class="form-control mb-3" accept=".js,.html,.txt">
<button class="btn btn-accent w-100"><i class="bi bi-arrow-clockwise me-1"></i>디오브푸스케이트</button>
</form></div></div>
<div class="col-lg-7">{% if result %}
<div class="tool-panel mb-2"><h6 class="panel-title">결과</h6>
<pre style="background:var(--bg); padding:.6rem; font-size:.78rem; max-height:400px; overflow:auto; margin:0; white-space:pre-wrap; word-break:break-all;">{{ result.result }}</pre></div>
{% if result.steps %}<div class="tool-panel mb-2"><h6 class="panel-title">단계</h6>
{% for s in result.steps %}<div class="small">→ {{ s.step }}</div>{% endfor %}</div>{% endif %}
{% if result.iocs %}<div class="tool-panel"><h6 class="panel-title">IOC</h6>
{% for k, vs in result.iocs.items() %}{% if vs %}<div><strong>{{ k }}:</strong> {% for v in vs %}<code class="me-1">{{ v }}</code>{% endfor %}</div>{% endif %}{% endfor %}
</div>{% endif %}{% endif %}</div></div></div>{% endblock %}''')

# WORDLIST
w('wordlist.html', hdr('Wordlist 생성','시드 + 규칙으로 비밀번호 사전 생성.','bi-list-ol') + '''
<div class="container pb-5">{% if error %}<div class="alert-error mb-3">{{ error }}</div>{% endif %}
<div class="row g-3"><div class="col-lg-5"><div class="tool-panel"><form method="POST">
<label class="form-label-sm">시드 단어</label>
<textarea name="seeds" class="form-control mb-3" rows="5" placeholder="password, admin, company"></textarea>
<div class="row mb-2">
<div class="col-6"><label><input type="checkbox" name="leet" checked> Leetspeak</label></div>
<div class="col-6"><label><input type="checkbox" name="case" checked> 대소문자</label></div>
<div class="col-6"><label><input type="checkbox" name="years" checked> 연도</label></div>
<div class="col-6"><label><input type="checkbox" name="numbers"> 숫자</label></div>
<div class="col-6"><label><input type="checkbox" name="symbols"> 특수문자</label></div></div>
<div class="row">
<div class="col-6"><label class="form-label-sm">연도 From</label><input type="number" name="year_from" class="form-control mb-2" value="2020"></div>
<div class="col-6"><label class="form-label-sm">연도 To</label><input type="number" name="year_to" class="form-control mb-2" value="2026"></div>
<div class="col-6"><label class="form-label-sm">최소</label><input type="number" name="min_len" class="form-control mb-2" value="4"></div>
<div class="col-6"><label class="form-label-sm">최대</label><input type="number" name="max_len" class="form-control mb-3" value="20"></div></div>
<button class="btn btn-accent w-100"><i class="bi bi-list-ol me-1"></i>생성</button>
</form></div></div>
<div class="col-lg-7">{% if result %}<div class="tool-panel">
<h6 class="panel-title">{{ result.count }}개</h6>
<button class="btn btn-sm btn-outline-secondary mb-2" onclick="navigator.clipboard.writeText(document.getElementById('wl').textContent)"><i class="bi bi-clipboard me-1"></i>복사</button>
<pre id="wl" style="background:var(--bg); padding:.5rem; font-size:.78rem; max-height:500px; overflow:auto; margin:0;">{% for w in result.words %}{{ w }}
{% endfor %}</pre>
</div>{% endif %}</div></div></div>{% endblock %}''')

# SPREADSHEET
w('spreadsheet.html', hdr('CSV / Excel 뷰어','CSV·TSV·XLSX 업로드 후 표 형식 표시.','bi-table') + '''
<div class="container pb-5">{% if error %}<div class="alert-error mb-3">{{ error }}</div>{% endif %}
{% if not result %}<div class="row justify-content-center"><div class="col-lg-6"><div class="tool-panel">''' + MULTI + '''</div></div></div>
{% else %}{% for r in result.files %}
<div class="tool-panel mb-3"><h6 class="panel-title">{{ r.filename }}{% if r.format %} <span class="tag">{{ r.format }}</span>{% endif %}</h6>
{% if r.error %}<div class="text-danger">{{ r.error }}</div>
{% elif r.format == 'CSV' %}
<div class="text-dim small mb-2">{{ r.rows_total }}행 · {{ r.cols }}열 · 구분자 <code>{{ r.delimiter }}</code></div>
<div style="max-height:500px; overflow:auto;"><table class="table table-sm" style="font-size:.76rem;">
<thead style="position:sticky; top:0; background:var(--bg-card);"><tr>
{% for h in r.headers %}<th class="text-dim">{{ h }}</th>{% endfor %}
</tr></thead><tbody>
{% for row in r.rows %}<tr>{% for c in row %}<td style="max-width:300px; overflow:hidden; text-overflow:ellipsis;">{{ c }}</td>{% endfor %}</tr>{% endfor %}
</tbody></table></div>
{% elif r.format == 'XLSX' %}{% for sh in r.sheets %}
<details class="mb-2"><summary style="cursor:pointer;"><strong>{{ sh.name }}</strong> <span class="text-dim small">{{ sh.rows }}행 · {{ sh.cols }}열</span></summary>
<div style="max-height:400px; overflow:auto; margin-top:.5rem;"><table class="table table-sm" style="font-size:.76rem;">
<thead><tr>{% for h in sh.headers %}<th class="text-dim">{{ h }}</th>{% endfor %}</tr></thead>
<tbody>{% for row in sh.data %}<tr>{% for c in row %}<td>{{ c }}</td>{% endfor %}</tr>{% endfor %}</tbody>
</table></div></details>
{% endfor %}{% endif %}
</div>{% endfor %}
{% endif %}</div>{% endblock %}''')

# TEXTDIFF
w('textdiff.html', hdr('텍스트 Diff','두 텍스트 라인별 unified diff.','bi-file-diff') + '''
<div class="container pb-5">{% if error %}<div class="alert-error mb-3">{{ error }}</div>{% endif %}
<form method="POST"><div class="row g-3 mb-3">
<div class="col-md-6"><label class="form-label-sm">A</label>
<textarea name="text_a" class="form-control" rows="12" style="font-family:monospace; font-size:.74rem;">{{ a }}</textarea></div>
<div class="col-md-6"><label class="form-label-sm">B</label>
<textarea name="text_b" class="form-control" rows="12" style="font-family:monospace; font-size:.74rem;">{{ b }}</textarea></div>
</div><button class="btn btn-accent"><i class="bi bi-file-diff me-1"></i>비교</button></form>
{% if result %}<div class="tool-panel mt-3">
<h6 class="panel-title">유사도 {{ result.similarity }}% · A {{ result.lines_a }}행 / B {{ result.lines_b }}행</h6>
<pre style="background:var(--bg); padding:.6rem; font-size:.78rem; max-height:500px; overflow:auto; margin:0;">{% for line in result.diff %}{% if line.startswith('+') %}<span style="color:#22c55e">{{ line }}</span>{% elif line.startswith('-') %}<span style="color:#ef4444">{{ line }}</span>{% elif line.startswith('@') %}<span style="color:#06b6d4">{{ line }}</span>{% else %}{{ line }}{% endif %}
{% endfor %}</pre></div>{% endif %}</div>{% endblock %}''')

# CVE
w('cve.html', hdr('CVE 검색','CVE ID 또는 키워드로 알려진 취약점 검색.','bi-bug') + '''
<div class="container pb-5">{% if error %}<div class="alert-error mb-3">{{ error }}</div>{% endif %}
<div class="row justify-content-center"><div class="col-lg-8"><div class="tool-panel mb-3"><form method="POST">
<input type="text" name="query" class="form-control mb-3" placeholder="CVE-2021-44228 또는 log4j" autofocus required>
<button class="btn btn-accent w-100"><i class="bi bi-search me-1"></i>검색</button>
</form></div>
{% if result %}<div class="text-dim small mb-2">DB: {{ result.db_size }}개</div>
{% for m in result.matches %}<div class="tool-panel mb-2">
<div class="d-flex gap-2 mb-2"><strong style="color:var(--accent);">{{ m.id }}</strong>
<strong>{{ m.name }}</strong>
<span class="ms-auto"><span class="tag">{{ m.severity }}</span></span></div>
<p>{{ m.description }}</p>
<div class="d-flex gap-2 small">
<span class="text-dim">제품:</span>{% for p in m.products %}<code class="me-1">{{ p }}</code>{% endfor %}
<span class="ms-auto text-dim">{{ m.date }}</span>
</div></div>{% endfor %}
{% if not result.matches %}<div class="tool-panel text-dim text-center">결과 없음</div>{% endif %}
{% endif %}</div></div></div>{% endblock %}''')

# PHASH
w('phash.html', hdr('이미지 Perceptual Hash','aHash + Hamming 거리로 유사 이미지 탐지.','bi-images') + '''
<div class="container pb-5">{% if error %}<div class="alert-error mb-3">{{ error }}</div>{% endif %}
{% if not result %}<div class="row justify-content-center"><div class="col-lg-6"><div class="tool-panel">''' + MULTI + '''
<div class="form-hint mt-2">2개 이상 업로드하면 페어별 유사도 계산</div></div></div></div>
{% else %}<div class="tool-panel mb-3"><h6 class="panel-title">계산된 해시 ({{ result.hashes|length }})</h6>
<table class="table table-sm" style="font-size:.78rem;"><tbody>
{% for h in result.hashes %}<tr><td>{{ h.filename }}</td><td><code>{{ h.phash }}</code></td>
<td class="text-dim small">{{ h.size }} B</td></tr>{% endfor %}
</tbody></table></div>
{% if result.pairs %}<div class="tool-panel"><h6 class="panel-title">페어별 유사도</h6>
<table class="table table-sm" style="font-size:.82rem;">
<thead><tr class="text-dim"><th>A</th><th>B</th><th>거리</th><th>유사도</th></tr></thead><tbody>
{% for p in result.pairs %}<tr><td>{{ p.a }}</td><td>{{ p.b }}</td><td>{{ p.distance }}</td>
<td>{% if p.similarity > 90 %}<strong style="color:#22c55e">{{ p.similarity }}%</strong>{% elif p.similarity > 70 %}<strong style="color:#f59e0b">{{ p.similarity }}%</strong>{% else %}<strong style="color:#6b7280">{{ p.similarity }}%</strong>{% endif %}</td>
</tr>{% endfor %}</tbody></table></div>{% endif %}
{% endif %}</div>{% endblock %}''')

# DMESG
w('dmesg.html', hdr('Linux dmesg / journalctl','커널·systemd 저널 분석 (USB·디스크·sshd·sudo 카테고리).','bi-terminal-fill') + '''
<div class="container pb-5">{% if error %}<div class="alert-error mb-3">{{ error }}</div>{% endif %}
<div class="row g-3"><div class="col-lg-4"><div class="tool-panel"><form method="POST" enctype="multipart/form-data">
<input type="file" name="file" class="form-control mb-3" accept=".log,.txt">
<textarea name="text" class="form-control mb-3" rows="10" style="font-family:monospace; font-size:.74rem;"></textarea>
<button class="btn btn-accent w-100"><i class="bi bi-search me-1"></i>분석</button>
</form></div></div>
<div class="col-lg-8">{% if result %}<div class="tool-panel mb-2">
<h6 class="panel-title">통계</h6>
<div class="d-flex gap-3"><span><strong style="color:#ef4444">{{ result.errors }}</strong> Errors</span>
<span><strong style="color:#f59e0b">{{ result.warnings }}</strong> Warnings</span>
<span>총 {{ result.total }}</span></div>
{% if result.top_categories %}<div class="mt-2">{% for c, n in result.top_categories %}<span class="tag me-1">{{ c }}: {{ n }}</span>{% endfor %}</div>{% endif %}
</div>
<div class="tool-panel"><div style="max-height:600px; overflow-y:auto; font-family:monospace; font-size:.74rem;">
{% for e in result.events %}{% if e.severity == 'error' %}<div style="color:#ef4444; padding:.1rem .3rem;">{{ e.raw }}</div>{% elif e.severity == 'warn' %}<div style="color:#f59e0b; padding:.1rem .3rem;">{{ e.raw }}</div>{% else %}<div style="padding:.1rem .3rem;">{{ e.raw }}</div>{% endif %}{% endfor %}
</div></div>{% endif %}
</div></div></div>{% endblock %}''')

# IOS BACKUP
w('ios_backup.html', hdr('iOS Manifest.db','iTunes 백업 Manifest.db 도메인·앱별 파일 분류.','bi-phone-fill') + '''
<div class="container pb-5">{% if error %}<div class="alert-error mb-3">{{ error }}</div>{% endif %}
{% if not result %}<div class="row justify-content-center"><div class="col-lg-6"><div class="tool-panel"><form method="POST" enctype="multipart/form-data">
<input type="file" name="file" class="form-control mb-3" required>
<div class="form-hint mb-3">~/Library/Application Support/MobileSync/Backup/&lt;UDID&gt;/Manifest.db</div>
<button class="btn btn-accent w-100"><i class="bi bi-search me-1"></i>분석</button>
</form></div></div></div>
{% else %}
<div class="d-flex gap-3 mb-3"><strong>{{ result.filename }}</strong>
<span class="text-dim small">{{ "{:,}".format(result.size) }} B · {{ result.total_files }} 파일</span></div>
<div class="row g-3 mb-3"><div class="col-md-6"><div class="tool-panel">
<h6 class="panel-title">상위 도메인</h6>
<table class="table table-sm" style="font-size:.78rem;"><tbody>
{% for d, c in result.top_domains %}<tr><td><code>{{ d }}</code></td><td><strong>{{ c }}</strong></td></tr>{% endfor %}
</tbody></table></div></div>
<div class="col-md-6"><div class="tool-panel">
<h6 class="panel-title">상위 앱</h6>
<table class="table table-sm" style="font-size:.78rem;"><tbody>
{% for a, c in result.top_apps %}<tr><td><code>{{ a }}</code></td><td><strong>{{ c }}</strong></td></tr>{% endfor %}
</tbody></table></div></div></div>
<div class="tool-panel"><h6 class="panel-title">파일 샘플</h6>
<div style="max-height:500px; overflow-y:auto;"><table class="table table-sm" style="font-size:.74rem;">
<thead><tr class="text-dim"><th>FileID</th><th>Domain</th><th>Path</th></tr></thead><tbody>
{% for f in result.sample_files %}<tr><td><code style="font-size:.7rem;">{{ f.fileID[:16] }}</code></td>
<td>{{ f.domain }}</td><td style="word-break:break-all;">{{ f.path }}</td></tr>{% endfor %}
</tbody></table></div></div>
{% endif %}</div>{% endblock %}''')

# WHATSAPP
w('whatsapp.html', hdr('WhatsApp DB','msgstore.db 평문/crypt14/15 분석.','bi-whatsapp') + '''
<div class="container pb-5">{% if error %}<div class="alert-error mb-3">{{ error }}</div>{% endif %}
{% if not result %}<div class="row justify-content-center"><div class="col-lg-6"><div class="tool-panel"><form method="POST" enctype="multipart/form-data">
<input type="file" name="file" class="form-control mb-3" required>
<input type="text" name="key" class="form-control mb-3" placeholder="키 (선택, 64자 hex)" style="font-family:monospace;">
<button class="btn btn-accent w-100"><i class="bi bi-whatsapp me-1"></i>분석</button>
</form></div></div></div>
{% else %}<div class="tool-panel mb-2">
<h6 class="panel-title">{{ result.filename }}</h6>
<div class="text-dim small mb-2">{{ "{:,}".format(result.size) }} B · {{ result.format }}</div>
{% if result.tables %}<div><strong>테이블 ({{ result.tables|length }})</strong>
<div class="mt-1">{% for t in result.tables %}<code class="me-1 mb-1 d-inline-block">{{ t }}</code>{% endfor %}</div></div>{% endif %}
{% if result.msg_count %}<div class="mt-2"><strong>총 메시지:</strong> {{ "{:,}".format(result.msg_count) }}</div>{% endif %}
{% if result.note %}<div class="mt-2 text-dim small" style="white-space:pre-wrap;">{{ result.note }}</div>{% endif %}
</div>
{% if result.messages %}<div class="tool-panel"><h6 class="panel-title">최근 100건</h6>
<div style="max-height:500px; overflow-y:auto;"><table class="table table-sm" style="font-size:.78rem;">
<thead><tr class="text-dim"><th>시각</th><th>채팅</th><th>내용</th></tr></thead><tbody>
{% for m in result.messages %}<tr>
<td><code style="font-size:.7rem;">{{ m.time[:19] }}</code></td>
<td style="font-size:.72rem;">{{ m.chat[:30] }}{% if m.from_me %} (나){% endif %}</td>
<td style="word-break:break-all;">{{ m.text }}</td>
</tr>{% endfor %}</tbody></table></div></div>{% endif %}
{% endif %}</div>{% endblock %}''')

# TELEGRAM
w('telegram.html', hdr('Telegram tdata','Telegram Desktop tdata 파일 분석.','bi-telegram') + '''
<div class="container pb-5">{% if error %}<div class="alert-error mb-3">{{ error }}</div>{% endif %}
{% if not result %}<div class="row justify-content-center"><div class="col-lg-6"><div class="tool-panel">''' + MULTI + '''</div></div></div>
{% else %}{% for r in result.files %}
<div class="tool-panel mb-2"><h6 class="panel-title">{{ r.filename }}{% if r.format %} <span class="tag">{{ r.format }}</span>{% endif %}</h6>
{% if r.version %}<div>버전: {{ r.version }}</div>{% endif %}
{% if r.data_length %}<div>데이터 길이: {{ r.data_length }}</div>{% endif %}
{% if r.utf16_strings %}<div class="mt-2"><strong>UTF-16 문자열 ({{ r.utf16_strings|length }})</strong>
<div style="max-height:300px; overflow-y:auto; font-size:.72rem; background:var(--bg); padding:.4rem;">
{% for s in r.utf16_strings %}<div>{{ s }}</div>{% endfor %}</div></div>{% endif %}
</div>{% endfor %}
{% endif %}</div>{% endblock %}''')

# PST
w('pst.html', hdr('Outlook PST / OST','!BDN 시그니처·포맷·암호화 방식 확인.','bi-envelope-fill') + '''
<div class="container pb-5">{% if error %}<div class="alert-error mb-3">{{ error }}</div>{% endif %}
{% if not result %}<div class="row justify-content-center"><div class="col-lg-6"><div class="tool-panel">''' + MULTI + '''</div></div></div>
{% else %}{% for r in result.files %}
<div class="tool-panel mb-2"><h6 class="panel-title">{{ r.filename }}</h6>
{% if r.error %}<div class="text-danger">{{ r.error }}</div>
{% else %}<table class="table table-sm" style="font-size:.85rem;">
<tr><td class="text-dim">시그니처</td><td><code>{{ r.signature }}</code></td></tr>
<tr><td class="text-dim">포맷</td><td><strong>{{ r.format }}</strong></td></tr>
<tr><td class="text-dim">클라이언트 버전</td><td>{{ r.version_client }}</td></tr>
<tr><td class="text-dim">암호화</td><td>{{ r.encryption }}</td></tr>
</table>
<div class="text-dim small mt-2">{{ r.note }}</div>
{% endif %}</div>{% endfor %}
{% endif %}</div>{% endblock %}''')

print('=== 30개 템플릿 생성 완료 ===')
