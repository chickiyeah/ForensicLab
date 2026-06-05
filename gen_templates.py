"""18개 도구 템플릿 일괄 생성"""
from pathlib import Path

T = Path(r'E:\forensic\templates\tools')

def hdr(title, sub, icon='bi-tools'):
    return f'''{{% extends 'base.html' %}}{{% block content %}}
<div class="page-hero"><div class="container">
<div class="d-flex align-items-center gap-3 mb-2"><a href="/" class="text-dim text-decoration-none small"><i class="bi bi-house me-1"></i>홈</a><i class="bi bi-chevron-right text-dim small"></i><a href="/tools" class="text-dim text-decoration-none small">분석 도구</a><i class="bi bi-chevron-right text-dim small"></i><span class="text-accent small">{title}</span></div>
<h1 class="page-title"><i class="bi {icon} me-2 text-accent"></i>{title}</h1>
<p class="page-sub">{sub}</p>
</div></div>'''

# JumpList
(T / 'jumplist.html').write_text(hdr('JumpList 분석','Windows .automaticDestinations-ms OLECF 컨테이너에서 DestList 스트림을 파싱해 최근 접근 파일·접근 횟수·시각·핀 상태를 추출.','bi-bookmark-fill') + '''
<div class="container pb-5">
{% if error %}<div class="alert-error mb-3">{{ error }}</div>{% endif %}
{% if not result %}
<div class="row justify-content-center"><div class="col-lg-6"><div class="tool-panel">
<form method="POST" enctype="multipart/form-data">
<input type="file" name="file" class="form-control mb-3" required>
<div class="form-hint mb-3">%APPDATA%\\Microsoft\\Windows\\Recent\\AutomaticDestinations\\&lt;AppID&gt;.automaticDestinations-ms</div>
<button class="btn btn-accent w-100"><i class="bi bi-search me-1"></i>분석</button>
</form></div></div></div>
{% else %}
<div class="d-flex gap-3 mb-3 flex-wrap align-items-center"><strong>{{ result.filename }}</strong>
<span class="text-dim small">{{ "{:,}".format(result.file_size) }} B · 스트림 {{ result.streams|length }}개 · 엔트리 {{ result.entries|length }}개</span>
<a href="/tools/jumplist" class="btn btn-sm btn-outline-secondary ms-auto"><i class="bi bi-arrow-left me-1"></i>새 파일</a></div>

{% if result.entries %}
<div class="tool-panel mb-3"><h6 class="panel-title"><i class="bi bi-clock-history me-2"></i>DestList 엔트리 ({{ result.n_entries or result.entries|length }} 중 핀 {{ result.n_pinned or 0 }})</h6>
<table class="table table-sm" style="font-size:.8rem;">
<thead><tr class="text-dim"><th>#</th><th>마지막 접근</th><th>접근 횟수</th><th>호스트</th><th>경로</th></tr></thead>
<tbody>{% for e in result.entries %}<tr>
<td>{{ e.idx }}</td><td><code>{{ e.last_access[:19] }}</code></td>
<td><strong style="color:#f59e0b">{{ e.access_count }}</strong></td>
<td>{{ e.hostname }}</td><td style="word-break:break-all;"><code>{{ e.path }}</code></td>
</tr>{% endfor %}</tbody></table></div>
{% endif %}

<div class="tool-panel"><h6 class="panel-title"><i class="bi bi-list me-2"></i>전체 스트림</h6>
<div style="max-height:300px; overflow-y:auto; font-size:.78rem;">
{% for s in result.streams %}<div class="d-flex justify-content-between p-1" style="border-bottom:1px solid var(--border);">
<code>{{ s.name }}</code><span class="text-dim">{{ s.size }} B</span></div>{% endfor %}
</div></div>
{% endif %}
</div>{% endblock %}
''', encoding='utf-8')

# OLEDUMP
(T / 'oledump.html').write_text(hdr('VBA·OLE 추출','Office 문서(.doc/.docx/.xls/.xlsx)에서 VBA 매크로·OLE 스트림·임베디드 객체를 추출하고 의심 키워드를 탐지합니다.','bi-file-earmark-word-fill') + '''
<div class="container pb-5">
{% if error %}<div class="alert-error mb-3">{{ error }}</div>{% endif %}
{% if not result %}
<div class="row justify-content-center"><div class="col-lg-6"><div class="tool-panel">
<form method="POST" enctype="multipart/form-data">
<input type="file" name="file" class="form-control mb-3" required>
<div class="form-hint mb-3">.doc / .docx / .xls / .xlsx / .ppt / .pptx / .docm / .xlsm</div>
<button class="btn btn-accent w-100"><i class="bi bi-search me-1"></i>분석</button>
</form></div></div></div>
{% else %}
<div class="d-flex gap-3 mb-3 flex-wrap"><strong>{{ result.filename }}</strong>
<span class="tag">{{ result.format }}</span>
<a href="/tools/oledump" class="btn btn-sm btn-outline-secondary ms-auto"><i class="bi bi-arrow-left me-1"></i>새 파일</a></div>

{% if result.suspicious %}
<div class="tool-panel mb-3" style="border-left:3px solid #ef4444;">
<h6 class="panel-title text-danger"><i class="bi bi-exclamation-triangle me-2"></i>의심 키워드 ({{ result.suspicious|length }})</h6>
<table class="table table-sm" style="font-size:.8rem;"><tbody>
{% for s in result.suspicious %}<tr><td><code style="color:#ef4444">{{ s.keyword }}</code></td><td>{{ s.stream }}</td></tr>{% endfor %}
</tbody></table></div>
{% endif %}

<div class="row g-3"><div class="col-md-7"><div class="tool-panel">
<h6 class="panel-title"><i class="bi bi-list me-2"></i>스트림 ({{ result.streams|length }})</h6>
<div style="max-height:500px; overflow-y:auto; font-size:.78rem;">
{% for s in result.streams %}<div class="d-flex justify-content-between p-1" style="border-bottom:1px solid var(--border);">
<code style="color:{% if s.macro %}#ef4444{% else %}var(--text){% endif %}">{{ s.name }}</code>
<span class="text-dim">{{ s.size }} B {% if s.macro %}<span class="badge bg-danger ms-1" style="font-size:.6rem">매크로</span>{% endif %}</span>
</div>{% endfor %}</div></div></div>

<div class="col-md-5"><div class="tool-panel">
<h6 class="panel-title"><i class="bi bi-code me-2"></i>매크로 코드 ({{ result.macros|length }})</h6>
{% for m in result.macros %}
<div class="mb-2"><strong style="font-size:.78rem; color:var(--accent)">{{ m.stream }}</strong>
<div class="text-dim small">{{ m.size }} bytes</div>
{% if m.strings %}<details><summary class="text-dim small" style="cursor:pointer;">추출 문자열 보기</summary>
<pre style="font-size:.7rem; background:var(--bg); padding:.4rem; border-radius:.35rem; max-height:200px; overflow:auto;">{{ m.strings|join('\\n') }}</pre>
</details>{% endif %}</div>
{% endfor %}</div></div></div>
{% endif %}
</div>{% endblock %}
''', encoding='utf-8')

# PDFSCAN
(T / 'pdfscan.html').write_text(hdr('PDF 악성 분석','PDF 내부의 /JavaScript·/OpenAction·/Launch·/EmbeddedFile 등 위험 객체와 URL을 탐지합니다.','bi-file-earmark-pdf-fill') + '''
<div class="container pb-5">
{% if error %}<div class="alert-error mb-3">{{ error }}</div>{% endif %}
{% if not result %}
<div class="row justify-content-center"><div class="col-lg-6"><div class="tool-panel">
<form method="POST" enctype="multipart/form-data">
<input type="file" name="file" class="form-control mb-3" accept=".pdf" required>
<button class="btn btn-accent w-100"><i class="bi bi-shield-check me-1"></i>분석</button>
</form></div></div></div>
{% else %}
<div class="d-flex gap-3 mb-3 flex-wrap"><strong>{{ result.filename }}</strong>
<span class="text-dim small">{{ "{:,}".format(result.file_size) }} B · PDF v{{ result.version }}</span>
<span class="ms-auto"></span>
<span style="color:{% if result.suspicious %}#ef4444{% else %}#22c55e{% endif %}; font-weight:700;">{{ result.verdict }}</span>
<a href="/tools/pdfscan" class="btn btn-sm btn-outline-secondary ms-2"><i class="bi bi-arrow-left me-1"></i>새 파일</a></div>

{% if result.suspicious %}
<div class="tool-panel mb-3" style="border:2px solid #ef444466; background:rgba(239,68,68,.05);">
<h6 class="panel-title text-danger"><i class="bi bi-exclamation-triangle-fill me-2"></i>의심 패턴 ({{ result.suspicious|length }})</h6>
<ul class="mb-0" style="font-size:.85rem;">{% for s in result.suspicious %}<li>{{ s }}</li>{% endfor %}</ul></div>
{% endif %}

<div class="row g-3 mb-3"><div class="col-md-6"><div class="tool-panel">
<h6 class="panel-title"><i class="bi bi-tag me-2"></i>PDF 객체 카운트</h6>
<table class="table table-sm" style="font-size:.85rem;">
<tr><td class="text-dim">전체 객체</td><td><strong>{{ result.object_count }}</strong></td></tr>
<tr><td class="text-dim">스트림</td><td>{{ result.stream_count }}</td></tr>
<tr><td class="text-dim">필터</td><td>{{ result.filter_count }}</td></tr>
{% for k, v in result.counts.items() %}{% if v > 0 %}
<tr><td><code style="color:{% if k in ('/JavaScript','/JS','/OpenAction','/AA','/Launch') %}#ef4444{% else %}var(--accent){% endif %}">{{ k }}</code></td><td><strong>{{ v }}</strong></td></tr>
{% endif %}{% endfor %}</table></div></div>

<div class="col-md-6"><div class="tool-panel">
<h6 class="panel-title"><i class="bi bi-link-45deg me-2"></i>URL ({{ result.urls|length }})</h6>
<div style="max-height:400px; overflow-y:auto; font-size:.78rem;">
{% for u in result.urls %}<div class="p-1" style="border-bottom:1px solid var(--border); word-break:break-all;">
<code>{{ u }}</code></div>{% endfor %}
{% if not result.urls %}<div class="text-dim">URL 없음</div>{% endif %}
</div></div></div></div>
{% endif %}
</div>{% endblock %}
''', encoding='utf-8')

# JWT
(T / 'jwt.html').write_text(hdr('JWT 디코더','JSON Web Token Header·Payload·Signature 분해 및 알고리즘·만료·취약점 검사.','bi-key-fill') + '''
<div class="container pb-5">
<div class="row g-3"><div class="col-lg-5"><div class="tool-panel">
<h6 class="panel-title"><i class="bi bi-input-cursor-text me-2"></i>JWT 입력</h6>
<form method="POST">
<textarea name="token" class="form-control mb-3" rows="8" style="font-family:monospace; font-size:.75rem; word-break:break-all;" placeholder="eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.SIGNATURE">{{ token }}</textarea>
<button class="btn btn-accent w-100"><i class="bi bi-unlock me-1"></i>디코드</button>
</form></div></div>
<div class="col-lg-7">{% if error %}<div class="alert-error">{{ error }}</div>{% endif %}
{% if result %}
{% if result.warnings %}
<div class="tool-panel mb-2">{% for w in result.warnings %}<div style="font-size:.82rem; padding:.1rem 0;">{{ w }}</div>{% endfor %}</div>
{% endif %}
<div class="tool-panel mb-2"><h6 class="panel-title">Header — <code style="color:var(--accent)">{{ result.alg }}</code></h6>
<pre style="background:var(--bg); padding:.5rem; border-radius:.35rem; font-size:.78rem; margin:0;">{{ result.header | tojson(indent=2) }}</pre></div>
<div class="tool-panel mb-2"><h6 class="panel-title">Payload</h6>
<pre style="background:var(--bg); padding:.5rem; border-radius:.35rem; font-size:.78rem; margin:0; max-height:400px; overflow:auto;">{{ result.payload | tojson(indent=2) }}</pre></div>
<div class="tool-panel"><h6 class="panel-title">Signature ({{ result.signature_len }} bytes)</h6>
<code style="font-size:.72rem; word-break:break-all;">{{ result.signature_hex }}</code></div>
{% endif %}
</div></div></div>{% endblock %}
''', encoding='utf-8')

# CERT
(T / 'cert.html').write_text(hdr('X.509 인증서','PEM/DER/PKCS#12 인증서의 Subject/Issuer/SAN/유효기간/Fingerprint를 추출하고 자가서명·만료·취약 알고리즘을 경고합니다.','bi-shield-fill-check') + '''
<div class="container pb-5">
{% if error %}<div class="alert-error mb-3">{{ error }}</div>{% endif %}
{% if not result %}
<div class="row justify-content-center"><div class="col-lg-7"><div class="tool-panel">
<form method="POST" enctype="multipart/form-data">
<label class="form-label-sm">파일 (.crt/.cer/.pem/.der/.p12/.pfx)</label>
<input type="file" name="file" class="form-control mb-3">
<label class="form-label-sm">또는 PEM 텍스트 붙여넣기</label>
<textarea name="pem" class="form-control mb-3" rows="6" style="font-family:monospace; font-size:.7rem;" placeholder="-----BEGIN CERTIFICATE-----..."></textarea>
<button class="btn btn-accent w-100"><i class="bi bi-search me-1"></i>분석</button>
</form></div></div></div>
{% else %}
<div class="d-flex gap-3 mb-3 flex-wrap align-items-center"><strong>{{ result.filename }}</strong>
<a href="/tools/cert" class="btn btn-sm btn-outline-secondary ms-auto"><i class="bi bi-arrow-left me-1"></i>새 인증서</a></div>
{% if result.warnings %}<div class="tool-panel mb-3">{% for w in result.warnings %}<div style="font-size:.85rem; padding:.1rem 0;">{{ w }}</div>{% endfor %}</div>{% endif %}
<div class="tool-panel"><table class="table table-sm" style="font-size:.85rem;">
<tr><td class="text-dim" style="width:140px;">Subject</td><td><code>{{ result.subject }}</code></td></tr>
<tr><td class="text-dim">Issuer</td><td><code>{{ result.issuer }}</code></td></tr>
<tr><td class="text-dim">Serial</td><td><code>{{ result.serial }}</code></td></tr>
<tr><td class="text-dim">버전</td><td>{{ result.version }}</td></tr>
<tr><td class="text-dim">유효 시작</td><td>{{ result.not_before }}</td></tr>
<tr><td class="text-dim">유효 만료</td><td>{{ result.not_after }}</td></tr>
<tr><td class="text-dim">서명 알고리즘</td><td><code>{{ result.signature_algorithm }}</code></td></tr>
<tr><td class="text-dim">공개키 크기</td><td>{{ result.public_key_size }}-bit</td></tr>
<tr><td class="text-dim">SHA-256 지문</td><td><code style="font-size:.7rem; word-break:break-all;">{{ result.fingerprint_sha256 }}</code></td></tr>
<tr><td class="text-dim">SHA-1 지문</td><td><code style="font-size:.7rem; word-break:break-all;">{{ result.fingerprint_sha1 }}</code></td></tr>
{% if result.san %}<tr><td class="text-dim">SAN</td><td>{% for s in result.san %}<code class="me-2">{{ s }}</code>{% endfor %}</td></tr>{% endif %}
</table></div>
{% endif %}
</div>{% endblock %}
''', encoding='utf-8')

# YARA
(T / 'yara.html').write_text(hdr('YARA-lite 스캐너','간소화된 YARA 규칙(문자열·헥스 패턴)으로 파일을 스캔하여 매칭 위치를 표시합니다.','bi-search') + '''
<div class="container pb-5">
{% if error %}<div class="alert-error mb-3">{{ error }}</div>{% endif %}
<div class="row g-3"><div class="col-lg-5"><div class="tool-panel">
<h6 class="panel-title"><i class="bi bi-code-square me-2"></i>YARA 규칙</h6>
<form method="POST" enctype="multipart/form-data">
<input type="file" name="file" class="form-control mb-2" required>
<textarea name="rules" class="form-control mb-2" rows="14" style="font-family:monospace; font-size:.74rem;" placeholder='rule Mimikatz {
  strings:
    $a = "mimikatz"
    $b = "sekurlsa"
    $c = { 4D 5A 90 00 }
  condition:
    any of them
}'>{{ rules }}</textarea>
<button class="btn btn-accent w-100"><i class="bi bi-search me-1"></i>스캔</button>
</form></div></div>
<div class="col-lg-7">{% if result %}
<div class="tool-panel"><h6 class="panel-title">{{ result.filename }} — {{ result.matches|length }}개 규칙 매칭 ({{ result.match_count }}건)</h6>
{% for m in result.matches %}
<div class="mb-2 p-2" style="background:var(--bg); border-radius:.35rem; border-left:3px solid var(--accent);">
<strong style="color:var(--accent)">rule {{ m.rule }}</strong>
{% for h in m.hits %}<div class="ms-3 mt-1" style="font-size:.78rem;">
<code>${{ h.var }} ({{ h.type }})</code> = <code style="color:#f59e0b">{{ h.pattern }}</code>
<div class="text-dim small">오프셋: {{ h.offsets|join(', ') }}</div></div>{% endfor %}
</div>{% endfor %}
{% if not result.matches %}<div class="text-dim">매칭 없음</div>{% endif %}
</div>{% endif %}
</div></div></div>{% endblock %}
''', encoding='utf-8')

# HEXDIFF
(T / 'hexdiff.html').write_text(hdr('파일 헥스 비교','두 파일을 바이트 단위로 비교하여 차이 위치를 헥스로 표시합니다.','bi-distribute-horizontal') + '''
<div class="container pb-5">
{% if error %}<div class="alert-error mb-3">{{ error }}</div>{% endif %}
{% if not result %}
<div class="row justify-content-center"><div class="col-lg-6"><div class="tool-panel">
<form method="POST" enctype="multipart/form-data">
<label class="form-label-sm">파일 A</label>
<input type="file" name="file_a" class="form-control mb-3" required>
<label class="form-label-sm">파일 B</label>
<input type="file" name="file_b" class="form-control mb-3" required>
<button class="btn btn-accent w-100"><i class="bi bi-arrow-left-right me-1"></i>비교</button>
</form></div></div></div>
{% else %}
<div class="tool-panel mb-3" style="border-left:3px solid {% if result.identical %}#22c55e{% else %}#ef4444{% endif %};">
<h6 class="panel-title">{% if result.identical %}<i class="bi bi-check-circle-fill text-success me-2"></i>완전 일치{% else %}<i class="bi bi-x-circle-fill text-danger me-2"></i>{{ result.diffs|length }}개 바이트 차이{% endif %}</h6>
<div class="row" style="font-size:.82rem;">
<div class="col-md-6"><strong>A: {{ result.name_a }}</strong> ({{ result.size_a }} B)
<div class="text-dim small">SHA-256: <code style="font-size:.65rem; word-break:break-all;">{{ result.sha256_a }}</code></div></div>
<div class="col-md-6"><strong>B: {{ result.name_b }}</strong> ({{ result.size_b }} B)
<div class="text-dim small">SHA-256: <code style="font-size:.65rem; word-break:break-all;">{{ result.sha256_b }}</code></div></div>
</div></div>

{% if not result.identical %}
<div class="tool-panel"><h6 class="panel-title">바이트별 차이 ({{ result.diffs|length }})</h6>
<div style="max-height:500px; overflow-y:auto;">
<table class="table table-sm" style="font-size:.78rem; font-family:monospace;">
<thead><tr class="text-dim"><th>오프셋</th><th>A</th><th>B</th></tr></thead>
<tbody>{% for d in result.diffs %}<tr>
<td><code>0x{{ "%08x"|format(d.offset) }}</code></td>
<td style="color:#22c55e">{{ d.a }}</td>
<td style="color:#ef4444">{{ d.b }}</td>
</tr>{% endfor %}</tbody></table></div>
<a href="/tools/hexdiff" class="btn btn-sm btn-outline-secondary mt-2"><i class="bi bi-arrow-left me-1"></i>새 비교</a></div>
{% endif %}
{% endif %}
</div>{% endblock %}
''', encoding='utf-8')

# SECRETS
(T / 'secrets.html').write_text(hdr('Secret 스캐너','코드·로그·설정 파일에서 AWS·GCP·GitHub·Slack·Stripe·DB 비밀번호 등 22종 패턴을 자동 탐지합니다.','bi-shield-lock-fill') + '''
<div class="container pb-5">
{% if error %}<div class="alert-error mb-3">{{ error }}</div>{% endif %}
<div class="row g-3"><div class="col-lg-5"><div class="tool-panel">
<form method="POST" enctype="multipart/form-data">
<label class="form-label-sm">파일 업로드</label>
<input type="file" name="file" class="form-control mb-3">
<label class="form-label-sm">또는 텍스트 붙여넣기</label>
<textarea name="text" class="form-control mb-3" rows="10" style="font-family:monospace; font-size:.74rem;"></textarea>
<button class="btn btn-accent w-100"><i class="bi bi-search me-1"></i>스캔</button>
</form></div></div>
<div class="col-lg-7">{% if result %}
<div class="d-flex gap-3 mb-3"><strong>{{ result.filename }}</strong><span class="text-dim small">{{ "{:,}".format(result.file_size) }} B</span>
<span class="ms-auto"><strong style="color:{% if result.total %}#ef4444{% else %}#22c55e{% endif %};">{{ result.total }}건 발견</strong></span></div>
{% if result.by_type %}<div class="tool-panel mb-2"><h6 class="panel-title">타입별</h6>
<div class="d-flex flex-wrap gap-1">{% for t, c in result.by_type %}<span class="tag" style="font-size:.74rem;">{{ t }} <strong style="color:#ef4444">{{ c }}</strong></span>{% endfor %}</div>
</div>{% endif %}
{% for f in result.findings %}<div class="tool-panel mb-2" style="padding:.5rem .7rem;">
<div class="d-flex justify-content-between"><strong style="color:#ef4444; font-size:.84rem;">{{ f.type }}</strong>
<code class="text-dim" style="font-size:.7rem;">@ {{ f.offset }}</code></div>
<code style="font-size:.74rem; word-break:break-all; color:#f59e0b;">{{ f.value }}</code>
<div class="text-dim small" style="font-size:.7rem;">...{{ f.context }}...</div>
</div>{% endfor %}
{% endif %}
</div></div></div>{% endblock %}
''', encoding='utf-8')

# ESEDB
(T / 'esedb.html').write_text(hdr('ESE DB 헤더','Windows ESE 데이터베이스(SRUDB.dat·Windows.edb·WebCacheV01.dat)의 헤더를 파싱합니다.','bi-database-fill') + '''
<div class="container pb-5">
{% if error %}<div class="alert-error mb-3">{{ error }}</div>{% endif %}
{% if not result %}
<div class="row justify-content-center"><div class="col-lg-6"><div class="tool-panel">
<form method="POST" enctype="multipart/form-data">
<input type="file" name="file" class="form-control mb-3" required>
<div class="form-hint mb-3">SRUDB.dat / Windows.edb / WebCacheV01.dat — 헤더만 읽음</div>
<button class="btn btn-accent w-100"><i class="bi bi-search me-1"></i>분석</button>
</form></div></div></div>
{% else %}
<div class="d-flex gap-3 mb-3"><strong>{{ result.filename }}</strong>
<a href="/tools/esedb" class="btn btn-sm btn-outline-secondary ms-auto"><i class="bi bi-arrow-left me-1"></i>새 파일</a></div>
<div class="tool-panel"><table class="table table-sm" style="font-size:.85rem;">
<tr><td class="text-dim" style="width:160px;">시그니처</td><td><code>{{ result.signature }}</code></td></tr>
<tr><td class="text-dim">파일 포맷</td><td>v{{ result.file_format_version }}</td></tr>
<tr><td class="text-dim">파일 타입</td><td>{{ result.file_type }}</td></tr>
<tr><td class="text-dim">페이지 크기</td><td>{{ result.page_size }} bytes</td></tr>
<tr><td class="text-dim">DB 상태</td><td><strong style="color:{% if result.db_state == 'CleanShutdown' %}#22c55e{% else %}#ef4444{% endif %}">{{ result.db_state }}</strong></td></tr>
<tr><td class="text-dim">로그 위치</td><td>{{ result.log_position }}</td></tr>
<tr><td class="text-dim">Consistent 위치</td><td>{{ result.consistent_position }}</td></tr>
</table>
<div class="text-dim small mt-2"><i class="bi bi-info-circle me-1"></i>{{ result.note }}</div></div>
{% endif %}
</div>{% endblock %}
''', encoding='utf-8')

# MFT
(T / 'mft.html').write_text(hdr('$MFT NTFS 파서','NTFS Master File Table에서 FILE 레코드를 파싱해 파일명·MAC 타임스탬프·삭제 여부를 추출합니다.','bi-list-columns-reverse') + '''
<div class="container pb-5">
{% if error %}<div class="alert-error mb-3">{{ error }}</div>{% endif %}
{% if not result %}
<div class="row justify-content-center"><div class="col-lg-6"><div class="tool-panel">
<form method="POST" enctype="multipart/form-data">
<input type="file" name="file" class="form-control mb-3" required>
<div class="form-hint mb-3">$MFT (raw extract). 최대 50MB 분석</div>
<button class="btn btn-accent w-100"><i class="bi bi-search me-1"></i>파싱</button>
</form></div></div></div>
{% else %}
<div class="d-flex gap-3 mb-3 flex-wrap"><strong>{{ result.filename }}</strong>
<span class="text-dim small">총 {{ result.total }} · 삭제 {{ result.deleted }} · 디렉터리 {{ result.dirs }}</span>
<a href="/tools/mft" class="btn btn-sm btn-outline-secondary ms-auto"><i class="bi bi-arrow-left me-1"></i>새 파일</a></div>
<div class="tool-panel"><div style="max-height:600px; overflow-y:auto;">
<table class="table table-sm" style="font-size:.78rem;">
<thead style="position:sticky; top:0; background:var(--bg-card); z-index:1;">
<tr class="text-dim"><th>#</th><th>상태</th><th>이름</th><th>수정</th><th>생성</th><th>접근</th></tr>
</thead><tbody>{% for r in result.records %}<tr>
<td>{{ r.rec_num }}</td>
<td>{% if r.is_dir %}<i class="bi bi-folder text-warning"></i>{% else %}<i class="bi bi-file text-info"></i>{% endif %}
{% if not r.in_use %}<span class="badge bg-danger ms-1" style="font-size:.6rem">DEL</span>{% endif %}</td>
<td style="word-break:break-all;"><code style="color:{% if r.in_use %}var(--accent){% else %}#ef4444{% endif %}">{{ r.filename }}</code></td>
<td><code style="font-size:.72rem;">{{ r.timestamps.modified[:19] if r.timestamps.modified else '' }}</code></td>
<td><code style="font-size:.72rem;">{{ r.timestamps.created[:19] if r.timestamps.created else '' }}</code></td>
<td><code style="font-size:.72rem;">{{ r.timestamps.accessed[:19] if r.timestamps.accessed else '' }}</code></td>
</tr>{% endfor %}</tbody></table></div></div>
{% endif %}
</div>{% endblock %}
''', encoding='utf-8')

# EMAIL_AUTH
(T / 'email_auth.html').write_text(hdr('SPF / DKIM / DMARC','도메인 DNS 조회 + 이메일 헤더 분석으로 메일 인증 정책과 검증 결과를 확인합니다.','bi-envelope-check-fill') + '''
<div class="container pb-5">
{% if error %}<div class="alert-error mb-3">{{ error }}</div>{% endif %}
<div class="row g-3"><div class="col-lg-5"><div class="tool-panel">
<form method="POST">
<label class="form-label-sm">도메인</label>
<input type="text" name="domain" class="form-control mb-3" placeholder="example.com">
<label class="form-label-sm">또는 이메일 헤더 붙여넣기</label>
<textarea name="headers" class="form-control mb-3" rows="10" style="font-family:monospace; font-size:.72rem;" placeholder="Authentication-Results: ...
Received: from ..."></textarea>
<button class="btn btn-accent w-100"><i class="bi bi-shield-check me-1"></i>분석</button>
</form></div></div>
<div class="col-lg-7">{% if result %}
{% if result.spf %}<div class="tool-panel mb-2" style="border-left:3px solid var(--accent);">
<strong>SPF</strong><div style="font-family:monospace; font-size:.78rem; margin-top:.3rem; word-break:break-all;">{{ result.spf }}</div></div>{% endif %}
{% if result.dmarc %}<div class="tool-panel mb-2" style="border-left:3px solid #a78bfa;">
<strong>DMARC</strong><div style="font-family:monospace; font-size:.78rem; margin-top:.3rem; word-break:break-all;">{{ result.dmarc }}</div></div>{% endif %}
{% if result.mx %}<div class="tool-panel mb-2"><strong>MX 레코드</strong>
{% for m in result.mx %}<div style="font-family:monospace; font-size:.78rem;">{{ m }}</div>{% endfor %}</div>{% endif %}
{% if result.auth_results %}<div class="tool-panel mb-2"><strong>Authentication-Results</strong>
<div class="d-flex gap-2 my-2">
<span class="tag" style="background:{% if result.spf_pass %}rgba(34,197,94,.15);color:#22c55e{% else %}rgba(239,68,68,.15);color:#ef4444{% endif %};">SPF {% if result.spf_pass %}PASS{% else %}FAIL{% endif %}</span>
<span class="tag" style="background:{% if result.dkim_pass %}rgba(34,197,94,.15);color:#22c55e{% else %}rgba(239,68,68,.15);color:#ef4444{% endif %};">DKIM {% if result.dkim_pass %}PASS{% else %}FAIL{% endif %}</span>
<span class="tag" style="background:{% if result.dmarc_pass %}rgba(34,197,94,.15);color:#22c55e{% else %}rgba(239,68,68,.15);color:#ef4444{% endif %};">DMARC {% if result.dmarc_pass %}PASS{% else %}FAIL{% endif %}</span>
</div>
<pre style="background:var(--bg); padding:.5rem; border-radius:.35rem; font-size:.72rem; margin:0;">{{ result.auth_results }}</pre>
</div>{% endif %}
{% if result.hop_ips %}<div class="tool-panel"><strong>경유 IP</strong>
{% for ip in result.hop_ips %}<code class="d-block">{{ ip }}</code>{% endfor %}</div>{% endif %}
{% endif %}
</div></div></div>{% endblock %}
''', encoding='utf-8')

# DNS
(T / 'dns.html').write_text(hdr('DNS / DGA 탐지','도메인 목록에서 DGA(Domain Generation Algorithm) 패턴을 휴리스틱으로 탐지하고 의심도를 점수화합니다.','bi-broadcast') + '''
<div class="container pb-5">
{% if error %}<div class="alert-error mb-3">{{ error }}</div>{% endif %}
<div class="row g-3"><div class="col-lg-5"><div class="tool-panel">
<form method="POST">
<label class="form-label-sm">도메인 목록 (한 줄에 하나 또는 텍스트)</label>
<textarea name="text" class="form-control mb-3" rows="14" style="font-family:monospace; font-size:.74rem;" placeholder="example.com
xkqjvwzlmpoiu.net
google.com
asdfgqwerty1234.xyz"></textarea>
<button class="btn btn-accent w-100"><i class="bi bi-search me-1"></i>분석</button>
</form></div></div>
<div class="col-lg-7">{% if result %}
<div class="tool-panel"><h6 class="panel-title">분석 결과 — {{ result.total }}개 도메인, 의심 {{ result.suspicious|length }}건</h6>
<div style="max-height:600px; overflow-y:auto;">
<table class="table table-sm" style="font-size:.82rem;">
<thead><tr class="text-dim"><th>도메인</th><th>점수</th><th>엔트로피</th><th>판정</th></tr></thead>
<tbody>{% for d in result.domains %}<tr>
<td><code style="color:{% if d.score >= 50 %}#ef4444{% elif d.score >= 20 %}#f59e0b{% else %}var(--text){% endif %}">{{ d.domain }}</code></td>
<td><strong>{{ d.score }}</strong></td>
<td>{{ d.entropy }}</td>
<td><span class="tag" style="background:{% if d.score >= 50 %}rgba(239,68,68,.15);color:#ef4444{% elif d.score >= 20 %}rgba(245,158,11,.15);color:#f59e0b{% else %}rgba(34,197,94,.15);color:#22c55e{% endif %};">{{ d.verdict }}</span></td>
</tr>{% endfor %}</tbody></table></div></div>
{% endif %}
</div></div></div>{% endblock %}
''', encoding='utf-8')

# STEGO
(T / 'stego.html').write_text(hdr('스테가노그래피 탐지','이미지에서 LSB 편향·파일 끝 부가 데이터·임베디드 시그니처·EXIF 숨김 데이터를 탐지합니다.','bi-eye-fill') + '''
<div class="container pb-5">
{% if error %}<div class="alert-error mb-3">{{ error }}</div>{% endif %}
{% if not result %}
<div class="row justify-content-center"><div class="col-lg-6"><div class="tool-panel">
<form method="POST" enctype="multipart/form-data">
<input type="file" name="file" class="form-control mb-3" required>
<button class="btn btn-accent w-100"><i class="bi bi-eye me-1"></i>분석</button>
</form></div></div></div>
{% else %}
<div class="d-flex gap-3 mb-3 flex-wrap"><strong>{{ result.filename }}</strong>
<span class="text-dim small">{{ result.image_format }} · {{ result.image_size }} · {{ result.image_mode }}</span>
<a href="/tools/stego" class="btn btn-sm btn-outline-secondary ms-auto"><i class="bi bi-arrow-left me-1"></i>새 파일</a></div>
{% if result.lsb_analysis %}
<div class="tool-panel mb-3"><h6 class="panel-title"><i class="bi bi-grid-3x3 me-2"></i>LSB 분석</h6>
<div class="row"><div class="col-md-4"><div class="text-dim small">LSB=1 비율</div>
<div style="font-size:1.8rem; font-weight:700; color:{% if 0.45 < result.lsb_analysis.ratio < 0.55 %}#22c55e{% else %}#ef4444{% endif %};">{{ result.lsb_analysis.ratio }}</div>
<div class="text-dim small">표본 {{ result.lsb_analysis.sample_size }}개</div></div>
<div class="col-md-8"><strong>{{ result.lsb_analysis.verdict }}</strong>
{% if result.lsb_message %}<div class="mt-2 p-2" style="background:var(--bg); border-radius:.35rem;">
<div class="text-dim small">추출된 LSB ASCII:</div>
<code style="word-break:break-all;">{{ result.lsb_message }}</code></div>{% endif %}
</div></div></div>{% endif %}

{% if result.findings %}
<div class="tool-panel mb-3"><h6 class="panel-title text-warning"><i class="bi bi-exclamation-triangle me-2"></i>탐지 항목</h6>
{% for f in result.findings %}<div class="p-2 mb-2" style="background:var(--bg); border-radius:.35rem;">
<strong>{{ f.type }}</strong> <span class="text-dim small">@ 오프셋 0x{{ "%X"|format(f.offset) }}, {{ f.size }} bytes</span>
<div style="font-family:monospace; font-size:.74rem; word-break:break-all; margin-top:.3rem;">{{ f.preview }}</div>
</div>{% endfor %}</div>{% endif %}

{% if result.embedded_signatures %}
<div class="tool-panel"><h6 class="panel-title"><i class="bi bi-file-earmark-zip me-2"></i>임베디드 시그니처 ({{ result.embedded_signatures|length }})</h6>
{% for e in result.embedded_signatures %}<div class="d-flex gap-2 p-1" style="border-bottom:1px solid var(--border);">
<code>{{ e.sig }}</code><strong>{{ e.label }}</strong><span class="text-dim ms-auto">@ {{ e.offset }}</span></div>{% endfor %}
</div>{% endif %}
{% endif %}
</div>{% endblock %}
''', encoding='utf-8')

# QR
(T / 'qr.html').write_text(hdr('QR / 바코드 디코더','이미지에서 QR·EAN·Code128·Code39 등 1D/2D 바코드를 인식해 텍스트를 추출합니다.','bi-qr-code-scan') + '''
<div class="container pb-5">
{% if error %}<div class="alert-error mb-3">{{ error }}</div>{% endif %}
{% if not result %}
<div class="row justify-content-center"><div class="col-lg-6"><div class="tool-panel">
<form method="POST" enctype="multipart/form-data">
<input type="file" name="file" class="form-control mb-3" accept="image/*" required>
<button class="btn btn-accent w-100"><i class="bi bi-qr-code-scan me-1"></i>스캔</button>
</form>
<div class="text-dim small mt-3"><i class="bi bi-info-circle me-1"></i>이 도구는 pyzbar+libzbar이 설치된 환경에서 동작합니다.</div>
</div></div></div>
{% else %}
<div class="d-flex gap-3 mb-3"><strong>{{ result.filename }}</strong>
<span class="text-dim small">{{ result.image_size }} · {{ result.codes|length }}개 코드</span>
<a href="/tools/qr" class="btn btn-sm btn-outline-secondary ms-auto"><i class="bi bi-arrow-left me-1"></i>새 이미지</a></div>
{% if result.codes %}{% for c in result.codes %}
<div class="tool-panel mb-2"><h6 class="panel-title"><span class="tag">{{ c.type }}</span> <span class="text-dim small ms-2">{{ c.rect }}</span></h6>
<div style="word-break:break-all; font-family:monospace; font-size:.84rem;">{{ c.data }}</div>
{% if c.data.startswith('http') %}<a href="{{ c.data }}" target="_blank" class="btn btn-sm btn-outline-info mt-2"><i class="bi bi-box-arrow-up-right me-1"></i>URL 열기</a>{% endif %}
</div>{% endfor %}
{% else %}<div class="tool-panel text-dim">{{ result.note or '코드 없음' }}</div>{% endif %}
{% endif %}
</div>{% endblock %}
''', encoding='utf-8')

# OCR
(T / 'ocr.html').write_text(hdr('이미지 OCR','tesseract OCR로 이미지에서 텍스트를 추출합니다 (한국어·영어 자동 인식).','bi-card-text') + '''
<div class="container pb-5">
{% if error %}<div class="alert-error mb-3">{{ error }}</div>{% endif %}
{% if not result %}
<div class="row justify-content-center"><div class="col-lg-6"><div class="tool-panel">
<form method="POST" enctype="multipart/form-data">
<input type="file" name="file" class="form-control mb-3" accept="image/*" required>
<label class="form-label-sm">언어</label>
<select name="lang" class="form-select mb-3">
<option value="eng+kor" selected>영어 + 한국어</option>
<option value="kor">한국어만</option><option value="eng">영어만</option>
<option value="jpn">일본어</option><option value="chi_sim">중국어 간체</option>
</select>
<button class="btn btn-accent w-100"><i class="bi bi-card-text me-1"></i>OCR 실행</button>
</form>
<div class="text-dim small mt-3"><i class="bi bi-info-circle me-1"></i>tesseract 시스템 패키지 + pytesseract 설치 필요.</div>
</div></div></div>
{% else %}
<div class="d-flex gap-3 mb-3"><strong>{{ result.filename }}</strong>
<span class="text-dim small">{{ result.image_size }} · 단어 {{ result.word_count }} · 글자 {{ result.char_count }}</span>
<a href="/tools/ocr" class="btn btn-sm btn-outline-secondary ms-auto"><i class="bi bi-arrow-left me-1"></i>새 이미지</a></div>
<div class="tool-panel"><pre style="background:var(--bg); padding:1rem; border-radius:.4rem; white-space:pre-wrap; word-break:break-word; font-size:.86rem; max-height:600px; overflow:auto; margin:0;">{{ result.text }}</pre></div>
{% endif %}
</div>{% endblock %}
''', encoding='utf-8')

# WHOIS
(T / 'whois.html').write_text(hdr('WHOIS / IP 정보','도메인 또는 IP의 WHOIS 정보·등록자·국가·ASN·RFC1918 분류를 표시합니다.','bi-globe-asia-australia') + '''
<div class="container pb-5">
{% if error %}<div class="alert-error mb-3">{{ error }}</div>{% endif %}
<div class="row g-3"><div class="col-lg-4"><div class="tool-panel">
<form method="POST">
<label class="form-label-sm">도메인 또는 IP</label>
<input type="text" name="target" class="form-control mb-3" placeholder="example.com 또는 8.8.8.8" {% if result %}value="{{ result.target }}"{% endif %}>
<button class="btn btn-accent w-100"><i class="bi bi-search me-1"></i>조회</button>
</form></div></div>
<div class="col-lg-8">{% if result %}
<div class="tool-panel mb-2"><table class="table table-sm" style="font-size:.85rem;">
<tr><td class="text-dim" style="width:140px;">대상</td><td><code>{{ result.target }}</code></td></tr>
<tr><td class="text-dim">분류</td><td><strong>{{ result.classification }}</strong></td></tr>
<tr><td class="text-dim">WHOIS 서버</td><td><code>{{ result.whois_server }}</code></td></tr>
{% for k, v in result.extracted.items() %}<tr><td class="text-dim">{{ k }}</td><td><code>{{ v }}</code></td></tr>{% endfor %}
</table></div>
<div class="tool-panel"><h6 class="panel-title">전체 WHOIS 응답</h6>
<pre style="background:var(--bg); padding:.75rem; border-radius:.4rem; font-size:.72rem; max-height:500px; overflow:auto; margin:0;">{{ result.raw }}</pre>
</div>{% endif %}
</div></div></div>{% endblock %}
''', encoding='utf-8')

# PASSWD
(T / 'passwd.html').write_text(hdr('암호 강도 측정','Shannon 엔트로피·문자 클래스·일반 비밀번호 사전으로 강도와 크랙 시간을 추정합니다.','bi-key') + '''
<div class="container pb-5">
{% if error %}<div class="alert-error mb-3">{{ error }}</div>{% endif %}
<div class="row g-3"><div class="col-lg-5"><div class="tool-panel">
<form method="POST">
<label class="form-label-sm">비밀번호 (서버 로그 저장 안 됨)</label>
<input type="text" name="password" class="form-control mb-3" autocomplete="off" autofocus>
<button class="btn btn-accent w-100"><i class="bi bi-shield-check me-1"></i>측정</button>
</form>
<div class="text-dim small mt-2"><i class="bi bi-info-circle me-1"></i>입력값은 메모리에서만 처리됩니다.</div>
</div></div>
<div class="col-lg-7">{% if result %}
<div class="tool-panel mb-2" style="border:2px solid {{ result.grade_color }}66;">
<div class="text-center"><div style="font-size:2.5rem; font-weight:700; color:{{ result.grade_color }};">{{ result.grade }}</div>
<div class="text-dim">엔트로피 <strong style="color:var(--text)">{{ result.entropy_bits }}</strong> bits</div></div>
</div>
<div class="tool-panel mb-2"><h6 class="panel-title">크랙 예상 시간</h6>
<div class="row"><div class="col-md-6"><div class="text-dim small">오프라인 (10억/초)</div>
<strong style="color:#ef4444;">{{ result.crack_time_offline }}</strong></div>
<div class="col-md-6"><div class="text-dim small">온라인 (1000/초)</div>
<strong style="color:#22c55e;">{{ result.crack_time_online }}</strong></div></div>
</div>
<div class="tool-panel mb-2"><h6 class="panel-title">구성</h6>
<table class="table table-sm" style="font-size:.84rem;">
<tr><td class="text-dim">길이</td><td><strong>{{ result.length }}</strong> 자</td></tr>
<tr><td class="text-dim">문자 클래스</td><td>{{ result.classes }}/4
{% if result.has_lower %}<span class="tag" style="font-size:.7rem">소문자</span>{% endif %}
{% if result.has_upper %}<span class="tag" style="font-size:.7rem">대문자</span>{% endif %}
{% if result.has_digit %}<span class="tag" style="font-size:.7rem">숫자</span>{% endif %}
{% if result.has_symbol %}<span class="tag" style="font-size:.7rem">기호</span>{% endif %}</td></tr>
<tr><td class="text-dim">풀 크기</td><td>{{ result.pool_size }}</td></tr>
<tr><td class="text-dim">총 조합</td><td><code>{{ result.combinations }}</code></td></tr>
</table></div>
{% if result.weakness %}<div class="tool-panel" style="border-left:3px solid #ef4444;">
<h6 class="panel-title text-danger"><i class="bi bi-exclamation-triangle me-2"></i>약점</h6>
{% for w in result.weakness %}<div class="small">{{ w }}</div>{% endfor %}
</div>{% endif %}
{% endif %}
</div></div></div>{% endblock %}
''', encoding='utf-8')

# GIT
(T / 'git.html').write_text(hdr('Git 저장소 분석','.git 디렉터리를 ZIP으로 압축해 업로드하면 커밋·브랜치·삭제된 blob·config·logs를 분석합니다.','bi-git') + '''
<div class="container pb-5">
{% if error %}<div class="alert-error mb-3">{{ error }}</div>{% endif %}
{% if not result %}
<div class="row justify-content-center"><div class="col-lg-6"><div class="tool-panel">
<form method="POST" enctype="multipart/form-data">
<input type="file" name="file" class="form-control mb-3" accept=".zip" required>
<div class="form-hint mb-3">.git 폴더를 ZIP으로 압축 (예: zip -r repo_git.zip .git)</div>
<button class="btn btn-accent w-100"><i class="bi bi-search me-1"></i>분석</button>
</form></div></div></div>
{% else %}
<div class="d-flex gap-3 mb-3 flex-wrap"><strong>{{ result.filename }}</strong>
<span class="text-dim small">{{ result.objects }} 객체 · {{ result.commits|length }} 커밋 · {{ result.branches|length }} 브랜치</span>
<a href="/tools/git" class="btn btn-sm btn-outline-secondary ms-auto"><i class="bi bi-arrow-left me-1"></i>새 ZIP</a></div>

{% if result.branches %}<div class="tool-panel mb-3"><h6 class="panel-title"><i class="bi bi-diagram-3 me-2"></i>브랜치 / 태그</h6>
{% for b in result.branches %}<div class="d-flex gap-2"><strong style="color:var(--accent);">{{ b.name }}</strong><code style="font-size:.7rem;">{{ b.commit }}</code></div>{% endfor %}
{% for t in result.tags %}<div class="d-flex gap-2"><span class="tag">tag</span><strong>{{ t.name }}</strong><code style="font-size:.7rem;">{{ t.commit }}</code></div>{% endfor %}
</div>{% endif %}

{% if result.commits %}<div class="tool-panel mb-3"><h6 class="panel-title"><i class="bi bi-list-task me-2"></i>커밋 ({{ result.commits|length }})</h6>
<div style="max-height:400px; overflow-y:auto;">{% for c in result.commits %}
<div class="p-2 mb-1" style="background:var(--bg); border-radius:.35rem;">
<code style="color:var(--accent); font-size:.74rem;">{{ c.sha[:12] }}</code>
<span class="text-dim small ms-2">{{ c.author }}</span>
<div style="font-size:.82rem; margin-top:.2rem;">{{ c.message }}</div>
</div>{% endfor %}</div>
</div>{% endif %}

{% if result.logs %}<div class="tool-panel mb-3"><h6 class="panel-title"><i class="bi bi-journal me-2"></i>HEAD 활동 로그</h6>
<pre style="background:var(--bg); padding:.5rem; border-radius:.35rem; font-size:.72rem; max-height:300px; overflow:auto; margin:0;">{{ result.logs|join('\\n') }}</pre>
</div>{% endif %}

{% if result.deleted_blobs %}<div class="tool-panel mb-3" style="border-left:3px solid #f59e0b;">
<h6 class="panel-title text-warning"><i class="bi bi-trash me-2"></i>발견된 BLOB ({{ result.deleted_blobs|length }})</h6>
<div style="max-height:300px; overflow-y:auto;">{% for b in result.deleted_blobs %}
<div class="p-2 mb-1" style="background:var(--bg); border-radius:.35rem;">
<code style="color:var(--accent); font-size:.7rem;">{{ b.sha[:12] }}</code> <span class="text-dim small">{{ b.size }} B</span>
<div style="font-size:.78rem; font-family:monospace; margin-top:.2rem; word-break:break-all;">{{ b.preview }}</div>
</div>{% endfor %}</div>
</div>{% endif %}

{% if result.config %}<div class="tool-panel"><h6 class="panel-title">.git/config</h6>
<pre style="background:var(--bg); padding:.5rem; border-radius:.35rem; font-size:.74rem; max-height:300px; overflow:auto; margin:0;">{{ result.config }}</pre>
</div>{% endif %}
{% endif %}
</div>{% endblock %}
''', encoding='utf-8')

print('OK 20개 템플릿 생성 완료')
