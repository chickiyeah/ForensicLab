# -*- coding: utf-8 -*-
"""6차 확장 + 풀 도구 카탈로그 페이지"""
from pathlib import Path
T = Path(r'E:\forensic\templates\tools')

def hdr(t, s, i='bi-tools'):
    return f'''{{% extends 'base.html' %}}{{% block content %}}
<div class="page-hero"><div class="container">
<div class="d-flex align-items-center gap-3 mb-2"><a href="/" class="text-dim text-decoration-none small"><i class="bi bi-house me-1"></i>홈</a><i class="bi bi-chevron-right text-dim small"></i><a href="/tools" class="text-dim text-decoration-none small">분석 도구</a><i class="bi bi-chevron-right text-dim small"></i><span class="text-accent small">{t}</span></div>
<h1 class="page-title"><i class="bi {i} me-2 text-accent"></i>{t}</h1>
<p class="page-sub">{s}</p></div></div>'''

def w(n, c): (T/n).write_text(c, encoding='utf-8'); print(f'  OK {n}')

# 1. CASE 목록
w('case.html', hdr('사건 관리','사건 생성·증거 등록·발견사항 추적','bi-folder-fill') + '''
<div class="container pb-5">{% if error %}<div class="alert-error mb-3">{{ error }}</div>{% endif %}
<div class="row g-3"><div class="col-lg-4"><div class="tool-panel">
<h6 class="panel-title">새 사건</h6>
<form method="POST">
<input type="text" name="case_number" class="form-control mb-2" placeholder="사건번호 (자동 생성)">
<input type="text" name="name" class="form-control mb-2" placeholder="사건명" required>
<textarea name="description" class="form-control mb-2" rows="3" placeholder="설명"></textarea>
<input type="text" name="examiner" class="form-control mb-2" placeholder="분석가">
<select name="priority" class="form-select mb-3">
<option value="low">낮음</option><option value="medium" selected>중간</option>
<option value="high">높음</option><option value="critical">긴급</option></select>
<button class="btn btn-accent w-100"><i class="bi bi-plus me-1"></i>생성</button>
</form></div></div>
<div class="col-lg-8"><div class="tool-panel">
<h6 class="panel-title">사건 목록 ({{ cases|length }})</h6>
{% if cases %}<table class="table table-sm" style="font-size:.84rem;">
<thead><tr class="text-dim"><th>번호</th><th>이름</th><th>분석가</th><th>증거</th><th>발견</th><th>상태</th></tr></thead><tbody>
{% for c in cases %}<tr>
<td><a href="/tools/case/{{ c.id }}"><code>{{ c.case_number }}</code></a></td>
<td>{{ c.name }}</td><td>{{ c.examiner }}</td>
<td><strong>{{ c.evidence_count }}</strong></td>
<td><strong style="color:#f59e0b">{{ c.findings_count }}</strong></td>
<td><span class="tag" style="background:{% if c.status=='closed' %}rgba(107,114,128,.15);color:#9ca3af{% else %}rgba(34,197,94,.15);color:#22c55e{% endif %};">{{ c.status }}</span></td>
</tr>{% endfor %}</tbody></table>
{% else %}<div class="text-dim text-center p-4">사건 없음</div>{% endif %}
</div></div></div></div>{% endblock %}''')

# 2. CASE 상세
w('case_detail.html', hdr('사건 상세','증거·발견사항·메모 관리','bi-folder-fill') + '''
<div class="container pb-5">
<div class="tool-panel mb-3">
<div class="d-flex justify-content-between align-items-start flex-wrap">
<div><h6 class="panel-title mb-1">{{ case.case_number }} — {{ case.name }}</h6>
<div class="text-dim small">분석가: {{ case.examiner }} · 우선순위: {{ case.priority }} · 상태: {{ case.status }}</div>
<div class="text-dim small">생성: {{ case.created_at }}</div></div>
<div class="d-flex gap-2">
<a href="/tools/case/{{ case.id }}/report" class="btn btn-sm btn-accent"><i class="bi bi-file-earmark-pdf me-1"></i>PDF 보고서</a>
{% if case.status != 'closed' %}<form method="POST" style="display:inline;">
<input type="hidden" name="action" value="close">
<button class="btn btn-sm btn-outline-secondary">사건 종료</button></form>{% endif %}
</div></div>
{% if case.description %}<div class="mt-2">{{ case.description }}</div>{% endif %}</div>

<ul class="nav nav-tabs mb-3" style="border-color:var(--border);">
<li class="nav-item"><a class="nav-link active text-accent" data-bs-toggle="tab" href="#tab-ev">증거 ({{ evidence|length }})</a></li>
<li class="nav-item"><a class="nav-link text-dim" data-bs-toggle="tab" href="#tab-fd">발견사항 ({{ findings|length }})</a></li>
<li class="nav-item"><a class="nav-link text-dim" data-bs-toggle="tab" href="#tab-bm">북마크 ({{ bookmarks|length }})</a></li>
</ul>

<div class="tab-content">
<div class="tab-pane fade show active" id="tab-ev">
<div class="tool-panel mb-3"><form method="POST" enctype="multipart/form-data">
<input type="hidden" name="action" value="add_evidence">
<div class="row g-2"><div class="col-md-4"><input type="file" name="file" class="form-control" required></div>
<div class="col-md-3"><input type="text" name="tool" class="form-control" placeholder="사용 도구"></div>
<div class="col-md-3"><input type="text" name="tags" class="form-control" placeholder="태그 (쉼표)"></div>
<div class="col-md-2"><button class="btn btn-accent w-100">추가</button></div></div>
<textarea name="notes" class="form-control mt-2" rows="2" placeholder="메모"></textarea>
</form></div>
<div class="tool-panel"><table class="table table-sm" style="font-size:.78rem;">
<thead><tr class="text-dim"><th>파일</th><th>SHA-256</th><th>크기</th><th>도구</th><th>업로드</th><th>태그</th></tr></thead><tbody>
{% for e in evidence %}<tr><td><strong>{{ e.filename }}</strong></td>
<td><code style="font-size:.7rem;">{{ e.sha256[:16] }}…</code></td>
<td>{{ "{:,}".format(e.size) }}</td>
<td>{{ e.tool_used }}</td><td><code style="font-size:.7rem;">{{ e.uploaded_at[:19] }}</code></td>
<td>{{ e.tags }}</td></tr>{% endfor %}</tbody></table></div></div>

<div class="tab-pane fade" id="tab-fd">
<div class="tool-panel mb-3"><form method="POST">
<input type="hidden" name="action" value="add_finding">
<div class="row g-2 mb-2"><div class="col-md-2"><select name="severity" class="form-select">
<option value="low">낮음</option><option value="medium" selected>중간</option>
<option value="high">높음</option><option value="critical">긴급</option></select></div>
<div class="col-md-3"><input type="text" name="category" class="form-control" placeholder="카테고리"></div>
<div class="col-md-7"><input type="text" name="title" class="form-control" placeholder="제목" required></div></div>
<textarea name="description" class="form-control mb-2" rows="3" placeholder="상세 설명"></textarea>
<input type="text" name="attack_techniques" class="form-control mb-2" placeholder="MITRE ATT&CK (예: T1059, T1547)">
<button class="btn btn-accent">발견 추가</button></form></div>
{% for f in findings %}<div class="tool-panel mb-2" style="border-left:3px solid {% if f.severity=='critical' %}#dc2626{% elif f.severity=='high' %}#ef4444{% elif f.severity=='medium' %}#f59e0b{% else %}#3b82f6{% endif %};">
<div class="d-flex justify-content-between"><strong>{{ f.title }}</strong>
<span class="tag">{{ f.severity }}</span></div>
<div class="text-dim small">{{ f.category }} · {{ f.created_at[:19] }}</div>
<div class="mt-1">{{ f.description }}</div>
{% if f.attack_techniques %}<div class="mt-1 small">ATT&CK: <code>{{ f.attack_techniques }}</code></div>{% endif %}
</div>{% endfor %}</div>

<div class="tab-pane fade" id="tab-bm">
<div class="tool-panel mb-3"><form method="POST">
<input type="hidden" name="action" value="add_bookmark">
<input type="text" name="title" class="form-control mb-2" placeholder="북마크 제목" required>
<textarea name="content" class="form-control mb-2" rows="3"></textarea>
<input type="text" name="tags" class="form-control mb-2" placeholder="태그">
<button class="btn btn-accent">북마크 추가</button></form></div>
{% for b in bookmarks %}<div class="tool-panel mb-2">
<strong>{{ b.title }}</strong> <span class="text-dim small">{{ b.created_at[:19] }}</span>
<div class="mt-1">{{ b.content }}</div>
{% if b.tags %}<div class="mt-1">{% for t in b.tags.split(',') %}<span class="tag me-1">{{ t.strip() }}</span>{% endfor %}</div>{% endif %}
</div>{% endfor %}</div></div>
</div>{% endblock %}''')

# 3. SEARCH (검색)
w('search.html', hdr('전체 검색','사건·증거·발견·도구·OCR 통합 검색','bi-search') + '''
<div class="container pb-5">{% if error %}<div class="alert-error mb-3">{{ error }}</div>{% endif %}
<div class="row justify-content-center"><div class="col-lg-10"><div class="tool-panel mb-3">
<form method="POST"><div class="d-flex gap-2">
<input type="text" name="q" class="form-control" value="{{ q }}" placeholder="검색어 입력..." autofocus>
<button class="btn btn-accent"><i class="bi bi-search me-1"></i>검색</button>
</div></form></div>

{% if q %}
{% if cases %}<div class="tool-panel mb-2"><h6 class="panel-title">사건 ({{ cases|length }})</h6>
{% for c in cases %}<div class="d-flex gap-2 p-1" style="border-bottom:1px solid var(--border);">
<a href="/tools/case/{{ c.id }}"><code>{{ c.case_number }}</code></a>
<span>{{ c.name }}</span></div>{% endfor %}</div>{% endif %}

{% if findings %}<div class="tool-panel mb-2"><h6 class="panel-title">발견사항 ({{ findings|length }})</h6>
{% for f in findings %}<div class="d-flex gap-2 p-1" style="border-bottom:1px solid var(--border);">
<a href="/tools/case/{{ f.case_id }}">{{ f.title }}</a>
<span class="tag">{{ f.severity }}</span></div>{% endfor %}</div>{% endif %}

{% if results %}<div class="tool-panel"><h6 class="panel-title">증거·노트 ({{ results|length }})</h6>
{% for r in results %}<div class="p-2 mb-1" style="background:var(--bg); border-radius:.3rem;">
<div><code>{{ r.case_number }}</code> <strong>{{ r.evidence_filename }}</strong></div>
<div class="small mt-1">{{ r.snip | safe }}</div>
{% if r.tags %}<div class="mt-1">{% for t in r.tags.split(',') %}<span class="tag me-1">{{ t.strip() }}</span>{% endfor %}</div>{% endif %}
</div>{% endfor %}</div>{% endif %}

{% if not cases and not findings and not results %}<div class="text-dim text-center p-4">결과 없음</div>{% endif %}
{% endif %}
</div></div></div>{% endblock %}''')

# 4. DASHBOARD
w('dashboard.html', hdr('분석 대시보드','전체 사건·증거·발견 통계 시각화','bi-speedometer2') + '''
<div class="container pb-5">
<div class="row g-3 mb-3">
<div class="col-md-2"><div class="tool-panel text-center" style="padding:1rem;">
<div style="font-size:2rem; color:var(--accent); font-weight:700;">{{ stats.total_cases }}</div>
<div class="text-dim small">전체 사건</div></div></div>
<div class="col-md-2"><div class="tool-panel text-center" style="padding:1rem;">
<div style="font-size:2rem; color:#22c55e; font-weight:700;">{{ stats.open_cases }}</div>
<div class="text-dim small">진행중</div></div></div>
<div class="col-md-2"><div class="tool-panel text-center" style="padding:1rem;">
<div style="font-size:2rem; color:#6b7280; font-weight:700;">{{ stats.closed_cases }}</div>
<div class="text-dim small">종료</div></div></div>
<div class="col-md-2"><div class="tool-panel text-center" style="padding:1rem;">
<div style="font-size:2rem; color:#a78bfa; font-weight:700;">{{ stats.total_evidence }}</div>
<div class="text-dim small">증거</div></div></div>
<div class="col-md-2"><div class="tool-panel text-center" style="padding:1rem;">
<div style="font-size:2rem; color:#f59e0b; font-weight:700;">{{ stats.total_findings }}</div>
<div class="text-dim small">발견사항</div></div></div>
<div class="col-md-2"><div class="tool-panel text-center" style="padding:1rem;">
<div style="font-size:2rem; color:#06b6d4; font-weight:700;">{{ stats.total_audit }}</div>
<div class="text-dim small">감사 로그</div></div></div>
</div>

<div class="row g-3 mb-3">
<div class="col-md-6"><div class="tool-panel">
<h6 class="panel-title">심각도별 발견사항</h6>
{% for sev in ['critical','high','medium','low'] %}{% if severity.get(sev) %}
<div class="d-flex justify-content-between mb-1">
<span style="color:{% if sev=='critical' %}#dc2626{% elif sev=='high' %}#ef4444{% elif sev=='medium' %}#f59e0b{% else %}#3b82f6{% endif %};">{{ sev }}</span>
<strong>{{ severity.get(sev, 0) }}</strong></div>{% endif %}{% endfor %}
</div></div>
<div class="col-md-6"><div class="tool-panel">
<h6 class="panel-title">도구 사용 횟수</h6>
{% for t, c in tool_usage.items() %}<div class="d-flex justify-content-between mb-1 small">
<code style="font-size:.74rem;">{{ t.replace('tool_use:','') }}</code><strong>{{ c }}</strong></div>{% endfor %}
{% if not tool_usage %}<div class="text-dim small">아직 활동 없음</div>{% endif %}
</div></div></div>

<div class="row g-3">
<div class="col-md-6"><div class="tool-panel"><h6 class="panel-title">최근 사건</h6>
{% for c in recent_cases %}<div class="d-flex justify-content-between p-1 small">
<a href="/tools/case/{{ c.id }}" style="font-size:.84rem;"><code>{{ c.case_number }}</code> {{ c.name }}</a>
<span class="text-dim">{{ c.created_at[:10] }}</span></div>{% endfor %}
</div></div>
<div class="col-md-6"><div class="tool-panel"><h6 class="panel-title">최근 발견</h6>
{% for f in recent_findings %}<div class="d-flex justify-content-between p-1 small">
<a href="/tools/case/{{ f.case_id }}" style="font-size:.84rem;">[{{ f.case_number }}] {{ f.title }}</a>
<span class="tag" style="font-size:.7rem;">{{ f.severity }}</span></div>{% endfor %}
</div></div></div>

</div>{% endblock %}''')

# 5. ATT&CK
w('attack.html', hdr('MITRE ATT&CK 매핑','분석 결과 → ATT&CK 기법 자동 매핑','bi-bullseye') + '''
<div class="container pb-5">{% if error %}<div class="alert-error mb-3">{{ error }}</div>{% endif %}
<div class="row g-3"><div class="col-lg-5"><div class="tool-panel">
<form method="POST">
<label class="form-label-sm">분석 결과 (로그·텍스트)</label>
<textarea name="text" class="form-control mb-3" rows="14" style="font-family:monospace; font-size:.74rem;" placeholder="powershell -enc ...&#10;reg add HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run..."></textarea>
<button class="btn btn-accent w-100"><i class="bi bi-bullseye me-1"></i>매핑</button>
</form><div class="text-dim small mt-2">DB: {{ db_size }}개 기법</div></div></div>

<div class="col-lg-7">{% if result %}
<div class="tool-panel mb-2"><h6 class="panel-title">탐지된 기법 ({{ result.total_techniques }})</h6>
<div class="d-flex flex-wrap gap-2 mb-2">
{% for tactic, count in result.tactics.items() %}
<span class="tag" style="background:rgba(239,68,68,.15);color:#ef4444;">{{ tactic }} ({{ count }})</span>
{% endfor %}</div>
{% if result.killchain_stage %}<div><strong>주요 단계:</strong> {{ result.killchain_stage }}</div>{% endif %}
</div>

{% for m in result.matches %}<div class="tool-panel mb-2">
<div class="d-flex justify-content-between"><div>
<strong style="color:var(--accent);">{{ m.id }}</strong> {{ m.name }}</div>
<a href="{{ m.url }}" target="_blank"><span class="tag">{{ m.tactic }}</span></a></div>
<p class="text-dim small mb-1">{{ m.description }}</p>
<div class="small"><strong>키워드:</strong>
{% for k in m.matched_keywords %}<code class="me-1">{{ k }}</code>{% endfor %}</div>
</div>{% endfor %}
{% endif %}</div></div></div>{% endblock %}''')

# 6. Threat Intel
w('threat_intel.html', hdr('위협 인텔리전스','VirusTotal·AbuseIPDB IoC 조회','bi-radar') + '''
<div class="container pb-5">{% if error %}<div class="alert-error mb-3">{{ error }}</div>{% endif %}
<div class="row g-3"><div class="col-lg-5"><div class="tool-panel"><form method="POST">
<label class="form-label-sm">IOC (IP / 해시 / 도메인)</label>
<input type="text" name="ioc" class="form-control mb-3" required>
<label class="form-label-sm">VirusTotal API 키 (선택)</label>
<input type="password" name="vt_key" class="form-control mb-3">
<label class="form-label-sm">AbuseIPDB API 키 (선택)</label>
<input type="password" name="abuseip_key" class="form-control mb-3">
<button class="btn btn-accent w-100"><i class="bi bi-radar me-1"></i>조회</button>
</form></div></div>
<div class="col-lg-7">{% if result %}
<div class="tool-panel mb-2"><strong>IOC:</strong> <code>{{ result.ioc }}</code>
<span class="tag ms-2">{{ result.ioc_type }}</span></div>
{% for src, data in result.sources.items() %}
<div class="tool-panel mb-2"><h6 class="panel-title">{{ src }}</h6>
{% if data.error %}<div class="text-danger">{{ data.error }}</div>
{% else %}<table class="table table-sm" style="font-size:.84rem;">
{% for k, v in data.items() %}<tr><td class="text-dim">{{ k }}</td>
<td>{% if v is iterable and v is not string %}{% for x in v %}<code class="me-1">{{ x }}</code>{% endfor %}{% else %}<code>{{ v }}</code>{% endif %}</td></tr>{% endfor %}
</table>{% endif %}</div>{% endfor %}
{% endif %}</div></div></div>{% endblock %}''')

# 7. AI 분류
w('ai_classify.html', hdr('AI 자동 분류','시그니처·OpenCV·얼굴감지·키워드 종합 분류','bi-robot') + '''
<div class="container pb-5">{% if error %}<div class="alert-error mb-3">{{ error }}</div>{% endif %}
{% if not result %}<div class="row justify-content-center"><div class="col-lg-6"><div class="tool-panel"><form method="POST" enctype="multipart/form-data">
<input type="file" name="file" class="form-control mb-3" required>
<button class="btn btn-accent w-100"><i class="bi bi-robot me-1"></i>분류</button>
</form></div></div></div>
{% else %}<div class="tool-panel"><h6 class="panel-title">{{ result.filename }}</h6>
<table class="table table-sm" style="font-size:.84rem;">
{% for k, v in result.items() %}{% if k not in ('filename','tags','categories','faces') %}
{% if not (v is mapping or v is iterable and v is not string) %}
<tr><td class="text-dim">{{ k }}</td><td><code>{{ v }}</code></td></tr>{% endif %}{% endif %}{% endfor %}
{% if result.categories %}{% for k, v in result.categories.items() %}
<tr><td class="text-dim">{{ k }}</td><td><strong>{{ v }}</strong></td></tr>{% endfor %}{% endif %}
</table>
{% if result.tags %}<div class="mt-2"><strong>태그:</strong> {% for t in result.tags %}<span class="tag me-1">{{ t }}</span>{% endfor %}</div>{% endif %}
</div>{% endif %}</div>{% endblock %}''')

# 8. Plaso
w('plaso.html', hdr('Plaso 슈퍼 타임라인','log2timeline.py + psort.py 자동 통합','bi-stack') + '''
<div class="container pb-5">{% if error %}<div class="alert-error mb-3">{{ error }}</div>{% endif %}
{% if not result %}<div class="row justify-content-center"><div class="col-lg-6"><div class="tool-panel"><form method="POST" enctype="multipart/form-data">
<input type="file" name="file" class="form-control mb-3" required>
<div class="form-hint mb-3">디스크 이미지·아티팩트 파일 → Plaso super timeline</div>
<button class="btn btn-accent w-100"><i class="bi bi-stack me-1"></i>백그라운드 실행</button>
</form></div></div></div>
{% else %}<div class="alert alert-success">백그라운드 작업: <a href="{{ result.redirect }}">{{ result.job_id }}</a></div>
<script>setTimeout(()=>location.href='{{ result.redirect }}', 1500);</script>{% endif %}
</div>{% endblock %}''')

# 9. OCR 인덱싱
w('ocr_index.html', hdr('OCR 인덱싱·검색','이미지·PDF → 텍스트 추출 + 풀텍스트 검색','bi-search') + '''
<div class="container pb-5">{% if error %}<div class="alert-error mb-3">{{ error }}</div>{% endif %}
<div class="row g-3"><div class="col-lg-5">
<div class="tool-panel mb-2"><h6 class="panel-title">이미지/PDF 인덱싱</h6>
<form method="POST" enctype="multipart/form-data">
<input type="file" name="file" multiple class="form-control mb-2" required>
<select name="lang" class="form-select mb-3">
<option value="eng+kor" selected>영어+한국어</option>
<option value="kor">한국어</option><option value="eng">영어</option>
<option value="jpn">일본어</option><option value="chi_sim">중국어</option></select>
<button class="btn btn-accent w-100">인덱스 추가</button></form>
<div class="text-dim small mt-2">DB: {{ db_size }}개 인덱싱됨</div></div>
<div class="tool-panel"><h6 class="panel-title">검색</h6>
<form method="GET"><div class="d-flex gap-2">
<input type="text" name="q" class="form-control" value="{{ q }}" placeholder="키워드 검색">
<button class="btn btn-accent">검색</button></div></form></div></div>
<div class="col-lg-7">{% if result %}
{% if result.mode == 'indexed' %}<div class="tool-panel">
<h6 class="panel-title">인덱싱 완료 ({{ result.files|length }})</h6>
{% for f in result.files %}<div class="p-2 mb-1" style="background:var(--bg); border-radius:.3rem;">
<strong>{{ f.filename }}</strong> <span class="text-dim small">{{ f.text_len }}자</span>
{% if f.preview %}<div class="small mt-1">{{ f.preview }}</div>{% endif %}
{% if f.error %}<div class="text-danger small">{{ f.error }}</div>{% endif %}
</div>{% endfor %}</div>
{% elif result.mode == 'search' %}<div class="tool-panel">
<h6 class="panel-title">'{{ result.query }}' — {{ result.results|length }}건</h6>
{% for r in result.results %}<div class="p-2 mb-1" style="background:var(--bg); border-radius:.3rem;">
<strong>{{ r.filename }}</strong>
<div class="small mt-1">{{ r.snip | safe }}</div></div>{% endfor %}
</div>{% endif %}{% endif %}</div></div></div>{% endblock %}''')

# 10. Face/객체 인식
w('face.html', hdr('얼굴·객체 인식','OpenCV Haar Cascade 얼굴/눈 감지','bi-person-bounding-box') + '''
<div class="container pb-5">{% if error %}<div class="alert-error mb-3">{{ error }}</div>{% endif %}
{% if not result %}<div class="row justify-content-center"><div class="col-lg-6"><div class="tool-panel"><form method="POST" enctype="multipart/form-data">
<input type="file" name="file" multiple class="form-control mb-3" accept="image/*" required>
<button class="btn btn-accent w-100"><i class="bi bi-person me-1"></i>얼굴 감지</button>
</form></div></div></div>
{% else %}{% for r in result.files %}<div class="tool-panel mb-3">
<h6 class="panel-title">{{ r.filename }}</h6>
{% if r.error %}<div class="text-danger">{{ r.error }}</div>
{% else %}<div class="text-dim small">{{ r.image_size }} · 선명도 {{ r.sharpness }}{% if r.is_blurry %} (흐림){% endif %}</div>
<div class="mt-2"><strong>{{ r.face_count }}개 얼굴 감지</strong></div>
{% if r.faces %}<table class="table table-sm mt-2" style="font-size:.78rem;">
<thead><tr class="text-dim"><th>#</th><th>위치 (x,y)</th><th>크기</th><th>눈 감지</th><th>이미지 점유율</th></tr></thead><tbody>
{% for face in r.faces %}<tr><td>{{ loop.index }}</td>
<td>({{ face.x }}, {{ face.y }})</td>
<td>{{ face.w }}x{{ face.h }}</td>
<td>{{ face.eyes }}</td>
<td>{{ face.pct_of_image }}%</td></tr>{% endfor %}
</tbody></table>{% endif %}
{% endif %}</div>{% endfor %}{% endif %}</div>{% endblock %}''')

# ====================================================================
# /tools 풀 도구 카탈로그 (검색 기능 포함)
# ====================================================================
INDEX_HTML = '''{% extends 'base.html' %}{% block content %}
<div class="page-hero"><div class="container">
<h1 class="page-title"><i class="bi bi-cpu me-2"></i>분석 도구 카탈로그</h1>
<p class="page-sub">디지털 포렌식 분석에 필요한 모든 도구를 한 곳에서. 우상단 검색 박스로 빠르게 찾을 수 있습니다.</p>
</div></div>

<div class="container pb-5">

<!-- 검색 박스 -->
<div class="tool-panel mb-3" style="position:sticky; top:60px; z-index:10; background:var(--bg-card);">
<div class="d-flex gap-2 align-items-center">
<div class="position-relative flex-grow-1">
<i class="bi bi-search position-absolute" style="left:.8rem; top:50%; transform:translateY(-50%); color:var(--text-dim);"></i>
<input type="text" id="toolSearch" class="form-control" placeholder="도구 검색... (예: hash, MFT, JWT, 모바일, 메모리)" style="padding-left:2.3rem;" autofocus>
</div>
<button class="btn btn-outline-secondary btn-sm" onclick="document.getElementById('toolSearch').value='';doFilter();"><i class="bi bi-x"></i></button>
<span class="text-dim small ms-2" id="resultCount"></span>
</div>
<div class="mt-2 d-flex flex-wrap gap-1" id="catFilter">
<button class="btn btn-sm btn-accent" data-cat="all" onclick="setCat('all')">전체</button>
{% set cats = tools | groupby('cat') %}
{% for cat, items in cats %}<button class="btn btn-sm btn-outline-secondary" data-cat="{{ cat }}" onclick="setCat('{{ cat }}')">{{ cat }} ({{ items|length }})</button>{% endfor %}
</div>
</div>

<div class="row g-2" id="toolGrid">
{% for t in tools %}
<div class="col-md-6 col-lg-4 col-xl-3 tool-item" data-name="{{ t.name|lower }} {{ t.desc|lower }} {{ t.keywords|lower }}" data-cat="{{ t.cat }}">
<a href="{{ t.url }}" class="tool-card-link">
<div class="tool-card h-100" style="border-left:3px solid {{ t.color }};">
<div class="d-flex align-items-center gap-2 mb-1">
<i class="bi {{ t.icon }}" style="font-size:1.2rem; color:{{ t.color }};"></i>
<strong style="font-size:.85rem;">{{ t.name }}</strong>
{% if t.pro %}<span class="badge bg-warning text-dark ms-auto" style="font-size:.55rem;">PRO</span>{% endif %}
</div>
<p class="text-dim mb-1" style="font-size:.74rem; line-height:1.35;">{{ t.desc }}</p>
<div class="d-flex justify-content-between" style="font-size:.7rem;">
<span class="text-dim">{{ t.cat }}</span>
<code class="text-accent">/tools/{{ t.url.split('/tools/')[-1] }}</code>
</div></div></a></div>
{% endfor %}
</div>

</div>

<script>
function doFilter() {
  const q = document.getElementById('toolSearch').value.toLowerCase().trim();
  const cat = document.querySelector('#catFilter .btn-accent')?.dataset?.cat || 'all';
  let vis = 0;
  document.querySelectorAll('.tool-item').forEach(el => {
    const okq = !q || el.dataset.name.includes(q);
    const okc = cat === 'all' || el.dataset.cat === cat;
    el.style.display = okq && okc ? '' : 'none';
    if (okq && okc) vis++;
  });
  document.getElementById('resultCount').textContent = vis + ' / {{ tools|length }}개';
}
function setCat(cat) {
  document.querySelectorAll('#catFilter .btn').forEach(b => {
    b.classList.remove('btn-accent');
    b.classList.add('btn-outline-secondary');
    if (b.dataset.cat === cat) {
      b.classList.add('btn-accent');
      b.classList.remove('btn-outline-secondary');
    }
  });
  doFilter();
}
document.getElementById('toolSearch').addEventListener('input', doFilter);
doFilter();
</script>
{% endblock %}'''

(T / 'index.html').write_text(INDEX_HTML, encoding='utf-8')
print('  OK index.html (풀 카탈로그)')

print('=== 11개 템플릿 생성 완료 (10 + 카탈로그) ===')
