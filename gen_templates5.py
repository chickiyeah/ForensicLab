# -*- coding: utf-8 -*-
"""5차 확장 9개 템플릿"""
from pathlib import Path
T = Path(r'E:\forensic\templates\tools')

def hdr(t, s, i='bi-tools'):
    return f'''{{% extends 'base.html' %}}{{% block content %}}
<div class="page-hero"><div class="container">
<div class="d-flex align-items-center gap-3 mb-2"><a href="/" class="text-dim text-decoration-none small"><i class="bi bi-house me-1"></i>홈</a><i class="bi bi-chevron-right text-dim small"></i><a href="/tools" class="text-dim text-decoration-none small">분석 도구</a><i class="bi bi-chevron-right text-dim small"></i><span class="text-accent small">{t}</span></div>
<h1 class="page-title"><i class="bi {i} me-2 text-accent"></i>{t}</h1>
<p class="page-sub">{s}</p></div></div>'''

def w(n, c): (T/n).write_text(c, encoding='utf-8'); print(f'  OK {n}')

# 1. JOBS 리스트
w('jobs.html', hdr('백그라운드 작업','Volatility/ALEAPP/Hashcat 등 대용량 작업 큐','bi-cpu') + '''
<div class="container pb-5"><div class="tool-panel">
<h6 class="panel-title">작업 ({{ jobs|length }})</h6>
{% if jobs %}<table class="table table-sm" style="font-size:.82rem;">
<thead><tr class="text-dim"><th>ID</th><th>이름</th><th>상태</th><th>진행</th><th>시작</th><th>종료</th></tr></thead><tbody>
{% for j in jobs %}<tr>
<td><a href="/tools/jobs/{{ j.id }}"><code>{{ j.id[:12] }}</code></a></td>
<td>{{ j.name }}</td>
<td><span class="tag" style="background:{% if j.status == 'completed' %}rgba(34,197,94,.15);color:#22c55e{% elif j.status == 'running' %}rgba(0,212,255,.15);color:#00d4ff{% elif j.status == 'failed' %}rgba(239,68,68,.15);color:#ef4444{% else %}rgba(107,114,128,.15);color:#9ca3af{% endif %};">{{ j.status }}</span></td>
<td><div style="background:var(--bg); height:.4rem; border-radius:.2rem; overflow:hidden; width:100px;"><div style="background:var(--accent); height:100%; width:{{ j.progress }}%;"></div></div></td>
<td><code style="font-size:.7rem;">{{ j.started[:19] if j.started else '' }}</code></td>
<td><code style="font-size:.7rem;">{{ j.finished[:19] if j.finished else '' }}</code></td>
</tr>{% endfor %}</tbody></table>
{% else %}<div class="text-dim text-center p-5">아직 작업이 없습니다.</div>{% endif %}
</div></div>{% endblock %}''')

# 2. JOB DETAIL
w('job_detail.html', hdr('작업 상세','백그라운드 작업 결과·로그','bi-list-task') + '''
<div class="container pb-5">
<div class="tool-panel mb-3"><div class="d-flex justify-content-between align-items-center">
<div><h6 class="panel-title mb-1">{{ job.name }}</h6>
<code class="text-dim small">{{ job.id }}</code></div>
<div><span class="tag" style="background:{% if job.status == 'completed' %}rgba(34,197,94,.15);color:#22c55e{% elif job.status == 'running' %}rgba(0,212,255,.15);color:#00d4ff{% elif job.status == 'failed' %}rgba(239,68,68,.15);color:#ef4444{% else %}rgba(107,114,128,.15);color:#9ca3af{% endif %}; font-size:.9rem;">{{ job.status }}</span></div></div>
<div class="mt-2" style="background:var(--bg); height:.5rem; border-radius:.25rem; overflow:hidden;">
<div style="background:var(--accent); height:100%; width:{{ job.progress }}%; transition:width .3s;"></div></div>
<div class="d-flex justify-content-between text-dim small mt-1">
<span>시작: {{ job.started or '-' }}</span><span>종료: {{ job.finished or '진행 중' }}</span></div></div>

{% if job.log %}<div class="tool-panel mb-3"><h6 class="panel-title">로그 ({{ job.log|length }})</h6>
<div style="max-height:300px; overflow-y:auto; font-family:monospace; font-size:.74rem;">
{% for l in job.log %}<div><span class="text-dim">{{ l.time[:19] }}</span> {{ l.msg }}</div>{% endfor %}
</div></div>{% endif %}

{% if job.result %}<div class="tool-panel"><h6 class="panel-title">결과</h6>
<pre style="background:var(--bg); padding:.6rem; font-size:.74rem; max-height:600px; overflow:auto;">{{ job.result | tojson(indent=2) }}</pre>
</div>{% endif %}

{% if job.status == 'running' or job.status == 'pending' %}
<script>setTimeout(()=>location.reload(), 5000);</script>{% endif %}
</div>{% endblock %}''')

# 3. CoC
w('coc.html', hdr('Chain of Custody','변조 불가 증거 보관 체인 — SHA-256 해시 사슬','bi-link-45deg') + '''
<div class="container pb-5">
<div class="tool-panel mb-3" style="border:2px solid {% if verification.valid %}#22c55e{% else %}#ef4444{% endif %};">
<div class="d-flex justify-content-between align-items-center">
<div><h6 class="panel-title mb-1">체인 검증</h6>
<span style="font-size:.9rem;">{% if verification.valid %}<i class="bi bi-check-circle-fill text-success"></i> 무결성 확인됨{% else %}<i class="bi bi-x-circle-fill text-danger"></i> 변조 감지!{% endif %}</span></div>
<div class="text-end"><strong style="font-size:1.5rem;">{{ verification.entries }}</strong>
<div class="text-dim small">엔트리</div></div></div>
{% if verification.first %}<div class="text-dim small mt-2">최초 {{ verification.first }} · 최후 {{ verification.last }}</div>{% endif %}
{% if verification.invalid %}<div class="mt-2 text-danger">
{% for i in verification.invalid %}<div>엔트리 #{{ i.idx }}: {{ i.reason }}</div>{% endfor %}</div>{% endif %}
</div>

<div class="tool-panel mb-3"><h6 class="panel-title">증거 등록</h6>
<form method="POST" enctype="multipart/form-data" action="/tools/coc/add" onsubmit="return false;" id="cocForm">
<input type="file" name="file" class="form-control mb-2" id="cocFile" required>
<select name="action" class="form-select mb-2">
<option value="evidence_intake">증거 접수 (Intake)</option>
<option value="custody_transfer">보관자 이관</option>
<option value="analysis_started">분석 시작</option>
<option value="analysis_completed">분석 완료</option>
<option value="evidence_release">증거 반환</option>
</select>
<input type="text" name="note" class="form-control mb-2" placeholder="메모 (선택)">
<button class="btn btn-accent w-100" onclick="submitCoc()"><i class="bi bi-plus me-1"></i>체인에 추가</button>
</form>
<div id="cocResult" class="mt-2"></div></div>

<div class="tool-panel"><div class="d-flex justify-content-between mb-2">
<h6 class="panel-title">최근 엔트리 ({{ entries|length }})</h6>
<a href="/tools/coc/download" class="btn btn-sm btn-outline-secondary"><i class="bi bi-download me-1"></i>JSONL 다운로드</a></div>
<div style="max-height:600px; overflow-y:auto;">
{% for e in entries %}<details class="mb-1" style="background:var(--bg); border-radius:.35rem;">
<summary style="padding:.4rem .6rem; cursor:pointer; font-size:.82rem;">
<code class="text-dim small">{{ e.timestamp[:19] }}</code>
<strong>{{ e.action }}</strong>
<span class="text-dim small">{{ e.metadata.get('filename', '') }}</span></summary>
<pre style="background:#0a0f1c; padding:.5rem; margin:0; font-size:.7rem;">{{ e | tojson(indent=2) }}</pre>
</details>{% endfor %}</div></div>

<script>
async function submitCoc() {
  const fd = new FormData(document.getElementById('cocForm'));
  if (!document.getElementById('cocFile').files.length) { alert('파일 선택'); return; }
  const r = await fetch('/tools/coc/add', { method: 'POST', body: fd });
  const j = await r.json();
  document.getElementById('cocResult').innerHTML =
    '<div class="alert alert-success">엔트리 추가됨: ' + j.entry.hash.substr(0,16) + '...</div>';
  setTimeout(()=>location.reload(), 2000);
}
</script>
</div>{% endblock %}''')

# 4. VOL FULL
w('vol_full.html', hdr('Volatility 3 풀 분석','메모리 덤프 → pslist·malfind·netscan·hivelist 등 23개 플러그인','bi-cpu-fill') + '''
<div class="container pb-5">{% if error %}<div class="alert-error mb-3">{{ error }}</div>{% endif %}
{% if not result %}<div class="row justify-content-center"><div class="col-lg-8">
<div class="tool-panel"><form method="POST" enctype="multipart/form-data">
<input type="file" name="file" class="form-control mb-3" required>
<label class="form-label-sm">실행할 플러그인 (다중 선택)</label>
<div class="row" style="max-height:400px; overflow-y:auto;">
{% for p, short, desc in plugins %}<div class="col-md-6 mb-1">
<label style="font-size:.82rem;"><input type="checkbox" name="plugins" value="{{ p }}"
{% if short in ('pslist','malfind','netscan','cmdline') %}checked{% endif %}>
<strong>{{ short }}</strong> <span class="text-dim small">{{ desc }}</span></label>
</div>{% endfor %}</div>
<button class="btn btn-accent w-100 mt-3"><i class="bi bi-play me-1"></i>백그라운드 실행</button>
</form><div class="text-dim small mt-2"><i class="bi bi-info-circle me-1"></i>
대용량 메모리 덤프는 시간이 오래 걸립니다. 백그라운드 작업으로 처리됩니다.</div>
</div></div></div>
{% else %}
<div class="alert alert-success">작업 시작됨: <a href="{{ result.redirect }}">{{ result.job_id }}</a></div>
<script>setTimeout(()=>location.href='{{ result.redirect }}', 1500);</script>
{% endif %}</div>{% endblock %}''')

# 5. LLM REPORT
w('llm_report.html', hdr('LLM 자동 보고서','Claude API로 분석 결과 → 전문가 narrative 보고서','bi-robot') + '''
<div class="container pb-5">{% if error %}<div class="alert-error mb-3">{{ error }}</div>{% endif %}
<div class="row g-3"><div class="col-lg-5"><div class="tool-panel">
<form method="POST"><label class="form-label-sm">Anthropic API 키 (또는 환경변수 ANTHROPIC_API_KEY)</label>
<input type="password" name="api_key" class="form-control mb-2" placeholder="sk-ant-...">
<label class="form-label-sm">분석 컨텍스트</label>
<input type="text" name="context" class="form-control mb-2" value="디지털 포렌식 분석">
<label class="form-label-sm">언어</label>
<select name="language" class="form-select mb-2">
<option value="한국어">한국어</option><option value="English">English</option>
<option value="日本語">日本語</option><option value="中文">中文</option></select>
<label class="form-label-sm">분석 데이터 (JSON / 텍스트)</label>
<textarea name="analysis_data" class="form-control mb-3" rows="14" style="font-family:monospace; font-size:.72rem;" placeholder="포렌식 분석 결과 붙여넣기..." required></textarea>
<button class="btn btn-accent w-100"><i class="bi bi-robot me-1"></i>보고서 생성</button>
</form><div class="text-dim small mt-2">Claude API 사용. 비용: 입력 토큰당 ~$3/M, 출력 ~$15/M</div>
</div></div>
<div class="col-lg-7">{% if result %}<div class="tool-panel">
<h6 class="panel-title">{{ result.model }} 생성 보고서 ({{ result.language }})</h6>
<div class="text-dim small mb-2">입력 {{ result.tokens_in }}T · 출력 {{ result.tokens_out }}T</div>
<div style="background:var(--bg); padding:1rem; border-radius:.4rem; max-height:700px; overflow-y:auto; white-space:pre-wrap; font-size:.86rem; line-height:1.6;">{{ result.report }}</div>
<div class="mt-2"><button class="btn btn-sm btn-outline-secondary" onclick="navigator.clipboard.writeText(document.querySelector('div[style*=overflow-y]').innerText)"><i class="bi bi-clipboard me-1"></i>복사</button></div>
</div>{% endif %}</div></div></div>{% endblock %}''')

# 6. HASHCAT
w('hashcat_job.html', hdr('Hashcat 통합','오프라인 해시 크래킹 (MD5·SHA·NTLM·ZIP·Office·BitLocker 등 30+ 모드)','bi-shield-lock') + '''
<div class="container pb-5">{% if error %}<div class="alert-error mb-3">{{ error }}</div>{% endif %}
{% if not result %}<div class="row justify-content-center"><div class="col-lg-8"><div class="tool-panel">
<form method="POST">
<label class="form-label-sm">해시 모드</label>
<select name="mode" class="form-select mb-3">
{% for m, name in modes.items() %}<option value="{{ m }}">{{ m }}: {{ name }}</option>{% endfor %}
</select>
<label class="form-label-sm">공격 모드</label>
<select name="attack_mode" class="form-select mb-3">
<option value="0">0: Straight (사전 공격)</option>
<option value="3">3: Mask (무차별)</option>
<option value="6">6: Hybrid (사전+마스크)</option>
</select>
<label class="form-label-sm">해시 (한 줄에 하나)</label>
<textarea name="hashes" class="form-control mb-3" rows="5" style="font-family:monospace; font-size:.74rem;" required></textarea>
<label class="form-label-sm">사전 / 마스크</label>
<textarea name="wordlist" class="form-control mb-3" rows="8" style="font-family:monospace; font-size:.74rem;" placeholder="password&#10;admin&#10;123456&#10;...&#10;또는 마스크: ?u?l?l?l?l?d?d" required></textarea>
<button class="btn btn-accent w-100"><i class="bi bi-shield-lock me-1"></i>크래킹 시작</button>
</form><div class="text-dim small mt-2"><i class="bi bi-info-circle me-1"></i>
서버 CPU 모드로 실행 (GPU 없음). 30분 타임아웃.</div>
</div></div></div>
{% else %}<div class="alert alert-success">백그라운드 작업: <a href="{{ result.redirect }}">{{ result.job_id }}</a></div>
<script>setTimeout(()=>location.href='{{ result.redirect }}', 1500);</script>{% endif %}
</div>{% endblock %}''')

# 7. ALEAPP
w('aleapp.html', hdr('ALEAPP (Android 풀 분석)','Android 추출 ZIP → 200+ 아티팩트 자동 파싱 (Sysdiagnose 수준)','bi-android2') + '''
<div class="container pb-5">{% if error %}<div class="alert-error mb-3">{{ error }}</div>{% endif %}
{% if not result %}<div class="row justify-content-center"><div class="col-lg-6"><div class="tool-panel">
<form method="POST" enctype="multipart/form-data">
<input type="file" name="file" class="form-control mb-3" accept=".zip,.tar" required>
<div class="form-hint mb-3">Android 추출 ZIP/TAR (Magnet/Cellebrite/MSAB 또는 adb backup)</div>
<button class="btn btn-accent w-100"><i class="bi bi-android2 me-1"></i>ALEAPP 실행</button>
</form><div class="text-dim small mt-2">ALEAPP은 200+ 아티팩트 추출. 20분 이상 소요될 수 있음.</div>
</div></div></div>
{% else %}<div class="alert alert-success">백그라운드: <a href="{{ result.redirect }}">{{ result.job_id }}</a></div>
<script>setTimeout(()=>location.href='{{ result.redirect }}', 1500);</script>{% endif %}
</div>{% endblock %}''')

# 8. iLEAPP
w('ileapp.html', hdr('iLEAPP (iOS 풀 분석)','iOS 백업/추출 → 300+ 아티팩트 자동 파싱 (Cellebrite UFED 대안)','bi-phone') + '''
<div class="container pb-5">{% if error %}<div class="alert-error mb-3">{{ error }}</div>{% endif %}
{% if not result %}<div class="row justify-content-center"><div class="col-lg-6"><div class="tool-panel">
<form method="POST" enctype="multipart/form-data">
<input type="file" name="file" class="form-control mb-3" accept=".zip,.tar" required>
<div class="form-hint mb-3">iOS 백업 ZIP (Manifest.db 포함) 또는 GrayKey/Cellebrite 추출</div>
<button class="btn btn-accent w-100"><i class="bi bi-phone me-1"></i>iLEAPP 실행</button>
</form></div></div></div>
{% else %}<div class="alert alert-success">백그라운드: <a href="{{ result.redirect }}">{{ result.job_id }}</a></div>
<script>setTimeout(()=>location.href='{{ result.redirect }}', 1500);</script>{% endif %}
</div>{% endblock %}''')

# 9. E01 MOUNT
w('e01_mount.html', hdr('E01 / EnCase 이미지','libewf로 E01·Ex01 이미지 메타데이터·해시·세그먼트 분석','bi-hdd-rack-fill') + '''
<div class="container pb-5">{% if error %}<div class="alert-error mb-3">{{ error }}</div>{% endif %}
{% if not result %}<div class="row justify-content-center"><div class="col-lg-6"><div class="tool-panel">
<form method="POST" enctype="multipart/form-data">
<input type="file" name="file" class="form-control mb-3" accept=".E01,.Ex01,.S01" required>
<button class="btn btn-accent w-100">분석</button>
</form></div></div></div>
{% else %}<div class="tool-panel">
<h6 class="panel-title">{{ result.filename }}</h6>
<table class="table table-sm" style="font-size:.85rem;">
<tr><td class="text-dim">파일 크기</td><td>{{ "{:,}".format(result.size) }} B</td></tr>
<tr><td class="text-dim">미디어 크기</td><td>{{ "{:,}".format(result.media_size) }} B</td></tr>
<tr><td class="text-dim">섹터 크기</td><td>{{ result.sector_size }} B</td></tr>
<tr><td class="text-dim">섹터 수</td><td>{{ "{:,}".format(result.num_sectors) }}</td></tr>
<tr><td class="text-dim">청크</td><td>{{ result.segments }}</td></tr>
<tr><td class="text-dim">압축</td><td>{{ result.compression_method }}</td></tr>
<tr><td class="text-dim">MD5</td><td><code>{{ result.md5 }}</code></td></tr>
<tr><td class="text-dim">SHA-1</td><td><code>{{ result.sha1 }}</code></td></tr>
</table>
{% if result.header_values %}<h6 class="panel-title mt-3">헤더 값</h6>
<table class="table table-sm" style="font-size:.82rem;"><tbody>
{% for k, v in result.header_values.items() %}<tr><td class="text-dim">{{ k }}</td><td><code style="word-break:break-all;">{{ v }}</code></td></tr>{% endfor %}
</tbody></table>{% endif %}
</div>{% endif %}</div>{% endblock %}''')

# 10. MFT FULL
w('mft_full.html', hdr('MFT 풀 파싱 (pytsk3)','디스크 이미지 또는 $MFT → 파일 시스템 풀 워킹','bi-list-columns-reverse') + '''
<div class="container pb-5">{% if error %}<div class="alert-error mb-3">{{ error }}</div>{% endif %}
{% if not result %}<div class="row justify-content-center"><div class="col-lg-6"><div class="tool-panel">
<form method="POST" enctype="multipart/form-data">
<input type="file" name="file" class="form-control mb-3" required>
<div class="form-hint mb-3">디스크 이미지 (.dd/.img/.E01) 또는 $MFT 추출 파일</div>
<button class="btn btn-accent w-100">파싱</button>
</form></div></div></div>
{% else %}{% if result.partitions %}<div class="tool-panel mb-3">
<h6 class="panel-title">발견된 파티션 ({{ result.partitions|length }})</h6>
<table class="table table-sm" style="font-size:.82rem;"><thead><tr class="text-dim"><th>주소</th><th>설명</th><th>시작</th><th>길이</th></tr></thead><tbody>
{% for p in result.partitions %}<tr><td>{{ p.addr }}</td><td>{{ p.desc }}</td><td>{{ p.start }}</td><td>{{ p.len }}</td></tr>{% endfor %}
</tbody></table><div class="text-dim small">{{ result.note }}</div></div>
{% else %}<div class="tool-panel mb-3">
<h6 class="panel-title">{{ result.filename }} — {{ result.fs_type }}</h6>
<div class="text-dim small">블록 크기 {{ result.block_size }} · 블록 수 {{ result.block_count }} · 추출 {{ result.total }}건</div>
</div>
<div class="tool-panel"><div style="max-height:600px; overflow-y:auto;">
<table class="table table-sm" style="font-size:.76rem;">
<thead style="position:sticky; top:0; background:var(--bg-card);"><tr class="text-dim">
<th>경로</th><th>타입</th><th>크기</th><th>수정</th><th>생성</th><th>inode</th></tr></thead><tbody>
{% for f in result.files %}<tr><td style="word-break:break-all;"><code>{{ f.path }}</code></td>
<td>{{ f.type }}</td><td>{{ "{:,}".format(f.size) }}</td>
<td><code style="font-size:.7rem;">{{ f.mtime[:19] if f.mtime else '' }}</code></td>
<td><code style="font-size:.7rem;">{{ f.ctime[:19] if f.ctime else '' }}</code></td>
<td>{{ f.inode }}</td>
</tr>{% endfor %}</tbody></table></div></div>{% endif %}
{% endif %}</div>{% endblock %}''')

print('=== 10개 5차 템플릿 생성 완료 ===')
