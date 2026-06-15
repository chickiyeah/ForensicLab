"""ForensicLab 5차 확장 — 유료 도구 비등 만들기

7대 핵심 시스템:
1. /tools/vol-full      Volatility 3 풀 통합
2. /tools/coc           Chain of Custody 대시보드
3. /tools/llm-report    LLM 기반 자동 보고서 (Claude API)
4. /tools/jobs          백그라운드 작업 큐
5. /tools/hashcat-job   Hashcat 통합
6. /tools/aleapp        Android 풀 분석 (ALEAPP-like)
7. /tools/ileapp        iOS 풀 분석 (iLEAPP-like)
"""
import os
import io
import re
import json
import time
import uuid
import shutil
import hashlib
import datetime as _dt
import tempfile
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor
from collections import defaultdict
from pathlib import Path

from flask import request, render_template, jsonify, send_file, abort

from monitor.views.tools import bp, _save_log


# ====================================================================
# 백그라운드 작업 큐 시스템 (Phase 4)
# ====================================================================
_JOB_STORE = {}  # job_id -> {status, result, started, finished, name, output_file}
_EXECUTOR = ThreadPoolExecutor(max_workers=2)
_JOB_LOCK = threading.Lock()


def _new_job(name: str, fn, *args, **kwargs):
    """백그라운드 작업 생성"""
    job_id = uuid.uuid4().hex[:16]
    with _JOB_LOCK:
        _JOB_STORE[job_id] = {
            'id': job_id, 'name': name, 'status': 'pending',
            'started': None, 'finished': None,
            'result': None, 'progress': 0, 'log': [],
        }
    def runner():
        try:
            with _JOB_LOCK:
                _JOB_STORE[job_id]['status'] = 'running'
                _JOB_STORE[job_id]['started'] = _dt.datetime.utcnow().isoformat()
            r = fn(*args, _job_id=job_id, **kwargs)
            with _JOB_LOCK:
                _JOB_STORE[job_id]['result'] = r
                _JOB_STORE[job_id]['status'] = 'completed'
                _JOB_STORE[job_id]['finished'] = _dt.datetime.utcnow().isoformat()
                _JOB_STORE[job_id]['progress'] = 100
        except Exception as e:
            with _JOB_LOCK:
                _JOB_STORE[job_id]['status'] = 'failed'
                _JOB_STORE[job_id]['result'] = {'error': str(e)}
                _JOB_STORE[job_id]['finished'] = _dt.datetime.utcnow().isoformat()
    _EXECUTOR.submit(runner)
    return job_id


def _job_log(job_id, msg, pct=None):
    if not job_id: return
    with _JOB_LOCK:
        j = _JOB_STORE.get(job_id)
        if j:
            if pct is not None: j['progress'] = pct
            j['log'].append({
                'time': _dt.datetime.utcnow().isoformat(),
                'msg': msg,
                'progress': j['progress'],
            })


@bp.route('/jobs')
def jobs_list():
    with _JOB_LOCK:
        jobs = sorted(_JOB_STORE.values(),
                      key=lambda j: j.get('started') or '', reverse=True)
    return render_template('tools/jobs.html', jobs=jobs)


@bp.route('/jobs/<job_id>')
def job_detail(job_id):
    with _JOB_LOCK:
        j = _JOB_STORE.get(job_id)
    if not j: abort(404)
    return render_template('tools/job_detail.html', job=j)


@bp.route('/jobs/<job_id>/status')
def job_status_api(job_id):
    with _JOB_LOCK:
        j = _JOB_STORE.get(job_id)
    if not j: return jsonify({'error': 'not found'}), 404
    # 로그 마지막 60개 + 결과(완료 시) 포함
    log_tail = j.get('log', [])[-60:]
    return jsonify({
        'id': j['id'], 'status': j['status'], 'progress': j['progress'],
        'name': j['name'], 'started': j['started'], 'finished': j['finished'],
        'log_count': len(j.get('log', [])),
        'log': log_tail,
        'result': j.get('result') if j['status'] in ('completed', 'failed') else None,
    })


# ====================================================================
# Chain of Custody (체인 오브 커스터디)
# ====================================================================
_COC_DIR = Path(tempfile.gettempdir(), 'forensiclab_coc')
_COC_DIR.mkdir(exist_ok=True)
_COC_LOG = _COC_DIR / 'chain.jsonl'

def _coc_record(action: str, evidence_hash: str, metadata: dict) -> dict:
    """이전 로그 해시 + 현재 데이터로 변조 불가 체인 생성"""
    with _JOB_LOCK:
        prev_hash = '0' * 64
        if _COC_LOG.exists():
            try:
                with open(_COC_LOG, 'rb') as f:
                    f.seek(-1024, 2) if f.seek(0, 2) > 1024 else None
                    last = f.read().splitlines()[-1] if f.read() else None
                # 마지막 줄 다시 읽기
                with open(_COC_LOG, 'r', encoding='utf-8') as f:
                    lines = f.readlines()
                    if lines:
                        prev_entry = json.loads(lines[-1])
                        prev_hash = prev_entry['hash']
            except Exception: pass
        entry = {
            'timestamp': _dt.datetime.utcnow().isoformat(),
            'action': action,
            'evidence_sha256': evidence_hash,
            'metadata': metadata,
            'prev_hash': prev_hash,
        }
        # 현재 엔트리 해시
        entry_data = json.dumps({k: v for k, v in entry.items() if k != 'hash'}, sort_keys=True)
        entry['hash'] = hashlib.sha256(entry_data.encode()).hexdigest()
        with open(_COC_LOG, 'a', encoding='utf-8') as f:
            f.write(json.dumps(entry) + '\n')
        return entry


def _coc_verify_chain() -> dict:
    """전체 체인 검증"""
    if not _COC_LOG.exists(): return {'valid': True, 'entries': 0}
    entries = []
    with open(_COC_LOG, 'r', encoding='utf-8') as f:
        for line in f:
            try: entries.append(json.loads(line))
            except Exception: pass
    if not entries: return {'valid': True, 'entries': 0}
    invalid = []
    prev_hash = '0' * 64
    for i, entry in enumerate(entries):
        # 해시 재계산
        entry_copy = {k: v for k, v in entry.items() if k != 'hash'}
        recalc = hashlib.sha256(json.dumps(entry_copy, sort_keys=True).encode()).hexdigest()
        if recalc != entry['hash']:
            invalid.append({'idx': i, 'reason': '엔트리 해시 변조'})
        if entry.get('prev_hash') != prev_hash:
            invalid.append({'idx': i, 'reason': '이전 해시 연결 깨짐'})
        prev_hash = entry['hash']
    return {
        'valid': len(invalid) == 0,
        'entries': len(entries),
        'invalid': invalid,
        'first': entries[0]['timestamp'] if entries else None,
        'last': entries[-1]['timestamp'] if entries else None,
    }


@bp.route('/coc')
def coc_view():
    verification = _coc_verify_chain()
    recent = []
    if _COC_LOG.exists():
        with open(_COC_LOG, 'r', encoding='utf-8') as f:
            lines = f.readlines()[-100:]
        for line in reversed(lines):
            try: recent.append(json.loads(line))
            except Exception: pass
    return render_template('tools/coc.html',
                           verification=verification, entries=recent)


@bp.route('/coc/add', methods=['POST'])
def coc_add():
    f = request.files.get('file')
    action = request.form.get('action', 'evidence_intake')
    note = request.form.get('note', '')
    if not f or not f.filename:
        return jsonify({'error': '파일 필요'}), 400
    data = f.read()
    h = hashlib.sha256(data).hexdigest()
    entry = _coc_record(action, h, {
        'filename': f.filename,
        'size': len(data),
        'note': note,
        'md5': hashlib.md5(data).hexdigest(),
        'sha1': hashlib.sha1(data).hexdigest(),
        'user_agent': request.headers.get('User-Agent', ''),
        'remote_addr': request.remote_addr,
    })
    return jsonify({'ok': True, 'entry': entry})


@bp.route('/coc/download')
def coc_download():
    if not _COC_LOG.exists(): abort(404)
    return send_file(str(_COC_LOG), as_attachment=True,
                     download_name='chain_of_custody.jsonl')


# ====================================================================
# Volatility 3 풀 통합
# ====================================================================
_VOL_PLUGINS = [
    ('windows.pslist.PsList', 'pslist', 'Windows 프로세스 목록'),
    ('windows.psscan.PsScan', 'psscan', 'Windows 프로세스 스캔 (숨김 포함)'),
    ('windows.pstree.PsTree', 'pstree', 'Windows 프로세스 트리'),
    ('windows.cmdline.CmdLine', 'cmdline', 'Windows 명령행 인자'),
    ('windows.netscan.NetScan', 'netscan', 'Windows 네트워크 연결'),
    ('windows.netstat.NetStat', 'netstat', 'Windows netstat'),
    ('windows.dlllist.DllList', 'dlllist', '로드된 DLL'),
    ('windows.handles.Handles', 'handles', '핸들 (파일·레지스트리)'),
    ('windows.malfind.Malfind', 'malfind', '의심 메모리 영역 (코드 인젝션)'),
    ('windows.modules.Modules', 'modules', '커널 모듈'),
    ('windows.svcscan.SvcScan', 'svcscan', '서비스'),
    ('windows.registry.hivelist.HiveList', 'hivelist', '레지스트리 하이브 목록'),
    ('windows.registry.printkey.PrintKey', 'printkey', '레지스트리 키 출력'),
    ('windows.filescan.FileScan', 'filescan', '파일 객체 스캔'),
    ('windows.mftscan.MFTScan', 'mftscan', 'MFT 스캔'),
    ('windows.callbacks.Callbacks', 'callbacks', '커널 콜백'),
    ('windows.driverscan.DriverScan', 'driverscan', '드라이버'),
    ('windows.envars.Envars', 'envars', '환경변수'),
    ('linux.pslist.PsList', 'linux_pslist', 'Linux 프로세스'),
    ('linux.bash.Bash', 'linux_bash', 'Linux bash 명령 이력'),
    ('linux.lsof.Lsof', 'linux_lsof', 'Linux 열린 파일'),
    ('mac.pslist.PsList', 'mac_pslist', 'macOS 프로세스'),
    ('mac.bash.Bash', 'mac_bash', 'macOS bash 이력'),
]


def _run_volatility(dump_path: str, plugin: str, _job_id=None) -> dict:
    """volatility3 실행"""
    _job_log(_job_id, f'volatility3 시작: {plugin}', 5)
    try:
        # JSON 출력으로 실행
        result = subprocess.run(
            ['vol', '-f', dump_path, '-r', 'json', plugin],
            capture_output=True, text=True, timeout=600)
        _job_log(_job_id, f'vol 종료 (exit={result.returncode})', 90)
        if result.returncode != 0:
            return {'error': result.stderr[-2000:], 'plugin': plugin}
        try:
            data = json.loads(result.stdout)
            return {'plugin': plugin, 'rows': data, 'count': len(data) if isinstance(data, list) else 0}
        except json.JSONDecodeError:
            return {'plugin': plugin, 'raw_output': result.stdout[:50000]}
    except subprocess.TimeoutExpired:
        return {'error': 'Volatility 시간 초과 (10분)', 'plugin': plugin}
    except FileNotFoundError:
        return {'error': 'vol 명령을 찾을 수 없음 — pip install volatility3 필요', 'plugin': plugin}
    except Exception as e:
        return {'error': str(e), 'plugin': plugin}


def _vol_full_job(dump_data: bytes, plugins: list, _job_id=None) -> dict:
    """전체 Volatility 작업 (백그라운드)"""
    _job_log(_job_id, '메모리 덤프 저장 중...', 2)
    tf = tempfile.NamedTemporaryFile(delete=False, suffix='.dmp')
    tf.write(dump_data); tf.close()
    results = {}
    try:
        for i, p in enumerate(plugins):
            pct = int((i / max(len(plugins), 1)) * 90) + 5
            _job_log(_job_id, f'{p} 실행 중...', pct)
            results[p] = _run_volatility(tf.name, p, _job_id=None)
    finally:
        try: os.unlink(tf.name)
        except Exception: pass
    return {'plugins_run': len(plugins), 'results': results}


@bp.route('/vol-full', methods=['GET', 'POST'])
def vol_full_tool():
    result = error = job_id = None
    if request.method == 'POST':
        f = request.files.get('file')
        plugins = request.form.getlist('plugins')
        if not f or not f.filename: error = '메모리 덤프 필요'
        elif not plugins: error = '실행할 플러그인 선택'
        else:
            data = f.read()
            h = hashlib.sha256(data).hexdigest()
            _coc_record('volatility_analysis', h, {
                'filename': f.filename, 'size': len(data),
                'plugins': plugins,
            })
            job_id = _new_job(f'Volatility: {f.filename}', _vol_full_job,
                              data, plugins)
            result = {'job_id': job_id, 'redirect': f'/tools/jobs/{job_id}'}
    return render_template('tools/vol_full.html', result=result, error=error,
                           plugins=_VOL_PLUGINS, job_id=job_id)


# ====================================================================
# LLM 자동 보고서 (Claude API)
# ====================================================================
@bp.route('/llm-report', methods=['GET', 'POST'])
def llm_report_tool():
    result = error = None
    if request.method == 'POST':
        api_key = (request.form.get('api_key') or os.environ.get('ANTHROPIC_API_KEY') or '').strip()
        analysis_data = (request.form.get('analysis_data') or '').strip()
        context = (request.form.get('context') or '디지털 포렌식 분석').strip()
        language = request.form.get('language', '한국어')
        if not api_key: error = 'API 키 필요 (또는 ANTHROPIC_API_KEY 환경변수)'
        elif not analysis_data: error = '분석 결과 JSON/텍스트 입력'
        else:
            try:
                import anthropic
                client = anthropic.Anthropic(api_key=api_key)
                prompt = f"""당신은 디지털 포렌식 전문가입니다. 다음 분석 결과를 바탕으로 {language}로 전문가 수준의 포렌식 보고서를 작성하세요.

**분석 컨텍스트**: {context}

**분석 데이터**:
```
{analysis_data[:30000]}
```

다음 섹션으로 구성해주세요:
1. **개요** (Executive Summary) - 핵심 발견사항 3-5줄
2. **분석 방법론** - 사용된 도구·기법
3. **주요 발견** - 시각·근거와 함께 상세히
4. **위협 평가** - 심각도·영향
5. **권장 조치** - 즉시·중기·장기
6. **결론**

가독성 있게 Markdown 형식으로 작성하고, 시각·해시·경로 등 구체적 근거를 인용하세요."""
                resp = client.messages.create(
                    model='claude-sonnet-4-5',
                    max_tokens=8000,
                    messages=[{'role': 'user', 'content': prompt}],
                )
                report = resp.content[0].text
                # CoC 기록
                _coc_record('llm_report_generated', hashlib.sha256(analysis_data.encode()).hexdigest()[:32], {
                    'context': context, 'language': language,
                    'report_len': len(report),
                })
                result = {
                    'report': report, 'context': context,
                    'language': language,
                    'tokens_in': resp.usage.input_tokens,
                    'tokens_out': resp.usage.output_tokens,
                    'model': 'claude-sonnet-4-5',
                }
            except ImportError:
                error = 'anthropic 라이브러리 미설치'
            except Exception as e:
                error = f'API 오류: {e}'
    return render_template('tools/llm_report.html', result=result, error=error)


# ====================================================================
# Hashcat 통합
# ====================================================================
_HASHCAT_MODES = {
    0: 'MD5', 100: 'SHA1', 1400: 'SHA-256', 1700: 'SHA-512',
    1000: 'NTLM', 3000: 'LM', 5500: 'NetNTLMv1', 5600: 'NetNTLMv2',
    1800: 'sha512crypt $6$ (Unix)', 7400: 'sha256crypt $5$ (Unix)',
    500: 'md5crypt $1$ (Unix)', 1500: 'descrypt (Unix DES)',
    11600: '7-Zip', 13600: 'WinZip', 12500: 'RAR3-hp', 13000: 'RAR5',
    13400: 'KeePass 1/2', 9400: 'MS Office 2007', 9500: 'MS Office 2010',
    9600: 'MS Office 2013/2016', 10500: 'PDF 1.7 L8 (Acrobat 10-11)',
    22000: 'WPA-PBKDF2-PMKID+EAPOL (Wi-Fi)',
    22100: 'BitLocker', 12300: 'Oracle T: Type (Oracle 12c+)',
    300: 'MySQL 4.1/5+',  3100: 'Oracle H: Type', 131: 'MSSQL 2000',
    1731: 'MSSQL 2012/2014', 7300: 'iSCSI CHAP',
    16900: 'Ansible Vault', 18300: 'Apple File System (APFS)',
    8200: '1Password', 9100: 'Lotus Notes/Domino 8',
}


def _hashcat_job(hashes_file: str, wordlist: str, mode: int,
                 attack_mode: int = 0, _job_id=None) -> dict:
    """Hashcat 백그라운드 실행"""
    _job_log(_job_id, 'Hashcat 시작', 5)
    out_file = hashes_file + '.out'
    try:
        cmd = ['hashcat', '-a', str(attack_mode), '-m', str(mode),
               hashes_file, '--potfile-disable',
               '-o', out_file, '--quiet', '--status', '--status-timer=5']
        if attack_mode == 0:  # 사전 공격
            cmd.append(wordlist)
        elif attack_mode == 3:  # 무차별
            cmd.append(wordlist)  # 마스크
        elif attack_mode == 6:  # 사전+규칙
            cmd.extend([wordlist, '?d?d'])
        _job_log(_job_id, f'명령: {" ".join(cmd)}', 10)
        # CPU 모드 (GPU 없음)
        cmd.append('--force')
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
        _job_log(_job_id, f'Hashcat 종료 (exit={proc.returncode})', 95)
        cracked = []
        if os.path.exists(out_file):
            with open(out_file) as f:
                cracked = [line.strip() for line in f if line.strip()]
        return {'cracked': cracked, 'cracked_count': len(cracked),
                'stdout': proc.stdout[-3000:],
                'stderr': proc.stderr[-2000:] if proc.returncode != 0 else ''}
    except subprocess.TimeoutExpired:
        return {'error': 'Hashcat 시간 초과 (30분)'}
    except FileNotFoundError:
        return {'error': 'hashcat 시스템 패키지 필요'}
    except Exception as e:
        return {'error': str(e)}
    finally:
        try: os.unlink(hashes_file); os.unlink(out_file)
        except Exception: pass


@bp.route('/hashcat-job', methods=['GET', 'POST'])
def hashcat_tool():
    result = error = None
    if request.method == 'POST':
        hashes_text = (request.form.get('hashes') or '').strip()
        wordlist_text = (request.form.get('wordlist') or '').strip()
        mode = int(request.form.get('mode', 0))
        attack_mode = int(request.form.get('attack_mode', 0))
        if not hashes_text: error = '해시 입력 필요'
        elif not wordlist_text: error = '사전 또는 마스크 필요'
        else:
            # 임시 파일에 저장
            ht = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.hash')
            ht.write(hashes_text); ht.close()
            wt = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt')
            wt.write(wordlist_text); wt.close()
            job_id = _new_job(f'Hashcat: mode {mode}',
                              _hashcat_job, ht.name, wt.name, mode, attack_mode)
            result = {'job_id': job_id, 'redirect': f'/tools/jobs/{job_id}'}
    return render_template('tools/hashcat_job.html', result=result, error=error,
                           modes=_HASHCAT_MODES)


# ====================================================================
# ALEAPP / iLEAPP - Android·iOS 풀 분석
# ====================================================================
def _aleapp_job(zip_data: bytes, _job_id=None) -> dict:
    """ALEAPP 백그라운드 실행"""
    _job_log(_job_id, 'ZIP 압축 해제 중', 5)
    try:
        import tempfile, zipfile
        # 입출력 디렉터리
        work = tempfile.mkdtemp(prefix='aleapp_')
        input_dir = os.path.join(work, 'input')
        output_dir = os.path.join(work, 'output')
        os.makedirs(input_dir); os.makedirs(output_dir)
        zip_path = os.path.join(work, 'in.zip')
        with open(zip_path, 'wb') as f: f.write(zip_data)
        _job_log(_job_id, 'ALEAPP 실행 시작', 20)
        try:
            # CLI 실행
            r = subprocess.run(
                ['python', '/opt/ALEAPP/aleapp.py', '-t', 'zip',
                 '-i', zip_path, '-o', output_dir],
                capture_output=True, text=True, timeout=1200,
                cwd='/opt/ALEAPP')
            _job_log(_job_id, f'ALEAPP 종료 (exit={r.returncode})', 90)
            html_report = None
            for root, _, files in os.walk(output_dir):
                for fn in files:
                    if fn.endswith('.html') and 'index' in fn.lower():
                        html_report = os.path.join(root, fn)
                        break
                if html_report: break
            artifacts = []
            for root, _, files in os.walk(output_dir):
                for fn in files:
                    fp = os.path.join(root, fn)
                    artifacts.append({
                        'name': os.path.relpath(fp, output_dir),
                        'size': os.path.getsize(fp),
                    })
            return {'report_found': bool(html_report),
                    'artifacts': artifacts[:200],
                    'stdout': r.stdout[-3000:],
                    'output_dir': output_dir}
        except FileNotFoundError:
            return {'error': 'ALEAPP 미설치 — pip install ALEAPP'}
        except subprocess.TimeoutExpired:
            return {'error': '시간 초과 (20분)'}
    except Exception as e:
        return {'error': str(e)}


def _ileapp_job(zip_data: bytes, _job_id=None) -> dict:
    """iLEAPP 백그라운드 실행 (ALEAPP과 동일 패턴)"""
    _job_log(_job_id, 'ZIP 압축 해제 중', 5)
    try:
        import tempfile
        work = tempfile.mkdtemp(prefix='ileapp_')
        output_dir = os.path.join(work, 'output')
        os.makedirs(output_dir)
        zip_path = os.path.join(work, 'in.zip')
        with open(zip_path, 'wb') as f: f.write(zip_data)
        _job_log(_job_id, 'iLEAPP 실행 시작', 20)
        try:
            r = subprocess.run(
                ['python', '/opt/iLEAPP/ileapp.py', '-t', 'zip',
                 '-i', zip_path, '-o', output_dir],
                capture_output=True, text=True, timeout=1200,
                cwd='/opt/iLEAPP')
            _job_log(_job_id, f'iLEAPP 종료 (exit={r.returncode})', 90)
            artifacts = []
            for root, _, files in os.walk(output_dir):
                for fn in files:
                    fp = os.path.join(root, fn)
                    artifacts.append({'name': os.path.relpath(fp, output_dir),
                                      'size': os.path.getsize(fp)})
            return {'artifacts': artifacts[:200],
                    'stdout': r.stdout[-3000:]}
        except FileNotFoundError:
            return {'error': 'iLEAPP 미설치 — pip install iLEAPP'}
        except subprocess.TimeoutExpired:
            return {'error': '시간 초과'}
    except Exception as e:
        return {'error': str(e)}


@bp.route('/aleapp', methods=['GET', 'POST'])
def aleapp_tool():
    result = error = None
    if request.method == 'POST':
        f = request.files.get('file')
        if not f or not f.filename: error = 'Android 추출 ZIP 필요'
        else:
            data = f.read()
            _coc_record('aleapp_intake', hashlib.sha256(data).hexdigest(), {
                'filename': f.filename, 'size': len(data),
            })
            job_id = _new_job(f'ALEAPP: {f.filename}', _aleapp_job, data)
            result = {'job_id': job_id, 'redirect': f'/tools/jobs/{job_id}'}
    return render_template('tools/aleapp.html', result=result, error=error)


@bp.route('/ileapp', methods=['GET', 'POST'])
def ileapp_tool():
    result = error = None
    if request.method == 'POST':
        f = request.files.get('file')
        if not f or not f.filename: error = 'iOS 백업 ZIP 필요'
        else:
            data = f.read()
            _coc_record('ileapp_intake', hashlib.sha256(data).hexdigest(), {
                'filename': f.filename, 'size': len(data),
            })
            job_id = _new_job(f'iLEAPP: {f.filename}', _ileapp_job, data)
            result = {'job_id': job_id, 'redirect': f'/tools/jobs/{job_id}'}
    return render_template('tools/ileapp.html', result=result, error=error)


# ====================================================================
# libewf / pytsk3 - E01·풀 디스크 마운트
# ====================================================================
@bp.route('/e01-mount', methods=['GET', 'POST'])
def e01_mount_tool():
    result = error = None
    if request.method == 'POST':
        f = request.files.get('file')
        if not f or not f.filename: error = 'E01 파일 필요'
        else:
            try:
                import pyewf
                data = f.read()
                tf = tempfile.NamedTemporaryFile(delete=False, suffix='.E01')
                tf.write(data); tf.close()
                ewf = pyewf.handle()
                ewf.open([tf.name])
                # E01 메타데이터
                header_values = {}
                try:
                    for k in ['case_number','description','examiner_name','evidence_number',
                              'notes','acquiry_operating_system','acquiry_software',
                              'acquiry_software_version','model','serial_number','password',
                              'media_size','sector_size','media_type','volume_type']:
                        try: header_values[k] = str(ewf.get_header_value(k))[:500]
                        except Exception: pass
                except Exception: pass
                r = {
                    'filename': f.filename, 'size': len(data),
                    'media_size': ewf.get_media_size(),
                    'sector_size': ewf.get_bytes_per_sector(),
                    'num_sectors': ewf.get_number_of_sectors(),
                    'compression_method': ewf.get_compression_method(),
                    'segments': ewf.get_number_of_chunks(),
                    'md5': ewf.get_hash_value('MD5'),
                    'sha1': ewf.get_hash_value('SHA1'),
                    'header_values': header_values,
                }
                ewf.close()
                os.unlink(tf.name)
                _coc_record('e01_analysis', hashlib.sha256(data).hexdigest(), {
                    'filename': f.filename, 'media_size': r['media_size'],
                })
                result = r
            except ImportError:
                error = 'libewf-python 미설치 — pip install libewf-python'
            except Exception as e: error = str(e)
    return render_template('tools/e01_mount.html', result=result, error=error)


@bp.route('/mft-full', methods=['GET', 'POST'])
def mft_full_tool():
    """pytsk3 기반 풀 MFT 파싱"""
    result = error = None
    if request.method == 'POST':
        f = request.files.get('file')
        if not f or not f.filename: error = '디스크 이미지 또는 $MFT 필요'
        else:
            try:
                import pytsk3
                data = f.read()
                tf = tempfile.NamedTemporaryFile(delete=False, suffix='.dd')
                tf.write(data); tf.close()
                # 이미지 열기
                img = pytsk3.Img_Info(tf.name)
                # 파일시스템 열기 (오프셋 0)
                try:
                    fs = pytsk3.FS_Info(img)
                except Exception as e:
                    # MBR/GPT 파티션 시도
                    try:
                        vol = pytsk3.Volume_Info(img)
                        partitions = []
                        for part in vol:
                            partitions.append({'addr': part.addr, 'desc': part.desc.decode('latin1'),
                                               'start': part.start, 'len': part.len})
                        os.unlink(tf.name)
                        return render_template('tools/mft_full.html',
                                               result={'partitions': partitions,
                                                       'note': '파티션 발견 — 특정 파티션 오프셋 필요'},
                                               error=None)
                    except Exception:
                        os.unlink(tf.name)
                        raise e
                # 루트 디렉터리부터 재귀 (제한)
                files = []
                def walk(fs_obj, path, depth=0):
                    if depth > 5 or len(files) > 1000: return
                    try:
                        directory = fs_obj.open_dir(path=path)
                        for entry in directory:
                            if not entry.info.name.name: continue
                            name = entry.info.name.name.decode('utf-8', errors='replace')
                            if name in ('.', '..'): continue
                            f_type = '?'
                            try:
                                f_type = {1:'파일',2:'디렉터리',5:'심볼릭링크'}.get(int(entry.info.meta.type), '?')
                            except Exception: pass
                            meta = entry.info.meta
                            files.append({
                                'name': name,
                                'path': path + '/' + name,
                                'type': f_type,
                                'size': meta.size if meta else 0,
                                'mtime': _dt.datetime.utcfromtimestamp(meta.mtime).isoformat() if meta and meta.mtime else '',
                                'ctime': _dt.datetime.utcfromtimestamp(meta.crtime).isoformat() if meta and meta.crtime else '',
                                'inode': entry.info.meta.addr if meta else 0,
                            })
                            if f_type == '디렉터리' and depth < 5 and len(files) < 1000:
                                try: walk(fs_obj, path + '/' + name, depth + 1)
                                except Exception: pass
                    except Exception: pass
                walk(fs, '/')
                result = {
                    'filename': f.filename, 'fs_type': str(fs.info.ftype),
                    'block_size': fs.info.block_size,
                    'block_count': fs.info.block_count,
                    'files': files[:500],
                    'total': len(files),
                }
                os.unlink(tf.name)
            except ImportError:
                error = 'pytsk3 미설치 — pip install pytsk3 (libtsk 필요)'
            except Exception as e:
                error = str(e)
    return render_template('tools/mft_full.html', result=result, error=error)


# ====================================================================
# 강화 _save_log — 자동 CoC 기록
# ====================================================================
# 기존 _save_log는 보존하되, 향후 모든 도구가 자동으로 CoC에 기록되도록
# 보조 헬퍼 제공
def coc_auto_record(tool_name: str, filename: str, data_hash: str, summary: str):
    """모든 신규 분석에서 호출할 수 있는 CoC 기록"""
    return _coc_record(f'tool_use:{tool_name}', data_hash, {
        'tool': tool_name, 'filename': filename, 'summary': summary,
    })


# ====================================================================
# 다운로드 가능한 CoC 인증서
# ====================================================================
@bp.route('/coc/certificate/<evidence_hash>')
def coc_certificate(evidence_hash):
    """특정 증거의 CoC 인증서 생성"""
    if not _COC_LOG.exists(): abort(404)
    matching = []
    with open(_COC_LOG, 'r', encoding='utf-8') as f:
        for line in f:
            try:
                e = json.loads(line)
                if e.get('evidence_sha256', '').startswith(evidence_hash):
                    matching.append(e)
            except Exception: pass
    if not matching: abort(404)
    cert = {
        'evidence_sha256': matching[0]['evidence_sha256'],
        'first_seen': matching[0]['timestamp'],
        'last_action': matching[-1]['timestamp'],
        'total_actions': len(matching),
        'chain': matching,
        'verification': _coc_verify_chain(),
        'issued': _dt.datetime.utcnow().isoformat(),
    }
    return jsonify(cert)
