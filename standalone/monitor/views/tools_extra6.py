"""ForensicLab 6차 확장 — '유료 왜 씀?' 모드

10대 엔터프라이즈 시스템:
1. /tools/case        사건 관리 (Case Management)
2. /tools/search      풀 텍스트 검색 (SQLite FTS5)
3. /tools/dashboard   분석 대시보드 (통계·그래프)
4. /tools/casereport  법정 PDF 보고서 (ReportLab)
5. /tools/attack      MITRE ATT&CK 매핑
6. /tools/threat-intel 위협 인텔리전스 (VT/AbuseIPDB 등)
7. /tools/ai-classify AI 자동 분류
8. /tools/plaso       Plaso 슈퍼 타임라인
9. /tools/ocr-index   OCR 인덱싱 + 검색
10. /tools/face       얼굴/객체 인식
"""
import os
import io
import json
import sqlite3
import hashlib
import datetime as _dt
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from collections import Counter


# plaso 등 무거운 외부 프로세스를 '약간' 낮은 우선순위로 실행하는 prefix.
# (idle I/O 클래스 -c3 은 디스크를 계속 양보해 워커가 굶어 CPU<10% 정체를 유발하므로
#  사용하지 않음. best-effort 저우선순위로 두어 다른 컨테이너엔 양보하되 굶지는 않게.)
def _low_prio_prefix():
    pre = []
    n = os.cpu_count() or 4
    cores = max(2, n - 4)   # plaso 에 줄 코어 수 — 나머지(>=4)는 타 컨테이너 몫으로 보장
    if shutil.which('taskset'):
        pre += ['taskset', '-c', '0-%d' % (cores - 1)]   # 특정 코어에 고정 → 호스트 CPU 락 방지
    if shutil.which('nice'):
        pre += ['nice', '-n', '10']
    if shutil.which('ionice'):
        pre += ['ionice', '-c', '2', '-n', '6']
    return pre


_LOWPRIO = _low_prio_prefix()
# 워커 수: 호스트 코어 - 4 (다른 컨테이너용 여유 확보). 10코어 → 6워커
_PLASO_WORKERS = str(max(2, (os.cpu_count() or 4) - 4))

from functools import wraps
from flask import request, render_template, jsonify, send_file, abort, url_for, session, redirect, flash

from monitor.views.tools import bp, _save_log, PARTITION_TYPES


# ────────────────────────────────────────────────────────────
# 현재 사용자 / 인증 헬퍼
# ────────────────────────────────────────────────────────────
def _current_user():
    """현재 세션 사용자명 (없으면 None)"""
    return session.get('username')


def login_required(fn):
    """로그인 필수 데코레이터"""
    @wraps(fn)
    def wrap(*args, **kwargs):
        if not _current_user():
            if request.method == 'GET':
                return redirect(f'/login?next={request.path}')
            return jsonify({'error': '로그인 필요'}), 401
        return fn(*args, **kwargs)
    return wrap
from monitor.views.tools_extra5 import _coc_record, _new_job, _job_log


# ====================================================================
# 사건 관리 DB (Case Management)
# ====================================================================
# 영속 데이터 디렉터리 (/app/data — 바인드 마운트, 컨테이너 재시작에도 보존)
_DATA_DIR = os.environ.get('FORENSIC_DATA_DIR') or os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), 'data')
try:
    os.makedirs(_DATA_DIR, exist_ok=True)
except Exception:
    pass

_CASE_DB = Path(_DATA_DIR, 'forensiclab_cases.db')

def _init_case_db():
    con = sqlite3.connect(_CASE_DB)
    con.executescript('''
        CREATE TABLE IF NOT EXISTS cases (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_number TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL,
            description TEXT,
            examiner TEXT,
            status TEXT DEFAULT 'open',
            priority TEXT DEFAULT 'medium',
            created_at TEXT NOT NULL,
            closed_at TEXT,
            metadata TEXT,
            owner TEXT
        );
        CREATE TABLE IF NOT EXISTS case_members (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id INTEGER NOT NULL,
            username TEXT NOT NULL,
            role TEXT NOT NULL,
            added_by TEXT NOT NULL,
            added_at TEXT NOT NULL,
            UNIQUE(case_id, username),
            FOREIGN KEY(case_id) REFERENCES cases(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS evidence (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id INTEGER NOT NULL,
            filename TEXT NOT NULL,
            sha256 TEXT NOT NULL,
            size INTEGER,
            uploaded_at TEXT NOT NULL,
            tool_used TEXT,
            tags TEXT,
            notes TEXT,
            analysis_result TEXT,
            FOREIGN KEY(case_id) REFERENCES cases(id)
        );
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id INTEGER NOT NULL,
            evidence_id INTEGER,
            severity TEXT,
            category TEXT,
            title TEXT NOT NULL,
            description TEXT,
            attack_techniques TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY(case_id) REFERENCES cases(id),
            FOREIGN KEY(evidence_id) REFERENCES evidence(id)
        );
        CREATE TABLE IF NOT EXISTS bookmarks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id INTEGER NOT NULL,
            evidence_id INTEGER,
            title TEXT NOT NULL,
            content TEXT,
            tags TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY(case_id) REFERENCES cases(id)
        );
        CREATE VIRTUAL TABLE IF NOT EXISTS search_idx USING fts5(
            case_number, evidence_filename, content, tags,
            tokenize="unicode61"
        );
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            user TEXT,
            action TEXT,
            target TEXT,
            ip TEXT,
            metadata TEXT
        );
    ''')
    # 마이그레이션: 기존 cases 테이블에 owner 컬럼 추가
    try:
        cols = [r[1] for r in con.execute('PRAGMA table_info(cases)').fetchall()]
        if 'owner' not in cols:
            con.execute("ALTER TABLE cases ADD COLUMN owner TEXT")
            con.commit()
    except Exception: pass
    con.commit(); con.close()

_init_case_db()


# ────────────────────────────────────────────────────────────
# 사건 권한 시스템 (RBAC)
# ────────────────────────────────────────────────────────────
# Role 위계: owner(4) > admin(3) > editor(2) > viewer(1) > none(0)
_ROLE_LEVEL = {'owner': 4, 'admin': 3, 'editor': 2, 'viewer': 1}

def _user_role(case_id: int, username: str):
    """반환: 'owner' | 'admin' | 'editor' | 'viewer' | None"""
    if not username: return None
    con = sqlite3.connect(_CASE_DB)
    try:
        case = con.execute('SELECT owner FROM cases WHERE id=?', (case_id,)).fetchone()
        if not case: return None
        if case[0] == username: return 'owner'
        m = con.execute(
            'SELECT role FROM case_members WHERE case_id=? AND username=?',
            (case_id, username)).fetchone()
        return m[0] if m else None
    finally: con.close()


def _has_perm(case_id: int, username: str, min_role: str) -> bool:
    """지정 역할 이상 권한 있는지"""
    role = _user_role(case_id, username)
    if not role: return False
    return _ROLE_LEVEL.get(role, 0) >= _ROLE_LEVEL.get(min_role, 0)


def _user_cases_query():
    """현재 유저가 멤버인 사건만 반환하는 SQL fragment"""
    u = _current_user()
    return ('SELECT DISTINCT c.* FROM cases c LEFT JOIN case_members m ON c.id = m.case_id '
            'WHERE c.owner=? OR m.username=?', (u, u))


def require_role(min_role: str):
    """case_id 인자에 대해 권한 검사하는 데코레이터"""
    def deco(fn):
        @wraps(fn)
        def wrap(case_id, *args, **kwargs):
            u = _current_user()
            if not u:
                if request.method == 'GET':
                    return redirect(f'/login?next={request.path}')
                return jsonify({'error': '로그인 필요'}), 401
            if not _has_perm(case_id, u, min_role):
                if request.method == 'GET':
                    return render_template('tools/case_no_access.html',
                                           case_id=case_id, required=min_role), 403
                return jsonify({'error': '권한 부족',
                                'required': min_role}), 403
            return fn(case_id, *args, **kwargs)
        return wrap
    return deco


def _audit(action: str, target: str = '', metadata: dict = None):
    """모든 액션을 감사 로그에 기록"""
    try:
        con = sqlite3.connect(_CASE_DB)
        user = _current_user() or request.headers.get('X-Forwarded-User', 'anonymous')
        con.execute(
            'INSERT INTO audit_log (timestamp, user, action, target, ip, metadata) VALUES (?,?,?,?,?,?)',
            (_dt.datetime.utcnow().isoformat(), user,
             action, target, request.remote_addr or '',
             json.dumps(metadata or {})))
        con.commit(); con.close()
    except Exception: pass


# ====================================================================
# 1. /tools/case — 사건 관리
# ====================================================================
@bp.route('/case', methods=['GET','POST'])
@login_required
def case_list():
    u = _current_user()
    error = None
    if request.method == 'POST':
        try:
            con = sqlite3.connect(_CASE_DB)
            case_num = request.form.get('case_number') or f'CASE-{_dt.datetime.utcnow().strftime("%Y%m%d-%H%M%S")}'
            con.execute('''
                INSERT INTO cases (case_number, name, description, examiner, priority, created_at, metadata, owner)
                VALUES (?,?,?,?,?,?,?,?)''', (
                case_num,
                request.form.get('name', ''),
                request.form.get('description', ''),
                request.form.get('examiner', u),
                request.form.get('priority', 'medium'),
                _dt.datetime.utcnow().isoformat(),
                '{}',
                u))
            con.commit(); con.close()
            _audit('case_created', case_num)
            _coc_record('case_created', '0'*64, {
                'case_number': case_num,
                'name': request.form.get('name',''),
                'owner': u})
        except sqlite3.IntegrityError:
            error = '이미 존재하는 사건번호'
        except Exception as e: error = str(e)
    # 본인이 소유자거나 멤버인 사건만 표시
    con = sqlite3.connect(_CASE_DB)
    con.row_factory = sqlite3.Row
    cases = [dict(r) for r in con.execute('''
        SELECT DISTINCT c.* FROM cases c
        LEFT JOIN case_members m ON c.id = m.case_id
        WHERE c.owner=? OR m.username=?
        ORDER BY c.created_at DESC LIMIT 100''', (u, u)).fetchall()]
    for c in cases:
        c['evidence_count'] = con.execute(
            'SELECT COUNT(*) FROM evidence WHERE case_id=?', (c['id'],)).fetchone()[0]
        c['findings_count'] = con.execute(
            'SELECT COUNT(*) FROM findings WHERE case_id=?', (c['id'],)).fetchone()[0]
        c['my_role'] = 'owner' if c['owner'] == u else (
            con.execute('SELECT role FROM case_members WHERE case_id=? AND username=?',
                        (c['id'], u)).fetchone() or [None])[0]
    con.close()
    return render_template('tools/case.html', cases=cases, error=error,
                           current_user=u)


@bp.route('/case/<int:case_id>', methods=['GET','POST'])
@require_role('viewer')
def case_detail(case_id):
    u = _current_user()
    my_role = _user_role(case_id, u)
    can_edit = _ROLE_LEVEL[my_role] >= _ROLE_LEVEL['editor']
    can_admin = _ROLE_LEVEL[my_role] >= _ROLE_LEVEL['admin']
    con = sqlite3.connect(_CASE_DB)
    con.row_factory = sqlite3.Row
    if request.method == 'POST':
        action = request.form.get('action')
        # 멤버 관리 (admin 이상)
        if action == 'add_member':
            if not can_admin: con.close(); abort(403)
            target = (request.form.get('username') or '').strip()
            role = request.form.get('role', 'viewer')
            if role not in ('admin','editor','viewer') or not target:
                con.close()
                return redirect(f'/tools/case/{case_id}')
            try:
                con.execute('''INSERT INTO case_members (case_id, username, role, added_by, added_at)
                               VALUES (?,?,?,?,?)''',
                            (case_id, target, role, u, _dt.datetime.utcnow().isoformat()))
                con.commit()
                _audit('member_added', target, {'case_id': case_id, 'role': role})
                _coc_record('member_added', '0'*64, {'case_id': case_id,
                            'username': target, 'role': role, 'added_by': u})
            except sqlite3.IntegrityError: pass
            con.close()
            return redirect(f'/tools/case/{case_id}#members')
        elif action == 'remove_member':
            if not can_admin: con.close(); abort(403)
            target = request.form.get('username', '')
            con.execute('DELETE FROM case_members WHERE case_id=? AND username=?',
                       (case_id, target))
            con.commit()
            _audit('member_removed', target, {'case_id': case_id})
            con.close()
            return redirect(f'/tools/case/{case_id}#members')
        elif action == 'change_role':
            if not can_admin: con.close(); abort(403)
            target = request.form.get('username', '')
            new_role = request.form.get('role', 'viewer')
            if new_role in ('admin','editor','viewer'):
                con.execute('UPDATE case_members SET role=? WHERE case_id=? AND username=?',
                           (new_role, case_id, target))
                con.commit()
                _audit('role_changed', target, {'case_id': case_id, 'new_role': new_role})
            con.close()
            return redirect(f'/tools/case/{case_id}#members')
        # 수정 액션 (editor 이상)
        if not can_edit:
            con.close()
            return jsonify({'error': '읽기 전용 (viewer)'}), 403
        if action == 'add_evidence':
            f = request.files.get('file')
            if f and f.filename:
                data = f.read()
                sha = hashlib.sha256(data).hexdigest()
                con.execute('''INSERT INTO evidence
                    (case_id, filename, sha256, size, uploaded_at, tool_used, tags, notes)
                    VALUES (?,?,?,?,?,?,?,?)''', (
                    case_id, f.filename, sha, len(data),
                    _dt.datetime.utcnow().isoformat(),
                    request.form.get('tool', ''),
                    request.form.get('tags', ''),
                    request.form.get('notes', '')))
                # 검색 인덱스 추가
                case = con.execute('SELECT case_number FROM cases WHERE id=?', (case_id,)).fetchone()
                con.execute('INSERT INTO search_idx (case_number, evidence_filename, content, tags) VALUES (?,?,?,?)',
                    (case['case_number'], f.filename,
                     request.form.get('notes', ''), request.form.get('tags', '')))
                _coc_record('evidence_added', sha, {
                    'case_id': case_id, 'filename': f.filename,
                    'size': len(data)})
                _audit('evidence_added', f.filename, {'case_id': case_id})
        elif action == 'add_finding':
            con.execute('''INSERT INTO findings
                (case_id, severity, category, title, description, attack_techniques, created_at)
                VALUES (?,?,?,?,?,?,?)''', (
                case_id, request.form.get('severity', 'medium'),
                request.form.get('category', ''),
                request.form.get('title', ''),
                request.form.get('description', ''),
                request.form.get('attack_techniques', ''),
                _dt.datetime.utcnow().isoformat()))
            _audit('finding_added', request.form.get('title',''), {'case_id': case_id})
        elif action == 'add_bookmark':
            con.execute('''INSERT INTO bookmarks (case_id, title, content, tags, created_at)
                VALUES (?,?,?,?,?)''', (
                case_id, request.form.get('title', ''),
                request.form.get('content', ''),
                request.form.get('tags', ''),
                _dt.datetime.utcnow().isoformat()))
        elif action == 'attach_log':
            # 내 분석 이력(AnalysisLog)을 사건 증거로 첨부 (메인 DB → 사건 evidence 테이블)
            from monitor.models import AnalysisLog
            log_id = request.form.get('log_id', type=int)
            log = (AnalysisLog.query
                   .filter_by(id=log_id, user_id=session.get('user_id')).first()
                   if log_id else None)
            if log:
                con.execute('''INSERT INTO evidence
                    (case_id, filename, sha256, size, uploaded_at, tool_used, tags, notes, analysis_result)
                    VALUES (?,?,?,?,?,?,?,?,?)''', (
                    case_id, (log.filename or (log.tool_label or log.tool)),
                    (log.share_token or ''), (log.file_size or 0),
                    _dt.datetime.utcnow().isoformat(),
                    (log.tool_label or log.tool), '분석이력',
                    (log.summary or '')[:1000], log.result_json))
                case_row = con.execute('SELECT case_number FROM cases WHERE id=?', (case_id,)).fetchone()
                con.execute('INSERT INTO search_idx (case_number, evidence_filename, content, tags) VALUES (?,?,?,?)',
                    (case_row['case_number'], (log.filename or ''),
                     (log.summary or ''), '분석이력'))
                _audit('log_attached', (log.filename or str(log_id)),
                       {'case_id': case_id, 'log_id': log_id})
        elif action == 'close':
            if not can_admin: con.close(); abort(403)
            con.execute('UPDATE cases SET status=?, closed_at=? WHERE id=?',
                       ('closed', _dt.datetime.utcnow().isoformat(), case_id))
            _audit('case_closed', '', {'case_id': case_id})
        con.commit()
    case = con.execute('SELECT * FROM cases WHERE id=?', (case_id,)).fetchone()
    if not case: con.close(); abort(404)
    case = dict(case)
    evidence = [dict(r) for r in con.execute(
        'SELECT * FROM evidence WHERE case_id=? ORDER BY uploaded_at DESC', (case_id,)).fetchall()]
    findings = [dict(r) for r in con.execute(
        'SELECT * FROM findings WHERE case_id=? ORDER BY created_at DESC', (case_id,)).fetchall()]
    bookmarks = [dict(r) for r in con.execute(
        'SELECT * FROM bookmarks WHERE case_id=? ORDER BY created_at DESC', (case_id,)).fetchall()]
    members = [dict(r) for r in con.execute(
        'SELECT * FROM case_members WHERE case_id=? ORDER BY added_at', (case_id,)).fetchall()]
    con.close()
    # 현재 사용자의 최근 분석 이력 (사건 증거로 첨부 가능)
    my_logs = []
    try:
        from monitor.models import AnalysisLog
        my_logs = (AnalysisLog.query
                   .filter_by(user_id=session.get('user_id'))
                   .order_by(AnalysisLog.created.desc()).limit(15).all())
    except Exception:
        my_logs = []
    return render_template('tools/case_detail.html',
                           case=case, evidence=evidence,
                           findings=findings, bookmarks=bookmarks,
                           members=members, my_role=my_role,
                           can_edit=can_edit, can_admin=can_admin,
                           current_user=u, my_logs=my_logs)


# ====================================================================
# 2. /tools/search — 풀 텍스트 검색 (FTS5)
# ====================================================================
@bp.route('/search', methods=['GET','POST'])
@login_required
def search_tool():
    u = _current_user()
    results = error = None
    q = request.form.get('q', request.args.get('q', '')).strip() if request else ''
    if q:
        try:
            con = sqlite3.connect(_CASE_DB)
            con.row_factory = sqlite3.Row
            # 본인 멤버 사건 ID 목록
            allowed_ids = {r[0] for r in con.execute('''
                SELECT DISTINCT c.id FROM cases c
                LEFT JOIN case_members m ON c.id = m.case_id
                WHERE c.owner=? OR m.username=?''', (u, u)).fetchall()}
            # 사건명 검색 (allowed_ids 필터)
            cases = [dict(r) for r in con.execute(
                '''SELECT DISTINCT c.id, c.case_number, c.name FROM cases c
                LEFT JOIN case_members m ON c.id = m.case_id
                WHERE (c.owner=? OR m.username=?) AND (c.name LIKE ? OR c.description LIKE ?)
                LIMIT 20''',
                (u, u, f'%{q}%', f'%{q}%')).fetchall()]
            # 발견사항 (allowed 사건만)
            findings = []
            if allowed_ids:
                placeholders = ','.join('?' * len(allowed_ids))
                findings = [dict(r) for r in con.execute(
                    f'''SELECT id, case_id, title, severity, category FROM findings
                    WHERE case_id IN ({placeholders})
                    AND (title LIKE ? OR description LIKE ?) LIMIT 50''',
                    list(allowed_ids) + [f'%{q}%', f'%{q}%']).fetchall()]
            # FTS5 검색 (allowed 사건만 - case_number로 필터)
            allowed_nums = {r[0] for r in con.execute(
                f'SELECT case_number FROM cases WHERE id IN ({",".join("?"*len(allowed_ids))})',
                list(allowed_ids)).fetchall()} if allowed_ids else set()
            rows = con.execute('''
                SELECT case_number, evidence_filename, content, tags,
                       snippet(search_idx, -1, '<mark>', '</mark>', '...', 30) AS snip
                FROM search_idx WHERE search_idx MATCH ? LIMIT 500
            ''', (q,)).fetchall()
            results = [dict(r) for r in rows if r['case_number'] in allowed_nums][:200]
            con.close()
            _audit('search', q, {'results': len(results)})
            return render_template('tools/search.html', results=results,
                                   cases=cases, findings=findings, q=q,
                                   current_user=u)
        except Exception as e: error = str(e)
    return render_template('tools/search.html', results=results, error=error,
                           q=q, current_user=u)


# ====================================================================
# 3. /tools/dashboard — 분석 대시보드
# ====================================================================
@bp.route('/dashboard')
@login_required
def dashboard_tool():
    u = _current_user()
    con = sqlite3.connect(_CASE_DB)
    con.row_factory = sqlite3.Row
    # 본인 멤버 사건 ID
    allowed = [r[0] for r in con.execute('''
        SELECT DISTINCT c.id FROM cases c
        LEFT JOIN case_members m ON c.id = m.case_id
        WHERE c.owner=? OR m.username=?''', (u, u)).fetchall()]
    if not allowed:
        con.close()
        return render_template('tools/dashboard.html',
                               stats={'total_cases':0,'open_cases':0,'closed_cases':0,
                                      'total_evidence':0,'total_findings':0,'total_audit':0},
                               severity={}, tool_usage={}, daily=[],
                               recent_cases=[], recent_findings=[],
                               current_user=u)
    ph = ','.join('?' * len(allowed))
    stats = {
        'total_cases': len(allowed),
        'open_cases': con.execute(f"SELECT COUNT(*) FROM cases WHERE id IN ({ph}) AND status='open'", allowed).fetchone()[0],
        'closed_cases': con.execute(f"SELECT COUNT(*) FROM cases WHERE id IN ({ph}) AND status='closed'", allowed).fetchone()[0],
        'total_evidence': con.execute(f"SELECT COUNT(*) FROM evidence WHERE case_id IN ({ph})", allowed).fetchone()[0],
        'total_findings': con.execute(f"SELECT COUNT(*) FROM findings WHERE case_id IN ({ph})", allowed).fetchone()[0],
        'total_audit': con.execute('SELECT COUNT(*) FROM audit_log WHERE user=?', (u,)).fetchone()[0],
    }
    severity = dict(con.execute(
        f'SELECT severity, COUNT(*) FROM findings WHERE case_id IN ({ph}) GROUP BY severity',
        allowed).fetchall())
    tool_usage = dict(con.execute(
        '''SELECT action, COUNT(*) FROM audit_log
        WHERE action LIKE 'tool_use:%' AND user=? GROUP BY action LIMIT 20''',
        (u,)).fetchall())
    daily = con.execute('''
        SELECT DATE(timestamp) AS d, COUNT(*) AS c FROM audit_log
        WHERE timestamp > datetime('now', '-30 days') AND user=?
        GROUP BY DATE(timestamp) ORDER BY d''', (u,)).fetchall()
    recent_cases = [dict(r) for r in con.execute(
        f'SELECT * FROM cases WHERE id IN ({ph}) ORDER BY created_at DESC LIMIT 10', allowed).fetchall()]
    recent_findings = [dict(r) for r in con.execute(
        f'''SELECT f.*, c.case_number FROM findings f
        LEFT JOIN cases c ON c.id = f.case_id
        WHERE f.case_id IN ({ph})
        ORDER BY f.created_at DESC LIMIT 10''', allowed).fetchall()]
    con.close()
    return render_template('tools/dashboard.html',
                           stats=stats, severity=severity,
                           tool_usage=tool_usage,
                           daily=[(r[0], r[1]) for r in daily],
                           recent_cases=recent_cases,
                           recent_findings=recent_findings,
                           current_user=u)


# ====================================================================
# 4. /tools/casereport — 법정 PDF 보고서
# ====================================================================
@bp.route('/case/<int:case_id>/report')
@require_role('viewer')
def case_report(case_id):
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib import colors
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak)
        from reportlab.lib.units import cm
        from reportlab.pdfbase import pdfmetrics
        from reportlab.pdfbase.ttfonts import TTFont
        try:
            pdfmetrics.registerFont(TTFont('Korean', '/usr/share/fonts/truetype/nanum/NanumGothic.ttf'))
            font_name = 'Korean'
        except Exception:
            try:
                pdfmetrics.registerFont(TTFont('Korean', '/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf'))
                font_name = 'Korean'
            except Exception:
                font_name = 'Helvetica'

        con = sqlite3.connect(_CASE_DB)
        con.row_factory = sqlite3.Row
        case = con.execute('SELECT * FROM cases WHERE id=?', (case_id,)).fetchone()
        if not case: con.close(); abort(404)
        case = dict(case)
        evidence = [dict(r) for r in con.execute(
            'SELECT * FROM evidence WHERE case_id=? ORDER BY uploaded_at', (case_id,)).fetchall()]
        findings = [dict(r) for r in con.execute(
            'SELECT * FROM findings WHERE case_id=? ORDER BY created_at', (case_id,)).fetchall()]
        bookmarks = [dict(r) for r in con.execute(
            'SELECT * FROM bookmarks WHERE case_id=? ORDER BY created_at', (case_id,)).fetchall()]
        con.close()

        buf = io.BytesIO()
        doc = SimpleDocTemplate(buf, pagesize=A4,
                                rightMargin=2*cm, leftMargin=2*cm,
                                topMargin=2*cm, bottomMargin=2*cm)
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle('TitleK', parent=styles['Title'],
                                     fontName=font_name, fontSize=20, spaceAfter=12)
        h2 = ParagraphStyle('H2K', parent=styles['Heading2'],
                            fontName=font_name, fontSize=14, spaceAfter=8, textColor=colors.HexColor('#0066cc'))
        body = ParagraphStyle('BodyK', parent=styles['BodyText'],
                              fontName=font_name, fontSize=10, leading=14)
        story = []
        story.append(Paragraph('포렌식 분석 보고서', title_style))
        story.append(Paragraph(f"<b>사건 번호:</b> {case['case_number']}", body))
        story.append(Paragraph(f"<b>사건명:</b> {case['name']}", body))
        story.append(Paragraph(f"<b>분석가:</b> {case['examiner'] or '-'}", body))
        story.append(Paragraph(f"<b>우선순위:</b> {case['priority']}", body))
        story.append(Paragraph(f"<b>상태:</b> {case['status']}", body))
        story.append(Paragraph(f"<b>생성:</b> {case['created_at']}", body))
        if case.get('closed_at'):
            story.append(Paragraph(f"<b>종료:</b> {case['closed_at']}", body))
        story.append(Spacer(1, 0.5*cm))

        if case['description']:
            story.append(Paragraph('사건 설명', h2))
            story.append(Paragraph(case['description'].replace('\n','<br/>'), body))
            story.append(Spacer(1, 0.5*cm))

        # 증거 목록
        story.append(Paragraph(f'증거 ({len(evidence)}건)', h2))
        if evidence:
            data = [['#', '파일명', 'SHA-256', '크기', '도구', '시각']]
            for i, e in enumerate(evidence, 1):
                data.append([
                    str(i), e['filename'][:30],
                    e['sha256'][:16] + '…',
                    f"{e['size']:,}" if e['size'] else '',
                    e.get('tool_used', '') or '',
                    e['uploaded_at'][:16],
                ])
            t = Table(data, repeatRows=1)
            t.setStyle(TableStyle([
                ('FONTNAME', (0,0), (-1,-1), font_name),
                ('FONTSIZE', (0,0), (-1,-1), 8),
                ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#0066cc')),
                ('TEXTCOLOR', (0,0), (-1,0), colors.white),
                ('GRID', (0,0), (-1,-1), 0.3, colors.grey),
            ]))
            story.append(t); story.append(Spacer(1, 0.5*cm))

        # 발견사항
        story.append(Paragraph(f'주요 발견사항 ({len(findings)}건)', h2))
        for i, f in enumerate(findings, 1):
            sev_color = {'critical':'#dc2626','high':'#ef4444','medium':'#f59e0b','low':'#3b82f6'}.get(f.get('severity',''), '#6b7280')
            story.append(Paragraph(
                f"<b>[{i}] {f['title']}</b> <font color='{sev_color}'>[{f.get('severity','medium')}]</font>",
                body))
            if f.get('description'):
                story.append(Paragraph(f['description'].replace('\n','<br/>'), body))
            if f.get('attack_techniques'):
                story.append(Paragraph(f"<i>MITRE ATT&CK: {f['attack_techniques']}</i>", body))
            story.append(Spacer(1, 0.3*cm))

        # 메모 / 북마크
        if bookmarks:
            story.append(Paragraph(f'분석 메모 ({len(bookmarks)}건)', h2))
            for b in bookmarks:
                story.append(Paragraph(f"<b>{b['title']}</b>", body))
                story.append(Paragraph(b.get('content','').replace('\n','<br/>'), body))
                story.append(Spacer(1, 0.2*cm))

        # 푸터: Chain of Custody
        story.append(PageBreak())
        story.append(Paragraph('Chain of Custody', h2))
        story.append(Paragraph(
            '본 보고서에 포함된 모든 증거는 SHA-256 해시 체인으로 무결성이 검증됩니다.', body))
        story.append(Paragraph(
            f"보고서 생성: {_dt.datetime.utcnow().isoformat()} UTC", body))
        story.append(Paragraph(
            "ForensicLab — 디지털 포렌식 분석 플랫폼", body))

        doc.build(story)
        buf.seek(0)
        _audit('report_generated', case['case_number'])
        _coc_record('report_generated', '0'*64, {
            'case_number': case['case_number'], 'case_id': case_id,
            'evidence_count': len(evidence), 'findings_count': len(findings)})
        return send_file(buf, mimetype='application/pdf',
                         as_attachment=True,
                         download_name=f"report_{case['case_number']}.pdf")
    except ImportError:
        return jsonify({'error': 'reportlab 미설치'}), 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ====================================================================
# 5. /tools/attack — MITRE ATT&CK 매핑
# ====================================================================
_ATTACK_DB = [
    # Tactic, Technique ID, Name, Description, Keywords
    ('Initial Access', 'T1566', 'Phishing', '피싱 이메일', ['phishing','spearphishing','이메일','첨부']),
    ('Initial Access', 'T1190', 'Exploit Public-Facing', '공개 서비스 익스플로잇', ['cve','exploit','rce','sqli']),
    ('Execution', 'T1059', 'Command and Scripting Interpreter', '명령행/스크립트 실행', ['powershell','cmd','bash','python']),
    ('Execution', 'T1059.001', 'PowerShell', 'PowerShell 실행', ['powershell','iex','invoke-expression']),
    ('Execution', 'T1059.003', 'Windows Command Shell', 'cmd.exe 실행', ['cmd.exe','cmd','batch']),
    ('Execution', 'T1059.007', 'JavaScript', 'JS 실행', ['javascript','eval','wscript.shell']),
    ('Execution', 'T1204', 'User Execution', '사용자 실행', ['lnk','docm','xlsm']),
    ('Persistence', 'T1547', 'Boot or Logon Autostart', '부팅/로그온 자동시작', ['run','runonce','startup','registry']),
    ('Persistence', 'T1547.001', 'Registry Run Keys', '레지스트리 Run', ['hklm\\software\\microsoft\\windows\\currentversion\\run']),
    ('Persistence', 'T1053', 'Scheduled Task/Job', '예약 작업', ['schtasks','at','cron','launchd']),
    ('Persistence', 'T1543', 'Create or Modify System Process', '서비스 생성', ['service','sc create','systemd']),
    ('Persistence', 'T1574', 'Hijack Execution Flow', '실행 흐름 하이재킹', ['dll hijack','sideloading']),
    ('Privilege Escalation', 'T1068', 'Exploitation for Privilege Escalation', '권한 상승 익스플로잇', ['kernel','exploit','seimpersonate']),
    ('Privilege Escalation', 'T1134', 'Access Token Manipulation', '토큰 조작', ['token','impersonate','seimpersonateprivilege']),
    ('Defense Evasion', 'T1140', 'Deobfuscate/Decode', '디오브푸/디코딩', ['base64','xor','rot13','obfuscate']),
    ('Defense Evasion', 'T1027', 'Obfuscated Files', '난독화', ['packed','obfuscate','encoded','base64']),
    ('Defense Evasion', 'T1070', 'Indicator Removal', '흔적 제거', ['clearev','wevtutil cl','rm -rf','sdelete']),
    ('Defense Evasion', 'T1218', 'System Binary Proxy Execution', 'LOLBAS', ['rundll32','regsvr32','mshta','wmic']),
    ('Defense Evasion', 'T1562', 'Impair Defenses', '방어 약화', ['defender','firewall','antivirus disable']),
    ('Credential Access', 'T1003', 'OS Credential Dumping', '자격증명 덤프', ['mimikatz','lsass','sam','ntds.dit']),
    ('Credential Access', 'T1003.001', 'LSASS Memory', 'LSASS 메모리', ['lsass','procdump','comsvcs']),
    ('Credential Access', 'T1003.002', 'SAM Hash', 'SAM 덤프', ['sam','hivedump','reg save']),
    ('Credential Access', 'T1110', 'Brute Force', '무차별 대입', ['brute force','hydra','hashcat']),
    ('Credential Access', 'T1552', 'Unsecured Credentials', '평문 자격증명', ['password','config','env']),
    ('Discovery', 'T1057', 'Process Discovery', '프로세스 정찰', ['tasklist','ps','get-process']),
    ('Discovery', 'T1018', 'Remote System Discovery', '원격 시스템 정찰', ['net view','arp','ping sweep']),
    ('Discovery', 'T1082', 'System Information', '시스템 정보', ['systeminfo','uname','hostname']),
    ('Discovery', 'T1083', 'File and Directory Discovery', '파일 정찰', ['dir','ls','find','tree']),
    ('Lateral Movement', 'T1021', 'Remote Services', '원격 서비스', ['rdp','smb','wmi','psexec']),
    ('Lateral Movement', 'T1021.001', 'RDP', 'RDP', ['rdp','mstsc','3389']),
    ('Lateral Movement', 'T1021.002', 'SMB/Admin Shares', 'SMB 공유', ['c$','admin$','ipc$']),
    ('Collection', 'T1005', 'Data from Local System', '로컬 데이터 수집', ['copy','xcopy','find','grep']),
    ('Collection', 'T1113', 'Screen Capture', '화면 캡처', ['screenshot','printscreen']),
    ('Command and Control', 'T1071', 'Application Layer Protocol', 'C2 통신', ['http c2','https c2','dns tunneling']),
    ('Command and Control', 'T1071.001', 'Web Protocols', 'HTTP/HTTPS C2', ['http','https','user-agent']),
    ('Command and Control', 'T1090', 'Proxy', '프록시 사용', ['tor','socks','vpn']),
    ('Command and Control', 'T1572', 'Protocol Tunneling', '프로토콜 터널링', ['dns tunneling','icmp tunnel']),
    ('Exfiltration', 'T1041', 'Exfil Over C2', 'C2로 데이터 유출', ['exfil','upload','c2']),
    ('Exfiltration', 'T1567', 'Exfil to Web Service', '클라우드로 유출', ['pastebin','dropbox','onedrive','mega']),
    ('Impact', 'T1486', 'Data Encrypted for Impact', '랜섬웨어', ['ransomware','encrypt','readme.txt','tor']),
    ('Impact', 'T1490', 'Inhibit System Recovery', '복구 차단', ['vssadmin delete','wbadmin','bcdedit']),
    ('Impact', 'T1485', 'Data Destruction', '데이터 파괴', ['del','rm','sdelete','cipher /w']),
    ('Impact', 'T1499', 'Endpoint DoS', '엔드포인트 DoS', ['fork bomb','infinite loop']),
]

@bp.route('/attack', methods=['GET','POST'])
def attack_tool():
    result = error = None
    if request.method == 'POST':
        text = (request.form.get('text') or '').strip()
        if not text: error = '분석 결과 텍스트 입력'
        else:
            matches = []
            lo = text.lower()
            for tactic, tid, name, desc, keywords in _ATTACK_DB:
                hit_kws = [kw for kw in keywords if kw.lower() in lo]
                if hit_kws:
                    matches.append({
                        'tactic': tactic, 'id': tid, 'name': name,
                        'description': desc, 'matched_keywords': hit_kws,
                        'url': f'https://attack.mitre.org/techniques/{tid.replace(".", "/")}/',
                    })
            # 전술별 집계
            tactics_summary = Counter(m['tactic'] for m in matches)
            result = {'matches': matches, 'tactics': dict(tactics_summary),
                      'total_techniques': len(matches),
                      'killchain_stage': max(tactics_summary, key=tactics_summary.get) if tactics_summary else None}
            _audit('attack_mapping', '', {'techniques': len(matches)})
    return render_template('tools/attack.html', result=result, error=error,
                           db_size=len(_ATTACK_DB))


# ====================================================================
# 6. /tools/threat-intel — 위협 인텔리전스
# ====================================================================
@bp.route('/threat-intel', methods=['GET','POST'])
def threat_intel_tool():
    result = error = None
    if request.method == 'POST':
        ioc = (request.form.get('ioc') or '').strip()
        vt_key = (request.form.get('vt_key') or os.environ.get('VT_API_KEY') or '').strip()
        abuseip_key = (request.form.get('abuseip_key') or os.environ.get('ABUSEIPDB_KEY') or '').strip()
        if not ioc: error = 'IOC (IP/해시/도메인) 입력'
        else:
            r = {'ioc': ioc, 'sources': {}}
            ioc_type = ('ip' if re.match(r'^\d+\.\d+\.\d+\.\d+$', ioc) else
                        'hash' if re.match(r'^[a-fA-F0-9]{32,64}$', ioc) else 'domain')
            r['ioc_type'] = ioc_type
            try:
                import requests as _req
                # VirusTotal
                if vt_key:
                    try:
                        if ioc_type == 'hash':
                            url = f'https://www.virustotal.com/api/v3/files/{ioc}'
                        elif ioc_type == 'ip':
                            url = f'https://www.virustotal.com/api/v3/ip_addresses/{ioc}'
                        else:
                            url = f'https://www.virustotal.com/api/v3/domains/{ioc}'
                        resp = _req.get(url, headers={'x-apikey': vt_key}, timeout=15)
                        if resp.ok:
                            data = resp.json().get('data', {}).get('attributes', {})
                            stats = data.get('last_analysis_stats', {})
                            r['sources']['VirusTotal'] = {
                                'malicious': stats.get('malicious', 0),
                                'suspicious': stats.get('suspicious', 0),
                                'harmless': stats.get('harmless', 0),
                                'undetected': stats.get('undetected', 0),
                                'reputation': data.get('reputation', 0),
                                'first_seen': data.get('first_seen', data.get('first_submission_date', '')),
                                'tags': data.get('tags', []),
                            }
                        else:
                            r['sources']['VirusTotal'] = {'error': f'HTTP {resp.status_code}'}
                    except Exception as e:
                        r['sources']['VirusTotal'] = {'error': str(e)}
                # AbuseIPDB
                if abuseip_key and ioc_type == 'ip':
                    try:
                        resp = _req.get('https://api.abuseipdb.com/api/v2/check',
                                        params={'ipAddress': ioc, 'maxAgeInDays': 90},
                                        headers={'Key': abuseip_key, 'Accept': 'application/json'},
                                        timeout=15)
                        if resp.ok:
                            data = resp.json().get('data', {})
                            r['sources']['AbuseIPDB'] = {
                                'abuse_confidence': data.get('abuseConfidenceScore', 0),
                                'country': data.get('countryCode', ''),
                                'usage_type': data.get('usageType', ''),
                                'isp': data.get('isp', ''),
                                'total_reports': data.get('totalReports', 0),
                                'last_reported': data.get('lastReportedAt', ''),
                            }
                    except Exception as e:
                        r['sources']['AbuseIPDB'] = {'error': str(e)}
                # 키 없으면 내장 휴리스틱
                if not vt_key and not abuseip_key:
                    r['sources']['Local'] = {'note': 'API 키 없음 — 내장 검사만',
                                             'is_private_ip': ioc_type == 'ip' and any(ioc.startswith(p) for p in ['10.','127.','192.168.','172.16.','172.17.','172.18.','172.19.','172.20.','172.21.','172.22.','172.23.','172.24.','172.25.','172.26.','172.27.','172.28.','172.29.','172.30.','172.31.'])}
            except ImportError:
                error = 'requests 미설치'
            result = r
            _audit('threat_intel', ioc, {'type': ioc_type})
    return render_template('tools/threat_intel.html', result=result, error=error)


# ====================================================================
# 7. /tools/ai-classify — AI 자동 분류
# ====================================================================
@bp.route('/ai-classify', methods=['GET','POST'])
def ai_classify_tool():
    result = error = None
    if request.method == 'POST':
        f = request.files.get('file')
        if not f or not f.filename: error = '파일 필요'
        else:
            data = f.read()
            r = {'filename': f.filename, 'size': len(data), 'tags': [], 'categories': {}}
            # 확장자 기반 카테고리
            ext = f.filename.lower().rsplit('.', 1)[-1] if '.' in f.filename else ''
            CAT_MAP = {
                'jpg':'이미지','jpeg':'이미지','png':'이미지','gif':'이미지','bmp':'이미지',
                'heic':'이미지','webp':'이미지','tiff':'이미지','svg':'이미지',
                'mp4':'비디오','mov':'비디오','avi':'비디오','mkv':'비디오','webm':'비디오',
                'mp3':'오디오','wav':'오디오','flac':'오디오','ogg':'오디오',
                'pdf':'문서','doc':'문서','docx':'문서','xls':'문서','xlsx':'문서',
                'ppt':'문서','pptx':'문서','txt':'문서','rtf':'문서','odt':'문서',
                'exe':'실행파일','dll':'실행파일','msi':'실행파일','elf':'실행파일',
                'so':'실행파일','dylib':'실행파일','app':'실행파일',
                'zip':'압축','rar':'압축','7z':'압축','tar':'압축','gz':'압축',
                'py':'코드','js':'코드','java':'코드','c':'코드','cpp':'코드',
                'go':'코드','rs':'코드','rb':'코드','php':'코드','sh':'코드',
                'sql':'데이터베이스','db':'데이터베이스','sqlite':'데이터베이스',
                'log':'로그','evtx':'로그','pcap':'네트워크',
            }
            cat = CAT_MAP.get(ext, '기타')
            r['categories']['primary'] = cat
            r['categories']['extension'] = ext
            # 매직바이트 검증
            magic = data[:16]
            r['magic'] = magic.hex()
            # 시그니처 기반 카테고리 (확장자와 다를 수도)
            SIG = [(b'MZ','실행파일 (PE)'),(b'\x7fELF','실행파일 (ELF)'),
                   (b'\xCF\xFA\xED\xFE','실행파일 (Mach-O)'),
                   (b'%PDF','문서 (PDF)'),(b'\xFF\xD8\xFF','이미지 (JPEG)'),
                   (b'\x89PNG','이미지 (PNG)'),(b'PK\x03\x04','압축/Office'),
                   (b'\xD0\xCF\x11\xE0','OLE2 (구 Office)'),
                   (b'SQLite format 3','데이터베이스 (SQLite)')]
            for sig, label in SIG:
                if magic.startswith(sig):
                    r['categories']['signature'] = label
                    if cat != label.split('(')[0].strip():
                        r['tags'].append('🚨 확장자-시그니처 불일치')
                    break
            # OpenCV 기반 이미지 분류 (있는 경우)
            if cat == '이미지':
                try:
                    import cv2
                    import numpy as np
                    img_array = np.frombuffer(data, dtype=np.uint8)
                    img = cv2.imdecode(img_array, cv2.IMREAD_COLOR)
                    if img is not None:
                        h, w = img.shape[:2]
                        r['image_size'] = f'{w}x{h}'
                        # 평균 색상
                        mean_b, mean_g, mean_r = cv2.mean(img)[:3]
                        r['avg_color'] = f'#{int(mean_r):02x}{int(mean_g):02x}{int(mean_b):02x}'
                        # 밝기
                        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
                        r['brightness'] = round(float(np.mean(gray)) / 255 * 100, 1)
                        # 흑백 vs 컬러
                        std_color = float(np.std([mean_r, mean_g, mean_b]))
                        r['color_type'] = '컬러' if std_color > 10 else '흑백/단색'
                        # 얼굴 감지 (Haar Cascade)
                        try:
                            cascade_path = cv2.data.haarcascades + 'haarcascade_frontalface_default.xml'
                            face_cascade = cv2.CascadeClassifier(cascade_path)
                            faces = face_cascade.detectMultiScale(gray, 1.1, 5)
                            r['faces_detected'] = len(faces)
                            if len(faces) > 0:
                                r['tags'].append(f'👤 얼굴 {len(faces)}개 감지')
                        except Exception: pass
                except ImportError:
                    r['note'] = 'opencv-python 미설치'
                except Exception as e:
                    r['cv_error'] = str(e)
            # 텍스트 추출 (작은 파일만)
            if cat == '문서' or len(data) < 1*1024*1024:
                try:
                    text = data.decode('utf-8', errors='ignore')
                    if text and any(c.isalpha() for c in text[:1000]):
                        # 키워드 기반 분류
                        text_lo = text.lower()
                        topic_kw = {
                            '금융': ['은행','계좌','신용카드','입금','출금','송금','transfer','account'],
                            '의료': ['진료','병원','환자','처방','medical','patient','prescription'],
                            '법률': ['소송','계약','법원','lawsuit','court','contract','legal'],
                            '인사': ['직원','채용','이력서','employee','hire','salary','resume'],
                            '기술': ['code','function','class','import','def ','algorithm','api'],
                            '악성': ['malware','exploit','payload','reverse shell','backdoor','trojan'],
                        }
                        for topic, kws in topic_kw.items():
                            hits = sum(1 for kw in kws if kw in text_lo)
                            if hits >= 2:
                                r['tags'].append(f'📄 {topic} ({hits}개 키워드)')
                except Exception: pass
            _audit('ai_classify', f.filename)
            result = r
    return render_template('tools/ai_classify.html', result=result, error=error)


# ====================================================================
# 8. /tools/plaso — Plaso 슈퍼 타임라인
# ====================================================================

# ── 디스크 이미지 사전 점검 (preflight): 파티션/파일시스템/MBR 손상 진단 ──────────
def _fs_from_bytes(b):
    """VBR(볼륨 부트 레코드) 바이트에서 파일시스템 종류 추정."""
    if len(b) < 512:
        return None
    if b[3:11] == b'NTFS    ':
        return 'NTFS'
    if b[3:11] == b'EXFAT   ':
        return 'exFAT'
    # FAT: 부트 시그니처 0x55AA 확인(오탐 방지)
    if b[510:512] == b'\x55\xAA':
        if b[82:90].startswith(b'FAT32'):
            return 'FAT32'
        if b[54:62].startswith(b'FAT1'):
            return 'FAT12/16'
    # ext2/3/4: 슈퍼블록(+1024) magic 0xEF53(LE 53 EF)@+56 + 블록크기(+24) sanity(0..6)
    if len(b) >= 1024 + 60 and b[1024 + 56:1024 + 58] == b'\x53\xEF':
        if int.from_bytes(b[1024 + 24:1024 + 28], 'little') <= 6:
            return 'ext2/3/4'
    # HFS+/HFSX: 볼륨헤더(+1024) sig 'H+'/'HX' + 버전 4/5 (2바이트만으론 오탐 → 버전까지 확인)
    if len(b) >= 1028 and b[1024:1026] in (b'H+', b'HX') and b[1026:1028] in (b'\x00\x04', b'\x00\x05'):
        return 'HFS+'
    return None


def _make_reader(path, is_e01):
    """E01(pyewf) 또는 raw 파일에 대해 (read(off,n), size, handle) 반환."""
    if is_e01:
        import pyewf
        h = pyewf.handle()
        h.open([path])
        def rd(off, n):
            h.seek(off)
            return h.read(n)
        return rd, h.get_media_size(), h
    size = os.path.getsize(path)
    fh = open(path, 'rb')
    def rd(off, n):
        fh.seek(off)
        return fh.read(n)
    return rd, size, fh


def _parse_mbr(mbr):
    valid = mbr[510:512] == b'\x55\xAA'
    parts = []
    for i in range(4):
        e = mbr[446 + i * 16: 462 + i * 16]
        ptype = e[4]
        start = int.from_bytes(e[8:12], 'little')
        sectors = int.from_bytes(e[12:16], 'little')
        if ptype != 0 and sectors > 0:
            parts.append({'idx': i + 1, 'type': hex(ptype),
                          'type_name': PARTITION_TYPES.get(ptype, '알 수 없음'),
                          'start_lba': start, 'sectors': sectors})
    return valid, parts


def _vbr_scan(reader, size, max_bytes=512 * 1024 * 1024, limit_hits=8):
    """MBR이 손상됐을 때 VBR 시그니처로 볼륨 위치를 직접 스캔(앞 512MB·조기중단으로 부하 최소화)."""
    found = []
    block = 4 * 1024 * 1024
    cap = min(size or 0, max_bytes)
    off = 0
    while off < cap and len(found) < limit_hits:
        try:
            buf = reader(off, block)
        except Exception:
            break
        if not buf:
            break
        mv = memoryview(buf)
        for s in range(0, max(0, len(buf) - 1088), 512):
            fs = _fs_from_bytes(bytes(mv[s:s + 1088]))
            if fs:
                found.append({'offset': off + s, 'sector': (off + s) // 512, 'fs': fs})
                if len(found) >= limit_hits:
                    break
        off += len(buf)
    return found, (cap < (size or 0))


def _disk_preflight(path, is_e01):
    info = {'image_type': 'E01' if is_e01 else 'raw', 'media_size': None,
            'mbr_valid': None, 'partitions': [], 'filesystems': [], 'scan': [],
            'warnings': [], 'recommend': None, 'ok': False}
    reader = handle = None
    try:
        reader, size, handle = _make_reader(path, is_e01)
        info['media_size'] = size
        # 분할/잘린 이미지 점검: 끝 섹터 읽기
        try:
            if size and size > 1024 and len(reader(size - 512, 512) or b'') < 512:
                info['warnings'].append('이미지 끝을 못 읽음 — 분할/잘린 이미지 의심')
        except Exception:
            info['warnings'].append('이미지 끝 읽기 실패 — 분할 E01(.E02+ 누락) 또는 손상 의심')
        mbr = reader(0, 512) or b''
        valid, parts = _parse_mbr(mbr)
        info['mbr_valid'] = valid
        if any(p['type'] == '0xee' for p in parts):
            info['image_type'] += ' (GPT 보호 MBR)'
        for p in parts:
            fs = _fs_from_bytes(reader(p['start_lba'] * 512, 1088) or b'')
            p['fs'] = fs
            if fs:
                info['filesystems'].append({'offset': p['start_lba'] * 512, 'fs': fs, 'source': 'MBR partition %d' % p['idx']})
        info['partitions'] = parts
        if info['filesystems']:
            info['ok'] = True
        else:
            info['warnings'].append('MBR 파티션 테이블에서 파일시스템 미발견'
                                    + ('' if valid else ' (부트시그니처 0x55AA 없음 → MBR 손상 가능성)'))
            hits, partial = _vbr_scan(reader, size)
            info['scan'] = hits
            if hits:
                info['ok'] = True
                info['recommend'] = ('MBR/파티션 테이블 손상 의심 — VBR 스캔으로 볼륨 %d개 발견. '
                                     'log2timeline은 파티션 테이블에 의존하므로 결과가 비거나 부족할 수 있음. '
                                     '/tools/mbr-repair 로 MBR 재건 후 재분석을 권장.' % len(hits))
                if partial:
                    info['warnings'].append('VBR 스캔은 앞 2GB만 수행함(전체 아님)')
            else:
                info['recommend'] = ('파일시스템 미발견 — 분할 E01(첫 조각만 업로드)·암호화 볼륨·'
                                     '비표준/원시 데이터 이미지 가능성. e01-mount 로 media_size 확인 권장.')
        return info
    except Exception as e:
        info['warnings'].append('preflight 오류: %s' % e)
        return info
    finally:
        try:
            if handle is not None:
                handle.close()
        except Exception:
            pass


def _volume_size(vbr, fs):
    """VBR 부트섹터에서 볼륨의 실제 바이트 크기 산출(carve 정확도용). 모르면 None."""
    try:
        bps = int.from_bytes(vbr[11:13], 'little') or 512
        if fs == 'NTFS':
            ts = int.from_bytes(vbr[40:48], 'little')           # total sectors @0x28
            return ts * bps if ts else None
        if fs == 'exFAT':
            vl = int.from_bytes(vbr[72:80], 'little')            # VolumeLength @0x48 (sectors)
            shift = vbr[108] if len(vbr) > 108 else 9            # BytesPerSectorShift @0x6C
            return vl * (1 << shift) if vl and 9 <= shift <= 12 else None
        if fs == 'FAT32':
            ts = int.from_bytes(vbr[32:36], 'little')            # total sectors @0x20
            return ts * bps if ts else None
        if fs == 'FAT12/16':
            ts = int.from_bytes(vbr[19:21], 'little') or int.from_bytes(vbr[32:36], 'little')
            return ts * bps if ts else None
        if fs == 'ext2/3/4':
            bc = int.from_bytes(vbr[1024 + 4:1024 + 8], 'little')      # s_blocks_count_lo
            lbs = int.from_bytes(vbr[1024 + 24:1024 + 28], 'little')   # s_log_block_size
            return bc * (1024 << lbs) if bc and lbs <= 6 else None
    except Exception:
        return None
    return None


def _carve_region(reader, start, end, out_path, chunk=8 * 1024 * 1024, cap=8 * 1024 * 1024 * 1024):
    """이미지의 [start,end) 구간을 raw 파일로 추출(볼륨 단위). cap으로 과대 추출 방지."""
    end = min(end, start + cap)
    written = 0
    with open(out_path, 'wb') as w:
        off = start
        while off < end:
            buf = reader(off, min(chunk, end - off))
            if not buf:
                break
            w.write(buf)
            off += len(buf)
            written += len(buf)
    return written


def _run_l2t_pipeline(src_path, base_tmp, whole_disk=True):
    """log2timeline + psort 실행 → (csv_path|None, returncode, stderr_tail).
    CSV(전체)는 삭제하지 않고 경로 반환 → 호출측이 병합/카운트 후 정리."""
    plaso_out = base_tmp + '.plaso'
    csv_out = base_tmp + '.csv'
    args = ['log2timeline.py', '--unattended']
    if whole_disk:
        args += ['--partitions', 'all', '--volumes', 'all']
    args += ['--workers', _PLASO_WORKERS, '--worker_memory_limit', '2147483648',
             '--storage_file', plaso_out, src_path]
    r1 = subprocess.run(_LOWPRIO + args, capture_output=True, text=True, timeout=1800)
    if os.path.exists(plaso_out):
        subprocess.run(_LOWPRIO + ['psort.py', '-w', csv_out, plaso_out, '-o', 'l2tcsv'],
                       capture_output=True, text=True, timeout=600)
        try:
            os.unlink(plaso_out)
        except Exception:
            pass
    return (csv_out if os.path.exists(csv_out) else None), r1.returncode, (r1.stderr or '')[-1500:]


@bp.route('/plaso', methods=['GET','POST'])
def plaso_tool():
    result = error = None
    if request.method == 'POST':
        f = request.files.get('file')
        if not f or not f.filename: error = '아티팩트 파일 필요'
        else:
            data = f.read()
            def _plaso_job(data, _job_id=None):
                _job_log(_job_id, 'plaso 라이브러리 확인', 5)
                # plaso 모듈 로딩 가능한지 우선 확인
                try:
                    import sys
                    if '/opt/plaso' not in sys.path:
                        sys.path.insert(0, '/opt/plaso')
                    import plaso
                    _job_log(_job_id, f'plaso v{plaso.__version__} 모듈 로딩 OK', 10)
                except Exception as e:
                    return {'error': f'plaso 모듈 로딩 실패: {e}',
                            'note': 'plaso는 dfvfs·libyal 의존성 트리가 매우 복잡하여 서버 빌드 제한적임. '
                                    '로컬 PC에서 pip install plaso 후 log2timeline.py 직접 실행 권장.'}
                tf = tempfile.NamedTemporaryFile(delete=False, suffix=os.path.splitext(f.filename)[1])
                tf.write(data); tf.close()
                is_e01 = (data[:3] == b'EVF'
                          or os.path.splitext(f.filename)[1].lower() in ('.e01', '.ex01', '.s01'))
                preflight = None
                cleanup = [tf.name]
                try:
                    # ── 1) 사전 점검: 파티션/파일시스템/MBR 손상 진단 ──
                    _job_log(_job_id, '이미지 사전 점검(파티션·파일시스템·MBR)', 12)
                    try:
                        preflight = _disk_preflight(tf.name, is_e01)
                    except Exception as _pe:
                        preflight = {'warnings': ['preflight 실패: %s' % _pe], 'filesystems': [],
                                     'scan': [], 'recommend': None}
                    _job_log(_job_id, 'preflight: ' + ('; '.join(preflight.get('warnings') or []) or 'OK'), 18)

                    # ── 2) 처리할 소스 결정 ──
                    mbr_fs = preflight.get('filesystems') or []
                    scan_vols = preflight.get('scan') or []
                    sources = []   # (path, label, whole_disk)
                    if mbr_fs:
                        sources.append((tf.name, '전체 이미지(파티션 테이블 정상)', True))
                    elif scan_vols:
                        # MBR/파티션 테이블 손상 → 탐지된 볼륨을 잘라내(carve) 직접 분석
                        _job_log(_job_id, 'MBR 손상 — 탐지 볼륨을 실제 크기로 carve 후 개별 분석', 22)
                        reader, size, handle = _make_reader(tf.name, is_e01)
                        try:
                            covered_end = 0   # 이전 볼륨이 덮은 끝(이 안의 탐지는 오탐/잔여로 스킵)
                            cnt = 0
                            for v in scan_vols:
                                if cnt >= 3:
                                    break
                                if v['offset'] < covered_end:
                                    continue
                                vbr = reader(v['offset'], 1088) or b''
                                vsz = _volume_size(vbr, v['fs'])
                                # 실제 크기를 알면 그만큼, 모르면 이미지 끝까지 (8GB cap)
                                end = (v['offset'] + vsz) if vsz else size
                                end = min(end, size, v['offset'] + 8 * 1024 * 1024 * 1024)
                                cpath = tf.name + ('.vol%d' % cnt)
                                _job_log(_job_id, 'carve @sector %d (%s, %.0fMB)'
                                         % (v['sector'], v['fs'], (end - v['offset']) / 1048576.0), 24 + cnt * 2)
                                w = _carve_region(reader, v['offset'], end, cpath)
                                covered_end = v['offset'] + (vsz or (end - v['offset']))
                                cleanup.append(cpath)
                                sources.append((cpath, 'sector %d / %s / %.0fMB' % (v['sector'], v['fs'], w / 1048576.0), False))
                                cnt += 1
                        finally:
                            try: handle.close()
                            except Exception: pass
                    else:
                        sources.append((tf.name, '전체 이미지', True))

                    # ── 3) 각 소스 log2timeline → CSV 스트리밍 병합(상한 없음) ──
                    import csv as _csv
                    merged_dir = os.path.join(_DATA_DIR, 'plaso')
                    os.makedirs(merged_dir, exist_ok=True)
                    merged_csv = os.path.join(merged_dir, '%s.csv' % (_job_id or 'job'))
                    total = 0
                    sample = []
                    SAMPLE_MAX = 500   # 결과 페이지 미리보기용(전체는 CSV 다운로드)
                    per_source, l2t_err, header_written = [], '', False
                    base = 32
                    step = max(4, int(58 / max(1, len(sources))))
                    with open(merged_csv, 'w', encoding='utf-8', newline='') as mf:
                        wr = _csv.writer(mf)
                        for idx, (sp, label, whole) in enumerate(sources):
                            _job_log(_job_id, 'log2timeline [%d/%d] %s' % (idx + 1, len(sources), label), base + idx * step)
                            csvpath, rc, errtail = _run_l2t_pipeline(sp, sp, whole_disk=whole)
                            if rc != 0 and 'command not found' in errtail.lower():
                                return {'error': 'plaso 미설치 — pip install plaso', 'stderr': errtail}
                            cnt = 0
                            if csvpath:
                                with open(csvpath, 'r', encoding='utf-8', errors='replace', newline='') as cf:
                                    for ri, row in enumerate(_csv.reader(cf)):
                                        if ri == 0 and row and str(row[0]).lower().startswith('date'):
                                            if not header_written:
                                                wr.writerow(row); header_written = True
                                            continue
                                        wr.writerow(row); cnt += 1; total += 1
                                        if len(sample) < SAMPLE_MAX:
                                            sample.append(row)
                                try: os.unlink(csvpath)
                                except Exception: pass
                            if errtail:
                                l2t_err = errtail
                            per_source.append({'source': label, 'events': cnt})
                            _job_log(_job_id, '[%d/%d] %s → %d 이벤트' % (idx + 1, len(sources), label, cnt), base + (idx + 1) * step)

                    out = {'rows': sample, 'total': total, 'per_source': per_source,
                           'preflight': preflight, 'log2timeline_stderr': l2t_err}
                    if total > 0:
                        out['download'] = '/tools/plaso/download/%s' % (_job_id or '')
                        out['summary'] = '소스 %d개에서 총 %d 이벤트 — 전체 CSV 다운로드 가능 (미리보기 %d행)' % (
                            len(per_source), total, len(sample))
                    else:
                        try: os.unlink(merged_csv)
                        except Exception: pass
                        out['diagnosis'] = preflight.get('recommend') or (
                            '타임라인 0건 — ' + ('; '.join(preflight.get('warnings') or [])
                            or '처리할 파일시스템/아티팩트를 찾지 못함.'))
                    return out
                except subprocess.TimeoutExpired:
                    return {'error': 'Plaso 시간 초과 (30분)', 'preflight': preflight}
                except FileNotFoundError:
                    return {'error': 'log2timeline.py 미설치 — pip install plaso'}
                except Exception as e:
                    return {'error': str(e), 'preflight': preflight}
                finally:
                    for p in cleanup:
                        try: os.unlink(p)
                        except Exception: pass
            job_id = _new_job(f'Plaso: {f.filename}', _plaso_job, data)
            result = {'job_id': job_id, 'redirect': f'/tools/jobs/{job_id}'}
    return render_template('tools/plaso.html', result=result, error=error)


@bp.route('/plaso/download/<job_id>')
def plaso_download(job_id):
    """완료된 plaso 잡의 전체 타임라인 CSV 다운로드."""
    if not re.match(r'^[a-f0-9]{6,40}$', job_id):
        abort(404)
    path = os.path.join(_DATA_DIR, 'plaso', job_id + '.csv')
    if not os.path.exists(path):
        abort(404)
    return send_file(path, as_attachment=True,
                     download_name='plaso_timeline_%s.csv' % job_id, mimetype='text/csv')


# ====================================================================
# 9. /tools/ocr-index — OCR 인덱싱 + 검색
# ====================================================================
_OCR_DB = Path(_DATA_DIR, 'forensiclab_ocr_idx.db')

def _init_ocr_db():
    con = sqlite3.connect(_OCR_DB)
    con.execute('''
        CREATE VIRTUAL TABLE IF NOT EXISTS ocr_idx USING fts5(
            filename, sha256 UNINDEXED, text, language UNINDEXED,
            tokenize="unicode61"
        );
    ''')
    con.commit(); con.close()

_init_ocr_db()


@bp.route('/ocr-index', methods=['GET','POST'])
def ocr_index_tool():
    result = error = None
    q = (request.args.get('q') or request.form.get('q') or '').strip()
    if request.method == 'POST' and not q:
        # 인덱싱 모드
        files = request.files.getlist('file')
        lang = request.form.get('lang', 'eng+kor')
        indexed = []
        for f in files:
            if not f or not f.filename: continue
            data = f.read()
            sha = hashlib.sha256(data).hexdigest()
            try:
                # tesseract subprocess
                tf = tempfile.NamedTemporaryFile(delete=False, suffix=os.path.splitext(f.filename)[1])
                tf.write(data); tf.close()
                r = subprocess.run(['tesseract', tf.name, '-', '-l', lang],
                                   capture_output=True, text=True, timeout=60)
                text = r.stdout.strip()
                os.unlink(tf.name)
                if text:
                    con = sqlite3.connect(_OCR_DB)
                    con.execute(
                        'INSERT INTO ocr_idx (filename, sha256, text, language) VALUES (?,?,?,?)',
                        (f.filename, sha, text, lang))
                    con.commit(); con.close()
                    indexed.append({'filename': f.filename, 'sha256': sha,
                                    'text_len': len(text),
                                    'preview': text[:300]})
                else:
                    indexed.append({'filename': f.filename, 'sha256': sha,
                                    'error': 'OCR 결과 없음'})
            except FileNotFoundError:
                error = 'tesseract 시스템 패키지 필요'
                break
            except Exception as e:
                indexed.append({'filename': f.filename, 'error': str(e)})
        if indexed:
            result = {'mode': 'indexed', 'files': indexed}
            _audit('ocr_index', '', {'count': len(indexed)})
    elif q:
        # 검색 모드
        try:
            con = sqlite3.connect(_OCR_DB)
            con.row_factory = sqlite3.Row
            rows = con.execute('''
                SELECT filename, sha256, language,
                       snippet(ocr_idx, -1, '<mark>', '</mark>', '...', 30) AS snip
                FROM ocr_idx WHERE ocr_idx MATCH ? LIMIT 100
            ''', (q,)).fetchall()
            result = {'mode': 'search', 'query': q,
                      'results': [dict(r) for r in rows]}
            con.close()
        except Exception as e: error = str(e)
    # 통계
    try:
        con = sqlite3.connect(_OCR_DB)
        total = con.execute('SELECT COUNT(*) FROM ocr_idx').fetchone()[0]
        con.close()
    except Exception: total = 0
    return render_template('tools/ocr_index.html', result=result, error=error,
                           q=q, db_size=total)


# ====================================================================
# 10. /tools/face — 얼굴/객체 인식
# ====================================================================
@bp.route('/face', methods=['GET','POST'])
def face_tool():
    result = error = None
    if request.method == 'POST':
        files = request.files.getlist('file')
        if not files: error = '이미지 필요'
        else:
            results = []
            try:
                import cv2
                import numpy as np
                cascade_path = cv2.data.haarcascades + 'haarcascade_frontalface_default.xml'
                eye_path = cv2.data.haarcascades + 'haarcascade_eye.xml'
                face_c = cv2.CascadeClassifier(cascade_path)
                eye_c = cv2.CascadeClassifier(eye_path)
                for f in files:
                    if not f or not f.filename: continue
                    data = f.read()
                    arr = np.frombuffer(data, dtype=np.uint8)
                    img = cv2.imdecode(arr, cv2.IMREAD_COLOR)
                    r = {'filename': f.filename, 'size': len(data)}
                    if img is None:
                        r['error'] = '이미지 디코드 실패'
                        results.append(r); continue
                    h, w = img.shape[:2]
                    r['image_size'] = f'{w}x{h}'
                    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
                    # 얼굴 감지
                    faces = face_c.detectMultiScale(gray, 1.1, 5, minSize=(30, 30))
                    r['faces'] = []
                    for (fx, fy, fw, fh) in faces:
                        face_gray = gray[fy:fy+fh, fx:fx+fw]
                        eyes = eye_c.detectMultiScale(face_gray, 1.1, 4)
                        r['faces'].append({
                            'x': int(fx), 'y': int(fy), 'w': int(fw), 'h': int(fh),
                            'eyes': len(eyes),
                            'pct_of_image': round((fw * fh) / (w * h) * 100, 1),
                        })
                    r['face_count'] = len(faces)
                    # 평균 색·블러 점수
                    blur_score = cv2.Laplacian(gray, cv2.CV_64F).var()
                    r['sharpness'] = round(float(blur_score), 1)
                    r['is_blurry'] = blur_score < 100
                    results.append(r)
                _audit('face_recognition', '', {'count': len(results)})
            except ImportError:
                error = 'opencv-python-headless 미설치'
            except Exception as e:
                error = str(e)
            result = {'files': results}
    return render_template('tools/face.html', result=result, error=error)
