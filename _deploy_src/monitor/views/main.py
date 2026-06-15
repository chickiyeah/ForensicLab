from flask import Blueprint, render_template, request, url_for, redirect, session
from werkzeug.security import generate_password_hash, check_password_hash
from monitor.models import User, AnalysisLog
from monitor import db
from sqlalchemy import func

bp = Blueprint('main', __name__, url_prefix='/')


@bp.route('/')
def index():
    from monitor.views.tools import _TOOL_CATALOG

    def _h(n):
        n = float(n or 0)
        for u in ('B', 'KB', 'MB', 'GB', 'TB'):
            if n < 1024:
                return ('%.0f %s' % (n, u)) if u == 'B' else ('%.1f %s' % (n, u))
            n /= 1024
        return '%.1f PB' % n

    try:
        n_analyses = AnalysisLog.query.count()
        n_bytes = db.session.query(func.coalesce(func.sum(AnalysisLog.file_size), 0)).scalar() or 0
        n_users = User.query.count()
    except Exception:
        n_analyses = n_bytes = n_users = 0
    return render_template('index.html',
                           stat_analyses=n_analyses,
                           stat_data=_h(n_bytes),
                           stat_users=n_users,
                           stat_tools=len(_TOOL_CATALOG))


@bp.route('/intro')
def intro():
    return render_template('intro.html')


@bp.route('/login', methods=['GET', 'POST'])
def login():
    if session.get('user_id'):
        return redirect(url_for('main.index'))
    error = None
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
            session['username'] = user.username
            nxt = session.pop('next_url', None)
            return redirect(nxt or url_for('main.index'))
        error = '아이디 또는 비밀번호가 올바르지 않습니다.'
    return render_template('login.html', error=error)


@bp.route('/signup', methods=['GET', 'POST'])
def signup():
    if session.get('user_id'):
        return redirect(url_for('main.index'))
    error = None
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        confirm = request.form.get('confirm', '')
        if not username or not email or not password:
            error = '모든 필드를 입력하세요.'
        elif len(username) < 3:
            error = '아이디는 3자 이상이어야 합니다.'
        elif password != confirm:
            error = '비밀번호가 일치하지 않습니다.'
        elif len(password) < 6:
            error = '비밀번호는 6자 이상이어야 합니다.'
        elif User.query.filter_by(username=username).first():
            error = '이미 사용중인 아이디입니다.'
        elif User.query.filter_by(email=email).first():
            error = '이미 사용중인 이메일입니다.'
        else:
            user = User(username=username, email=email,
                        password_hash=generate_password_hash(password))
            db.session.add(user)
            db.session.commit()
            session['user_id'] = user.id
            session['username'] = user.username
            nxt = session.pop('next_url', None)
            return redirect(nxt or url_for('main.index'))
    return render_template('signup.html', error=error)


@bp.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('main.index'))


@bp.route('/mypage', methods=['GET', 'POST'])
def mypage():
    if not session.get('user_id'):
        return redirect(url_for('main.login'))
    user = User.query.get(session['user_id'])
    if not user:
        session.clear()
        return redirect(url_for('main.login'))

    pw_error = None
    pw_success = False

    if request.method == 'POST' and request.form.get('action') == 'change_password':
        current = request.form.get('current_password', '')
        new_pw = request.form.get('new_password', '')
        confirm = request.form.get('confirm_password', '')
        if not check_password_hash(user.password_hash, current):
            pw_error = '현재 비밀번호가 올바르지 않습니다.'
        elif len(new_pw) < 6:
            pw_error = '새 비밀번호는 6자 이상이어야 합니다.'
        elif new_pw != confirm:
            pw_error = '새 비밀번호가 일치하지 않습니다.'
        else:
            user.password_hash = generate_password_hash(new_pw)
            db.session.commit()
            pw_success = True

    recent_logs = (AnalysisLog.query
                   .filter_by(user_id=user.id)
                   .order_by(AnalysisLog.created.desc())
                   .limit(10).all())

    tool_stats = (db.session.query(
                      AnalysisLog.tool,
                      AnalysisLog.tool_label,
                      func.count(AnalysisLog.id).label('cnt'))
                  .filter(AnalysisLog.user_id == user.id)
                  .group_by(AnalysisLog.tool)
                  .order_by(func.count(AnalysisLog.id).desc())
                  .all())

    total_logs = sum(s.cnt for s in tool_stats)
    tool_count = len(tool_stats)

    return render_template('mypage.html',
                           user=user,
                           recent_logs=recent_logs,
                           tool_stats=tool_stats,
                           total_logs=total_logs,
                           tool_count=tool_count,
                           pw_error=pw_error,
                           pw_success=pw_success)
