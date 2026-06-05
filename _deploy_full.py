"""전체 배포 스크립트 - 새 서버 10.8.0.17"""
import paramiko, os

HOST, USER, PASS = '10.8.0.17', 'ruddls030', 'dlstn0722'
BASE_LOCAL  = r'E:\forensic'
BASE_REMOTE = '/home/ruddls030/forensic/flask'

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect(HOST, username=USER, password=PASS)
sftp = ssh.open_sftp()


def mkdir_p(path):
    parts = path.split('/')
    cur = ''
    for p in parts:
        if not p:
            cur = '/'
            continue
        cur = cur.rstrip('/') + '/' + p
        try:
            sftp.stat(cur)
        except FileNotFoundError:
            sftp.mkdir(cur)


def wr(path, content):
    with sftp.open(path, 'w') as f:
        f.write(content)
    print(f'  WRITE {path.replace(BASE_REMOTE + "/", "")}')


def up(local_rel, remote_rel):
    local = os.path.join(BASE_LOCAL, local_rel)
    remote = f'{BASE_REMOTE}/{remote_rel}'
    sftp.put(local, remote)
    print(f'  PUT   {remote_rel}')


# ── 디렉토리 생성 ─────────────────────────────────────
for d in [
    f'{BASE_REMOTE}/config',
    f'{BASE_REMOTE}/data',
    f'{BASE_REMOTE}/hospital',
    f'{BASE_REMOTE}/hospital/views',
    f'{BASE_REMOTE}/hospital/templates',
    f'{BASE_REMOTE}/hospital/templates/tools',
    f'{BASE_REMOTE}/hospital/templates/monitor',
    f'{BASE_REMOTE}/hospital/static',
    f'{BASE_REMOTE}/hospital/static/css',
    f'{BASE_REMOTE}/hospital/static/js',
    f'{BASE_REMOTE}/hospital/static/uploads',
    f'{BASE_REMOTE}/hospital/static/tools',
    f'{BASE_REMOTE}/migrations',
]:
    mkdir_p(d)
print('[1/6] Directories OK')

# ── requirements.txt ──────────────────────────────────
wr(f'{BASE_REMOTE}/requirements.txt',
"""flask==3.0.0
flask-sqlalchemy
flask-migrate
flask-wtf
wtforms
gunicorn==21.2.0
Pillow
pypdf
dpkt
""")

# ── gunicorn.conf.py ──────────────────────────────────
wr(f'{BASE_REMOTE}/gunicorn.conf.py',
"""bind = '0.0.0.0:5000'
workers = 1
reload = True
reload_extra_files = ['hospital/templates', 'hospital/static/css/my.css']
""")

# ── config/ ───────────────────────────────────────────
wr(f'{BASE_REMOTE}/config/__init__.py', '')
wr(f'{BASE_REMOTE}/config/default.py',
"""import os
SECRET_KEY = os.environ.get('SECRET_KEY', 'forensiclab-secret-2026')
SQLALCHEMY_DATABASE_URI = 'sqlite:////app/data/forensic.db'
SQLALCHEMY_TRACK_MODIFICATIONS = False
MAX_CONTENT_LENGTH = 200 * 1024 * 1024
""")
wr(f'{BASE_REMOTE}/config/production.py',
"""from config.default import *
DEBUG = False
""")
wr(f'{BASE_REMOTE}/config/development.py',
"""from config.default import *
DEBUG = True
""")
print('[2/6] Config files OK')

# ── hospital/__init__.py ──────────────────────────────
wr(f'{BASE_REMOTE}/hospital/__init__.py',
"""from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
import os

db = SQLAlchemy()
migrate = Migrate()


def create_app():
    app = Flask(__name__, template_folder='templates', static_folder='static')

    cfg = os.environ.get('APP_CONFIG_FILE', '/app/config/production.py')
    app.config.from_pyfile(cfg)

    os.makedirs('/app/data', exist_ok=True)

    db.init_app(app)
    migrate.init_app(app, db)

    from hospital.views.main import bp as main_bp
    from hospital.views.tools import bp as tools_bp
    from hospital.views.monitor import bp as monitor_bp

    app.register_blueprint(main_bp)
    app.register_blueprint(tools_bp)
    app.register_blueprint(monitor_bp)

    return app
""")

# ── hospital/models.py ────────────────────────────────
wr(f'{BASE_REMOTE}/hospital/models.py',
"""from hospital import db
from datetime import datetime
from sqlalchemy import Numeric
import uuid


class Sensor(db.Model):
    idx = db.Column(db.Integer, primary_key=True)
    part = db.Column(db.String(200), nullable=False)
    data = db.Column(Numeric(precision=6, scale=2), default=0)
    regdate = db.Column(db.DateTime, default=datetime.now)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    created = db.Column(db.DateTime, default=datetime.now)
    analysis_logs = db.relationship('AnalysisLog', backref='user', lazy=True)


class AnalysisLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    tool = db.Column(db.String(50), nullable=False)
    tool_label = db.Column(db.String(100))
    filename = db.Column(db.String(255))
    file_size = db.Column(db.Integer)
    summary = db.Column(db.Text)
    result_json = db.Column(db.Text)
    share_token = db.Column(db.String(36), unique=True,
                            default=lambda: str(uuid.uuid4()))
    created = db.Column(db.DateTime, default=datetime.now)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
""")

# ── hospital/forms.py ─────────────────────────────────
wr(f'{BASE_REMOTE}/hospital/forms.py',
"""from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField
from wtforms.validators import DataRequired, Email, Length, EqualTo


class LoginForm(FlaskForm):
    username = StringField('아이디', validators=[DataRequired()])
    password = PasswordField('비밀번호', validators=[DataRequired()])


class SignupForm(FlaskForm):
    username = StringField('아이디', validators=[DataRequired(), Length(min=3, max=50)])
    email = StringField('이메일', validators=[DataRequired(), Email()])
    password = PasswordField('비밀번호', validators=[DataRequired(), Length(min=6)])
    confirm = PasswordField('비밀번호 확인', validators=[EqualTo('password')])
""")

# ── hospital/views/__init__.py ────────────────────────
wr(f'{BASE_REMOTE}/hospital/views/__init__.py', '')

# ── hospital/views/main.py ────────────────────────────
wr(f'{BASE_REMOTE}/hospital/views/main.py',
"""from flask import Blueprint, render_template, request, url_for, redirect, session
from werkzeug.security import generate_password_hash, check_password_hash
from hospital.models import User
from hospital import db

bp = Blueprint('main', __name__, url_prefix='/')


@bp.route('/')
def index():
    return render_template('index.html')


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
            return redirect(url_for('main.index'))
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
            return redirect(url_for('main.index'))
    return render_template('signup.html', error=error)


@bp.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('main.index'))
""")

# ── hospital/views/monitor.py ─────────────────────────
wr(f'{BASE_REMOTE}/hospital/views/monitor.py',
"""from flask import Blueprint, render_template, request, jsonify
from hospital.models import Sensor
from hospital import db

bp = Blueprint('monitor', __name__, url_prefix='/monitor')


@bp.route('/sensor')
def sensor():
    sensors = Sensor.query.order_by(Sensor.regdate.desc()).limit(100).all()
    return render_template('monitor/sensor.html', sensors=sensors)


@bp.route('/sensor/data', methods=['POST'])
def sensor_data():
    part = request.form.get('part', '').strip()
    data = request.form.get('data', 0)
    if not part:
        return jsonify(error='part required'), 400
    s = Sensor(part=part, data=data)
    db.session.add(s)
    db.session.commit()
    return jsonify(ok=True)


@bp.route('/sensor/api')
def sensor_api():
    sensors = Sensor.query.order_by(Sensor.regdate.desc()).limit(50).all()
    return jsonify([{
        'part': s.part,
        'data': float(s.data or 0),
        'regdate': s.regdate.strftime('%Y-%m-%d %H:%M:%S'),
    } for s in sensors])
""")
print('[3/6] Python source files OK')

# ── 센서 모니터링 템플릿 ──────────────────────────────
wr(f'{BASE_REMOTE}/hospital/templates/monitor/sensor.html',
"""{% extends 'base.html' %}
{% block content %}
<div class="page-hero">
  <div class="container">
    <div class="d-flex align-items-center gap-3 mb-2">
      <a href="/" class="text-dim text-decoration-none small"><i class="bi bi-house me-1"></i>홈</a>
      <i class="bi bi-chevron-right text-dim small"></i>
      <span class="text-accent small">센서 모니터링</span>
    </div>
    <h1 class="page-title"><i class="bi bi-activity me-2 text-accent"></i>센서 모니터링</h1>
    <p class="page-sub">IoT 센서 데이터를 실시간으로 모니터링합니다.</p>
  </div>
</div>
<div class="container pb-5">
  <div class="tool-panel">
    <h6 class="panel-title"><i class="bi bi-database me-2"></i>최근 센서 데이터</h6>
    {% if sensors %}
    <div class="table-responsive">
      <table class="table table-dark table-hover">
        <thead><tr><th>파트</th><th>데이터</th><th>시간</th></tr></thead>
        <tbody>
          {% for s in sensors %}
          <tr>
            <td>{{ s.part }}</td>
            <td>{{ s.data }}</td>
            <td>{{ s.regdate.strftime('%Y-%m-%d %H:%M:%S') }}</td>
          </tr>
          {% endfor %}
        </tbody>
      </table>
    </div>
    {% else %}
    <div class="empty-state"><i class="bi bi-activity"></i><p>센서 데이터가 없습니다.</p></div>
    {% endif %}
  </div>
</div>
{% endblock %}
""")

# ── static/js/scripts.js ──────────────────────────────
wr(f'{BASE_REMOTE}/hospital/static/js/scripts.js',
"""function copyShareLink(token) {
  navigator.clipboard.writeText(location.origin + '/tools/share/' + token).then(function() {
    var btn = event.currentTarget;
    var orig = btn.innerHTML;
    btn.innerHTML = '<i class="bi bi-check me-1"></i>복사됨';
    setTimeout(function() { btn.innerHTML = orig; }, 2000);
  });
}
""")
print('[4/6] Inline templates & JS OK')

# ── 로컬 파일 업로드 ──────────────────────────────────
local_to_remote = [
    (r'Dockerfile',                          'Dockerfile'),
    (r'views\tools.py',                      'hospital/views/tools.py'),
    (r'templates\base.html',                 'hospital/templates/base.html'),
    (r'templates\navbar.html',               'hospital/templates/navbar.html'),
    (r'templates\index.html',                'hospital/templates/index.html'),
    (r'templates\intro.html',                'hospital/templates/intro.html'),
    (r'templates\login.html',                'hospital/templates/login.html'),
    (r'templates\signup.html',               'hospital/templates/signup.html'),
    (r'templates\tools\index.html',          'hospital/templates/tools/index.html'),
    (r'templates\tools\hash.html',           'hospital/templates/tools/hash.html'),
    (r'templates\tools\carve.html',          'hospital/templates/tools/carve.html'),
    (r'templates\tools\mbr.html',            'hospital/templates/tools/mbr.html'),
    (r'templates\tools\mbr_repair.html',     'hospital/templates/tools/mbr_repair.html'),
    (r'templates\tools\strings.html',        'hospital/templates/tools/strings.html'),
    (r'templates\tools\log.html',            'hospital/templates/tools/log.html'),
    (r'templates\tools\gps.html',            'hospital/templates/tools/gps.html'),
    (r'templates\tools\metadata.html',       'hospital/templates/tools/metadata.html'),
    (r'templates\tools\timeline.html',       'hospital/templates/tools/timeline.html'),
    (r'templates\tools\pcap.html',           'hospital/templates/tools/pcap.html'),
    (r'templates\tools\history.html',        'hospital/templates/tools/history.html'),
    (r'templates\tools\share.html',          'hospital/templates/tools/share.html'),
    (r'templates\tools\report.html',         'hospital/templates/tools/report.html'),
    (r'static\css\my.css',                   'hospital/static/css/my.css'),
    (r'static\tools\forensiclab_mbr_repair.py', 'hospital/static/tools/forensiclab_mbr_repair.py'),
]

BASE_LOCAL = r'E:\forensic'
for local_rel, remote_rel in local_to_remote:
    local = os.path.join(BASE_LOCAL, local_rel)
    if os.path.exists(local):
        sftp.put(local, f'{BASE_REMOTE}/{remote_rel}')
        print(f'  PUT   {remote_rel}')
    else:
        print(f'  SKIP  {local_rel} (not found)')
print('[5/6] Local files uploaded')

# ── docker-compose.yml 업데이트 ───────────────────────
sftp.put(r'E:\forensic\docker-compose.yml', '/home/ruddls030/forensic/docker-compose.yml')
print('  PUT   docker-compose.yml')

sftp.close()

# ── Docker 재빌드 & 재시작 ─────────────────────────────
print('[6/6] Rebuilding Docker...')
cmd = (
    'cd /home/ruddls030/forensic && '
    'docker-compose down && '
    'docker-compose build flask && '
    'docker-compose up -d'
)
_, o, e = ssh.exec_command(cmd, timeout=300)
stdout = o.read().decode()
stderr = e.read().decode()
if stdout:
    print(stdout[-3000:])
if stderr:
    print('[stderr]', stderr[-2000:])

# ── DB 마이그레이션 ───────────────────────────────────
import time
print('Waiting 5s for containers to start...')
time.sleep(5)

print('Running db init + upgrade...')
_, o2, e2 = ssh.exec_command(
    'cd /home/ruddls030/forensic && '
    'docker-compose exec -T forensic-flask '
    'flask --app "hospital:create_app()" db init 2>&1 || true && '
    'docker-compose exec -T forensic-flask '
    'flask --app "hospital:create_app()" db migrate -m "init" 2>&1 || true && '
    'docker-compose exec -T forensic-flask '
    'flask --app "hospital:create_app()" db upgrade 2>&1',
    timeout=120
)
out2 = o2.read().decode()
err2 = e2.read().decode()
print(out2 or '(no output)')
if err2:
    print('[migrate stderr]', err2[:1000])

ssh.close()
print('\nDone! http://10.8.0.17:405')
