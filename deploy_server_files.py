import paramiko

HOST, USER, PASS = '10.8.0.2', 'rndp', 'cjm@0124'
ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect(HOST, username=USER, password=PASS)
sftp = ssh.open_sftp()

MODELS = r"""from hospital import db
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
"""

MAIN = r"""from flask import Blueprint, render_template, request, url_for, redirect, session
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
"""

with sftp.open('/home/ruddls030/forensic/flask/hospital/models.py', 'w') as f:
    f.write(MODELS)
print('models.py done')

with sftp.open('/home/ruddls030/forensic/flask/hospital/views/main.py', 'w') as f:
    f.write(MAIN)
print('main.py done')

# requirements.txt - add dpkt
_, o, _ = ssh.exec_command('cat /home/ruddls030/forensic/flask/requirements.txt')
req = o.read().decode()
if 'dpkt' not in req:
    with sftp.open('/home/ruddls030/forensic/flask/requirements.txt', 'w') as f:
        f.write(req.rstrip() + '\ndpkt\n')
    print('requirements.txt updated')
else:
    print('dpkt already in requirements')

sftp.close()
ssh.close()
print('all server files written')

