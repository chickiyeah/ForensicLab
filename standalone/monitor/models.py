from monitor import db
from datetime import datetime
import uuid


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
