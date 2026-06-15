import os

# flask/ 프로젝트 루트 (이 파일은 flask/config/default.py)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.environ.get('DATA_DIR', os.path.join(BASE_DIR, 'data'))
os.makedirs(DATA_DIR, exist_ok=True)

_db_path = os.path.join(DATA_DIR, 'forensic.db').replace('\\', '/')

SECRET_KEY = os.environ.get('SECRET_KEY', 'forensiclab-secret-2026')
SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'sqlite:///' + _db_path)
SQLALCHEMY_TRACK_MODIFICATIONS = False
MAX_CONTENT_LENGTH = int(os.environ.get('MAX_CONTENT_LENGTH_BYTES', 16 * 1024 * 1024 * 1024))  # 기본 16 GB
