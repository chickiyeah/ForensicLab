import os
SECRET_KEY = os.environ.get('SECRET_KEY', 'forensiclab-secret-2026')
SQLALCHEMY_DATABASE_URI = 'sqlite:////app/data/forensic.db'
SQLALCHEMY_TRACK_MODIFICATIONS = False
MAX_CONTENT_LENGTH = 200 * 1024 * 1024
