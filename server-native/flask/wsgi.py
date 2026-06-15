"""gunicorn 진입점.

    gunicorn --config gunicorn.conf.py wsgi:app
또는 (서버와 동일하게)
    gunicorn --config gunicorn.conf.py "monitor:create_app()"
"""
from monitor import create_app
import monitor.models  # noqa: F401 - 모든 모델(User/AnalysisLog/Sensor) 등록

app = create_app()
