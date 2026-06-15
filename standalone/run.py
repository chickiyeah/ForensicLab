"""ForensicLab standalone 실행 진입점 (도커/gunicorn 불필요).

    python run.py            # 0.0.0.0:5000, 디버그 ON
    PORT=8080 python run.py  # 포트 변경

윈도우 PowerShell:
    $env:PORT=8080; python run.py
"""
import os

from monitor import create_app, db
import monitor.models  # noqa: F401 - 모든 모델(User/AnalysisLog/Sensor) 등록용

app = create_app()

if __name__ == "__main__":
    # standalone: 마이그레이션 없이 누락된 테이블 자동 생성
    with app.app_context():
        db.create_all()

    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", "5000"))
    debug = os.environ.get("DEBUG", "1") not in ("0", "false", "False")
    print(f" * ForensicLab standalone -> http://{host}:{port}")
    app.run(host=host, port=port, debug=debug)
