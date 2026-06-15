# ForensicLab — Standalone (도커 없이 실행)

서버 `/home/ruddls030/forensic/flask` 를 그대로 내려받아 **도커/nginx/gunicorn 없이** 로컬에서 구동하도록 구성한 사본입니다.

## 구조
```
standalone/
├── run.py                 # ★ 실행 진입점 (도커 대체)
├── requirements-core.txt  # 최소 구동 의존성
├── requirements.txt       # 서버 전체 의존성 (리눅스 권장)
├── config/                # default/development/production (경로 상대화 완료)
├── monitor/               # 앱 패키지 (구 hospital)
│   ├── __init__.py        # create_app() — /app 하드코딩 제거됨
│   ├── models.py / forms.py
│   ├── views/             # main, tools, tools_extra*, monitor
│   ├── templates/  static/
├── data/                  # SQLite DB (forensic.db) — 자동 생성/사용
└── migrations/            # (선택) flask-migrate
```

## 빠른 실행 (Windows PowerShell)
```powershell
cd E:\forensic\standalone
python -m venv venv
venv\Scripts\Activate.ps1
pip install -r requirements-core.txt
python run.py
```
→ 브라우저에서 http://localhost:5000

포트 변경: `$env:PORT=8080; python run.py`

## 리눅스 / WSL (전체 기능)
```bash
cd standalone
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt      # 디스크/타임라인/메모리 분석까지
python run.py
```
> `requirements.txt` 의 `pytsk3`, `libyal` 계열, `plaso`, `volatility3`, `yara-python`,
> `pytesseract`, `pyzbar` 등은 리눅스 네이티브 라이브러리에 의존합니다. Windows 에서는
> 설치가 어려워, 순수 파이썬 도구(hash, strings, carve, encoding 등) 위주로만 동작합니다.

## 동작 원리 (도커가 하던 일 대체)
| 도커 | standalone |
|------|-----------|
| `gunicorn monitor:create_app()` | `python run.py` (Flask 내장 서버) |
| `APP_CONFIG_FILE=/app/config/production.py` | `config/production.py` 기본 자동 로드 |
| `sqlite:////app/data/forensic.db` | `data/forensic.db` 상대 경로 자동 |
| DB 마이그레이션 | `run.py` 가 `db.create_all()` 로 누락 테이블 자동 생성 |

## 운영 배포(선택)
- 리눅스/Mac: `gunicorn --config gunicorn.conf.py "monitor:create_app()"`
- Windows 프로덕션: `pip install waitress` 후
  `waitress-serve --port=5000 --call monitor:create_app`
```
```
