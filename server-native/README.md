# ForensicLab — 네이티브 서버 구성 (도커 없음)

`nginx + flask(gunicorn)` 로만 돌아가는 서버에 맞춘 폴더입니다. **도커/docker-compose/Dockerfile 없음.** 앱 패키지명은 `monitor`.

## 구조
```
server-native/
├── flask/                  # 앱 루트 (서버에 그대로 올림)
│   ├── monitor/            # 앱 패키지 (create_app)
│   ├── config/             # default/development/production (경로 상대화)
│   ├── migrations/         # flask-migrate
│   ├── data/               # SQLite DB (런타임 생성)
│   ├── requirements.txt
│   ├── gunicorn.conf.py    # 127.0.0.1:5000 바인드 (nginx 뒤)
│   └── wsgi.py             # gunicorn 진입점
├── nginx/
│   └── forensic.conf       # reverse proxy → 127.0.0.1:5000
├── forensic.service        # systemd 유닛 (gunicorn 자동기동)
├── deploy.sh               # 원클릭 설치 스크립트
└── README.md
```

## 요청별 동작
| 구성 요소 | 내용 |
|-----------|------|
| nginx | `forensic.conf` — 외부 포트 → `127.0.0.1:5000` 프록시 (도커 hostname `flask` 아님) |
| flask | gunicorn 으로 `monitor:create_app()` 실행, systemd 가 관리 |
| DB | `flask/data/forensic.db` 상대경로 자동 |

## 배포 (서버에서)
```bash
# 이 폴더(server-native)를 서버로 복사 후
NGINX_PORT=405 bash deploy.sh      # 외부 포트 405 로 설치
```
`deploy.sh` 가 하는 일: 시스템 패키지 설치 → venv+pip → nginx 설정 등록/reload → systemd 등록/기동.
경로·사용자·포트는 현재 위치/실행 계정에 맞춰 자동 치환됩니다.

## 수동 실행 (확인용)
```bash
cd flask
python3 -m venv venv && . venv/bin/activate
pip install -r requirements.txt
gunicorn --config gunicorn.conf.py "monitor:create_app()"   # 127.0.0.1:5000
# 별도로 nginx 가 80(또는 405) → 5000 프록시
```

## 관리
```bash
sudo systemctl restart forensic       # 앱 재시작
sudo systemctl status forensic        # 상태
journalctl -u forensic -f             # 로그
sudo nginx -s reload                  # nginx.conf 변경 후
```

## 참고
- 무거운 포렌식 라이브러리(pytsk3·plaso·volatility3·libyal·yara·tesseract)는 함수 내부 지연 import 라, 빠지면 해당 도구만 실행 시점에 실패하고 앱 부팅에는 영향 없음.
- `forensic.service` 의 `User`/`WorkingDirectory`/`ExecStart` 경로는 `deploy.sh` 가 자동 치환하지만, 수동 등록 시 직접 맞춰야 함.
