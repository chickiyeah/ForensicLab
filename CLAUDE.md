# ForensicLab 프로젝트

## 개요
디지털 포렌식 분석 웹 플랫폼. 원격 서버에 Docker로 배포된 nginx + Flask 구조.

## 서버 정보
| 항목 | 값 |
|------|-----|
| 서버 IP | 10.8.0.17 |
| SSH ID | ruddls030 |
| SSH PW | dlstn0722 |
| 외부 접속 URL | http://10.8.0.17:405 |
| 프로젝트 경로 | /home/ruddls030/forensic |
| Flask 소스 경로 | /home/ruddls030/forensic/flask |

## 컨테이너 구조
```
forensic-nginx   nginx:alpine     0.0.0.0:405 → 80 → flask:5000
forensic-flask   forensic-flask   gunicorn (workers=1, --reload)
```

### docker-compose 주요 설정
- `privileged: true` — 서버 연결 외부 블록 장치 접근용
- Flask 소스 바인드 마운트 (`./flask:/app`) — 파일 수정 시 gunicorn 자동 reload
- nginx config 바인드 마운트 (`./nginx/nginx.conf`) — 수정 후 `docker-compose exec forensic-nginx nginx -s reload` 필요

### 컨테이너 관리
```bash
cd /home/ruddls030/forensic

docker compose ps           # 상태 확인
docker compose logs -f      # 로그 스트림
docker compose down         # 중지
docker compose up -d        # 시작
docker compose build flask  # Flask 이미지 재빌드 (requirements 변경 시)
docker compose up -d        # 재시작
docker restart forensic-flask  # 빠른 재시작 (템플릿만 바꿀 때)
```

## Flask 앱 구조
```
/home/ruddls030/forensic/flask/
├── Dockerfile
├── gunicorn.conf.py          # reload_extra_files = [templates/, my.css]
├── requirements.txt
├── config/
│   ├── default.py
│   ├── development.py
│   └── production.py         # APP_CONFIG_FILE 환경변수로 지정
├── hospital/
│   ├── __init__.py           # create_app() — blueprints 등록
│   ├── models.py
│   ├── forms.py
│   ├── views/
│   │   ├── main.py           # blueprint: main  (/, /intro, /login, /signup 등)
│   │   ├── monitor.py        # blueprint: monitor (/monitor/sensor 등)
│   │   └── tools.py          # blueprint: tools  (/tools/*)
│   ├── templates/
│   │   ├── base.html
│   │   ├── navbar.html
│   │   ├── index.html
│   │   ├── intro.html
│   │   └── tools/
│   │       ├── index.html
│   │       ├── hash.html
│   │       ├── carve.html
│   │       ├── mbr.html
│   │       ├── mbr_repair.html
│   │       ├── strings.html
│   │       ├── log.html
│   │       ├── gps.html
│   │       └── metadata.html
│   └── static/
│       ├── css/my.css
│       ├── js/scripts.js
│       ├── uploads/
│       └── tools/
│           └── forensiclab_mbr_repair.py  # 로컬 실행용 MBR 복구 스크립트
└── migrations/
```

## 설치된 패키지
### apt (Dockerfile)
`lrzsz` `unzip` `vsftpd` `nano` `util-linux`

### pip (requirements.txt)
`flask==3.0.0` `flask-sqlalchemy` `flask-migrate` `flask-wtf` `wtforms`
`gunicorn==21.2.0` `Pillow` `pypdf`

## 구현된 도구 목록

| URL | 도구명 | 원본 파일 | 기능 |
|-----|--------|----------|------|
| `/tools/hash` | 해시 검증 | `0316.py` | MD5·SHA1·SHA256·SHA512 계산, 두 값 비교 |
| `/tools/carve` | 파일 카빙 | `web/crawfile.py` | GIF·JPEG·PNG·PDF·ZIP 시그니처 탐색·복구, ZIP 다운로드 |
| `/tools/mbr` | MBR 분석 | `anl*.py` | 파티션 테이블 파싱, VBR 스캔, 헥스 덤프 (읽기 전용) |
| `/tools/mbr-repair` | MBR 복구 | `web/mbrrepair.py` | VBR 스캔 후 MBR 재건 (서버 연결 외부 장치 또는 이미지 파일) |
| `/tools/strings` | 문자열 추출 | 신규 | ASCII·Unicode 추출, 키워드 필터 |
| `/tools/log` | 로그 분석 | 신규 | Apache·Syslog·Windows Event 파싱, 공격 패턴 탐지 |
| `/tools/gps` | GPS 추출 | 신규 | EXIF GPS 좌표 추출, Leaflet 지도 표시 |
| `/tools/metadata` | 메타데이터 추출 | 신규 | 이미지 EXIF·카메라·촬영설정, PDF 속성, 파일 해시 |
| `/tools/mbr-repair/download-script` | 로컬 MBR 복구 스크립트 | 신규 | 유저 PC에서 직접 실행하는 Python 스크립트 다운로드 |
| `/monitor/sensor` | 센서 모니터링 | 기존 | IoT 센서 데이터 실시간 모니터링 |

## MBR 복구 도구 관련 중요 사항

### 서버 측 장치 접근 (`/tools/mbr-repair`)
- `privileged: true` 컨테이너에서 실행
- `/proc/mounts` 파싱으로 서버 OS 디스크 자동 탐지 → 선택·입력 모두 차단
- `lsblk` API(`/tools/mbr-repair/devices`)로 외부 연결 장치 목록 제공
- 허용 경로: `/dev/sd*`, `/dev/nvme*`, `/dev/vd*`, `/tmp/mbrfix_*`
- **서버에 꽂힌 외부 장치만 대상** — 서버 자체 디스크 접근 불가

### 로컬 실행 스크립트 (`forensiclab_mbr_repair.py`)
- 유저 PC에 연결된 디스크 대상
- Windows(`\\.\PhysicalDrive*`)·Linux(`/dev/sd*`) 모두 지원
- OS 디스크 자동 탐지 및 차단
- 면책 조항 포함, `YES` 타이핑으로만 실행 가능
- **브라우저는 로컬 디스크 직접 접근 불가 → 스크립트 다운로드 방식**

## 디자인 시스템
- 다크 테마 (`#070b14` 배경)
- 포인트 컬러: `#00d4ff` (cyan)
- Bootstrap 5.3.3 + Bootstrap Icons 1.11.3
- CSS 변수: `--bg`, `--bg-card`, `--border`, `--accent`, `--text`, `--text-dim`

## 로컬 작업 파일 위치
```
E:\forensic\
├── CLAUDE.md
├── deploy.py                 # 초기 배포 스크립트
├── docker-compose.yml        # 서버 업로드용 로컬 사본
├── Dockerfile                # 서버 업로드용 로컬 사본
├── views/
│   └── tools.py
├── templates/
│   ├── base.html
│   ├── navbar.html
│   ├── index.html
│   ├── intro.html
│   └── tools/
│       └── *.html
├── static/
│   ├── css/my.css
│   └── tools/
│       └── forensiclab_mbr_repair.py
└── web/                      # 원본 분석 툴 스크립트
    ├── crawfile.py           # GIF 카빙 (web/carve 도구 원본)
    └── mbrrepair.py          # MBR 스마트 복구 (web/mbr-repair 원본)
```

## 배포 방법 (paramiko 사용)
```python
import paramiko

HOST, USER, PASS = '10.8.0.2', 'rndp', 'cjm@0124'
ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect(HOST, username=USER, password=PASS)
sftp = ssh.open_sftp()

# 파일 업로드
sftp.put(r'E:\forensic\views\tools.py',
         '/home/ruddls030/forensic/flask/hospital/views/tools.py')

sftp.close()

# 템플릿만 변경 시
ssh.exec_command('docker restart forensic-flask')

# requirements.txt 변경 시 (전체 재빌드)
# ssh.exec_command('cd /home/ruddls030/forensic && docker-compose down && docker-compose build flask && docker-compose up -d')

ssh.close()
```

## 앞으로 할 수 있는 작업
- [ ] 로그인/회원가입 기능 연동 (기존 hospital/views/main.py에 라우트 있음)
- [ ] 센서 모니터링 대시보드 고도화
- [ ] 분석 결과 PDF 리포트 export
- [ ] 파일 카빙 — 더 많은 시그니처 추가 (EXE, DOC, MP4 등)
- [ ] 타임라인 재구성 도구
- [ ] 네트워크 패킷 분석 (pcap 파싱)
