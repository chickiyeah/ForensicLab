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
├── gunicorn.conf.py          # timeout=1800, reload=False (운영 안정화)
├── requirements.txt
├── config/
│   ├── default.py
│   ├── development.py
│   └── production.py         # APP_CONFIG_FILE 환경변수로 지정
├── monitor/
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
| `/tools/carve` | 파일 카빙 | `web/crawfile.py` | 15종 시그니처 탐색·복구 (GIF·JPEG·PNG·PDF·ZIP·EXE·DOC·MP4·BMP·WAV·AVI·WebP·SQLite·7z·ELF), ZIP 다운로드 |
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
         '/home/ruddls030/forensic/flask/monitor/views/tools.py')

sftp.close()

# 템플릿만 변경 시
ssh.exec_command('docker restart forensic-flask')

# requirements.txt 변경 시 (전체 재빌드)
# ssh.exec_command('cd /home/ruddls030/forensic && docker-compose down && docker-compose build flask && docker-compose up -d')

ssh.close()
```

## 완료된 작업 (2026-06-08 기준)
- [x] 로그인/회원가입 기능 연동 — `/login` `/signup` `/logout` `/mypage`, navbar 세션 연동
- [x] 분석 결과 PDF 리포트 export — `/tools/report-pdf` `/tools/llm-report` `/tools/case/<id>/report`
- [x] 파일 카빙 시그니처 추가 — 총 15종: GIF·JPEG·PNG·PDF·ZIP·EXE(PE)·DOC(OLE2)·MP4 + **BMP·WAV·AVI·WebP·SQLite·7z·ELF** (size_func 기반, `tools.py` SIGNATURES)
- [x] Volatility 3 수집·분석 다운로드 스크립트 — `forensiclab_vol3_collector.py` (WinPmem/AVML 메모리 수집 후 vol3 표준 플러그인 자동 실행). `/tools/scripts` 9종, `_KNOWN_CHECKSUMS`·verify 등록 완료
- [x] 타임라인 재구성 — `/tools/timeline` `/tools/plaso`
- [x] 네트워크 패킷 분석 — `/tools/pcap`
- [x] 쓰기/특권 도구 로그인 게이트 — `tools.py`의 `WRITE_TOOL_PREFIXES` (`/tools/mbr-repair`·`/tools/unlock`·`/tools/e01-mount`). 비로그인 시 `/login` 리다이렉트(`session['next_url']` 후 로그인 시 복귀)
- [x] 사건↔분석이력 연결 — 사건 상세(`/tools/case/<id>`)에서 내 최근 `AnalysisLog`를 `attach_log` 액션으로 사건 evidence 테이블에 첨부(태그 `분석이력`). 메인 DB 스키마 변경 없이 기존 evidence 재사용
- [x] 파일 업로드 실시간 진행률 — `base.html` 글로벌 제출 핸들러가 파일 있는 폼을 XHR로 전송하며 `xhr.upload.onprogress`로 % 표시(오버레이의 `#ovProgressBar` 재사용). 업로드 완료 후엔 "분석 진행 중" 스피너+경과시간. 다운로드 응답(`Content-Disposition: attachment`)은 blob 저장으로 분기, 그 외 HTML/JSON은 `document.write`로 페이지 교체. `data-no-overlay`/검색폼/파일없는폼은 기존 네이티브 제출 유지
- [removed] 센서 모니터링 — 포렌식 플랫폼과 무관하여 제거 (`monitor` 블루프린트·`Sensor` 모델·`/monitor/*`·navbar 링크 삭제). DB의 `sensor` 테이블은 미사용으로 잔존(무해)

> 현재 서버에 라우트 199개 → 센서 제거 후 191개, 170+ 도구. 전체 목록은 `/tools` 카탈로그 참조.

## 쓰기/특권 도구 로그인 게이트
- 위치: `monitor/views/tools.py` 상단 `@bp.before_request` + `WRITE_TOOL_PREFIXES`
- 현재 게이트: `/tools/mbr-repair`(디스크 쓰기)·`/tools/unlock`(복호화)·`/tools/e01-mount`(이미지 마운트)
- 새 도구 게이트는 `WRITE_TOOL_PREFIXES` 튜플에 경로 prefix 추가만 하면 됨
- 로그인 성공 시 `session['next_url']`로 원래 페이지 복귀 (`main.py` login/signup)

## 업로드 용량 제한 (2026-06-09: 200MB → 16GB)
413 "Request Entity Too Large"는 3겹 제한을 다 올려야 함. 모두 16GB로 상향:
- Flask `MAX_CONTENT_LENGTH` — `config/default.py` (413 직접 원인). env `MAX_CONTENT_LENGTH_BYTES`
- 도구 `MAX_UPLOAD` — `tools.py` (`f.read(MAX_UPLOAD)` 읽기 상한). env `MAX_UPLOAD_BYTES`
- nginx `client_max_body_size` — `nginx/nginx.conf` (16g)
- nginx `client_body_timeout 1800s` — 느린 업로드가 기본 60초에 **408**로 끊기는 것 방지 (상위 NPM/CF가 408을 502로 표시). `proxy_request_buffering`는 기본(on) 유지 — 단일 워커를 느린 업로드가 점유하지 않도록.
- **주의(도메인 경로)**: `forensic.jvision.org`는 NPM(Nginx Proxy Manager) 경유 → NPM Proxy Host의 Advanced에 `client_max_body_size 16g;` 도 넣어야 함. 내부망 `10.8.0.17:405` 직접 경로는 위 docker nginx로 충분.
- 주의(메모리): 도구가 파일을 통째로 RAM에 읽음(`f.read`). 수 GB 이미지는 RAM 사용 큼(호스트 98GB라 여유는 있음). 초대형 이미지는 로컬 수집 스크립트 권장.

## 502 / 분석 중 끊김 방지 (2026-06-09)
무거운 분석 도중 502가 나던 원인 2가지를 잡음:
- **gunicorn `reload=True` 제거** → `reload=False`. reload가 켜져 있으면 파일 변경 시 워커를 재시작하는데, **진행 중인 분석 요청이 502로 죽음**. (단점: 템플릿/코드 변경 반영하려면 `docker restart forensic-flask` 필요 — 배포 스크립트가 이미 그렇게 함)
- **gunicorn `timeout = 1800`**(기본 30초) + nginx **`proxy_read_timeout/send_timeout 1800s`**(기본 300초) → 5분 넘는 동기 분석도 안 끊김.
- 파일 위치: `flask/gunicorn.conf.py`, `nginx/nginx.conf`. 변경 후 `docker restart forensic-flask` + `docker restart forensic-nginx`.

## plaso 타임라인 CSV 다운로드 + 상한 제거 (2026-06-09)
- 이벤트 표시 상한(2만) 제거 — 전체 타임라인을 `_DATA_DIR/plaso/<job_id>.csv`에 **스트리밍 병합 저장**(메모리에 다 안 올림, 미리보기 500행만 result에 포함). `total`은 실제 전체 수.
- 다운로드: `GET /tools/plaso/download/<job_id>` (`plaso_download`, job_id 헥스 검증 후 `send_file`). `job_detail.html`에 "전체 CSV 다운로드" 버튼(result에 `download` 있을 때 표시).
- 검증: 파티션테이블 삭제 E01 → carve → **124,631 이벤트**, CSV 52MB 다운로드 정상.
- 누적된 `_DATA_DIR/plaso/*.csv`는 자동 삭제 안 함(결과 보존). 디스크 정리 필요시 수동.

## 표시 통계 실데이터화 (2026-06-09)
홈 화면 등의 지어낸 수치를 실DB/시스템 값으로 교체:
- `main.py` index() — `AnalysisLog` 건수, `SUM(file_size)`(humanize), `User` 수, 도구 수를 계산해 `index.html`에 전달.
- `tools.py` `@bp.app_context_processor _inject_tool_count` → 모든 템플릿에 `tool_count`(= `len(_TOOL_CATALOG)`). navbar "전체 도구 (N)"가 실제 도구 수 표시.
- 제거된 가짜값: `10,482`(분석파일)·`3,271`(이상징후)·`99.7%`(정확도)·`150+`(도구)·터미널 애니메이션 수치.
- 원칙: **표시 수치는 DB/시스템에서 실제로 계산한 값만** (포렌식 사이트 신뢰도). plaso "514 구성요소"도 실측값.

## 영속 데이터 (`/app/data` — 바인드 마운트, 재시작에도 보존)
2026-06-09에 `/tmp` 휘발 문제 해결. 각 모듈 상단의 `_DATA_DIR`(= flask root + `/data`, 컨테이너에선 `/app/data`)에 저장:
- `forensiclab_cases.db` (사건/증거/발견/멤버/audit) — `tools_extra6.py`
- `forensiclab_ocr_idx.db` (OCR 인덱스) — `tools_extra6.py`
- `forensiclab_coc/chain.jsonl` (Chain of Custody) — `tools_extra5.py`
- `forensiclab_honeytrap/events.jsonl` (허니트랩 이벤트) — `tools_extra10.py`
- `forensic.db` (User/AnalysisLog, SQLAlchemy)
> `_UNLOCK_DIR`(복호화 작업공간)만 의도적으로 `/tmp` 유지(휘발). 기존 `/tmp` 데이터는 `docker cp`로 마이그레이션 완료.

## 무거운 외부 프로세스 자원 제한
호스트는 **10코어 공용**(siawiki·komjeong 등 다른 컨테이너 공존). 무제한 병렬 도구가 호스트를 포화시키면 전체 서비스가 마비됨.
- **plaso 튜닝** (2026-06-09): 실제 장애 원인은 CPU 포화가 아니라 디스크 I/O 정체였음(호스트 RAM 98GB/46GB여유, OOM 없음, CPU<10%). `tools_extra6.py`:
  - `_LOWPRIO` = **`taskset -c 0-{nproc-5}`**(코어 고정, 10코어→0-5 사용/4개는 타 서비스 보장) + `nice -n 10` + `ionice -c 2 -n 6`. taskset이 호스트 CPU 락(타 컨테이너 접근 불능)을 막는 핵심. **주의: `ionice -c 3`(idle)은 디스크를 계속 양보해 워커가 굶어 CPU<10%로 정체되므로 쓰지 말 것.**
  - preflight VBR 스캔은 앞 512MB·조기중단(최대 8볼륨)으로 부하 최소화. `_fs_from_bytes`는 FAT(0x55AA 확인)·ext(블록크기 sanity)·HFS+(버전 4/5) 검증으로 오탐 제거(2바이트 매직만으론 랜덤 데이터 오탐 다수 발생했었음).
- **깨진 MBR 자동 우회 분석** (2026-06-09): 파티션 테이블이 손상/삭제돼 log2timeline이 FS를 못 찾을 때, preflight의 VBR 스캔으로 찾은 볼륨을 **`_volume_size`로 부트섹터에서 실제 크기를 읽어 정확히** `_carve_region`으로 잘라내 `_run_l2t_pipeline`로 **개별 log2timeline+psort 처리 후 통합 타임라인** 생성. **중요: carve 경계를 "다음 탐지 오프셋"으로 잡으면 볼륨이 truncate돼 `Address missing in partial image`로 0건이 됨 → 반드시 부트섹터의 실제 볼륨 크기(NTFS @0x28, FAT32 @0x20, exFAT @0x48, ext 슈퍼블록)로 carve. 볼륨 내부의 오탐 탐지는 covered_end로 스킵(dedup).** 실측 검증: 파티션테이블 삭제된 2.56GB E01 → NTFS@sector63 전체(2103MB) carve → log2timeline 2만+ 이벤트 추출 성공. 결과에 `per_source`(소스별 이벤트 수)·`summary`·`total` 포함. 파티션 테이블 정상이면 전체 이미지를 `--partitions all`로 처리. carve는 단일 스레드(1코어), log2timeline은 `_LOWPRIO`(taskset)로 제한 → 호스트 안정.
  - `_PLASO_WORKERS = max(2, nproc-4)` (10코어 → 6워커, 다른 컨테이너용 여유 확보), `--worker_memory_limit 2GiB`.
  - `_new_job`은 `ThreadPoolExecutor(max_workers=2)` 백그라운드 실행 → 웹 요청 스레드는 안 막힘.
  - **버그 수정** (2026-06-09): `_plaso_job` 안에서 `os.path.splitext(f.filename)`(앞)과 `with open(csv_out) as f`(뒤)가 같은 이름 `f`를 써서, `f`가 함수 전체 지역변수로 잡혀 앞부분이 `UnboundLocalError: cannot access local variable 'f'`. CSV 핸들을 `cf`로 rename해 해결. (= 사용자가 "E01 분석 안됨"으로 본 JSON 에러. plaso 잡이 import plaso 성공 후 항상 이 지점에서 실패하던 것.) 잡 클로저가 외부 `f`를 참조할 땐 내부에서 `f` 재할당 금지.
- 새 무거운 subprocess 도구는 `_LOWPRIO + [...]` 패턴 사용 권장.
- **"No supported file system found in source" 수정** (2026-06-09): log2timeline에 `--unattended --partitions all --volumes all` 추가. 파티션이 여럿이면 log2timeline이 대화형으로 파티션 선택을 묻는데 subprocess엔 입력이 없어 FS를 못 찾고 0건으로 끝나던 문제. 무인 모드 + 전체 파티션/볼륨 처리로 해결.
- **plaso preflight(사전 점검) 추가** (2026-06-09): `tools_extra6.py`의 `_disk_preflight()` — log2timeline 실행 전 이미지를 점검. ① media_size·끝섹터로 **분할/잘린 E01 감지** ② **MBR 파싱 + 파티션별 FS 탐지**(`_fs_from_bytes`: NTFS/exFAT/FAT/ext/HFS+) ③ MBR에서 FS 못 찾으면 **VBR 스캔(`_vbr_scan`, 앞 2GB)** 으로 볼륨 찾아 "MBR 손상 의심 → `/tools/mbr-repair` 권장" 진단. 결과 dict에 `preflight` + (0건일 때) `diagnosis` 포함 → 몇 분 기다린 끝의 빈 결과 대신 **원인을 바로 제시**. E01은 pyewf, raw는 직접 read.

## 앞으로 할 수 있는 작업 (제안)
- [ ] 같은 자원 제한(`_LOWPRIO`)을 다른 무거운 도구에도 적용 검토 — `hashcat-job`(전 CPU 점유), `vol-full`, `aleapp`/`ileapp`
- [ ] 분석이력(history)에서 역방향으로 "어느 사건에 첨부됐는지" 표시
- [ ] `data/` 디렉터리 정기 백업
