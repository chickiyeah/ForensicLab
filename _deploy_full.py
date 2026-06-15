"""전체 배포 스크립트 - 서버 10.8.0.17

로컬 good 스냅샷 `_deploy_src/` 를 서버 flask 트리에 그대로 미러링한다.
`_deploy_src/` 는 현재 서버의 검증된 good 상태(2026-06-15)를 받아둔 것:
  flask/{monitor, config, gunicorn.conf.py, requirements.txt, Dockerfile}
  (단, __pycache__·*.pyc·static/uploads·data·*.bak_* 는 제외)

스냅샷 재생성이 필요하면 위 경로를 같은 제외 규칙으로 다시 내려받으면 된다.
구버전 부분 목록/인라인 하드코딩을 쓰지 않으므로, 클린 서버에서도
도구 본체(tools_extra*)·전체 템플릿·정적 수집 스크립트까지 완전히 복원된다.
"""
import paramiko, os, posixpath, time

HOST, USER, PASS = '10.8.0.17', 'ruddls030', 'dlstn0722'
BASE_LOCAL  = r'E:\forensic'
SRC_LOCAL   = r'E:\forensic\_deploy_src'
BASE_REMOTE = '/home/ruddls030/forensic/flask'

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect(HOST, username=USER, password=PASS)
sftp = ssh.open_sftp()

_made = set()


def mkdir_p(path):
    parts = path.split('/')
    cur = ''
    for p in parts:
        if not p:
            cur = '/'
            continue
        cur = cur.rstrip('/') + '/' + p
        if cur in _made:
            continue
        try:
            sftp.stat(cur)
        except FileNotFoundError:
            sftp.mkdir(cur)
        _made.add(cur)


# ── 런타임 디렉토리 보장 ──────────────────────────────
for d in [
    BASE_REMOTE,
    f'{BASE_REMOTE}/data',
    f'{BASE_REMOTE}/monitor/static/uploads',
    f'{BASE_REMOTE}/migrations',
]:
    mkdir_p(d)
print('[1/4] Runtime directories OK')

# ── good 스냅샷 전체 미러링 ───────────────────────────
if not os.path.isdir(SRC_LOCAL):
    raise SystemExit(f'스냅샷 폴더가 없습니다: {SRC_LOCAL}')
n_files = 0
for root, dirs, files in os.walk(SRC_LOCAL):
    dirs[:] = [d for d in dirs if d not in ('__pycache__',)]
    for fn in files:
        if fn.endswith('.pyc') or '.bak_' in fn:
            continue
        lp = os.path.join(root, fn)
        rel = os.path.relpath(lp, SRC_LOCAL).replace(os.sep, '/')
        rp = f'{BASE_REMOTE}/{rel}'
        mkdir_p(posixpath.dirname(rp))
        sftp.put(lp, rp)
        n_files += 1
print(f'[2/4] Mirrored {n_files} files from _deploy_src')

# ── docker-compose.yml (flask 디렉토리 밖) ────────────
sftp.put(os.path.join(BASE_LOCAL, 'docker-compose.yml'),
         '/home/ruddls030/forensic/docker-compose.yml')
print('  PUT   docker-compose.yml')
sftp.close()

# ── Docker 재빌드 & 재시작 ─────────────────────────────
print('[3/4] Rebuilding Docker...')
cmd = (
    'cd /home/ruddls030/forensic && '
    'docker compose down && '
    'docker compose build flask && '
    'docker compose up -d'
)
_, o, e = ssh.exec_command(cmd, timeout=300)
stdout = o.read().decode()
stderr = e.read().decode()
if stdout:
    print(stdout[-3000:])
if stderr:
    print('[stderr]', stderr[-2000:])

# ── DB 마이그레이션 ───────────────────────────────────
print('[4/4] Waiting 5s for containers to start...')
time.sleep(5)

print('Running db init + upgrade...')
_, o2, e2 = ssh.exec_command(
    'cd /home/ruddls030/forensic && '
    'docker compose exec -T forensic-flask '
    'flask --app "monitor:create_app()" db init 2>&1 || true && '
    'docker compose exec -T forensic-flask '
    'flask --app "monitor:create_app()" db migrate -m "init" 2>&1 || true && '
    'docker compose exec -T forensic-flask '
    'flask --app "monitor:create_app()" db upgrade 2>&1',
    timeout=120
)
out2 = o2.read().decode()
err2 = e2.read().decode()
print(out2 or '(no output)')
if err2:
    print('[migrate stderr]', err2[:1000])

ssh.close()
print('\nDone! http://10.8.0.17:405')
