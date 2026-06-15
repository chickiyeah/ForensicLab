# -*- coding: utf-8 -*-
import paramiko, time, re, json
ssh=paramiko.SSHClient(); ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
for a in range(6):
    try:
        ssh.connect('10.8.0.17',username='ruddls030',password='dlstn0722',timeout=20,banner_timeout=20); break
    except Exception as e:
        print('retry',a+1,e); time.sleep(5)
def run(c,t=180):
    _,o,e=ssh.exec_command(c,timeout=t); return o.read().decode()+e.read().decode()

E="/tmp/tmpkz3w8g0m.E01"
# 남은 E01 확인
if 'No such' in run("ls %s 2>&1"%E) or not run("ls %s 2>&1"%E).strip():
    print("E01 없음 — 사용자 재업로드 필요"); ssh.close(); raise SystemExit
print("E01 size:", run("stat -c %%s %s"%E).strip())
# 실제 웹 엔드포인트로 업로드(컨테이너 내부 localhost) → 잡 생성
print("POST /tools/plaso ...")
resp = run("docker exec forensic-flask sh -c 'curl -s -F \"file=@%s;filename=ence.E01\" http://localhost:5000/tools/plaso'"%E, t=300)
m = re.search(r'/tools/jobs/([a-f0-9]{8,})', resp)
if not m:
    print("job id 못 찾음. 응답 일부:", resp[:500]); ssh.close(); raise SystemExit
jid=m.group(1); print("job_id:", jid)
# 폴링
for i in range(40):   # 최대 ~10분
    st=run("curl -s http://localhost:405/tools/jobs/%s/status"%jid)
    try: d=json.loads(st)
    except: print("status parse fail",st[:200]); break
    res=d.get('result') or {}
    log=d.get('log') or []
    last=log[-1]['msg'] if log else ''
    print("[%2d] status=%s prog=%s | %s"%(i,d.get('status'),d.get('progress'),last))
    if d.get('status') in ('completed','failed'):
        print("\n=== RESULT ===")
        print("total:", res.get('total'), "| summary:", res.get('summary'))
        print("per_source:", res.get('per_source'))
        print("diagnosis:", res.get('diagnosis'))
        pf=res.get('preflight') or {}
        print("preflight: mbr_valid=%s media=%s scan=%s"%(pf.get('mbr_valid'),pf.get('media_size'),[(s.get('sector'),s.get('fs')) for s in (pf.get('scan') or [])][:6]))
        if res.get('error'): print("ERROR:", res.get('error'))
        if res.get('rows'): print("sample row:", res['rows'][1] if len(res['rows'])>1 else res['rows'][0])
        break
    time.sleep(15)
ssh.close()
