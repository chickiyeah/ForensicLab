"""tools_extra3.py 의 _MAGIC_DB 라벨 bytes → str 변환"""
import re
from pathlib import Path

p = Path(r'E:\forensic\views\tools_extra3.py')
text = p.read_text(encoding='utf-8')

# _MAGIC_DB 라인만 처리: (b'시그니처', b'라벨', '미메')
# 라벨 b'...' → '...'  단, 시그니처 b'...'은 보존
# 패턴: ,b'<label>',' 또는 ,b"<label>",
# 더 안전하게: 행마다 정확히 처리

lines = text.split('\n')
out = []
in_magic = False
for ln in lines:
    if '_MAGIC_DB = [' in ln:
        in_magic = True
        out.append(ln); continue
    if in_magic:
        if ln.strip().startswith(']'):
            in_magic = False
            out.append(ln); continue
        # 두 번째 b'...'을 '...'으로 변환
        # 패턴: (시그bytes,)b'라벨','미메'
        # 정규식: ,b'([^']*)','
        new = re.sub(r",b'([^']*)',", lambda m: f",'{m.group(1)}',", ln)
        out.append(new)
    else:
        out.append(ln)

p.write_text('\n'.join(out), encoding='utf-8')
print('수정 완료')
