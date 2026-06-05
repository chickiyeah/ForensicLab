"""기존 파일 업로드 도구에 multiple 속성 추가"""
import re
from pathlib import Path

T = Path(r'E:\forensic\templates\tools')

# 단일 파일 입력 → 다중 파일 입력으로 변경 (특정 도구만, hexdiff/encrypt는 제외)
SKIP = {'hexdiff.html', 'encrypt.html', 'verify.html', 'sqlite.html',
        'whatsapp.html', 'ios_backup.html', 'hex.html', 'mbr_repair.html'}

def patch(path: Path):
    text = path.read_text(encoding='utf-8')
    orig = text
    # name="file" multiple 추가 (이미 있으면 스킵)
    # 패턴: <input type="file" name="file" ...> 에서 multiple 없으면 추가
    def add_mult(m):
        full = m.group(0)
        if 'multiple' in full: return full
        return full.replace('name="file"', 'name="file" multiple', 1)
    new = re.sub(r'<input[^>]+name="file"[^>]*>', add_mult, text)
    # name="file_a" / name="file_b" / name="file_key" 등은 그대로 둠 (별도 입력)
    if new != orig:
        path.write_text(new, encoding='utf-8')
        return True
    return False

count = 0
for p in sorted(T.glob('*.html')):
    if p.name in SKIP: continue
    if patch(p):
        count += 1
        print(f'  + {p.name}')

print(f'\n{count}개 템플릿에 multiple 속성 추가')
