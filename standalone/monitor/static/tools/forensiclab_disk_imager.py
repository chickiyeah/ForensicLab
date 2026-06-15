#!/usr/bin/env python3
"""
ForensicLab Disk Imager (Linux / macOS)
=======================================
dd 기반 비트 단위 디스크 이미징. SHA-256 동시 계산 + 진행률 표시.

사용 예:
  sudo python forensiclab_disk_imager.py --source /dev/sdb --output /mnt/case/evidence.dd
  sudo python forensiclab_disk_imager.py --source /dev/sda --output ./hdd.dd --chunk 64

면책: 본인 또는 위임받은 시스템·매체에서만 사용. 결과 파일은 원본과 동일한 민감 데이터를 포함합니다.
"""
import argparse
import hashlib
import os
import sys
import time
from pathlib import Path


def banner():
    print('=' * 70)
    print('  ForensicLab Disk Imager v1.0')
    print('=' * 70)


def fmt_bytes(n):
    for u in ['B', 'KB', 'MB', 'GB', 'TB']:
        if n < 1024: return f'{n:.2f} {u}'
        n /= 1024
    return f'{n:.2f} PB'


def main():
    banner()
    if sys.platform == 'win32':
        print('  ✗ 본 스크립트는 Linux/macOS 전용입니다.')
        print('    Windows는 FTK Imager / DumpIt / WinHex 사용을 권장합니다.')
        return 1
    if os.geteuid() != 0:
        print('  ✗ root 권한 필요. sudo 로 재실행하세요.')
        return 1

    p = argparse.ArgumentParser()
    p.add_argument('--source', '-s', required=True, help='원본 장치 (예: /dev/sdb)')
    p.add_argument('--output', '-o', required=True, help='출력 이미지 파일')
    p.add_argument('--chunk', type=int, default=4, help='청크 크기 MB (기본 4)')
    p.add_argument('--yes', action='store_true', help='면책 확인 자동 동의')
    args = p.parse_args()

    src = Path(args.source)
    out = Path(args.output).resolve()
    if not src.exists():
        print(f'  ✗ 소스 장치 없음: {src}'); return 1
    out.parent.mkdir(parents=True, exist_ok=True)

    # 소스 정보
    try:
        import subprocess
        info = subprocess.run(['lsblk', '-b', '-o', 'NAME,SIZE,MODEL,SERIAL,VENDOR',
                               str(src)], capture_output=True, text=True)
        print('\n  소스 정보:')
        for line in info.stdout.strip().split('\n'):
            print('   ', line)
    except Exception: pass

    print(f'\n  ⚠️ 원본: {src}')
    print(f'  ⚠️ 대상: {out}')
    print(f'  ⚠️ 출력은 원본과 동일한 모든 데이터를 평문으로 포함합니다.')
    if not args.yes:
        if input('\n  계속하려면 YES 입력: ') != 'YES':
            print('  취소됨'); return 1

    chunk = args.chunk * 1024 * 1024
    h_sha = hashlib.sha256()
    h_md5 = hashlib.md5()
    total = 0
    t0 = time.time()
    print(f'\n  이미징 시작: {src} → {out}\n')
    try:
        with open(src, 'rb') as r, open(out, 'wb') as w:
            while True:
                buf = r.read(chunk)
                if not buf: break
                w.write(buf)
                h_sha.update(buf); h_md5.update(buf)
                total += len(buf)
                elapsed = time.time() - t0
                mbps = (total / 1024 / 1024) / max(elapsed, 0.001)
                sys.stdout.write(f'\r  {fmt_bytes(total)}  |  {mbps:.1f} MB/s  |  {elapsed:.0f}s    ')
                sys.stdout.flush()
        print('\n\n  ✓ 이미징 완료')
        print(f'    크기   : {total:,} bytes ({fmt_bytes(total)})')
        print(f'    시간   : {time.time()-t0:.1f}초')
        print(f'    SHA-256: {h_sha.hexdigest()}')
        print(f'    MD5    : {h_md5.hexdigest()}')
        # 해시 파일 저장
        hash_file = out.with_suffix(out.suffix + '.hash.txt')
        with open(hash_file, 'w') as hf:
            hf.write(f'SHA-256: {h_sha.hexdigest()}\nMD5: {h_md5.hexdigest()}\n'
                     f'Source: {src}\nSize: {total}\n')
        print(f'    해시 저장: {hash_file}')
    except KeyboardInterrupt:
        print('\n\n  ✗ 중단됨'); return 1
    except Exception as e:
        print(f'\n\n  ✗ 오류: {e}'); return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
