#!/usr/bin/env python3
"""
ForensicLab Browser Artifacts Collector
=======================================
Chrome / Edge / Firefox / Brave / Opera / Vivaldi / Safari 의
히스토리·다운로드·쿠키·로그인·검색·북마크를 SQLite에서 추출합니다.

크로스 플랫폼:
  Windows: %LOCALAPPDATA%\<Brand>\User Data\<Profile>\
  Linux:   ~/.config/<brand>/Default/
  macOS:   ~/Library/Application Support/<Brand>/

출력: ./browser_artifacts_YYYYMMDD/<brand>_<profile>_<artifact>.csv

면책: 본인 계정 또는 위임받은 계정 데이터만 사용.
"""
import csv
import datetime
import os
import platform
import shutil
import sqlite3
import sys
import tempfile
from pathlib import Path


def chrome_time(ts):
    """Chrome epoch: us since 1601-01-01 UTC"""
    if not ts: return ''
    try:
        return (datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=int(ts))).isoformat()
    except Exception: return str(ts)


def firefox_time(ts):
    """Firefox: us since 1970-01-01"""
    if not ts: return ''
    try:
        return datetime.datetime.utcfromtimestamp(int(ts) / 1_000_000).isoformat()
    except Exception: return str(ts)


def webkit_time(ts):
    """Safari: sec since 2001-01-01 UTC (Cocoa)"""
    if not ts: return ''
    try:
        return (datetime.datetime(2001, 1, 1) + datetime.timedelta(seconds=float(ts))).isoformat()
    except Exception: return str(ts)


def find_browsers():
    sys_name = platform.system()
    home = Path.home()
    paths = []
    if sys_name == 'Windows':
        la = Path(os.environ.get('LOCALAPPDATA', home / 'AppData/Local'))
        ra = Path(os.environ.get('APPDATA', home / 'AppData/Roaming'))
        paths.extend([
            ('Chrome', la / 'Google/Chrome/User Data'),
            ('Edge', la / 'Microsoft/Edge/User Data'),
            ('Brave', la / 'BraveSoftware/Brave-Browser/User Data'),
            ('Opera', ra / 'Opera Software/Opera Stable'),
            ('Vivaldi', la / 'Vivaldi/User Data'),
            ('Firefox', ra / 'Mozilla/Firefox/Profiles'),
        ])
    elif sys_name == 'Darwin':
        paths.extend([
            ('Chrome', home / 'Library/Application Support/Google/Chrome'),
            ('Edge', home / 'Library/Application Support/Microsoft Edge'),
            ('Brave', home / 'Library/Application Support/BraveSoftware/Brave-Browser'),
            ('Firefox', home / 'Library/Application Support/Firefox/Profiles'),
            ('Safari', home / 'Library/Safari'),
        ])
    else:
        paths.extend([
            ('Chrome', home / '.config/google-chrome'),
            ('Chromium', home / '.config/chromium'),
            ('Edge', home / '.config/microsoft-edge'),
            ('Brave', home / '.config/BraveSoftware/Brave-Browser'),
            ('Firefox', home / '.mozilla/firefox'),
        ])
    return [(name, p) for name, p in paths if p.exists()]


def chromium_extract(brand: str, profile_dir: Path, out_dir: Path):
    """Chromium 계열: History, Cookies, Login Data, Bookmarks"""
    # 락 회피용 임시 복사
    targets = [
        ('History', 'urls', 'SELECT id, url, title, visit_count, typed_count, last_visit_time, hidden FROM urls ORDER BY last_visit_time DESC',
         ['id', 'url', 'title', 'visit_count', 'typed_count', 'last_visit', 'hidden'], 5),
        ('History', 'downloads',
         'SELECT id, target_path, referrer, start_time, end_time, total_bytes, received_bytes, state, mime_type FROM downloads',
         ['id', 'path', 'referrer', 'start', 'end', 'total', 'received', 'state', 'mime'], [3, 4]),
        ('History', 'keyword_search_terms',
         'SELECT keyword_id, url_id, term FROM keyword_search_terms', ['kw_id', 'url_id', 'term'], None),
        ('Login Data', 'logins',
         'SELECT origin_url, username_value, date_created, date_last_used, times_used FROM logins',
         ['origin', 'username', 'created', 'last_used', 'times_used'], [2, 3]),
        ('Cookies', 'cookies',
         'SELECT host_key, name, path, expires_utc, creation_utc, last_access_utc, is_secure, is_httponly FROM cookies',
         ['host', 'name', 'path', 'expires', 'created', 'last_access', 'secure', 'httponly'], [3, 4, 5]),
    ]
    for db_name, table, sql, cols, time_idx in targets:
        src = profile_dir / db_name
        if not src.exists(): continue
        try:
            with tempfile.NamedTemporaryFile(delete=False, suffix='.db') as tf:
                tmp = Path(tf.name)
            shutil.copy2(src, tmp)
            con = sqlite3.connect(f'file:{tmp}?mode=ro', uri=True)
            con.row_factory = sqlite3.Row
            cur = con.cursor()
            try:
                rows = cur.execute(sql).fetchall()
            except sqlite3.Error as e:
                print(f'    × {brand}/{table}: {e}')
                con.close(); tmp.unlink(missing_ok=True); continue
            csv_path = out_dir / f'{brand}_{profile_dir.name}_{table}.csv'
            with open(csv_path, 'w', encoding='utf-8', newline='') as f:
                w = csv.writer(f); w.writerow(cols)
                for r in rows:
                    row = list(r)
                    if time_idx is not None:
                        idxs = time_idx if isinstance(time_idx, list) else [time_idx]
                        for i in idxs:
                            if i < len(row) and row[i]:
                                row[i] = chrome_time(row[i])
                    w.writerow(row)
            print(f'    ✓ {brand}/{table}: {len(rows)}건 → {csv_path.name}')
            con.close(); tmp.unlink(missing_ok=True)
        except Exception as e:
            print(f'    × {brand}/{table}: {e}')


def firefox_extract(profile_dir: Path, out_dir: Path):
    src = profile_dir / 'places.sqlite'
    if not src.exists(): return
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix='.sqlite') as tf:
            tmp = Path(tf.name)
        shutil.copy2(src, tmp)
        con = sqlite3.connect(f'file:{tmp}?mode=ro', uri=True)
        cur = con.cursor()
        for table, sql, cols, time_idx in [
            ('places',
             'SELECT id,url,title,visit_count,last_visit_date,frecency FROM moz_places ORDER BY last_visit_date DESC',
             ['id', 'url', 'title', 'visits', 'last_visit', 'frecency'], 4),
            ('history',
             'SELECT id, place_id, visit_date, visit_type FROM moz_historyvisits', ['id', 'place_id', 'visit_date', 'type'], 2),
            ('bookmarks',
             'SELECT id, parent, title, dateAdded, lastModified FROM moz_bookmarks',
             ['id', 'parent', 'title', 'added', 'modified'], [3, 4]),
        ]:
            try:
                rows = cur.execute(sql).fetchall()
            except sqlite3.Error: continue
            csv_path = out_dir / f'Firefox_{profile_dir.name}_{table}.csv'
            with open(csv_path, 'w', encoding='utf-8', newline='') as f:
                w = csv.writer(f); w.writerow(cols)
                for r in rows:
                    row = list(r)
                    if time_idx is not None:
                        idxs = time_idx if isinstance(time_idx, list) else [time_idx]
                        for i in idxs:
                            if i < len(row) and row[i]:
                                row[i] = firefox_time(row[i])
                    w.writerow(row)
            print(f'    ✓ Firefox/{table}: {len(rows)}건')
        con.close(); tmp.unlink(missing_ok=True)
    except Exception as e:
        print(f'    × Firefox: {e}')


def main():
    print('=' * 70)
    print('  ForensicLab Browser Artifacts Collector v1.0')
    print('=' * 70)
    print('\n  실행 중인 브라우저는 모두 종료한 뒤 시작하세요 (DB 락 회피).')
    if input('\n  계속하려면 YES 입력: ') != 'YES':
        return 1
    out = Path(f'./browser_artifacts_{datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")}').resolve()
    out.mkdir(parents=True, exist_ok=True)
    print(f'\n  출력: {out}\n')
    found = find_browsers()
    if not found:
        print('  ✗ 브라우저 데이터 폴더를 찾을 수 없습니다.')
        return 1
    for brand, root in found:
        print(f'[{brand}] {root}')
        if brand == 'Firefox':
            for prof in root.iterdir():
                if prof.is_dir() and (prof / 'places.sqlite').exists():
                    firefox_extract(prof, out)
        else:
            for prof in root.iterdir():
                if prof.is_dir() and prof.name in ('Default',) or prof.name.startswith('Profile'):
                    chromium_extract(brand, prof, out)
    print(f'\n  ✓ 완료. 결과: {out}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
