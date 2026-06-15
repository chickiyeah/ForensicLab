#!/usr/bin/env python3
"""
ForensicLab USB Connection History (Windows)
============================================
USB 저장장치 연결 이력을 레지스트리 + setupapi.dev.log 에서 추출합니다.

레지스트리 키:
  HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR\<VID&PID>\<Serial>
    - FriendlyName, HardwareID, Service, Mfg
    - Properties\{83da6326-97a6-4088-9453-a1923f573b29}\0066  (최초/마지막 연결/제거)

setupapi.dev.log: 최초 연결 시각 + 드라이버 매핑.

요구: 관리자 권한 (HKLM 접근).
"""
import ctypes
import csv
import datetime
import os
import re
import struct
import sys
import winreg
from pathlib import Path


def is_admin():
    try: return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception: return False


def ft2str(ft):
    if not ft: return ''
    try:
        return (datetime.datetime(1601, 1, 1)
                + datetime.timedelta(microseconds=ft // 10)).isoformat()
    except Exception: return ''


def enum_usbstor():
    """HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR 순회"""
    devices = []
    try:
        usbstor = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                 r'SYSTEM\CurrentControlSet\Enum\USBSTOR')
    except OSError as e:
        print(f'  ✗ USBSTOR 키 열기 실패: {e}'); return devices
    i = 0
    while True:
        try:
            dev_class = winreg.EnumKey(usbstor, i); i += 1
        except OSError: break
        # dev_class: Disk&Ven_XX&Prod_YY&Rev_ZZ
        m = re.match(r'(?P<type>\w+)&Ven_(?P<vendor>[^&]+)&Prod_(?P<product>[^&]+)(?:&Rev_(?P<rev>\S+))?',
                     dev_class)
        meta = m.groupdict() if m else {'type': dev_class}
        sub = winreg.OpenKey(usbstor, dev_class)
        j = 0
        while True:
            try:
                serial_key = winreg.EnumKey(sub, j); j += 1
            except OSError: break
            try:
                k = winreg.OpenKey(sub, serial_key)
            except OSError: continue
            row = dict(meta); row['serial_raw'] = serial_key
            # Clean serial (suffix '&0' 제거)
            row['serial'] = serial_key.split('&')[0]
            for name in ['FriendlyName', 'HardwareID', 'Service', 'Mfg',
                         'Class', 'ClassGUID', 'DeviceDesc', 'ContainerID',
                         'Driver', 'CompatibleIDs']:
                try:
                    v, _ = winreg.QueryValueEx(k, name)
                    if isinstance(v, list): v = ' | '.join(v)
                    row[name] = v
                except OSError: row[name] = ''
            # Properties — 최초 연결 / 마지막 연결 / 마지막 제거 (FILETIME)
            try:
                props = winreg.OpenKey(k, r'Properties\{83da6326-97a6-4088-9453-a1923f573b29}')
                for prop_name, label in [
                    ('0064', '최초 연결'),
                    ('0066', '마지막 연결'),
                    ('0067', '마지막 제거'),
                ]:
                    try:
                        pk = winreg.OpenKey(props, prop_name)
                        # subkey '00000000' Data
                        data, _ = winreg.QueryValueEx(pk, '(Default)' if False else '')
                        if len(data) >= 8:
                            ft = struct.unpack('<Q', data[:8])[0]
                            row[label] = ft2str(ft)
                    except OSError: pass
            except OSError: pass
            devices.append(row)
    return devices


def parse_setupapi_log():
    """C:\Windows\INF\setupapi.dev.log — 최초 USB 드라이버 설치 시각"""
    paths = [Path(os.environ.get('SystemRoot', r'C:\Windows')) / 'INF' / 'setupapi.dev.log',
             Path(os.environ.get('SystemRoot', r'C:\Windows')) / 'inf' / 'setupapi.dev.log']
    log = next((p for p in paths if p.exists()), None)
    if not log: return []
    events = []
    try:
        with open(log, encoding='utf-16', errors='replace') as f:
            content = f.read()
    except UnicodeError:
        with open(log, encoding='latin1', errors='replace') as f:
            content = f.read()
    # 각 "Section start ... DateTime" 블록
    for m in re.finditer(
            r'>>>\s*\[(.+?)\]\s*\n>>>\s*Section start (\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}\.\d+)',
            content):
        dev, ts = m.group(1), m.group(2)
        if 'USB' in dev.upper() or 'STORAGE' in dev.upper():
            events.append({'device': dev.strip(), 'time': ts})
    return events


def main():
    print('=' * 70)
    print('  ForensicLab USB Connection History v1.0')
    print('=' * 70)
    if sys.platform != 'win32':
        print('  ✗ Windows 전용'); return 1
    if not is_admin():
        print('  ✗ 관리자 권한 필요'); return 1

    out_dir = Path(f'./usb_history_{datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")}').resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    print(f'  출력: {out_dir}\n')

    print('[1/2] HKLM\\SYSTEM\\Enum\\USBSTOR 스캔')
    devs = enum_usbstor()
    print(f'    ✓ {len(devs)}개 장치 발견')
    if devs:
        keys = sorted({k for d in devs for k in d.keys()})
        with open(out_dir / 'usbstor.csv', 'w', encoding='utf-8', newline='') as f:
            w = csv.DictWriter(f, fieldnames=keys); w.writeheader(); w.writerows(devs)
        # 콘솔 요약
        for d in devs:
            name = d.get('FriendlyName') or f"{d.get('vendor','?')} {d.get('product','?')}"
            print(f'    • {name} (S/N: {d.get("serial","?")})  최초:{d.get("최초 연결","-")[:19]}  최후:{d.get("마지막 연결","-")[:19]}')

    print('\n[2/2] setupapi.dev.log 스캔')
    events = parse_setupapi_log()
    print(f'    ✓ USB/저장장치 관련 이벤트 {len(events)}건')
    if events:
        with open(out_dir / 'setupapi_events.csv', 'w', encoding='utf-8', newline='') as f:
            w = csv.DictWriter(f, fieldnames=['time', 'device'])
            w.writeheader(); w.writerows(events)

    print(f'\n  ✓ 완료. 결과: {out_dir}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
