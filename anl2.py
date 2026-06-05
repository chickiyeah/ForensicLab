import struct
import os

def rebuild_mbr_raw(file_path):
    if not os.path.exists(file_path):
        print(f"[-] 파일을 찾을 수 없습니다: {file_path}")
        return

    found_partitions = []
    
    # 스캔할 시그니처와 타입 매핑
    targets = [
        (b'\xEB\x52\x90NTFS', 0x07),      # NTFS
        (b'\xEB\x58\x90MSDOS5.0', 0x0B),  # FAT32
        (b'\xEB\x3C\x90MSDOS5.0', 0x06)   # FAT16
    ]

    try:
        with open(file_path, 'rb+') as f:
            print(f"[*] Raw 스캔 시작: {file_path}")
            
            # 앞부분 500MB 정도만 정밀 스캔 (MBR 파티션은 보통 앞쪽에 몰려있음)
            scan_size = 1024 * 1024 * 500 
            data = f.read(scan_size)
            
            for sig, p_type in targets:
                curr_pos = 0
                while True:
                    idx = data.find(sig, curr_pos)
                    if idx == -1: break
                    
                    # 512바이트(섹터) 단위로 정렬된 시그니처만 인정
                    if idx % 512 == 0:
                        lba_start = idx // 512
                        
                        # 섹터 수(Size) 추출
                        # NTFS: 오프셋 0x28(8B), FAT: 오프셋 0x20(4B)
                        if p_type == 0x07:
                            size = struct.unpack('<Q', data[idx+0x28 : idx+0x30])[0]
                        else:
                            size = struct.unpack('<I', data[idx+0x20 : idx+0x24])[0]
                        
                        # 비정상 크기 필터링 (4바이트 초과나 0 제외)
                        if 0 < size < 0xFFFFFFFF:
                            # 중복 LBA 체크
                            if not any(p['lba'] == lba_start for p in found_partitions):
                                found_partitions.append({'type': p_type, 'lba': lba_start, 'size': size})
                                print(f"[+] 파티션 발견! LBA: {lba_start}, 타입: {hex(p_type)}, 크기: {size}")
                    
                    curr_pos = idx + 1
                    if len(found_partitions) >= 4: break
                if len(found_partitions) >= 4: break

            if not found_partitions:
                print("[-] 파티션을 찾지 못했습니다. 시그니처가 손상되었거나 Raw가 아닐 수 있습니다.")
                return

            # --- MBR 파티션 테이블 작성 ---
            # 1. 0번 섹터의 파티션 테이블 영역(446~510)을 0으로 초기화
            f.seek(446)
            f.write(b'\x00' * 64)
            
            # 2. 찾은 파티션들을 하나씩 기록
            f.seek(446)
            for p in found_partitions:
                # 16바이트 엔트리: Boot(00) + CHS_S(000000) + Type + CHS_E(000000) + LBA + Size
                entry = struct.pack('<B3sB3sII', 0x00, b'\x00\x00\x00', p['type'], b'\x00\x00\x00', p['lba'], p['size'])
                f.write(entry)
                print(f"[*] MBR Table에 LBA {p['lba']} 기록 완료.")

            # 3. MBR 시그니처 작성
            f.seek(510)
            f.write(b'\x55\xAA')
            
            print(f"\n[!] 성공: 총 {len(found_partitions)}개 파티션 복구 및 MBR 재건 완료.")

    except PermissionError:
        print("[-] 퍼미션 오류: 파일을 닫고 관리자 권한으로 실행하세요.")
    except Exception as e:
        print(f"[-] 에러: {e}")

rebuild_mbr_raw('E:/forensic/E01/ence2.001')