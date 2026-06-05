import struct
import os

def recover_all_partitions(file_path):
    if not os.path.exists(file_path):
        print("[-] 파일을 찾을 수 없습니다.")
        return

    partitions = []
    sector_size = 512

    try:
        with open(file_path, 'rb+') as f:
            print(f"[*] {file_path} 전체 스캔 시작... (시간이 걸릴 수 있습니다)")
            
            # 1. 시그니처 검색 (전체 파일을 1MB씩 읽으며 스캔)
            chunk_size = 1024 * 1024
            offset = 0
            
            while len(partitions) < 4:  # MBR은 최대 4개 파티션
                chunk = f.read(chunk_size)
                if not chunk: break
                
                # FAT32(MSDOS5.0) 또는 NTFS(NTFS) 검색
                for sig, p_type in [(b'MSDOS5.0', 0x0B), (b'NTFS    ', 0x07)]:
                    idx = chunk.find(sig)
                    if idx != -1:
                        # VBR 시작 지점 계산
                        vbr_start_offset = offset + idx
                        if p_type == 0x0B: vbr_start_offset -= 3 # FAT32는 시그니처가 3바이트 뒤에 있음
                        
                        lba_start = vbr_start_offset // sector_size
                        
                        # 섹터 수(Size) 읽기
                        f.seek(vbr_start_offset + (0x20 if p_type == 0x0B else 0x28))
                        if p_type == 0x0B:
                            total_sectors = struct.unpack('<I', f.read(4))[0]
                        else:
                            total_sectors = struct.unpack('<Q', f.read(8))[0]
                        
                        partitions.append({
                            'type': p_type,
                            'lba': lba_start,
                            'size': total_sectors
                        })
                        print(f"[+] 파티션 발견! 타입: {hex(p_type)}, LBA: {lba_start}, 크기: {total_sectors}")
                        
                        # 찾은 지점 이후부터 다시 검색하도록 포인터 이동
                        f.seek(vbr_start_offset + (total_sectors * sector_size))
                        offset = f.tell()
                        break 
                else:
                    offset += chunk_size

            # 2. MBR 기록 (446번지부터)
            print(f"\n[*] 총 {len(partitions)}개의 파티션을 MBR에 기록합니다.")
            f.seek(446)
            for p in partitions:
                # Boot(1) + CHS_S(3) + Type(1) + CHS_E(3) + LBA_S(4) + Size(4)
                entry = struct.pack('<B3sB3sII', 
                                    0x00, b'\x00\x00\x00', p['type'], b'\x00\x00\x00', 
                                    p['lba'], p['size'])
                f.write(entry)
            
            # 3. MBR 시그니처 작성
            f.seek(510)
            f.write(b'\x55\xAA')
            print("[!] MBR 복구 완료! 모든 파티션 정보가 입력되었습니다.")

    except PermissionError:
        print("[-] 권한 오류: 파일을 닫거나 관리자 권한으로 실행하세요.")
    except Exception as e:
        print(f"[-] 에러: {e}")

# 사용 예시
# lbas = find_partition_start('your_file.001')

# 실행 (이미지 파일명을 여기에 입력하세요)
recover_all_partitions('E:\\forensic\\E01\\ence3.001')