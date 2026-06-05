import struct
import os

def scan_and_repair_mbr_smart(image_path):
    clean_path = image_path.replace('&', '').replace("'", "").replace('"', '').strip()
    
    if not os.path.exists(clean_path):
        print(f"[-] 파일을 찾을 수 없습니다: {clean_path}")
        return

    partitions = []
    sector_size = 512
    chunk_size = 10 * 1024 * 1024 

    try:
        with open(clean_path, 'rb+') as f:
            file_size = os.path.getsize(clean_path)
            print(f"[*] {clean_path} 스마트 스캔 시작 (백업 섹터 필터링 적용)...")
            
            offset = 0
            while offset < file_size:
                f.seek(offset)
                chunk = f.read(chunk_size + sector_size) 
                if not chunk: break
                
                for sig, p_type in [(b'MSDOS5.0', 0x0C), (b'NTFS    ', 0x07)]:
                    start_idx = 0
                    while True:
                        idx = chunk.find(sig, start_idx)
                        if idx == -1: break
                        
                        vbr_start = offset + idx - 3
                        
                        if vbr_start >= 0 and vbr_start % sector_size == 0:
                            lba = vbr_start // sector_size
                            
                            f.seek(vbr_start)
                            header = f.read(sector_size)
                            
                            if len(header) == 512 and header[510:512] == b'\x55\xAA':
                                if p_type == 0x0C: # FAT32
                                    size = struct.unpack('<I', header[0x20:0x24])[0]
                                    name = "FAT32"
                                else: # NTFS
                                    size = struct.unpack('<Q', header[0x28:0x30])[0]
                                    name = "NTFS"
                                
                                if 0 < size < 0xFFFFFFFF:
                                    # --- [핵심 지능형 필터] 백업 섹터 거르기 ---
                                    is_backup = False
                                    for p in partitions:
                                        # FAT32 백업 (시작점 + 6) 검사
                                        if p['name'] == 'FAT32' and lba == p['lba'] + 6:
                                            is_backup = True
                                            print(f"[-] ♻️ FAT32 백업 섹터 스킵됨 (LBA {lba})")
                                            break
                                        # NTFS 백업 (시작점 + 크기) 검사 (오차 1섹터 허용)
                                        if p['name'] == 'NTFS' and abs(lba - (p['lba'] + p['size'])) <= 1:
                                            is_backup = True
                                            print(f"[-] ♻️ NTFS 백업 섹터 스킵됨 (LBA {lba})")
                                            break
                                    
                                    # 백업이 아니고, 아직 등록 안 된 LBA면 추가!
                                    if not is_backup and not any(p['lba'] == lba for p in partitions):
                                        partitions.append({'type': p_type, 'lba': lba, 'size': size, 'name': name})
                                        print(f"[+] 🎯 진짜 {name} 등록 완료! -> LBA: {lba}")
                        
                        start_idx = idx + 1
                
                offset += chunk_size
                if len(partitions) >= 4: 
                    break

            # --- MBR 파티션 테이블 재건 ---
            if not partitions:
                print("\n[-] 유효한 파티션을 찾지 못했습니다.")
                return

            partitions.sort(key=lambda x: x['lba'])
            
            f.seek(446)
            f.write(b'\x00' * 64) 

            print(f"\n[*] 최종 확정된 {len(partitions)}개의 파티션을 MBR에 기록합니다.")
            for i, p in enumerate(partitions[:4]):
                f.seek(446 + (i * 16))
                entry = struct.pack('<B3sB3sII', 0x00, b'\x00\x00\x00', p['type'], b'\x00\x00\x00', p['lba'], p['size'])
                f.write(entry)
                print(f" -> [Slot {i+1}] {p['name']} 기록 완료 (LBA {p['lba']}, Size {p['size']})")

            f.seek(510)
            f.write(b'\x55\xAA')
            
            print("\n✅ 지능형 MBR 완벽 복구 완료!")

    except PermissionError:
        print("\n❌ [권한 오류] 툴을 끄고 실행하세요.")
    except Exception as e:
        print(f"\n❌ [오류 발생] {e}")

scan_and_repair_mbr_smart('C:/Users/0_8_2/131.001')