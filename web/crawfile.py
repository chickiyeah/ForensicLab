import os

def carve_gif_from_raw(image_path, output_dir):
    # GIF의 표준 시그니처 (헤더와 푸터)
    GIF_HEADERS = [b'\x47\x49\x46\x38\x39\x61', b'\x47\x49\x46\x38\x37\x61']
    GIF_FOOTER = b'\x00\x3B' # GIF 파일의 끝을 알리는 바이트
    
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    print(f"[*] 분석 시작: {image_path}")
    
    with open(image_path, 'rb') as f:
        data = f.read() # 이미지 전체를 바이너리로 읽기 (파일이 너무 크면 분할 처리 필요)
        
        found_count = 0
        start_pos = 0
        
        while True:
            # 1. 헤더 찾기 (89a 혹은 87a)
            first_header = data.find(GIF_HEADERS[0], start_pos)
            second_header = data.find(GIF_HEADERS[1], start_pos)
            
            # 두 헤더 중 더 빨리 나타나는 지점 선택
            if first_header == -1: header_idx = second_header
            elif second_header == -1: header_idx = first_header
            else: header_idx = min(first_header, second_header)
            
            if header_idx == -1:
                break # 더 이상 GIF 헤더가 없음

            # 2. 푸터(끝지점) 찾기
            # 헤더 이후에 나오는 가장 가까운 00 3B를 찾음
            footer_idx = data.find(GIF_FOOTER, header_idx)
            
            if footer_idx != -1:
                # 파일 복구 (헤더부터 푸터까지 추출)
                # +2는 푸터 길이(\x00\x3B)만큼 포함하기 위함
                gif_content = data[header_idx : footer_idx + 2]
                
                found_count += 1
                file_name = f"recovered_{found_count}.gif"
                with open(os.path.join(output_dir, file_name), 'wb') as out:
                    out.write(gif_content)
                
                print(f"[!] 발견 및 복구 완료: {file_name} (오프셋: {hex(header_idx)})")
                
                # 다음 검색을 위해 시작 지점 갱신
                start_pos = footer_idx + 2
            else:
                # 푸터가 없으면 깨진 파일로 간주하고 넘어감
                start_pos = header_idx + 6

    print(f"\n[*] 작업 완료. 총 {found_count}개의 GIF를 복구했습니다.")

import os

def carve_with_metadata(image_path, output_dir, sector_size=512):
    # GIF 시그니처
    GIF_HEADERS = [b'\x47\x49\x46\x38\x39\x61', b'\x47\x49\x46\x38\x37\x61']
    GIF_FOOTER = b'\x00\x3B'
    
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    log_file = os.path.join(output_dir, "recovery_log.txt")
    
    print(f"[*] 분석 시작: {image_path} (섹터 크기: {sector_size}B)")
    
    with open(image_path, 'rb') as f:
        # 대용량 파일을 위해 메모리에 다 올리지 않고 처리하는 방식 권장하나, 
        # 이해를 돕기 위해 전체 읽기 방식을 유지합니다. (파일이 크면 분할 필요)
        data = f.read()
        
        found_count = 0
        start_pos = 0
        
        with open(log_file, "w", encoding="utf-8") as log:
            log.write(f"{'파일명':<20} | {'16진수 오프셋':<15} | {'섹터 위치':<15} | {'크기(Bytes)':<10}\n")
            log.write("-" * 70 + "\n")

            while True:
                # 1. 헤더 찾기
                h1 = data.find(GIF_HEADERS[0], start_pos)
                h2 = data.find(GIF_HEADERS[1], start_pos)
                
                if h1 == -1: header_idx = h2
                elif h2 == -1: header_idx = h1
                else: header_idx = min(h1, h2)
                
                if header_idx == -1: break

                # 2. 푸터 찾기
                footer_idx = data.find(GIF_FOOTER, header_idx)
                
                if footer_idx != -1:
                    gif_size = (footer_idx + 2) - header_idx
                    gif_content = data[header_idx : footer_idx + 2]
                    
                    # 위치 계산
                    sector_num = header_idx // sector_size
                    hex_offset = hex(header_idx)
                    
                    found_count += 1
                    file_name = f"recovered_{found_count}.gif"
                    
                    # 파일 저장
                    with open(os.path.join(output_dir, file_name), 'wb') as out:
                        out.write(gif_content)
                    
                    # 메타데이터 기록
                    log_entry = f"{file_name:<20} | {hex_offset:<15} | {sector_num:<15} | {gif_size:<10}\n"
                    log.write(log_entry)
                    print(f"[!] {file_name} 복구 완료 (Sector: {sector_num})")
                    
                    start_pos = footer_idx + 2
                else:
                    start_pos = header_idx + 6

    print(f"\n[*] 분석 완료! 로그 파일 확인: {log_file}")
# 실행 (이미지 경로와 저장 폴더 설정)
carve_with_metadata("E:\\forensic\\E01\\ence10.001", "c:\\users\\0_8_2\\extracted_files2")