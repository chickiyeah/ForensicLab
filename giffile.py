import pytsk3
import sys

def scan_image(image_path):
    # 1. 이미지 파일 열기
    img_info = pytsk3.Img_Info(image_path)
    
    try:
        # 2. 파티션 테이블 분석 (MBR/GPT 등 자동 인식)
        volume = pytsk3.Volume_Info(img_info)
        print(f"[*] 파티션 분석 완료: {len(volume)} 개의 영역 발견")
    except Exception as e:
        print(f"[!] 파티션 정보를 읽을 수 없습니다 (Raw 파티션으로 시도): {e}")
        volume = None

    if volume:
        for partition in volume:
            # 실제 데이터가 있는 파티션만 탐색 (비할당 공간 제외)
            if partition.len > 2048 and "Unallocated" not in partition.desc.decode():
                print(f"\n--- 파티션 분석: {partition.desc.decode()} (시작 섹터: {partition.start}) ---")
                try:
                    fs_info = pytsk3.FS_Info(img_info, offset=partition.start * 512)
                    root_dir = fs_info.open_dir(path="/")
                    recursive_scan(root_dir, [])
                except Exception as e:
                    print(f"    [!] 파일 시스템 인식 실패: {e}")
    else:
        # 파티션 테이블이 없는 경우 (통이미지)
        fs_info = pytsk3.FS_Info(img_info)
        root_dir = fs_info.open_dir(path="/")
        recursive_scan(root_dir, [])

def recursive_scan(directory, path_segments):
    for directory_entry in directory:
        # '.', '..' 디렉토리 제외
        name = directory_entry.info.name.name.decode('utf-8')
        if name in [".", ".."]:
            continue

        current_path = path_segments + [name]
        full_path = "/" + "/".join(current_path)

        # 3. 삭제된 파일 여부 확인
        is_deleted = "Deleted" if directory_entry.info.meta and \
                     directory_entry.info.meta.flags & pytsk3.TSK_FS_META_FLAG_UNALLOC else "Active"

        # 4. 필터링 (LNK, GIF 또는 특정 이름 검색)
        ext = name.lower().split('.')[-1]
        if ext in ['gif', 'lnk'] or 'findx' in name.lower():
            print(f"[{is_deleted}] 발견: {full_path}")
            
            # 파일 내용 추출 (추가 로직)
            # file_obj = directory_entry.open_file()
            # file_data = file_obj.read_random(0, file_obj.info.meta.size)

        # 디렉토리인 경우 재귀 탐색
        if directory_entry.info.meta and \
           directory_entry.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
            try:
                sub_dir = directory_entry.as_directory()
                recursive_scan(sub_dir, current_path)
            except:
                pass

# 실행 예시
scan_image("E:\\forensic\\E01\\ence10.001")