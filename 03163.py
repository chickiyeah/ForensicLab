import hashlib
import os

def calculate_drive_hash(drive_path, algorithm="sha256"):
    """
    드라이브(블록 디바이스) 자체의 Raw 데이터를 읽어 전체 해시값을 계산합니다.
    (Windows: \\\\.\\E: 또는 \\\\.\\PhysicalDrive0, Linux: /dev/sdb 등)
    ※ 관리자 권한이 필요합니다.
    """
    hash_func = hashlib.new(algorithm)
    
    print(f"{drive_path}의 Raw 드라이브 해시 계산 중... (시간이 오래 걸릴 수 있습니다)")
    
    try:
        # 드라이브를 바이너리 읽기 모드로 열기
        with open(drive_path, "rb") as f:
            # 드라이브의 전체 크기를 파악하여 진행률 계산 준비
            try:
                f.seek(0, 2)
                total_size = f.tell()
                f.seek(0)
            except OSError:
                total_size = 0  # 크기를 구할 수 없는 경우
            
            read_size = 0
            chunk_size = 1024 * 1024
            sector_size = 512
            
            while True:
                try:
                    chunk = f.read(chunk_size)  # 기본적으로 1MB씩 빠르게 읽기
                    if not chunk:
                        break
                    hash_func.update(chunk)
                    read_size += len(chunk)
                except (PermissionError, OSError):
                    return hash_func.hexdigest()# 권한/읽기 오류 발생 시, 파일 포인터를 현재 위치로 재정렬
                    try:
                        f.seek(read_size)
                    except OSError:
                        break  # 포인터마저 이동 불가능하면 종료
                    
                    # 오류가 난 1MB 구간만 512바이트(섹터) 단위로 잘게 쪼개서 정밀 복구 시도
                    for _ in range(chunk_size // sector_size):
                        try:
                            sector = f.read(sector_size)
                            if not sector:
                                break
                            hash_func.update(sector)
                            read_size += len(sector)
                        except (PermissionError, OSError):
                            # 접근이 완벽히 차단된 보호/불량 섹터는 0x00으로 패딩 (오프셋 유지)
                            hash_func.update(b'\x00' * sector_size)
                            read_size += sector_size
                            f.seek(read_size)  # 강제로 다음 섹터로 포인터 이동
                
                if total_size > 0:
                    percent = (read_size / total_size) * 100
                    print(f"\r진행률: {percent:.2f}% ({read_size / (1024**3):.2f} GB / {total_size / (1024**3):.2f} GB)", end="", flush=True)
                else:
                    print(f"\r진행 상황: {read_size / (1024**3):.2f} GB 읽음...", end="", flush=True)
            print()  # 해시 계산 완료 후 줄바꿈
    except PermissionError:
        print("접근 권한이 없습니다. 터미널/명령 프롬프트를 관리자 권한으로 실행해주세요.")
        return None
    except OSError as e:
        print(f"디바이스를 읽는 중 오류가 발생했습니다: {e}")
        return None

    return hash_func.hexdigest()

if __name__ == "__main__":
    print("※ 주의: Raw 드라이브 접근은 관리자 권한이 필요합니다.")
    usb_path = input("드라이브 디바이스 경로 입력 (예: \\\\.\\E: 또는 /dev/sdb): ")
    algo = input("알고리즘 입력 (md5 / sha1 / sha256): ").lower() or "sha256"
    
    try:
        result = calculate_drive_hash(usb_path, algo)
        if result:
            print(f"\n[Raw 드라이브 전체] {algo} 해시 값:")
            print(result)
    except ValueError:
        print("지원하지 않는 알고리즘입니다.")
    except Exception as e:
        print(f"오류 발생: {e}")
