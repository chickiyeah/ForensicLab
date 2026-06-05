import zipfile
import os

def unzip_with_pw_and_korean(zip_file, target_dir, password):
    # 비밀번호는 바이트 형태로 변환되어야 합니다.
    password_bytes = password.encode('utf-8')

    with zipfile.ZipFile(zip_file, 'r') as z:
        for info in z.infolist():
            # 1. 한글 파일명 깨짐 방지 처리
            try:
                filename = info.filename.encode('cp437').decode('cp949')
            except:
                filename = info.filename

            target_path = os.path.join(target_dir, filename)

            # 2. 폴더/파일 생성 및 해제
            if info.is_dir():
                os.makedirs(target_path, exist_ok=True)
            else:
                # 상위 폴더가 없을 경우 생성
                os.makedirs(os.path.dirname(target_path), exist_ok=True)
                
                # 암호를 입력하여 파일 내용 읽기
                with open(target_path, 'wb') as f:
                    try:
                        f.write(z.read(info.filename, pwd=password_bytes))
                    except RuntimeError:
                        print(f"오류: 암호가 틀렸거나 파일이 손상되었습니다 ({filename})")
                        return

# 사용 예시


unzip_with_pw_and_korean("C:/Users/0_8_2/VirtualDesktop.Android-20251201-223435.zip", "C:/Users/0_8_2/extracted_files","")
print("한글 파일명 복구 및 압축 해제 완료!")