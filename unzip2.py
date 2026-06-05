import pyzipper
from itertools import permutations

def attempt_extract(zip_path, pw):
    try:
        with pyzipper.AESZipFile(zip_path) as z:
            z.setpassword(pw.encode('utf-8'))
            z.extractall()
            return True
    except:
        return False

def crack_final_advanced(zip_path, sentence):
    # 1. 특수문자 제거 및 기본 단어 리스트업
    clean_sentence = sentence.replace("!", "").replace("'", "")
    words = clean_sentence.split()
    
    candidates = set()
    
    # 기본 문장 형태들 추가
    candidates.add(sentence)                      # 원본 문장
    candidates.add(sentence.strip("!"))           # 끝 느낌표 제거
    candidates.add(sentence.replace(" ", ""))     # 문장 전체 공백 제거
    candidates.add(sentence.lower())              # 전체 소문자

    # 2. 단어 조합 생성 (순열 이용)
    # n은 조합할 단어의 개수 (1개부터 4개까지 시도)
    for n in range(1, 5):
        for p in permutations(words, n):
            # (1) 공백 포함 조합 (예: "Julie Newmar")
            spaced_pw = " ".join(p)
            candidates.add(spaced_pw)
            candidates.add(spaced_pw.lower()) # 소문자 버전
            
            # (2) 공백 없는 조합 (예: "JulieNewmar")
            joined_pw = "".join(p)
            candidates.add(joined_pw)
            candidates.add(joined_pw.lower()) # 소문자 버전

    print(f"🧐 총 {len(candidates)}개의 조합을 시도합니다...")

    # 3. 무차별 대입 실행
    for idx, pw in enumerate(candidates):
        if attempt_extract(zip_path, pw):
            print(f"\n{"="*30}")
            print(f"🎯 암호 발견: {pw}")
            print(f"{"="*30}")
            return True
        
        if idx % 50 == 0:
            print(f"시도 중... [{idx}/{len(candidates)}]", end="\r")

    print("\n❌ 모든 조합 시도 실패. 단어 외의 다른 암호일 가능성이 큽니다.")
    return False

# 중복 제거 후 실행
zip_file = "C:/Users/0_8_2/Autoexec.zip" # 파일명을 확인하세요
hint_sentence = "Don't forget Julie Newmar in Gotham City Central Park!"

crack_final_advanced(zip_file, hint_sentence)