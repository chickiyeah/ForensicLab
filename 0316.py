import hashlib


def hash_file(filepath, algorithm="sha256"):
    h = hashlib.new(algorithm)
    with open(filepath, "rb") as f:
        while chunk := f.read(4096):
            h.update(chunk)
    return h.hexdigest()
    
if __name__ == "__main__":
    path = input("해시 계산할 파일 경로: ")
    algo = input("알고리즘 입력 (md5 / sha1 / sha256 / sha512): ").lower()
    try:
        result = hash_file(path, algo)
        print(f"\n[{algo}] hash 값:")
        print(result)
    except FileNotFoundError:
        print("파일을 찾을 수 없습니다.")
    except ValueError:
        print("지원하지 않는 알고리즘입니다.")