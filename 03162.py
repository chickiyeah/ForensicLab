import hashlib

def hash_string(text, algorithm="md5"):
    h = hashlib.new(algorithm)
    h.update(text.encode("utf-8"))
    etext = h.hexdigest()
    print(text ,etext , h)


def main():
    print("start program")
    text = input("해시 계산할 문자열 입력 : ")
    print(text)
    hash_string(text)
    print("end program")


if __name__ == "__main__":
    main()