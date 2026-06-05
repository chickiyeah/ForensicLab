import struct

starting_sector = 7168128
sector_size = 403456

# 1. 교수님 방식 (빅 엔디언 / 단순 변환)
hex_big1 = "{:08x}".format(starting_sector)
hex_big2 = "{:08x}".format(sector_size)

# 2. 실제 MBR 방식 (리틀 엔디언)
# <I : 리틀 엔디언(<) 방식의 4바이트 정수(I)로 변환
hex_little1 = struct.pack('<I', starting_sector).hex()
hex_little2 = struct.pack('<I', sector_size).hex()

print("--- [1. 교수님 스타일: 단순 변환] ---")
print(f"00 020300 0B 3173BE {hex_big1} {hex_big2}")

print("\n--- [2. 실제 MBR 스타일: 리틀 엔디언] ---")
# 리틀 엔디언은 보통 가독성을 위해 2글자씩 띄어쓰는 경우가 많습니다.
def split_hex(hex_str):
    return " ".join([hex_str[i:i+2] for i in range(0, len(hex_str), 2)])

print(f"00 02 03 00 0B 31 73 BE {split_hex(hex_little1)} {split_hex(hex_little2)}")