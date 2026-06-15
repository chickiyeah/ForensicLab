"""ForensicLab — 도구별 사용법 도움말 시스템"""
from flask import request, render_template, jsonify
from monitor.views.tools import bp


# url path → 도움말 dict
# 각 도움말: title, what, how, input, output, example, tips, related
_TOOL_HELP = {
    # ─────────── 기본 도구 ───────────
    'hash': {
        'what': '파일 또는 텍스트의 MD5·SHA1·SHA256·SHA512 해시를 계산하고 두 값을 비교하여 무결성을 검증합니다.',
        'how': '1) 파일 업로드 또는 텍스트 입력 → 2) 알고리즘 선택 → 3) 분석 시작 → 4) 두 값 비교 시 양쪽에 입력',
        'input': '모든 파일 (제한: 200MB) 또는 텍스트',
        'output': '각 알고리즘별 16진수 해시값',
        'tips': '증거 파일 위변조 확인 시 원본 해시와 비교. 같은 해시 = 동일 파일 보장.',
    },
    'carve': {
        'what': 'RAW 디스크 이미지나 메모리 덤프에서 GIF·JPEG·PNG·PDF·ZIP 파일 시그니처를 탐색해 삭제된 파일을 복구합니다.',
        'how': '1) 디스크 이미지 업로드 → 2) 시그니처 종류 선택 → 3) 카빙 실행 → 4) 결과 다운로드',
        'input': '.dd / .raw / .img / 메모리 덤프',
        'output': '복구된 파일 ZIP 다운로드',
        'tips': '파일시스템 메타데이터 없이 시그니처만으로 복구하므로 헤더가 손상된 파일은 못 찾음.',
    },
    'mbr': {
        'what': '디스크 이미지의 MBR 파티션 테이블을 파싱하고 VBR 시그니처를 스캔하여 파티션 구조를 시각화합니다.',
        'how': '1) 디스크 이미지 또는 MBR 섹터(512B) 업로드 → 2) 자동 분석',
        'input': '.dd / .img / MBR 섹터 파일',
        'output': '4개 파티션 엔트리 + VBR 시그니처 + 헥스덤프',
        'tips': '읽기 전용. 손상된 MBR 복구는 /tools/mbr-repair 사용.',
    },
    'mbr-repair': {
        'what': '손상된 MBR을 VBR 시그니처 스캔으로 자동 재건합니다. ⚠️ 디스크에 쓰기 작업.',
        'how': '1) 이미지 업로드 또는 서버 연결 외부 장치 선택 → 2) 미리보기로 발견된 파티션 확인 → 3) 적용',
        'input': '이미지 파일 또는 /dev/sdX',
        'output': '재건된 MBR + 백업',
        'tips': '⚠️ 원본 백업 필수. 본인 소유 매체에서만 사용. 로컬 PC 디스크는 다운로드 스크립트 사용.',
    },
    'strings': {
        'what': '바이너리 파일에서 인쇄 가능한 ASCII·UTF-16·UTF-32·CJK 문자열을 추출합니다.',
        'how': '1) 파일 업로드 → 2) 최소 길이/인코딩/키워드 설정 → 3) 실행',
        'input': '모든 바이너리 파일',
        'output': '추출된 문자열 + 오프셋 + 인코딩 표시',
        'tips': '악성코드에서 URL·명령·경로 단서 추출. 인코딩은 OS별 다름 (Windows=UTF-16 LE).',
    },
    'log': {
        'what': 'Apache·Nginx·IIS·syslog·journalctl·Windows Event·Docker·k8s·CloudTrail 등 12종 로그 포맷 자동 파싱.',
        'how': '1) 로그 파일 또는 텍스트 붙여넣기 → 2) 자동 형식 감지',
        'input': '.log / .txt / EVTX export',
        'output': '이벤트별 분류 + 상위 IP/상태/공격 패턴',
        'tips': '대용량은 잘림. 분할 업로드 권장.',
    },
    'gps': {
        'what': '이미지 EXIF GPS 좌표 추출 + OpenStreetMap 지도 + DMS 형식 변환.',
        'how': '1) JPEG/TIFF/HEIC 업로드 → 2) 자동 지도 표시',
        'input': '.jpg / .jpeg / .tiff / .heic',
        'output': '좌표 (Decimal·DMS) + 지도 핀 + Google Maps 링크',
        'tips': '대부분 SNS 업로드 이미지는 EXIF 제거됨. 원본 사진에서만 작동.',
    },
    'metadata': {
        'what': '이미지 EXIF·카메라·촬영설정·PDF 속성·파일 해시 통합 추출.',
        'how': '1) 파일 업로드 → 2) 자동 메타데이터 표시',
        'input': '이미지·PDF·바이너리',
        'output': 'EXIF + 카메라 + 촬영설정 + PDF 메타 + 해시',
        'tips': '메타데이터에 사용자 이름·소프트웨어 버전·GPS 등 민감 정보 포함됨.',
    },
    'timeline': {
        'what': 'EXIF·PDF·LNK·Prefetch·EML·DOCX 파일들에서 타임스탬프 추출 후 통합 타임라인.',
        'how': '1) 여러 파일 업로드 → 2) 자동 통합·정렬',
        'input': '복수 파일 (이미지·PDF·로그·LNK·.pf)',
        'output': '시간순 통합 타임라인',
        'tips': '대규모 타임라인은 /tools/plaso 권장.',
    },
    'pcap': {
        'what': 'PCAP/PCAPNG 파일 → 프로토콜 분포·IP 통계·DNS·HTTP·의심 패턴.',
        'how': '1) .pcap 업로드 → 2) 자동 파싱',
        'input': '.pcap / .pcapng (최대 100MB)',
        'output': '프로토콜 비율 + 상위 IP + 의심 흐름',
        'tips': 'TLS 1.3은 SNI 외 내용 분석 불가. wireshark display filter 학습 권장.',
    },
    'email': {
        'what': '.eml/.msg/.mbox 파일의 헤더·발신경로·첨부·스푸핑 탐지.',
        'how': '1) 이메일 파일 업로드 → 2) 자동 분석',
        'input': '.eml / .msg / .mbox / .emlx',
        'output': '헤더 + 본문 + 첨부 + 의심 패턴',
        'tips': 'SPF/DKIM/DMARC 검증은 /tools/email-auth, 헤더 심층 분석은 /tools/emaildeep',
    },
    'zipcrack': {
        'what': 'ZIP 파일 비밀번호 사전·브루트포스 크래킹.',
        'how': '1) 암호화된 ZIP 업로드 → 2) wordlist 선택 또는 마스크 설정 → 3) 시작',
        'input': '암호화 ZIP',
        'output': '발견된 비밀번호',
        'tips': '느림. 큰 ZIP은 /tools/hashcat-job (RAR/7Z/Office 등도 가능)',
    },
    'encrypt': {
        'what': '파일 AES-256-GCM 암호화/복호화 + PBKDF2 키 유도.',
        'how': '1) 모드 선택 (암호화/복호화) → 2) 비밀번호 입력 → 3) 파일 업로드',
        'input': '평문 (암호화) / .enc (복호화)',
        'output': '암호화된 / 복호화된 파일',
        'tips': '비밀번호 분실 시 복호화 불가. 키 안전하게 보관.',
    },
    'registry': {
        'what': 'NTUSER·SAM·SYSTEM·SOFTWARE·SECURITY·.reg 파싱 + 50+ 바이너리 디코더 + 자동실행·USB·실행이력 탐지.',
        'how': '1) 하이브 파일 업로드 → 2) 트리에서 키 선택 → 3) 값별 자동 디코딩',
        'input': 'NTUSER.DAT / SAM / SYSTEM / Amcache.hve / .reg',
        'output': '키 트리 + 값 + 포렌식 발견사항',
        'tips': '바이너리 값(RegBin)은 SAM V·UserAssist·MountedDevices 등 자동 해석. 사람이 읽는 형태로.',
    },

    # ─────────── 실행파일 ───────────
    'pe': {
        'what': 'Windows PE / Linux ELF / macOS Mach-O 헤더·섹션·임포트·의심 API 자동 탐지.',
        'how': '1) .exe/.dll/.so/.dylib 업로드 → 2) 자동 분석',
        'input': 'PE/ELF/Mach-O 바이너리',
        'output': '머신·시각·섹션·엔트로피·임포트 DLL·의심 API',
        'tips': '섹션 엔트로피 >7.0 = 패킹/암호화. VirtualAlloc·CreateRemoteThread 등은 인젝션 가능성.',
    },
    'entropy': {
        'what': 'Shannon 엔트로피 + 슬라이딩 윈도우 + 50+ 매직바이트 시그니처.',
        'how': '1) 파일 업로드 → 2) 자동 엔트로피 그래프',
        'input': '모든 파일',
        'output': '엔트로피 그래프 + 시그니처 + 판정',
        'tips': '7.5+ = 암호화/압축, 6.8-7.5 = 패킹된 EXE, <5.0 = 텍스트.',
    },
    'decode': {
        'what': 'Base64·Base32·Base85·Hex·URL·ROT-N·Atbash·Vigenère·XOR·Morse·이진수·10진수 동시 시도.',
        'how': '1) 텍스트 입력 → 2) (선택) Vigenère/XOR 키 → 3) 자동 모든 방식 시도',
        'input': '인코딩된 텍스트',
        'output': '방식별 디코딩 결과 (점수순 정렬)',
        'tips': '점수 90+ = 가장 가능성 높음. 다중 인코딩은 결과 다시 디코드.',
    },
    'prefetch': {
        'what': 'Windows Prefetch (.pf) 파일에서 실행 횟수·최대 8회 실행 시각·참조 파일 추출.',
        'how': '1) .pf 파일 업로드 → 2) 자동 분석',
        'input': 'C:\\Windows\\Prefetch\\*.pf',
        'output': 'EXE명·실행 횟수·시각·참조 파일',
        'tips': 'MAM 압축 (Win10+) 자동 해제. 부정 실행의 핵심 증거.',
    },
    'lnk': {
        'what': '.lnk 바로가기에서 대상 경로·작업폴더·MAC 주소·볼륨 시리얼·생성/접근/수정 시각.',
        'how': '1) .lnk 업로드 → 2) 자동 파싱',
        'input': 'Windows 바로가기 (.lnk)',
        'output': '대상·인수·MAC·DroidBirth·타임스탬프',
        'tips': 'MAC 주소는 LNK 생성 시점의 PC NIC. 추적 핵심 단서.',
    },
    'diskimg': {
        'what': 'E01·VHD·VHDX·VMDK·QCOW2·NTFS·ext·APFS·GPT 등 20+ 디스크/볼륨 포맷 자동 인식.',
        'how': '1) 이미지 파일 업로드 → 2) 자동 감지',
        'input': '.dd / .img / .E01 / .vhd / .vhdx / .vmdk / .qcow2',
        'output': '포맷 + MBR 파티션 + 헥스 헤더',
        'tips': '앞 8KB + 뒤 4KB만 읽음. 깊은 분석은 /tools/e01-mount / /tools/mft-full.',
    },

    # ─────────── Windows 아티팩트 ───────────
    'evtx': {
        'what': 'Windows .evtx 이벤트 로그 풀 파싱 + 이벤트 ID 통계.',
        'how': '1) .evtx 업로드 → 2) 자동 파싱',
        'input': 'C:\\Windows\\System32\\winevt\\Logs\\*.evtx',
        'output': '이벤트 목록 + 상위 ID',
        'tips': '핵심 ID: 4624 로그온·4625 실패·4688 프로세스·7045 서비스·1102 로그 삭제.',
    },
    'jumplist': {
        'what': '.automaticDestinations-ms (OLECF DestList) 파싱 — 최근 접근 파일·횟수·시각.',
        'how': '1) JumpList 파일 업로드',
        'input': '%APPDATA%\\Microsoft\\Windows\\Recent\\AutomaticDestinations\\*.automaticDestinations-ms',
        'output': '엔트리·시각·핀 상태·접근 횟수',
        'tips': 'EntryID = 스트림명 hex. DroidFileID에 MAC 포함.',
    },
    'mft': {
        'what': 'NTFS $MFT FILE 레코드 파싱 — 파일명·MAC 타임·삭제 여부.',
        'how': '1) $MFT 파일 또는 디스크 이미지 업로드 (50MB 제한)',
        'input': '$MFT raw extract',
        'output': '파일 목록 + 4개 타임스탬프 + inode',
        'tips': '대용량은 /tools/mft-full (pytsk3 기반).',
    },
    'esedb': {
        'what': 'ESE DB (SRUDB·Windows.edb·WebCacheV01) 헤더 파싱.',
        'how': '1) .edb / .dat 업로드',
        'input': 'ESE 데이터베이스 파일',
        'output': '시그니처 + 페이지 크기 + DB 상태',
        'tips': '풀 파싱은 libesedb / SrumECmd 별도 도구.',
    },
    'amcache': {
        'what': 'Amcache.hve의 InventoryApplicationFile 키 자동 추출 — 실행파일 SHA1·LinkDate·제품명.',
        'how': '1) Amcache.hve 업로드',
        'input': 'C:\\Windows\\AppCompat\\Programs\\Amcache.hve',
        'output': 'Modern 키 (Win10+) + Legacy 키 (Win7-8)',
        'tips': '시스템에 한 번이라도 실행된 PE의 영구 기록.',
    },

    # ─────────── 문서·DB ───────────
    'sqlite': {
        'what': 'SQLite 데이터베이스 브라우저 + SELECT 쿼리.',
        'how': '1) .db/.sqlite 업로드 → 2) 테이블 목록 → 3) "쿼리 채우기" 클릭 → 실행',
        'input': 'SQLite DB (Chrome History·Firefox places·iOS Manifest 등)',
        'output': '테이블 목록 + 쿼리 결과 (최대 1000행)',
        'tips': '읽기 전용. SELECT/PRAGMA/WITH만 허용.',
    },
    'oledump': {
        'what': 'Office 문서 VBA 매크로·OLE 스트림·임베디드 객체·의심 키워드.',
        'how': '1) .doc/.docx/.xls/.xlsm 업로드',
        'input': 'Office 97-2003 (OLE2) 또는 2007+ (OOXML)',
        'output': '스트림·매크로·의심 키워드 (powershell·http·Shell)',
        'tips': 'VBA 디오브푸는 /tools/psdeobf로 코드 추출 후 분석.',
    },
    'pdfscan': {
        'what': 'PDF 내 /JavaScript·/OpenAction·/Launch·/EmbeddedFile·URL 탐지.',
        'how': '1) .pdf 업로드',
        'input': 'PDF 파일',
        'output': '의심 패턴·객체 카운트·URL 목록',
        'tips': '/JavaScript + /OpenAction = 자동 실행 악성 PDF 의심.',
    },
    'plist': {
        'what': 'macOS bplist 바이너리 + XML plist 파싱.',
        'how': '1) .plist 업로드',
        'input': 'bplist00 또는 XML plist',
        'output': '구조화된 JSON',
        'tips': 'LaunchAgents·LaunchDaemons·앱 설정·QuarantineEvents 분석에 사용.',
    },

    # ─────────── 암호·서명 ───────────
    'jwt': {
        'what': 'JWT (JSON Web Token) Header·Payload·Signature 분해 + alg=none·만료 검증.',
        'how': '1) JWT 토큰 붙여넣기 → 2) 자동 분해',
        'input': 'header.payload.signature 형식',
        'output': '디코드된 JSON + 검증 경고',
        'tips': 'alg=none = 서명 없음 (취약점). HS256·RS256은 키 필요.',
    },
    'cert': {
        'what': 'X.509 인증서 (PEM/DER/PKCS#12) 파싱 + 자가서명·취약 알고리즘 경고.',
        'how': '1) .crt/.pem/.der/.p12 업로드 또는 PEM 텍스트',
        'input': 'X.509 인증서',
        'output': 'Subject·Issuer·SAN·유효기간·지문 (SHA-256/1)',
        'tips': 'SHA-1 서명·짧은 키·만료 임박 = 위험 신호.',
    },
    'yara': {
        'what': 'YARA-lite 규칙 (문자열·헥스 패턴)으로 파일 스캔.',
        'how': '1) 검사 파일 업로드 → 2) YARA 규칙 입력 → 3) 스캔',
        'input': '파일 + YARA rule 텍스트',
        'output': '규칙 매칭 결과 + 오프셋',
        'tips': '문자열 + 헥스만 지원 (정규식 X). 풀 YARA 필요 시 yara-python 별도 설치.',
    },
    'secrets': {
        'what': '소스 코드/로그/설정 파일에서 AWS·GCP·GitHub·Slack·Stripe·DB 비밀번호 등 22종 자동 탐지.',
        'how': '1) 파일 업로드 또는 텍스트 붙여넣기',
        'input': '모든 텍스트/코드',
        'output': '발견된 시크릿 + 타입·위치',
        'tips': '커밋 전 점검에 유용. 발견 즉시 키 재발급 권장.',
    },
    'passwd': {
        'what': '비밀번호 강도 측정 — Shannon 엔트로피·문자 클래스·일반 비밀번호 사전.',
        'how': '1) 비밀번호 입력 → 2) 자동 측정',
        'input': '비밀번호 텍스트',
        'output': '등급 (매우약함~매우강함) + 크랙 시간 + 약점',
        'tips': '입력은 로그에 저장되지 않습니다. 메모리에서만 처리.',
    },
    'stego': {
        'what': '이미지 LSB 편향 + 파일 끝 부가 데이터 + 임베디드 시그니처 탐지.',
        'how': '1) 이미지 업로드',
        'input': 'JPEG/PNG/BMP',
        'output': 'LSB 비율 + EOF 데이터 + 임베디드 ZIP/PE 등',
        'tips': 'LSB 1비율 ~50% = 정상. 편향 시 메시지 추출 자동 시도.',
    },
    'hexdiff': {
        'what': '두 파일을 바이트 단위로 비교 (Unified diff)',
        'how': '1) 파일 A·B 업로드 → 2) 자동 비교',
        'input': '두 파일',
        'output': '오프셋별 차이 + SHA-256 비교',
        'tips': '패치 분석·변조 탐지에 유용.',
    },

    # ─────────── 네트워크·메일 ───────────
    'email-auth': {
        'what': 'SPF·DKIM·DMARC 정책 조회 + 이메일 헤더 검증 결과 표시.',
        'how': '1) 도메인 입력 (DNS 조회) 또는 이메일 헤더 붙여넣기',
        'input': '도메인 또는 raw 헤더',
        'output': 'SPF·DMARC TXT + MX + Pass/Fail 배지',
        'tips': '피싱 이메일의 발신 도메인 신뢰도 확인에 사용.',
    },
    'dns': {
        'what': '도메인 → DGA(Domain Generation Algorithm) 휴리스틱 점수.',
        'how': '1) 도메인 목록 (한 줄에 하나) → 2) 자동 점수',
        'input': '도메인 텍스트',
        'output': '도메인별 점수 (0-100) + 판정',
        'tips': '점수 50+ = DGA 강력 의심. 봇넷 C2 도메인 탐지.',
    },
    'whois': {
        'what': '도메인·IP의 WHOIS 정보 + RFC1918 분류 + RIR 추정.',
        'how': '1) 도메인 또는 IP 입력',
        'input': '도메인 또는 IPv4',
        'output': '등록자·국가·ASN·NetRange + 전체 WHOIS 응답',
        'tips': 'raw WHOIS 프로토콜 (port 43). 일부 TLD는 정보 마스킹.',
    },

    # ─────────── 이미지·기타 ───────────
    'qr': {
        'what': '이미지에서 QR·EAN·Code128·Code39 등 바코드 디코딩.',
        'how': '1) 이미지 업로드',
        'input': '이미지 (PNG/JPEG)',
        'output': '코드 타입·내용·위치',
        'tips': 'pyzbar + libzbar 시스템 패키지 필요. QR URL은 /tools/urlsafe로 검사.',
    },
    'ocr': {
        'what': 'tesseract OCR — 이미지/스크린샷에서 텍스트 추출 (한·영·일·중).',
        'how': '1) 이미지 업로드 → 2) 언어 선택',
        'input': '이미지 (PNG/JPEG/TIFF)',
        'output': '추출된 텍스트 + 단어/글자 수',
        'tips': '한국어는 lang=kor 또는 eng+kor. 인덱싱 검색은 /tools/ocr-index.',
    },
    'phash': {
        'what': '이미지 perceptual hash (aHash) + Hamming 거리로 유사 이미지 탐지.',
        'how': '1) 2개 이상 이미지 업로드',
        'input': '이미지들',
        'output': '해시 + 페어별 유사도 (%)',
        'tips': '90%+ = 거의 동일, 70%+ = 유사 (크기/색조 변형). 정확한 매칭은 SHA-256 사용.',
    },
    'git': {
        'what': '.git 디렉터리 ZIP에서 커밋·브랜치·blob·logs 추출.',
        'how': '1) .git 폴더를 ZIP으로 압축 (zip -r repo_git.zip .git) → 2) 업로드',
        'input': '.git/* ZIP',
        'output': '커밋 메시지·작성자·삭제된 blob·HEAD 활동 로그',
        'tips': '삭제된 blob에서 비밀키·민감정보 발견 가능. .gitignore 점검 필수.',
    },

    # ─────────── PRO ───────────
    'vol-full': {
        'what': 'Volatility 3 풀 통합 — 23개 플러그인으로 메모리 덤프 분석.',
        'how': '1) .dmp/.raw 업로드 → 2) 플러그인 선택 (pslist·malfind·netscan 등) → 3) 백그라운드 실행',
        'input': '메모리 덤프 (Windows/Linux/macOS)',
        'output': '/tools/jobs/<id>에서 결과 폴링',
        'tips': '대용량 (GB) 메모리 덤프는 10분+ 소요. 로컬 PC에서 빠를 수 있음.',
    },
    'aleapp': {
        'what': 'ALEAPP — Android 추출 ZIP에서 200+ 아티팩트 자동 파싱.',
        'how': '1) Android 추출 ZIP 업로드 → 2) 백그라운드 실행',
        'input': 'Magnet/Cellebrite/MSAB ZIP 또는 adb backup',
        'output': 'HTML 보고서 + 아티팩트 파일 목록',
        'tips': '시간 소요 큼 (20분+). Cellebrite UFED 대체 가능.',
    },
    'ileapp': {
        'what': 'iLEAPP — iOS 백업/추출에서 300+ 아티팩트 자동 파싱.',
        'how': '1) iOS 백업 ZIP 업로드 → 2) 백그라운드 실행',
        'input': 'iTunes 백업 또는 GrayKey/Cellebrite 추출',
        'output': 'HTML 보고서 + 아티팩트',
        'tips': 'Manifest.db 포함된 백업 ZIP 필요.',
    },
    'e01-mount': {
        'what': 'EnCase E01·Ex01 이미지 메타데이터·해시·세그먼트 분석 (libewf).',
        'how': '1) .E01 업로드',
        'input': '.E01 / .Ex01 / .S01',
        'output': '미디어 크기 + 해시 + 헤더 값 (case_number·examiner 등)',
        'tips': '풀 마운트는 별도 libewf 도구. 여기선 메타데이터만.',
    },
    'mft-full': {
        'what': 'pytsk3 기반 풀 MFT/파일시스템 워킹 (디스크 이미지 직접).',
        'how': '1) 디스크 이미지 업로드 → 2) 파일시스템 자동 인식',
        'input': '.dd / .img / .E01 / $MFT',
        'output': '파일 트리 + 4개 타임스탬프 + inode',
        'tips': '큰 디스크는 메모리 부담. 최대 1000파일까지 워킹.',
    },
    'hashcat-job': {
        'what': 'Hashcat 통합 — MD5·NTLM·ZIP·Office·BitLocker 등 30+ 모드 해시 크래킹.',
        'how': '1) 모드 선택 → 2) 해시 입력 → 3) 사전 또는 마스크 입력 → 4) 백그라운드 실행',
        'input': '해시 텍스트 + 사전/마스크',
        'output': '/tools/jobs/<id> 에서 크래킹된 비밀번호',
        'tips': 'GPU 없는 CPU 모드라 느림. 큰 사전은 별도 PC 사용 권장. 30분 타임아웃.',
    },
    'llm-report': {
        'what': 'Claude API로 분석 결과 → 전문가 narrative 포렌식 보고서 자동 생성.',
        'how': '1) Anthropic API 키 입력 → 2) 분석 결과 JSON/텍스트 → 3) 언어 선택',
        'input': 'API 키 + 분석 결과 (최대 30KB)',
        'output': '6섹션 보고서 (개요·방법론·발견·위협·권장조치·결론)',
        'tips': 'API 비용: 입력 $3/M·출력 $15/M (Sonnet 4.5). 한국어/영어/일본어/중국어 지원.',
    },
    'coc': {
        'what': 'Chain of Custody — SHA-256 해시 사슬로 변조 불가 증거 보관.',
        'how': '1) 증거 업로드 + 액션(접수/이관/분석) 선택 → 2) 자동 체인 추가 → 3) 검증',
        'input': '모든 파일',
        'output': '체인 무결성 + JSONL 다운로드 + 인증서',
        'tips': '모든 분석 도구가 자동으로 CoC에 기록. 법정 인정 증거 보관에 사용.',
    },
    'jobs': {
        'what': 'Volatility/Hashcat/ALEAPP 등 대용량 백그라운드 작업 큐.',
        'how': '작업 자동 등록 → 진행률 모니터링',
        'input': '(자동)',
        'output': '작업 ID·상태·진행률·로그·결과',
        'tips': '5초마다 자동 새로고침. 작업 결과는 JSON으로 반환.',
    },

    # ─────────── 엔터프라이즈 ───────────
    'case': {
        'what': '사건 관리 — 사건 생성·증거 등록·발견사항·북마크·종료.',
        'how': '1) 새 사건 생성 → 2) 증거 업로드 → 3) 발견사항/북마크 추가 → 4) PDF 보고서',
        'input': '사건명·분석가·증거 파일들',
        'output': '사건 대시보드 + 증거 + 발견사항',
        'tips': '각 사건마다 자동으로 CoC 기록. PDF 보고서로 출력 가능.',
    },
    'search': {
        'what': '사건·증거·발견사항·도구 결과·OCR 텍스트 통합 풀텍스트 검색 (SQLite FTS5).',
        'how': '1) 검색어 입력 → 2) 자동 매칭',
        'input': '검색어',
        'output': '사건/증거/발견사항 매칭 + 하이라이트',
        'tips': '여러 단어 AND로 검색 가능. FTS5 문법 지원.',
    },
    'dashboard': {
        'what': '전체 사건·증거·발견·도구 사용 통계 시각화.',
        'how': '/tools/dashboard 접속',
        'input': '(자동)',
        'output': '사건·증거·발견 통계 + 최근 활동',
        'tips': '심각도별·도구별·일별 활동 차트.',
    },
    'attack': {
        'what': '분석 결과 텍스트 → MITRE ATT&CK 기법 자동 매핑 (41개 기법 DB).',
        'how': '1) 로그/분석 결과 붙여넣기 → 2) 자동 매핑',
        'input': '로그·텍스트',
        'output': '탐지 기법 + 전술별 집계 + 킬체인 단계',
        'tips': '키워드 휴리스틱이므로 정확도는 어림. 전문 ATT&CK 매핑은 별도 분석가 검토 필요.',
    },
    'threat-intel': {
        'what': 'IOC (IP/해시/도메인) → VirusTotal + AbuseIPDB 평판 조회.',
        'how': '1) IOC 입력 → 2) API 키 입력 (선택) → 3) 조회',
        'input': 'IP/해시/도메인 + API 키',
        'output': '평판·악성·국가·ASN·태그',
        'tips': 'API 키 없으면 로컬 휴리스틱만 사용. VT 무료 키 가능.',
    },
    'ai-classify': {
        'what': '파일 → OpenCV·시그니처·키워드 종합 자동 분류 + 얼굴 감지.',
        'how': '1) 파일 업로드',
        'input': '모든 파일',
        'output': '카테고리·태그·이미지 메타·얼굴 수',
        'tips': '확장자-시그니처 불일치 자동 경고. 이미지엔 OpenCV Haar 얼굴 감지.',
    },
    'plaso': {
        'what': 'log2timeline + psort 자동 통합 슈퍼 타임라인 생성.',
        'how': '1) 디스크 이미지/아티팩트 업로드 → 2) 백그라운드 실행',
        'input': '아티팩트 파일 또는 디스크 이미지',
        'output': 'l2tcsv 형식 통합 타임라인 (수천~수만 이벤트)',
        'tips': 'pip install plaso 필요. 대용량은 1시간+ 소요.',
    },
    'ocr-index': {
        'what': '이미지/PDF tesseract OCR → SQLite FTS5에 인덱싱 → 검색.',
        'how': '1) 이미지 업로드 (자동 인덱싱) → 2) 검색어 입력',
        'input': '이미지/PDF (인덱싱) 또는 검색어',
        'output': '인덱싱된 텍스트 또는 검색 결과 (스니펫)',
        'tips': '큰 이미지는 시간 소요. 인덱스 영구 보관.',
    },
    'face': {
        'what': 'OpenCV Haar Cascade — 이미지에서 얼굴/눈 감지 + 선명도 측정.',
        'how': '1) 이미지 업로드',
        'input': '이미지',
        'output': '얼굴 수·위치·눈 수·선명도',
        'tips': '정면 얼굴 위주 (옆얼굴은 정확도 낮음). 얼굴 인식 = 매칭은 별도 (face_recognition 필요).',
    },

    # 4차 추가
    'httpsec': {
        'what': 'URL → HSTS·CSP·X-Frame·X-Content-Type 등 보안 헤더 채점.',
        'how': '1) URL 입력',
        'input': 'https://example.com',
        'output': '등급 A+/A/B/C/F + 각 헤더 상태',
        'tips': '서버에서 직접 HTTP 요청 → CORS 무관.',
    },
    'tls': {
        'what': 'host:port → TLS 인증서 체인·SAN·만료·취약 cipher 검증.',
        'how': '1) host:443 입력',
        'input': '서버 호스트:포트',
        'output': '인증서 정보 + 취약점 경고',
        'tips': 'SHA-1 서명·TLS 1.1 이하 = 경고. 만료 30일 이하 = 임박 알림.',
    },
    'portscan': {
        'what': '40+ 흔한 포트 (FTP·SSH·HTTP·RDP·MongoDB 등) 안전 스캔.',
        'how': '1) 호스트 입력',
        'input': '도메인 또는 IP',
        'output': '열린 포트·서비스·배너',
        'tips': '⚠️ 본인 소유 호스트만 스캔. 외부 IP 스캔은 불법 가능성.',
    },
    'dnslookup': {
        'what': 'A·AAAA·MX·NS·TXT·SOA·CAA·SPF·DMARC 한 번에 조회.',
        'how': '1) 도메인 입력',
        'input': '도메인',
        'output': '모든 DNS 레코드',
        'tips': 'dnspython 사용. DNSSEC 지원.',
    },
    'multihash': {
        'what': '한 파일에 MD5·SHA1·SHA256·SHA384·SHA512·SHA3·BLAKE2·CRC32·Adler32 동시 계산.',
        'how': '1) 파일 또는 텍스트',
        'input': '모든 파일/텍스트',
        'output': '9가지 해시 알고리즘 결과',
        'tips': '증거 보관·NSRL 비교에 유용.',
    },

    # 모바일
    'ios-sms': {'what':'iOS sms.db 메시지·iMessage 추출','how':'sms.db 업로드','input':'/private/var/mobile/Library/SMS/sms.db','output':'메시지 100건','tips':'iOS 백업에서 추출. 키 필요 없음.'},
    'ios-photos': {'what':'Photos.sqlite 사진 메타','how':'업로드','input':'iOS Photos.sqlite','output':'사진 메타·위치·앨범','tips':'iOS 13+ 형식 (ZASSET).'},
    'ios-calendar': {'what':'Calendar.sqlitedb 일정','how':'업로드','input':'Calendar.sqlitedb','output':'일정·알람','tips':'CalendarItem 테이블.'},
    'ios-notes': {'what':'NoteStore.sqlite 메모','how':'업로드','input':'NoteStore.sqlite','output':'메모 제목·내용·시각','tips':'암호화된 메모는 패스워드 필요 (현재 미지원).'},
    'ios-health': {'what':'healthdb_secure.sqlite 건강 데이터','how':'업로드','input':'healthdb_secure.sqlite','output':'데이터 타입·기간·수량','tips':'걸음수·심박·운동 등.'},
    'android-contacts': {'what':'contacts2.db 연락처','how':'업로드','input':'/data/data/com.android.providers.contacts/databases/contacts2.db','output':'이름·마지막 연락·횟수','tips':'starred = 즐겨찾기.'},
    'android-sms': {'what':'mmssms.db SMS/MMS','how':'업로드','input':'mmssms.db','output':'주소·내용·시각·송수신','tips':'type: 1=수신, 2=발신.'},
    'android-calllog': {'what':'calllog.db 통화 기록','how':'업로드','input':'calllog.db','output':'번호·시각·길이·종류','tips':'type: 1=수신, 2=발신, 3=부재중.'},
    'android-wifi': {'what':'wpa_supplicant.conf·WifiConfigStore.xml SSID/비밀번호','how':'파일 업로드','input':'wpa_supplicant.conf','output':'SSID + PSK','tips':'Android 9+는 WifiConfigStore.xml 형식.'},

    # macOS
    'fsevents': {'what':'.fseventsd 파일 시스템 이벤트 로그','how':'gz 파일 업로드','input':'/.fseventsd/*.gz','output':'경로·이벤트·플래그','tips':'1SLD/2SLD/3SLD 버전 자동 감지.'},
    'knowledgec': {'what':'macOS 앱 사용·잠금 이력','how':'knowledgeC.db 업로드','input':'~/Library/Application Support/Knowledge/knowledgeC.db','output':'스트림·값·시각','tips':'/app/usage·/app/inFocus·/safari/history 스트림.'},
    'quarantine': {'what':'macOS Gatekeeper 격리 이력','how':'QuarantineEventsV2 업로드','input':'~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2','output':'다운로드 시각·에이전트·URL','tips':'Safari/Chrome 다운로드 흔적.'},
    'spotlight': {'what':'macOS Spotlight store.db 헤더','how':'업로드','input':'/.Spotlight-V100/Store-V2/<UUID>/store.db','output':'시그니처 + 포맷','tips':'풀 파싱은 mac_apt 별도 도구.'},
    'keychain': {'what':'macOS Keychain 분석','how':'업로드','input':'.keychain or keychain-2.db','output':'포맷·버전','tips':'복호화는 사용자 패스워드 필요.'},
    'tcc': {'what':'macOS TCC.db 권한 부여 이력','how':'업로드','input':'/Library/Application Support/com.apple.TCC/TCC.db','output':'서비스·클라이언트·허용','tips':'Camera·Microphone·Contacts 등 권한 추적.'},
    'tracev3': {'what':'macOS Unified Log .tracev3 청크 구조','how':'업로드','input':'/var/db/diagnostics/Persist/*.tracev3','output':'청크 태그·크기','tips':'풀 파싱은 mac_apt / tracev3 도구.'},

    # 브라우저
    'chromecache': {'what':'Chrome 캐시 파일 (data_0/data_1/f_*)','how':'업로드','input':'캐시 디렉터리 내 파일','output':'포맷·URL·문자열','tips':'simple cache 시그니처 0xC103CAC3.'},
    'firefoxcache': {'what':'Firefox cache2 메타데이터','how':'캐시 파일 업로드','input':'~/.mozilla/firefox/<profile>/cache2/entries/*','output':'마지막 fetch·만료·URL key','tips':'마지막 64B에 메타데이터.'},
    'localstorage': {'what':'브라우저 LocalStorage','how':'.localstorage 또는 leveldb 파일','input':'SQLite or LevelDB','output':'키-값·문자열','tips':'Firefox는 SQLite, Chrome은 LevelDB.'},
    'indexeddb': {'what':'IndexedDB LevelDB 문자열 추출','how':'.log/.ldb 파일들 업로드','input':'IndexedDB leveldb 파일','output':'추출 문자열','tips':'전용 파서 별도 필요. 여기선 단순 strings.'},

    # 클라우드
    'dockerfile': {'what':'Dockerfile 베스트 프랙티스 + 보안 검사','how':'Dockerfile 텍스트/파일','input':'Dockerfile','output':'라인별 이슈 + 등급','tips':'USER root·latest 태그·하드코딩 비밀 탐지.'},
    'k8sec': {'what':'Kubernetes YAML 보안 검사','how':'YAML 입력','input':'K8s manifest YAML','output':'privileged·root·capabilities 이슈','tips':'kubesec 유사한 룰 기반.'},
    'terraform': {'what':'Terraform tfstate JSON 분석','how':'.tfstate 업로드','input':'terraform.tfstate','output':'리소스·outputs·메타','tips':'tfstate에 secrets 있을 수 있음 — 보관 주의.'},
    'cloudtrail': {'what':'AWS CloudTrail 감사 로그','how':'JSON 업로드','input':'CloudTrail JSON (배열 또는 줄별)','output':'이벤트별 상세','tips':'eventName·sourceIPAddress·userIdentity 분석.'},
    'azureactivity': {'what':'Azure Activity Log','how':'JSON 업로드','input':'Azure JSON','output':'이벤트 상세','tips':'관리 작업 추적.'},
    'gcpaudit': {'what':'GCP Audit Log','how':'JSON 업로드','input':'GCP JSON','output':'이벤트 상세','tips':'Cloud Audit Logs.'},
    'k8saudit': {'what':'Kubernetes Audit Log','how':'JSON 업로드','input':'kube-apiserver audit','output':'이벤트 상세','tips':'API 서버 작업 추적.'},
    'o365audit': {'what':'Office 365 통합 감사 로그','how':'JSON 업로드','input':'O365 JSON','output':'이벤트 상세','tips':'사용자 활동·메일·SharePoint 등.'},
    'pkgvuln': {'what':'package.json / requirements.txt → CVE 매칭','how':'파일 업로드','input':'package.json or requirements.txt','output':'알려진 취약 패키지','tips':'내장 DB 10종 + 확장 가능.'},

    # 악성 강화
    'vbastomp': {'what':'VBA Stomping 탐지 (p-code vs 소스 비교)','how':'Office 파일 업로드','input':'.doc/.docx with macros','output':'PerformanceCache vs CompressedSourceCode','tips':'Stomping = p-code만 남기고 소스 삭제하는 회피 기법.'},
    'xlm': {'what':'Excel 4.0 XLM 매크로 탐지','how':'XLS/XLSM 업로드','input':'Excel 매크로 파일','output':'macrosheet + CALL/EXEC 함수','tips':'XLM은 VBA 외에 별도 매크로 시트.'},
    'msi': {'what':'Windows Installer 패키지 분석','how':'.msi 업로드','input':'.msi','output':'OLE 스트림 + CustomAction','tips':'CustomAction에 악성 코드 가능.'},
    'msix': {'what':'MSIX/UWP 패키지','how':'.msix/.appx 업로드','input':'AppxManifest','output':'name·publisher·capabilities','tips':'capabilities에 권한 명시.'},
    'chm': {'what':'CHM Windows Help 파일','how':'.chm 업로드','input':'.chm','output':'URL·스크립트 추출','tips':'CHM에 임베디드 스크립트로 악성 가능.'},
    'gobin': {'what':'Go/Rust 바이너리 식별','how':'바이너리 업로드','input':'PE/ELF/Mach-O','output':'buildinfo + 함수명','tips':'Go: \\xff Go buildinf: 시그니처. Rust: rustc_version 키워드.'},
    'dotnet': {'what':'.NET 어셈블리 BSJB 메타데이터','how':'.NET PE 업로드','input':'.exe/.dll (.NET)','output':'런타임 버전 + 타입·의심 API','tips':'Reflection·Process.Start·DownloadString 등 위험.'},
    'applocker': {'what':'AppLocker 정책 XML 파싱','how':'XML 업로드','input':'AppLocker XML','output':'룰·액션·SID','tips':'Allow/Deny 규칙 분석.'},

    # 압축
    'iso': {'what':'ISO9660 PVD 파싱','how':'.iso 업로드','input':'.iso','output':'볼륨 ID·크기·생성일·앱 ID','tips':'32768바이트 오프셋에 CD001 시그니처.'},
    'dmg': {'what':'macOS DMG (koly 푸터)','how':'.dmg 업로드','input':'.dmg','output':'버전·XML 메타','tips':'파일 끝 512B = koly 푸터.'},
    'rar': {'what':'RAR4/RAR5 헤더','how':'.rar 업로드','input':'.rar','output':'버전·암호화 마커','tips':'풀 압축 해제는 rar/unrar 도구.'},
    'sevenz': {'what':'7-Zip 헤더','how':'.7z 업로드','input':'.7z','output':'시그·버전·next header','tips':'7-Zip은 솔리드 압축.'},
    'tar': {'what':'TAR 멤버 메타데이터','how':'.tar 업로드','input':'.tar','output':'멤버별 mode·UID·GID·mtime','tips':'권한·소유자 정보 보존.'},
    'cab': {'what':'Microsoft Cabinet (CAB)','how':'.cab 업로드','input':'.cab','output':'파일/폴더 수·크기','tips':'Windows 설치 패키지.'},
    'gzmeta': {'what':'GZIP 메타데이터','how':'.gz 업로드','input':'.gz','output':'mtime·원본 파일명·OS','tips':'GZIP 헤더에 원본명·OS 정보 포함.'},

    # 자동·통합
    'auto': {'what':'시그니처 → 가장 적합한 분석 도구 자동 추천','how':'파일 업로드','input':'모든 파일','output':'추천 도구 링크','tips':'어떤 도구 쓸지 모를 때 첫 단계.'},
    'autoanalyze': {'what':'시그+엔트로피+IOC 자동 종합 분석','how':'파일 업로드','input':'모든 파일','output':'엔트로피·IOC 수·추천 도구','tips':'/tools/auto 보다 한 단계 더 깊은 분석.'},
    'zipsearch': {'what':'ZIP 내부 모든 파일에서 키워드 검색','how':'ZIP + 키워드','input':'ZIP + 검색어','output':'파일별 매칭 + 컨텍스트','tips':'대용량 ZIP의 특정 파일 빠르게 찾기.'},
    'triage': {'what':'forensiclab_triage_collector.py 결과 ZIP 통합 분석','how':'트리아지 ZIP 업로드','input':'triage ZIP','output':'12종 아티팩트 자동 파싱 + 통합 타임라인','tips':'/tools/scripts에서 수집 스크립트 다운로드 후 실행.'},
    'triagediff': {'what':'두 트리아지 ZIP 차이 비교','how':'ZIP A·B 업로드','input':'트리아지 ZIP × 2','output':'A에만·B에만·해시 변경된 파일','tips':'시점별 시스템 변화 추적.'},
    'report-pdf': {'what':'분석 이력 → PDF 보고서 가이드','how':'안내 페이지','input':'-','output':'PDF 출력 절차','tips':'/tools/case/<id>/report로 사건별 PDF 자동 생성.'},

    # 유틸
    'time': {'what':'Unix·FILETIME·Chrome·Cocoa·DOS·HFS·Mozilla 타임스탬프 상호 변환','how':'시각 값 입력','input':'정수 또는 ISO 날짜','output':'모든 포맷 변환','tips':'Chrome epoch = μs since 1601, Cocoa = sec since 2001.'},
    'magic': {'what':'100+ 매직바이트 시그니처 매칭','how':'파일 업로드','input':'모든 파일','output':'매칭 시그니처 + MIME','tips':'/tools/auto와 유사하지만 시그니처만 표시.'},
    'hex': {'what':'Hex Viewer + 패턴 검색','how':'파일 + 오프셋/길이/검색','input':'모든 파일','output':'헥스 + ASCII 라인 + 검색 결과','tips':'큰 파일은 오프셋 지정. 검색 = 0x헥스 또는 텍스트.'},
    'regex': {'what':'정규식 매칭·그룹·치환 테스트','how':'패턴 + 텍스트 입력','input':'정규식 + 검사 텍스트','output':'매칭·그룹·치환 결과','tips':'Python re 모듈 사용. i/m/s 플래그 지원.'},
    'convert': {'what':'JSON/XML/YAML 자동 감지 + 변환','how':'텍스트 입력 + 출력 형식 선택','input':'JSON/XML/YAML','output':'변환된 형식','tips':'JSON 들여쓰기/압축, YAML 등.'},
    'textdiff': {'what':'두 텍스트 unified diff','how':'A·B 텍스트','input':'두 텍스트','output':'라인별 +/- 차이 + 유사도 %','tips':'설정 파일 변경 추적에 유용.'},
    'wordlist': {'what':'시드 단어 + 규칙 (leet/연도/숫자/기호) → 사전 생성','how':'시드 + 규칙 체크','input':'시드 단어','output':'생성된 wordlist','tips':'/tools/zipcrack /tools/hashcat-job에 사용.'},
    'encoding': {'what':'BOM 감지 + 자동 인코딩 추정 + 변환','how':'파일 또는 텍스트','input':'인코딩 알 수 없는 파일','output':'감지 인코딩 + 변환','tips':'한국어는 UTF-8/CP949/EUC-KR 자동 인식.'},
    'markdown': {'what':'간단 Markdown → HTML 미리보기','how':'마크다운 입력','input':'.md 텍스트','output':'HTML 렌더링','tips':'기본 문법만 지원 (제목·강조·링크·코드).'},

    # IOC·악성
    'sigma': {'what':'Sigma YAML 규칙으로 JSON 이벤트 매칭','how':'Sigma + JSON 이벤트','input':'Sigma rule + 이벤트 배열','output':'매칭 + 심각도','tips':'간소화된 detection.selection 만 지원.'},
    'psdeobf': {'what':'PowerShell Base64·-EncodedCommand·문자열 연결·char[] 자동 펴기','how':'코드 입력','input':'난독화된 PowerShell','output':'디코드된 코드 + 변환 단계 + IOC','tips':'Cobalt Strike·Emotet 디로더 분석에 유용.'},
    'jsdeobf': {'what':'JS eval·\\xNN·\\uNNNN·atob·fromCharCode 자동 펴기','how':'JS 코드 입력','input':'난독화된 JS','output':'디코드 + 단계 + IOC','tips':'드라이브-바이 다운로드 분석.'},
    'ioc': {'what':'텍스트에서 IP·도메인·해시·CVE·BTC·이메일·CIDR·MAC·경로 자동 추출','how':'텍스트 또는 파일','input':'모든 텍스트','output':'카테고리별 IOC 목록','tips':'15종 패턴. 위협 헌팅 시작점.'},
    'cuckoo': {'what':'Cuckoo/CAPE 샌드박스 리포트 JSON 파싱','how':'리포트 JSON 업로드','input':'sandbox report JSON','output':'시그·프로세스·네트워크·도메인','tips':'점수·시그너처 심각도 자동 표시.'},
    'memscan': {'what':'RAW 메모리 덤프에서 URL·프로세스·자격증명 단서 추출','how':'덤프 업로드','input':'RAW 메모리','output':'URLs·processes·paths·creds·IoC','tips':'풀 메모리 분석은 /tools/vol-full.'},
    'cve': {'what':'CVE ID 또는 키워드로 내장 DB 조회','how':'CVE-XXXX 또는 키워드','input':'CVE 또는 제품명','output':'CVE 정보 + 심각도','tips':'10개 핵심 CVE 내장 (Log4Shell, Heartbleed, Shellshock 등). 외부 NVD는 별도.'},
    'hashlookup': {'what':'파일/해시 → 알려진 양성/악성 DB','how':'파일 또는 해시 입력','input':'파일 또는 MD5/SHA1/SHA256','output':'알려진/미상 + 설명','tips':'내장 DB는 작음. NSRL/VT 풀 통합은 미구현.',},

    # 네트워크
    'har': {'what':'브라우저 HAR 캡처 → 요청·응답·시간·도메인 통계','how':'.har 업로드','input':'.har JSON','output':'메서드·상태·호스트 통계 + 요청 목록','tips':'개발자 도구 Network 탭 → Save all as HAR.'},
    'dmesg': {'what':'Linux dmesg / journalctl 커널·systemd 로그','how':'로그 업로드','input':'.log 텍스트','output':'심각도 분류 + 카테고리 (usb·sshd·sudo)','tips':'/var/log/dmesg 또는 journalctl 출력.'},
    'cidr': {'what':'CIDR 서브넷 계산 + 사설/공용 분류','how':'CIDR 표기 입력','input':'192.168.1.0/24','output':'첫/마지막 호스트·총 주소·분류','tips':'IPv4·IPv6 모두 지원.'},
    'cidrcompare': {'what':'여러 IP가 어떤 CIDR에 속하는지 확인','how':'CIDR 목록 + IP 목록','input':'두 리스트','output':'IP별 매칭 CIDR','tips':'화이트리스트 매칭에 유용.'},
    'urlsafe': {'what':'URL Punycode·피싱·HTTP·단축 URL 탐지','how':'URL 입력','input':'URL','output':'경고 + 안전도 점수','tips':'@호스트·IP 직접·shortener·HTTP = 의심.'},
    'uaparse': {'what':'User-Agent → 브라우저·OS·디바이스·봇 식별','how':'UA 문자열 입력','input':'User-Agent','output':'브라우저·OS·디바이스·봇 가능성','tips':'curl/wget/python = CLI/봇.'},
    'emaildeep': {'what':'이메일 헤더 → 경유 IP·X-헤더·도메인 불일치','how':'헤더 또는 .eml','input':'이메일 raw','output':'경유 IP·SPF/DKIM/DMARC·From-RP 불일치','tips':'/tools/email-auth와 함께 사용.'},
    'sign': {'what':'HMAC/RSA/ECDSA/Ed25519 서명 검증 또는 HMAC 계산','how':'알고리즘·데이터·키·서명 입력','input':'키 + 데이터 + 서명','output':'유효/불일치','tips':'PEM 공개키. 서명은 Base64 또는 hex.'},
    'jwe': {'what':'JWE 5-part 또는 JWS 3-part 분해','how':'토큰 입력','input':'JWE/JWS 토큰','output':'헤더·암호키·IV·암호문·태그','tips':'JWS는 /tools/jwt와 동일.'},
    'pgp': {'what':'PGP 메시지/키 패킷 헤더 파싱','how':'PEM 텍스트 또는 파일','input':'-----BEGIN PGP-----','output':'패킷 태그·종류','tips':'풀 복호화는 GnuPG 별도.'},
    'pkcs7': {'what':'PKCS#7/CMS 인증서 번들','how':'.p7b/.cms 업로드','input':'PKCS#7','output':'포함된 인증서 목록','tips':'PEM·DER 자동 감지.'},
    'sshhosts': {'what':'SSH known_hosts 호스트·해시·키 타입','how':'known_hosts 텍스트/파일','input':'~/.ssh/known_hosts','output':'호스트·해시 여부·키 타입','tips':'|1|...= SHA-1 해시된 호스트.'},
    'gpgkey': {'what':'GPG 키 PGP 패킷 분석','how':'.gpg 파일','input':'PGP 키','output':'패킷 태그·UserID','tips':'tag 6=PublicKey, 13=UserID, 14=PublicSubKey.'},
    'geoip': {'what':'IP → 사설/공용·RIR 추정·역방향 DNS','how':'IP 목록','input':'IP 텍스트','output':'분류·RIR·hostname','tips':'정확한 GeoIP DB 별도 (MaxMind GeoLite2).'},
    'heif': {'what':'iOS 14+ HEIC/HEIF 사진 EXIF·박스 구조','how':'.heic/.heif 업로드','input':'HEIC/HEIF/AVIF','output':'PNP·박스·EXIF','tips':'Pillow HEIF 지원은 pillow-heif 별도.'},
    'ios-backup': {'what':'iOS Manifest.db 백업 도메인·앱별 파일 분류','how':'Manifest.db 업로드','input':'iTunes 백업 Manifest.db','output':'상위 도메인·앱·파일 샘플','tips':'백업 디렉터리 내 Manifest.db 위치.'},
    'apk': {'what':'Android APK manifest·permissions·서명 인증서·DEX 정보','how':'.apk 업로드','input':'APK','output':'권한·activities·DEX 헤더','tips':'AndroidManifest.xml은 binary AXML 형식.'},
    'whatsapp': {'what':'WhatsApp msgstore.db (평문/crypt14/15)','how':'msgstore.db 업로드','input':'msgstore.db','output':'테이블·메시지 100건','tips':'crypt 디크립트는 32B 키 별도 (github.com/MaxiHuHe04).'},
    'telegram': {'what':'Telegram Desktop tdata 파일','how':'tdata 파일','input':'TDF$ 헤더 파일','output':'버전·UTF-16 문자열','tips':'본격 분석은 telegram-desktop-decrypt 별도.'},
    'pst': {'what':'Outlook PST/OST 헤더 (!BDN)','how':'.pst/.ost 업로드','input':'PST/OST','output':'포맷·암호화 방식','tips':'풀 파싱은 libpff / readpst.'},

    # 다운로드
    'scripts': {'what':'로컬 실행 8종 스크립트 (RAM·트리아지·USB 등) 다운로드','how':'카드 클릭 다운로드','input':'-','output':'.py 스크립트','tips':'관리자 권한으로 실행. 결과는 /tools/triage로 분석.'},
    'verify': {'what':'다운로드한 스크립트 SHA-256 검증','how':'스크립트 업로드','input':'.py 파일','output':'마스터 DB와 자동 비교','tips':'변조 여부 즉시 확인.'},
    'history': {'what':'내 분석 이력 조회','how':'/tools/history 접속','input':'-','output':'시간순 분석 기록','tips':'각 항목 클릭 시 결과 페이지 이동.'},
}


# ────────────────────────────────────────────────
# Context processor — 모든 템플릿에 도움말 자동 주입
# ────────────────────────────────────────────────
@bp.context_processor
def inject_tool_help():
    """현재 요청 path에 매칭되는 도움말 자동 주입"""
    path = (request.path or '').rstrip('/')
    # /tools/<name> 추출
    if path.startswith('/tools/'):
        name = path[len('/tools/'):].split('/')[0]
        return {'current_tool_help': _TOOL_HELP.get(name), 'current_tool_name': name}
    return {'current_tool_help': None, 'current_tool_name': None}


# ────────────────────────────────────────────────
# 통합 도움말 페이지
# ────────────────────────────────────────────────
@bp.route('/help')
def help_index():
    return render_template('tools/help_index.html', helps=_TOOL_HELP)


@bp.route('/help/<name>')
def help_detail(name):
    h = _TOOL_HELP.get(name)
    if not h:
        return jsonify({'error': 'not found'}), 404
    return jsonify({'name': name, 'help': h, 'url': f'/tools/{name}'})
