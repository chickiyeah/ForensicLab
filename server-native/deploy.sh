#!/usr/bin/env bash
# ForensicLab 네이티브 배포 (도커 없음) — Debian/Ubuntu 기준
# 사용: 이 폴더(server-native)를 서버로 복사한 뒤  bash deploy.sh
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
APP="$HERE/flask"
NGINX_PORT="${NGINX_PORT:-80}"   # 외부 포트 (예: NGINX_PORT=405 bash deploy.sh)

echo "[1/5] 시스템 패키지 설치"
sudo apt-get update
sudo apt-get install -y \
  python3 python3-venv python3-dev build-essential pkg-config nginx git \
  autoconf automake libtool m4 gettext libssl-dev libffi-dev libxml2-dev zlib1g-dev \
  hashcat john sleuthkit ewf-tools cryptsetup-bin dislocker fuse3 \
  tesseract-ocr tesseract-ocr-kor tesseract-ocr-jpn tesseract-ocr-chi-sim libzbar0 \
  libtsk-dev libewf-dev libbde-dev libevtx-dev libfsapfs-dev libfsext-dev \
  libfsfat-dev libfshfs-dev libfsntfs-dev libfsxfs-dev libfvde-dev libluksde-dev \
  libmodi-dev libphdi-dev libqcow-dev libsigscan-dev libsmdev-dev libsmraw-dev \
  libvhdi-dev libvmdk-dev || true

echo "[2/5] 파이썬 venv + 의존성"
cd "$APP"
python3 -m venv venv
. venv/bin/activate
pip install --upgrade pip setuptools wheel
pip install -r requirements.txt
mkdir -p data

echo "[3/5] nginx 설정 (포트 ${NGINX_PORT})"
sed "s/listen 80;/listen ${NGINX_PORT};/" "$HERE/nginx/forensic.conf" \
  | sudo tee /etc/nginx/sites-available/forensic.conf >/dev/null
sudo ln -sf /etc/nginx/sites-available/forensic.conf /etc/nginx/sites-enabled/forensic.conf
sudo nginx -t && sudo systemctl reload nginx

echo "[4/5] systemd 서비스 등록"
# WorkingDirectory / ExecStart 경로를 현재 위치로 치환
sed -e "s#/home/ruddls030/forensic/flask#${APP}#g" \
    -e "s/^User=.*/User=$(id -un)/" -e "s/^Group=.*/Group=$(id -gn)/" \
    "$HERE/forensic.service" | sudo tee /etc/systemd/system/forensic.service >/dev/null
sudo systemctl daemon-reload
sudo systemctl enable --now forensic

echo "[5/5] 완료"
sudo systemctl --no-pager status forensic | head -n 5
echo "→ http://<서버IP>:${NGINX_PORT}"
