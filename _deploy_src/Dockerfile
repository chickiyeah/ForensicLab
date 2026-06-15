FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    lrzsz \
    unzip \
    vsftpd \
    nano \
    util-linux \
    hashcat \
    tesseract-ocr \
    tesseract-ocr-kor \
    tesseract-ocr-jpn \
    tesseract-ocr-chi-sim \
    libzbar0 \
    git \
    sleuthkit \
    libtsk-dev \
    libewf-dev \
    libewf2 \
    ewf-tools \
    build-essential \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 5000

CMD ["gunicorn", "--config", "/app/gunicorn.conf.py", "monitor:create_app()"]
