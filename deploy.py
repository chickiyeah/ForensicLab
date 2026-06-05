import paramiko
import io

HOST = "10.8.0.17"
USER = "ruddls030"
PASS = "dlstn0722"
PROJECT_DIR = "/home/ruddls030/forensic"

FILES = {
    "docker-compose.yml": """\
version: '3.8'

services:
  flask:
    build: ./flask
    container_name: forensic-flask
    restart: unless-stopped
    networks:
      - app-net

  nginx:
    image: nginx:alpine
    container_name: forensic-nginx
    restart: unless-stopped
    ports:
      - "405:80"
    volumes:
      - ./nginx/nginx.conf:/etc/nginx/conf.d/default.conf
    depends_on:
      - flask
    networks:
      - app-net

networks:
  app-net:
    driver: bridge
""",
    "nginx/nginx.conf": """\
server {
    listen 80;

    location / {
        proxy_pass http://flask:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
""",
    "flask/app.py": """\
from flask import Flask, jsonify

app = Flask(__name__)

@app.route('/')
def hello():
    return 'Hello World!'

@app.route('/health')
def health():
    return jsonify(status='ok')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
""",
    "flask/requirements.txt": """\
flask==3.0.0
gunicorn==21.2.0
""",
    "flask/Dockerfile": """\
FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .

EXPOSE 5000

CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "app:app"]
""",
}


def run(ssh, cmd):
    print(f"$ {cmd}")
    _, stdout, stderr = ssh.exec_command(cmd)
    out = stdout.read().decode().strip()
    err = stderr.read().decode().strip()
    if out:
        print(out)
    if err:
        print("[stderr]", err)
    return out


def upload_file(sftp, remote_path, content):
    sftp.putfo(io.BytesIO(content.encode()), remote_path)
    print(f"  uploaded: {remote_path}")


def main():
    print(f"Connecting to {HOST}...")
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(HOST, username=USER, password=PASS)
    print("Connected.\n")

    sftp = ssh.open_sftp()

    # Create directories
    for d in [PROJECT_DIR, f"{PROJECT_DIR}/nginx", f"{PROJECT_DIR}/flask"]:
        run(ssh, f"mkdir -p {d}")

    # Upload files
    print("\nUploading files...")
    for rel_path, content in FILES.items():
        upload_file(sftp, f"{PROJECT_DIR}/{rel_path}", content)

    sftp.close()

    # Build and run
    print("\nBuilding and starting containers...")
    run(ssh, f"cd {PROJECT_DIR} && docker compose down 2>/dev/null || true")
    run(ssh, f"cd {PROJECT_DIR} && docker compose build --no-cache")
    run(ssh, f"cd {PROJECT_DIR} && docker compose up -d")

    print("\nContainer status:")
    run(ssh, f"cd {PROJECT_DIR} && docker compose ps")

    ssh.close()
    print(f"\nDone! Server: http://{HOST}:405")


if __name__ == "__main__":
    main()
