@echo off
cd /d %~dp0
if not exist venv (
    python -m venv venv
    call venv\Scripts\activate.bat
    pip install -r requirements-core.txt
) else (
    call venv\Scripts\activate.bat
)
python run.py
