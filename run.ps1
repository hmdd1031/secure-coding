$ErrorActionPreference = "Stop"

if (-not $env:SECRET_KEY -or $env:SECRET_KEY.Length -lt 32) {
    throw "SECRET_KEY 환경변수를 32자 이상 난수로 설정하세요."
}
if (-not $env:ADMIN_PASSWORD) {
    throw "ADMIN_PASSWORD 환경변수를 먼저 설정하세요."
}
if (-not $env:DEMO_PASSWORD) {
    throw "DEMO_PASSWORD 환경변수를 먼저 설정하세요."
}

python -m venv .venv
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r .\requirements.txt
python .\app.py
