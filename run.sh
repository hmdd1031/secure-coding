#!/usr/bin/env bash
set -euo pipefail

: "${SECRET_KEY:?SECRET_KEY 환경변수를 32자 이상 난수로 설정하세요.}"
: "${ADMIN_PASSWORD:?ADMIN_PASSWORD 환경변수를 설정하세요.}"
: "${DEMO_PASSWORD:?DEMO_PASSWORD 환경변수를 설정하세요.}"

python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python app.py
