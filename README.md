# WHITE MARKET

Flask와 SQLite로 구현한 시큐어코딩 중고거래 플랫폼입니다.

## 주요 기능

- 회원가입, 로그인, 프로필 및 마이페이지
- 이름, 닉네임, 로그인 아이디 분리
- 우편번호와 구조화된 주소 입력
- 상품 등록, 검색, 수정, 삭제 및 거래 상태 관리
- 상품별 1대1 메시지
- 게시판과 댓글
- 상품·사용자 신고 및 자동 제한
- 가상 잔액 송금
- 관리자 통합 관리

## 보안 기능

- 비밀번호 해시 저장
- SQL 파라미터 바인딩
- XSS 및 CSRF 방어
- IDOR 접근 권한 검사
- 이미지 파일 실제 형식 검사 및 WEBP 재인코딩
- 로그인 시도 횟수 제한
- 중복 송금 방지
- 세션 무효화
- Host allowlist
- 보안 헤더 적용

## 실행 환경

- Python 3
- Flask
- SQLite
- Pillow
- WSL Ubuntu

## 설치 및 실행

```bash
python3 -m venv .venv
source .venv/bin/activate

python -m pip install --upgrade pip
python -m pip install -r requirements.txt

## 환경변수 설정

Linux 및 WSL:

```bash
export SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
export ADMIN_PASSWORD="강한-관리자-비밀번호"
export DEMO_PASSWORD="강한-데모-비밀번호"
export TRUSTED_HOSTS="127.0.0.1,localhost"
```

실제 비밀번호와 비밀키는 저장소에 커밋하지 않습니다.

## 서버 실행

```bash
python app.py
```

브라우저에서 다음 주소로 접속합니다.

```text
http://127.0.0.1:5000
```

## 테스트 및 보안 검사

개발용 패키지를 설치합니다.

```bash
python -m pip install -r requirements-dev.txt
```

다음 명령으로 테스트와 보안 검사를 실행합니다.

```bash
python -m pytest -q
python -m bandit -r app.py -x tests
python -m pip_audit -r requirements.txt
```

최종 확인 결과:

- pytest: 40 passed
- Bandit: No issues identified
- pip-audit: No known vulnerabilities found
