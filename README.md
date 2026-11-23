# Health Management App

## 프로젝트 목적
개인의 건강 기록을 관리하는 서비스를 만들고, 이후 신뢰할 수 있는 공개 자료를 바탕으로 일반 건강 정보를 제공하는 것을 목표로 합니다.

## MVP 목표
사용자가 회원가입·로그인 후 본인의 건강 기록을 생성·조회·수정·삭제하고, 다른 사용자의 기록에는 접근할 수 없도록 합니다.

## 기술 구성

### 현재 준비됨
React, TypeScript, Vite, FastAPI, SQLAlchemy, Alembic, PostgreSQL

### 후속 구현
요청별 세션 검증, 로그아웃, 체중 기록 CRUD 및 사용자별 접근 권한

## 디렉터리 구조
- backend - 프로젝트의 서버 역할을 하는 부분
- frontend - 프로젝트의 화면 역할을 하는 부분
- docs - 프로젝트의 문서들을 보관하는 부분

## 실행 방법
### 프론트엔드

프로젝트 루트에서 다음 명령을 실행합니다.

```powershell
Set-Location .\frontend
npm.cmd install
npm.cmd run dev
```

### 백엔드

백엔드 의존성은 Windows와 Python 3.11 환경을 기준으로 버전을 고정했습니다. `backend/requirements.txt`는 실행용 패키지와 그 의존성을, `backend/requirements-dev.txt`는 실행용 목록에 테스트 패키지를 추가한 구성을 담습니다.

처음 구성하는 환경에서는 `backend` 디렉터리에서 다음 명령으로 설치합니다.

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.\.venv\Scripts\python.exe -m pip check
```

`backend/.env.example`을 참고해 `backend/.env`에 로컬 PostgreSQL 설정을 준비합니다.

프로젝트 루트의 PowerShell에서 다음 명령을 실행합니다.

```powershell
Set-Location .\backend
.\.venv\Scripts\python.exe -m uvicorn main:app --reload
```

서버가 실행되면 다음 주소에서 API를 확인할 수 있습니다.

- API 기본 경로: http://127.0.0.1:8000/
- 상태 확인 API: http://127.0.0.1:8000/health
- 대화형 API 문서: http://127.0.0.1:8000/docs

서버를 종료하려면 실행 중인 터미널에서 `Ctrl+C`를 누릅니다.

### 백엔드 테스트

테스트는 `backend/tests/`에 모여 있으며, DB 테스트는 검증용 `hma_migrations` 데이터베이스와 마이그레이션 적용이 필요합니다. `backend`에서 실행합니다.

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

의존성 목록을 새 환경에서 재현할 때는 비어 있는 `.venv-verify` 가상환경을 사용합니다. 이 환경도 기존 `backend/.env`와 검증용 DB를 사용합니다.

```powershell
py -3.11 -m venv .venv-verify
.\.venv-verify\Scripts\python.exe -m pip install -r requirements-dev.txt
.\.venv-verify\Scripts\python.exe -m pip check
.\.venv-verify\Scripts\python.exe -m pytest -q
```

## 현재 상태
- 프론트엔드: React·TypeScript·Vite 기본 프로젝트 구성
- 백엔드: PostgreSQL 연결, 회원가입·로그인, 세션 토큰 해시 저장과 쿠키 발급, 로그인 실패 횟수 제한 및 관련 테스트 구성
- API: `/health`, `/api/v1/auth/register`, `/api/v1/auth/login`
- 후속 구현: 요청별 세션 검증, 로그아웃, 체중 기록 CRUD 및 사용자별 접근 권한
