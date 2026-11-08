# Health Management App

## 프로젝트 목적
개인의 건강 기록을 관리하는 서비스를 만들고, 이후 신뢰할 수 있는 공개 자료를 바탕으로 일반 건강 정보를 제공하는 것을 목표로 합니다.

## MVP 목표
사용자가 회원가입·로그인 후 본인의 건강 기록을 생성·조회·수정·삭제하고, 다른 사용자의 기록에는 접근할 수 없도록 합니다.

## 기술 구성

### 현재 준비됨
React, TypeScript, Vite

### 계획 중
FastAPI, PostgreSQL

## 디렉터리 구조
- backend - 프로젝트의 서버 역할을 하는 부분
- frontend - 프로젝트의 화면 역할을 하는 부분
- docs - 프로젝트의 문서들을 보관하는 부분

## 실행 방법
### 프론트엔드

프로젝트 루트에서 다음 명령을 실행합니다.

```cmd
cd frontend
npm.cmd install
npm.cmd run dev
```

## 현재 상태
- 프론트엔드: React·TypeScript·Vite 기본 프로젝트 구성
- 백엔드: 가상환경만 구성, API·DB·인증 미구현