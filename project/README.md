# Kernel Crash RAG Dashboard

리눅스 커널 크래시 / Exploit PoC를 수집·분류·검색하는 RAG 대시보드.

## 개발 환경 실행

터미널 1 — 백엔드 (FastAPI, 포트 8123):

```bash
python -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8123
```

터미널 2 — 프론트엔드 (Vite dev 서버, 포트 5173, `/api`·`/events`를 8123으로 프록시):

```bash
cd frontend
npm install
npm run dev
```

개발 중에는 `http://localhost:5173`으로 접속한다.

## 프로덕션 빌드

```bash
cd frontend
npm install
npm run build
```

빌드 결과(`frontend/dist/`)는 FastAPI가 정적 파일로 직접 서빙한다(`app/main.py`). 빌드 후에는
백엔드 하나만 띄우면 `http://127.0.0.1:8123`에서 전체 앱(정적 프론트엔드 + API)에 접속할 수 있다.

## 테스트

```bash
python -m pytest -v
```
