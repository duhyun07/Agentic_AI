import logging
import tempfile
from contextlib import asynccontextmanager
from pathlib import Path

import httpx
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.analysis.clova_client import ClovaStudioClient
from app.api.dashboard import router as dashboard_router
from app.api.events import router as events_router
from app.api.rag import build_rag_router
from app.config import get_settings
from app.scheduler import acquire_scheduler_lock, build_scheduler, release_scheduler_lock

logger = logging.getLogger(__name__)

FRONTEND_DIST = Path(__file__).resolve().parent.parent / "frontend" / "dist"

_settings_for_rag = get_settings()
_rag_http_client = httpx.Client(timeout=30.0)
_clova_client_for_rag = ClovaStudioClient(
    base_url=_settings_for_rag.clova_base_url,
    api_key=_settings_for_rag.clova_api_key,
    request_id=_settings_for_rag.clova_request_id,
    http_client=_rag_http_client,
)

_scheduler = None
_scheduler_lock_path: Path | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _scheduler, _scheduler_lock_path
    settings = get_settings()
    lock_path = Path(tempfile.gettempdir()) / "kernel_dashboard_scheduler.lock"
    if acquire_scheduler_lock(lock_path):
        _scheduler = build_scheduler(settings)
        _scheduler.start()
        _scheduler_lock_path = lock_path
        logger.info("scheduler started")
    else:
        logger.info("scheduler lock already held, skipping start in this process")

    yield

    # 각 정리 단계를 독립적으로 감싼다 — scheduler.shutdown()이 실행 중이던
    # job의 예외로 실패하더라도 락 해제와 httpx 클라이언트 종료는 이어져야
    # 한다(하나의 실패가 나머지 리소스 정리를 막지 않도록).
    if _scheduler is not None:
        try:
            _scheduler.shutdown()
        except Exception:
            logger.exception("scheduler shutdown failed")

        scheduler_http_client = getattr(_scheduler, "http_client", None)
        if scheduler_http_client is not None:
            try:
                scheduler_http_client.close()
            except Exception:
                logger.exception("failed to close scheduler http client")

        if _scheduler_lock_path is not None:
            release_scheduler_lock(_scheduler_lock_path)

    try:
        _rag_http_client.close()
    except Exception:
        logger.exception("failed to close RAG http client")


app = FastAPI(title="Kernel Crash RAG Dashboard", lifespan=lifespan)
app.include_router(dashboard_router)
app.include_router(events_router)
app.include_router(build_rag_router(clova_client=_clova_client_for_rag))


@app.middleware("http")
async def security_headers_middleware(request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


if (FRONTEND_DIST / "assets").is_dir():
    app.mount("/assets", StaticFiles(directory=FRONTEND_DIST / "assets"), name="spa-assets")


@app.get("/{full_path:path}", include_in_schema=False)
async def serve_spa(full_path: str) -> FileResponse:
    """React SPA(대시보드/검색)를 서빙한다.

    `/api/*`, `/events/*`는 위에서 먼저 등록된 라우터가 매칭하므로 이
    catch-all까지 내려오지 않는다. React Router가 클라이언트에서
    `/search` 같은 경로를 처리하므로, 서버는 어떤 비-API 경로 요청이든
    항상 같은 `index.html`을 돌려주면 된다(SPA 새로고침/딥링크 지원).
    """
    if full_path.startswith("api/") or full_path.startswith("events/"):
        raise HTTPException(status_code=404, detail="not found")
    index_file = FRONTEND_DIST / "index.html"
    if not index_file.is_file():
        raise HTTPException(
            status_code=404,
            detail="frontend build not found - run `npm install && npm run build` in frontend/",
        )
    return FileResponse(index_file)
