from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.db import get_db
from app.models import CVE, Crash
from app.rag.retriever import Retriever

router = APIRouter(prefix="/api")

DEFAULT_PAGE_SIZE = 100
MAX_PAGE_SIZE = 500
DEFAULT_SIMILAR_TOP_K = 5

_retriever = Retriever()

_HAS_ANY_ASSET = or_(
    Crash.vmlinux_url.is_not(None),
    Crash.disk_image_url.is_not(None),
    Crash.kernel_image_url.is_not(None),
)


def _serialize(crash: Crash) -> dict:
    return {
        "id": crash.id,
        "source": crash.source,
        "bug_type": crash.bug_type,
        "summary": crash.summary,
        "severity": crash.severity,
        "status": crash.status,
        "patch_status": crash.patch_status,
        "first_seen": crash.first_seen.isoformat() if crash.first_seen else None,
        "vmlinux_url": crash.vmlinux_url,
        "disk_image_url": crash.disk_image_url,
        "kernel_image_url": crash.kernel_image_url,
    }


def _serialize_detail(crash: Crash) -> dict:
    return {**_serialize(crash), "raw_log": crash.raw_log}


@router.get("/crashes")
def list_crashes(
    severity: str | None = None,
    has_assets: bool | None = None,
    limit: int = Query(default=DEFAULT_PAGE_SIZE, ge=1, le=MAX_PAGE_SIZE),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
) -> list[dict]:
    stmt = select(Crash).order_by(Crash.id.desc())
    if severity is not None:
        stmt = stmt.where(Crash.severity == severity)
    if has_assets is True:
        stmt = stmt.where(_HAS_ANY_ASSET)
    elif has_assets is False:
        stmt = stmt.where(~_HAS_ANY_ASSET)
    stmt = stmt.limit(limit).offset(offset)
    crashes = db.execute(stmt).scalars().all()
    return [_serialize(c) for c in crashes]


@router.get("/crashes/{crash_id}")
def get_crash(crash_id: int, db: Session = Depends(get_db)) -> dict:
    crash = db.get(Crash, crash_id)
    if crash is None:
        raise HTTPException(status_code=404, detail="crash not found")
    return _serialize_detail(crash)


@router.get("/crashes/{crash_id}/similar")
def get_similar(
    crash_id: int,
    top_k: int = Query(default=DEFAULT_SIMILAR_TOP_K, ge=1, le=50),
    db: Session = Depends(get_db),
) -> dict:
    crash = db.get(Crash, crash_id)
    if crash is None:
        raise HTTPException(status_code=404, detail="crash not found")
    if crash.embedding is None:
        return {"results": []}
    results = _retriever.search(db, query_embedding=crash.embedding, top_k=top_k)
    return {"results": results}


@router.get("/stats")
def get_stats(db: Session = Depends(get_db)) -> dict:
    total_crashes = db.scalar(select(func.count()).select_from(Crash)) or 0
    crashes_with_assets = db.scalar(select(func.count()).select_from(Crash).where(_HAS_ANY_ASSET)) or 0
    embedded_cve_count = (
        db.scalar(select(func.count()).select_from(CVE).where(CVE.embedding.is_not(None))) or 0
    )
    last_collected_at = db.scalar(select(func.max(Crash.first_seen)))
    return {
        "total_crashes": total_crashes,
        "crashes_with_assets": crashes_with_assets,
        "embedded_cve_count": embedded_cve_count,
        "last_collected_at": last_collected_at.isoformat() if last_collected_at else None,
    }
