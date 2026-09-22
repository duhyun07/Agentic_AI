import logging

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.db import get_db
from app.rag.retriever import Retriever

logger = logging.getLogger(__name__)


class RagQueryRequest(BaseModel):
    query: str = Field(min_length=1, max_length=2000)
    top_k: int = Field(default=5, ge=1, le=50)


def build_rag_router(clova_client) -> APIRouter:
    router = APIRouter(prefix="/api/rag")
    retriever = Retriever()

    @router.post("/query")
    def query(request: RagQueryRequest, db: Session = Depends(get_db)) -> dict:
        try:
            query_embedding = clova_client.embed(request.query)
        except Exception:
            logger.exception("failed to embed RAG query")
            raise HTTPException(status_code=503, detail="embedding service unavailable")
        results = retriever.search(db, query_embedding=query_embedding, top_k=request.top_k)
        return {"results": results}

    return router
