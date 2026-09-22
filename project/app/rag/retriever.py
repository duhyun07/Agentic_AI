from sqlalchemy.orm import Session

from app.analysis.pipeline import cosine_distance
from app.models import CVE, PoC

# 요청 하나당 코사인 거리 계산에 들어가는 후보 수의 상한. pgvector ANN 인덱스
# 없이 매 요청마다 순수 Python으로 거리를 계산하므로, 테이블이 커져도 요청
# 하나의 비용이 무한히 늘지 않도록 값을 캡핑한다(진짜 최적화는 DB 측
# `cosine_distance` 연산자 + ivfflat/hnsw 인덱스로 옮기는 것이며, 이는 별도
# 작업으로 남겨둔다).
MAX_CANDIDATES_PER_TYPE = 2000


class Retriever:
    def search(self, session: Session, query_embedding: list[float], top_k: int = 5) -> list[dict]:
        candidates: list[dict] = []

        for cve in (
            session.query(CVE)
            .filter(CVE.embedding.is_not(None))
            .limit(MAX_CANDIDATES_PER_TYPE)
            .all()
        ):
            candidates.append(
                {
                    "type": "cve",
                    "cve_id": cve.cve_id,
                    "description": cve.description,
                    "distance": cosine_distance(query_embedding, cve.embedding),
                }
            )

        for poc in (
            session.query(PoC)
            .filter(PoC.embedding.is_not(None))
            .limit(MAX_CANDIDATES_PER_TYPE)
            .all()
        ):
            candidates.append(
                {
                    "type": "poc",
                    "repo_url": poc.repo_url,
                    "cve_ref": poc.cve_ref,
                    "distance": cosine_distance(query_embedding, poc.embedding),
                }
            )

        candidates.sort(key=lambda c: c["distance"])
        return candidates[:top_k]
