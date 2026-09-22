import logging
import math
import time

from sqlalchemy.orm import Session

from app.models import Crash, CVE, PoC

logger = logging.getLogger(__name__)


def cosine_distance(a: list[float], b: list[float]) -> float:
    dot = sum(x * y for x, y in zip(a, b, strict=True))
    norm_a = math.sqrt(sum(x * x for x in a))
    norm_b = math.sqrt(sum(y * y for y in b))
    if norm_a == 0 or norm_b == 0:
        return 1.0
    cosine_similarity = dot / (norm_a * norm_b)
    return 1.0 - cosine_similarity


class AnalysisPipeline:
    DEDUP_THRESHOLD = 0.05
    MAX_RETRIES = 3

    def __init__(self, clova_client, base_delay: float = 1.0):
        self._clova_client = clova_client
        self._base_delay = base_delay

    def process_crash(self, session: Session, crash: Crash) -> None:
        classified = False
        for attempt in range(self.MAX_RETRIES):
            try:
                classification = self._clova_client.classify_crash(crash.raw_log)
                crash.bug_type = classification["bug_type"]
                crash.summary = classification["summary"]
                crash.severity = classification["severity"]
                crash.embedding = self._clova_client.embed(crash.raw_log)
                crash.status = "분석 완료"
                session.add(crash)
                session.commit()
                classified = True
                break
            except Exception:
                # 커밋이 실패했을 수도 있으므로(예: embedding 차원 불일치) 세션을
                # 매 시도마다 복구해야 다음 재시도가 PendingRollbackError 없이
                # 진행된다. 실패 원인은 마지막 시도뿐 아니라 매 시도마다 남긴다.
                session.rollback()
                is_last_attempt = attempt == self.MAX_RETRIES - 1
                logger.warning(
                    "crash analysis attempt %d/%d failed for crash_id=%s",
                    attempt + 1,
                    self.MAX_RETRIES,
                    crash.id,
                    exc_info=True,
                )
                if not is_last_attempt:
                    time.sleep(self._base_delay * (2 ** attempt))

        if not classified:
            session.rollback()
            crash.status = "분석 대기"
            session.add(crash)
            session.commit()
            return

        try:
            resolve_patch_status(session, crash)
            session.add(crash)
            session.commit()
        except Exception:
            logger.exception(
                "patch status resolution failed for crash_id=%s; classification result kept",
                crash.id,
            )
            session.rollback()

    def find_duplicate(self, session: Session, crash: Crash) -> Crash | None:
        if crash.embedding is None:
            return None
        candidates = (
            session.query(Crash)
            .filter(Crash.id != crash.id, Crash.embedding.is_not(None))
            .all()
        )
        for candidate in candidates:
            if cosine_distance(crash.embedding, candidate.embedding) < self.DEDUP_THRESHOLD:
                return candidate
        return None


PATCH_MATCH_THRESHOLD = 0.1


def resolve_patch_status(session: Session, crash: Crash) -> None:
    if crash.syzbot_fixed is not None:
        crash.patch_status = "fixed" if crash.syzbot_fixed else "unfixed"
        return

    if crash.embedding is None:
        crash.patch_status = "unknown"
        return

    candidates = session.query(CVE).filter(CVE.embedding.is_not(None)).all()
    best: CVE | None = None
    best_distance = float("inf")
    for cve in candidates:
        distance = cosine_distance(crash.embedding, cve.embedding)
        if distance < best_distance:
            best_distance = distance
            best = cve

    if best is None or best_distance >= PATCH_MATCH_THRESHOLD:
        crash.patch_status = "unknown"
        return

    if best.patched is True:
        crash.patch_status = "fixed"
    elif best.patched is False:
        # CVECollector는 더 이상 patched=False를 쓰지 않는다("Patch" 레퍼런스
        # 태그 부재는 "패치 없음"이 아니라 "정보 없음"이므로 None으로 남긴다).
        # 다만 이 로직이 고쳐지기 전에 이미 수집된 CVE 행에는 patched=False가
        # 남아있을 수 있으므로, 그 레거시 데이터를 위해 이 분기를 유지한다.
        crash.patch_status = "unfixed"
    else:
        crash.patch_status = "unknown"


def embed_pending_cves(session: Session, clova_client) -> int:
    """embedding이 없는 CVE에 설명 텍스트로 임베딩을 채운다. 채워진 개수를 반환한다.

    개별 CVE 임베딩 실패가 나머지 백필을 막지 않도록 항목마다 커밋/롤백한다.
    """
    count = 0
    for cve in session.query(CVE).filter(CVE.embedding.is_(None)).all():
        if not (cve.description or "").strip():
            continue
        try:
            cve.embedding = clova_client.embed(cve.description)
            session.add(cve)
            session.commit()
            count += 1
        except Exception:
            logger.exception("failed to embed CVE id=%s", cve.id)
            session.rollback()
    return count


def embed_pending_pocs(session: Session, clova_client) -> int:
    """embedding이 없는 PoC에 설명(없으면 repo_url) 텍스트로 임베딩을 채운다."""
    count = 0
    for poc in session.query(PoC).filter(PoC.embedding.is_(None)).all():
        text = (poc.description or "").strip() or poc.repo_url
        if not text:
            continue
        try:
            poc.embedding = clova_client.embed(text)
            session.add(poc)
            session.commit()
            count += 1
        except Exception:
            logger.exception("failed to embed PoC id=%s", poc.id)
            session.rollback()
    return count
