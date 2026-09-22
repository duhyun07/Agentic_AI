import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.analysis.pipeline import AnalysisPipeline
from app.models import Base, Crash, PoC


class FakeClovaClient:
    def classify_crash(self, raw_log: str) -> dict:
        return {"bug_type": "use-after-free", "summary": "ext4 UAF", "severity": "high"}

    def embed(self, text: str) -> list[float]:
        return [0.1] * 1024


@pytest.fixture
def db_session(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path}/test.db")
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        yield session


def test_process_crash_sets_bug_type_and_embedding(db_session):
    crash = Crash(source="syzbot", raw_log="BUG: KASAN: use-after-free in ext4_put_super")
    db_session.add(crash)
    db_session.commit()

    pipeline = AnalysisPipeline(clova_client=FakeClovaClient(), base_delay=0.001)
    pipeline.process_crash(db_session, crash)

    db_session.refresh(crash)
    assert crash.bug_type == "use-after-free"
    assert crash.severity == "high"
    assert crash.status == "분석 완료"
    assert crash.embedding is not None


def test_process_crash_marks_pending_on_classify_failure(db_session):
    crash = Crash(source="syzbot", raw_log="garbage log")
    db_session.add(crash)
    db_session.commit()

    class FailingClient:
        def __init__(self):
            self.call_count = 0

        def classify_crash(self, raw_log: str) -> dict:
            self.call_count += 1
            raise RuntimeError("HCX-005 timeout")

        def embed(self, text: str) -> list[float]:
            return [0.1] * 1024

    client = FailingClient()
    pipeline = AnalysisPipeline(clova_client=client, base_delay=0.001)
    pipeline.process_crash(db_session, crash)

    db_session.refresh(crash)
    assert crash.status == "분석 대기"
    assert client.call_count == 3  # Verify 3 retry attempts


def test_process_crash_retries_on_transient_failure(db_session):
    crash = Crash(source="syzbot", raw_log="BUG: KASAN: use-after-free in ext4_put_super")
    db_session.add(crash)
    db_session.commit()

    class TransientFailingClient:
        def __init__(self):
            self.call_count = 0

        def classify_crash(self, raw_log: str) -> dict:
            self.call_count += 1
            if self.call_count == 1:
                raise RuntimeError("HCX-005 timeout")
            return {"bug_type": "use-after-free", "summary": "ext4 UAF", "severity": "high"}

        def embed(self, text: str) -> list[float]:
            return [0.1] * 1024

    client = TransientFailingClient()
    pipeline = AnalysisPipeline(clova_client=client, base_delay=0.001)
    pipeline.process_crash(db_session, crash)

    db_session.refresh(crash)
    assert crash.status == "분석 완료"  # Should succeed after retry
    assert crash.bug_type == "use-after-free"
    assert crash.embedding is not None
    assert client.call_count == 2  # Should have tried twice (failed once, succeeded once)


def test_dedup_matcher_finds_similar_crash_by_cosine_distance():
    from app.analysis.pipeline import cosine_distance

    a = [1.0, 0.0]
    b = [1.0, 0.0]
    c = [0.0, 1.0]

    assert cosine_distance(a, b) < 0.01
    assert cosine_distance(a, c) > 0.9


def test_cosine_distance_raises_on_dimension_mismatch_instead_of_silently_truncating():
    from app.analysis.pipeline import cosine_distance

    with pytest.raises(ValueError):
        cosine_distance([1.0, 0.0, 0.0], [1.0, 0.0])


def test_resolve_patch_status_uses_syzbot_flag_when_present(db_session):
    from app.analysis.pipeline import resolve_patch_status

    crash = Crash(
        source="syzbot",
        raw_log="BUG",
        syzbot_fixed=True,
        embedding=[0.1] * 1024,
    )
    db_session.add(crash)
    db_session.commit()

    resolve_patch_status(db_session, crash)

    assert crash.patch_status == "fixed"


def test_resolve_patch_status_falls_back_to_matched_cve(db_session):
    from app.analysis.pipeline import resolve_patch_status
    from app.models import CVE

    db_session.add(
        CVE(cve_id="CVE-2024-1", description="match", embedding=[1.0, 0.0], patched=True)
    )
    db_session.commit()

    crash = Crash(source="nvd-manual", raw_log="BUG", embedding=[1.0, 0.0])
    db_session.add(crash)
    db_session.commit()

    resolve_patch_status(db_session, crash)

    assert crash.patch_status == "fixed"


def test_patch_status_failure_does_not_revert_status_or_consume_retry(db_session, monkeypatch):
    """I5 규약: patch-status 조회가 DB 에러로 실패해도 분류 결과(status="분석 완료")는
    유지되어야 하고, HCX-005 재시도 횟수를 소모해서는 안 된다."""
    import app.analysis.pipeline as pipeline_module

    crash = Crash(source="syzbot", raw_log="BUG: KASAN: use-after-free in ext4_put_super")
    db_session.add(crash)
    db_session.commit()

    def _raise(session, crash):
        raise RuntimeError("simulated CVE table scan DB error")

    monkeypatch.setattr(pipeline_module, "resolve_patch_status", _raise)

    client = FakeClovaClient()
    pipeline = AnalysisPipeline(clova_client=client, base_delay=0.001)
    pipeline.process_crash(db_session, crash)

    db_session.refresh(crash)
    assert crash.status == "분석 완료"
    assert crash.bug_type == "use-after-free"
    assert crash.patch_status == "unknown"  # left at default, resolution never succeeded


def test_resolve_patch_status_unknown_when_no_match(db_session):
    from app.analysis.pipeline import resolve_patch_status

    crash = Crash(source="nvd-manual", raw_log="BUG", embedding=[1.0, 0.0])
    db_session.add(crash)
    db_session.commit()

    resolve_patch_status(db_session, crash)

    assert crash.patch_status == "unknown"


def test_embed_pending_cves_fills_missing_embeddings_only(db_session):
    from app.analysis.pipeline import embed_pending_cves
    from app.models import CVE

    pending = CVE(cve_id="CVE-2024-1", description="use-after-free in netfilter")
    already_embedded = CVE(cve_id="CVE-2024-2", description="already done", embedding=[0.5] * 1024)
    db_session.add_all([pending, already_embedded])
    db_session.commit()

    count = embed_pending_cves(db_session, FakeClovaClient())

    db_session.refresh(pending)
    db_session.refresh(already_embedded)
    assert count == 1
    assert pending.embedding == [0.1] * 1024
    assert already_embedded.embedding == [0.5] * 1024


def test_embed_pending_cves_skips_failed_item_and_continues(db_session):
    from app.analysis.pipeline import embed_pending_cves
    from app.models import CVE

    failing = CVE(cve_id="CVE-2024-3", description="boom")
    ok = CVE(cve_id="CVE-2024-4", description="fine")
    db_session.add_all([failing, ok])
    db_session.commit()

    class PartiallyFailingClient:
        def embed(self, text: str) -> list[float]:
            if text == "boom":
                raise RuntimeError("HCX-005 timeout")
            return [0.2] * 1024

    count = embed_pending_cves(db_session, PartiallyFailingClient())

    db_session.refresh(failing)
    db_session.refresh(ok)
    assert count == 1
    assert failing.embedding is None
    assert ok.embedding == [0.2] * 1024


def test_embed_pending_pocs_uses_description_or_falls_back_to_repo_url(db_session):
    from app.analysis.pipeline import embed_pending_pocs

    with_description = PoC(repo_url="https://github.com/a/b", description="exploit for CVE-2024-1")
    without_description = PoC(repo_url="https://github.com/c/d")
    db_session.add_all([with_description, without_description])
    db_session.commit()

    count = embed_pending_pocs(db_session, FakeClovaClient())

    db_session.refresh(with_description)
    db_session.refresh(without_description)
    assert count == 2
    assert with_description.embedding == [0.1] * 1024
    assert without_description.embedding == [0.1] * 1024
