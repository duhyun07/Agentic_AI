from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.models import Base, CVE
from app.scheduler import _run_cve_and_poc_job, acquire_scheduler_lock, release_scheduler_lock


def test_acquire_lock_succeeds_when_no_existing_lock(tmp_path):
    lock_path = tmp_path / "scheduler.lock"
    assert acquire_scheduler_lock(lock_path) is True


def test_acquire_lock_fails_when_already_held(tmp_path):
    lock_path = tmp_path / "scheduler.lock"
    assert acquire_scheduler_lock(lock_path) is True
    assert acquire_scheduler_lock(lock_path) is False


def test_release_lock_allows_reacquisition(tmp_path):
    lock_path = tmp_path / "scheduler.lock"
    assert acquire_scheduler_lock(lock_path) is True
    assert acquire_scheduler_lock(lock_path) is False

    release_scheduler_lock(lock_path)

    assert acquire_scheduler_lock(lock_path) is True


def test_release_lock_is_noop_when_file_missing(tmp_path):
    lock_path = tmp_path / "scheduler.lock"
    release_scheduler_lock(lock_path)  # should not raise


def test_acquire_lock_reclaims_stale_lock_from_dead_process(tmp_path):
    """이전 보유 프로세스가 비정상 종료해 락 파일을 못 지운 경우
    (PID가 더 이상 살아있지 않음), 새 프로세스가 락을 회수할 수 있어야 한다."""
    lock_path = tmp_path / "scheduler.lock"
    # 존재하지 않을 가능성이 매우 높은 PID를 넣어 stale 상태를 흉내낸다.
    lock_path.write_text("999999999")

    assert acquire_scheduler_lock(lock_path) is True


def test_acquire_lock_does_not_reclaim_lock_from_live_process(tmp_path):
    """락 파일의 PID가 현재도 살아있는 프로세스(예: 테스트 프로세스 자신)면
    회수하지 않고 정상적으로 실패해야 한다."""
    import os

    lock_path = tmp_path / "scheduler.lock"
    lock_path.write_text(str(os.getpid()))

    assert acquire_scheduler_lock(lock_path) is False


class _FakeClovaClient:
    def embed(self, text: str) -> list[float]:
        return [0.1] * 1024


def test_cve_poc_job_embeds_cves_even_when_github_poc_step_fails(tmp_path, monkeypatch):
    """C3 회귀 방지: GitHub PoC 수집 단계가 실패해도(예: 토큰 만료,
    rate limit) 이미 수집된 CVE의 임베딩 백필은 계속 진행되어야 한다.
    두 단계가 같은 try 블록에 있으면 하나의 실패가 나머지를 막는다."""
    engine = create_engine(f"sqlite:///{tmp_path}/test.db")
    Base.metadata.create_all(engine)
    TestSession = sessionmaker(bind=engine)
    monkeypatch.setattr("app.scheduler.SessionLocal", TestSession)

    with TestSession() as session:
        session.add(CVE(cve_id="CVE-2024-1", description="use-after-free in ext4"))
        session.commit()

    class FailingRetryingClient:
        def get(self, url, **kwargs):
            raise RuntimeError("simulated network failure")

    _run_cve_and_poc_job(
        retrying_client=FailingRetryingClient(),
        nvd_api_key="test-key",
        github_token="test-token",
        clova_client=_FakeClovaClient(),
    )

    with TestSession() as session:
        cve = session.query(CVE).filter(CVE.cve_id == "CVE-2024-1").one()
        assert cve.embedding is not None
