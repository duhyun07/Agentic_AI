import logging
import os
import sys
from pathlib import Path

import httpx
from apscheduler.events import EVENT_JOB_ERROR, EVENT_JOB_MISSED
from apscheduler.schedulers.background import BackgroundScheduler

from app.analysis.clova_client import ClovaStudioClient
from app.analysis.pipeline import AnalysisPipeline, embed_pending_cves, embed_pending_pocs
from app.broadcaster import broadcaster
from app.collectors.cve import CVECollector
from app.collectors.github_poc import GitHubPoCCollector
from app.collectors.http_utils import RetryingClient
from app.collectors.syzbot import SyzbotCollector
from app.config import Settings
from app.db import SessionLocal
from app.models import Crash, CVE, CollectionError

logger = logging.getLogger(__name__)

PENDING_CRASH_BATCH_SIZE = 50


def _is_process_running(pid: int) -> bool:
    """다른 프로세스가 여전히 살아있는지 크로스플랫폼으로 확인한다."""
    if pid <= 0:
        # POSIX에서 pid<=0은 "나 자신" 또는 "프로세스 그룹 전체"를 뜻해
        # os.kill의 의미가 달라진다. 락 파일이 손상된 경우이므로 안전하게
        # "죽어있다"고 보지 않고 회수를 거부한다(fail-closed).
        return False
    if sys.platform == "win32":
        import ctypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.OpenProcess.restype = ctypes.c_void_p
        kernel32.OpenProcess.argtypes = (ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32)
        kernel32.CloseHandle.argtypes = (ctypes.c_void_p,)

        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if handle:
            kernel32.CloseHandle(handle)
            return True
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _write_lock_file(lock_path: Path) -> bool:
    try:
        fd = os.open(str(lock_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    except FileExistsError:
        return False
    try:
        os.write(fd, str(os.getpid()).encode())
    finally:
        os.close(fd)
    return True


def _safe_unlink(lock_path: Path) -> bool:
    """다른 프로세스가 그 사이 파일 핸들을 쥐고 있으면(특히 Windows) unlink가
    PermissionError를 던질 수 있다. 락은 필수 자원이 아니라 최적화 수단이므로
    실패해도 앱 기동/종료를 막지 않고 False만 반환한다."""
    try:
        lock_path.unlink(missing_ok=True)
        return True
    except OSError:
        logger.exception("failed to remove scheduler lock at %s", lock_path)
        return False


def acquire_scheduler_lock(lock_path: Path) -> bool:
    """같은 서버에서 스케줄러가 두 번 뜨는 것을 막는 파일 락.

    APScheduler는 uvicorn 워커가 2개 이상이면 각 워커가 독립적으로
    스케줄러를 띄워 job이 중복 실행되는 문제가 알려져 있다
    (설계 문서 참고). O_EXCL로 원자적으로 파일을 생성해 락을 구현한다.

    락 파일이 이미 있으면 그 안에 적힌 PID가 여전히 살아있는 프로세스인지
    확인한다. 이전 보유자가 비정상 종료(kill/OOM/강제 재시작)로 락 파일을
    지우지 못하고 죽었다면, PID가 죽어있으므로 stale 락으로 판단해 회수한다.

    두 프로세스가 동시에 같은 stale 락을 회수하려 하면 "unlink 후 재생성"
    사이에 서로의 파일을 지워버리는 레이스가 생길 수 있다. 이를 막기 위해
    재생성에 성공한 뒤 파일 내용이 정말 자신의 PID인지 다시 읽어 확인한다 —
    그 사이 다른 프로세스가 또 회수했다면 내용이 달라져 있으므로 그때는
    양보(False)한다.
    """
    if _write_lock_file(lock_path):
        return True

    try:
        existing_pid = int(lock_path.read_text().strip())
    except (OSError, ValueError):
        existing_pid = None

    if existing_pid is not None and _is_process_running(existing_pid):
        return False

    logger.warning(
        "reclaiming stale scheduler lock at %s (previous holder pid=%s is gone)",
        lock_path,
        existing_pid,
    )
    if not _safe_unlink(lock_path):
        return False
    if not _write_lock_file(lock_path):
        return False

    try:
        return int(lock_path.read_text().strip()) == os.getpid()
    except (OSError, ValueError):
        return False


def release_scheduler_lock(lock_path: Path) -> None:
    """`acquire_scheduler_lock`으로 획득한 락 파일을 해제한다.

    서버 종료 시 반드시 호출해야 다음 시작 시 락을 다시 획득할 수 있다.
    파일이 이미 없어도, 파일이 잠겨 있어 삭제가 실패해도 예외를 던지지 않는다.
    """
    _safe_unlink(lock_path)


def _record_collection_error(session, source: str, reason: str) -> None:
    """CollectionError 기록 자체가 실패해도(DB 장애 등) 예외를 전파하지 않는다."""
    try:
        session.add(CollectionError(source=source, reason=reason))
        session.commit()
    except Exception:
        logger.exception("failed to record CollectionError for source=%s", source)
        session.rollback()


def _run_syzbot_job(retrying_client: RetryingClient, clova_client: ClovaStudioClient) -> None:
    session = SessionLocal()
    try:
        collector = SyzbotCollector(client=retrying_client)
        collector.collect(session)
        pipeline = AnalysisPipeline(clova_client=clova_client)
        pending = (
            session.query(Crash)
            .filter(Crash.status == "분석 대기")
            .limit(PENDING_CRASH_BATCH_SIZE)
            .all()
        )
        for crash in pending:
            pipeline.process_crash(session, crash)
            if crash.status == "분석 완료":
                broadcaster.publish(
                    {
                        "crash_id": crash.id,
                        "bug_type": crash.bug_type,
                        "severity": crash.severity,
                        "summary": crash.summary,
                        "patch_status": crash.patch_status,
                    }
                )
    except Exception as exc:
        logger.exception("syzbot job failed")
        session.rollback()
        _record_collection_error(session, "syzbot", str(exc))
    finally:
        session.close()


def _run_cve_and_poc_job(
    retrying_client: RetryingClient,
    nvd_api_key: str,
    github_token: str,
    clova_client: ClovaStudioClient,
    github_min_seconds_between_calls: float = 6.0,
    nvd_min_seconds_between_calls: float = 0.6,
) -> None:
    """CVE/PoC 수집과 임베딩 백필을 각각 독립된 단계로 실행한다.

    각 단계를 개별 try/except로 감싸 한 단계(특히 GitHub PoC 수집처럼
    외부 rate limit/토큰 문제로 실패하기 쉬운 단계)의 실패가 나머지
    단계(CVE 임베딩 백필 등)를 막지 않도록 한다.
    """
    session = SessionLocal()
    try:
        try:
            cve_collector = CVECollector(
                client=retrying_client,
                api_key=nvd_api_key,
                min_seconds_between_calls=nvd_min_seconds_between_calls,
            )
            cve_collector.collect(session)
        except Exception as exc:
            logger.exception("cve collection failed")
            session.rollback()
            _record_collection_error(session, "cve", str(exc))

        try:
            embed_pending_cves(session, clova_client)
        except Exception:
            logger.exception("cve embedding backfill failed")
            session.rollback()

        try:
            cve_ids = [row.cve_id for row in session.query(CVE).all()]
            poc_collector = GitHubPoCCollector(
                client=retrying_client,
                token=github_token,
                min_seconds_between_calls=github_min_seconds_between_calls,
            )
            poc_collector.collect(session, cve_ids=cve_ids)
        except Exception as exc:
            logger.exception("github poc collection failed")
            session.rollback()
            _record_collection_error(session, "github_poc", str(exc))

        try:
            embed_pending_pocs(session, clova_client)
        except Exception:
            logger.exception("poc embedding backfill failed")
            session.rollback()
    finally:
        session.close()


def _log_missed_or_failed_job(event) -> None:
    if event.code == EVENT_JOB_MISSED:
        logger.warning("scheduled job %s missed its run time (previous run still in progress?)", event.job_id)
    else:
        logger.error("scheduled job %s raised an exception: %s", event.job_id, event.exception)


def build_scheduler(settings: Settings) -> BackgroundScheduler:
    http_client = httpx.Client(
        timeout=30.0,
        headers={"User-Agent": "kernel-crash-dashboard/1.0 (+syzbot collector)"},
    )
    retrying_client = RetryingClient(http_client, max_retries=settings.hcx_max_retries)
    clova_client = ClovaStudioClient(
        base_url=settings.clova_base_url,
        api_key=settings.clova_api_key,
        request_id=settings.clova_request_id,
        http_client=http_client,
    )
    github_min_seconds_between_calls = 60.0 / settings.github_rate_limit_per_minute

    scheduler = BackgroundScheduler()
    scheduler.add_listener(_log_missed_or_failed_job, EVENT_JOB_MISSED | EVENT_JOB_ERROR)
    scheduler.add_job(
        _run_syzbot_job,
        "interval",
        minutes=settings.syzbot_poll_interval_minutes,
        args=[retrying_client, clova_client],
        id="syzbot_job",
        max_instances=1,
        coalesce=True,
        misfire_grace_time=300,
    )
    scheduler.add_job(
        _run_cve_and_poc_job,
        "interval",
        hours=settings.cve_poll_interval_hours,
        args=[
            retrying_client,
            settings.nvd_api_key,
            settings.github_token,
            clova_client,
            github_min_seconds_between_calls,
            settings.nvd_min_seconds_between_calls,
        ],
        id="cve_poc_job",
        max_instances=1,
        coalesce=True,
        misfire_grace_time=3600,
    )
    scheduler.http_client = http_client  # main.py closes this on shutdown
    return scheduler
