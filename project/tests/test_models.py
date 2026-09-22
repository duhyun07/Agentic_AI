from sqlalchemy import create_engine, inspect
from sqlalchemy.orm import Session

from app.models import Base, Crash, CVE, PoC, CrashPoCLink, CollectionError


def test_tables_created(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path}/test.db")
    Base.metadata.create_all(engine)
    inspector = inspect(engine)
    tables = set(inspector.get_table_names())
    assert {"crashes", "cves", "pocs", "crash_poc_links", "collection_errors"} <= tables


def test_crash_defaults(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path}/test.db")
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        crash = Crash(source="syzbot", raw_log="BUG: KASAN: use-after-free")
        session.add(crash)
        session.commit()
        session.refresh(crash)
        assert crash.status == "분석 대기"
        assert crash.id is not None


def test_crash_patch_status_default(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path}/test.db")
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        crash = Crash(source="syzbot", raw_log="BUG")
        session.add(crash)
        session.commit()
        session.refresh(crash)
        assert crash.patch_status == "unknown"
        assert crash.syzbot_fixed is None


def test_cve_patched_default(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path}/test.db")
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        cve = CVE(cve_id="CVE-2024-1", description="test")
        session.add(cve)
        session.commit()
        session.refresh(cve)
        assert cve.patched is None
