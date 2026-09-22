import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.api.dashboard import router
from app.db import get_db
from app.models import Base, Crash
from fastapi import FastAPI


@pytest.fixture
def client(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path}/test.db")
    Base.metadata.create_all(engine)
    TestSession = sessionmaker(bind=engine)

    def override_get_db():
        db = TestSession()
        try:
            yield db
        finally:
            db.close()

    with TestSession() as session:
        session.add(
            Crash(
                source="syzbot",
                raw_log="BUG: KASAN",
                bug_type="use-after-free",
                severity="high",
                patch_status="fixed",
            )
        )
        session.add(
            Crash(
                source="syzbot",
                raw_log="BUG: WARNING",
                bug_type="warning",
                severity="medium",
                patch_status="unknown",
                vmlinux_url="https://storage.googleapis.com/syzbot-assets/aaa/vmlinux-bbb.xz",
            )
        )
        session.commit()

    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_db] = override_get_db
    return TestClient(app)


def test_list_crashes_returns_saved_crash(client):
    response = client.get("/api/crashes")
    assert response.status_code == 200
    body = response.json()
    assert len(body) == 2
    assert body[-1]["bug_type"] == "use-after-free"
    assert body[-1]["patch_status"] == "fixed"


def test_filter_crashes_by_severity(client):
    response = client.get("/api/crashes", params={"severity": "high"})
    assert response.status_code == 200
    assert len(response.json()) == 1

    response = client.get("/api/crashes", params={"severity": "low"})
    assert response.status_code == 200
    assert response.json() == []


def test_get_crash_returns_404_for_missing_id(client):
    response = client.get("/api/crashes/999999")
    assert response.status_code == 404


def test_get_crash_returns_200_for_existing_id(client):
    response = client.get("/api/crashes/1")
    assert response.status_code == 200
    body = response.json()
    assert body["bug_type"] == "use-after-free"
    assert body["raw_log"] == "BUG: KASAN"


def test_filter_crashes_by_has_assets(client):
    response = client.get("/api/crashes", params={"has_assets": "true"})
    assert response.status_code == 200
    body = response.json()
    assert len(body) == 1
    assert body[0]["bug_type"] == "warning"

    response = client.get("/api/crashes", params={"has_assets": "false"})
    assert response.status_code == 200
    body = response.json()
    assert len(body) == 1
    assert body[0]["bug_type"] == "use-after-free"


def test_get_similar_returns_empty_when_crash_has_no_embedding(client):
    response = client.get("/api/crashes/1/similar")
    assert response.status_code == 200
    assert response.json() == {"results": []}


def test_get_similar_returns_404_for_missing_id(client):
    response = client.get("/api/crashes/999999/similar")
    assert response.status_code == 404


def test_get_stats(client):
    response = client.get("/api/stats")
    assert response.status_code == 200
    body = response.json()
    assert body["total_crashes"] == 2
    assert body["crashes_with_assets"] == 1
    assert body["embedded_cve_count"] == 0
    assert body["last_collected_at"] is not None
