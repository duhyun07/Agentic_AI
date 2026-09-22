import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.api.rag import build_rag_router
from app.db import get_db
from app.models import Base, CVE


class FakeClovaClient:
    def embed(self, text: str) -> list[float]:
        return [1.0, 0.0]

    def classify_crash(self, raw_log: str) -> dict:
        raise NotImplementedError


@pytest.fixture
def client(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path}/test.db")
    Base.metadata.create_all(engine)
    TestSession = sessionmaker(bind=engine)

    with TestSession() as session:
        session.add(
            CVE(cve_id="CVE-2024-1", description="ext4 use-after-free", embedding=[1.0, 0.0])
        )
        session.commit()

    def override_get_db():
        db = TestSession()
        try:
            yield db
        finally:
            db.close()

    app = FastAPI()
    app.include_router(build_rag_router(clova_client=FakeClovaClient()))
    app.dependency_overrides[get_db] = override_get_db
    return TestClient(app)


def test_rag_query_returns_relevant_cve(client):
    response = client.post("/api/rag/query", json={"query": "ext4 use-after-free crash"})
    assert response.status_code == 200
    body = response.json()
    assert any(item["cve_id"] == "CVE-2024-1" for item in body["results"])


def test_rag_query_rejects_empty_query(client):
    response = client.post("/api/rag/query", json={"query": ""})
    assert response.status_code == 422


def test_rag_query_rejects_oversized_query(client):
    response = client.post("/api/rag/query", json={"query": "a" * 3000})
    assert response.status_code == 422


def test_rag_query_returns_503_when_embedding_fails(client):
    """이 앱은 이미 정상 FakeClovaClient로 라우터가 구성되어 있으므로, 임베딩
    실패 시나리오는 실패하는 CLOVA 클라이언트로 구성한 별도 앱 인스턴스로
    검증한다."""

    class FailingClovaClient:
        def embed(self, text: str) -> list[float]:
            raise RuntimeError("HCX-005 unavailable")

    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from app.api.rag import build_rag_router

    failing_app = FastAPI()
    failing_app.include_router(build_rag_router(clova_client=FailingClovaClient()))
    failing_app.dependency_overrides.update(client.app.dependency_overrides)
    failing_client = TestClient(failing_app)

    response = failing_client.post("/api/rag/query", json={"query": "anything"})
    assert response.status_code == 503
