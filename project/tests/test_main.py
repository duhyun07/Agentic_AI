import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import app.main as main_module
from app.db import get_db
from app.models import Base, Crash


@pytest.fixture
def client(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path}/test.db")
    Base.metadata.create_all(engine)
    TestSession = sessionmaker(bind=engine)

    with TestSession() as session:
        session.add(
            Crash(
                source="syzbot",
                raw_log="BUG",
                bug_type="use-after-free",
                severity="high",
                patch_status="fixed",
            )
        )
        session.commit()

    def override_get_db():
        db = TestSession()
        try:
            yield db
        finally:
            db.close()

    main_module.app.dependency_overrides[get_db] = override_get_db
    try:
        yield TestClient(main_module.app)
    finally:
        main_module.app.dependency_overrides.pop(get_db, None)


def test_app_smoke_crashes_api_returns_200(client):
    response = client.get("/api/crashes")
    assert response.status_code == 200
    body = response.json()
    assert len(body) == 1
    assert body[0]["patch_status"] == "fixed"
