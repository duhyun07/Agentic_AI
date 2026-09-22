from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import app.main as main_module
from app.db import get_db
from app.models import Base


def test_spa_route_returns_404_when_frontend_not_built(tmp_path, monkeypatch):
    monkeypatch.setattr(main_module, "FRONTEND_DIST", tmp_path / "dist")
    client = TestClient(main_module.app)

    response = client.get("/")

    assert response.status_code == 404


def test_spa_route_serves_index_html_for_root_and_client_routes(tmp_path, monkeypatch):
    dist = tmp_path / "dist"
    dist.mkdir()
    (dist / "index.html").write_text("<html><body>SPA shell</body></html>", encoding="utf-8")
    monkeypatch.setattr(main_module, "FRONTEND_DIST", dist)
    client = TestClient(main_module.app)

    root_response = client.get("/")
    search_response = client.get("/search")

    assert root_response.status_code == 200
    assert "SPA shell" in root_response.text
    assert search_response.status_code == 200
    assert "SPA shell" in search_response.text


def test_spa_route_does_not_shadow_api_routes(tmp_path, monkeypatch):
    dist = tmp_path / "dist"
    dist.mkdir()
    (dist / "index.html").write_text("<html><body>SPA shell</body></html>", encoding="utf-8")
    monkeypatch.setattr(main_module, "FRONTEND_DIST", dist)

    engine = create_engine(f"sqlite:///{tmp_path}/test.db")
    Base.metadata.create_all(engine)
    TestSession = sessionmaker(bind=engine)

    def override_get_db():
        db = TestSession()
        try:
            yield db
        finally:
            db.close()

    main_module.app.dependency_overrides[get_db] = override_get_db
    try:
        client = TestClient(main_module.app)

        response = client.get("/api/crashes")

        assert response.status_code == 200
        assert response.headers["content-type"].startswith("application/json")
    finally:
        main_module.app.dependency_overrides.pop(get_db, None)


def test_unmatched_api_path_returns_json_404_not_spa_html(tmp_path, monkeypatch):
    monkeypatch.setattr(main_module, "FRONTEND_DIST", tmp_path / "dist")
    client = TestClient(main_module.app)

    response = client.get("/api/does-not-exist")

    assert response.status_code == 404
    assert response.headers["content-type"].startswith("application/json")
    assert response.json() == {"detail": "not found"}
