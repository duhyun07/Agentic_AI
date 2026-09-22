import pytest
from app.config import Settings


@pytest.fixture
def settings() -> Settings:
    return Settings(
        database_url="postgresql+psycopg://postgres:postgres@localhost:5432/kernel_dashboard_test",
        clova_api_key="test-key",
        clova_request_id="test-req",
        github_token="test-token",
        nvd_api_key="test-nvd-key",
    )
