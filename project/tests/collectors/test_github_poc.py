import httpx
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.collectors.github_poc import GitHubPoCCollector
from app.collectors.http_utils import RetryingClient
from app.models import Base, PoC

GITHUB_SEARCH_RESPONSE = {
    "items": [
        {
            "html_url": "https://github.com/someuser/CVE-2024-12345-exploit",
            "description": "PoC for CVE-2024-12345",
        }
    ]
}


@pytest.fixture
def db_session(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path}/test.db")
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        yield session


def test_collect_saves_new_poc(db_session, httpx_mock):
    httpx_mock.add_response(
        url=httpx.URL(
            "https://api.github.com/search/repositories",
            params={"q": "CVE-2024-12345 exploit"},
        ),
        json=GITHUB_SEARCH_RESPONSE,
    )

    client = RetryingClient(httpx.Client())
    collector = GitHubPoCCollector(client=client, token="test-token")
    saved = collector.collect(db_session, cve_ids=["CVE-2024-12345"])

    assert saved == 1
    poc = db_session.query(PoC).one()
    assert poc.cve_ref == "CVE-2024-12345"
    assert poc.repo_url.endswith("CVE-2024-12345-exploit")
