import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.models import Base, CVE, PoC
from app.rag.retriever import Retriever


@pytest.fixture
def db_session(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path}/test.db")
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        session.add(
            CVE(
                cve_id="CVE-2024-1",
                description="ext4 use-after-free",
                embedding=[1.0, 0.0],
            )
        )
        session.add(
            CVE(
                cve_id="CVE-2024-2",
                description="unrelated network bug",
                embedding=[0.0, 1.0],
            )
        )
        session.add(
            PoC(
                repo_url="https://github.com/x/ext4-poc",
                cve_ref="CVE-2024-1",
                embedding=[1.0, 0.0],
            )
        )
        session.commit()
        yield session


def test_search_returns_most_similar_items_first(db_session):
    retriever = Retriever()
    results = retriever.search(db_session, query_embedding=[1.0, 0.0], top_k=2)

    assert len(results) == 2
    assert results[0]["cve_id"] == "CVE-2024-1" or results[0]["repo_url"].endswith("ext4-poc")
