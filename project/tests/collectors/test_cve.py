import httpx
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.collectors.cve import CVECollector
from app.collectors.http_utils import RetryingClient
from app.models import Base, CVE

NVD_RESPONSE = {
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2024-12345",
                "descriptions": [{"lang": "en", "value": "Use-after-free in ext4 subsystem"}],
                "published": "2024-05-01T00:00:00.000",
            }
        }
    ]
}


@pytest.fixture
def db_session(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path}/test.db")
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        yield session


def test_collect_saves_new_cve(db_session, httpx_mock):
    httpx_mock.add_response(
        url=httpx.URL(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={"keywordSearch": "linux kernel", "resultsPerPage": "100"},
        ),
        json=NVD_RESPONSE,
    )

    client = RetryingClient(httpx.Client())
    collector = CVECollector(client=client, api_key="test-key")
    saved = collector.collect(db_session)

    assert saved == 1
    cve = db_session.query(CVE).one()
    assert cve.cve_id == "CVE-2024-12345"
    assert "ext4" in cve.description


def test_collect_skips_existing_cve(db_session, httpx_mock):
    db_session.add(CVE(cve_id="CVE-2024-12345", description="Existing CVE", published=None))
    db_session.commit()

    httpx_mock.add_response(
        url=httpx.URL(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={"keywordSearch": "linux kernel", "resultsPerPage": "100"},
        ),
        json=NVD_RESPONSE,
    )

    client = RetryingClient(httpx.Client())
    collector = CVECollector(client=client, api_key="test-key")
    saved = collector.collect(db_session)

    assert saved == 0
    assert db_session.query(CVE).count() == 1


def test_collect_handles_multiple_cves(db_session, httpx_mock):
    response = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2024-11111",
                    "descriptions": [{"lang": "en", "value": "First CVE"}],
                    "published": "2024-01-01T00:00:00.000",
                }
            },
            {
                "cve": {
                    "id": "CVE-2024-22222",
                    "descriptions": [{"lang": "en", "value": "Second CVE"}],
                    "published": "2024-02-01T00:00:00.000",
                }
            },
        ]
    }

    httpx_mock.add_response(
        url=httpx.URL(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={"keywordSearch": "linux kernel", "resultsPerPage": "100"},
        ),
        json=response,
    )

    client = RetryingClient(httpx.Client())
    collector = CVECollector(client=client, api_key="test-key")
    saved = collector.collect(db_session)

    assert saved == 2
    assert db_session.query(CVE).count() == 2


NVD_RESPONSE_WITH_PATCH = {
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2024-99999",
                "descriptions": [{"lang": "en", "value": "Buffer overflow in netfilter"}],
                "published": "2024-06-01T00:00:00.000",
                "references": [
                    {"url": "https://example.com/advisory", "tags": ["Third Party Advisory"]},
                    {"url": "https://git.kernel.org/commit/abc", "tags": ["Patch"]},
                ],
            }
        }
    ]
}


def test_collect_marks_cve_as_patched_when_patch_reference_present(db_session, httpx_mock):
    httpx_mock.add_response(
        url=httpx.URL(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={"keywordSearch": "linux kernel", "resultsPerPage": "100"},
        ),
        json=NVD_RESPONSE_WITH_PATCH,
    )

    client = RetryingClient(httpx.Client())
    collector = CVECollector(client=client, api_key="test-key")
    collector.collect(db_session)

    cve = db_session.query(CVE).filter(CVE.cve_id == "CVE-2024-99999").one()
    assert cve.patched is True


NVD_RESPONSE_WITHOUT_PATCH_TAG = {
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2024-88888",
                "descriptions": [{"lang": "en", "value": "Race condition in scheduler"}],
                "published": "2024-06-01T00:00:00.000",
                "references": [
                    {"url": "https://example.com/advisory", "tags": ["Third Party Advisory"]},
                ],
            }
        }
    ]
}


def test_collect_leaves_patched_unknown_when_no_patch_tag_present(db_session, httpx_mock):
    """references가 있어도 'Patch' 태그가 없으면 '패치 없음'(False)이 아니라
    '알 수 없음'(None)으로 남아야 한다 — NVD는 태그를 선택적으로만 채우므로
    태그 부재가 곧 패치 부재를 의미하지 않는다."""
    httpx_mock.add_response(
        url=httpx.URL(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={"keywordSearch": "linux kernel", "resultsPerPage": "100"},
        ),
        json=NVD_RESPONSE_WITHOUT_PATCH_TAG,
    )

    client = RetryingClient(httpx.Client())
    collector = CVECollector(client=client, api_key="test-key")
    collector.collect(db_session)

    cve = db_session.query(CVE).filter(CVE.cve_id == "CVE-2024-88888").one()
    assert cve.patched is None


def test_collect_skips_malformed_entry_but_saves_the_rest(db_session, httpx_mock):
    """한 항목이 필수 필드가 없어 파싱에 실패해도 나머지 정상 항목은
    저장되어야 한다 (배치 전체 롤백/livelock 방지)."""
    response = {
        "vulnerabilities": [
            {"cve": {"descriptions": [], "published": "2024-01-01T00:00:00.000"}},  # id 누락
            {
                "cve": {
                    "id": "CVE-2024-33333",
                    "descriptions": [{"lang": "en", "value": "valid entry"}],
                    "published": "2024-01-01T00:00:00.000",
                }
            },
        ]
    }
    httpx_mock.add_response(
        url=httpx.URL(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={"keywordSearch": "linux kernel", "resultsPerPage": "100"},
        ),
        json=response,
    )

    client = RetryingClient(httpx.Client())
    collector = CVECollector(client=client, api_key="test-key")
    saved = collector.collect(db_session)

    assert saved == 1
    assert db_session.query(CVE).filter(CVE.cve_id == "CVE-2024-33333").count() == 1


def test_parse_published_treats_offsetless_timestamp_as_utc():
    """NVD published는 오프셋 없는 UTC 시각이므로, naive datetime이 아니라
    UTC가 명시된 aware datetime으로 파싱되어야 한다. (SQLite는 timezone-aware
    datetime을 그대로 왕복시키지 못하므로 DB 저장이 아니라 파싱 함수 자체를
    직접 검증한다 — 실제 PostgreSQL 컬럼은 DateTime(timezone=True)다.)"""
    from datetime import timezone

    parsed = CVECollector._parse_published("2024-05-01T00:00:00.000")

    assert parsed.tzinfo is not None
    assert parsed.utcoffset() == timezone.utc.utcoffset(None)
