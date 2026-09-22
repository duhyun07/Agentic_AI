import logging
import time
from urllib.parse import urlparse

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.collectors.http_utils import RetryingClient
from app.models import PoC

logger = logging.getLogger(__name__)

GITHUB_SEARCH_URL = "https://api.github.com/search/repositories"


class GitHubPoCCollector:
    def __init__(self, client: RetryingClient, token: str, min_seconds_between_calls: float = 6.0):
        self._client = client
        self._token = token
        self._min_seconds_between_calls = min_seconds_between_calls

    def collect(self, session: Session, cve_ids: list[str]) -> int:
        headers = {"Authorization": f"Bearer {self._token}"}
        saved = 0
        for cve_id in cve_ids:
            params = {"q": f"{cve_id} exploit"}
            data = self._client.get(GITHUB_SEARCH_URL, params=params, headers=headers).json()
            for item in data.get("items", []):
                try:
                    saved += self._save_one(session, item, cve_id)
                except Exception:
                    logger.exception("skipping malformed GitHub search result: %r", item.get("id"))
                    continue
            session.commit()
            time.sleep(self._min_seconds_between_calls)
        return saved

    def _save_one(self, session: Session, item: dict, cve_id: str) -> int:
        repo_url = item["html_url"]
        parsed = urlparse(repo_url)
        if parsed.scheme != "https" or parsed.hostname != "github.com":
            logger.warning("skipping PoC result with unexpected repo host: %r", repo_url)
            return 0

        exists = session.execute(select(PoC).where(PoC.repo_url == repo_url)).scalar_one_or_none()
        if exists is not None:
            return 0
        session.add(PoC(repo_url=repo_url, cve_ref=cve_id, description=item.get("description")))
        return 1
