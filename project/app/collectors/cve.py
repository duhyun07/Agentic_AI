import logging
import time
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.collectors.http_utils import RetryingClient
from app.models import CVE

logger = logging.getLogger(__name__)

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
RESULTS_PER_PAGE = 100
MAX_PAGES = 20  # NVD 최대치 안전장치: 한 번 실행에서 최대 2000건까지만 페이지네이션


class CVECollector:
    def __init__(
        self,
        client: RetryingClient,
        api_key: str,
        min_seconds_between_calls: float = 0.6,
    ):
        self._client = client
        self._api_key = api_key
        self._min_seconds_between_calls = min_seconds_between_calls

    def collect(self, session: Session) -> int:
        headers = {"apiKey": self._api_key} if self._api_key else {}
        saved = 0
        start_index = 0

        for page in range(MAX_PAGES):
            params = {
                "keywordSearch": "linux kernel",
                "resultsPerPage": str(RESULTS_PER_PAGE),
            }
            if start_index:
                params["startIndex"] = str(start_index)
            data = self._client.get(NVD_URL, params=params, headers=headers).json()
            vulnerabilities = data.get("vulnerabilities", [])

            for item in vulnerabilities:
                try:
                    saved += self._save_one(session, item)
                except Exception:
                    logger.exception("skipping malformed NVD CVE entry: %r", item)
                    continue
            session.commit()

            total_results = data.get("totalResults", 0)
            # NVD가 요청한 resultsPerPage보다 적게 돌려줄 수 있으므로, 실제
            # 수신 건수만큼만 전진시켜야 다음 페이지에서 구간을 건너뛰지 않는다.
            start_index += len(vulnerabilities)
            if start_index >= total_results or not vulnerabilities:
                break
            time.sleep(self._min_seconds_between_calls)

        return saved

    def _save_one(self, session: Session, item: dict) -> int:
        cve_data = item["cve"]
        cve_id = cve_data["id"]
        exists = session.execute(select(CVE).where(CVE.cve_id == cve_id)).scalar_one_or_none()
        if exists is not None:
            return 0

        description = next(
            (d["value"] for d in cve_data.get("descriptions", []) if d["lang"] == "en"),
            "",
        )
        published = self._parse_published(cve_data.get("published"))
        references = cve_data.get("references", [])
        # references에 "Patch" 태그가 있으면 patched=True로 확신할 수 있지만,
        # 태그가 없다고 해서 "패치가 없다"(False)로 단정할 근거는 없다 — NVD가
        # 태그를 선택적으로만 채우기 때문에, 그 경우는 unknown(None)으로 둔다.
        patched = True if any("Patch" in ref.get("tags", []) for ref in references) else None

        session.add(
            CVE(
                cve_id=cve_id,
                description=description,
                published=published,
                patched=patched,
            )
        )
        return 1

    @staticmethod
    def _parse_published(raw: str | None) -> datetime | None:
        if not raw:
            return None
        parsed = datetime.fromisoformat(raw)
        if parsed.tzinfo is None:
            # NVD 2.0 API의 published는 오프셋 없이 UTC 시각을 준다.
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed
