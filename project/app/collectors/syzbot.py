import logging
from urllib.parse import parse_qs, urljoin, urlparse

from bs4 import BeautifulSoup
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.collectors.http_utils import RetryingClient
from app.models import Crash

logger = logging.getLogger(__name__)

SYZBOT_BASE_URL = "https://syzkaller.appspot.com"
SYZBOT_UPSTREAM_URL = f"{SYZBOT_BASE_URL}/upstream"
ALLOWED_REPORT_HOSTS = {"syzkaller.appspot.com"}
ALLOWED_ASSET_HOSTS = {"storage.googleapis.com"}
# syzbot 크래시 상세 페이지의 "Assets" 컬럼에 실리는 링크 텍스트 →
# Crash 모델 필드명 매핑 (https://github.com/google/syzkaller/blob/master/docs/syzbot_assets.md)
ASSET_LABEL_TO_FIELD = {
    "vmlinux": "vmlinux_url",
    "disk image": "disk_image_url",
    "kernel image": "kernel_image_url",
}
MAX_REPORT_CHARS = 500_000
# 매 실행마다 상세 페이지를 가져올 버그 수 상한. syzbot 서버에 부담을 주지
# 않기 위함이며, 페이지네이션/상한이 없던 이전 구현의 알려진 문제(설계
# 리뷰의 I7 항목)도 함께 해결한다.
MAX_BUGS_PER_COLLECT = 50


class UntrustedReportUrlError(Exception):
    pass


def _validate_url_host(url: str, allowed_hosts: set[str]) -> str:
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.hostname not in allowed_hosts:
        raise UntrustedReportUrlError(f"disallowed host: {parsed.hostname!r}")
    return url


def _validate_report_url(url: str) -> str:
    return _validate_url_host(url, ALLOWED_REPORT_HOSTS)


def _extract_bug_list(html: str, section: str) -> list[dict]:
    """syzbot 대시보드(/upstream) HTML에서 지정한 섹션(예: "open")의 버그
    제목/extid 목록을 파싱한다.

    syzbot은 공개 JSON API가 없다 — 진짜 API(dashapi)는 `/api`에
    `method=bug_list`로 클라이언트 인증(계정+비밀번호)이 필요한 POST
    요청만 지원하며, 이 프로젝트는 그런 자격증명을 갖고 있지 않다.
    대신 인증 없이도 열람 가능한 `/upstream` 대시보드 HTML을 그대로
    파싱한다. 페이지 구조는 `<details><summary class="bug_list_caption">
    open ...</summary><table class="list_table">`이고, 각 행의 첫 번째
    셀에 `<a href="/bug?extid=...">제목</a>`이 들어있다(2026-08-22
    확인).
    """
    soup = BeautifulSoup(html, "html.parser")
    target_table = None
    for details in soup.find_all("details"):
        caption = details.find("summary", class_="bug_list_caption")
        if caption is not None and caption.get_text(strip=True).startswith(section):
            target_table = details.find("table", class_="list_table")
            break
    if target_table is None:
        return []

    body = target_table.find("tbody")
    if body is None:
        return []

    bugs = []
    for row in body.find_all("tr"):
        title_cell = row.find("td")
        if title_cell is None:
            continue
        link = title_cell.find("a")
        if link is None or not link.get("href"):
            continue
        extid_values = parse_qs(urlparse(link["href"]).query).get("extid")
        if not extid_values:
            continue
        bugs.append({"title": link.get_text(strip=True), "extid": extid_values[0]})
    return bugs


def _extract_report_url(html: str) -> str | None:
    """버그 상세 페이지(/bug?extid=...)의 "Crashes" 테이블에서 가장 최근
    크래시의 리포트(`/text?tag=CrashReport&x=...`) 링크를 찾는다.
    """
    soup = BeautifulSoup(html, "html.parser")
    crashes_table = None
    for table in soup.find_all("table", class_="list_table"):
        caption = table.find("caption")
        if caption is not None and "Crashes" in caption.get_text():
            crashes_table = table
            break
    if crashes_table is None:
        return None

    body = crashes_table.find("tbody")
    if body is None:
        return None

    for row in body.find_all("tr"):
        cells = row.find_all("td")
        # 컬럼 순서: time, kernel, commit, syzkaller commit, config, log,
        # report, syz repro, c repro, vm info, assets, manager, title
        if len(cells) < 7:
            continue
        report_cell = cells[6]
        link = report_cell.find("a")
        if link is not None and link.get("href"):
            return urljoin(SYZBOT_BASE_URL, link["href"])
    return None


def _extract_assets(html: str) -> dict[str, str]:
    """버그 상세 페이지의 "Crashes" 테이블에서 가장 최근 크래시 행의
    `<td class="assets">`에 실린 vmlinux/디스크 이미지/커널 이미지
    다운로드 링크를 추출한다. 신뢰할 수 없는 호스트로의 링크는 무시한다.
    """
    soup = BeautifulSoup(html, "html.parser")
    crashes_table = None
    for table in soup.find_all("table", class_="list_table"):
        caption = table.find("caption")
        if caption is not None and "Crashes" in caption.get_text():
            crashes_table = table
            break
    if crashes_table is None:
        return {}

    body = crashes_table.find("tbody")
    if body is None:
        return {}

    row = body.find("tr")
    if row is None:
        return {}

    assets_cell = row.find("td", class_="assets")
    if assets_cell is None:
        return {}

    assets: dict[str, str] = {}
    for link in assets_cell.find_all("a"):
        href = link.get("href")
        label = link.get_text(strip=True)
        field = ASSET_LABEL_TO_FIELD.get(label)
        if href is None or field is None:
            continue
        try:
            assets[field] = _validate_url_host(urljoin(SYZBOT_BASE_URL, href), ALLOWED_ASSET_HOSTS)
        except UntrustedReportUrlError:
            logger.warning("skipping untrusted syzbot asset link: %r", href)
            continue
    return assets


class SyzbotCollector:
    def __init__(self, client: RetryingClient):
        self._client = client

    def collect(self, session: Session) -> int:
        html = self._client.get(SYZBOT_UPSTREAM_URL).text
        bugs = _extract_bug_list(html, section="open")[:MAX_BUGS_PER_COLLECT]

        saved = 0
        for bug in bugs:
            try:
                saved += self._save_one(session, bug)
            except Exception:
                logger.exception(
                    "skipping malformed/unreachable syzbot bug entry: %r", bug.get("extid")
                )
                continue
        session.commit()
        return saved

    def _save_one(self, session: Session, bug: dict) -> int:
        detail_url = f"{SYZBOT_BASE_URL}/bug?extid={bug['extid']}"
        detail_html = self._client.get(detail_url).text

        report_url = _extract_report_url(detail_html)
        if report_url is None:
            logger.warning("no crash report link found for syzbot bug extid=%s", bug["extid"])
            return 0
        report_url = _validate_report_url(report_url)

        # syzbot API가 신뢰할 수 없는 호스트로의 리다이렉트를 통해 SSRF를
        # 유발하지 못하도록 리다이렉트를 따라가지 않는다.
        response = self._client.get(report_url, follow_redirects=False)
        report = response.text[:MAX_REPORT_CHARS]
        assets = _extract_assets(detail_html)
        extid = bug["extid"]

        existing = (
            session.execute(select(Crash).where(Crash.syzbot_extid == extid)).scalars().first()
        )
        if existing is None:
            # extid 추적이 추가되기 전에 저장된 레거시 행 — raw_log로 매칭해
            # extid를 뒤늦게 채워주고, 그 당시엔 없었을 자산 링크도 백필한다
            # (syzbot은 크래시를 처음 신고한 뒤 며칠 뒤에야 자산을 붙이는 경우가
            # 흔해서, 신규/기존 여부와 무관하게 매 수집마다 누락된 자산을
            # 채워 넣어야 한다).
            existing = (
                session.execute(
                    select(Crash).where(Crash.raw_log == report, Crash.syzbot_extid.is_(None))
                )
                .scalars()
                .first()
            )

        if existing is not None:
            existing.syzbot_extid = extid
            for field, url in assets.items():
                if getattr(existing, field) is None:
                    setattr(existing, field, url)
            return 0

        # "open" 섹션에서 가져온 버그이므로 아직 패치되지 않은 상태다.
        session.add(
            Crash(source="syzbot", raw_log=report, syzbot_fixed=False, syzbot_extid=extid, **assets)
        )
        return 1
