import httpx
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.collectors.http_utils import RetryingClient
from app.collectors.syzbot import MAX_BUGS_PER_COLLECT, SyzbotCollector
from app.models import Base, Crash

UPSTREAM_URL = "https://syzkaller.appspot.com/upstream"
SYZBOT_REPORT_TEXT = "BUG: KASAN: use-after-free in ext4_put_super\nCall Trace:\n ext4_put_super+0x123"


def make_upstream_html(bugs: list[dict], section: str = "open") -> str:
    rows = "".join(
        f'<tr><td><a href="/bug?extid={bug["extid"]}">{bug["title"]}</a></td></tr>' for bug in bugs
    )
    return f"""
    <html><body>
    <details>
      <summary class="bug_list_caption">{section} (test)</summary>
      <table class="list_table"><tbody>{rows}</tbody></table>
    </details>
    </body></html>
    """


def make_bug_detail_html(report_href: str | None, assets: dict[str, str] | None = None) -> str:
    report_cell = (
        f'<td class="repro"><a href="{report_href}">report</a></td>'
        if report_href
        else '<td class="repro"></td>'
    )
    assets_links = "".join(
        f'<span class="no-break">[<a href="{href}">{label}</a>]</span>'
        for label, href in (assets or {}).items()
    )
    return f"""
    <html><body>
    <table class="list_table">
      <caption>Crashes (1):</caption>
      <tbody>
        <tr>
          <td>time</td><td>kernel</td><td>commit</td><td>syzkaller</td><td>config</td><td>log</td>
          {report_cell}
          <td class="assets">{assets_links}</td>
        </tr>
      </tbody>
    </table>
    </body></html>
    """


@pytest.fixture
def db_session(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path}/test.db")
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        yield session


def test_collect_saves_new_crash(db_session, httpx_mock):
    httpx_mock.add_response(
        url=UPSTREAM_URL,
        html=make_upstream_html([{"extid": "abc123", "title": "KASAN: use-after-free Read in ext4_put_super"}]),
    )
    httpx_mock.add_response(
        url="https://syzkaller.appspot.com/bug?extid=abc123",
        html=make_bug_detail_html("/text?tag=CrashReport&x=xyz789"),
    )
    httpx_mock.add_response(
        url="https://syzkaller.appspot.com/text?tag=CrashReport&x=xyz789",
        text=SYZBOT_REPORT_TEXT,
    )

    client = RetryingClient(httpx.Client())
    collector = SyzbotCollector(client=client)
    saved = collector.collect(db_session)

    assert saved == 1
    crash = db_session.query(Crash).one()
    assert crash.source == "syzbot"
    assert "use-after-free" in crash.raw_log
    assert crash.syzbot_fixed is False


def test_collect_skips_existing_crash(db_session, httpx_mock):
    db_session.add(Crash(source="syzbot", raw_log=SYZBOT_REPORT_TEXT, bug_type=None))
    db_session.commit()

    httpx_mock.add_response(
        url=UPSTREAM_URL,
        html=make_upstream_html([{"extid": "abc123", "title": "KASAN: use-after-free Read in ext4_put_super"}]),
    )
    httpx_mock.add_response(
        url="https://syzkaller.appspot.com/bug?extid=abc123",
        html=make_bug_detail_html("/text?tag=CrashReport&x=xyz789"),
    )
    httpx_mock.add_response(
        url="https://syzkaller.appspot.com/text?tag=CrashReport&x=xyz789",
        text=SYZBOT_REPORT_TEXT,
    )

    client = RetryingClient(httpx.Client())
    collector = SyzbotCollector(client=client)
    saved = collector.collect(db_session)

    assert saved == 0
    assert db_session.query(Crash).count() == 1


def test_collect_records_new_crash_as_unfixed(db_session, httpx_mock):
    """open 섹션에서 가져온 버그는 아직 패치되지 않았으므로 syzbot_fixed=False로
    기록되어야 한다."""
    httpx_mock.add_response(
        url=UPSTREAM_URL,
        html=make_upstream_html([{"extid": "def456", "title": "KASAN: slab-out-of-bounds in ext4_iget"}]),
    )
    httpx_mock.add_response(
        url="https://syzkaller.appspot.com/bug?extid=def456",
        html=make_bug_detail_html("/text?tag=CrashReport&x=uvw000"),
    )
    httpx_mock.add_response(
        url="https://syzkaller.appspot.com/text?tag=CrashReport&x=uvw000",
        text="BUG: KASAN: slab-out-of-bounds in ext4_iget",
    )

    client = RetryingClient(httpx.Client())
    collector = SyzbotCollector(client=client)
    collector.collect(db_session)

    crash = db_session.query(Crash).one()
    assert crash.syzbot_fixed is False


def test_collect_rejects_report_url_on_untrusted_host(db_session, httpx_mock):
    """버그 상세 페이지의 리포트 링크가 syzkaller.appspot.com이 아닌 다른
    호스트를 가리키면 그 요청은 나가지 않아야 한다 (SSRF 방지)."""
    httpx_mock.add_response(
        url=UPSTREAM_URL,
        html=make_upstream_html([{"extid": "evil1", "title": "fake bug"}]),
    )
    httpx_mock.add_response(
        url="https://syzkaller.appspot.com/bug?extid=evil1",
        html=make_bug_detail_html("https://attacker.example.com/steal?x=1"),
    )

    client = RetryingClient(httpx.Client())
    collector = SyzbotCollector(client=client)
    saved = collector.collect(db_session)

    assert saved == 0
    assert db_session.query(Crash).count() == 0
    requests = httpx_mock.get_requests()
    assert len(requests) == 2  # 목록 조회 + 상세 페이지 조회. 악성 호스트로는 요청 안 나감
    assert all(r.url.host != "attacker.example.com" for r in requests)


def test_collect_rejects_report_url_with_non_https_scheme(db_session, httpx_mock):
    httpx_mock.add_response(
        url=UPSTREAM_URL,
        html=make_upstream_html([{"extid": "evil2", "title": "fake bug"}]),
    )
    httpx_mock.add_response(
        url="https://syzkaller.appspot.com/bug?extid=evil2",
        html=make_bug_detail_html("http://syzkaller.appspot.com/text?tag=CrashReport&x=1"),
    )

    client = RetryingClient(httpx.Client())
    collector = SyzbotCollector(client=client)
    saved = collector.collect(db_session)

    assert saved == 0
    requests = httpx_mock.get_requests()
    assert len(requests) == 2


def test_collect_rejects_report_url_with_lookalike_host(db_session, httpx_mock):
    httpx_mock.add_response(
        url=UPSTREAM_URL,
        html=make_upstream_html([{"extid": "evil3", "title": "fake bug"}]),
    )
    httpx_mock.add_response(
        url="https://syzkaller.appspot.com/bug?extid=evil3",
        html=make_bug_detail_html("https://syzkaller.appspot.com.attacker.example.com/x"),
    )

    client = RetryingClient(httpx.Client())
    collector = SyzbotCollector(client=client)
    saved = collector.collect(db_session)

    assert saved == 0
    requests = httpx_mock.get_requests()
    assert len(requests) == 2


def test_collect_skips_bug_without_report_link_but_saves_the_rest(db_session, httpx_mock):
    """상세 페이지에 리포트 링크가 없는 버그는 건너뛰고, 나머지 정상
    버그는 계속 저장되어야 한다 (배치 전체 실패 방지)."""
    httpx_mock.add_response(
        url=UPSTREAM_URL,
        html=make_upstream_html(
            [
                {"extid": "broken1", "title": "bug with no report yet"},
                {"extid": "abc123", "title": "KASAN: use-after-free Read in ext4_put_super"},
            ]
        ),
    )
    httpx_mock.add_response(
        url="https://syzkaller.appspot.com/bug?extid=broken1",
        html=make_bug_detail_html(None),
    )
    httpx_mock.add_response(
        url="https://syzkaller.appspot.com/bug?extid=abc123",
        html=make_bug_detail_html("/text?tag=CrashReport&x=xyz789"),
    )
    httpx_mock.add_response(
        url="https://syzkaller.appspot.com/text?tag=CrashReport&x=xyz789",
        text=SYZBOT_REPORT_TEXT,
    )

    client = RetryingClient(httpx.Client())
    collector = SyzbotCollector(client=client)
    saved = collector.collect(db_session)

    assert saved == 1
    assert db_session.query(Crash).count() == 1


def test_collect_saves_asset_download_links(db_session, httpx_mock):
    """상세 페이지의 Assets 컬럼에 있는 vmlinux/디스크/커널 이미지 링크가
    Crash 레코드에 저장되어야 한다."""
    httpx_mock.add_response(
        url=UPSTREAM_URL,
        html=make_upstream_html([{"extid": "abc123", "title": "KASAN: use-after-free Read in ext4_put_super"}]),
    )
    httpx_mock.add_response(
        url="https://syzkaller.appspot.com/bug?extid=abc123",
        html=make_bug_detail_html(
            "/text?tag=CrashReport&x=xyz789",
            assets={
                "vmlinux": "https://storage.googleapis.com/syzbot-assets/aaa/vmlinux-bbb.xz",
                "disk image": "https://storage.googleapis.com/syzbot-assets/ccc/disk-ddd.raw.xz",
                "kernel image": "https://storage.googleapis.com/syzbot-assets/eee/bzImage-fff.xz",
            },
        ),
    )
    httpx_mock.add_response(
        url="https://syzkaller.appspot.com/text?tag=CrashReport&x=xyz789",
        text=SYZBOT_REPORT_TEXT,
    )

    client = RetryingClient(httpx.Client())
    collector = SyzbotCollector(client=client)
    collector.collect(db_session)

    crash = db_session.query(Crash).one()
    assert crash.vmlinux_url == "https://storage.googleapis.com/syzbot-assets/aaa/vmlinux-bbb.xz"
    assert crash.disk_image_url == "https://storage.googleapis.com/syzbot-assets/ccc/disk-ddd.raw.xz"
    assert crash.kernel_image_url == "https://storage.googleapis.com/syzbot-assets/eee/bzImage-fff.xz"


def test_collect_ignores_asset_links_on_untrusted_host(db_session, httpx_mock):
    httpx_mock.add_response(
        url=UPSTREAM_URL,
        html=make_upstream_html([{"extid": "abc123", "title": "KASAN: use-after-free Read in ext4_put_super"}]),
    )
    httpx_mock.add_response(
        url="https://syzkaller.appspot.com/bug?extid=abc123",
        html=make_bug_detail_html(
            "/text?tag=CrashReport&x=xyz789",
            assets={"vmlinux": "https://attacker.example.com/vmlinux.xz"},
        ),
    )
    httpx_mock.add_response(
        url="https://syzkaller.appspot.com/text?tag=CrashReport&x=xyz789",
        text=SYZBOT_REPORT_TEXT,
    )

    client = RetryingClient(httpx.Client())
    collector = SyzbotCollector(client=client)
    collector.collect(db_session)

    crash = db_session.query(Crash).one()
    assert crash.vmlinux_url is None


def test_collect_backfills_assets_onto_legacy_crash_without_extid(db_session, httpx_mock):
    """extid 추적이 추가되기 전에 저장된 레거시 크래시(raw_log만 있고
    syzbot_extid, 자산 링크가 전부 비어있는 상태)는, 같은 버그가 다시
    수집될 때 새로 생기는 자산 링크를 백필받아야 한다 — 새 행을 중복
    생성해서는 안 된다."""
    db_session.add(Crash(source="syzbot", raw_log=SYZBOT_REPORT_TEXT, bug_type=None))
    db_session.commit()

    httpx_mock.add_response(
        url=UPSTREAM_URL,
        html=make_upstream_html([{"extid": "abc123", "title": "KASAN: use-after-free Read in ext4_put_super"}]),
    )
    httpx_mock.add_response(
        url="https://syzkaller.appspot.com/bug?extid=abc123",
        html=make_bug_detail_html(
            "/text?tag=CrashReport&x=xyz789",
            assets={"vmlinux": "https://storage.googleapis.com/syzbot-assets/aaa/vmlinux-bbb.xz"},
        ),
    )
    httpx_mock.add_response(
        url="https://syzkaller.appspot.com/text?tag=CrashReport&x=xyz789",
        text=SYZBOT_REPORT_TEXT,
    )

    client = RetryingClient(httpx.Client())
    collector = SyzbotCollector(client=client)
    saved = collector.collect(db_session)

    assert saved == 0
    assert db_session.query(Crash).count() == 1
    crash = db_session.query(Crash).one()
    assert crash.syzbot_extid == "abc123"
    assert crash.vmlinux_url == "https://storage.googleapis.com/syzbot-assets/aaa/vmlinux-bbb.xz"


def test_collect_caps_number_of_bugs_processed_per_run(db_session, httpx_mock):
    """한 번 실행에서 처리하는 버그 수는 MAX_BUGS_PER_COLLECT로 제한되어야
    한다 (syzbot 서버에 과도한 요청을 보내지 않기 위함)."""
    bugs = [{"extid": f"bug{i}", "title": f"bug number {i}"} for i in range(MAX_BUGS_PER_COLLECT + 5)]
    httpx_mock.add_response(url=UPSTREAM_URL, html=make_upstream_html(bugs))
    for bug in bugs[:MAX_BUGS_PER_COLLECT]:
        httpx_mock.add_response(
            url=f"https://syzkaller.appspot.com/bug?extid={bug['extid']}",
            html=make_bug_detail_html(f"/text?tag=CrashReport&x={bug['extid']}"),
        )
        httpx_mock.add_response(
            url=f"https://syzkaller.appspot.com/text?tag=CrashReport&x={bug['extid']}",
            text=f"report for {bug['extid']}",
        )

    client = RetryingClient(httpx.Client())
    collector = SyzbotCollector(client=client)
    saved = collector.collect(db_session)

    assert saved == MAX_BUGS_PER_COLLECT
    assert db_session.query(Crash).count() == MAX_BUGS_PER_COLLECT
