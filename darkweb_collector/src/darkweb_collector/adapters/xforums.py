from __future__ import annotations

import hashlib
from pathlib import Path

from darkweb_collector.adapters.darkforums import DarkforumsAdapter
from darkweb_collector.adapters.forum_artifacts import restore_detail_artifacts
from darkweb_collector.adapters.pagination import collect_paginated_seed
from darkweb_collector.browser_client import fetch_html_with_browser, fetch_page_artifacts_with_browser
from darkweb_collector.models import DetailResult, DetailTask, RunContext, SeedResult, SiteConfig
from darkweb_collector.runtime import user_data_root
from darkweb_collector.session_cookies import resolve_session_cookie
from darkweb_collector.sites.xforums import (
    parse_xforums_detail, parse_xforums_list, xforums_page_url, xforums_section,
)
from darkweb_collector.tor_fetch import browser_proxy_server_for_url, fetch_url


class XforumsAdapter(DarkforumsAdapter):
    site_name = "xforums"
    list_parser = staticmethod(parse_xforums_list)
    detail_parser = staticmethod(parse_xforums_detail)
    detail_screenshot_selector = "article.message--post.is-first, article.message--post[data-position='0']"
    screenshot_hide_selectors = (".p-navSticky", "#tc-qam-floatingMenu", ".u-bottomFixer", ".u-scrollButtons", ".u-navButtons")

    @staticmethod
    def _browser_options(config: SiteConfig, url: str) -> dict:
        raw = str(config.extras.get("browser_storage_state_file") or "").strip()
        storage_path = Path(raw).expanduser() if raw else None
        if storage_path is not None and not storage_path.is_absolute():
            storage_path = user_data_root() / storage_path
        return {
            "wait_seconds": config.render_wait_seconds,
            "timeout_seconds": config.fetch_timeout_seconds,
            "proxy_server": browser_proxy_server_for_url(url),
            "browser_engine": str(config.extras.get("browser_engine") or "chromium"),
            "storage_state_path": str(storage_path) if storage_path else None,
            "persist_storage_state": bool(storage_path),
            "cookie_header": resolve_session_cookie(config),
        }

    def _fetch_html(self, url: str, config: SiteConfig, mode: str) -> str:
        # HTTP is sufficient when the source allows it; challenge pages never
        # count as empty lists. Browser fallback uses the existing bounded pool.
        try:
            html = fetch_url(
                url, mode="tor_http", timeout_seconds=min(config.fetch_timeout_seconds, 20),
                retries=0, cookie_header=resolve_session_cookie(config),
            )
            self.list_parser(url, html)
            return html
        except Exception:
            if mode != "browser":
                raise
        html = fetch_html_with_browser(url, **self._browser_options(config, url))
        self.list_parser(url, html)
        return html

    def collect_seed(self, config: SiteConfig, run_ctx: RunContext) -> SeedResult:
        def fetch_page(source_url: str, page: int, collected_at: str):
            url = xforums_page_url(source_url, page)
            html = self._fetch_html(url, config, config.seed_fetch_mode)
            parsed = self.list_parser(url, html, max_topics=2 ** 31 - 1)
            parsed["section"] = xforums_section(source_url)
            parsed["collected_at_utc"] = collected_at
            identifiers = sorted(topic["tid"] for topic in parsed["topics"])
            signature = hashlib.sha256("\n".join(identifiers).encode("utf-8")).hexdigest()
            return parsed, html, parsed["has_more"], signature, url

        return collect_paginated_seed(self.site_name, config, fetch_page)

    def collect_detail(self, detail_task: DetailTask, config: SiteConfig, run_ctx: RunContext) -> DetailResult:
        restored = restore_detail_artifacts(
            detail_task, config, screenshot_selector=self.detail_screenshot_selector,
            hide_selectors=self.screenshot_hide_selectors,
        )
        if restored is not None:
            return restored
        html, screenshot = fetch_page_artifacts_with_browser(
            detail_task.target_url,
            screenshot_selector=self.detail_screenshot_selector,
            hide_selectors=self.screenshot_hide_selectors,
            **self._browser_options(config, detail_task.target_url),
        )
        detail = self.detail_parser(detail_task.target_url, html)
        return DetailResult(
            site_name=self.site_name, target_url=detail_task.target_url,
            payload=detail, raw_html=html, screenshot_png=screenshot or None,
            metadata=detail_task.metadata,
        )
