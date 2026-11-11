from __future__ import annotations

import hashlib

from darkweb_collector.adapters.darkforums import DarkforumsAdapter
from darkweb_collector.adapters.forum_artifacts import restore_detail_artifacts
from darkweb_collector.adapters.pagination import collect_paginated_seed
from darkweb_collector.browser_client import fetch_html_with_browser, fetch_page_artifacts_with_browser, screenshot_html_with_browser
from darkweb_collector.collection_errors import CollectionFailure, safe_failure_text, summarize_failures
from darkweb_collector.models import DetailResult, DetailTask, RunContext, SeedResult, SiteConfig
from darkweb_collector.source_sessions import browser_session_options, http_session_options
from darkweb_collector.sites.xforums import (
    parse_xforums_detail, parse_xforums_list, xforums_page_url, xforums_section,
)
from darkweb_collector.tor_fetch import browser_proxy_server_for_url, fetch_url


class XforumsAdapter(DarkforumsAdapter):
    site_name = "xforums"
    list_parser = staticmethod(parse_xforums_list)
    detail_parser = staticmethod(parse_xforums_detail)
    detail_screenshot_selector = "article.message--post.is-first, article.message--post[data-position='0']"
    detail_capture_content_selector = (
        "article.message--post:is(.is-first, [data-position='0']) .message-body, "
        "article.message--post:is(.is-first, [data-position='0']) .message-userContent:not(:has(.message-body))"
    )
    screenshot_hide_selectors = (".p-navSticky", "#tc-qam-floatingMenu", ".u-bottomFixer", ".u-scrollButtons", ".u-navButtons")

    @staticmethod
    def _browser_options(config: SiteConfig, url: str, verification_provider: str = "") -> dict:
        proxy_server = browser_proxy_server_for_url(url)
        return {
            "wait_seconds": config.render_wait_seconds,
            "timeout_seconds": config.fetch_timeout_seconds,
            "proxy_server": proxy_server,
            **browser_session_options(config, url, proxy_server),
            "browser_engine": str(config.extras.get("browser_engine") or "chromium"),
            "verification_provider": verification_provider,
        }

    def _fetch_html(self, url: str, config: SiteConfig, mode: str) -> str:
        # HTTP is sufficient when the source allows it; challenge pages never
        # count as empty lists. Browser fallback uses the existing bounded pool.
        failures: list[tuple[str, Exception]] = []
        proxy_server = browser_proxy_server_for_url(url)
        verification_provider = ""
        try:
            html = fetch_url(
                url, mode="tor_http", timeout_seconds=min(config.fetch_timeout_seconds, 20),
                retries=0, **http_session_options(config, url, proxy_server),
            )
            self.list_parser(url, html)
            return html
        except Exception as exc:
            if mode != "browser" or (isinstance(exc, CollectionFailure) and exc.kind in {
                "retry_budget", "unavailable", "rate_limited", "restricted",
            }):
                raise
            failures.append(("http", exc))
            verification_provider = "dnsproxy" if (
                isinstance(exc, CollectionFailure) and exc.kind == "blocked" and exc.verification_provider == "dnsproxy"
            ) else ""
        try:
            def validate(html):
                self.list_parser(url, html)
                return True
            html = fetch_html_with_browser(
                url, validate_html=validate, **self._browser_options(config, url, verification_provider),
            )
            return html
        except CollectionFailure as exc:
            if exc.kind in {"retry_budget", "unavailable", "rate_limited", "restricted"}:
                raise
            failures.append(("browser", exc))
        except Exception as exc:
            failures.append(("browser", exc))
        raise summarize_failures("xforums listing fetch routes failed", failures)

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

        return collect_paginated_seed(self.site_name, config, fetch_page, plan_details=self.plan_details)

    def collect_detail(self, detail_task: DetailTask, config: SiteConfig, run_ctx: RunContext) -> DetailResult:
        restored = restore_detail_artifacts(
            detail_task, config, screenshot_selector=self.detail_screenshot_selector,
            capture_content_selector=self.detail_capture_content_selector,
            hide_selectors=self.screenshot_hide_selectors,
        )
        if restored is not None:
            return restored
        url = detail_task.target_url
        proxy_server = browser_proxy_server_for_url(url)
        detail, parsed_html = {}, None
        def validate(html):
            nonlocal detail, parsed_html
            if html != parsed_html:
                parsed = self.detail_parser(url, html)
                detail, parsed_html = parsed, html
            return True
        failures = []
        metadata = dict(detail_task.metadata)
        metadata.pop("artifact_error", None)
        try:
            http_options = http_session_options(config, url, proxy_server)
            html = fetch_url(
                url, mode="tor_http", timeout_seconds=min(config.fetch_timeout_seconds, 20),
                retries=0, **http_options,
            )
            validate(html)
        except Exception as exc:
            if config.detail_fetch_mode != "browser" or (isinstance(exc, CollectionFailure) and exc.kind in {
                "retry_budget", "unavailable", "rate_limited", "restricted",
            }):
                raise
            failures.append(("http", exc))
            verification_provider = "dnsproxy" if (
                isinstance(exc, CollectionFailure) and exc.kind == "blocked" and exc.verification_provider == "dnsproxy"
            ) else ""
            try:
                html, screenshot = fetch_page_artifacts_with_browser(
                    url, screenshot_selector=self.detail_screenshot_selector,
                    capture_content_selector=self.detail_capture_content_selector,
                    hide_selectors=self.screenshot_hide_selectors, validate_html=validate,
                    on_artifact_error=lambda message: metadata.update(artifact_error=message),
                    **self._browser_options(config, url, verification_provider),
                )
            except Exception as browser_error:
                if isinstance(browser_error, CollectionFailure) and browser_error.kind in {
                    "retry_budget", "unavailable", "rate_limited", "restricted",
                }:
                    raise
                failures.append(("browser", browser_error))
                raise summarize_failures("xforums detail fetch routes failed", failures)
        else:
            try:
                session_options = browser_session_options(config, url, proxy_server)
                screenshot = screenshot_html_with_browser(
                    html, url, wait_seconds=config.render_wait_seconds,
                    capture_content_selector=self.detail_capture_content_selector,
                    timeout_seconds=config.fetch_timeout_seconds, proxy_server=proxy_server,
                    browser_engine=str(config.extras.get("browser_engine") or "chromium"),
                    storage_state_path=session_options["storage_state_path"],
                    cookie_header=session_options["cookie_header"], user_agent=http_options["user_agent"],
                    screenshot_selector=self.detail_screenshot_selector, hide_selectors=self.screenshot_hide_selectors,
                )
            except Exception as exc:
                screenshot = None
                metadata["artifact_error"] = safe_failure_text(f"artifact: forum evidence capture failed ({type(exc).__name__}): {exc}")
        if not screenshot:
            metadata.setdefault("artifact_error", "artifact: forum evidence capture produced no image")
            detail["_collector_artifact_error"] = metadata["artifact_error"]
        return DetailResult(
            site_name=self.site_name, target_url=detail_task.target_url,
            payload=detail, raw_html=html, screenshot_png=screenshot or None,
            metadata=metadata,
        )
