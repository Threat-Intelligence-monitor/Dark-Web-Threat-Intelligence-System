from __future__ import annotations

from darkweb_collector.detail_artifacts import persist_detail_artifacts

from contextlib import nullcontext
import hashlib
import json
import logging
import time
from pathlib import Path
from urllib.parse import urlparse

from darkweb_collector.adapters.base import SiteAdapter
from darkweb_collector.access_bypass.profiles import profile_for as bypass_profile_for
from darkweb_collector.adapters.forum_artifacts import FORUM_CAPTURE_CONTENT_SELECTOR, detail_artifacts_complete, restore_detail_artifacts
from darkweb_collector.adapters.pagination import collect_forum_seed, is_forum_listing_html
from darkweb_collector.browser_client import fetch_html_with_browser, fetch_page_artifacts_with_browser, screenshot_html_with_browser
from darkweb_collector.collection_errors import CollectionFailure, raise_if_error_page, safe_failure_text, summarize_failures
from darkweb_collector.db import (
    get_db_connection,
    get_forum_detail_snapshot,
    get_forum_topic_snapshot,
    upsert_forum_detail,
    upsert_forum_topic,
)
from darkweb_collector.models import DetailResult, DetailTask, RunContext, SeedResult, SiteConfig
from darkweb_collector.source_sessions import browser_session_options, http_session_options
from darkweb_collector.sites.darkforums import (
    SYNDICATION_DEFAULT_PATH,
    build_darkforums_feed_detail,
    parse_darkforums_detail,
    parse_darkforums_list,
    parse_darkforums_syndication,
)
from darkweb_collector.tor_fetch import browser_proxy_server_for_url, fetch_url, fetch_via_http_proxy, is_onion_url
from darkweb_collector.utils import dump_json, dump_text, safe_stem


logger = logging.getLogger(__name__)


def _section_name(url: str) -> str:
    path = urlparse(url).path.strip("/")
    if path.startswith("Forum-"):
        return path[6:].replace("-", "_").lower()
    return safe_stem(path or "section")


def _detail_artifact_stem(url: str) -> str:
    return hashlib.sha1(url.encode("utf-8")).hexdigest()[:10]


def _detail_artifacts_exist(output_dir, section_name: str, topic_url: str, snapshot=None, site_name="", source_version="") -> bool:
    artifact_stem = _detail_artifact_stem(topic_url)
    details_dir = output_dir / section_name / "details"
    return detail_artifacts_complete(details_dir, artifact_stem, (snapshot or {}).get("artifact_payload", (snapshot or {}).get("raw_json")),
                                     root=output_dir, site_name=site_name, target_url=topic_url, forum=True, source_version=source_version)


FEED_FALLBACK_KINDS = frozenset({"blocked", "unavailable", "timeout", "network", "not_found"})
FEED_CACHE_TTL_SECONDS = 6 * 3600
FEED_CACHE_MAX_AGE_SECONDS = 7 * 86400
FEED_CACHE_MAX_ITEMS = 300
FEED_TOPIC_LIMIT = 40


def _feed_cache_path(output_dir: Path) -> Path:
    return output_dir / "darkforums-feed.json"


def _load_feed_cache(output_dir: Path) -> dict:
    """Read the feed cache (thread url -> feed topic snapshot). Never raises."""
    try:
        payload = json.loads(_feed_cache_path(output_dir).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    items = payload.get("items") if isinstance(payload, dict) else None
    return items if isinstance(items, dict) else {}


def _store_feed_topics(output_dir: Path, topics: list[dict], feed_url: str) -> None:
    """Persist feed topics so the detail phase can reuse the post bodies it already has."""
    now = time.time()
    items = _load_feed_cache(output_dir)
    for topic in topics:
        url = str(topic.get("full_url") or "").strip()
        if not url:
            continue
        items[url] = {**topic, "cached_at": now, "feed_url": feed_url}
    items = {
        url: item for url, item in items.items()
        if now - float(item.get("cached_at") or 0) <= FEED_CACHE_MAX_AGE_SECONDS
    }
    if len(items) > FEED_CACHE_MAX_ITEMS:
        newest = sorted(items.items(), key=lambda pair: float(pair[1].get("cached_at") or 0), reverse=True)
        items = dict(newest[:FEED_CACHE_MAX_ITEMS])
    path = _feed_cache_path(output_dir)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(".tmp")
        temporary.write_text(json.dumps({"version": 1, "items": items}, ensure_ascii=False), encoding="utf-8")
        temporary.replace(path)
    except OSError:
        logger.warning("darkforums feed cache could not be written to %s", path, exc_info=True)


class DarkforumsAdapter(SiteAdapter):
    site_name = "darkforums"
    supports_frontier = True
    list_parser = staticmethod(parse_darkforums_list)
    detail_parser = staticmethod(parse_darkforums_detail)
    detail_screenshot_selectors = ("#thread-info", ".post.classic")
    detail_capture_content_selector = FORUM_CAPTURE_CONTENT_SELECTOR
    terminal_failure_kinds = frozenset({"retry_budget", "unavailable", "rate_limited", "restricted"})

    @staticmethod
    def _is_valid_seed_html(html: str) -> bool:
        return is_forum_listing_html(html)

    @staticmethod
    def _browser_options(config: SiteConfig, url: str) -> dict:
        proxy_server = browser_proxy_server_for_url(url)
        return {
            "wait_seconds": config.render_wait_seconds,
            "timeout_seconds": config.fetch_timeout_seconds,
            "proxy_server": proxy_server,
            **browser_session_options(config, url, proxy_server),
            "browser_engine": str(config.extras.get("browser_engine") or "firefox"),
            "bypass_profile": bypass_profile_for(config.site_name, url=url, extras=config.extras),
        }

    def _fetch_html(self, url: str, config: SiteConfig, mode: str) -> str:
        proxy_server = browser_proxy_server_for_url(url)
        def validate(html):
            raise_if_error_page(html)
            if not self._is_valid_seed_html(html):
                raise CollectionFailure("parse", f"{self.site_name} response has no recognized forum listing")
            self.list_parser(url, html)
            return True

        routes = []
        if not is_onion_url(url):
            routes.append(("direct", lambda: fetch_via_http_proxy(
                url, timeout=config.fetch_timeout_seconds, retries=0, bypass_proxy=True,
                **http_session_options(config, url, None),
            )))
        if mode == "browser":
            routes.append(("browser", lambda: fetch_html_with_browser(
                url, validate_html=validate, **self._browser_options(config, url),
            )))
        elif is_onion_url(url) or proxy_server:
            routes.append(("proxy", lambda: fetch_url(
                url=url, mode=mode, timeout_seconds=config.fetch_timeout_seconds,
                retries=0, **http_session_options(config, url, proxy_server),
            )))
        failures: list[tuple[str, Exception]] = []
        for route_name, fetcher in routes:
            try:
                html = fetcher()
                if route_name != "browser":
                    validate(html)
                return html
            except CollectionFailure as exc:
                if exc.kind in self.terminal_failure_kinds:
                    raise
                failures.append((route_name, exc))
            except Exception as exc:
                failures.append((route_name, exc))
        raise summarize_failures(f"{self.site_name} listing fetch routes failed", failures)

    @staticmethod
    def _is_valid_detail_html(html: str) -> bool:
        if not html:
            return False
        nul_ratio = html.count("\x00") / max(len(html), 1)
        if nul_ratio > 0.01:
            return False
        required_markers = ("id=\"posts\"", "post_body", "post_content", "post classic")
        return any(marker in html for marker in required_markers)

    @staticmethod
    def _is_valid_detail_payload(detail: dict) -> bool:
        content = str(detail.get("content") or "").strip()
        return bool(content)

    def _feed_url(self, config: SiteConfig) -> str:
        configured = str(config.extras.get("darkforums_feed_url") or "").strip()
        if configured:
            return configured
        for seed in config.seed_urls:
            parsed = urlparse(seed)
            if parsed.scheme and parsed.netloc:
                return f"{parsed.scheme}://{parsed.netloc}{SYNDICATION_DEFAULT_PATH}"
        return f"https://darkforums.as{SYNDICATION_DEFAULT_PATH}"

    def _fetch_feed_xml(self, config: SiteConfig, feed_url: str) -> str:
        """Fetch the feed over HTTP first, then through the browser.

        `/syndication.php` usually answers a plain client, but the egress that Cloudflare
        has already flagged gets a 403 for it too. The browser route is slower, yet it can
        still load the page because there is no interactive challenge on the feed itself.
        """
        try:
            return fetch_via_http_proxy(
                feed_url,
                timeout=config.fetch_timeout_seconds,
                retries=1,
                bypass_proxy=True,
                **http_session_options(config, feed_url, None),
            )
        except CollectionFailure as exc:
            if exc.kind in self.terminal_failure_kinds:
                raise
            logger.warning("darkforums feed direct fetch failed (%s); retrying through the browser", exc.kind)
        return fetch_html_with_browser(feed_url, **self._browser_options(config, feed_url))

    def _collect_feed_seed(self, config: SiteConfig, cause: Exception | None = None) -> SeedResult:
        """Read the newest threads (and their post bodies) from the RSS feed.

        The forum listing sits behind the same managed challenge as thread pages,
        while `/syndication.php` is served untouched. Its items carry the first
        post body, which thread pages hide behind "Hidden Content" for guests.
        """
        feed_url = self._feed_url(config)
        xml_text = self._fetch_feed_xml(config, feed_url)
        parsed = parse_darkforums_syndication(xml_text, base_url=feed_url, max_topics=FEED_TOPIC_LIMIT)
        topics = parsed["topics"]
        if not topics:
            raise CollectionFailure("parse", "darkforums feed returned no topics")
        _store_feed_topics(config.output_dir, topics, feed_url)
        collected_at = parsed["collected_at_utc"]
        section = {
            "section": "feed",
            "source_url": feed_url,
            "collected_at_utc": collected_at,
            "title": parsed["title"],
            "source_count": len(topics),
            "topics": topics,
        }
        payload = {
            "site_name": self.site_name,
            "source_url": feed_url,
            "collected_at_utc": collected_at,
            "section_count": 1,
            "topic_count": len(topics),
            "sections": [section],
            "pagination_errors": [],
        }
        logger.info("darkforums seed recovered from the syndication feed (%s topics)", len(topics))
        return SeedResult(
            site_name=self.site_name,
            collected_at_utc=collected_at,
            payload=payload,
            raw_html_by_url={feed_url: xml_text},
            metadata={"feed_fallback": cause is not None, "feed_cause": safe_failure_text(str(cause)) if cause else "", "discovery_lane": "feed"},
        )

    def _detail_from_feed(self, detail_task: DetailTask, config: SiteConfig) -> DetailResult | None:
        """Reuse a feed snapshot for this thread when the page itself is unreachable."""
        url = detail_task.target_url
        item = _load_feed_cache(config.output_dir).get(url)
        if not item:
            return None
        if time.time() - float(item.get("cached_at") or 0) > FEED_CACHE_TTL_SECONDS:
            return None
        try:
            detail = build_darkforums_feed_detail(url, item)
        except CollectionFailure:
            return None
        metadata = dict(detail_task.metadata)
        metadata["artifact_error"] = "artifact: darkforums feed route has no rendered screenshot"
        detail["_collector_artifact_error"] = metadata["artifact_error"]
        logger.info("darkforums detail served from the feed cache: %s", url)
        return DetailResult(
            site_name=self.site_name,
            target_url=url,
            payload=detail,
            raw_html=str(item.get("content_html") or ""),
            screenshot_png=None,
            metadata=metadata,
        )

    def collect_seed(self, config: SiteConfig, run_ctx: RunContext) -> SeedResult:
        """Prefer the feed; the listing costs a ~90s failed challenge cycle first.

        The forum listing answers this collector's egress with a managed challenge
        (HTTP 403), so trying it first burns the whole seed budget and then still
        needs the feed. `/syndication.php` answers in about three seconds, so the
        order is flipped unless `darkforums_feed_first` is set to false.
        """
        if self._feed_preferred(config):
            try:
                return self._collect_feed_seed(config)
            except CollectionFailure as exc:
                if exc.kind in self.terminal_failure_kinds:
                    raise
                logger.warning("darkforums feed route failed (%s); falling back to the forum listing", exc.kind)
        try:
            return collect_forum_seed(self, config, self.list_parser, _section_name)
        except CollectionFailure as exc:
            if exc.kind not in FEED_FALLBACK_KINDS:
                raise
            logger.warning("darkforums listing route failed (%s); trying the syndication feed", exc.kind)
            return self._collect_feed_seed(config, exc)

    @staticmethod
    def _feed_preferred(config: SiteConfig) -> bool:
        value = config.extras.get("darkforums_feed_first")
        if value is None:
            return True
        return str(value).strip().lower() not in {"0", "false", "no", "off"}

    def plan_details(self, seed_result: SeedResult, config: SiteConfig) -> list[DetailTask]:
        per_section_tasks: list[list[DetailTask]] = []
        with get_db_connection() as connection:
            for section in seed_result.payload["sections"]:
                section_name = str(section["section"])
                section_tasks: list[DetailTask] = []
                for topic in section["topics"]:
                    topic_snapshot = get_forum_topic_snapshot(
                        connection,
                        site_name=self.site_name,
                        section=section_name,
                        url=str(topic["full_url"]),
                    )
                    detail_snapshot = get_forum_detail_snapshot(
                        connection,
                        site_name=self.site_name,
                        section=section_name,
                        topic_url=str(topic["full_url"]),
                    )
                    topic_changed = topic_snapshot is None or topic_snapshot["content_hash"] != topic["content_hash"]
                    detail_artifacts_ready = _detail_artifacts_exist(
                        config.output_dir,
                        section_name,
                        str(topic["full_url"]),
                        detail_snapshot, self.site_name, str(topic["content_hash"]),
                    )
                    if not topic_changed and detail_snapshot is not None and detail_artifacts_ready:
                        continue
                    section_tasks.append(
                        DetailTask(
                            site_name=self.site_name,
                            target_url=str(topic["full_url"]),
                            metadata={
                                "section": section_name,
                                "artifact_stem": _detail_artifact_stem(str(topic["full_url"])),
                                "title": topic["title"],
                                "source_version": topic["content_hash"],
                                "discovery_lane": topic.get("discovery_lane", "recent"),
                                "frontier_fetched_version": topic["content_hash"] if not topic_changed and detail_snapshot is not None else "",
                                "frontier_artifacts_complete": detail_artifacts_ready,
                            },
                        )
                    )
                if section_tasks:
                    per_section_tasks.append(section_tasks)

        tasks: list[DetailTask] = []
        while any(per_section_tasks):
            next_round: list[list[DetailTask]] = []
            for bucket in per_section_tasks:
                if not bucket:
                    continue
                tasks.append(bucket.pop(0))
                if bucket:
                    next_round.append(bucket)
            per_section_tasks = next_round
        return tasks

    def collect_detail(self, detail_task: DetailTask, config: SiteConfig, run_ctx: RunContext) -> DetailResult | None:
        restored = restore_detail_artifacts(
            detail_task, config, screenshot_selectors=self.detail_screenshot_selectors,
            capture_content_selector=self.detail_capture_content_selector,
            hide_selectors=("header", "#panel", "#quick-search", ".bam_wrapper", ".footer", "footer"),
        )
        if restored is not None:
            return restored
        from_feed = self._detail_from_feed(detail_task, config)
        if from_feed is not None:
            return from_feed
        url = detail_task.target_url
        proxy_server = browser_proxy_server_for_url(url)
        hide_selectors = ("header", "#panel", "#quick-search", ".bam_wrapper", ".footer", "footer")
        detail, parsed_html = {}, None
        def validate(html):
            nonlocal detail, parsed_html
            if html == parsed_html:
                return True
            raise_if_error_page(html)
            if not self._is_valid_detail_html(html):
                raise CollectionFailure("parse", f"{self.site_name} detail has no recognized post structure")
            parsed = self.detail_parser(url, html)
            if not self._is_valid_detail_payload(parsed):
                raise CollectionFailure("parse", f"{self.site_name} detail has no visible post content")
            detail, parsed_html = parsed, html
            return True

        # While the feed is the preferred source, threads outside it are almost always
        # unreachable from this egress; a browser attempt would burn ~90s before failing,
        # so keep those to the cheap direct probe. Set `darkforums_feed_first: false` to
        # restore the old browser route.
        routes = [] if is_onion_url(url) else ["direct"]
        if config.detail_fetch_mode == "browser" and not self._feed_preferred(config):
            routes.append("browser")
        elif is_onion_url(url) or proxy_server:
            routes.append("proxy")
        failures: list[tuple[str, Exception]] = []
        for route in routes:
            try:
                artifact_error = ""
                if route == "browser":
                    capture_errors = []
                    html, screenshot_png = fetch_page_artifacts_with_browser(
                        url, screenshot_selectors=self.detail_screenshot_selectors,
                        capture_content_selector=self.detail_capture_content_selector,
                        hide_selectors=hide_selectors, validate_html=validate,
                        on_artifact_error=capture_errors.append,
                        **self._browser_options(config, url),
                    )
                    artifact_error = capture_errors[-1] if capture_errors else ""
                else:
                    route_proxy = None if route == "direct" else proxy_server
                    http_options = http_session_options(config, url, route_proxy)
                    if route == "direct":
                        html = fetch_via_http_proxy(
                            url, timeout=config.fetch_timeout_seconds, retries=0, bypass_proxy=True,
                            **http_options,
                        )
                    else:
                        html = fetch_url(
                            url, mode=config.detail_fetch_mode, timeout_seconds=config.fetch_timeout_seconds,
                            retries=0, **http_options,
                        )
                    validate(html)
                    try:
                        session_options = browser_session_options(config, url, route_proxy)
                        screenshot_png = screenshot_html_with_browser(
                            html, url,
                            wait_seconds=config.render_wait_seconds,
                            timeout_seconds=config.fetch_timeout_seconds,
                            proxy_server=route_proxy,
                            browser_engine=str(config.extras.get("browser_engine") or "firefox"),
                            storage_state_path=session_options["storage_state_path"],
                            cookie_header=session_options["cookie_header"],
                            user_agent=http_options["user_agent"],
                            screenshot_selectors=self.detail_screenshot_selectors,
                            capture_content_selector=self.detail_capture_content_selector,
                            hide_selectors=hide_selectors,
                        )
                    except Exception as exc:
                        screenshot_png = None
                        artifact_error = safe_failure_text(f"artifact: forum evidence capture failed ({type(exc).__name__}): {exc}")
                metadata = dict(detail_task.metadata)
                metadata.pop("artifact_error", None)
                if not screenshot_png:
                    metadata["artifact_error"] = artifact_error or "artifact: forum evidence capture produced no image"
                    detail["_collector_artifact_error"] = metadata["artifact_error"]
                return DetailResult(
                    site_name=self.site_name, target_url=url, payload=detail,
                    raw_html=html, screenshot_png=screenshot_png or None, metadata=metadata,
                )
            except CollectionFailure as exc:
                if exc.kind in self.terminal_failure_kinds:
                    raise
                failures.append((route, exc))
            except Exception as exc:
                failures.append((route, exc))
        raise summarize_failures(f"{self.site_name} detail fetch routes failed", failures)

    def persist(
        self,
        config: SiteConfig,
        run_ctx: RunContext,
        seed_result: SeedResult | None = None,
        detail_results: list[DetailResult] | None = None,
        connection=None,
    ) -> None:
        if seed_result is not None:
            output_dir = config.output_dir
            with get_db_connection() as seed_connection:
                for section in seed_result.payload["sections"]:
                    section_name = str(section["section"])
                    section_dir = output_dir / section_name
                    section_url = str(section["source_url"])
                    html = seed_result.raw_html_by_url[section_url]
                    dump_text(section_dir / "section_page.html", html)
                    dump_json(section_dir / "topics_list.json", section)
                    for topic in section["topics"]:
                        upsert_forum_topic(
                            seed_connection,
                            site_name=self.site_name,
                            section=section_name,
                            title=topic["title"],
                            url=topic["full_url"],
                            author=topic.get("author", ""),
                            replies=topic.get("replies", ""),
                            views=topic.get("views", ""),
                            published_at=topic.get("published_at", ""),
                            last_reply_at=topic.get("last_reply_at", ""),
                            content_hash=topic["content_hash"],
                            collected_at_utc=section["collected_at_utc"],
                        )
                seed_connection.commit()
            dump_json(output_dir / "latest.json", seed_result.payload)

        if detail_results:
            with (nullcontext(connection) if connection is not None else get_db_connection()) as detail_connection:
                for detail_result in detail_results:
                    section_name = str(detail_result.metadata["section"])
                    section_dir = config.output_dir / section_name / "details"
                    artifact_stem = str(detail_result.metadata.get("artifact_stem") or _detail_artifact_stem(detail_result.target_url))
                    artifacts = persist_detail_artifacts(detail_connection, config, detail_result, section_dir,
                                                         artifact_stem, section=section_name)
                    upsert_forum_detail(
                        detail_connection,
                        site_name=self.site_name,
                        section=section_name,
                        topic_url=detail_result.target_url,
                        artifact_refs=artifacts,
                        content=detail_result.payload.get("content", ""),
                        authors=detail_result.payload.get("author", ""),
                        timestamps=detail_result.payload.get("timestamp", ""),
                        published_at_utc=detail_result.payload.get("published_at_utc", ""),
                        content_access=detail_result.payload.get("content_access", ""),
                        attachments=", ".join(detail_result.payload.get("attachments", [])),
                        victims=detail_result.payload.get("victims", []),
                        attackers=detail_result.payload.get("attackers", []),
                        content_hash=detail_result.payload["content_hash"],
                        collected_at_utc=detail_result.payload.get("collected_at_utc", ""),
                    )
                if connection is None:
                    detail_connection.commit()
