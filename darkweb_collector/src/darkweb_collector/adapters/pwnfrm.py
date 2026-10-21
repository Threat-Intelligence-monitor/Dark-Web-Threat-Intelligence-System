from __future__ import annotations

from contextlib import nullcontext
import hashlib
from urllib.parse import urlparse

from darkweb_collector.adapters.base import SiteAdapter
from darkweb_collector.adapters.forum_artifacts import detail_artifacts_complete, restore_detail_artifacts
from darkweb_collector.adapters.pagination import collect_forum_seed
from darkweb_collector.collection_errors import CollectionFailure, raise_if_error_page
from darkweb_collector.db import (
    get_db_connection,
    get_forum_detail_snapshot,
    get_forum_topic_snapshot,
    upsert_forum_detail,
    upsert_forum_topic,
)
from darkweb_collector.models import DetailResult, DetailTask, RunContext, SeedResult, SiteConfig
from darkweb_collector.session_cookies import resolve_session_cookie
from darkweb_collector.sites.pwnfrm import parse_pwnfrm_detail, parse_pwnfrm_list
from darkweb_collector.tor_fetch import fetch_page_artifacts, fetch_url
from darkweb_collector.utils import dump_json, dump_text, safe_stem


def _section_name(url: str) -> str:
    """`/Forum-Databases?...` -> `databases`. Falls back to a slug of the path."""
    path = urlparse(url).path.strip("/")
    if path.startswith("Forum-"):
        return path[6:].replace("-", "_").lower()
    return safe_stem(path or "section")


def _detail_artifact_stem(url: str) -> str:
    return hashlib.sha1(url.encode("utf-8")).hexdigest()[:10]


def _detail_artifacts_exist(output_dir, section_name: str, topic_url: str) -> bool:
    artifact_stem = _detail_artifact_stem(topic_url)
    details_dir = output_dir / section_name / "details"
    return detail_artifacts_complete(details_dir, artifact_stem)


class PwnfrmAdapter(SiteAdapter):
    site_name = "pwnfrm"
    supports_frontier = True

    def _fetch_html(self, url: str, config: SiteConfig, mode: str) -> str:
        # pwnfrm sits behind tor; cookie header is optional (only used if the
        # site config declares a session_cookie* in extras).
        return fetch_url(
            url=url,
            mode=mode,
            timeout_seconds=config.fetch_timeout_seconds,
            render_wait_seconds=config.render_wait_seconds,
            retries=1,
            cookie_header=resolve_session_cookie(config),
        )

    @staticmethod
    def _is_valid_detail_html(html: str) -> bool:
        if not html:
            return False
        nul_ratio = html.count("\x00") / max(len(html), 1)
        if nul_ratio > 0.01:
            return False
        # MyBB classic skin markers — identical to darkforums.
        required_markers = ("id=\"posts\"", "post_body", "post_content", "post classic")
        return any(marker in html for marker in required_markers)

    @staticmethod
    def _is_valid_detail_payload(detail: dict) -> bool:
        content = str(detail.get("content") or "").strip()
        return bool(content)

    def collect_seed(self, config: SiteConfig, run_ctx: RunContext) -> SeedResult:
        return collect_forum_seed(self, config, parse_pwnfrm_list, _section_name)

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
                    topic_changed = (
                        topic_snapshot is None
                        or topic_snapshot["content_hash"] != topic["content_hash"]
                    )
                    detail_artifacts_ready = _detail_artifacts_exist(
                        config.output_dir,
                        section_name,
                        str(topic["full_url"]),
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

        # Round-robin so one noisy section can't starve the others.
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

    def collect_detail(
        self, detail_task: DetailTask, config: SiteConfig, run_ctx: RunContext
    ) -> DetailResult | None:
        restored = restore_detail_artifacts(
            detail_task, config, screenshot_selectors=("#thread-info", ".post.classic"),
            hide_selectors=("header", "#panel", "#quick-search", ".bam_wrapper", ".footer", "footer"),
        )
        if restored is not None:
            return restored
        cookie_header = resolve_session_cookie(config)
        html, screenshot_png = fetch_page_artifacts(
            url=detail_task.target_url,
            mode=config.detail_fetch_mode,
            timeout_seconds=config.fetch_timeout_seconds,
            render_wait_seconds=config.render_wait_seconds,
            screenshot_selectors=("#thread-info", ".post.classic"),
            hide_selectors=("header", "#panel", "#quick-search", ".bam_wrapper", ".footer", "footer"),
            render_html_for_screenshot=True,
            cookie_header=cookie_header,
        )
        raise_if_error_page(html)
        if not self._is_valid_detail_html(html):
            raise CollectionFailure("parse", "pwnfrm detail has no recognized post structure")
        detail = parse_pwnfrm_detail(detail_task.target_url, html)
        if not self._is_valid_detail_payload(detail):
            raise CollectionFailure("parse", "pwnfrm detail has no visible post content")
        return DetailResult(
            site_name=self.site_name, target_url=detail_task.target_url, payload=detail,
            raw_html=html, screenshot_png=screenshot_png, metadata=detail_task.metadata,
        )

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
                    artifact_stem = str(
                        detail_result.metadata.get("artifact_stem")
                        or _detail_artifact_stem(detail_result.target_url)
                    )
                    if detail_result.raw_html is not None:
                        dump_text(section_dir / f"{artifact_stem}.html", detail_result.raw_html)
                    if detail_result.screenshot_png is not None:
                        (section_dir / f"{artifact_stem}.png").write_bytes(detail_result.screenshot_png)
                    dump_json(section_dir / f"{artifact_stem}.json", {**detail_result.payload, "_collector_artifacts_complete": detail_result.screenshot_png is not None})
                    upsert_forum_detail(
                        detail_connection,
                        site_name=self.site_name,
                        section=section_name,
                        topic_url=detail_result.target_url,
                        content=detail_result.payload.get("content", ""),
                        authors=detail_result.payload.get("author", ""),
                        timestamps=detail_result.payload.get("timestamp", ""),
                        published_at_utc=detail_result.payload.get("published_at_utc", ""),
                        attachments=", ".join(detail_result.payload.get("attachments", [])),
                        victims=detail_result.payload.get("victims", []),
                        attackers=detail_result.payload.get("attackers", []),
                        content_hash=detail_result.payload["content_hash"],
                        collected_at_utc=detail_result.payload.get("collected_at_utc", ""),
                    )
                if connection is None:
                    detail_connection.commit()
