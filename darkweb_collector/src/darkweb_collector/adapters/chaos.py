from __future__ import annotations

from darkweb_collector.detail_artifacts import detail_artifact_paths, persist_detail_artifacts

from contextlib import nullcontext
from darkweb_collector.adapters.base import SiteAdapter
from darkweb_collector.adapters.forum_artifacts import detail_artifacts_complete, restore_detail_artifacts
from darkweb_collector.collection_errors import CollectionFailure, raise_if_error_page
from darkweb_collector.db import get_db_connection, get_victim_snapshot, record_victim_detail
from darkweb_collector.models import DetailResult, DetailTask, RunContext, SeedResult, SiteConfig
from darkweb_collector.pipeline import persist_run
from darkweb_collector.runtime import default_db_path
from darkweb_collector.sites.chaos import parse_chaos_detail, parse_chaos_homepage
from darkweb_collector.tor_fetch import fetch_page_artifacts, fetch_url
from darkweb_collector.utils import dump_json, dump_text, safe_stem
from urllib.parse import urlparse


def _detail_artifacts_exist(output_dir, artifact_stem: str, snapshot=None, site_name="", target_url="", source_version="") -> bool:
    details_dir = output_dir / "details"
    return detail_artifacts_complete(details_dir, artifact_stem, (snapshot or {}).get("artifact_payload", (snapshot or {}).get("detail_raw_json")),
                                     root=output_dir, site_name=site_name, target_url=target_url, source_version=source_version)


class ChaosAdapter(SiteAdapter):
    site_name = "chaos"

    def _fetch_html(self, url: str, config: SiteConfig, mode: str) -> str:
        return fetch_url(
            url=url,
            mode=mode,
            timeout_seconds=config.fetch_timeout_seconds,
            render_wait_seconds=config.render_wait_seconds,
            retries=1,
        )

    def collect_seed(self, config: SiteConfig, run_ctx: RunContext) -> SeedResult:
        if len(config.seed_urls) != 1:
            raise ValueError("chaos adapter expects exactly one seed URL")
        target_url = config.seed_urls[0]
        html = self._fetch_html(target_url, config, config.seed_fetch_mode)
        parsed = parse_chaos_homepage(target_url, html)
        parsed["title"] = parsed.get("page_title", "CHAOS")
        for victim in parsed["victims"]:
            victim["site_name"] = self.site_name
            victim["source_url"] = target_url
            victim["display_label"] = victim["name"]
            victim.setdefault("published_at_utc", None)
        return SeedResult(
            site_name=self.site_name,
            collected_at_utc=parsed["collected_at_utc"],
            payload=parsed,
            raw_html_by_url={target_url: html},
        )

    def plan_details(self, seed_result: SeedResult, config: SiteConfig) -> list[DetailTask]:
        tasks: list[DetailTask] = []
        with get_db_connection() as connection:
            for victim in seed_result.payload["victims"]:
                artifact_stem = safe_stem(
                    f"{victim['content_hash'][:10]}_{victim.get('domain') or victim['name']}"
                )
                snapshot = get_victim_snapshot(
                    connection,
                    site_name=victim["site_name"],
                    source_url=victim["source_url"],
                    name=victim["name"],
                    domain=victim.get("domain"),
                    status=victim["status"],
                )
                if (
                    snapshot
                    and snapshot["content_hash"] == victim["content_hash"]
                    and snapshot["last_detail_fetch_status"] == "ok"
                    and _detail_artifacts_exist(config.output_dir, artifact_stem, snapshot, self.site_name,
                                               str(victim.get("detail_url") or ""), str(victim.get("content_hash") or ""))
                ):
                    continue
                tasks.append(
                    DetailTask(
                        site_name=self.site_name,
                        target_url=victim["detail_url"],
                        metadata={
                            "source_url": victim["source_url"],
                            "name": victim["name"],
                            "domain": victim.get("domain"),
                            "status": victim["status"],
                            "artifact_stem": artifact_stem,
                            "source_version": victim["content_hash"],
                            "frontier_artifact_only": bool(
                                snapshot and snapshot["content_hash"] == victim["content_hash"]
                                and snapshot["last_detail_fetch_status"] == "ok"
                                and {"html", "json"} <= detail_artifact_paths(
                                    config.output_dir, config.output_dir / "details", artifact_stem,
                                    snapshot.get("artifact_payload", snapshot.get("detail_raw_json")), site_name=self.site_name,
                                    target_url=str(victim.get("detail_url") or "")).keys()
                            ),
                        },
                    )
                )
                if len(tasks) >= config.max_detail_pages_per_run:
                    break
        return tasks

    def collect_detail(self, detail_task: DetailTask, config: SiteConfig, run_ctx: RunContext) -> DetailResult | None:
        detail_path = urlparse(detail_task.target_url).path
        screenshot_selector = None
        if detail_path:
            screenshot_selector = (
                f"xpath=//a[@href='{detail_path}']/ancestor::div[contains(@class,'rounded-xl') "
                f"and contains(@class,'bg-bunker')][1]"
            )
        restored = restore_detail_artifacts(detail_task, config, screenshot_selector=screenshot_selector)
        if restored is not None:
            return restored
        detail, parsed_html = {}, None
        def validate(html):
            nonlocal detail, parsed_html
            if html == parsed_html:
                return True
            raise_if_error_page(html)
            parsed = parse_chaos_detail(detail_task.target_url, html)
            if not str(parsed.get("content") or "").strip() or not parsed.get("victims"):
                raise CollectionFailure("parse", "chaos detail has no recognized victim content")
            detail, parsed_html = parsed, html
            return True
        metadata = dict(detail_task.metadata)
        metadata.pop("artifact_error", None)
        html, screenshot_png = fetch_page_artifacts(
            url=detail_task.target_url,
            mode=config.detail_fetch_mode,
            timeout_seconds=config.fetch_timeout_seconds,
            render_wait_seconds=config.render_wait_seconds,
            screenshot_selector=screenshot_selector,
            validate_html=validate,
            on_artifact_error=lambda message: metadata.update(artifact_error=message),
        )
        validate(html)
        if not screenshot_png:
            metadata.setdefault("artifact_error", "artifact: victim evidence capture produced no image")
            detail["_collector_artifact_error"] = metadata["artifact_error"]
        return DetailResult(
            site_name=self.site_name,
            target_url=detail_task.target_url,
            payload=detail,
            raw_html=html,
            screenshot_png=screenshot_png,
            metadata=metadata,
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
            output_dir.mkdir(parents=True, exist_ok=True)
            _, html = next(iter(seed_result.raw_html_by_url.items()))
            dump_text(output_dir / "latest.html", html)
            dump_json(output_dir / "latest.json", seed_result.payload)
            persist_run(default_db_path(), seed_result.payload)

        if detail_results:
            details_dir = config.output_dir / "details"
            with (nullcontext(connection) if connection is not None else get_db_connection()) as detail_connection:
                for detail_result in detail_results:
                    artifact_stem = detail_result.metadata.get("artifact_stem") or safe_stem(detail_result.target_url)
                    persist_detail_artifacts(detail_connection, config, detail_result, details_dir, artifact_stem)
                    record_victim_detail(
                        detail_connection,
                        site_name=self.site_name,
                        source_url=str(detail_result.metadata["source_url"]),
                        name=str(detail_result.metadata["name"]),
                        domain=detail_result.metadata.get("domain"),
                        status=str(detail_result.metadata["status"]),
                        detail_payload=detail_result.payload,
                    )
                if connection is None:
                    detail_connection.commit()
