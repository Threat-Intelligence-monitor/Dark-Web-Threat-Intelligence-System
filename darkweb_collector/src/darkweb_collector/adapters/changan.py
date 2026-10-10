from __future__ import annotations

from contextlib import nullcontext
from html import escape
import hashlib
import json
import re
import shutil
import subprocess
from urllib.parse import urlencode, urlsplit, urlunsplit

from darkweb_collector.adapters.base import SiteAdapter
from darkweb_collector.adapters.forum_artifacts import restore_detail_artifacts
from darkweb_collector.adapters.pagination import collect_paginated_seed
from darkweb_collector.browser_client import fetch_page_artifacts_with_browser
from darkweb_collector.changan_auto_login import recover_changan_session
from darkweb_collector.db import (
    get_db_connection,
    get_forum_detail_snapshot,
    get_forum_topic_snapshot,
    upsert_forum_detail,
    upsert_forum_topic,
)
from darkweb_collector.models import DetailResult, DetailTask, RunContext, SeedResult, SiteConfig
from darkweb_collector.site_auth import (
    SiteAuthenticationRequired,
    mark_site_auth_invalid,
    require_site_auth_token,
)
from darkweb_collector.sites.changan import parse_changan_detail, parse_changan_list
from darkweb_collector.tor_fetch import browser_proxy_server_for_url, get_tor_socks_settings
from darkweb_collector.utils import dump_json, dump_text, utc_now_iso


AUTH_ERROR_CODES = {4009, 4087}
SECTION = "sellers_place"


def _capture_ready_script(expects_image: bool) -> str:
    return f"""
() => {{
    const root = document.querySelector('.product-detail-info');
    if (!root) return false;
    const text = (selector) => String(root.querySelector(selector)?.textContent || '').trim();
    const productReady = Boolean(text('.name') && text('.title') && /\\d/.test(text('.price')));
    const image = root.querySelector(':scope > .el-image img');
    const imageReady = !{str(expects_image).lower()} || Boolean(
        image && image.complete && image.naturalWidth > 0 && image.naturalHeight > 0
    );
    return productReady && imageReady;
}}
"""


def _stored_capture_is_complete(html_path, json_path) -> bool:
    try:
        html = html_path.read_text(encoding="utf-8", errors="replace")
        payload = json.loads(json_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    if not isinstance(payload, dict):
        return False
    mirror_hash = escape(str(payload.get("content_hash") or ""), quote=True)
    if mirror_hash and f'data-collector-content-hash="{mirror_hash}"' in html:
        return bool(payload.get("content")) and all(
            f'src="{escape(str(url), quote=True)}"' in html for url in payload.get("attachments") or []
        )
    required_patterns = (
        r'class="name"[^>]*>\s*[^<\s]',
        r'class="title"[^>]*>\s*[^<\s]',
        r'class="price"[\s\S]{0,1000}>\s*\$\s*\d',
    )
    if not all(re.search(pattern, html) for pattern in required_patterns):
        return False
    if payload.get("attachments"):
        root_start = html.find('class="product-detail-info"')
        info_start = html.find('class="info box"', root_start)
        image_markup = html[root_start:info_start] if root_start >= 0 and info_start > root_start else ""
        if "<img " not in image_markup or 'class="el-image__inner"' not in image_markup:
            return False
    return True


def _base_url(url: str) -> str:
    parsed = urlsplit(url)
    return urlunsplit((parsed.scheme, parsed.netloc, "", "", "")).rstrip("/")


def _artifact_stem(url: str) -> str:
    return hashlib.sha1(url.encode("utf-8")).hexdigest()[:10]


def _fallback_html(detail: dict) -> str:
    title = escape(str(detail.get("title") or "长安不夜城商品详情"))
    content = escape(str(detail.get("content") or "")).replace("\n", "<br>")
    content_hash = escape(str(detail.get("content_hash") or ""), quote=True)
    images = "".join(f'<img src="{escape(str(url), quote=True)}" style="max-width:100%">' for url in detail.get("attachments") or [])
    return f'<!doctype html><html><head><meta charset="utf-8"><title>{title}</title></head><body><article data-collector-content-hash="{content_hash}"><h1>{title}</h1><p>{content}</p>{images}</article></body></html>'


class ChanganAdapter(SiteAdapter):
    site_name = "changan"
    supports_frontier = True

    def _api_get_once(
        self,
        config: SiteConfig,
        path: str,
        params: dict[str, object] | None = None,
    ) -> dict:
        token, _ = require_site_auth_token(config)
        base_url = _base_url(config.seed_urls[0])
        query = urlencode(params or {})
        url = f"{base_url}{path}{'?' + query if query else ''}"
        curl = shutil.which("curl")
        if not curl:
            raise RuntimeError("curl not found in PATH")
        socks_host, socks_port = get_tor_socks_settings()
        command = [
            curl,
            "--socks5-hostname",
            f"{socks_host}:{socks_port}",
            "--silent",
            "--show-error",
            "--location",
            "--max-time",
            str(config.fetch_timeout_seconds),
            "--header",
            "Accept: application/json",
            "--header",
            f"Authorization: Bearer {token}",
            "--header",
            f"Referer: {base_url}/#/home",
            "--user-agent",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/126 Safari/537.36",
            url,
        ]
        result = subprocess.run(command, capture_output=True, check=False)
        if result.returncode != 0:
            error = result.stderr.decode("utf-8", errors="replace").strip() or "unknown curl error"
            raise RuntimeError(f"changan API request failed: {error}")
        body = result.stdout.decode("utf-8", errors="replace")
        try:
            payload = json.loads(body)
        except json.JSONDecodeError as exc:
            raise RuntimeError("changan API returned invalid JSON") from exc
        code = int(payload.get("code") or 0)
        if code in AUTH_ERROR_CODES:
            message = str(payload.get("msg") or "长安不夜城登录会话已失效")
            mark_site_auth_invalid(config, message)
            raise SiteAuthenticationRequired(str(config.extras.get("auth_platform") or "changan"), message)
        if code != 2000:
            raise RuntimeError(f"changan API error {code}: {payload.get('msg') or 'unknown error'}")
        return payload

    def _api_get(
        self,
        config: SiteConfig,
        path: str,
        params: dict[str, object] | None = None,
    ) -> dict:
        try:
            return self._api_get_once(config, path, params)
        except SiteAuthenticationRequired as exc:
            if recover_changan_session(config, str(exc)):
                return self._api_get_once(config, path, params)
            raise

    def collect_seed(self, config: SiteConfig, run_ctx: RunContext) -> SeedResult:
        base_url = _base_url(config.seed_urls[0])
        page_size = max(1, config.max_topics_per_run)

        def fetch_page(source_url: str, page: int, collected_at: str):
            params = {"cid": 0, "page_num": page, "page_size": page_size, "order": "", "order_by": ""}
            raw = self._api_get(config, "/api/category/goods", params)
            data = raw.get("data") if isinstance(raw.get("data"), dict) else raw
            goods = data.get("goods") if isinstance(data.get("goods"), list) else data.get("list")
            if not isinstance(goods, list):
                raise RuntimeError("changan API did not return a goods list")
            section = parse_changan_list(
                raw, base_url=base_url, collected_at_utc=collected_at,
                max_topics=len(goods), excluded_categories=config.extras.get("excluded_categories"),
            )
            stored_raw = dict(raw)
            stored_data = dict(data)
            stored_data.pop("list", None)
            stored_data["goods"] = [topic["raw"] for topic in section["topics"]]
            stored_data["source_total"] = section["source_total"]
            if isinstance(raw.get("data"), dict):
                stored_raw["data"] = stored_data
            else:
                stored_raw = stored_data
            identifiers = sorted(str(item.get("id") or item.get("gid") or item.get("goods_id") or "") for item in goods if isinstance(item, dict))
            signature = hashlib.sha256("\n".join(identifiers).encode("utf-8")).hexdigest()
            if not goods and page == 1 and (section["source_total"] or 0) > 0:
                raise RuntimeError("changan API returned an empty first page with a positive total")
            more = bool(goods)
            if section["source_total"] is not None:
                actual_page_size = int(data.get("page_size") or data.get("pageSize") or len(goods) or page_size)
                more = more and page * actual_page_size < section["source_total"]
            url = f"{base_url}/api/category/goods?{urlencode(params)}"
            return section, json.dumps(stored_raw, ensure_ascii=False, indent=2), more, signature, url

        return collect_paginated_seed(self.site_name, config, fetch_page, plan_details=self.plan_details)

    def plan_details(self, seed_result: SeedResult, config: SiteConfig) -> list[DetailTask]:
        tasks: list[DetailTask] = []
        section = seed_result.payload["sections"][0]
        with get_db_connection() as connection:
            for topic in section["topics"]:
                topic_url = str(topic["full_url"])
                topic_snapshot = get_forum_topic_snapshot(connection, self.site_name, SECTION, topic_url)
                detail_snapshot = get_forum_detail_snapshot(connection, self.site_name, SECTION, topic_url)
                stem = _artifact_stem(topic_url)
                detail_dir = config.output_dir / SECTION / "details"
                artifacts_ready = all(
                    (detail_dir / f"{stem}.{suffix}").exists()
                    for suffix in ("html", "json", "png")
                )
                if artifacts_ready:
                    artifacts_ready = _stored_capture_is_complete(
                        detail_dir / f"{stem}.html",
                        detail_dir / f"{stem}.json",
                    )
                unchanged = topic_snapshot is not None and topic_snapshot["content_hash"] == topic["content_hash"]
                if unchanged and detail_snapshot is not None and artifacts_ready:
                    continue
                tasks.append(
                    DetailTask(
                        site_name=self.site_name,
                        target_url=topic_url,
                        metadata={
                            "section": SECTION,
                            "artifact_stem": stem,
                            "goods_id": topic["goods_id"],
                            "title": topic["title"],
                            "source_version": topic["content_hash"],
                            "discovery_lane": topic.get("discovery_lane", "recent"),
                            "frontier_fetched_version": topic["content_hash"] if unchanged and detail_snapshot is not None else "",
                            "frontier_artifacts_complete": artifacts_ready,
                        },
                    )
                )
        return tasks

    def collect_detail(
        self,
        detail_task: DetailTask,
        config: SiteConfig,
        run_ctx: RunContext,
    ) -> DetailResult | None:
        restored = restore_detail_artifacts(detail_task, config, fallback_html=_fallback_html)
        if restored is not None:
            return restored
        raw = self._api_get(config, "/api/goods/detail", {"gid": detail_task.metadata["goods_id"]})
        detail = parse_changan_detail(
            raw,
            detail_url=detail_task.target_url,
            collected_at_utc=utc_now_iso(),
        )
        raw_html = _fallback_html(detail)
        screenshot_png = None
        _, storage_state_path = require_site_auth_token(config)
        try:
            raw_html, screenshot_png = fetch_page_artifacts_with_browser(
                url=detail_task.target_url,
                wait_seconds=config.render_wait_seconds,
                timeout_seconds=config.fetch_timeout_seconds,
                proxy_server=browser_proxy_server_for_url(detail_task.target_url),
                screenshot_selectors=(".product-detail-info",),
                hide_selectors=("header", ".header", ".sidebar", ".nav"),
                storage_state_path=storage_state_path,
                capture_ready_script=_capture_ready_script(bool(detail.get("attachments"))),
            )
        except Exception as exc:
            print(f"[changan] warning: detail screenshot failed for {detail_task.target_url}: {exc}")
        return DetailResult(
            site_name=self.site_name,
            target_url=detail_task.target_url,
            payload=detail,
            raw_html=raw_html,
            screenshot_png=screenshot_png,
            metadata=detail_task.metadata,
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
            config.output_dir.mkdir(parents=True, exist_ok=True)
            dump_json(config.output_dir / "latest.json", seed_result.payload)
            dump_text(config.output_dir / "latest.raw.json", seed_result.raw_html_by_url[config.seed_urls[0]])
            with get_db_connection() as seed_connection:
                for section in seed_result.payload["sections"]:
                    for topic in section["topics"]:
                        upsert_forum_topic(
                            seed_connection,
                            site_name=self.site_name,
                            section=SECTION,
                            title=topic["title"],
                            url=topic["full_url"],
                            author=topic.get("author", ""),
                            replies="",
                            views=topic.get("views", ""),
                            published_at=topic.get("published_at", ""),
                            last_reply_at="",
                            content_hash=topic["content_hash"],
                            collected_at_utc=section["collected_at_utc"],
                        )
                seed_connection.commit()

        if detail_results:
            detail_dir = config.output_dir / SECTION / "details"
            detail_dir.mkdir(parents=True, exist_ok=True)
            with (nullcontext(connection) if connection is not None else get_db_connection()) as detail_connection:
                for result in detail_results:
                    stem = str(result.metadata.get("artifact_stem") or _artifact_stem(result.target_url))
                    if result.raw_html is not None:
                        dump_text(detail_dir / f"{stem}.html", result.raw_html)
                    if result.screenshot_png is not None:
                        (detail_dir / f"{stem}.png").write_bytes(result.screenshot_png)
                    dump_json(detail_dir / f"{stem}.json", result.payload)
                    upsert_forum_detail(
                        detail_connection,
                        site_name=self.site_name,
                        section=SECTION,
                        topic_url=result.target_url,
                        content=result.payload.get("content", ""),
                        authors=result.payload.get("author", ""),
                        timestamps=result.payload.get("timestamp", ""),
                        published_at_utc=result.payload.get("published_at_utc", ""),
                        attachments=", ".join(result.payload.get("attachments", [])),
                        victims=result.payload.get("victims", []),
                        attackers=result.payload.get("attackers", []),
                        content_hash=result.payload["content_hash"],
                        collected_at_utc=result.payload.get("collected_at_utc", ""),
                    )
                if connection is None:
                    detail_connection.commit()
