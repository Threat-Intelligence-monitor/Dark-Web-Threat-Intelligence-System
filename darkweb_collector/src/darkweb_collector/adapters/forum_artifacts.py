from __future__ import annotations

import hashlib
import json

from darkweb_collector.browser_client import screenshot_html_with_browser
from darkweb_collector.db import get_db_connection, get_forum_detail_snapshot
from darkweb_collector.models import DetailResult, DetailTask, SiteConfig
from darkweb_collector.tor_fetch import browser_proxy_server_for_url


def restore_detail_artifacts(
    detail_task: DetailTask,
    config: SiteConfig,
    *,
    screenshot_selector: str | None = None,
    screenshot_selectors: tuple[str, ...] = (),
    hide_selectors: tuple[str, ...] = (),
    fallback_html=None,
) -> DetailResult | None:
    if not detail_task.metadata.get("frontier_artifact_only"):
        return None
    section = str(detail_task.metadata["section"])
    stem = str(detail_task.metadata.get("artifact_stem") or hashlib.sha1(detail_task.target_url.encode("utf-8")).hexdigest()[:10])
    directory = config.output_dir / section / "details"
    try:
        payload = json.loads((directory / f"{stem}.json").read_text(encoding="utf-8"))
        if not isinstance(payload, dict) or not payload.get("content_hash"):
            return None
        with get_db_connection() as connection:
            snapshot = get_forum_detail_snapshot(connection, detail_task.site_name, section, detail_task.target_url)
        if snapshot is None or snapshot["content_hash"] != payload["content_hash"]:
            return None
        html = (directory / f"{stem}.html").read_text(encoding="utf-8")
        if fallback_html is not None:
            html = fallback_html(payload)
        if not html.strip():
            return None
    except (OSError, ValueError, TypeError, KeyError):
        return None
    screenshot = screenshot_html_with_browser(
        html, detail_task.target_url,
        wait_seconds=config.render_wait_seconds, timeout_seconds=config.fetch_timeout_seconds,
        proxy_server=browser_proxy_server_for_url(detail_task.target_url),
        browser_engine=str(config.extras.get("browser_engine") or "firefox"),
        screenshot_selector=screenshot_selector,
        screenshot_selectors=screenshot_selectors, hide_selectors=hide_selectors,
    )
    return DetailResult(
        site_name=detail_task.site_name, target_url=detail_task.target_url, payload=payload,
        raw_html=html, screenshot_png=screenshot, metadata=detail_task.metadata,
    )
