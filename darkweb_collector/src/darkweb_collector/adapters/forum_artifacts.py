from __future__ import annotations

import hashlib
import json

from darkweb_collector.browser_client import screenshot_html_with_browser
from darkweb_collector.collection_errors import CollectionFailure
from darkweb_collector.db import get_db_connection, get_forum_detail_snapshot, get_victim_snapshot
from darkweb_collector.models import DetailResult, DetailTask, SiteConfig
from darkweb_collector.tor_fetch import browser_proxy_server_for_url


def detail_artifacts_complete(directory, stem: str) -> bool:
    if not all((directory / f"{stem}.{suffix}").is_file() for suffix in ("html", "json", "png")):
        return False
    try:
        payload = json.loads((directory / f"{stem}.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    return isinstance(payload, dict) and payload.get("_collector_artifacts_complete") is not False


def restore_detail_artifacts(
    detail_task: DetailTask,
    config: SiteConfig,
    *,
    screenshot_selector: str | None = None,
    screenshot_selectors: tuple[str, ...] = (),
    hide_selectors: tuple[str, ...] = (),
    screenshot_styles: str = "",
    fallback_html=None,
) -> DetailResult | None:
    if not detail_task.metadata.get("frontier_artifact_only"):
        return None
    section = str(detail_task.metadata.get("section") or "")
    stem = str(detail_task.metadata.get("artifact_stem") or hashlib.sha1(detail_task.target_url.encode("utf-8")).hexdigest()[:10])
    directory = config.output_dir / section / "details"
    try:
        payload = json.loads((directory / f"{stem}.json").read_text(encoding="utf-8"))
        if not isinstance(payload, dict) or not str(payload.get("content") or "").strip():
            return None
        with get_db_connection() as connection:
            if section:
                snapshot = get_forum_detail_snapshot(connection, detail_task.site_name, section, detail_task.target_url)
                if snapshot is None or snapshot["content_hash"] != payload.get("content_hash"):
                    return None
            else:
                snapshot = get_victim_snapshot(
                    connection, detail_task.site_name, str(detail_task.metadata["source_url"]),
                    str(detail_task.metadata["name"]), detail_task.metadata.get("domain"),
                    str(detail_task.metadata.get("status", "active")),
                )
                if (
                    snapshot is None or snapshot["last_detail_fetch_status"] != "ok"
                    or snapshot["content_hash"] != detail_task.metadata.get("source_version")
                    or payload.get("source_url") != detail_task.target_url
                ):
                    return None
        html = (directory / f"{stem}.html").read_text(encoding="utf-8")
        if fallback_html is not None:
            html = fallback_html(payload)
        if not html.strip():
            return None
    except (OSError, ValueError, TypeError, KeyError):
        return None
    try:
        screenshot = screenshot_html_with_browser(
            html, detail_task.target_url,
            wait_seconds=config.render_wait_seconds, timeout_seconds=config.fetch_timeout_seconds,
            proxy_server=browser_proxy_server_for_url(detail_task.target_url),
            browser_engine=str(config.extras.get("browser_engine") or "firefox"),
            screenshot_selector=screenshot_selector,
            screenshot_selectors=screenshot_selectors, hide_selectors=hide_selectors,
            screenshot_styles=screenshot_styles,
        )
        if not screenshot:
            raise CollectionFailure("artifact", "stored detail evidence capture produced no image")
    except Exception as exc:
        raise CollectionFailure("artifact", "stored detail evidence capture failed") from exc
    return DetailResult(
        site_name=detail_task.site_name, target_url=detail_task.target_url, payload=payload,
        raw_html=html, screenshot_png=screenshot, metadata=detail_task.metadata,
    )
