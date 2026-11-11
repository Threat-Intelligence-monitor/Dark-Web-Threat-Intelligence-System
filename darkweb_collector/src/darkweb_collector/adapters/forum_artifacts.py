from __future__ import annotations

import hashlib
import json

from darkweb_collector.browser_client import screenshot_html_with_browser
from darkweb_collector.collection_errors import CollectionFailure, has_detail_body, raise_if_error_page, safe_failure_text
from darkweb_collector.db import get_db_connection, get_forum_detail_snapshot, get_victim_snapshot
from darkweb_collector.detail_artifacts import ARTIFACTS_KEY, detail_artifact_paths
from darkweb_collector.models import DetailResult, DetailTask, SiteConfig
from darkweb_collector.source_sessions import browser_session_options, http_session_options
from darkweb_collector.tor_fetch import browser_proxy_server_for_url


# Prefer the actual body over a wider MyBB content column containing author UI.
FORUM_CAPTURE_CONTENT_SELECTOR = ".post_body, .post_content:not(:has(.post_body)), .messageContent:not(:has(.post_body))"


def detail_artifacts_complete(directory, stem: str, raw_payload=None, *, root=None, site_name="", target_url="", forum=False, source_version="") -> bool:
    try:
        stored = raw_payload if isinstance(raw_payload, dict) else json.loads(raw_payload or "{}")
    except (TypeError, ValueError):
        return False
    if not isinstance(stored, dict):
        return False
    manifest = stored.get(ARTIFACTS_KEY)
    if isinstance(manifest, dict) and source_version and manifest.get("source_version") != source_version:
        return False
    if ARTIFACTS_KEY not in stored and stored.get("artifact_stem") not in (None, "", stem):
        return False
    paths = detail_artifact_paths(root or directory, directory, stem, raw_payload,
                                  site_name=site_name, target_url=target_url, forum=forum)
    if not {"html", "json", "png"} <= paths.keys():
        return False
    try:
        payload = json.loads(paths["json"].read_text(encoding="utf-8"))
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
    capture_content_selector: str | None = None,
) -> DetailResult | None:
    if not detail_task.metadata.get("frontier_artifact_only"):
        return None
    section = str(detail_task.metadata.get("section") or "")
    stem = str(detail_task.metadata.get("artifact_stem") or hashlib.sha1(detail_task.target_url.encode("utf-8")).hexdigest()[:10])
    directory = config.output_dir / section / "details"
    try:
        with get_db_connection() as connection:
            version = str(detail_task.metadata.get("source_version") or "")
            frontier = connection.execute("""SELECT fetched_version, claimed_version, lease_token
                FROM crawl_frontier WHERE site_name = ? AND target_url = ?""",
                (detail_task.site_name, detail_task.target_url)).fetchone()
            if not version or frontier is None or frontier["fetched_version"] != version:
                return None
            token = detail_task.metadata.get("frontier_token")
            if token and (frontier["lease_token"] != token or frontier["claimed_version"] != version):
                return None
            if section:
                snapshot = get_forum_detail_snapshot(connection, detail_task.site_name, section, detail_task.target_url)
                stored_payload = (snapshot or {}).get("artifact_payload", (snapshot or {}).get("raw_json"))
            else:
                snapshot = get_victim_snapshot(
                    connection, detail_task.site_name, str(detail_task.metadata["source_url"]),
                    str(detail_task.metadata["name"]), detail_task.metadata.get("domain"),
                    str(detail_task.metadata.get("status", "active")),
                )
                stored_payload = (snapshot or {}).get("artifact_payload", (snapshot or {}).get("detail_raw_json"))
            if snapshot is None:
                return None
            paths = detail_artifact_paths(config.output_dir, directory, stem, stored_payload,
                site_name=detail_task.site_name, target_url=detail_task.target_url, forum=bool(section))
            stored = stored_payload if isinstance(stored_payload, dict) else json.loads(stored_payload or "{}")
            versioned = ARTIFACTS_KEY in stored
            if versioned and stored[ARTIFACTS_KEY].get("source_version") != version:
                return None
            payload_bytes = paths["json"].read_bytes()
            if versioned and hashlib.sha256(payload_bytes).hexdigest() != paths["json"].stem:
                return None
            payload = json.loads(payload_bytes)
            if not isinstance(payload, dict) or not has_detail_body(payload):
                return None
            # Legacy Changan payloads omit source_url; their body is verified in SQL.
            if payload.get("source_url") not in (None, detail_task.target_url):
                return None
            if section:
                if snapshot["content_hash"] != payload.get("content_hash"):
                    return None
                body = connection.execute("SELECT content FROM forum_details WHERE id = ?", (snapshot["id"],)).fetchone()
                if body is None or body[0] != payload.get("content"):
                    return None
            else:
                if (
                    snapshot["last_detail_fetch_status"] != "ok"
                    or snapshot["content_hash"] != detail_task.metadata.get("source_version")
                    or payload.get("source_url") != detail_task.target_url
                ):
                    return None
                if not isinstance(stored, dict) or stored.get("fetch_status") != "ok" or payload.get("fetch_status") != "ok":
                    return None
                if any(stored.get(key) != payload.get(key) for key in ("page_title", "content", "text_excerpt", "outbound_link_count")):
                    return None
        html_bytes = paths["html"].read_bytes()
        if versioned and hashlib.sha256(html_bytes).hexdigest() != paths["html"].stem:
            return None
        html = html_bytes.decode("utf-8")
        if not html.strip():
            return None
    except (OSError, ValueError, TypeError, KeyError):
        return None
    payload = dict(payload)
    payload.pop("_collector_artifact_error", None)
    metadata = dict(detail_task.metadata)
    metadata.pop("artifact_error", None)
    capture_html = html
    screenshot = None
    try:
        if fallback_html is not None:
            capture_html = fallback_html(payload)
        if not str(capture_html or "").strip():
            raise CollectionFailure("artifact", "stored detail evidence document is empty")
        raise_if_error_page(capture_html)
        proxy_server = browser_proxy_server_for_url(detail_task.target_url)
        browser_options = browser_session_options(config, detail_task.target_url, proxy_server)
        http_options = http_session_options(config, detail_task.target_url, proxy_server)
        screenshot = screenshot_html_with_browser(
            capture_html, detail_task.target_url,
            wait_seconds=config.render_wait_seconds, timeout_seconds=config.fetch_timeout_seconds,
            proxy_server=proxy_server,
            browser_engine=browser_options["browser_engine"],
            storage_state_path=browser_options["storage_state_path"],
            cookie_header=browser_options["cookie_header"],
            user_agent=http_options["user_agent"],
            screenshot_selector=screenshot_selector,
            screenshot_selectors=screenshot_selectors, hide_selectors=hide_selectors,
            screenshot_styles=screenshot_styles,
            capture_content_selector=capture_content_selector,
        )
        if not screenshot:
            raise CollectionFailure("artifact", "stored detail evidence capture produced no image")
    except Exception as exc:
        # A verified, already-saved body remains usable when only its evidence
        # cannot be refreshed. The caller persists partial and retries evidence.
        error = safe_failure_text(f"artifact: stored detail evidence capture failed ({type(exc).__name__}): {exc}")
        metadata["artifact_error"] = error
        payload["_collector_artifact_error"] = error
        payload["_collector_artifacts_complete"] = False
        capture_html, screenshot = html, None
    return DetailResult(
        site_name=detail_task.site_name, target_url=detail_task.target_url, payload=payload,
        raw_html=capture_html, screenshot_png=screenshot, metadata=metadata,
    )
