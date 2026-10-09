from __future__ import annotations

import atexit
import json
import os
from pathlib import Path
from threading import Lock, current_thread
import traceback
import time
from dataclasses import dataclass
from urllib.parse import urlparse


@dataclass(frozen=True)
class BrowserProxyConfig:
    server: str | None = None
    engine: str = "firefox"


_CAPTURE_READY_SCRIPT = r"""
() => {
    const isVisible = (element) => {
        const style = window.getComputedStyle(element);
        const rect = element.getBoundingClientRect();
        return style.display !== 'none' && style.visibility !== 'hidden' &&
            Number(style.opacity || 1) > 0 && rect.width > 0 && rect.height > 0;
    };
    const loadingText = /^(loading(?:[,.\u2026\s]+please wait)?|please wait)[.!\u2026]*$/i;
    const hasVisibleLoadingState = Array.from(document.body?.querySelectorAll('*') || []).some((element) => {
        if (!isVisible(element)) return false;
        const text = String(element.textContent || '').replace(/\s+/g, ' ').trim();
        return text.length <= 80 && loadingText.test(text);
    });
    const hasPendingImage = Array.from(document.images || []).some(
        (image) => isVisible(image) && Boolean(image.currentSrc || image.src) && !image.complete
    );
    return document.readyState !== 'loading' && !hasVisibleLoadingState && !hasPendingImage;
}
"""


def _cookie_rows(cookie_header: str | None, url: str) -> list[dict[str, object]]:
    if not cookie_header:
        return []
    parsed = urlparse(url)
    if not parsed.hostname:
        return []
    rows: list[dict[str, object]] = []
    for item in str(cookie_header).split(";"):
        name, separator, value = item.strip().partition("=")
        if not separator or not name:
            continue
        rows.append(
            {
                "name": name,
                "value": value,
                "domain": parsed.hostname,
                "path": "/",
                "secure": parsed.scheme.lower() == "https",
            }
        )
    return rows


class BrowserClient:
    def __init__(self, proxy: BrowserProxyConfig) -> None:
        self._proxy = proxy
        self._playwright_context = None
        self._playwright = None
        self._browser = None
        self._created_monotonic = 0.0
        self._task_count = 0

    def _open(self) -> None:
        from playwright.sync_api import sync_playwright

        if self._proxy.engine not in {"chromium", "firefox"}:
            raise ValueError(f"unsupported browser engine: {self._proxy.engine}")
        self._playwright_context = sync_playwright()
        try:
            self._playwright = self._playwright_context.start()
            launch_kwargs = {
                "headless": True,
            }
            if self._proxy.engine == "chromium":
                launch_kwargs["args"] = ["--disable-blink-features=AutomationControlled"]
            if self._proxy.server:
                launch_kwargs["proxy"] = {"server": self._proxy.server}
            browser_type = getattr(self._playwright, self._proxy.engine)
            self._browser = browser_type.launch(**launch_kwargs)
            self._created_monotonic = time.monotonic()
            self._task_count = 0
        except Exception:
            try:
                self.close()
            except Exception:
                pass
            raise

    def _should_rotate(self) -> bool:
        if self._browser is None:
            return True
        if self._task_count >= 10:
            return True
        return (time.monotonic() - self._created_monotonic) >= 15 * 60

    def _ensure_browser(self) -> None:
        if self._should_rotate():
            self.close()
            self._open()

    def fetch_page_artifacts(
        self,
        url: str,
        wait_seconds: int,
        timeout_seconds: int,
        capture_screenshot: bool = True,
        screenshot_selector: str | None = None,
        screenshot_selectors: tuple[str, ...] = (),
        hide_selectors: tuple[str, ...] = (),
        screenshot_styles: str = "",
        storage_state_path: str | None = None,
        persist_storage_state: bool = False,
        capture_ready_script: str = "",
        cookie_header: str | None = None,
    ) -> tuple[str, bytes]:
        from playwright.sync_api import TimeoutError as PlaywrightTimeoutError

        self._ensure_browser()
        assert self._browser is not None
        storage_path = Path(storage_state_path).expanduser().resolve() if storage_state_path else None
        if self._proxy.engine == "chromium":
            browser_version = str(getattr(self._browser, "version", "122.0.0.0"))
            user_agent = (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                f"AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{browser_version} Safari/537.36"
            )
        else:
            user_agent = (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) "
                "Gecko/20100101 Firefox/123.0"
            )
        context_kwargs = {
            "user_agent": user_agent,
            "viewport": {"width": 1440, "height": 960},
            "locale": "en-US",
        }
        if storage_path is not None and storage_path.exists():
            context_kwargs["storage_state"] = str(storage_path)
        try:
            context = self._browser.new_context(**context_kwargs)
        except Exception:
            if "storage_state" not in context_kwargs:
                raise
            context_kwargs.pop("storage_state", None)
            context = self._browser.new_context(**context_kwargs)
        if self._proxy.engine == "chromium":
            context.add_init_script(
                "Object.defineProperty(navigator, 'webdriver', {get: () => undefined});"
            )
        cookie_rows = _cookie_rows(cookie_header, url)
        if cookie_rows:
            context.add_cookies(cookie_rows)
        page = context.new_page()
        selector_timeout_ms = min(timeout_seconds * 1000, 10_000)
        try:
            # Onion sites commonly keep polling or streaming connections open,
            # so waiting for networkidle adds a full timeout to otherwise loaded
            # pages. The configured render wait and selectors below handle the
            # dynamic content after DOM readiness.
            page.goto(url, wait_until="domcontentloaded", timeout=timeout_seconds * 1000)
            page.wait_for_timeout(wait_seconds * 1000)
            _clear_browser_check_interstitial(page, timeout_ms=timeout_seconds * 1000)
            if hide_selectors:
                selector_rules = ", ".join(hide_selectors)
                page.add_style_tag(content=f"{selector_rules} {{ display: none !important; }}")
                page.wait_for_timeout(500)
            if screenshot_styles:
                page.add_style_tag(content=screenshot_styles)
                page.wait_for_timeout(500)
            if not capture_screenshot:
                html = _read_page_content(page)
                self._task_count += 1
                return html, b""
            capture_timeout_ms = min(timeout_seconds * 1000, 30_000) if capture_ready_script else selector_timeout_ms
            _wait_for_capture_ready(
                page,
                timeout_ms=capture_timeout_ms,
                capture_ready_script=capture_ready_script,
            )
            screenshot_png = None
            if screenshot_selectors:
                try:
                    clip_boxes = []
                    for selector in screenshot_selectors:
                        page.wait_for_selector(selector, timeout=selector_timeout_ms)
                        locator = page.locator(selector).first
                        locator.scroll_into_view_if_needed(timeout=selector_timeout_ms)
                        box = locator.bounding_box()
                        if box is not None:
                            clip_boxes.append(box)
                    if clip_boxes:
                        min_x = min(box["x"] for box in clip_boxes)
                        min_y = min(box["y"] for box in clip_boxes)
                        max_x = max(box["x"] + box["width"] for box in clip_boxes)
                        max_y = max(box["y"] + box["height"] for box in clip_boxes)
                        screenshot_png = page.screenshot(
                            type="png",
                            timeout=selector_timeout_ms,
                            animations="disabled",
                            clip={
                                "x": min_x,
                                "y": min_y,
                                "width": max_x - min_x,
                                "height": max_y - min_y,
                            },
                        )
                except PlaywrightTimeoutError:
                    screenshot_png = None
            elif screenshot_selector:
                try:
                    page.wait_for_selector(screenshot_selector, timeout=selector_timeout_ms)
                    locator = page.locator(screenshot_selector).first
                    locator.scroll_into_view_if_needed(timeout=selector_timeout_ms)
                    screenshot_png = locator.screenshot(
                        type="png",
                        timeout=selector_timeout_ms,
                        animations="disabled",
                    )
                except PlaywrightTimeoutError:
                    screenshot_png = None
            if screenshot_png is None:
                screenshot_png = page.screenshot(
                    type="png",
                    full_page=True,
                    timeout=selector_timeout_ms,
                    animations="disabled",
                )
            # Capture HTML after the page-specific selectors have had a chance to
            # appear. Some forum pages finish rendering well after the initial
            # DOMContentLoaded/networkidle checkpoint, which made us persist a
            # head-only document while the screenshot already contained the post.
            html = _read_page_content(page)
            self._task_count += 1
            return html, screenshot_png
        finally:
            if storage_path is not None and persist_storage_state:
                try:
                    _persist_browser_storage_state(context, storage_path)
                except Exception:
                    pass
            context.close()

    def screenshot_html_content(
        self,
        html: str,
        base_url: str,
        wait_seconds: int,
        timeout_seconds: int,
        screenshot_selector: str | None = None,
        screenshot_selectors: tuple[str, ...] = (),
        hide_selectors: tuple[str, ...] = (),
        screenshot_styles: str = "",
    ) -> bytes:
        from playwright.sync_api import TimeoutError as PlaywrightTimeoutError

        self._ensure_browser()
        assert self._browser is not None
        context = self._browser.new_context(
            user_agent=(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) "
                "Gecko/20100101 Firefox/123.0"
            ),
            viewport={"width": 1440, "height": 960},
            # The supplied HTML is already the rendered evidence document.
            # Re-running its application bundle can replace that content with
            # a loading screen while the app hydrates.
            java_script_enabled=False,
        )
        page = context.new_page()
        selector_timeout_ms = min(timeout_seconds * 1000, 10_000)
        try:
            rendered_html = _inject_base_href(html, base_url)
            capture_styles = []
            if hide_selectors:
                selector_rules = ", ".join(hide_selectors)
                capture_styles.append(f"{selector_rules} {{ display: none !important; }}")
            if screenshot_styles:
                capture_styles.append(screenshot_styles)
            rendered_html = _inject_capture_styles(rendered_html, "\n".join(capture_styles))
            page.set_content(rendered_html, wait_until="domcontentloaded", timeout=timeout_seconds * 1000)
            page.wait_for_timeout(wait_seconds * 1000)
            _clear_browser_check_interstitial(page, timeout_ms=timeout_seconds * 1000)

            _wait_for_capture_ready(page, timeout_ms=selector_timeout_ms)
            screenshot_png = None
            if screenshot_selectors:
                try:
                    clip_boxes = []
                    for selector in screenshot_selectors:
                        page.wait_for_selector(selector, timeout=selector_timeout_ms)
                        locator = page.locator(selector).first
                        locator.scroll_into_view_if_needed(timeout=selector_timeout_ms)
                        box = locator.bounding_box()
                        if box is not None:
                            clip_boxes.append(box)
                    if clip_boxes:
                        min_x = min(box["x"] for box in clip_boxes)
                        min_y = min(box["y"] for box in clip_boxes)
                        max_x = max(box["x"] + box["width"] for box in clip_boxes)
                        max_y = max(box["y"] + box["height"] for box in clip_boxes)
                        screenshot_png = page.screenshot(
                            type="png",
                            timeout=selector_timeout_ms,
                            animations="disabled",
                            clip={
                                "x": min_x,
                                "y": min_y,
                                "width": max_x - min_x,
                                "height": max_y - min_y,
                            },
                        )
                except PlaywrightTimeoutError:
                    screenshot_png = None
            elif screenshot_selector:
                try:
                    page.wait_for_selector(screenshot_selector, timeout=selector_timeout_ms)
                    locator = page.locator(screenshot_selector).first
                    locator.scroll_into_view_if_needed(timeout=selector_timeout_ms)
                    screenshot_png = locator.screenshot(
                        type="png",
                        timeout=selector_timeout_ms,
                        animations="disabled",
                    )
                except PlaywrightTimeoutError:
                    screenshot_png = None
            if screenshot_png is None:
                screenshot_png = page.screenshot(
                    type="png",
                    full_page=True,
                    timeout=selector_timeout_ms,
                    animations="disabled",
                )
            self._task_count += 1
            return screenshot_png
        finally:
            context.close()

    def close(self) -> None:
        browser, playwright, context = self._browser, self._playwright, self._playwright_context
        self._browser = self._playwright = self._playwright_context = None
        try:
            if browser is not None:
                browser.close()
        finally:
            if playwright is not None:
                playwright.stop()
            elif context is not None:
                context.__exit__()


_GLOBAL_CLIENTS: dict[object, tuple[BrowserProxyConfig, BrowserClient]] = {}
_GLOBAL_CLIENT_LOCK = Lock()

_BROWSER_CHECK_MARKERS = (
    "checking your browser",
    "cf-browser-verification",
    "security verification",
    "verify you are human",
    "please move your mouse or press a key",
    "please wait while we verify",
)


def _persist_browser_storage_state(context, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(
        f".{path.name}.{os.getpid()}.{current_thread().ident or 0}.tmp"
    )
    try:
        state = context.storage_state()
        temporary.write_text(json.dumps(state, ensure_ascii=False), encoding="utf-8")
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def _read_page_content(page, *, attempts: int = 6, wait_ms: int = 250) -> str:
    last_error: Exception | None = None
    for _ in range(attempts):
        try:
            return page.content()
        except Exception as exc:
            last_error = exc
            page.wait_for_timeout(wait_ms)
    if last_error is not None:
        raise last_error
    return ""


def _wait_for_capture_ready(page, *, timeout_ms: int, capture_ready_script: str = "") -> None:
    from playwright.sync_api import TimeoutError as PlaywrightTimeoutError

    try:
        page.wait_for_function(_CAPTURE_READY_SCRIPT, timeout=max(timeout_ms, 1_000))
        if capture_ready_script:
            page.wait_for_function(capture_ready_script, timeout=max(timeout_ms, 1_000))
    except PlaywrightTimeoutError as exc:
        raise RuntimeError("page remained in a loading state; screenshot skipped") from exc
    page.wait_for_timeout(500)


def _inject_base_href(html: str, base_url: str) -> str:
    base_tag = f'<base href="{base_url}">'
    if "<head>" in html:
        return html.replace("<head>", f"<head>{base_tag}", 1)
    if "<html>" in html:
        return html.replace("<html>", f"<html><head>{base_tag}</head>", 1)
    return f"<head>{base_tag}</head>{html}"


def _inject_capture_styles(html: str, styles: str) -> str:
    if not styles:
        return html
    style_tag = f"<style>{styles}</style>"
    if "</head>" in html:
        return html.replace("</head>", f"{style_tag}</head>", 1)
    return f"{style_tag}{html}"


def _looks_like_browser_check_page(html: str | None) -> bool:
    content = str(html or "").lower()
    return any(marker in content for marker in _BROWSER_CHECK_MARKERS)


def _clear_browser_check_interstitial(
    page,
    *,
    timeout_ms: int,
    settle_wait_ms: int = 750,
) -> str:
    html = _read_page_content(page)
    if not _looks_like_browser_check_page(html):
        return html

    deadline = time.monotonic() + max(timeout_ms, settle_wait_ms) / 1000
    viewport = getattr(page, "viewport_size", None) or {"width": 1440, "height": 960}
    center_x = int(viewport.get("width", 1440) * 0.5)
    center_y = int(viewport.get("height", 960) * 0.38)

    while time.monotonic() < deadline:
        try:
            page.mouse.move(center_x, center_y, steps=12)
            page.wait_for_timeout(120)
            page.mouse.click(center_x, center_y, delay=80)
            page.wait_for_timeout(120)
            page.mouse.wheel(0, 420)
            page.wait_for_timeout(120)
        except Exception:
            # Cloudflare/browser-check pages can trigger a navigation mid-action.
            # When that happens, just wait for the next stable DOM snapshot
            # instead of failing the whole fetch.
            page.wait_for_timeout(300)
        for key in ("Tab", "Space"):
            try:
                page.keyboard.press(key)
                page.wait_for_timeout(120)
            except Exception:
                page.wait_for_timeout(300)
            html = _read_page_content(page)
            if not _looks_like_browser_check_page(html):
                page.wait_for_timeout(settle_wait_ms)
                return _read_page_content(page)
        try:
            page.wait_for_load_state("networkidle", timeout=min(1500, timeout_ms))
        except Exception:
            pass
        html = _read_page_content(page)
        if not _looks_like_browser_check_page(html):
            page.wait_for_timeout(settle_wait_ms)
            return _read_page_content(page)
    return html


def _get_or_create_client(requested_proxy: BrowserProxyConfig) -> BrowserClient:
    thread_key = current_thread()
    with _GLOBAL_CLIENT_LOCK:
        existing = _GLOBAL_CLIENTS.get(thread_key)
        if existing is not None:
            existing_proxy, existing_client = existing
            if existing_proxy == requested_proxy:
                return existing_client
            _GLOBAL_CLIENTS.pop(thread_key, None)
        else:
            existing_client = None

    if existing_client is not None:
        existing_client.close()

    client = BrowserClient(proxy=requested_proxy)
    with _GLOBAL_CLIENT_LOCK:
        replaced = _GLOBAL_CLIENTS.get(thread_key)
        _GLOBAL_CLIENTS[thread_key] = (requested_proxy, client)

    if replaced is not None:
        _, replaced_client = replaced
        if replaced_client is not client:
            replaced_client.close()
    return client


def fetch_html_with_browser(
    url: str,
    wait_seconds: int,
    timeout_seconds: int,
    proxy_server: str | None = None,
    browser_engine: str = "firefox",
    storage_state_path: str | None = None,
    persist_storage_state: bool = False,
    cookie_header: str | None = None,
) -> str:
    requested_proxy = BrowserProxyConfig(server=proxy_server, engine=browser_engine)
    client = _get_or_create_client(requested_proxy)
    try:
        html, _ = client.fetch_page_artifacts(
            url=url,
            wait_seconds=wait_seconds,
            timeout_seconds=timeout_seconds,
            capture_screenshot=False,
            storage_state_path=storage_state_path,
            persist_storage_state=persist_storage_state,
            cookie_header=cookie_header,
        )
        return html
    except Exception:
        close_browser_client()
        raise


def fetch_page_artifacts_with_browser(
    url: str,
    wait_seconds: int,
    timeout_seconds: int,
    proxy_server: str | None = None,
    browser_engine: str = "firefox",
    screenshot_selector: str | None = None,
    screenshot_selectors: tuple[str, ...] = (),
    hide_selectors: tuple[str, ...] = (),
    screenshot_styles: str = "",
    storage_state_path: str | None = None,
    persist_storage_state: bool = False,
    capture_ready_script: str = "",
    cookie_header: str | None = None,
) -> tuple[str, bytes]:
    requested_proxy = BrowserProxyConfig(server=proxy_server, engine=browser_engine)
    client = _get_or_create_client(requested_proxy)
    try:
        return client.fetch_page_artifacts(
            url=url,
            wait_seconds=wait_seconds,
            timeout_seconds=timeout_seconds,
            screenshot_selector=screenshot_selector,
            screenshot_selectors=screenshot_selectors,
            hide_selectors=hide_selectors,
            screenshot_styles=screenshot_styles,
            storage_state_path=storage_state_path,
            persist_storage_state=persist_storage_state,
            capture_ready_script=capture_ready_script,
            cookie_header=cookie_header,
        )
    except Exception:
        close_browser_client()
        raise


def screenshot_html_with_browser(
    html: str,
    base_url: str,
    wait_seconds: int,
    timeout_seconds: int,
    proxy_server: str | None = None,
    browser_engine: str = "firefox",
    screenshot_selector: str | None = None,
    screenshot_selectors: tuple[str, ...] = (),
    hide_selectors: tuple[str, ...] = (),
    screenshot_styles: str = "",
) -> bytes:
    requested_proxy = BrowserProxyConfig(server=proxy_server, engine=browser_engine)
    client = _get_or_create_client(requested_proxy)
    try:
        return client.screenshot_html_content(
            html=html,
            base_url=base_url,
            wait_seconds=wait_seconds,
            timeout_seconds=timeout_seconds,
            screenshot_selector=screenshot_selector,
            screenshot_selectors=screenshot_selectors,
            hide_selectors=hide_selectors,
            screenshot_styles=screenshot_styles,
        )
    except Exception:
        close_browser_client()
        raise


def close_browser_client(*, all_threads: bool = False) -> None:
    thread_key = current_thread()
    with _GLOBAL_CLIENT_LOCK:
        if all_threads:
            clients = [client for _, client in _GLOBAL_CLIENTS.values()]
            _GLOBAL_CLIENTS.clear()
        else:
            entry = _GLOBAL_CLIENTS.pop(thread_key, None)
            clients = [entry[1]] if entry is not None else []
    for client in clients:
        try:
            client.close()
        except Exception:
            pass


atexit.register(lambda: close_browser_client(all_threads=True))
