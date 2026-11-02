from __future__ import annotations

import atexit
from pathlib import Path
from threading import Lock, current_thread
import traceback
import time
from dataclasses import dataclass
from typing import Callable
from urllib.parse import urlparse

from darkweb_collector.collection_errors import CollectionFailure, raise_if_error_page, request_attempt
from darkweb_collector.tor_fetch import raise_for_http_status
from darkweb_collector.source_sessions import read_browser_session, persist_browser_session, same_source


@dataclass(frozen=True)
class BrowserProxyConfig:
    server: str | None = None
    engine: str = "firefox"


_CAPTURE_READY_SCRIPT = r"""
(waitForImages = true) => {
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
    const visibleImages = Array.from(document.images || []).filter((image) => {
        const style = window.getComputedStyle(image);
        return image.getClientRects().length > 0 && style.display !== 'none' &&
            style.visibility !== 'hidden' && Number(style.opacity || 1) > 0 &&
            Boolean(image.currentSrc || image.src);
    });
    if (waitForImages && visibleImages.some(image => image.complete && image.naturalWidth === 0))
        throw new Error('visible source image failed to load; screenshot skipped');
    const hasPendingImage = visibleImages.some(image => !image.complete);
    const hasContent = document.body && isVisible(document.body) &&
        (document.body.innerText.trim().length > 0 || Array.from(document.images || []).some(isVisible));
    return document.readyState !== 'loading' && hasContent &&
        !hasVisibleLoadingState && (!waitForImages ||
            ((!document.fonts || document.fonts.status !== 'loading') && !hasPendingImage));
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


def _remaining_timeout_ms(deadline: float, maximum: int) -> int:
    remaining = int((deadline - time.monotonic()) * 1000)
    if remaining <= 0:
        raise TimeoutError("browser capture deadline was exhausted")
    return min(remaining, maximum)


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

    def _default_user_agent(self) -> str:
        version = str(self._browser.version)
        if self._proxy.engine == "chromium":
            return ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                    f"(KHTML, like Gecko) Chrome/{version} Safari/537.36")
        return f"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:{version}) Gecko/20100101 Firefox/{version}"

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
        user_agent: str | None = None,
        validate_html: Callable[[str], bool] | None = None,
    ) -> tuple[str, bytes | None]:
        from playwright.sync_api import TimeoutError as PlaywrightTimeoutError

        try:
            self._ensure_browser()
        except Exception as exc:
            raise CollectionFailure("infrastructure", "browser runtime could not be started", scope="site") from exc
        assert self._browser is not None
        storage_path = Path(storage_state_path).expanduser().resolve() if storage_state_path else None
        stored_state, session_revision, saved_agent = None, "", None
        if storage_path is not None:
            stored_state, session_revision, saved_agent = read_browser_session(
                storage_path, url, self._proxy.server, self._proxy.engine,
            )
        user_agent = user_agent or saved_agent or self._default_user_agent()
        context_kwargs = {
            "user_agent": user_agent,
            "viewport": {"width": 1440, "height": 960},
            "locale": "en-US",
        }
        cookie_rows = _cookie_rows(cookie_header, url)
        if stored_state is not None:
            explicit_names = {cookie["name"] for cookie in cookie_rows}
            stored_state["cookies"] = [cookie for cookie in stored_state["cookies"] if cookie["name"] not in explicit_names]
            context_kwargs["storage_state"] = stored_state
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
        if cookie_rows:
            context.add_cookies(cookie_rows)
        page = context.new_page()
        main_response = None

        def remember_main_response(received):
            nonlocal main_response
            if received.request.is_navigation_request() and received.frame == page.main_frame:
                main_response = received

        page.on("response", remember_main_response)
        selector_timeout_ms = min(timeout_seconds * 1000, 10_000)
        deadline = time.monotonic() + timeout_seconds
        session_eligible = False
        validated_html = None

        def verified_document(*, validate_content=True):
            nonlocal validated_html
            if not same_source(url, page.url):
                raise CollectionFailure("source_moved", "browser navigation left the configured source origin", scope="site")
            if main_response is None or not same_source(main_response.url, page.url):
                raise CollectionFailure("network", "browser final document response is unconfirmed")
            html = _read_page_content(page)
            raise_if_error_page(html)
            raise_for_http_status(main_response.status)
            if not 200 <= main_response.status < 300:
                raise CollectionFailure("network", "browser final document did not return a successful status")
            if validate_content and validate_html is not None and html != validated_html:
                if not validate_html(html):
                    raise CollectionFailure("parse", "browser document did not contain the expected source content")
            if validate_content:
                validated_html = html
            return html

        def finish_capture(screenshot):
            nonlocal session_eligible
            try:
                return verified_document(), screenshot
            except Exception:
                session_eligible = False
                if validated_html is None:
                    raise
                return validated_html, None

        try:
            # Onion sites commonly keep polling or streaming connections open,
            # so waiting for networkidle adds a full timeout to otherwise loaded
            # pages. The configured render wait and selectors below handle the
            # dynamic content after DOM readiness.
            request_attempt()
            try:
                response = page.goto(url, wait_until="domcontentloaded", timeout=timeout_seconds * 1000)
            except PlaywrightTimeoutError as exc:
                raise CollectionFailure("timeout", "browser document navigation timed out") from exc
            except Exception as exc:
                raise CollectionFailure("network", "browser document navigation failed") from exc
            status = getattr(response, "status", 0)
            if status in {401, 429}:
                raise_for_http_status(status)
            page.wait_for_timeout(max(0, min(wait_seconds, deadline - time.monotonic())) * 1000)
            _clear_browser_check_interstitial(page, timeout_ms=max(0, int((deadline - time.monotonic()) * 1000)))
            verified_document(validate_content=False)
            # Validate the source only after ordinary asynchronous content is
            # ready. A loading shell is not evidence of a parser regression.
            try:
                _wait_for_capture_ready(page, timeout_ms=max(1, int((deadline - time.monotonic()) * 1000)), wait_for_images=False)
            except Exception as exc:
                raise CollectionFailure("timeout", "browser content did not become ready within the request deadline") from exc
            verified_document()
            session_eligible = True
            try:
                if hide_selectors:
                    selector_rules = ", ".join(hide_selectors)
                    page.add_style_tag(content=f"{selector_rules} {{ display: none !important; }}")
                    page.wait_for_timeout(_remaining_timeout_ms(deadline, 500))
                if screenshot_styles:
                    page.add_style_tag(content=screenshot_styles)
                    page.wait_for_timeout(_remaining_timeout_ms(deadline, 500))
            except Exception:
                session_eligible = False
                self._task_count += 1
                return finish_capture(None)
            if not capture_screenshot:
                self._task_count += 1
                return finish_capture(b"")
            capture_timeout_ms = max(1, min(30_000 if capture_ready_script else selector_timeout_ms, int((deadline - time.monotonic()) * 1000)))
            try:
                _wait_for_capture_ready(
                    page,
                    timeout_ms=capture_timeout_ms,
                    capture_ready_script=capture_ready_script,
                )
            except Exception:
                session_eligible = False
                self._task_count += 1
                return finish_capture(None)
            screenshot_png = None
            if screenshot_selectors:
                try:
                    clip_boxes = []
                    for selector in screenshot_selectors:
                        locator = page.locator(selector).first
                        if not locator.count() or not locator.is_visible():
                            continue
                        locator.scroll_into_view_if_needed(timeout=_remaining_timeout_ms(deadline, selector_timeout_ms))
                        box = locator.bounding_box(timeout=_remaining_timeout_ms(deadline, selector_timeout_ms))
                        if box is not None:
                            clip_boxes.append(box)
                    if clip_boxes:
                        min_x = min(box["x"] for box in clip_boxes)
                        min_y = min(box["y"] for box in clip_boxes)
                        max_x = max(box["x"] + box["width"] for box in clip_boxes)
                        max_y = max(box["y"] + box["height"] for box in clip_boxes)
                        screenshot_png = page.screenshot(
                            type="png",
                            timeout=_remaining_timeout_ms(deadline, selector_timeout_ms),
                            animations="disabled",
                            clip={
                                "x": min_x,
                                "y": min_y,
                                "width": max_x - min_x,
                                "height": max_y - min_y,
                            },
                        )
                except Exception:
                    session_eligible = False
                    screenshot_png = None
            elif screenshot_selector:
                try:
                    locator = page.locator(screenshot_selector).first
                    if locator.count() and locator.is_visible():
                        locator.scroll_into_view_if_needed(timeout=_remaining_timeout_ms(deadline, selector_timeout_ms))
                        screenshot_png = locator.screenshot(
                            type="png",
                            timeout=_remaining_timeout_ms(deadline, selector_timeout_ms),
                            animations="disabled",
                        )
                except Exception:
                    session_eligible = False
                    screenshot_png = None
            if screenshot_png is None:
                try:
                    screenshot_png = page.screenshot(
                        type="png",
                        full_page=True,
                        timeout=_remaining_timeout_ms(deadline, selector_timeout_ms),
                        animations="disabled",
                    )
                except Exception:
                    session_eligible = False
                    screenshot_png = None
            # Capture HTML after the page-specific selectors have had a chance to
            # appear. Some forum pages finish rendering well after the initial
            # DOMContentLoaded/networkidle checkpoint, which made us persist a
            # head-only document while the screenshot already contained the post.
            self._task_count += 1
            return finish_capture(screenshot_png)
        finally:
            if storage_path is not None and persist_storage_state and session_eligible:
                try:
                    verified_document()
                    persist_browser_session(
                        context.storage_state(), storage_path, url=page.url,
                        proxy_server=self._proxy.server, user_agent=user_agent,
                        engine=self._proxy.engine, expected_revision=session_revision,
                    )
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
        storage_state_path: str | None = None,
        cookie_header: str | None = None,
        user_agent: str | None = None,
    ) -> bytes:
        from playwright.sync_api import TimeoutError as PlaywrightTimeoutError

        self._ensure_browser()
        assert self._browser is not None
        stored_state, saved_agent = None, None
        if storage_state_path:
            stored_state, _, saved_agent = read_browser_session(
                Path(storage_state_path).expanduser().resolve(), base_url, self._proxy.server, self._proxy.engine,
            )
        cookie_rows = _cookie_rows(cookie_header, base_url)
        if stored_state is not None:
            explicit_names = {cookie["name"] for cookie in cookie_rows}
            stored_state["cookies"] = [cookie for cookie in stored_state["cookies"] if cookie["name"] not in explicit_names]
        context = self._browser.new_context(
            user_agent=user_agent or saved_agent or self._default_user_agent(),
            viewport={"width": 1440, "height": 960},
            # The supplied HTML is already the rendered evidence document.
            # Re-running its application bundle can replace that content with
            # a loading screen while the app hydrates.
            java_script_enabled=False,
            storage_state=stored_state,
        )
        if cookie_rows:
            context.add_cookies(cookie_rows)
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
            raise_if_error_page(html)
            # Fulfil only the main document locally so same-origin image cookies
            # keep their browser scope without re-requesting the saved body.
            def render_document(route):
                if route.request.is_navigation_request() and route.request.frame == page.main_frame:
                    if same_source(base_url, route.request.url):
                        route.fulfill(status=200, content_type="text/html", body=rendered_html)
                    else:
                        route.abort()
                else:
                    route.continue_()
            page.route("**/*", render_document)
            deadline = time.monotonic() + timeout_seconds
            page.goto(base_url, wait_until="domcontentloaded", timeout=timeout_seconds * 1000)
            _wait_for_capture_ready(page, timeout_ms=max(1, int((deadline - time.monotonic()) * 1000)), javascript_enabled=False)
            screenshot_png = None
            if screenshot_selectors:
                try:
                    clip_boxes = []
                    for selector in screenshot_selectors:
                        locator = page.locator(selector).first
                        if not locator.count() or not locator.is_visible():
                            continue
                        locator.scroll_into_view_if_needed(timeout=_remaining_timeout_ms(deadline, selector_timeout_ms))
                        box = locator.bounding_box(timeout=_remaining_timeout_ms(deadline, selector_timeout_ms))
                        if box is not None:
                            clip_boxes.append(box)
                    if clip_boxes:
                        min_x = min(box["x"] for box in clip_boxes)
                        min_y = min(box["y"] for box in clip_boxes)
                        max_x = max(box["x"] + box["width"] for box in clip_boxes)
                        max_y = max(box["y"] + box["height"] for box in clip_boxes)
                        screenshot_png = page.screenshot(
                            type="png",
                            timeout=_remaining_timeout_ms(deadline, selector_timeout_ms),
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
                    locator = page.locator(screenshot_selector).first
                    if locator.count() and locator.is_visible():
                        locator.scroll_into_view_if_needed(timeout=_remaining_timeout_ms(deadline, selector_timeout_ms))
                        screenshot_png = locator.screenshot(
                            type="png",
                            timeout=_remaining_timeout_ms(deadline, selector_timeout_ms),
                            animations="disabled",
                        )
                except PlaywrightTimeoutError:
                    screenshot_png = None
            if screenshot_png is None:
                screenshot_png = page.screenshot(
                    type="png",
                    full_page=True,
                    timeout=_remaining_timeout_ms(deadline, selector_timeout_ms),
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


def _wait_for_capture_ready(page, *, timeout_ms: int, capture_ready_script: str = "",
                            wait_for_images: bool = True, javascript_enabled: bool = True) -> None:
    from playwright.sync_api import TimeoutError as PlaywrightTimeoutError

    deadline = time.monotonic() + max(timeout_ms, 1) / 1000
    try:
        if javascript_enabled:
            page.wait_for_function(_CAPTURE_READY_SCRIPT, arg=wait_for_images, polling=100, timeout=max(timeout_ms, 1))
        else:
            # In a script-disabled evidence document, scheduled JS callbacks may
            # not run. Poll readiness from Playwright without enabling the app.
            while not page.evaluate(_CAPTURE_READY_SCRIPT, wait_for_images):
                remaining = (deadline - time.monotonic()) * 1000
                if remaining <= 0:
                    raise RuntimeError("page remained in a loading state; screenshot skipped")
                page.wait_for_timeout(min(100, remaining))
        if capture_ready_script:
            page.wait_for_function(capture_ready_script, polling=100, timeout=max(1, int((deadline - time.monotonic()) * 1000)))
    except PlaywrightTimeoutError as exc:
        raise RuntimeError("page remained in a loading state; screenshot skipped") from exc


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
    try:
        raise_if_error_page(str(html or ""))
    except CollectionFailure as exc:
        return exc.kind == "blocked"
    return False


def _clear_browser_check_interstitial(
    page,
    *,
    timeout_ms: int,
    settle_wait_ms: int = 250,
) -> str:
    html = _read_page_content(page)
    if not _looks_like_browser_check_page(html):
        return html

    deadline = time.monotonic() + max(timeout_ms, 0) / 1000
    while time.monotonic() < deadline:
        # Only wait for ordinary automatic verification. Random clicks or Space
        # can activate unrelated controls and must never be sent to the source.
        page.wait_for_timeout(max(0, min(settle_wait_ms, (deadline - time.monotonic()) * 1000)))
        html = _read_page_content(page)
        if not _looks_like_browser_check_page(html):
            return html
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
    user_agent: str | None = None,
    validate_html: Callable[[str], bool] | None = None,
) -> str:
    requested_proxy = BrowserProxyConfig(server=proxy_server, engine=browser_engine)
    try:
        client = _get_or_create_client(requested_proxy)
    except Exception as exc:
        raise CollectionFailure("infrastructure", "browser runtime could not be started", scope="site") from exc
    try:
        html, _ = client.fetch_page_artifacts(
            url=url,
            wait_seconds=wait_seconds,
            timeout_seconds=timeout_seconds,
            capture_screenshot=False,
            storage_state_path=storage_state_path,
            persist_storage_state=persist_storage_state,
            cookie_header=cookie_header,
            user_agent=user_agent,
            validate_html=validate_html,
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
    user_agent: str | None = None,
    validate_html: Callable[[str], bool] | None = None,
) -> tuple[str, bytes | None]:
    requested_proxy = BrowserProxyConfig(server=proxy_server, engine=browser_engine)
    try:
        client = _get_or_create_client(requested_proxy)
    except Exception as exc:
        raise CollectionFailure("infrastructure", "browser runtime could not be started", scope="site") from exc
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
            user_agent=user_agent,
            validate_html=validate_html,
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
    storage_state_path: str | None = None,
    cookie_header: str | None = None,
    user_agent: str | None = None,
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
            storage_state_path=storage_state_path,
            cookie_header=cookie_header,
            user_agent=user_agent,
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
