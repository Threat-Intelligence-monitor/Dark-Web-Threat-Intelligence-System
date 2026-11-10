from __future__ import annotations

import atexit
import logging
import os
from pathlib import Path
import pickle
from queue import Empty, Full, Queue
import signal
import struct
import subprocess
import sys
from threading import Lock, Thread, current_thread
import traceback
import time
from dataclasses import dataclass
from typing import Callable
from urllib.parse import urlparse

from darkweb_collector.collection_errors import CollectionFailure, raise_if_error_page, request_attempt, safe_failure_text
from darkweb_collector.tor_fetch import raise_for_http_status
from darkweb_collector.source_sessions import read_browser_session, persist_browser_session, same_source


logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class BrowserProxyConfig:
    server: str | None = None
    engine: str = "firefox"
    verification_provider: str = ""


_CAPTURE_READY_SCRIPT = r"""
(options = {}) => {
    const waitForImages = typeof options === 'boolean' ? options : options.waitForImages !== false;
    const scoped = typeof options === 'object' && options.contentSelector != null;
    const isVisible = (element) => {
        const style = window.getComputedStyle(element);
        const rect = element.getBoundingClientRect();
        return style.display !== 'none' && style.visibility !== 'hidden' &&
            Number(style.opacity || 1) > 0 && rect.width > 0 && rect.height > 0;
    };
    const excluded = 'header, nav, footer, aside, form, button, [hidden], [aria-hidden="true"], ' +
        '.signature, .post_signature, .message-signature, .post_controls, .post_meta, .post_actions, .post_toolbar, ' +
        '.hide-tag, .hide-content, .hidden-content, .bbcode_hidden, .hidebox, ' +
        '[class*="bbCodeBlock--hide"], [class*="bbCodeBlock--hidden"]';
    const isExposed = (element) => {
        if (element.closest(excluded)) return false;
        for (let current = element; current; current = current.parentElement) {
            const style = window.getComputedStyle(current);
            if (style.display === 'none' || style.visibility === 'hidden' || Number(style.opacity || 1) === 0) return false;
        }
        return true;
    };
    const stablePost = element => /^(DIV|ARTICLE)$/.test(element.tagName) &&
        (/^post_\d+$/.test(element.id || '') || element.matches('article.message--post'));
    const postOwner = (element) => {
        let fallback = null;
        for (let current = element; current; current = current.parentElement) {
            // Copied post markup inside a quote is still original-post content.
            if (current.parentElement?.closest('blockquote, pre, code')) continue;
            if (stablePost(current)) return current;
            if (!fallback && current.matches('div.post, article.post, div.post-article, article.post-article')) fallback = current;
        }
        return fallback;
    };
    let content = document.body;
    if (scoped) {
        const ancillary = 'header, nav, aside, footer, form, blockquote, pre, code, .signature, .post_signature, .message-signature, .post_meta, .post_controls, .post_actions, .post_toolbar';
        const posts = Array.from(document.querySelectorAll('div[id^="post_"], article[id^="post_"], article.message--post'))
            .filter(post => stablePost(post) && !post.parentElement?.closest(ancillary));
        let original = posts[0];
        if (original?.matches('article.message--post'))
            original = posts.find(post => post.matches('article.message--post:is(.is-first, [data-position="0"])'));
        const candidates = options.contentSelector ? Array.from(document.querySelectorAll(options.contentSelector))
            .filter(body => !body.parentElement?.closest(ancillary)) : [];
        content = original ? candidates.find(body => postOwner(body) === original) : (posts.length === 0 && candidates.length === 1 ? candidates[0] : null);
    }
    if (options.inspectEmpty === true) {
        if (!scoped || !content || !isExposed(content) || document.readyState !== 'complete') return false;
        const owner = postOwner(content);
        const roots = [content];
        if (owner) roots.push(...Array.from(owner.querySelectorAll('.post_attachments, .attachments, .message-attachments'))
            .filter(element => postOwner(element) === owner && isExposed(element)));
        return roots.every(root => !root.textContent.trim() && !Array.from(
            root.querySelectorAll('img, video, audio, iframe, object, embed, svg, a[href]')
        ).some(isExposed));
    }
    if (scoped && (!content || !isVisible(content) || !isExposed(content))) {
        if (waitForImages) throw new Error('required original-post content scope is unavailable; screenshot skipped');
        return false;
    }
    const owner = scoped ? postOwner(content) : null;
    const roots = content ? [content] : [];
    if (owner) {
        for (const attachment of owner.querySelectorAll('.post_attachments, .attachments, .message-attachments')) {
            if (postOwner(attachment) === owner && isExposed(attachment)) roots.push(attachment);
        }
    }
    const belongs = element => !scoped || (isExposed(element) && (!owner || postOwner(element) === owner));
    const loadingText = /^(loading(?:[,.\u2026\s]+please wait)?|please wait)[.!\u2026]*$/i;
    const loadingElements = scoped ? roots.flatMap(root => [root, ...root.querySelectorAll('*')]) : Array.from(document.body?.querySelectorAll('*') || []);
    const hasVisibleLoadingState = loadingElements.some((element) => {
        if (!belongs(element)) return false;
        if (!isVisible(element)) return false;
        const text = String(element.textContent || '').replace(/\s+/g, ' ').trim();
        return text.length <= 80 && loadingText.test(text);
    });
    const images = scoped ? Array.from(new Set(roots.flatMap(root => Array.from(root.querySelectorAll('img'))))) : Array.from(document.images || []);
    const visibleImages = images.filter((image) => {
        const style = window.getComputedStyle(image);
        return image.getClientRects().length > 0 && style.display !== 'none' &&
            style.visibility !== 'hidden' && Number(style.opacity || 1) > 0 &&
            belongs(image) && (scoped || Boolean(image.currentSrc || image.src));
    });
    if (scoped && waitForImages) {
        // Activate only public original-post media, not avatars or later replies.
        // Cached HTML has app scripts disabled, so its explicit lazy attributes
        // must be resolved without restarting the source application.
        for (const image of visibleImages) {
            image.loading = 'eager';
            const source = image.dataset.src || image.dataset.lazySrc || image.dataset.original;
            if (source && image.getAttribute('src') !== source) image.setAttribute('src', source);
            if (image.dataset.srcset && image.getAttribute('srcset') !== image.dataset.srcset)
                image.setAttribute('srcset', image.dataset.srcset);
            const picture = image.closest('picture');
            if (picture) for (const source of picture.querySelectorAll('source[data-srcset]'))
                if (source.getAttribute('srcset') !== source.dataset.srcset) source.setAttribute('srcset', source.dataset.srcset);
        }
    }
    if (waitForImages && visibleImages.some(image => image.complete && image.naturalWidth === 0 &&
        (!scoped || Boolean(image.currentSrc || image.src))))
        throw new Error('visible source image failed to load; screenshot skipped');
    const hasPendingImage = visibleImages.some(image => !image.complete || scoped && !(image.currentSrc || image.src));
    const hasContent = content && isVisible(content) &&
        (content.innerText.trim().length > 0 || (scoped ? visibleImages : Array.from(document.images || [])).some(isVisible));
    return document.readyState !== 'loading' && hasContent &&
        !hasVisibleLoadingState && (!waitForImages ||
            ((!document.fonts || document.fonts.status !== 'loading') && !hasPendingImage));
}
"""


class _CaptureScopeUnavailable(RuntimeError):
    pass


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
        started = time.monotonic()
        logger.info("capture phase=launch-start engine=%s", self._proxy.engine)
        self._playwright_context = sync_playwright()
        try:
            self._playwright = self._playwright_context.start()
            launch_kwargs = {
                "headless": True,
            }
            if self._proxy.engine == "chromium":
                launch_kwargs["args"] = ["--disable-blink-features=AutomationControlled"]
                if self._proxy.verification_provider == "dnsproxy":
                    launch_kwargs["channel"] = "chromium"
            if self._proxy.server:
                launch_kwargs["proxy"] = {"server": self._proxy.server}
            browser_type = getattr(self._playwright, self._proxy.engine)
            self._browser = browser_type.launch(**launch_kwargs)
            self._created_monotonic = time.monotonic()
            self._task_count = 0
            logger.info("capture phase=launch-done engine=%s elapsed=%.3f", self._proxy.engine, time.monotonic() - started)
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
        capture_content_selector: str | None = None,
        _request_attempt: Callable[[], None] | None = None,
        _on_event: Callable[[str, object], None] | None = None,
        _deadline: float | None = None,
    ) -> tuple[str, bytes | None]:
        from playwright.sync_api import TimeoutError as PlaywrightTimeoutError

        try:
            self._ensure_browser()
        except Exception as exc:
            raise CollectionFailure("infrastructure", safe_failure_text(
                f"browser runtime could not be started ({type(exc).__name__}): {exc}"
            ), scope="site") from exc
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
        main_request = None
        terminal_failure = None
        session_eligible = False
        pending_session = None

        def report(kind, value):
            if _on_event is not None:
                _on_event(kind, value)

        def stop_source(failure):
            nonlocal terminal_failure, session_eligible
            if terminal_failure is None:
                terminal_failure = failure
                session_eligible = False
                report("failure", failure)

        def remember_main_request(received):
            nonlocal main_request
            if received.is_navigation_request() and received.frame == page.main_frame:
                main_request = received
                report("navigation", None)
                if time.monotonic() >= deadline:
                    stop_source(CollectionFailure("timeout", "browser navigation rejected after the execution deadline"))
                elif not same_source(url, received.url):
                    stop_source(CollectionFailure("source_moved", "browser navigation left the configured source origin", scope="site"))
                    try:
                        context.close()
                    except Exception:
                        pass

        def remember_main_response(received):
            nonlocal main_response
            if received.request.is_navigation_request() and received.frame == page.main_frame:
                main_response = received
                if (received.status in {401, 429} or received.status == 403 and validated_html is not None) and terminal_failure is None:
                    try:
                        if not same_source(url, received.url):
                            raise CollectionFailure("source_moved", "browser navigation left the configured source origin", scope="site")
                        raise_for_http_status(received.status, headers=received.headers)
                    except CollectionFailure as exc:
                        stop_source(exc)
                    # Closing the owned context cancels pending page waits.
                    # Page.close() can wait for those operations to time out.
                    try:
                        context.close()
                    except Exception:
                        pass

        def guard_request(route):
            if route.request.is_navigation_request() and route.request.frame == page.main_frame:
                if time.monotonic() >= deadline:
                    stop_source(CollectionFailure("timeout", "browser navigation rejected after the execution deadline"))
                elif not same_source(url, route.request.url):
                    stop_source(CollectionFailure("source_moved", "browser navigation left the configured source origin", scope="site"))
            if terminal_failure is not None or time.monotonic() >= deadline:
                route.abort()
            else:
                route.continue_()

        page.route("**/*", guard_request)
        page.on("request", remember_main_request)
        page.on("response", remember_main_response)
        selector_timeout_ms = min(timeout_seconds * 1000, 10_000)
        deadline = _deadline if _deadline is not None else time.monotonic() + timeout_seconds
        validated_html = None

        def check_rate_limit():
            if terminal_failure is not None:
                raise terminal_failure

        early_verification = self._proxy.engine == "chromium" and self._proxy.verification_provider == "dnsproxy"

        def observe_dnsproxy_document(response):
            if not early_verification or response is None:
                return
            headers = response.headers
            mime = str(headers.get("content-type") or "").split(";", 1)[0].strip().lower()
            if (response.status != 302 or "location" in headers
                    or str(headers.get("cf-mitigated") or "").strip().lower() == "challenge"
                    or mime not in {"text/html", "application/xhtml+xml"}
                    or not same_source(url, response.url)):
                return
            # This hint comes from the preceding strict HTTP-template check.
            # Allow its normal, short input-observation window to run without
            # clicking controls, synthesizing DOM events, or constructing tokens.
            started = time.monotonic()
            stop = min(deadline, started + 0.7)
            viewport = page.viewport_size or {"width": 1440, "height": 960}
            for index in range(24):
                check_rate_limit()
                if (time.monotonic() >= stop or page.is_closed() or main_response is not response
                        or main_request is not response.request or not same_source(url, page.url)):
                    break
                page.mouse.move(min(viewport["width"] - 1, 80 + index * 8),
                                min(viewport["height"] - 1, 120 + index * 3))
                check_rate_limit()
                remaining = min(stop, started + (index + 1) * 0.7 / 24) - time.monotonic()
                if remaining > 0:
                    page.wait_for_timeout(remaining * 1000)

        def verified_document(*, validate_content=True):
            nonlocal validated_html
            check_rate_limit()
            if not same_source(url, page.url):
                raise CollectionFailure("source_moved", "browser navigation left the configured source origin", scope="site")
            if main_response is None or not same_source(main_response.url, page.url):
                raise CollectionFailure("network", "browser final document response is unconfirmed")
            html = _read_page_content(page)
            check_rate_limit()
            raise_for_http_status(main_response.status, html, headers=main_response.headers)
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
            except Exception as exc:
                session_eligible = False
                if isinstance(exc, CollectionFailure) and exc.kind in {"rate_limited", "auth_required", "blocked", "source_moved"}:
                    raise
                if validated_html is None:
                    raise
                return validated_html, None

        try:
            # Onion sites commonly keep polling or streaming connections open,
            # so waiting for networkidle adds a full timeout to otherwise loaded
            # pages. The configured render wait and selectors below handle the
            # dynamic content after DOM readiness.
            if time.monotonic() >= deadline:
                raise CollectionFailure("timeout", "browser execution deadline exhausted before navigation")
            (_request_attempt or request_attempt)()
            try:
                response = page.goto(url, wait_until="commit" if early_verification else "domcontentloaded",
                                     timeout=_remaining_timeout_ms(deadline, timeout_seconds * 1000))
            except (PlaywrightTimeoutError, TimeoutError) as exc:
                raise CollectionFailure("timeout", safe_failure_text(
                    f"browser document navigation timed out ({type(exc).__name__}): {exc}"
                )) from exc
            except Exception as exc:
                raise CollectionFailure("network", safe_failure_text(
                    f"browser document navigation failed ({type(exc).__name__}): {exc}"
                )) from exc
            status = getattr(response, "status", 0)
            if status in {401, 429}:
                raise_for_http_status(status, headers=getattr(response, "headers", None))
            check_rate_limit()
            observe_dnsproxy_document(response)
            if early_verification:
                page.wait_for_load_state("domcontentloaded", timeout=_remaining_timeout_ms(deadline, timeout_seconds * 1000))
            render_deadline = min(deadline, time.monotonic() + max(0, wait_seconds))
            while time.monotonic() < render_deadline:
                page.wait_for_timeout(min(250, max(0, (render_deadline - time.monotonic()) * 1000)))
                check_rate_limit()
            _clear_browser_check_interstitial(page, timeout_ms=max(0, int((deadline - time.monotonic()) * 1000)))
            verified_document(validate_content=False)
            # Validate the source only after ordinary asynchronous content is
            # ready. A loading shell is not evidence of a parser regression.
            try:
                _wait_for_capture_ready(page, timeout_ms=max(1, int((deadline - time.monotonic()) * 1000)),
                                        wait_for_images=False, capture_content_selector=capture_content_selector)
            except _CaptureScopeUnavailable as exc:
                # A parser may still validate a legacy body layout; an unknown
                # evidence scope must remain partial rather than become complete.
                verified_document()
                report("artifact_error", exc)
                self._task_count += 1
                return finish_capture(None)
            except CollectionFailure:
                verified_document(validate_content=False)
                raise
            except Exception as exc:
                raise CollectionFailure("timeout", safe_failure_text(
                    f"browser content did not become ready within the request deadline ({type(exc).__name__}): {exc}"
                )) from exc
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
            except Exception as exc:
                session_eligible = False
                report("artifact_error", exc)
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
                    capture_content_selector=capture_content_selector,
                )
            except Exception as exc:
                session_eligible = False
                report("artifact_error", exc)
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
                            if capture_content_selector is not None:
                                offset = page.evaluate("() => ({x: window.scrollX, y: window.scrollY})")
                                box = {**box, "x": box["x"] + offset["x"], "y": box["y"] + offset["y"]}
                            clip_boxes.append(box)
                    if clip_boxes:
                        min_x = min(box["x"] for box in clip_boxes)
                        min_y = min(box["y"] for box in clip_boxes)
                        max_x = max(box["x"] + box["width"] for box in clip_boxes)
                        max_y = max(box["y"] + box["height"] for box in clip_boxes)
                        screenshot_png = page.screenshot(
                            type="png",
                            full_page=capture_content_selector is not None,
                            timeout=_remaining_timeout_ms(deadline, selector_timeout_ms),
                            animations="disabled",
                            clip={
                                "x": min_x,
                                "y": min_y,
                                "width": max_x - min_x,
                                "height": max_y - min_y,
                            },
                        )
                except Exception as exc:
                    session_eligible = False
                    report("artifact_error", exc)
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
                except Exception as exc:
                    session_eligible = False
                    report("artifact_error", exc)
                    screenshot_png = None
            if screenshot_png is None:
                try:
                    screenshot_png = page.screenshot(
                        type="png",
                        full_page=True,
                        timeout=_remaining_timeout_ms(deadline, selector_timeout_ms),
                        animations="disabled",
                    )
                except Exception as exc:
                    session_eligible = False
                    report("artifact_error", exc)
                    screenshot_png = None
            # Capture HTML after the page-specific selectors have had a chance to
            # appear. Some forum pages finish rendering well after the initial
            # DOMContentLoaded/networkidle checkpoint, which made us persist a
            # head-only document while the screenshot already contained the post.
            self._task_count += 1
            return finish_capture(screenshot_png)
        except Exception as exc:
            session_eligible = False
            check_rate_limit()
            if isinstance(exc, CollectionFailure):
                stop_source(exc)
            raise
        finally:
            try:
                if storage_path is not None and persist_storage_state and session_eligible:
                    try:
                        verified_document()
                        state = context.storage_state()
                        check_rate_limit()
                        if session_eligible:
                            pending_session = dict(
                                state=state, path=storage_path, url=page.url,
                                proxy_server=self._proxy.server, user_agent=user_agent,
                                engine=self._proxy.engine, expected_revision=session_revision,
                            )
                    except Exception as exc:
                        if isinstance(exc, CollectionFailure) and exc.kind in {"rate_limited", "auth_required", "blocked", "source_moved"}:
                            stop_source(exc)
                            raise
                check_rate_limit()
            finally:
                logger.info("capture phase=context-close-start engine=%s", self._proxy.engine)
                context.close()
                logger.info("capture phase=context-close-done engine=%s", self._proxy.engine)
                check_rate_limit()
                if pending_session is not None:
                    if _on_event is not None:
                        report("session", pending_session)
                    else:
                        try:
                            persist_browser_session(**pending_session)
                        except Exception:
                            pass

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
        capture_content_selector: str | None = None,
        _deadline: float | None = None,
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
            deadline = _deadline if _deadline is not None else time.monotonic() + timeout_seconds
            page.goto(base_url, wait_until="domcontentloaded", timeout=_remaining_timeout_ms(deadline, timeout_seconds * 1000))
            logger.info("capture phase=static-render-start engine=%s", self._proxy.engine)
            _wait_for_capture_ready(page, timeout_ms=max(1, int((deadline - time.monotonic()) * 1000)),
                                    javascript_enabled=False, capture_content_selector=capture_content_selector)
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
                            if capture_content_selector is not None:
                                offset = page.evaluate("() => ({x: window.scrollX, y: window.scrollY})")
                                box = {**box, "x": box["x"] + offset["x"], "y": box["y"] + offset["y"]}
                            clip_boxes.append(box)
                    if clip_boxes:
                        min_x = min(box["x"] for box in clip_boxes)
                        min_y = min(box["y"] for box in clip_boxes)
                        max_x = max(box["x"] + box["width"] for box in clip_boxes)
                        max_y = max(box["y"] + box["height"] for box in clip_boxes)
                        screenshot_png = page.screenshot(
                            type="png",
                            full_page=capture_content_selector is not None,
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
            logger.info("capture phase=context-close-start engine=%s", self._proxy.engine)
            context.close()
            logger.info("capture phase=context-close-done engine=%s", self._proxy.engine)

    def close(self) -> None:
        browser, playwright, context = self._browser, self._playwright, self._playwright_context
        self._browser = self._playwright = self._playwright_context = None
        try:
            if browser is not None:
                logger.info("capture phase=browser-close-start engine=%s", self._proxy.engine)
                browser.close()
        finally:
            if playwright is not None:
                playwright.stop()
            elif context is not None:
                context.__exit__()
            if browser is not None:
                logger.info("capture phase=browser-close-done engine=%s", self._proxy.engine)


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
                            wait_for_images: bool = True, javascript_enabled: bool = True,
                            capture_content_selector: str | None = None) -> None:
    from playwright.sync_api import TimeoutError as PlaywrightTimeoutError

    deadline = time.monotonic() + max(timeout_ms, 1) / 1000
    if capture_content_selector is not None and not capture_content_selector.strip():
        raise _CaptureScopeUnavailable("required original-post content scope is empty; screenshot skipped")
    options = {"waitForImages": wait_for_images, "contentSelector": capture_content_selector}
    try:
        if javascript_enabled:
            page.wait_for_function(_CAPTURE_READY_SCRIPT, arg=options, polling=100, timeout=max(timeout_ms, 1))
        else:
            # In a script-disabled evidence document, scheduled JS callbacks may
            # not run. Poll readiness from Playwright without enabling the app.
            while not page.evaluate(_CAPTURE_READY_SCRIPT, options):
                remaining = (deadline - time.monotonic()) * 1000
                if remaining <= 0:
                    raise RuntimeError("page remained in a loading state; screenshot skipped")
                page.wait_for_timeout(min(100, remaining))
        if capture_ready_script:
            page.wait_for_function(capture_ready_script, polling=100, timeout=max(1, int((deadline - time.monotonic()) * 1000)))
    except PlaywrightTimeoutError as exc:
        if not wait_for_images and capture_content_selector is not None:
            # Classify only after the existing render deadline; delayed content
            # keeps the full wait and an unfinished loading document stays a timeout.
            try:
                empty = page.evaluate(_CAPTURE_READY_SCRIPT, {**options, "inspectEmpty": True})
            except Exception:
                empty = False
            if empty:
                raise CollectionFailure("empty_content", "original post is empty after browser rendering") from exc
        if capture_content_selector is not None and not page.locator(capture_content_selector).count():
            raise _CaptureScopeUnavailable("required original-post content scope was not found; screenshot skipped") from exc
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
    capture_content_selector: str | None = None,
    verification_provider: str = "",
) -> str:
    options = dict(url=url, wait_seconds=wait_seconds, timeout_seconds=timeout_seconds,
                   capture_screenshot=False, proxy_server=proxy_server, browser_engine=browser_engine,
                   verification_provider=verification_provider, storage_state_path=storage_state_path,
                   persist_storage_state=persist_storage_state, cookie_header=cookie_header, user_agent=user_agent,
                   capture_content_selector=capture_content_selector)
    html, _ = _run_browser_request("fetch", options, validate_html=validate_html)
    return html


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
    capture_content_selector: str | None = None,
    verification_provider: str = "",
    on_artifact_error: Callable[[str], None] | None = None,
) -> tuple[str, bytes | None]:
    options = dict(url=url, wait_seconds=wait_seconds, timeout_seconds=timeout_seconds,
                   proxy_server=proxy_server, browser_engine=browser_engine, verification_provider=verification_provider,
                   screenshot_selector=screenshot_selector, screenshot_selectors=screenshot_selectors,
                   hide_selectors=hide_selectors, screenshot_styles=screenshot_styles,
                   storage_state_path=storage_state_path, persist_storage_state=persist_storage_state,
                   capture_ready_script=capture_ready_script, cookie_header=cookie_header, user_agent=user_agent,
                   capture_content_selector=capture_content_selector)
    return _run_browser_request("fetch", options, validate_html=validate_html, on_artifact_error=on_artifact_error)


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
    capture_content_selector: str | None = None,
) -> bytes:
    options = dict(
        html=html, base_url=base_url, wait_seconds=wait_seconds, timeout_seconds=timeout_seconds,
        proxy_server=proxy_server, browser_engine=browser_engine,
        screenshot_selector=screenshot_selector, screenshot_selectors=screenshot_selectors,
        hide_selectors=hide_selectors, screenshot_styles=screenshot_styles,
        storage_state_path=storage_state_path, cookie_header=cookie_header, user_agent=user_agent,
        capture_content_selector=capture_content_selector,
    )
    return _run_browser_request("screenshot", options)


def _run_browser_request(operation: str, options: dict, *, validate_html=None, on_artifact_error=None):
    started = time.monotonic()
    deadline = started + max(0.1, options["timeout_seconds"])
    label = "static" if operation == "screenshot" else "live"
    logger.info("capture phase=%s-start engine=%s", label, options["browser_engine"])
    thread_key = current_thread()
    requested_proxy = BrowserProxyConfig(server=options.get("proxy_server"), engine=options["browser_engine"],
                                        verification_provider=options.get("verification_provider", ""))
    with _GLOBAL_CLIENT_LOCK:
        worker = _GLOBAL_BROWSER_WORKERS.get(thread_key)
    try:
        if worker is None or worker._closed or worker.proxy != requested_proxy or worker.process.poll() is not None:
            if worker is not None:
                worker.close(graceful=True, deadline=deadline + 3)
            worker = _BrowserWorker(requested_proxy, cleanup_deadline=deadline + 3)
            with _GLOBAL_CLIENT_LOCK:
                _GLOBAL_BROWSER_WORKERS[thread_key] = worker
        return worker.capture({"operation": operation, "options": options}, deadline,
                              validate_html=validate_html, on_artifact_error=on_artifact_error)
    except Exception as exc:
        with _GLOBAL_CLIENT_LOCK:
            _GLOBAL_BROWSER_WORKERS.pop(thread_key, None)
        if worker is not None:
            worker.close(deadline=deadline + 3)
        from darkweb_collector.forum_rate_limit import note_current_source_failure

        note_current_source_failure(exc)
        raise
    finally:
        if worker is not None and worker._closed:
            with _GLOBAL_CLIENT_LOCK:
                _GLOBAL_BROWSER_WORKERS.pop(thread_key, None)
        logger.info("capture phase=%s-end engine=%s elapsed=%.3f", label, options["browser_engine"], time.monotonic() - started)


_CAPTURE_PACKET_LIMIT = 256 * 1024 * 1024


def _write_capture_packet(stream, value) -> None:
    payload = pickle.dumps(value)
    if len(payload) > _CAPTURE_PACKET_LIMIT:
        raise ValueError("static screenshot packet exceeds the size limit")
    stream.write(struct.pack("!I", len(payload)) + payload)
    stream.flush()


def _read_capture_packet(stream):
    header = stream.read(4)
    if len(header) != 4:
        raise EOFError("static screenshot channel closed")
    size = struct.unpack("!I", header)[0]
    if not 0 < size <= _CAPTURE_PACKET_LIMIT:
        raise ValueError("static screenshot packet size is invalid")
    payload = stream.read(size)
    if len(payload) != size:
        raise EOFError("static screenshot result was incomplete")
    return pickle.loads(payload)


class _BrowserWorker:
    """One serial browser process; business callbacks stay on the caller thread."""

    def __init__(self, proxy: BrowserProxyConfig, *, cleanup_deadline: float | None = None):
        self.proxy = proxy
        self.process, self.job, self.exchange_thread = None, None, None
        self.reply_queue = None
        self._closed = False
        assigned = False
        env = os.environ.copy()
        env["PYTHONPATH"] = os.pathsep.join(filter(None, (str(Path(__file__).resolve().parent.parent), env.get("PYTHONPATH"))))
        # The private pipes connect only to this trusted child. HTML/cookies
        # never enter command arguments, logs, or temporary documents.
        command = [sys.executable, "-c", "from darkweb_collector.browser_client import _browser_process; _browser_process()"]
        try:
            if os.name == "nt":
                from uuid import uuid4
                from darkweb_collector.worker_supervisor import _WorkerJob

                self.job = _WorkerJob(f"Local\\dwti-worker-screenshot-{uuid4().hex}")
            self.process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                            env=env, creationflags=(subprocess.CREATE_NO_WINDOW | 0x00000004) if self.job else 0,
                                            start_new_session=os.name != "nt")
            if self.job is not None:
                self.job.assign_and_resume(self.process)
                assigned = True
        except Exception:
            if self.process is not None and not assigned:
                self.process.kill()
            self.close(deadline=cleanup_deadline)
            raise

    def capture(self, request: dict | None, deadline: float, *, validate_html=None, on_artifact_error=None):
        response = Queue(maxsize=1)
        self.reply_queue = replies = Queue(maxsize=1)
        state_lock = Lock()
        state = {"html": None, "failure": None, "artifact_error": None, "navigation": 0, "session": None}
        callback_error = None
        live = request is not None and request["operation"] == "fetch"
        label = "live browser" if live else ("browser session save" if request is not None and request["operation"] == "commit_session" else "static screenshot")
        # The page may need a final read to distinguish an empty post from a
        # loading shell. This is cleanup time, not another navigation budget.
        receive_deadline = deadline + 2 if live else deadline
        cleanup_deadline = deadline + 3

        def deliver(kind, value):
            try:
                response.put((kind, value), timeout=max(0, receive_deadline - time.monotonic()))
                return True
            except Full:
                return False

        def exchange():
            try:
                _write_capture_packet(self.process.stdin, {**request, "deadline": deadline} if request is not None else None)
                while True:
                    kind, value = _read_capture_packet(self.process.stdout)
                    if kind == "phase":
                        logger.info("%s", value)
                    elif kind == "navigation":
                        with state_lock:
                            state["html"] = None
                            state["session"] = None
                            state["navigation"] += 1
                    elif kind == "session":
                        with state_lock:
                            state["session"] = value
                    elif kind == "artifact_error":
                        with state_lock:
                            state["artifact_error"] = value
                    elif kind == "failure":
                        with state_lock:
                            state["failure"] = value
                        deliver(kind, value)
                        return
                    elif kind == "callback":
                        if not deliver(kind, value):
                            return
                        reply = replies.get(timeout=max(0, receive_deadline - time.monotonic()))
                        _write_capture_packet(self.process.stdin, ("reply", reply))
                    elif kind == "result":
                        deliver(kind, value)
                        return
                    else:
                        raise ValueError("unsupported browser response message")
            except Exception:
                deliver("result", (False, CollectionFailure("infrastructure", "browser process exited without a complete result")))

        def raise_failure(failure):
            if callback_error is not None and (not isinstance(callback_error, CollectionFailure)
                    or isinstance(failure, CollectionFailure) and failure.kind == callback_error.kind):
                if not isinstance(callback_error, CollectionFailure):
                    self.close(deadline=cleanup_deadline)
                    from darkweb_collector.forum_rate_limit import note_current_source_failure

                    try:
                        note_current_source_failure(failure)
                    except Exception:
                        logger.warning("capture phase=source-backoff-save-failed engine=%s", self.proxy.engine)
                raise callback_error
            raise failure

        def partial_or_raise(error):
            self.close(deadline=cleanup_deadline)
            with state_lock:
                html, failure = state["html"], state["failure"]
            if failure is not None:
                raise_failure(failure)
            if callback_error is not None:
                raise callback_error
            if live and html is not None:
                if on_artifact_error is not None:
                    on_artifact_error(safe_failure_text(f"artifact: browser evidence capture failed ({type(error).__name__}): {error}"))
                return html, None
            if live and isinstance(error, TimeoutError):
                raise CollectionFailure("timeout", "live browser execution deadline exhausted") from error
            raise error

        # Both a blocked send and a partial response frame stay in this daemon
        # thread. The caller's deadline bounds the complete exchange, not a poll.
        self.exchange_thread = Thread(target=exchange, name="browser-io", daemon=True)
        self.exchange_thread.start()
        while True:
            try:
                kind, value = response.get(timeout=max(0, receive_deadline - time.monotonic()))
            except Empty:
                return partial_or_raise(TimeoutError(f"{label} execution deadline exhausted"))
            if kind == "callback":
                name, argument = value
                if time.monotonic() >= (receive_deadline if name == "validate_html" else deadline):
                    return partial_or_raise(TimeoutError(f"{label} execution deadline exhausted"))
                with state_lock:
                    navigation = state["navigation"]
                try:
                    if name == "request_attempt":
                        result = request_attempt()
                    elif name == "validate_html":
                        result = validate_html(argument) if validate_html is not None else True
                        with state_lock:
                            if result and validate_html is not None and state["navigation"] == navigation:
                                state["html"] = argument
                    else:
                        raise ValueError("unsupported browser callback")
                    reply = (True, result)
                except Exception as exc:
                    callback_error, reply = exc, (False, exc)
                if time.monotonic() >= (receive_deadline if name == "validate_html" else deadline):
                    return partial_or_raise(TimeoutError(f"{label} execution deadline exhausted"))
                replies.put_nowait(reply)
                continue
            if kind == "failure":
                raise_failure(value)
            succeeded, result = value
            self.exchange_thread.join(timeout=max(0, receive_deadline - time.monotonic()))
            if callback_error is not None:
                raise callback_error
            if not succeeded:
                return partial_or_raise(result)
            if live and result[1] is not None and state["session"] is not None:
                try:
                    if time.monotonic() < deadline:
                        self.capture({"operation": "commit_session", "options": state["session"]}, deadline)
                except Exception:
                    logger.warning("capture phase=session-save-failed engine=%s", self.proxy.engine)
            if live and result[1] is None and state["artifact_error"] is not None and on_artifact_error is not None:
                error = state["artifact_error"]
                on_artifact_error(safe_failure_text(f"artifact: browser evidence capture failed ({type(error).__name__}): {error}"))
            return result

    def close(self, *, graceful: bool = False, deadline: float | None = None) -> None:
        if self._closed:
            return
        self._closed = True
        deadline = min(time.monotonic() + 3, deadline) if deadline is not None else time.monotonic() + 3
        if (graceful and self.process is not None and self.process.poll() is None
                and (self.exchange_thread is None or not self.exchange_thread.is_alive())):
            try:
                self.capture(None, deadline)
            except Exception:
                pass
        # The private Job/session retains ownership if the child exits first.
        if self.job is not None:
            self.job.close()
        elif self.process is not None:
            try:
                os.killpg(self.process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        if self.reply_queue is not None:
            try:
                self.reply_queue.put_nowait((False, TimeoutError("browser request was cancelled")))
            except Full:
                pass
        if self.process is not None:
            try:
                self.process.wait(timeout=max(0, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                pass
            if self.exchange_thread is not None:
                self.exchange_thread.join(timeout=max(0, deadline - time.monotonic()))
            if self.exchange_thread is None or not self.exchange_thread.is_alive():
                self.process.stdin.close()
                self.process.stdout.close()


_GLOBAL_BROWSER_WORKERS: dict[object, _BrowserWorker] = {}


class _CapturePhaseHandler(logging.Handler):
    def emit(self, record):
        _write_capture_packet(sys.stdout.buffer, ("phase", record.getMessage()))


def _browser_process() -> None:
    logger.addHandler(_CapturePhaseHandler())
    logger.setLevel(logging.INFO)
    logger.propagate = False

    def callback(name, argument):
        _write_capture_packet(sys.stdout.buffer, ("callback", (name, argument)))
        kind, reply = _read_capture_packet(sys.stdin.buffer)
        if kind != "reply":
            raise ValueError("invalid browser callback reply")
        succeeded, value = reply
        if not succeeded:
            raise value
        return value

    def report(kind, value):
        _write_capture_packet(sys.stdout.buffer, (kind, value))

    try:
        while True:
            try:
                request = _read_capture_packet(sys.stdin.buffer)
            except EOFError:
                return
            if request is None:
                close_browser_client()
                _write_capture_packet(sys.stdout.buffer, ("result", (True, b"")))
                return
            operation, options = request["operation"], request["options"]
            try:
                if operation == "commit_session":
                    result = (True, persist_browser_session(**options) if time.monotonic() < request["deadline"] else False)
                else:
                    proxy = BrowserProxyConfig(server=options.pop("proxy_server"), engine=options.pop("browser_engine"),
                                               verification_provider=options.pop("verification_provider", ""))
                    client = _get_or_create_client(proxy)
                    if operation == "screenshot":
                        result = (True, client.screenshot_html_content(**options, _deadline=request["deadline"]))
                    elif operation == "fetch":
                        result = (True, client.fetch_page_artifacts(
                            **options, validate_html=lambda html: callback("validate_html", html),
                            _request_attempt=lambda: callback("request_attempt", None), _on_event=report,
                            _deadline=request["deadline"],
                        ))
                    else:
                        raise ValueError("unsupported browser operation")
            except Exception as exc:
                _write_capture_packet(sys.stdout.buffer, ("result", (False, exc)))
                close_browser_client()
                continue
            _write_capture_packet(sys.stdout.buffer, ("result", result))
    finally:
        close_browser_client()


def close_browser_client(*, all_threads: bool = False) -> None:
    thread_key = current_thread()
    with _GLOBAL_CLIENT_LOCK:
        if all_threads:
            clients = [client for _, client in _GLOBAL_CLIENTS.values()]
            _GLOBAL_CLIENTS.clear()
            workers = list(_GLOBAL_BROWSER_WORKERS.values())
            _GLOBAL_BROWSER_WORKERS.clear()
        else:
            entry = _GLOBAL_CLIENTS.pop(thread_key, None)
            clients = [entry[1]] if entry is not None else []
            worker = _GLOBAL_BROWSER_WORKERS.pop(thread_key, None)
            workers = [worker] if worker is not None else []
    for worker in workers:
        worker.close(graceful=True)
    for client in clients:
        try:
            client.close()
        except Exception:
            pass


atexit.register(lambda: close_browser_client(all_threads=True))
