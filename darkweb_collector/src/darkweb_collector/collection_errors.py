from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from html import unescape
from html.parser import HTMLParser
import re
from typing import Callable


class CollectionFailure(RuntimeError):
    """A collector outcome with a scheduling reason, never an inferred deletion."""

    def __init__(self, kind: str, message: str, *, scope: str = "target", retry_after: float = 0):
        super().__init__(message)
        self.kind = kind
        self.scope = scope
        self.retry_after = max(0.0, float(retry_after))


_request_callback: ContextVar[Callable[[], None] | None] = ContextVar("collection_request", default=None)


@contextmanager
def request_budget(callback: Callable[[], None]):
    token = _request_callback.set(callback)
    try:
        yield
    finally:
        _request_callback.reset(token)


def request_attempt() -> None:
    callback = _request_callback.get()
    if callback is not None:
        callback()


def managed_request() -> bool:
    return _request_callback.get() is not None


def has_detail_body(payload: dict) -> bool:
    body = payload.get("content") if "content" in payload else payload.get("text_excerpt")
    if not isinstance(body, str):
        return False
    text = re.sub(r"<(script|style)\b[^>]*>.*?</\1>", "", body, flags=re.I | re.S)
    return bool(unescape(re.sub(r"<[^>]+>", " ", text)).strip())



class _ErrorTemplate(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.stack = []
        self.error_text = []
        self.post_text = []
        self.template = ""
        self.password = False
        self.challenge = False
        self.login_form = False

    def handle_starttag(self, tag, attributes):
        attrs = dict(attributes)
        classes = set(str(attrs.get("class") or "").split())
        if tag == "html":
            self.template = str(attrs.get("data-template") or "")
        self.challenge = self.challenge or (
            (tag == "form" and str(attrs.get("id") or "") == "challenge-form")
            or str(attrs.get("id") or "").startswith("cf-challenge")
            or "cf-turnstile" in classes
            or (tag in {"script", "iframe"} and any(marker in str(attrs.get("src") or "") for marker in (
                "/cdn-cgi/challenge-platform/", "challenges.cloudflare.com/",
            )))
        )
        if tag == "input" and str(attrs.get("type") or "").lower() == "password":
            self.password = True
        if tag == "form" and re.search(r"(login|sign.?in|member\.php)", str(attrs.get("action") or ""), re.I):
            self.login_form = True
        error = bool(classes & {"error", "blockMessage", "blockMessage--error"})
        post = bool(classes & {"post_body", "message-body", "message-userContent"})
        if tag not in {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"}:
            self.stack.append((tag, error, post))

    def handle_endtag(self, tag):
        for index in range(len(self.stack) - 1, -1, -1):
            if self.stack[index][0] == tag:
                del self.stack[index:]
                break

    def handle_data(self, data):
        if any(item[1] for item in self.stack) and len(self.error_text) < 100:
            self.error_text.append(data)
        if any(item[2] for item in self.stack) and len(self.post_text) < 100:
            self.post_text.append(data)

def raise_if_error_page(html: str, *, missing_markers: tuple[str, ...] = ()) -> None:
    """Recognize error templates, not keywords quoted in a legitimate post."""
    if not str(html or "").strip():
        raise CollectionFailure("parse", "empty document; availability is unconfirmed")
    lowered = html.lower()
    title_match = re.search(r"<title[^>]*>(.*?)</title>", lowered, re.S)
    title = re.sub(r"<[^>]+>", " ", title_match.group(1)).strip() if title_match else ""
    template = _ErrorTemplate()
    template.feed(html)
    has_post = bool("".join(template.post_text).strip())
    if not has_post and (template.challenge or title in {
        "just a moment...", "checking your browser", "attention required! | cloudflare", "verify you are human",
    }):
        raise CollectionFailure("blocked", "browser verification page returned", scope="site")
    login_title = bool(re.search(r"(^|[-|:])\s*(log[ -]?in|sign[ -]?in|登录)\s*$", title))
    if template.password and not has_post and (login_title or template.template == "login" or template.login_form):
        raise CollectionFailure("auth_required", "source returned its login form", scope="site")
    panel = " ".join(template.error_text).lower()
    if not "".join(template.post_text).strip():
        if any(phrase in panel for phrase in (
            "do not have permission", "you must be logged", "you must be registered",
            "not have permission", "insufficient privileges",
        )):
            raise CollectionFailure("restricted", "source returned its permission error template")
        if any(phrase in panel for phrase in (
            "specified thread does not exist", "specified thread could not be found",
            "requested thread could not be found", "requested thread does not exist",
            "requested page could not be found", "requested post could not be found",
        )):
            raise CollectionFailure("unavailable", "source returned its explicit missing-content template")
    # These markers are supplied by each adapter and must identify its error container.
    if any(marker.lower() in lowered for marker in missing_markers):
        raise CollectionFailure("unavailable", "site returned its explicit unavailable template")


def classify_failure(error: Exception) -> CollectionFailure:
    if isinstance(error, CollectionFailure):
        return error
    from darkweb_collector.site_auth import SiteAuthenticationRequired
    if isinstance(error, SiteAuthenticationRequired):
        return CollectionFailure("auth_required", str(error), scope="site")
    name = type(error).__name__.lower()
    message = str(error).lower()
    if "timeout" in name or "timed out" in message or "timeout" in message:
        return CollectionFailure("timeout", "collection operation timed out")
    if any(part in name for part in ("proxyfetch", "torfetch", "connectionerror")):
        return CollectionFailure("network", "source connection failed")
    if any(part in name for part in ("operationalerror", "interfaceerror", "poolerror")):
        return CollectionFailure("infrastructure", "collection storage or message service unavailable", scope="site")
    if isinstance(error, (ValueError, TypeError, KeyError)):
        return CollectionFailure("parse", "document did not match the expected source schema")
    if isinstance(error, OSError):
        return CollectionFailure("infrastructure", "collection runtime or artifact storage failed", scope="site")
    return CollectionFailure("unknown", "collection failed without a confirmed availability reason")
