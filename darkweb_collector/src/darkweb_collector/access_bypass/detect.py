"""Detection of anti-automation edges from a single HTTP response.

Only *strong* markers count.  A forum page whose header links to a login page,
or whose post body discusses Cloudflare, must never be classified as a
challenge: the collector's failure taxonomy (``blocked``, ``rate_limited``,
``auth_required``) triggers cooldowns, so a false positive costs real time.

Markers therefore have to come from one of three places:

* a response header the edge sets on purpose (``cf-mitigated``, ``x-iinfo``
  together with a 4xx status);
* a challenge script/id that only exists on an interstitial
  (``window._cf_chl_opt``, ``/cdn-cgi/challenge-platform/``);
* an exact interstitial title, or a title prefix for white-labelled pages
  (``Checking your browser | DarkForums``).
"""

from __future__ import annotations

import re
from typing import Any, Iterable, Mapping

from darkweb_collector.access_bypass.model import ProtectionSignal

#: Titles (lower-cased, stripped) that only challenge pages use.
CHALLENGE_TITLES: dict[str, tuple[str, str]] = {
    "just a moment...": ("cloudflare", "js"),
    "just a moment": ("cloudflare", "js"),
    "attention required! | cloudflare": ("cloudflare", "js"),
    "cloudflare - browser check": ("cloudflare", "js"),
    "verify you are human": ("cloudflare", "turnstile"),
    "one more step": ("cloudflare", "js"),
    "ddos-guard": ("ddos-guard", "ddos-guard"),
    "checking your browser": ("cloudflare", "js"),
    "checking your browser...": ("cloudflare", "js"),
    "security check": ("cloudflare", "managed"),
    "access denied": ("", ""),
}

#: Title prefixes used by white-labelled challenge pages.  Edge vendors let a
#: site append its own name, so these are prefixes, not exact matches:
#: ``One More Step - Browser Check | XForums`` is still a challenge.
CHALLENGE_TITLE_PREFIXES: tuple[tuple[str, str, str], ...] = (
    ("checking your browser", "cloudflare", "js"),
    ("just a moment", "cloudflare", "js"),
    ("one more step", "cloudflare", "js"),
    ("browser check", "cloudflare", "managed"),
    ("verify you are human", "cloudflare", "turnstile"),
    ("ddos-guard", "ddos-guard", "ddos-guard"),
    ("security verification", "cloudflare", "managed"),
    ("attention required", "cloudflare", "js"),
)

#: ``(marker, vendor, challenge)`` triples searched in the document text.
CHALLENGE_MARKERS: tuple[tuple[str, str, str], ...] = (
    ("window._cf_chl_opt", "cloudflare", "js"),
    ("_cf_chl_opt", "cloudflare", "js"),
    ("/cdn-cgi/challenge-platform/", "cloudflare", "js"),
    ("cf-challenge", "cloudflare", "js"),
    ("id=\"challenge-form\"", "cloudflare", "js"),
    ("cf-turnstile", "cloudflare", "turnstile"),
    ("challenges.cloudflare.com/turnstile", "cloudflare", "turnstile"),
    ("challenges.cloudflare.com/cdn-cgi/challenge-platform", "cloudflare", "managed"),
    ("enable javascript and cookies to continue", "cloudflare", "js"),
    ("check.ddos-guard.net", "ddos-guard", "ddos-guard"),
    ("__ddg", "ddos-guard", "ddos-guard"),
    ("ddos-guard.net", "ddos-guard", "ddos-guard"),
    ("_incapsula_resource", "incapsula", "incapsula"),
    ("incapsula incident id", "incapsula", "incapsula"),
    ("bm-verify", "akamai", "akamai"),
    ("sec-if-cpt-container", "akamai", "akamai"),
    ("_abck", "akamai", "akamai"),
    ("awswaf.com", "aws-waf", "unknown"),
    ("aws-waf-token", "aws-waf", "unknown"),
)

#: Markers that mean "an interactive captcha widget was rendered".
CAPTCHA_WIDGET_MARKERS: tuple[tuple[str, str], ...] = (
    ("hcaptcha.com/1/api.js", "hcaptcha"),
    ("h-captcha", "hcaptcha"),
    ("recaptcha/api.js", "recaptcha"),
    ("g-recaptcha", "recaptcha"),
)

#: Cookies an edge issues once a challenge has been passed.
CLEARANCE_COOKIE_PREFIXES: tuple[str, ...] = (
    "cf_clearance",
    "__cf_bm",
    "__cflb",
    "cf_chl_",
    "cf_chl_prog",
    "cf_chl_2",
    "__ddg",
    "ddg",
    "incap_ses_",
    "visid_incap_",
    "ak_bmsc",
    "bm_sz",
    "_abck",
    "aws-waf-token",
)

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
_PASSWORD_INPUT_RE = re.compile(r"<input[^>]+type\s*=\s*[\"']?password", re.I)
_WS_RE = re.compile(r"\s+")
_SCRIPT_STYLE_RE = re.compile(r"<(script|style|noscript|template)\b[^>]*>.*?</\1\s*>", re.I | re.S)
_TAG_RE = re.compile(r"<[^>]+>")

#: Documents larger than this are content pages, not interstitials.  Edge
#: challenge documents are tens of KB at most, though a white-labelled page can
#: inline a large script bundle -- which is why the visible-text budget below,
#: not this byte ceiling, is the real gate.
_INTERSTITIAL_MAX_BYTES = 900_000

#: Visible characters an interstitial may have.  A challenge page is a heading
#: plus a sentence; a forum listing or thread has thousands of characters.  This
#: is the load-bearing heuristic: Cloudflare injects
#: ``/cdn-cgi/challenge-platform/`` into ordinary pages for bot management, so a
#: marker alone proves nothing about the *page* we received.
_INTERSTITIAL_MAX_TEXT = 6_000


def _text(value: Any) -> str:
    return "" if value is None else str(value)


def document_title(html: str | None) -> str:
    """Return the normalised ``<title>`` text, whitespace collapsed."""

    match = _TITLE_RE.search(_text(html))
    if not match:
        return ""
    return _WS_RE.sub(" ", re.sub(r"<[^>]+>", " ", match.group(1))).strip()


def _header(headers: Mapping[str, Any] | None, name: str) -> str:
    if not headers:
        return ""
    lowered = name.lower()
    for key, value in headers.items():
        if str(key).lower() == lowered:
            return _text(value).strip()
    return ""


def retry_after_seconds(headers: Mapping[str, Any] | None) -> float:
    """Parse ``Retry-After``/``X-RateLimit-Reset`` into seconds from now."""

    if not headers:
        return 0.0
    raw = _header(headers, "retry-after")
    if raw:
        try:
            return max(0.0, float(raw))
        except ValueError:
            pass
        try:
            from email.utils import parsedate_to_datetime
            from datetime import datetime, timezone

            when = parsedate_to_datetime(raw)
            if when.tzinfo is None:
                when = when.replace(tzinfo=timezone.utc)
            return max(0.0, (when - datetime.now(timezone.utc)).total_seconds())
        except Exception:
            pass
    return 0.0


def has_clearance_cookie(cookies: Iterable[Mapping[str, Any]] | None) -> bool:
    for cookie in cookies or ():
        name = _text(cookie.get("name") if isinstance(cookie, Mapping) else None).lower()
        if name and any(name.startswith(prefix) or name == prefix for prefix in CLEARANCE_COOKIE_PREFIXES):
            return True
    return False


def clearance_cookie_names(cookies: Iterable[Mapping[str, Any]] | None) -> tuple[str, ...]:
    names: list[str] = []
    for cookie in cookies or ():
        if not isinstance(cookie, Mapping):
            continue
        name = _text(cookie.get("name")).lower()
        if not name:
            continue
        if any(name.startswith(prefix) or name == prefix for prefix in CLEARANCE_COOKIE_PREFIXES):
            if name not in names:
                names.append(name)
    return tuple(names)


def classify_html(html: str | None, *, status: int = 0) -> ProtectionSignal:
    """Classify a document without response headers.

    Used by the probe and by tests; :func:`classify_response` adds the
    header-only signals that are not visible in the body.
    """

    body = _text(html)
    return _classify(status, None, body)


def classify_response(status: int, headers: Mapping[str, Any] | None,
                      html: str | None) -> ProtectionSignal:
    """Classify one HTTP response into a :class:`ProtectionSignal`."""

    return _classify(int(status or 0), headers, _text(html))


def _classify(status: int, headers: Mapping[str, Any] | None, html: str) -> ProtectionSignal:
    head = html[:_INTERSTITIAL_MAX_BYTES]
    lowered = head.lower()
    title = document_title(html).lower()

    # 1. Header verdicts.  ``cf-mitigated`` is Cloudflare telling us directly
    #    that the request was answered by the challenge engine.
    mitigated = _header(headers, "cf-mitigated").lower()
    if mitigated in {"challenge", "managed_challenge", "jschallenge"}:
        challenge = "managed" if mitigated != "jschallenge" else "js"
        return ProtectionSignal("challenge", "cloudflare", challenge, status,
                                ("header:cf-mitigated=" + mitigated,))
    if mitigated == "block":
        return ProtectionSignal("forbidden", "cloudflare", "", status, ("header:cf-mitigated=block",))

    if _header(headers, "x-amzn-waf-action").lower() in {"challenge", "captcha"}:
        return ProtectionSignal("challenge", "aws-waf", "unknown", status, ("header:x-amzn-waf-action",))

    content_markers = _has_content_markers(lowered)
    text_chars = _visible_text_length(head, _INTERSTITIAL_MAX_TEXT + 1)
    interstitial = (
        len(head) < _INTERSTITIAL_MAX_BYTES
        and text_chars <= _INTERSTITIAL_MAX_TEXT
        and not content_markers
    )

    # 2. Titles of known interstitials.  A challenge title is about as reliable
    #    as the ``cf-mitigated`` header, so it outranks the body markers; the
    #    content-marker veto only guards against a page that merely embeds the
    #    phrase (e.g. a quoted error message).
    if title:
        exact = CHALLENGE_TITLES.get(title)
        if exact and exact[0] and not content_markers:
            return ProtectionSignal("challenge", exact[0], exact[1], status, (f"title:{title}",))
        for prefix, vendor, challenge in CHALLENGE_TITLE_PREFIXES:
            if title.startswith(prefix) and not content_markers:
                return ProtectionSignal("challenge", vendor, challenge, status, (f"title:{title}",))

    # 3. Interactive captcha widgets.  These also appear on legitimate login
    #    forms, so they only count when the response is a block or when the
    #    document is an interstitial with no forum content.
    widget = _captcha_widget(lowered)
    if widget and (status in {403, 503} or interstitial):
        if status in {403, 503}:
            return ProtectionSignal("challenge", widget, "image-captcha", status, (f"widget:{widget}",))
        return ProtectionSignal("challenge", "cloudflare" if widget == "hcaptcha" else widget,
                                "managed", status, (f"widget:{widget}",))

    # 4. Challenge scripts/ids in the body.  Gated on the interstitial shape:
    #    Cloudflare ships ``/cdn-cgi/challenge-platform/`` inside ordinary pages
    #    for bot management, so the marker alone is not evidence.
    for marker, vendor, challenge in CHALLENGE_MARKERS:
        if marker in lowered and interstitial:
            return ProtectionSignal("challenge", vendor, challenge, status, (f"marker:{marker}",))

    # 5. Rate limiting.
    if status == 429:
        return ProtectionSignal("rate-limit", "", "", status, ("status:429",),
                                retry_after_seconds(headers))
    if status == 503 and ("rate limit" in lowered or "too many requests" in lowered
                          or "temporarily unavailable" in lowered):
        return ProtectionSignal("rate-limit", "", "", status, ("status:503",),
                                retry_after_seconds(headers))

    # 6. Login wall: a password form is the main template, not a header link.
    if _password_input(lowered) and interstitial:
        return ProtectionSignal("login", "site", "", status, ("form:password",))

    # 7. A bare 401/403 with nothing else is still a refusal, not a challenge.
    if status == 401:
        return ProtectionSignal("login", "site", "", status, ("status:401",))
    if status == 403:
        return ProtectionSignal("forbidden", "", "", status, ("status:403",))

    return ProtectionSignal("none", "", "", status)


def _visible_text_length(html: str, limit: int) -> int:
    """Count visible characters, stopping once ``limit`` is exceeded.

    Scripts, styles and tags are noise; what distinguishes an interstitial from
    a forum page is how much prose a human would see.
    """

    stripped = _SCRIPT_STYLE_RE.sub(" ", html)
    text = _WS_RE.sub(" ", _TAG_RE.sub(" ", stripped)).strip()
    return min(len(text), limit)


def _captcha_widget(lowered: str) -> str:
    for marker, vendor in CAPTCHA_WIDGET_MARKERS:
        if marker in lowered:
            return vendor
    return ""


def _password_input(lowered: str) -> bool:
    return bool(_PASSWORD_INPUT_RE.search(lowered))


#: Structural markers of a served forum/content document, quote-free so that
#: both ``class="trow"`` and ``class='trow'`` (and unquoted attributes) match.
_CONTENT_MARKERS = (
    "id=posts", "post_body", "post_content", "post classic",
    "class=post", "thread-info", "forumdisplay", "showthread",
    "message-body", "js-postlisthandle", "structitem",
    "class=forumbit", "class=forums", "class=thead", "class=trow",
    "class=navigation", "class=pagination", "data-template-name",
    "id=footer",
)


def _has_content_markers(lowered: str) -> bool:
    """True when the document is a real forum/content page.

    Challenge interstitials never contain a listing/thread structure, so the
    presence of one of these markers vetoes the title/widget guesses.  The
    listing markers matter as much as the thread ones: a blocked *index* page
    is still refused, but a served index must not be mistaken for a challenge.

    Quotes are stripped before matching: MyBB and XenForo skins mix
    ``class="trow"`` with ``class='trow'``, and a quote-sensitive marker table
    silently misses half of them (which is exactly how a real DarkForums index
    was first misread as a challenge page).
    """

    flat = lowered.replace('"', "").replace("'", "")
    return any(marker in flat for marker in _CONTENT_MARKERS)
