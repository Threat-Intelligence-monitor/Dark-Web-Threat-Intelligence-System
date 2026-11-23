"""Access-bypass layer for protected sources.

The sources this collector monitors sit behind anti-automation edges
(Cloudflare, DDoS-Guard, Akamai, Imperva) and, for the logged-in forums, behind
a session.  Before this package every adapter retried the same blocked request
with a new random ``User-Agent`` and called it a bypass; the measured result was
that a plain HTTP client is answered with a challenge page no matter which UA it
claims, because the *TLS/HTTP2 fingerprint* is what the edge scores.

The package is split by concern so a failure can be attributed:

``model``
    :class:`BypassProfile` (per-source policy) and :class:`ProtectionSignal`
    (per-response verdict).
``detect``
    Recognise an interstitial from one response: strong markers only, so a
    forum page that merely mentions Cloudflare is not misread as a challenge.
``headers``
    Browser-consistent header sets (client hints, ``Sec-Fetch-*``, UA family).
``clearance``
    Persist and replay ``cf_clearance``/``__ddg*`` cookies, bound to the UA
    family and egress path that earned them.
``pacing``
    Jittered per-host interval and penalty windows after a ``429``.
``httpfetch``
    The impersonated HTTP route (``curl_cffi``), with a ``curl.exe`` fallback.
``stealth``
    Playwright launch flags, context options and init scripts.
``challenge``
    Wait out / interact with an interstitial in a real browser.
``profiles``
    Resolution from site key, host, ``bypass_profiles.yaml`` and ``sites.yaml``.
``probe``
    CLI that reports which route currently works for a source.

The layer never raises a new exception family: it raises the collector's
:class:`~darkweb_collector.collection_errors.CollectionFailure` with the kinds
the adapters already schedule on (``blocked``, ``rate_limited``,
``auth_required``, ``timeout``, ``network``).  ``blocked`` is deliberately left
non-terminal in the adapters, which is what makes HTTP-then-browser fallback
work without new scheduling code.
"""

from __future__ import annotations

from typing import Any, Mapping

from darkweb_collector.access_bypass.model import BypassOutcome, BypassProfile, ProtectionSignal
from darkweb_collector.access_bypass.detect import classify_html, classify_response, document_title
from darkweb_collector.access_bypass.headers import build_headers, identity_for
from darkweb_collector.access_bypass import clearance, pacing, profiles, stealth

__all__ = [
    "BypassOutcome",
    "BypassProfile",
    "ProtectionSignal",
    "build_headers",
    "classify_html",
    "classify_response",
    "clearance",
    "document_title",
    "identity_for",
    "pacing",
    "profile_for",
    "profiles",
    "stealth",
    "usable_routes",
]


def profile_for(site_key: str | None = None, *, url: str = "",
                extras: Mapping[str, Any] | None = None) -> BypassProfile:
    """Convenience wrapper around :func:`profiles.profile_for`."""

    return profiles.profile_for(site_key, url=url, extras=extras)


def usable_routes(profile: BypassProfile) -> tuple[str, ...]:
    """Routes worth trying for ``profile``, cheapest first."""

    routes: list[str] = []
    if profile.http_strategy in {"auto", "impersonate"}:
        routes.append("impersonate")
    elif profile.http_strategy == "curl":
        routes.append("curl")
    if profile.browser_route_enabled and "browser" not in routes:
        routes.append("browser")
    if not routes:
        routes.append("curl")
    return tuple(routes)
