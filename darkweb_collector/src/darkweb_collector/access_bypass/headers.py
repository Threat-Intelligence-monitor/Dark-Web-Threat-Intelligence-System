"""Browser-consistent request headers.

An edge in front of the source compares the headers it receives with the TLS
fingerprint it observed.  A Chrome JA3 with ``Accept: */*`` and no
``Sec-Fetch-*`` is an obvious bot, so the header set has to be generated from
the same browser identity that the transport claims to be.

Two rules keep this honest:

* a Firefox identity never sends ``Sec-CH-UA-*`` (Firefox does not implement
  client hints), and
* the ``User-Agent`` is only emitted when the caller supplies one.  On the
  ``curl_cffi`` route the impersonation target picks the UA; overriding it with
  an unrelated version would make the Fingerprint *less* consistent, not more.
"""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any, Mapping
from urllib.parse import urlsplit

#: Chrome majors that shipped with the matching TLS profile in curl_cffi.
CHROME_MAJOR_BY_IMPERSONATE: dict[str, str] = {
    "chrome": "136",
    "chrome99": "99",
    "chrome100": "100",
    "chrome101": "101",
    "chrome104": "104",
    "chrome107": "107",
    "chrome110": "110",
    "chrome116": "116",
    "chrome119": "119",
    "chrome120": "120",
    "chrome123": "123",
    "chrome124": "124",
    "chrome131": "131",
    "chrome133a": "133",
    "chrome136": "136",
    "edge99": "99",
    "edge101": "101",
}

CHROME_MAJOR_RE = re.compile(r"Chrome/(\d+)", re.I)
FIREFOX_RE = re.compile(r"Firefox/(\d+)", re.I)

#: ``(brand, version)`` order used by Chrome's GREASE-y client hint string.
_CHROME_BRAND_ORDER = ('"Chromium";v="{major}"', '"Google Chrome";v="{major}"', '"Not_A Brand";v="24"')
_EDGE_BRAND_ORDER = ('"Chromium";v="{major}"', '"Microsoft Edge";v="{major}"', '"Not_A Brand";v="24"')
_CHROME_MAJOR_GREASE = {"135": "25", "136": "24", "137": "24", "138": "24", "139": "24", "140": "24", "141": "24"}

_LANGUAGES: dict[str, str] = {
    "en": "en-US,en;q=0.9",
    "en-gb": "en-GB,en;q=0.9,en-US;q=0.8",
    "de": "de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7",
    "ru": "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7",
    "zh": "zh-CN,zh;q=0.9,en;q=0.8",
}

#: Windows UA strings per browser identity.  Version-pinned so a session's UA
#: stays stable across requests (an edge notices UA oscillation).
DEFAULT_USER_AGENTS: dict[str, str] = {
    "chrome": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
               "(KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36"),
    "edge": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
             "(KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36 Edg/136.0.0.0"),
    "firefox": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:140.0) "
                "Gecko/20100101 Firefox/140.0"),
    "safari": ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
               "(KHTML, like Gecko) Version/18.4 Safari/605.1.15"),
}

#: ``Accept`` for a top-level document navigation.
NAVIGATION_ACCEPT = ("text/html,application/xhtml+xml,application/xml;q=0.9,"
                     "image/avif,image/webp,image/apng,*/*;q=0.8")
#: ``Accept`` for an XHR/fetch that expects JSON (used by API probes).
JSON_ACCEPT = "application/json, text/plain, */*"


@dataclass(frozen=True)
class BrowserIdentity:
    """Everything needed to present one coherent browser on the HTTP route."""

    profile: str
    user_agent: str
    accept_language: str
    client_hints: bool
    chrome_major: str = ""

    @property
    def is_chrome_like(self) -> bool:
        return self.client_hints and bool(self.chrome_major)

    def sec_ch_ua(self) -> str:
        if not self.is_chrome_like:
            return ""
        brands = _EDGE_BRAND_ORDER if self.profile.startswith("edge") else _CHROME_BRAND_ORDER
        return ", ".join(brand.format(major=self.chrome_major) for brand in brands)


def identity_for(profile: str, *, impersonate: str = "", user_agent: str = "") -> BrowserIdentity:
    """Resolve a header identity from profile, impersonation target and UA.

    ``profile`` wins for the shape of the headers; the UA version is taken from
    ``user_agent`` when supplied (so a persisted browser session keeps its own
    UA) and otherwise from the impersonation target.
    """

    name = (profile or "chrome").strip().lower()
    agent = (user_agent or "").strip()
    if not agent:
        agent = DEFAULT_USER_AGENTS.get("edge" if name.startswith("edge") else name,
                                       DEFAULT_USER_AGENTS["chrome"])
    if name.startswith("edge"):
        name = "edge"
    elif name.startswith("firefox"):
        name = "firefox"
    elif name.startswith("safari"):
        name = "safari"
    else:
        name = "chrome"

    chrome_major = ""
    match = CHROME_MAJOR_RE.search(agent)
    if match:
        chrome_major = match.group(1)
    elif name in {"chrome", "edge"}:
        chrome_major = CHROME_MAJOR_BY_IMPERSONATE.get((impersonate or "chrome").lower(), "136")

    if name == "firefox":
        match = FIREFOX_RE.search(agent)
        if match:
            chrome_major = match.group(1)
    language = "en"
    return BrowserIdentity(
        profile=name,
        user_agent=agent,
        accept_language=_LANGUAGES[language],
        client_hints=name in {"chrome", "edge"},
        chrome_major=chrome_major,
    )


def build_headers(
    url: str,
    *,
    identity: BrowserIdentity | None = None,
    profile: str = "chrome",
    impersonate: str = "",
    user_agent: str = "",
    referer: str = "",
    accept: str = "",
    navigation: bool = True,
    extra: Mapping[str, Any] | None = None,
    include_user_agent: bool = True,
) -> dict[str, str]:
    """Build the navigation header set for ``url``.

    The result is ordered the way Chrome emits it (edge fingerprinters compare
    order as well as presence).
    """

    ident = identity or identity_for(profile, impersonate=impersonate, user_agent=user_agent)
    parts = urlsplit(url)
    origin = f"{parts.scheme}://{parts.netloc}" if parts.scheme and parts.netloc else ""
    headers: dict[str, str] = {}
    if include_user_agent and ident.user_agent:
        headers["User-Agent"] = ident.user_agent
    if ident.client_hints:
        sec_ch_ua = ident.sec_ch_ua()
        if sec_ch_ua:
            headers["sec-ch-ua"] = sec_ch_ua
            headers["sec-ch-ua-mobile"] = "?0"
            headers["sec-ch-ua-platform"] = '"Windows"' if "Windows" in ident.user_agent else '"macOS"'
    headers["Accept"] = accept or (NAVIGATION_ACCEPT if navigation else "*/*")
    headers["Accept-Language"] = ident.accept_language
    if referer:
        headers["Referer"] = referer
    else:
        # A direct navigation has no Referer; same-origin navigation passes the
        # page it came from.
        pass
    if navigation:
        headers["Upgrade-Insecure-Requests"] = "1"
        headers["Sec-Fetch-Dest"] = "document"
        headers["Sec-Fetch-Mode"] = "navigate"
        headers["Sec-Fetch-Site"] = "same-origin" if referer and origin and referer.startswith(origin) else "none"
        headers["Sec-Fetch-User"] = "?1"
    else:
        headers["Sec-Fetch-Dest"] = "empty"
        headers["Sec-Fetch-Mode"] = "cors"
        headers["Sec-Fetch-Site"] = "same-origin" if referer else "none"
        headers["Priority"] = "u=0, i"
    for name, value in (extra or {}).items():
        if value is None:
            continue
        headers[str(name)] = str(value)
    return headers


def browser_context_headers(identity: BrowserIdentity) -> dict[str, str]:
    """Extra HTTP headers for a Playwright context (client hints only).

    Playwright already sends the navigation headers itself; forcing them here
    would duplicate ``Accept``/``Sec-Fetch-*`` and look synthetic, so only the
    client hints that headless Chromium omits are added.
    """

    if not identity.client_hints:
        return {}
    sec_ch_ua = identity.sec_ch_ua()
    if not sec_ch_ua:
        return {}
    return {
        "sec-ch-ua": sec_ch_ua,
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"' if "Windows" in identity.user_agent else '"macOS"',
    }
