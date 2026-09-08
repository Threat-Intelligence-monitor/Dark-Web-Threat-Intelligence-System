from __future__ import annotations

from datetime import datetime
import re

from darkweb_collector.normalize import content_hash
from darkweb_collector.sites.pwnfrm import (
    _clean_html_text,
    normalize_pwnfrm_timestamp,
    parse_pwnfrm_detail,
    parse_pwnfrm_list,
)


FORUM_SECTIONS = {
    "databases": "https://bf.st/Forum-Databases?sortby=started&order=desc&datecut=9999",
    "other_leaks": "https://bf.st/Forum-Other-Leaks?sortby=started&order=desc&datecut=9999",
    "leaks_market": "https://bf.st/Forum-Leaks-Market?sortby=started&order=desc&datecut=9999",
    "sellers_place": "https://bf.st/Forum-Sellers-Place?sortby=started&order=desc&datecut=9999",
}


def normalize_breachforums_timestamp(value: str | None, *, collected_at_utc: str | None = None) -> str:
    raw = _clean_html_text(value or "")
    match = re.search(r"\b[A-Za-z]{3,9}\s+\d{1,2},\s*\d{4}\b", raw)
    if match:
        for pattern in ("%b %d, %Y", "%B %d, %Y"):
            try:
                return datetime.strptime(match.group(0), pattern).date().isoformat()
            except ValueError:
                continue
    return normalize_pwnfrm_timestamp(raw, collected_at_utc=collected_at_utc)


def parse_breachforums_list(url: str, html: str, max_topics: int = 20) -> dict:
    normal = re.search(
        r'<td\b[^>]*class="[^"]*\btcat\b[^"]*"[^>]*>\s*Normal Threads\s*</td>',
        html, re.IGNORECASE,
    )
    listing = html
    if normal:
        title = re.search(r"<title>.*?</title>", html, re.IGNORECASE | re.DOTALL)
        listing = (title.group(0) if title else "") + html[normal.end():]
    return parse_pwnfrm_list(url, listing, max_topics=max_topics, site_name="breachforums")


def parse_breachforums_detail(url: str, html: str) -> dict:
    posts = list(re.finditer(r'<div\b[^>]*\bid=[\'"]post_\d+[\'"][^>]*>', html, re.IGNORECASE))
    scoped_html = html
    if posts:
        title = re.search(r"<title>.*?</title>", html, re.IGNORECASE | re.DOTALL)
        end = posts[1].start() if len(posts) > 1 else len(html)
        scoped_html = (title.group(0) if title else "") + html[posts[0].start():end]
    scoped_html = re.sub(r"<(script|style)\b[^>]*>.*?</\1>", " ", scoped_html, flags=re.IGNORECASE | re.DOTALL)
    detail = parse_pwnfrm_detail(url, scoped_html, site_name="breachforums")
    detail["published_at_utc"] = normalize_breachforums_timestamp(
        detail.get("timestamp"), collected_at_utc=detail["collected_at_utc"],
    )
    detail["content_hash"] = content_hash(detail["content"], detail["author"])
    return detail


def get_breachforums_sections() -> dict[str, str]:
    return dict(FORUM_SECTIONS)
