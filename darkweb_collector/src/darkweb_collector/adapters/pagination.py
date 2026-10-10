from __future__ import annotations

import hashlib
import re
from html import unescape
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

from darkweb_collector.crawl_frontier import count_frontier_pending, load_page_cursor
from darkweb_collector.db import get_db_connection
from darkweb_collector.models import SeedResult, SiteConfig
from darkweb_collector.utils import utc_now_iso


def forum_page_url(source_url: str, page: int) -> str:
    parsed = urlsplit(source_url)
    query = [(key, value) for key, value in parse_qsl(parsed.query, keep_blank_values=True) if key.lower() != "page"]
    if page > 1:
        query.append(("page", str(page)))
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(query), parsed.fragment))


def is_forum_listing_html(html: str) -> bool:
    lowered = str(html or "").lower()
    if not lowered or any(marker in lowered for marker in (
        "checking your browser", "cf-browser-verification", "verify you are human",
    )):
        return False
    has_topics = "thread-" in lowered or "subject_new" in lowered or "subject_old" in lowered
    empty_list = any(marker in lowered for marker in (
        "forumdisplay_nothreads", "forumdisplay_no_threads", "there are no threads",
        "there are either no threads", "no threads were found",
    ))
    return ("forum-" in lowered or "forumdisplay" in lowered) and (has_topics or empty_list)


def _forum_pagination(html: str, url: str, page: int, source_count: int) -> bool:
    current = re.search(
        r'<[^>]+(?:class=[\'"][^\'"]*pagination_current[^\'"]*[\'"]|aria-current=[\'"]page[\'"])[^>]*>\s*(\d+)',
        html, re.IGNORECASE,
    )
    if current and int(current.group(1)) != page:
        raise RuntimeError("forum pagination did not advance to the requested page")
    page_numbers: list[int] = []
    has_next = False
    for attributes in re.findall(r'<a\b([^>]+)>', html, re.IGNORECASE):
        href_match = re.search(r'\bhref=[\'"]([^\'"]+)[\'"]', attributes, re.IGNORECASE)
        if not href_match:
            continue
        target = urlsplit(urljoin(url, unescape(href_match.group(1))))
        base = urlsplit(url)
        if target.netloc != base.netloc:
            continue
        is_page_link = "pagination_" in attributes.lower() or target.path == base.path
        if not is_page_link:
            continue
        query = dict(parse_qsl(target.query))
        number = str(query.get("page") or "")
        if not number:
            match = re.search(r'(?:-page-|/page/)(\d+)', target.path)
            number = match.group(1) if match else ""
        if number.isdigit():
            page_numbers.append(int(number))
        if "pagination_next" in attributes.lower() or re.search(r'\brel=[\'"]next[\'"]', attributes, re.IGNORECASE):
            has_next = True
    if has_next or any(number > page for number in page_numbers):
        return True
    if current or page_numbers:
        return False
    # Without reliable navigation, an extra page is safer than treating a
    # parser's topic cap (or an all-filtered page) as the site's last page.
    return source_count > 0


def collect_forum_seed(adapter, config: SiteConfig, list_parser, section_name) -> SeedResult:
    def fetch_page(source_url: str, page: int, collected_at: str):
        url = forum_page_url(source_url, page)
        html = adapter._fetch_html(url, config, config.seed_fetch_mode)
        if not is_forum_listing_html(html):
            raise RuntimeError("forum listing is unavailable or contains no recognized list")
        identifiers = sorted(set(re.findall(r'\bid=[\'"]tid_(\d+)[\'"]', html, re.IGNORECASE)))
        parsed = list_parser(url, html, max_topics=max(1, len(identifiers)))
        if identifiers and not parsed["topics"]:
            raise RuntimeError("forum topic markers could not be parsed")
        if not identifiers and re.search(r'(?:Thread-|subject_(?:new|old))', html, re.IGNORECASE):
            raise RuntimeError("forum listing has no recognized topic identifiers")
        parsed["section"] = section_name(source_url)
        parsed["collected_at_utc"] = collected_at
        parsed["source_count"] = len(identifiers)
        signature = hashlib.sha256("\n".join(identifiers).encode("utf-8")).hexdigest()
        more = _forum_pagination(html, url, page, len(identifiers))
        return parsed, html, more, signature, url

    return collect_paginated_seed(adapter.site_name, config, fetch_page, plan_details=adapter.plan_details)


def collect_paginated_seed(site_name: str, config: SiteConfig, fetch_page, *, plan_details=None) -> SeedResult:
    """Read recent pages and a bounded, fair slice of persisted backfill cursors.

    fetch_page returns (parsed_section, raw_page, has_more, id_signature, url).
    Cursor updates are returned for the caller to save after candidates persist.
    """
    collected_at = utc_now_iso()
    recent_pages = max(1, int(config.extras.get("recent_pages_per_run", 1)))
    budget = max(0, int(config.extras.get("backfill_pages_per_run", 5)))
    limit = max(1, int(config.extras.get("frontier_max_pending", 500)))
    with get_db_connection() as connection:
        pending = count_frontier_pending(connection, site_name)
        cursors = {url: load_page_cursor(connection, site_name, url) for url in config.seed_urls}
    capacity = max(0, min(limit, config.frontier_dispatch_window, config.max_detail_pages_per_run) - pending)
    budget = min(budget, capacity)
    sections: dict[str, dict] = {}
    raw_pages: dict[str, str] = {}
    updates: dict[str, dict] = {}
    errors: list[dict] = []
    blocked: set[str] = set()
    seen_topics: set[str] = set()
    signatures: dict[str, set[str]] = {url: set() for url in config.seed_urls}
    pages_scanned = 0

    def result() -> SeedResult:
        return SeedResult(
            site_name=site_name, collected_at_utc=collected_at,
            payload={"site_name": site_name, "source_url": site_name, "collected_at_utc": collected_at,
                     "section_count": len(sections), "topic_count": len(seen_topics), "sections": list(sections.values())},
            raw_html_by_url=raw_pages,
            metadata={"cursor_updates": list(updates.values()), "pagination_errors": errors,
                      "pages_scanned": pages_scanned, "backfill_paused": pending >= min(limit, config.frontier_dispatch_window)},
        )

    def candidate_count() -> int:
        return len(plan_details(result(), config)) if plan_details is not None and sections else 0

    def record_cursor(url: str, next_page: int, signature: str, completed: bool = False):
        # Preserve last-visit order so the next run starts with the least
        # recently visited section even when the budget is smaller than it.
        updates.pop(url, None)
        updates[url] = {
            "source_url": url, "next_page": next_page,
            "last_signature": signature, "completed_at": collected_at if completed else "",
        }

    def visit(url: str, page: int, lane: str) -> bool:
        nonlocal pages_scanned
        try:
            parsed, raw, more, signature, page_url = fetch_page(url, page, collected_at)
            previous = str(cursors[url].get("last_signature") or "")
            if lane == "backfill" and parsed.get("source_count", len(parsed["topics"])) and (
                signature in signatures[url] or (previous and signature == previous)
            ):
                raise RuntimeError("pagination returned a previously visited page")
        except Exception as exc:
            errors.append({"source_url": url, "page": page, "lane": lane, "error_type": type(exc).__name__})
            blocked.add(url)
            return False
        pages_scanned += 1
        signatures[url].add(signature)
        raw_pages[page_url] = raw
        raw_pages.setdefault(url, raw)
        if url not in sections:
            sections[url] = {**parsed, "source_url": url, "topics": [], "pages": []}
        section = sections[url]
        for topic in parsed["topics"]:
            topic_url = str(topic["full_url"])
            if topic_url in seen_topics:
                continue
            seen_topics.add(topic_url)
            section["topics"].append({**topic, "section": section["section"], "discovery_lane": lane})
        section["topic_count"] = len(section["topics"])
        section["pages"].append({
            "page": page, "lane": lane, "source_url": page_url,
            "topic_count": len(parsed["topics"]), "source_count": parsed.get("source_count", len(parsed["topics"])),
        })
        if not more:
            blocked.add(url)
            record_cursor(url, max(page + 1, int(cursors[url].get("next_page") or 2)), signature, completed=True)
        elif lane == "backfill":
            record_cursor(url, page + 1, signature)
        return True

    for url in config.seed_urls:
        for page in range(1, recent_pages + 1):
            if not visit(url, page, "recent") or url in blocked:
                break

    recent_candidates = candidate_count()
    if recent_candidates:
        budget = 0
    active = sorted(
        (url for url in config.seed_urls if url not in blocked and not cursors[url].get("completed_at")),
        key=lambda url: (float(cursors[url].get("updated_at") or 0), int(cursors[url].get("next_page") or 2)),
    )
    next_pages = {
        url: max(recent_pages + 1, int(cursors[url].get("next_page") or 2)) for url in active
    }
    discovered = recent_candidates
    while budget and active and discovered < capacity:
        following: list[str] = []
        for url in active:
            if not budget or discovered >= capacity:
                break
            budget -= 1
            page = next_pages[url]
            if visit(url, page, "backfill") and url not in blocked:
                next_pages[url] = page + 1
                following.append(url)
            discovered = candidate_count()
        active = following
    if not pages_scanned and errors:
        raise RuntimeError(f"{site_name}: every listing request failed")
    seed_result = result()
    seed_result.metadata["backfill_paused"] = bool(recent_candidates or pending + discovered >= min(limit, config.frontier_dispatch_window))
    return seed_result
