from __future__ import annotations

import re
import sys
import time
from datetime import datetime, timedelta, timezone
from html import unescape
from urllib.parse import urljoin, urlparse

from darkweb_collector.normalize import content_hash
from darkweb_collector.sites.darkforums import (
    raise_if_hidden_post,
    determine_industry,
    determine_region,
    extract_attackers_from_content,
    extract_victims_from_content,
)


CRACKED_BASE_URL = "https://cracked.st"


def _safe_print(value: object) -> None:
    encoding = getattr(sys.stdout, "encoding", None) or "utf-8"
    text = str(value).encode(encoding, errors="replace").decode(encoding, errors="replace")
    print(text)

FORUM_SECTIONS = {
    "other_leaks": (
        f"{CRACKED_BASE_URL}/Forum-Other-Leaks"
        "?sortby=started&order=desc&datecut=9999&prefix=0"
    ),
    "combolists": (
        f"{CRACKED_BASE_URL}/Forum-Combolists--297"
        "?sortby=started&order=desc&datecut=9999&prefix=0"
    ),
}

DETAIL_QUOTE_RE = re.compile(r"<blockquote[^>]*>.*?</blockquote>", re.IGNORECASE | re.DOTALL)
SCRIPT_STYLE_RE = re.compile(r"<(?:script|style)[^>]*>.*?</(?:script|style)>", re.IGNORECASE | re.DOTALL)
FIRST_POST_BLOCK_RE = re.compile(
    r'<div(?=[^>]*id="post_\d+")(?=[^>]*class="[^"]*post-set[^"]*")[^>]*>.*?'
    r'(?=<div(?=[^>]*id="post_\d+")(?=[^>]*class="[^"]*post-set[^"]*")|$)',
    re.IGNORECASE | re.DOTALL,
)
TOPIC_RE = re.compile(
    r'<span[^>]*class="[^"]*subject(?:_new|_old)?"[^>]*id="tid_(\d+)"[^>]*>'
    r'\s*<a href="(Thread-[^"]+)"[^>]*>(.*?)</a>',
    re.IGNORECASE | re.DOTALL,
)
LIST_AUTHOR_RE = re.compile(
    r'<div[^>]*class="[^"]*author[^"]*"[^>]*>.*?'
    r'<a[^>]*data-class=[\'"]profile_url[\'"][^>]*>(.*?)</a>',
    re.IGNORECASE | re.DOTALL,
)
THREAD_DATE_RE = re.compile(
    r'<span[^>]*class="[^"]*thread-date[^"]*"[^>]*>(.*?)</span>',
    re.IGNORECASE | re.DOTALL,
)
PROFILECARD_AUTHOR_RE = re.compile(
    r'<a[^>]*data-class=[\'"]profile_url[\'"][^>]*>(.*?)</a>',
    re.IGNORECASE | re.DOTALL,
)
THREAD_HEADER_AUTHOR_RE = re.compile(
    r'<span[^>]*class="[^"]*smalltext[^"]*"[^>]*>\s*by\s*<a[^>]*>(.*?)</a>',
    re.IGNORECASE | re.DOTALL,
)
THREAD_HEADER_TIMESTAMP_RE = re.compile(
    r'<span[^>]*class="[^"]*smalltext[^"]*"[^>]*>\s*by\s*<a[^>]*>.*?</a>\s*-\s*(.*?)\s*</span>',
    re.IGNORECASE | re.DOTALL,
)
POST_DATE_TITLE_RE = re.compile(
    r'<span[^>]*class="[^"]*post_date[^"]*"[^>]*>.*?'
    r'<span[^>]*title="[^"]*"[^>]*>(.*?)</span>\s*</span>',
    re.IGNORECASE | re.DOTALL,
)
POST_BODY_RE = re.compile(
    r'<div[^>]*class="[^"]*post_body[^"]*"[^>]*>(.*?)'
    r'(?=<div[^>]*class="[^"]*signature\b|<div[^>]*class="[^"]*post_controls|'
    r'<div(?=[^>]*id="post_\d+")(?=[^>]*class="[^"]*post-set[^"]*")|$)',
    re.IGNORECASE | re.DOTALL,
)
CRACKED_TEXTUAL_TIMESTAMP_RE = re.compile(
    r"(?P<day>\d{1,2})\s+(?P<month>[A-Za-z]{3,9}),?\s+(?P<year>\d{4})"
    r"(?:\s*-\s*(?P<hour>\d{1,2}):(?P<minute>\d{2})\s*(?P<ampm>AM|PM))?",
    re.IGNORECASE,
)
RELATIVE_TIMESTAMP_RE = re.compile(
    r"(?P<value>\d+)\s+"
    r"(?P<unit>minute|minutes|hour|hours|day|days|week|weeks|month|months|year|years)\s+ago",
    re.IGNORECASE,
)


def _clean_html_text(value: str) -> str:
    if not value:
        return ""
    value = DETAIL_QUOTE_RE.sub("", value)
    value = SCRIPT_STYLE_RE.sub(" ", value)
    value = re.sub(r"<[^>]+>", " ", value)
    value = unescape(value)
    value = re.sub(r"\s+", " ", value)
    return value.strip()


def _extract_domain(url: str) -> str:
    return urlparse(url).netloc


def _extract_victim_from_title(title: str) -> str:
    patterns = [
        r"([^|]+)\s*Database",
        r"([^|]+)\s*Leak",
        r"([^|]+)\s*Breached",
        r"([^|]+)\s*Dump",
        r"([^|]+)\s*Data",
    ]
    for pattern in patterns:
        match = re.search(pattern, title, re.IGNORECASE)
        if match:
            victim = match.group(1).strip()
            return re.sub(r"^(?:The|A|An)\s+", "", victim, flags=re.IGNORECASE)
    return ""


def _extract_row(html: str, start: int, end: int) -> str:
    row_start = html.rfind("<tr", 0, start)
    if row_start == -1:
        row_start = max(0, start - 2000)
    row_end = html.find("</tr>", end)
    if row_end == -1:
        row_end = min(len(html), end + 3000)
    else:
        row_end += len("</tr>")
    return html[row_start:row_end]


def _extract_stat(row_html: str, label: str) -> str:
    pattern = re.compile(
        r'<span[^>]*class="[^"]*stats-count[^"]*"[^>]*>(.*?)</span>\s*'
        r"<br\s*/?>\s*"
        r'<span[^>]*class="[^"]*stats-desc[^"]*"[^>]*>(.*?)</span>',
        re.IGNORECASE | re.DOTALL,
    )
    for match in pattern.finditer(row_html):
        if _clean_html_text(match.group(2)).lower() == label.lower():
            return _clean_html_text(match.group(1))
    return ""


def _extract_list_author(row_html: str) -> str:
    match = LIST_AUTHOR_RE.search(row_html)
    return _clean_html_text(match.group(1)) if match else ""


def _extract_list_timestamp(row_html: str) -> str:
    match = THREAD_DATE_RE.search(row_html)
    return _clean_html_text(match.group(1)) if match else ""


def _extract_author(post_block: str, html: str) -> str:
    for source in (post_block, html):
        for pattern in (PROFILECARD_AUTHOR_RE, THREAD_HEADER_AUTHOR_RE):
            match = pattern.search(source)
            if match:
                author = _clean_html_text(match.group(1))
                if author:
                    return author
    return "Unknown"


def _extract_timestamp_text(post_block: str, html: str) -> str:
    for source in (post_block, html):
        for pattern in (POST_DATE_TITLE_RE, THREAD_HEADER_TIMESTAMP_RE):
            match = pattern.search(source)
            if match:
                timestamp = _clean_html_text(match.group(1))
                if timestamp:
                    return timestamp

        cleaned = _clean_html_text(source)
        for regex in (CRACKED_TEXTUAL_TIMESTAMP_RE, RELATIVE_TIMESTAMP_RE):
            match = regex.search(cleaned)
            if match:
                return _clean_html_text(match.group(0))
    return ""


def _parse_reference_dt(value: str | None) -> datetime:
    raw = str(value or "").strip()
    if raw:
        try:
            dt = datetime.fromisoformat(raw)
        except ValueError:
            dt = None
        if dt is not None:
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
    return datetime.now(timezone.utc)


def normalize_cracked_timestamp(value: str | None, *, collected_at_utc: str | None = None) -> str:
    raw = _clean_html_text(value)
    if not raw:
        return ""

    reference_dt = _parse_reference_dt(collected_at_utc)

    match = CRACKED_TEXTUAL_TIMESTAMP_RE.search(raw)
    if match:
        date_raw = f"{match.group('day')} {match.group('month')} {match.group('year')}"
        parsed_dt = None
        for fmt in ("%d %B %Y", "%d %b %Y"):
            try:
                parsed_dt = datetime.strptime(date_raw, fmt)
                break
            except ValueError:
                continue
        if parsed_dt is not None:
            hour = int(match.group("hour") or 0)
            minute = int(match.group("minute") or 0)
            ampm = str(match.group("ampm") or "").upper()
            if ampm:
                hour = hour % 12
                if ampm == "PM":
                    hour += 12
            dt = parsed_dt.replace(hour=hour, minute=minute, tzinfo=timezone.utc)
            return dt.date().isoformat()

    lowered = raw.lower()
    if "yesterday" in lowered:
        return (reference_dt - timedelta(days=1)).date().isoformat()
    if "today" in lowered:
        return reference_dt.date().isoformat()

    match = RELATIVE_TIMESTAMP_RE.search(lowered)
    if match:
        value_num = int(match.group("value"))
        unit = match.group("unit").lower()
        if unit.startswith("minute"):
            delta = timedelta(minutes=value_num)
        elif unit.startswith("hour"):
            delta = timedelta(hours=value_num)
        elif unit.startswith("day"):
            delta = timedelta(days=value_num)
        elif unit.startswith("week"):
            delta = timedelta(weeks=value_num)
        elif unit.startswith("month"):
            delta = timedelta(days=30 * value_num)
        else:
            delta = timedelta(days=365 * value_num)
        return (reference_dt - delta).date().isoformat()

    return ""


def parse_cracked_list(url: str, html: str, max_topics: int = 5) -> dict:
    start_time = time.time()
    _safe_print(f"[{time.strftime('%H:%M:%S')}] [cracked] parsing list: {url}")

    title_match = re.search(r"<title>\s*(.*?)\s*</title>", html, re.IGNORECASE | re.DOTALL)
    title = _clean_html_text(title_match.group(1)) if title_match else ""
    domain = _extract_domain(url)

    topics: list[dict] = []
    seen_tids: set[str] = set()

    matches = list(TOPIC_RE.finditer(html))
    _safe_print(f"[{time.strftime('%H:%M:%S')}] [cracked] found {len(matches)} topic matches")

    for match in matches:
        tid, href, raw_title = match.groups()
        if tid in seen_tids:
            continue
        seen_tids.add(tid)

        clean_title = _clean_html_text(raw_title)
        if not clean_title:
            continue

        row_html = _extract_row(html, match.start(), match.end())
        detail_url = urljoin(url, href)
        topic = {
            "tid": tid,
            "title": clean_title,
            "relative_url": href,
            "full_url": detail_url,
            "author": _extract_list_author(row_html),
            "replies": _extract_stat(row_html, "Replies"),
            "views": _extract_stat(row_html, "Views"),
            "published_at": _extract_list_timestamp(row_html),
            "content_hash": content_hash(clean_title, tid),
            "potential_victim": _extract_victim_from_title(clean_title),
        }
        topics.append(topic)
        _safe_print(f"[{time.strftime('%H:%M:%S')}] [cracked] topic {len(topics)}: {clean_title[:70]}")

        if len(topics) >= max_topics:
            _safe_print(f"[{time.strftime('%H:%M:%S')}] [cracked] reached cap of {max_topics} topics")
            break

    elapsed = time.time() - start_time
    _safe_print(f"[{time.strftime('%H:%M:%S')}] [cracked] list parse done in {elapsed:.2f}s, {len(topics)} topics")

    return {
        "site_name": "cracked",
        "source_url": url,
        "domain": domain,
        "title": title,
        "collected_at_utc": datetime.now(timezone.utc).isoformat(),
        "topic_count": len(topics),
        "topics": topics,
    }


def parse_cracked_detail(url: str, html: str) -> dict:
    start_time = time.time()
    _safe_print(f"[{time.strftime('%H:%M:%S')}] [cracked] parsing detail: {url}")

    title_match = re.search(r"<title>\s*(.*?)\s*</title>", html, re.IGNORECASE | re.DOTALL)
    title = _clean_html_text(title_match.group(1)) if title_match else ""
    domain = _extract_domain(url)

    post_block_match = FIRST_POST_BLOCK_RE.search(html)
    post_block = post_block_match.group(0) if post_block_match else html

    content_match = POST_BODY_RE.search(post_block)
    content = _clean_html_text(content_match.group(1)) if content_match else ""
    raise_if_hidden_post(content, post_block)
    _safe_print(f"[{time.strftime('%H:%M:%S')}] [cracked] content length: {len(content)} chars")

    author = _extract_author(post_block, html)
    _safe_print(f"[{time.strftime('%H:%M:%S')}] [cracked] author: {author}")

    timestamp = _extract_timestamp_text(post_block, html)
    _safe_print(f"[{time.strftime('%H:%M:%S')}] [cracked] timestamp: {timestamp}")

    victims = extract_victims_from_content(content, title)
    attackers = extract_attackers_from_content(content)
    victim_info = [
        {
            "name": victim,
            "industry": determine_industry(victim, f"{title} {content}"),
            "region": determine_region(victim),
        }
        for victim in victims
    ]

    attachment_matches = re.findall(
        r'<a[^>]*href="([^"]+)"[^>]*class="[^"]*attachment[^"]*"[^>]*>',
        post_block,
        re.IGNORECASE,
    )
    attachments = [urljoin(url, match) for match in attachment_matches]

    elapsed = time.time() - start_time
    _safe_print(f"[{time.strftime('%H:%M:%S')}] [cracked] detail parse done in {elapsed:.2f}s")

    collected_at_utc = datetime.now(timezone.utc).isoformat()
    return {
        "site_name": "cracked",
        "source_url": url,
        "domain": domain,
        "title": title,
        "collected_at_utc": collected_at_utc,
        "content": content,
        "author": author,
        "timestamp": timestamp,
        "published_at_utc": normalize_cracked_timestamp(timestamp, collected_at_utc=collected_at_utc),
        "attachments": attachments,
        "victims": victim_info,
        "attackers": attackers,
        "content_hash": content_hash(content[:1000], author),
    }


def get_cracked_sections() -> dict:
    return FORUM_SECTIONS
