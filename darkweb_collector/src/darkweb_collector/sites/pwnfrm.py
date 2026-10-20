from __future__ import annotations

import re
import sys
import time
from datetime import datetime, timedelta, timezone
from html import unescape
from urllib.parse import unquote, urljoin, urlparse

from darkweb_collector.normalize import content_hash
from darkweb_collector.sites.darkforums import (
    raise_if_hidden_post,
    determine_industry,
    determine_region,
    extract_attackers_from_content,
    extract_victims_from_content,
)


PWNFRM_ONION_HOST = "pwnfrm7rbf6kyerigxi677lcz5ifmoagdbqqknwdu2by27wfdst5qmqd.onion"

FORUM_SECTIONS = {
    "databases": f"http://{PWNFRM_ONION_HOST}/Forum-Databases?sortby=started&order=desc&datecut=9999&prefix=0",
    "other_leaks": f"http://{PWNFRM_ONION_HOST}/Forum-Other-Leaks?sortby=started&order=desc&datecut=9999&prefix=0",
}


def _safe_console_text(value: str) -> str:
    encoding = getattr(sys.stdout, "encoding", None) or "utf-8"
    try:
        return str(value).encode(encoding, errors="replace").decode(encoding, errors="replace")
    except LookupError:
        return str(value).encode("utf-8", errors="replace").decode("utf-8", errors="replace")


def _debug_log(message: str) -> None:
    print(_safe_console_text(message))


# --- HTML/text helpers ----------------------------------------------------

DETAIL_QUOTE_RE = re.compile(r'<blockquote[^>]*>.*?</blockquote>', re.IGNORECASE | re.DOTALL)
# pwnfrm wraps every post in `<div class="post " ... id="post_NNN">` (no
# "classic" suffix, no end-of-postbit comment). The first post runs until the
# next post block opens or the document ends.
FIRST_POST_BLOCK_RE = re.compile(
    r'<div[^>]*class="post\s*"[^>]*id="post_\d+".*?(?=<div[^>]*class="post\s*"[^>]*id="post_\d+"|$)',
    re.IGNORECASE | re.DOTALL,
)
# pwnfrm uses US-style MM-DD-YYYY (e.g. "01-24-2026, 07:25 AM"), unlike
# darkforums' DD-MM-YY. The named groups stay consistent so downstream code
# is symmetric.
ABSOLUTE_TIMESTAMP_RE = re.compile(
    r'(?P<month>\d{1,2})-(?P<day>\d{1,2})-(?P<year>\d{2,4}),\s*(?P<hour>\d{1,2}):(?P<minute>\d{2})\s*(?P<ampm>AM|PM)',
    re.IGNORECASE,
)
TEXTUAL_TIMESTAMP_RE = re.compile(
    r'(?P<day>\d{1,2})\s+(?P<month>[A-Za-z]{3,9})\s+(?P<year>\d{4})(?:,\s*(?P<hour>\d{1,2}):(?P<minute>\d{2})\s*(?P<ampm>AM|PM))?',
    re.IGNORECASE,
)
RELATIVE_TIMESTAMP_RE = re.compile(
    r'(?P<value>\d+)\s+(?P<unit>minute|minutes|hour|hours|day|days|week|weeks|month|months|year|years)\s+ago',
    re.IGNORECASE,
)
# Author on pwnfrm is the slug after `/User-` in the profile link.
AUTHOR_PROFILE_HREF_RE = re.compile(
    r'<div[^>]*class="[^"]*post__user-profile[^"]*"[^>]*>\s*<a[^>]+href="[^"]*?/User-([^"/?#]+)"',
    re.IGNORECASE | re.DOTALL,
)
AUTHOR_USER_HREF_RE = re.compile(
    r'<a[^>]+href="[^"]*?/User-([^"/?#]+)"',
    re.IGNORECASE,
)


def _clean_html_text(value: str) -> str:
    if not value:
        return ""
    value = DETAIL_QUOTE_RE.sub('', value)
    value = re.sub(r"<[^>]+>", " ", value)
    value = unescape(value)
    value = re.sub(r"\s+", " ", value)
    return value.strip()


def _extract_domain(url: str) -> str:
    return urlparse(url).netloc


def _extract_victim_from_title(title: str) -> str:
    patterns = [
        r'([^|]+)\s*Database',
        r'([^|]+)\s*Leak',
        r'([^|]+)\s*Breached',
        r'([^|]+)\s*Dump',
        r'([^|]+)\s*Data',
    ]
    for pattern in patterns:
        match = re.search(pattern, title, re.IGNORECASE)
        if match:
            victim = match.group(1).strip()
            victim = re.sub(r'^(?:The|A|An)\s+', '', victim, flags=re.IGNORECASE)
            return victim
    return ""


def _extract_timestamp_text(post_block: str, html: str) -> str:
    patterns = [
        r'<span class="post_date">(.*?)</span>',
        r'<span[^>]*class="[^"]*DateTime[^"]*"[^>]*>(.*?)</span>',
        r'<div[^>]*class="[^"]*thread-info__datetime[^"]*"[^>]*>(.*?)</div>',
    ]
    for source in (post_block, html):
        for pattern in patterns:
            match = re.search(pattern, source, re.IGNORECASE | re.DOTALL)
            if match:
                text = _clean_html_text(match.group(1))
                if text:
                    return text
        cleaned = _clean_html_text(source)
        for regex in (ABSOLUTE_TIMESTAMP_RE, TEXTUAL_TIMESTAMP_RE, RELATIVE_TIMESTAMP_RE):
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


def normalize_pwnfrm_timestamp(value: str | None, *, collected_at_utc: str | None = None) -> str:
    """Normalise pwnfrm post-date strings to an ISO date.

    Handles MM-DD-YYYY absolute timestamps, textual dates ("24 January 2026"),
    relative ("3 days ago"), and yesterday/today phrasing.
    """
    raw = _clean_html_text(value)
    if not raw:
        return ""

    reference_dt = _parse_reference_dt(collected_at_utc)

    match = ABSOLUTE_TIMESTAMP_RE.search(raw)
    if match:
        year = int(match.group("year"))
        if year < 100:
            year += 2000
        month = int(match.group("month"))
        day = int(match.group("day"))
        # Defensive swap: if "month" reads > 12 but "day" is sane, the source
        # was actually day-first and the regex labels are swapped.
        if month > 12 and day <= 12:
            month, day = day, month
        try:
            hour = int(match.group("hour")) % 12
            if match.group("ampm").upper() == "PM":
                hour += 12
            dt = datetime(year, month, day, hour, int(match.group("minute")), tzinfo=timezone.utc)
            return dt.date().isoformat()
        except ValueError:
            pass

    match = TEXTUAL_TIMESTAMP_RE.search(raw)
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
        n = int(match.group("value"))
        unit = match.group("unit").lower()
        if unit.startswith("minute"):
            delta = timedelta(minutes=n)
        elif unit.startswith("hour"):
            delta = timedelta(hours=n)
        elif unit.startswith("day"):
            delta = timedelta(days=n)
        elif unit.startswith("week"):
            delta = timedelta(weeks=n)
        elif unit.startswith("month"):
            delta = timedelta(days=30 * n)
        else:
            delta = timedelta(days=365 * n)
        return (reference_dt - delta).date().isoformat()

    return ""


# --- public parsers -------------------------------------------------------

def parse_pwnfrm_list(
    url: str,
    html: str,
    max_topics: int = 5,
    *,
    site_name: str = "pwnfrm",
) -> dict:
    """Parse a pwnfrm MyBB forum listing page."""
    start_time = time.time()
    _debug_log(f"[{time.strftime('%H:%M:%S')}] [{site_name}] parsing list: {url}")

    title_match = re.search(r"<title>\s*(.*?)\s*</title>", html, re.IGNORECASE | re.DOTALL)
    title = _clean_html_text(title_match.group(1)) if title_match else ""
    domain = _extract_domain(url)

    topics: list[dict] = []
    seen_tids: set[str] = set()

    # MyBB classic skin wraps each thread title in:
    #   <span class="subject_new|subject_old" id="tid_NN"><a href="Thread-…">…</a></span>
    topic_pattern = re.compile(
        r'<span[^>]*class="[^"]*subject(?:_new|_old)?"[^>]*id="tid_(\d+)"[^>]*>'
        r'\s*<a href="(Thread-[^"]+)"[^>]*>(.*?)</a>',
        re.IGNORECASE | re.DOTALL,
    )

    matches = topic_pattern.findall(html)
    _debug_log(f"[{time.strftime('%H:%M:%S')}] [{site_name}] found {len(matches)} topic matches")

    for tid, href, raw_title in matches:
        if tid in seen_tids:
            continue
        seen_tids.add(tid)

        clean_title = _clean_html_text(raw_title)
        if not clean_title:
            continue

        detail_url = urljoin(url, href)
        victim = _extract_victim_from_title(clean_title)

        topic = {
            "tid": tid,
            "title": clean_title,
            "relative_url": href,
            "full_url": detail_url,
            "author": "",
            "replies": "",
            "views": "",
            "published_at": "",
            "content_hash": content_hash(clean_title, tid),
            "potential_victim": victim,
        }
        topics.append(topic)
        _debug_log(
            f"[{time.strftime('%H:%M:%S')}] [{site_name}] topic {len(topics)}: "
            f"{clean_title[:70]}"
        )

        if len(topics) >= max_topics:
            _debug_log(
                f"[{time.strftime('%H:%M:%S')}] [{site_name}] reached cap of "
                f"{max_topics} topics, stopping"
            )
            break

    elapsed = time.time() - start_time
    _debug_log(
        f"[{time.strftime('%H:%M:%S')}] [{site_name}] list parse done in "
        f"{elapsed:.2f}s, {len(topics)} topics"
    )

    return {
        "site_name": site_name,
        "source_url": url,
        "domain": domain,
        "title": title,
        "collected_at_utc": datetime.now(timezone.utc).isoformat(),
        "topic_count": len(topics),
        "topics": topics,
    }


def parse_pwnfrm_detail(
    url: str,
    html: str,
    *,
    site_name: str = "pwnfrm",
) -> dict:
    """Parse a pwnfrm thread page and extract the first post."""
    start_time = time.time()
    _debug_log(f"[{time.strftime('%H:%M:%S')}] [{site_name}] parsing detail: {url}")

    title_match = re.search(r"<title>\s*(.*?)\s*</title>", html, re.IGNORECASE | re.DOTALL)
    title = _clean_html_text(title_match.group(1)) if title_match else ""
    domain = _extract_domain(url)

    post_block_match = FIRST_POST_BLOCK_RE.search(html)
    post_block = post_block_match.group(0) if post_block_match else html

    content_match = re.search(
        r'<div[^>]*class="[^"]*post_body[^"]*"[^>]*>(.*?)</div>\s*<div class="post_meta"',
        post_block,
        re.IGNORECASE | re.DOTALL,
    )
    if not content_match:
        content_match = re.search(
            r'<div[^>]*class="[^"]*post_body[^"]*"[^>]*>(.*?)</div>\s*<div class="post_controls"',
            post_block,
            re.IGNORECASE | re.DOTALL,
        )
    if not content_match:
        fallback_selectors = [
            r'<div[^>]*class="[^"]*post_content[^"]*"[^>]*>(.*?)</div>\s*(?:<div|<footer|<div class="post_controls")',
            r'<div[^>]*class="[^"]*messageContent[^"]*"[^>]*>(.*?)</div>',
            r'<div[^>]*class="[^"]*post_body[^"]*"[^>]*>(.*?)</div>',
        ]
        for selector in fallback_selectors:
            fallback_match = re.search(selector, post_block, re.IGNORECASE | re.DOTALL)
            if fallback_match:
                content_match = fallback_match
                break
    content = _clean_html_text(content_match.group(1)) if content_match else ""
    raise_if_hidden_post(content, post_block)
    _debug_log(f"[{time.strftime('%H:%M:%S')}] [{site_name}] content length: {len(content)} chars")

    # Prefer the /User-NAME slug from the profile link — it's stable across
    # username styles (color spans, prefix icons, deleted-line-through, etc.)
    # that defeat span-text extraction.
    author = "Unknown"
    profile_match = AUTHOR_PROFILE_HREF_RE.search(post_block)
    if profile_match:
        author = unquote(profile_match.group(1)).strip() or "Unknown"
    else:
        fallback = AUTHOR_USER_HREF_RE.search(post_block)
        if fallback:
            author = unquote(fallback.group(1)).strip() or "Unknown"
        else:
            user_match = re.search(
                r'<a[^>]*class="[^"]*username[^"]*"[^>]*>(.*?)</a>',
                post_block, re.IGNORECASE | re.DOTALL,
            )
            if user_match:
                author = _clean_html_text(user_match.group(1)) or "Unknown"
    _debug_log(f"[{time.strftime('%H:%M:%S')}] [{site_name}] author: {author}")

    timestamp = _extract_timestamp_text(post_block, html)
    _debug_log(f"[{time.strftime('%H:%M:%S')}] [{site_name}] timestamp: {timestamp}")

    victims = extract_victims_from_content(content, title)
    attackers = extract_attackers_from_content(content)
    _debug_log(
        f"[{time.strftime('%H:%M:%S')}] [{site_name}] victims={len(victims)} "
        f"attackers={len(attackers)}"
    )

    victim_info = []
    for victim in victims:
        victim_info.append({
            "name": victim,
            "industry": determine_industry(victim, f"{title} {content}"),
            "region": determine_region(victim),
        })

    attachment_matches = re.findall(
        r'<a[^>]*href="([^"]+)"[^>]*class="[^"]*attachment[^"]*"[^>]*>',
        post_block, re.IGNORECASE,
    )
    attachments = [urljoin(url, match) for match in attachment_matches]

    elapsed = time.time() - start_time
    _debug_log(f"[{time.strftime('%H:%M:%S')}] [{site_name}] detail parse done in {elapsed:.2f}s")

    collected_at_utc = datetime.now(timezone.utc).isoformat()
    return {
        "site_name": site_name,
        "source_url": url,
        "domain": domain,
        "title": title,
        "collected_at_utc": collected_at_utc,
        "content": content,
        "author": author,
        "timestamp": timestamp,
        "published_at_utc": normalize_pwnfrm_timestamp(timestamp, collected_at_utc=collected_at_utc),
        "attachments": attachments,
        "victims": victim_info,
        "attackers": attackers,
        "content_hash": content_hash(content[:1000], author),
    }


def get_pwnfrm_sections() -> dict:
    return FORUM_SECTIONS
