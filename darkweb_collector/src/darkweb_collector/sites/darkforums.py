from __future__ import annotations

import re
import sys
import time
from datetime import datetime, timedelta, timezone
from html import unescape
from urllib.parse import urljoin, urlparse

from darkweb_collector.collection_errors import CollectionFailure
from darkweb_collector.normalize import content_hash


FORUM_SECTIONS = {
    "databases": "https://darkforums.as/Forum-Databases",
    "other_leaks": "https://darkforums.as/Forum-Other-Leaks",
    "sellers_place": "https://darkforums.as/Forum-Sellers-Place"
}

# HTML cleaning
DETAIL_QUOTE_RE = re.compile(r'<blockquote[^>]*>.*?</blockquote>', re.IGNORECASE | re.DOTALL)
FIRST_POST_BLOCK_RE = re.compile(
    r'<div class="post classic .*?id="post_\d+".*?<!-- end: postbit_classic -->',
    re.IGNORECASE | re.DOTALL,
)
ABSOLUTE_TIMESTAMP_RE = re.compile(
    r'(?P<day>\d{1,2})-(?P<month>\d{1,2})-(?P<year>\d{2,4}),\s*(?P<hour>\d{1,2}):(?P<minute>\d{2})\s*(?P<ampm>AM|PM)',
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
ATTACKER_VALUE_RE = re.compile(r"[A-Za-z0-9$][A-Za-z0-9$ ._&+\-/]{1,48}")
ATTACKER_SHORT_CODE_RE = re.compile(r"[A-Za-z]?\d{1,3}$")
ATTACKER_BLOCKED_PHRASES = (
    "item owner",
    "visibility group",
    "rejected by",
    "subcontractor",
    "internal documents",
    "engineering documents",
    "howitzers",
    "ammunition",
    "format: csv",
    "all rows",
    "open deals",
    "email messages",
    "monthly comp",
    "position title",
    "recruiting source",
    "activities to do",
)
ATTACKER_GENERIC_VALUES = {
    "actor",
    "actors",
    "attacker",
    "attackers",
    "group",
    "groups",
    "hacker",
    "hackers",
    "team",
    "gang",
    "unknown",
    "none",
    "n/a",
    "null",
}
ATTACKER_PATTERNS = (
    r'\b[Aa]ttacker[s]?\s*[:=-]\s*([^\n\r.;,]{2,48})(?=[\n\r]|[.;,]|$)',
    r'\b[Hh]acker[s]?\s*[:=-]\s*([^\n\r.;,]{2,48})(?=[\n\r]|[.;,]|$)',
    r'\b[Gg]roup(?:\s+name)?\s*[:=-]\s*([^\n\r.;,]{2,48})(?=[\n\r]|[.;,]|$)',
    r'\b[Tt]hreat [Aa]ctor[s]?\s*[:=-]\s*([^\n\r.;,]{2,48})(?=[\n\r]|[.;,]|$)',
    r'\b[Aa]ctor[s]?\s*[:=-]\s*([^\n\r.;,]{2,48})(?=[\n\r]|[.;,]|$)',
    r'\b[Cc]redit[s]?\s+(?:to|goes to)\s*[:=-]?\s*([^\n\r.;,]{2,48})(?=[\n\r]|[.;,]|$)',
    r'(?:^|[\s(\[])[Bb]y\s+([A-Za-z0-9$][A-Za-z0-9$._&+\-/]{1,30}(?:\s+[A-Za-z0-9$][A-Za-z0-9$._&+\-/]{1,30}){0,2})\s+(?:group|team|gang)\b',
)


def _safe_console_text(value: str) -> str:
    encoding = getattr(sys.stdout, "encoding", None) or "utf-8"
    try:
        return str(value).encode(encoding, errors="replace").decode(encoding, errors="replace")
    except LookupError:
        return str(value).encode("utf-8", errors="replace").decode("utf-8", errors="replace")


def _debug_log(message: str) -> None:
    print(_safe_console_text(message))


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

def _clean_html_text(value: str) -> str:
    """Clean HTML text by removing tags and normalizing whitespace"""
    if not value:
        return ""
    # Remove quotes
    value = DETAIL_QUOTE_RE.sub('', value)
    # Remove HTML tags
    value = re.sub(r"<[^>]+>", " ", value)
    # Unescape HTML entities
    value = unescape(value)
    # Normalize whitespace
    value = re.sub(r"\s+", " ", value)
    return value.strip()


def _extract_domain(url: str) -> str:
    parsed = urlparse(url)
    return parsed.netloc


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


def normalize_darkforums_timestamp(value: str | None, *, collected_at_utc: str | None = None) -> str:
    raw = _clean_html_text(value)
    if not raw:
        return ""

    reference_dt = _parse_reference_dt(collected_at_utc)

    match = ABSOLUTE_TIMESTAMP_RE.search(raw)
    if match:
        year = int(match.group("year"))
        if year < 100:
            year += 2000
        hour = int(match.group("hour")) % 12
        if match.group("ampm").upper() == "PM":
            hour += 12
        try:
            dt = datetime(
                year,
                int(match.group("month")),
                int(match.group("day")),
                hour,
                int(match.group("minute")),
                tzinfo=timezone.utc,
            )
        except ValueError:
            pass
        else:
            return dt.date().isoformat()

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
        dt = reference_dt - timedelta(days=1)
        return dt.date().isoformat()
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


def parse_darkforums_list(url: str, html: str, max_topics: int = 5) -> dict:
    """
    Parse DarkForums list page to extract topic information
    
    Args:
        url: The URL of the list page
        html: The HTML content of the page
        max_topics: Maximum number of topics to extract (default: 5 for pilot testing)
    """
    start_time = time.time()
    _debug_log(f"[{time.strftime('%H:%M:%S')}] Starting to parse list page: {url}")
    
    # Extract page title
    title_match = re.search(r"<title>\s*(.*?)\s*</title>", html, re.IGNORECASE | re.DOTALL)
    title = _clean_html_text(title_match.group(1)) if title_match else ""
    domain = _extract_domain(url)
    
    topics = []
    
    # Find all topic links in the HTML
    # DarkForums uses MyBB forum software with specific patterns
    # Topic links look like: <a href="Thread-XXXXX-Title">Title</a>
    # or: <span class="subject_new" id="tid_XXX"><a href="Thread-XXXXX">Title</a></span>
    
    # Pattern 1: Find topic links with subject_new class (new posts)
    # Note: class attribute may have leading space: class=" subject_new"
    topic_pattern = re.compile(
        r'<span[^>]*class="[^"]*subject(?:_new)?"[^>]*id="tid_(\d+)"[^>]*>'
        r'\s*<a href="(Thread-[^"]+)"[^>]*>(.*?)</a>',
        re.IGNORECASE | re.DOTALL
    )
    
    matches = topic_pattern.findall(html)
    _debug_log(f"[{time.strftime('%H:%M:%S')}] Found {len(matches)} topic matches")
    
    for tid, href, topic_title in matches:
        # Skip if already have this topic
        if any(t.get('tid') == tid for t in topics):
            continue
        
        # Clean title
        clean_title = _clean_html_text(topic_title)
        
        # Build full URL
        detail_url = urljoin(url, href)
        
        # Extract potential victim from title (for database leaks)
        victim = _extract_victim_from_title(clean_title)
        
        topic_data = {
            "tid": tid,
            "title": clean_title,
            "relative_url": href,
            "full_url": detail_url,
            "author": "",  # Will be filled from detail page
            "replies": "",
            "views": "",
            "published_at": "",
            "content_hash": content_hash(clean_title, tid),
            "potential_victim": victim
        }
        
        topics.append(topic_data)
        _debug_log(f"[{time.strftime('%H:%M:%S')}] Found topic {len(topics)}: {clean_title[:60]}...")
        
        # Limit to max_topics for pilot testing
        if len(topics) >= max_topics:
            _debug_log(f"[{time.strftime('%H:%M:%S')}] Reached limit of {max_topics} topics, stopping")
            break

    end_time = time.time()
    _debug_log(f"[{time.strftime('%H:%M:%S')}] List parsing completed in {end_time - start_time:.2f}s, found {len(topics)} topics")
    
    return {
        "site_name": "darkforums",
        "source_url": url,
        "domain": domain,
        "title": title,
        "collected_at_utc": datetime.now(timezone.utc).isoformat(),
        "topic_count": len(topics),
        "topics": topics
    }


def _extract_victim_from_title(title: str) -> str:
    """Extract potential victim name from topic title"""
    # Common patterns in database leak titles
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
            # Clean up common prefixes/suffixes
            victim = re.sub(r'^(?:The|A|An)\s+', '', victim, flags=re.IGNORECASE)
            return victim
    
    return ""


def raise_if_hidden_post(content: str, html: str) -> None:
    hidden_wrapper = re.search(
        r"<[^>]+\bclass=['\"][^'\"]*\b(?:hide-tag|hide-content|hidden-content|bbcode_hidden|hidebox)\b",
        html, re.IGNORECASE,
    )
    if hidden_wrapper and re.fullmatch(
        r"(?:(?:hidden content|this content is hidden)[\s.!:,-]*)?"
        r"(?:you (?:must|need to|have to) (?:log in|login|register|reply|react|like)|"
        r"(?:please )?(?:log in|login|register|reply|react|like)|only registered members).{0,300}",
        " ".join(content.split()), re.IGNORECASE,
    ):
        raise CollectionFailure("restricted", "post body only contains an access or interaction prompt")


def parse_darkforums_detail(url: str, html: str) -> dict:
    """
    Parse DarkForums detail page to extract post content and metadata
    """
    start_time = time.time()
    _debug_log(f"[{time.strftime('%H:%M:%S')}] Parsing detail page: {url}")
    
    # Extract page title
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

    _debug_log(f"[{time.strftime('%H:%M:%S')}] Extracted content length: {len(content)} chars")
    
    # Extract author information
    author_match = re.search(
        r'<a[^>]*class="[^"]*username[^"]*"[^>]*>(.*?)</a>',
        post_block, re.IGNORECASE | re.DOTALL
    )
    if not author_match:
        author_match = re.search(
            r'<div class="post_user-profile[^"]*"[^>]*>.*?<a[^>]*>(.*?)</a>',
            post_block, re.IGNORECASE | re.DOTALL
        )
    author = _clean_html_text(author_match.group(1)) if author_match else "Unknown"
    
    _debug_log(f"[{time.strftime('%H:%M:%S')}] Author: {author}")
    
    # Extract post date/timestamp
    timestamp = _extract_timestamp_text(post_block, html)
    
    _debug_log(f"[{time.strftime('%H:%M:%S')}] Timestamp: {timestamp}")
    
    # Extract victims from content and title
    victims = extract_victims_from_content(content, title)
    _debug_log(f"[{time.strftime('%H:%M:%S')}] Found {len(victims)} victims")
    
    # Extract attackers
    attackers = extract_attackers_from_content(content)
    _debug_log(f"[{time.strftime('%H:%M:%S')}] Found {len(attackers)} attackers")
    
    # Build victim information with industry and region
    victim_info = []
    for victim in victims:
        industry = determine_industry(victim, f"{title} {content}")
        region = determine_region(victim)
        victim_info.append({
            'name': victim,
            'industry': industry,
            'region': region
        })
        _debug_log(f"[{time.strftime('%H:%M:%S')}] Victim: {victim} | Industry: {industry} | Region: {region}")
    
    # Extract attachments/links
    attachment_matches = re.findall(
        r'<a[^>]*href="([^"]+)"[^>]*class="[^"]*attachment[^"]*"[^>]*>',
        post_block, re.IGNORECASE
    )
    attachments = [urljoin(url, match) for match in attachment_matches]
    
    end_time = time.time()
    _debug_log(f"[{time.strftime('%H:%M:%S')}] Detail parsing completed in {end_time - start_time:.2f}s")
    
    collected_at_utc = datetime.now(timezone.utc).isoformat()

    return {
        "site_name": "darkforums",
        "source_url": url,
        "domain": domain,
        "title": title,
        "collected_at_utc": collected_at_utc,
        "content": content,
        "author": author,
        "timestamp": timestamp,
        "published_at_utc": normalize_darkforums_timestamp(timestamp, collected_at_utc=collected_at_utc),
        "attachments": attachments,
        "victims": victim_info,
        "attackers": attackers,
        "content_hash": content_hash(content[:1000], author)
    }


def extract_victims_from_content(content: str, title: str = "") -> list:
    """
    Extract victim information from post content and title
    
    For database leaks, victims are often mentioned in:
    1. Title (e.g., "CompanyName Database")
    2. Content (e.g., "Victim: Company Name", "Target: Organization")
    """
    victims = []
    
    # Extract from title first
    if title:
        title_victim = _extract_victim_from_title(title)
        if title_victim and len(title_victim) > 2:
            victims.append(title_victim)
    
    # Patterns to find victims in content
    victim_patterns = [
        # Explicit victim mentions
        r'[Vv]ictim[s]?[:\s]+(.+?)(?=\s+[Gg]roup:|\s+[Aa]ttacker:|[.,]|$)',
        r'[Tt]arget[:\s]+(.+?)(?=\s+[Gg]roup:|\s+[Aa]ttacker:|[.,]|$)',
        r'[Aa]ffected[:\s]+(.+?)(?=\s+[Gg]roup:|\s+[Aa]ttacker:|[.,]|$)',
    ]
    
    text_to_search = f"{title} {content}"
    
    for pattern in victim_patterns:
        matches = re.findall(pattern, text_to_search, re.IGNORECASE)
        for match in matches:
            victim = _clean_html_text(match)
            # Filter out common false positives
            if victim and len(victim) > 2 and len(victim) < 100:
                # Skip if it's just generic text
                generic_terms = ['the', 'this', 'that', 'these', 'those', 'database', 'data', 'unknown']
                if victim.lower() not in generic_terms and not any(
                    phrase in victim.lower()
                    for phrase in [
                        "this post",
                        "full database",
                        "most posts",
                        "processed database",
                        "private database",
                        "website",
                    ]
                ):
                    victims.append(victim)
    
    # Remove duplicates while preserving order
    seen = set()
    unique_victims = []
    for v in victims:
        v_lower = v.lower()
        if v_lower not in seen:
            seen.add(v_lower)
            unique_victims.append(v)
    
    return unique_victims[:10]  # Limit to top 10 victims


def extract_attackers_from_content(content: str) -> list:
    """
    Extract attacker/threat actor information from content
    """
    attackers = []

    for pattern in ATTACKER_PATTERNS:
        matches = re.findall(pattern, content, re.IGNORECASE)
        for match in matches:
            attacker = _clean_html_text(match).strip(" -:;,.")
            if attacker:
                attackers.append(attacker)

    return clean_extracted_attackers(attackers)[:5]  # Limit to top 5 attackers


def clean_extracted_attackers(values: list[str]) -> list[str]:
    """Normalize attacker candidates and drop obvious false positives."""
    seen = set()
    unique_attackers = []
    for value in values:
        attacker = _clean_html_text(value).strip(" -:;,.")
        lowered = attacker.lower()
        if not attacker or lowered in seen:
            continue
        if lowered in ATTACKER_GENERIC_VALUES:
            continue
        if len(attacker) < 3 or len(attacker) > 40:
            continue
        if len(attacker.split()) > 4:
            continue
        if ATTACKER_SHORT_CODE_RE.fullmatch(attacker):
            continue
        if not ATTACKER_VALUE_RE.fullmatch(attacker):
            continue
        if any(phrase in lowered for phrase in ATTACKER_BLOCKED_PHRASES):
            continue
        seen.add(lowered)
        unique_attackers.append(attacker)
    return unique_attackers


def determine_industry(victim: str, context: str = "") -> str:
    """Determine industry based on victim name/description"""
    victim_lower = f"{victim} {context}".lower()
    
    industries = {
        'finance': ['bank', 'financial', 'banking', 'credit', 'insurance', 'payment', 'finance', 'investment', 'capital', 'forex', 'broker', 'trading', 'crypto', 'cryptocurrency', 'wallet', 'exchange', 'coinbase'],
        'healthcare': ['health', 'hospital', 'medical', 'healthcare', 'pharmaceutical', 'clinic', 'patient'],
        'government': ['government', 'military', 'army', 'navy', 'air force', 'police', 'fbi', 'cia', 'federal', 'state', 'ministry', 'agency', 'department', 'gov', 'public', 'tsa', 'transportation security', 'identity card', 'id card', 'id cards', 'passport', 'national registry', 'reniec'],
        'technology': ['tech', 'technology', 'software', 'hardware', 'internet', 'social media', 'cloud', 'cyber', 'digital', 'app', 'platform', 'electronics', 'microelectronics', 'semiconductor', 'chip'],
        'retail': ['retail', 'ecommerce', 'shop', 'store', 'market', 'commerce', 'mall'],
        'education': ['university', 'universidad', 'college', 'school', 'education', 'academy', 'institute', 'student', 'faculty'],
        'telecommunications': ['telecom', 'telecommunication', 'mobile', 'phone', 'wireless', 'isp', 'internet service', 'broadband'],
        'energy': ['energy', 'oil', 'gas', 'electric', 'power', 'utility', 'renewable'],
        'transportation': ['airline', 'airport', 'transport', 'logistics', 'shipping', 'railway', 'aviation'],
        'entertainment': ['entertainment', 'gaming', 'game', 'media', 'streaming', 'movie', 'music', 'onlyfans', 'adult content', 'creator content'],
    }
    
    for industry, keywords in industries.items():
        for keyword in keywords:
            if keyword in victim_lower:
                return industry
    
    return 'other'


def determine_region(victim: str) -> str:
    """Determine region based on victim name/description"""
    victim_lower = victim.lower()
    
    regions = {
        'north_america': ['us', 'usa', 'united states', 'america', 'canada', 'mexico', 'north america', 'california', 'texas', 'florida', 'new york'],
        'europe': ['europe', 'uk', 'britain', 'england', 'germany', 'france', 'italy', 'spain', 'russia', 'netherlands', 'sweden', 'norway', 'poland', 'turkey', 'turkish'],
        'asia': ['asia', 'china', 'japan', 'korea', 'india', 'singapore', 'malaysia', 'thailand', 'vietnam', 'indonesia', 'philippines', 'pakistan', 'bangladesh'],
        'middle_east': ['middle east', 'saudi arabia', 'iran', 'iraq', 'israel', 'uae', 'dubai', 'qatar', 'kuwait', 'lebanon', 'jordan', 'syria'],
        'africa': ['africa', 'nigeria', 'south africa', 'egypt', 'kenya', 'morocco', 'ghana', 'ethiopia'],
        'oceania': ['oceania', 'australia', 'new zealand', 'fiji', 'papua new guinea'],
        'south_america': ['brazil', 'argentina', 'colombia', 'chile', 'peru', 'venezuela', 'ecuador', 'bolivia', 'uruguay', 'paraguay'],
    }
    
    for region, keywords in regions.items():
        for keyword in keywords:
            if keyword in victim_lower:
                return region
    
    return 'unknown'


def get_darkforums_sections() -> dict:
    """Get the list of forum sections to crawl"""
    return FORUM_SECTIONS
