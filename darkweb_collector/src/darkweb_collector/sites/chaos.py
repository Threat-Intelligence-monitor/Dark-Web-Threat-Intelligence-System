from __future__ import annotations

from datetime import datetime, timezone
from html import unescape
import re
from urllib.parse import urljoin, urlparse

from darkweb_collector.normalize import content_hash, normalize_status, size_to_gb


# Regex patterns for parsing CHAOS website
TITLE_RE = re.compile(r"<title>\s*(.*?)\s*</title>", re.IGNORECASE | re.DOTALL)

# Victim card pattern - matches the rounded-xl bg-bunker containers
VICTIM_CARD_RE = re.compile(
    r'<div class="rounded-xl bg-bunker p-4 flex justify-between w-full">'
    r'(.*?)'
    r'</div>\s*</div>\s*</div>',
    re.IGNORECASE | re.DOTALL
)

# Extract victim name from link
VICTIM_NAME_RE = re.compile(
    r'<a[^>]*href="(/[^"]+)"[^>]*class="[^"]*break-words[^"]*"[^>]*>(.*?)</a>',
    re.IGNORECASE | re.DOTALL
)

# Extract website link
WEBSITE_RE = re.compile(
    r'<a href="(https?://[^"]+)"[^>]*target="_blank"[^>]*>(.*?)</a>',
    re.IGNORECASE | re.DOTALL
)

# Extract leaked size
LEAKED_SIZE_RE = re.compile(
    r'Leaked size\s*<span[^>]*>(\d+(?:\.\d+)?)\s*Gb?</span>',
    re.IGNORECASE | re.DOTALL
)

# Extract view count
VIEW_COUNT_RE = re.compile(
    r'View count\s*<span[^>]*>(\d+)</span>',
    re.IGNORECASE | re.DOTALL
)

# Extract description
DESCRIPTION_RE = re.compile(
    r'<div class="px-2 max-w-\[80%\]">\s*<div[^>]*>(.*?)</div>\s*</div>',
    re.IGNORECASE | re.DOTALL
)

# Extract timer/countdown
TIMER_RE = re.compile(
    r'<div class="whitespace-nowrap">(\d+d\s+\d+h\s+\d+m\s+\d+s)</div>',
    re.IGNORECASE | re.DOTALL
)

# Clean text by removing HTML tags
def _clean_html_text(value: str) -> str:
    """Clean HTML text by removing tags and normalizing whitespace"""
    if not value:
        return ""
    # Remove HTML tags
    value = re.sub(r"<[^>]+>", " ", value)
    # Unescape HTML entities
    value = unescape(value)
    # Normalize whitespace
    value = re.sub(r"\s+", " ", value)
    return value.strip()


def _extract_domain_from_url(url: str) -> str | None:
    """Extract domain from URL"""
    try:
        parsed = urlparse(url)
        domain = parsed.netloc
        if domain.startswith("www."):
            domain = domain[4:]
        return domain
    except Exception:
        return None


def _extract_matching_card_html(html: str, detail_path: str) -> str:
    if not detail_path:
        return html
    href_marker = f'href="{detail_path}"'
    idx = html.find(href_marker)
    if idx == -1:
        return ""
    start_marker = '<div class="rounded-xl bg-bunker p-4 flex justify-between w-full">'
    start = html.rfind(start_marker, 0, idx)
    if start == -1:
        return ""
    next_start = html.find(start_marker, idx + len(href_marker))
    if next_start == -1:
        return html[start:]
    return html[start:next_start]


def parse_chaos_homepage(url: str, html: str) -> dict:
    """
    Parse CHAOS ransomware website homepage to extract victim information
    
    Args:
        url: The URL of the CHAOS homepage
        html: The HTML content of the page
        
    Returns:
        Dictionary containing parsed victim information
    """
    start_time = datetime.now(timezone.utc)
    
    # Extract page title
    title_match = TITLE_RE.search(html)
    page_title = _clean_html_text(title_match.group(1)) if title_match else "CHAOS"
    
    victims = []
    
    # Find all victim cards
    victim_cards = VICTIM_CARD_RE.findall(html)
    
    for card_html in victim_cards:
        victim = {}
        
        # Extract victim name and detail URL
        name_match = VICTIM_NAME_RE.search(card_html)
        if name_match:
            detail_path = name_match.group(1)
            victim["name"] = _clean_html_text(name_match.group(2))
            victim["detail_url"] = urljoin(url, detail_path)
            victim["detail_path"] = detail_path
        else:
            # Skip if no name found
            continue
        
        # Extract domain from website link
        website_match = WEBSITE_RE.search(card_html)
        if website_match:
            victim["website_url"] = website_match.group(1)
            victim["domain"] = _extract_domain_from_url(victim["website_url"])
        else:
            # Try to extract domain from victim name
            victim["domain"] = _extract_domain_from_url(victim.get("name", ""))
        
        # Extract leaked size
        size_match = LEAKED_SIZE_RE.search(card_html)
        if size_match:
            victim["claimed_size"] = f"{size_match.group(1)} GB"
            victim["claimed_size_gb"] = float(size_match.group(1))
        else:
            victim["claimed_size"] = None
            victim["claimed_size_gb"] = None
        
        # Extract view count
        view_match = VIEW_COUNT_RE.search(card_html)
        if view_match:
            victim["view_count"] = int(view_match.group(1))
        else:
            victim["view_count"] = None
        
        # Extract description
        desc_match = DESCRIPTION_RE.search(card_html)
        if desc_match:
            victim["description"] = _clean_html_text(desc_match.group(1))
        else:
            victim["description"] = None
        
        # Extract timer (if present)
        timer_match = TIMER_RE.search(card_html)
        if timer_match:
            victim["timer"] = timer_match.group(1)
        else:
            victim["timer"] = None
        
        # Determine status based on content
        if "blur-xs" in card_html:
            # If content is blurred, it's likely "going" (countdown active)
            victim["status"] = "going"
        elif victim.get("timer"):
            victim["status"] = "going"
        else:
            victim["status"] = "published"
        
        # Generate content hash
        victim["content_hash"] = content_hash(
            victim.get("name", ""),
            victim.get("domain", ""),
            victim.get("claimed_size", "")
        )
        
        victims.append(victim)
    
    end_time = datetime.now(timezone.utc)
    
    return {
        "site_name": "chaos",
        "source_url": url,
        "page_title": page_title,
        "collected_at_utc": start_time.isoformat(),
        "victim_count": len(victims),
        "victims": victims,
        "metadata": {
            "parse_duration_seconds": (end_time - start_time).total_seconds(),
            "raw_html_length": len(html),
        }
    }


def parse_chaos_detail(url: str, html: str) -> dict:
    """
    Parse CHAOS victim detail page
    
    Args:
        url: The URL of the detail page
        html: The HTML content of the page
        
    Returns:
        Dictionary containing parsed detail information
    """
    title_match = TITLE_RE.search(html)
    page_title = _clean_html_text(title_match.group(1)) if title_match else ""

    detail_path = urlparse(url).path or ""
    card_html = _extract_matching_card_html(html, detail_path)

    name = ""
    name_match = VICTIM_NAME_RE.search(card_html)
    if name_match:
        name = _clean_html_text(name_match.group(2))

    website_url = ""
    domain = None
    website_match = WEBSITE_RE.search(card_html)
    if website_match:
        website_url = website_match.group(1)
        domain = _extract_domain_from_url(website_url)

    size_match = LEAKED_SIZE_RE.search(card_html)
    claimed_size = f"{size_match.group(1)} GB" if size_match else ""

    view_match = VIEW_COUNT_RE.search(card_html)
    view_count = int(view_match.group(1)) if view_match else None

    desc_match = DESCRIPTION_RE.search(card_html)
    description = _clean_html_text(desc_match.group(1)) if desc_match else _clean_html_text(card_html)

    link_pattern = re.compile(r'href="([^"]+)"', re.IGNORECASE)
    links = [urljoin(url, href) for href in link_pattern.findall(card_html) if href]

    return {
        "source_url": url,
        "fetched_at_utc": datetime.now(timezone.utc).isoformat(),
        "fetch_status": "ok",
        "page_title": page_title,
        "text_excerpt": description[:2000] if description else None,
        "content": description,
        "victims": [name] if name else [],
        "domain": domain,
        "website": website_url,
        "claimed_size": claimed_size,
        "view_count": view_count,
        "outbound_link_count": len(links),
        "links": links[:20],
    }
