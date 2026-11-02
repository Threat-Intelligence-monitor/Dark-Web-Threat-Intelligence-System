"""DragonForceBlog site parser for darkweb_collector."""
from __future__ import annotations

from datetime import datetime, timezone
from html import unescape
import json
import re
from urllib.parse import urljoin, urlparse, parse_qs

from darkweb_collector.normalize import content_hash
from darkweb_collector.collection_errors import raise_if_error_page


TITLE_RE = re.compile(r"<title>\s*(.*?)\s*</title>", re.IGNORECASE | re.DOTALL)
UUID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.IGNORECASE)


def _class_attribute(name: str) -> str:
    token = re.escape(name)
    return (r'\bclass\s*=\s*(?:"(?:[^"<>]*\s)?' + token + r'(?:\s[^"<>]*)?"'
            r"|'(?:[^'<>]*\s)?" + token + r"(?:\s[^'<>]*)?'|" + token + r'(?=\s|>))')


def _clean_html_text(value: str) -> str:
    """Clean HTML text by removing tags and normalizing whitespace."""
    if not value:
        return ""
    value = re.sub(r"<[^>]+>", " ", value)
    value = unescape(value)
    value = re.sub(r"\s+", " ", value)
    return value.strip()


def _extract_publication_block(block_html: str, base_url: str) -> dict | None:
    """Extract data from a single publication block."""

    # Extract website/victim domain
    # Support both: class="list-publication__website" and class=list-publication__website
    domain = ""
    victim_match = re.search(_class_attribute("list-publication__website") + r'[^>]*>([^<]+)', block_html, re.IGNORECASE)
    if victim_match:
        domain = _clean_html_text(victim_match.group(1))

    if not domain:
        return None

    # Extract victim name (company name) - look for list-publication__name
    name = ""
    name_match = re.search(_class_attribute("list-publication__name") + r'[^>]*>([^<]+)', block_html, re.IGNORECASE)
    if name_match:
        name = _clean_html_text(name_match.group(1))

    # If no name found, use domain as name
    if not name:
        name = domain.replace("www.", "")

    # Extract description - look for longer text content
    description = ""
    # Try to find description in the block
    desc_match = re.search(_class_attribute("list-publication__description") + r'[^>]*>([^<]+)', block_html, re.IGNORECASE)
    if desc_match:
        description = _clean_html_text(desc_match.group(1))
    
    # If no description found or too short, look for longer text
    if len(description) < 50:
        # Look for substantial text content (50-2000 chars)
        text_matches = re.findall(r'>([^<]{50,2000})<', block_html)
        for text in text_matches:
            cleaned = _clean_html_text(text)
            # Filter out CSS, scripts, and base64 data
            if len(cleaned) > 50 and not any(x in cleaned.lower() for x in ['function', 'var ', 'const ', 'display:', 'margin:', 'padding:', 'data:image']):
                description = cleaned
                break

    # Extract publication date
    published_at = ""
    date_match = re.search(_class_attribute("publication-footer__date") + r'[^>]*>.*?mdi-creation[^<]*</span>\s*([^<]+)</span>', block_html, re.IGNORECASE)
    if date_match:
        published_at = _clean_html_text(date_match.group(1))

    # Extract claimed size
    claimed_size = ""
    size_match = re.search(_class_attribute("list-publication__size") + r'[^>]*>([^<]+)', block_html, re.IGNORECASE)
    if size_match:
        claimed_size = _clean_html_text(size_match.group(1))

    # Extract location
    location = ""
    location_match = re.search(_class_attribute("list-publication__location") + r'[^>]*>([^<]+)', block_html, re.IGNORECASE)
    if location_match:
        location = _clean_html_text(location_match.group(1))

    # Extract status/timer status
    status = "unknown"
    timer_match = re.search(r'class="list-publication__timer-publication"[^>]*>.*?class="(?:timer-publication__timer|publication-timer__label)"[^>]*>([^<]+)', block_html, re.IGNORECASE | re.DOTALL)
    if timer_match:
        timer_text = _clean_html_text(timer_match.group(1))
        if timer_text:
            status = "going"

    # Keep the victim's public website separate from the leak-site detail URL.
    website_url = ""
    link_match = re.search(r'href="(https?://[^"\s>]+)"', block_html, re.IGNORECASE)
    if link_match:
        website_url = link_match.group(1)

    # Extract file preview thumbnails (data:image URLs)
    thumbnails = []
    thumbnail_matches = re.findall(r'url\((data:image/[^)]+)\)', block_html, re.IGNORECASE)
    for thumb in thumbnail_matches[:10]:  # Limit to 10 thumbnails
        if thumb not in thumbnails:
            thumbnails.append(thumb)

    # Create display_label from name (first 50 chars)
    display_label = name[:50] if len(name) <= 50 else name[:47] + "..."

    # Calculate content hash
    content_hash_value = content_hash(name, domain, description, published_at)

    return {
        "site_name": "dragonforceblog",
        "source_url": base_url,
        "name": name,
        "display_label": display_label,
        "domain": domain.replace("www.", ""),
        "relative_path": "",
        "detail_url": "",
        "status": status,
        "timer_class": "list-publication__timer-publication",
        "timer_status": status,
        "published_at_utc": published_at,
        "claimed_size": claimed_size,
        "claimed_size_gb": None,
        "location": location,
        "website": domain,
        "website_url": website_url,
        "description": description,
        "publication_timer": None,
        "publicated_files": None,
        "open_label": "Open",
        "content_hash": content_hash_value,
        "thumbnails": thumbnails,
    }


def _build_detail_url(base_url: str, post_uuid: str) -> str:
    return urljoin(base_url, f"/blog/?post_uuid={post_uuid}")


def _extract_post_uuid_from_url(url: str) -> str:
    parsed = urlparse(url)
    values = parse_qs(parsed.query).get("post_uuid", [])
    return values[0] if values else ""


def _format_weight(value: int | float | None) -> str:
    if isinstance(value, str):
        try:
            value = float(value)
        except ValueError:
            return ""
    if not value:
        return ""
    size = float(value)
    gb = size / (1024 ** 3)
    if gb >= 1:
        return f"{gb:.2f} GB"
    mb = size / (1024 ** 2)
    if mb >= 1:
        return f"{mb:.2f} MB"
    kb = size / 1024
    return f"{kb:.2f} KB"


def _decode_payload_sequence(html: str, post_uuid: str) -> dict[str, object]:
    marker = f'"{post_uuid}"'
    idx = html.find(marker)
    if idx == -1:
        return {}

    decoder = json.JSONDecoder()
    payload = html[idx:]
    values: list[object] = []
    pos = 0

    while len(values) < 10 and pos < len(payload):
        while pos < len(payload) and payload[pos] in ", \r\n\t":
            pos += 1
        if pos >= len(payload):
            break
        try:
            value, next_pos = decoder.raw_decode(payload, pos)
        except json.JSONDecodeError:
            break
        values.append(value)
        pos = next_pos

    if len(values) < 6:
        return {}

    created_at = values[1] if len(values) > 1 else ""
    name = values[2] if len(values) > 2 else ""
    website = values[3] if len(values) > 3 else ""

    tail = list(values[4:])
    weight_index = next(
        (index for index, value in enumerate(tail) if isinstance(value, (int, float))),
        None,
    )
    if weight_index is None:
        return {}

    pre_weight = tail[:weight_index]
    weight = tail[weight_index]
    post_weight = tail[weight_index + 1 :]

    address = ""
    description = ""
    string_fields = [str(item) for item in pre_weight if isinstance(item, str)]
    if len(string_fields) >= 2:
        address = string_fields[0]
        description = " ".join(string_fields[1:])
    elif len(string_fields) == 1:
        description = string_fields[0]

    published_at = next((item for item in post_weight if isinstance(item, str)), "")
    tags = next((item for item in post_weight if isinstance(item, list)), [])
    logo_uuid = next(
        (item for item in post_weight if isinstance(item, str) and UUID_RE.fullmatch(item)),
        "",
    )

    return {
        "uuid": values[0],
        "created_at": created_at,
        "name": name,
        "website": website,
        "address": address,
        "description": description,
        "weight": weight,
        "published_at": published_at,
        "tags": tags,
        "logo_uuid": logo_uuid,
    }


def _extract_post_uuid_from_payload(html: str, name: str, website: str) -> str:
    candidates = []
    if name and website:
        candidates.append(
            re.compile(
                rf'"(?P<uuid>{UUID_RE.pattern})","[^"]*","{re.escape(name)}","{re.escape(website)}"',
                re.IGNORECASE,
            )
        )
    if website:
        candidates.append(
            re.compile(
                rf'"(?P<uuid>{UUID_RE.pattern})","[^"]*","[^"]*","{re.escape(website)}"',
                re.IGNORECASE,
            )
        )
    if name:
        candidates.append(
            re.compile(
                rf'"(?P<uuid>{UUID_RE.pattern})","[^"]*","{re.escape(name)}"',
                re.IGNORECASE,
            )
        )

    for pattern in candidates:
        match = pattern.search(html)
        if match:
            return match.group("uuid")
    return ""


def parse_dragonforceblog_list_page(url: str, html: str) -> dict:
    """Parse DragonForceBlog list page HTML and extract topic information."""
    raise_if_error_page(html)
    title_match = TITLE_RE.search(html)
    page_title = _clean_html_text(title_match.group(1)) if title_match else ""

    victims = []

    # Split HTML by publication blocks
    # Pattern: <div class="publications-list__publication" data-v-950956cb="">
    publication_blocks = re.split(r'<div\b[^>]*' + _class_attribute("publications-list__publication") + r'[^>]*>', html, flags=re.IGNORECASE)

    # Skip the first block (header/content before first publication)
    for block in publication_blocks[1:]:
        # Extract data from this block
        item = _extract_publication_block(block, url)
        if item:
            post_uuid = _extract_post_uuid_from_payload(
                html=html,
                name=item.get("name", ""),
                website=item.get("website", ""),
            )
            item["post_uuid"] = post_uuid
            if post_uuid:
                item["detail_url"] = _build_detail_url(url, post_uuid)
                item["relative_path"] = f"/blog/?post_uuid={post_uuid}"
            victims.append(item)

    return {
        "site_name": "dragonforceblog",
        "source_url": url,
        "title": page_title,
        "collected_at_utc": datetime.now(timezone.utc).isoformat(),
        "victim_count": len(victims),
        "victims": victims,
    }


def parse_dragonforceblog_detail_page(url: str, html: str) -> dict:
    """Parse DragonForceBlog detail page HTML and extract content information.

    For dragonforceblog, the detail page is a modal/popup that contains:
    - Company logo/image
    - File preview thumbnails
    - Company name and details
    - Description
    - Publication timer
    - Attachments download links
    """
    raise_if_error_page(html)
    title_match = TITLE_RE.search(html)
    page_title = _clean_html_text(title_match.group(1)) if title_match else ""
    post_uuid = _extract_post_uuid_from_url(url)
    payload_record = _decode_payload_sequence(html, post_uuid)

    victim_name = _clean_html_text(str(payload_record.get("website", "")))
    company_name = _clean_html_text(str(payload_record.get("name", "")))
    if not company_name:
        company_name = victim_name.replace("www.", "") if victim_name else ""

    content = _clean_html_text(str(payload_record.get("description", "")))
    timestamp = _clean_html_text(str(payload_record.get("created_at", "")))
    claimed_size = _format_weight(payload_record.get("weight"))
    location = _clean_html_text(str(payload_record.get("address", "")))
    website_url = ""
    if victim_name:
        website_url = victim_name if str(victim_name).startswith("http") else f"https://{victim_name}"

    thumbnails = []
    logo_uuid = _clean_html_text(str(payload_record.get("logo_uuid", "")))
    if logo_uuid:
        thumbnails.append(urljoin(url, f"/api/assets/blog/attachment?uuid={logo_uuid}"))

    # Author is not explicitly shown
    author = ""

    # Victims and attackers
    victims = []
    attackers = []

    if victim_name:
        victims.append(victim_name)

    # Attachments - look for download links
    attachments = []
    attachment_patterns = [
        r'href="([^"\s>]+)"[^>]*class="publicated-files__link"',
        r'href="(/api/assets/blog/attachment[^"\s>]+)"',
    ]
    for pattern in attachment_patterns:
        for match in re.finditer(pattern, html, re.IGNORECASE):
            href = match.group(1)
            if href and href != '#':
                attachments.append({
                    "url": urljoin(url, href),
                    "name": href.split('/')[-1] or "attachment",
                })
    if website_url:
        attachments.append({"url": website_url, "name": victim_name})

    link_matches = re.findall(r'href="([^"\s>#]+)"', html, re.IGNORECASE)
    outbound_links_sample = [
        urljoin(url, href)
        for href in link_matches
        if href and not href.startswith("#") and not href.startswith("javascript:")
    ][:20]

    # Calculate content hash
    content_hash_value = content_hash(content, timestamp, victim_name)

    fetched_at_utc = datetime.now(timezone.utc).isoformat()

    return {
        "site_name": "dragonforceblog",
        "source_url": url,
        "fetched_at_utc": fetched_at_utc,
        "fetch_status": "ok",
        "page_title": page_title,
        "text_excerpt": content[:1000] if content else "",
        "outbound_link_count": len(outbound_links_sample),
        "outbound_links_sample": outbound_links_sample,
        "content": content,
        "author": author,
        "timestamp": timestamp,
        "victims": victims,
        "attackers": attackers,
        "attachments": attachments,
        "content_hash": content_hash_value,
        "parsed_at_utc": fetched_at_utc,
        "claimed_size": claimed_size,
        "location": location,
        "company_name": company_name,
        "website": website_url,
        "post_uuid": post_uuid,
        "thumbnails": thumbnails,
    }
