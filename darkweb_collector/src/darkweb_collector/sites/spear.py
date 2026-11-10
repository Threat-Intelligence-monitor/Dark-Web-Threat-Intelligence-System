from __future__ import annotations

import re
from urllib.parse import parse_qs, unquote, urljoin, urlsplit, urlunsplit

from darkweb_collector.collection_errors import CollectionFailure, raise_if_error_page
from darkweb_collector.normalize import content_hash
from darkweb_collector.sites.forum_post_content import extract_body_content
from darkweb_collector.sites.darkforums import (
    determine_industry,
    determine_region,
    extract_attackers_from_content,
    extract_victims_from_content,
)
from darkweb_collector.sites.pwnfrm import (
    ABSOLUTE_TIMESTAMP_RE,
    RELATIVE_TIMESTAMP_RE,
    TEXTUAL_TIMESTAMP_RE,
    normalize_pwnfrm_timestamp,
)
from darkweb_collector.sites.xforums import _Document, _Node, _text
from darkweb_collector.utils import utc_now_iso


FORUM_SECTIONS = {
    name: f"https://spear.cx/Forum-{slug}?sortby=started&order=desc&datecut=9999"
    for name, slug in (
        ("databases", "Databases"),
        ("stealer_logs", "Stealer-Logs"),
        ("other_leaks", "Other-Leaks"),
        ("leaked_tools", "Leaked-Tools"),
    )
}


def get_spear_sections() -> dict[str, str]:
    return dict(FORUM_SECTIONS)


def normalize_spear_timestamp(value: str | None, *, collected_at_utc: str | None = None) -> str:
    if re.fullmatch(r"(?:less than (?:1|a) minute ago|just now)", str(value or "").strip(), re.IGNORECASE):
        value = "today"
    return normalize_pwnfrm_timestamp(value, collected_at_utc=collected_at_utc)


def _timestamp(node: _Node | None) -> str:
    if node is None:
        return ""
    for child in [node, *node.find_all()]:
        value = str(child.attrs.get("title") or "").strip()
        if normalize_spear_timestamp(value):
            return value
    text = _text(node)
    for pattern in (ABSOLUTE_TIMESTAMP_RE, TEXTUAL_TIMESTAMP_RE, RELATIVE_TIMESTAMP_RE):
        match = pattern.search(text)
        if match:
            return match.group(0)
    match = re.search(
        r"\b(?:yesterday|today)\b(?:\s*,?\s*\d{1,2}:\d{2}\s*(?:AM|PM))?"
        r"|less than (?:1|a) minute ago|just now", text, re.IGNORECASE,
    )
    return match.group(0) if match else ""


def _author(node: _Node | None, url: str) -> str:
    for link in node.find_all("a") if node else ():
        target = urlsplit(urljoin(url, link.attrs.get("href") or ""))
        if target.netloc == urlsplit(url).netloc and target.path.startswith("/User-"):
            return unquote(target.path[6:]).strip()
    return ""


def _thread_url(url: str, href: str, tid: str) -> str:
    target = urlsplit(urljoin(url, href))
    if target.scheme not in {"http", "https"} or target.netloc != urlsplit(url).netloc:
        return ""
    if target.path.startswith("/Thread-"):
        return urlunsplit((target.scheme, target.netloc, target.path, "", ""))
    if target.path == "/showthread.php" and parse_qs(target.query).get("tid") == [tid]:
        return urlunsplit((target.scheme, target.netloc, target.path, f"tid={tid}", ""))
    return ""


def parse_spear_list(url: str, html: str, max_topics: int = 20) -> dict:
    raise_if_error_page(html)
    root = _Document(html).root
    rows = [
        row for row in root.find_all("tr")
        if row.has_class("inline_row")
        and any(re.fullmatch(r"tid_\d+", node.attrs.get("id") or "") for node in row.find_all("span"))
    ]
    if not rows and not re.search(r"(?:no threads|currently no threads|no topics)", _text(root), re.IGNORECASE):
        raise CollectionFailure("parse", "Spear listing has no recognized thread rows")
    collected_at = utc_now_iso()
    topics = {}
    for row in rows:
        if row.find_all(cls="forumdisplay_sticky"):
            continue
        subject = next(node for node in row.find_all("span") if re.fullmatch(r"tid_\d+", node.attrs.get("id") or ""))
        tid = subject.attrs["id"][4:]
        link = subject.first("a")
        title = _text(link)
        target = _thread_url(url, link.attrs.get("href") or "", tid) if link else ""
        if not title or not target:
            continue
        cells = [child for child in row.children if isinstance(child, _Node) and child.tag == "td"]
        published = _timestamp(row.first(cls="thread_start_datetime"))
        last_reply = _timestamp(row.first(cls="lastpost"))
        topics.setdefault(tid, {
            "tid": tid, "title": title, "full_url": target,
            "relative_url": link.attrs.get("href") or "",
            "author": _author(row.first(cls="author"), url),
            "replies": _text(cells[3]) if len(cells) > 3 else "",
            "views": _text(cells[4]) if len(cells) > 4 else "",
            "published_at": published, "last_reply_at": last_reply,
            "content_hash": content_hash(title, tid, normalize_spear_timestamp(published, collected_at_utc=collected_at) or published),
        })
    values = list(topics.values())[:max(0, max_topics)]
    return {
        "site_name": "spear", "source_url": url, "domain": urlsplit(url).netloc,
        "title": _text(root.first("title")), "collected_at_utc": collected_at,
        "topic_count": len(values), "source_count": len(topics), "topics": values,
    }


def _strip_noncontent(node: _Node) -> bool:
    partial = False
    children = []
    for child in node.children:
        if not isinstance(child, _Node):
            children.append(child)
            continue
        classes = (child.attrs.get("class") or "").lower().split()
        if child.tag in {"script", "style", "noscript", "blockquote"} or any(
            name in classes for name in ("signature", "message-signature", "post_signature", "post_controls")
        ):
            continue
        if any(
            name.startswith(("hidden-content", "hide-content", "bbcodeblock--hide"))
            or name in {"hide-tag", "bbcode_hidden", "hidebox"}
            for name in classes
        ):
            partial = True
            continue
        if "hidden" in child.attrs or child.attrs.get("aria-hidden") == "true" or re.search(
            r"display\s*:\s*none", child.attrs.get("style") or "", re.IGNORECASE,
        ):
            continue
        partial = _strip_noncontent(child) or partial
        children.append(child)
    node.children = children
    return partial


def parse_spear_detail(url: str, html: str) -> dict:
    raise_if_error_page(html)
    query = parse_qs(urlsplit(url).query)
    if query.get("page", ["1"]) != ["1"]:
        raise CollectionFailure("parse", "Spear detail must contain the original post")
    root = _Document(html).root
    posts = [node for node in root.find_all() if re.fullmatch(r"post_\d+", node.attrs.get("id") or "")]
    if not posts:
        raise CollectionFailure("parse", "Spear response has no original post")
    post = posts[0]
    number = post.first(cls="postbit-number")
    if number is not None and _text(number).lstrip("#").strip() != "1":
        raise CollectionFailure("parse", "Spear response starts with a reply instead of the original post")
    body = post.first(cls="post_body")
    if body is None:
        raise CollectionFailure("parse", "Spear original post has no recognized body")
    partial = _strip_noncontent(body)
    content = _text(body)
    media_links = []
    if (partial and not re.sub(r"\b(?:downloads?|links?|mirrors?|samples?|hidden content)\b|[\W_]", "", content, flags=re.IGNORECASE)) or re.fullmatch(
        r"(?:hidden content[\s:.-]*)?(?:you (?:must|need to|have to) (?:register|log in|login|reply|like)|"
        r"(?:please )?(?:register|log in|login)|only registered members).{0,300}",
        content, re.IGNORECASE,
    ):
        raise CollectionFailure("restricted", "Spear original post requires login or an interaction")
    if not content:
        original = extract_body_content(body, base_url=url)
        content = original["content"]
        media_links = original.get("media_links", [])
    title = _text(root.first("h1")) or re.sub(r"\s*\|\s*Spear.*$", "", _text(root.first("title")), flags=re.IGNORECASE)
    author = _author(post.first(cls="post-username"), url) or "Unknown"
    timestamp = _timestamp(post.first(cls="post_date"))
    attachments = []
    for link in body.find_all("a"):
        target = urlsplit(urljoin(url, link.attrs.get("href") or ""))
        if target.scheme in {"http", "https"} and target.netloc == urlsplit(url).netloc and target.path == "/attachment.php" and parse_qs(target.query).get("aid"):
            target_url = urlunsplit(target)
            if target_url not in attachments:
                attachments.append(target_url)
    attachments.extend(link for link in media_links if link not in attachments)
    victims = extract_victims_from_content(content, title)
    collected_at = utc_now_iso()
    published_at = normalize_spear_timestamp(timestamp, collected_at_utc=collected_at)
    content_access = "partial" if partial else "public"
    return {
        "site_name": "spear", "source_url": url, "domain": urlsplit(url).netloc,
        "title": title, "collected_at_utc": collected_at, "content": content,
        "author": author, "timestamp": timestamp,
        "published_at_utc": published_at,
        "content_access": content_access, "attachments": attachments,
        **({"media_links": media_links} if media_links else {}),
        "victims": [{"name": victim, "industry": determine_industry(victim, f"{title} {content}"), "region": determine_region(victim)} for victim in victims],
        "attackers": extract_attackers_from_content(content),
        "content_hash": content_hash(title, content, author, published_at, content_access, *attachments),
    }
