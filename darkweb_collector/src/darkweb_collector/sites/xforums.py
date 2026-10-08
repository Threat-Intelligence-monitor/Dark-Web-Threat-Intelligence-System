from __future__ import annotations

from datetime import datetime, timezone
from html.parser import HTMLParser
import re
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

from darkweb_collector.normalize import content_hash
from darkweb_collector.sites.darkforums import (
    determine_industry,
    determine_region,
    extract_attackers_from_content,
    extract_victims_from_content,
)
from darkweb_collector.utils import utc_now_iso


class _Node:
    def __init__(self, tag: str, attrs=()):
        self.tag = tag
        self.attrs = dict(attrs)
        self.children: list[_Node | str] = []

    def has_class(self, name: str) -> bool:
        return name in (self.attrs.get("class") or "").split()

    def find_all(self, tag: str = "", cls: str = "") -> list[_Node]:
        found = []
        for child in self.children:
            if isinstance(child, _Node):
                if (not tag or child.tag == tag) and (not cls or child.has_class(cls)):
                    found.append(child)
                found.extend(child.find_all(tag, cls))
        return found

    def first(self, tag: str = "", cls: str = "") -> _Node | None:
        return next(iter(self.find_all(tag, cls)), None)

    def text(self) -> str:
        if self.tag in {"script", "style", "blockquote"} or self.has_class("message-signature"):
            return ""
        return " ".join(
            child.text() if isinstance(child, _Node) else child for child in self.children
        )


class _Document(HTMLParser):
    def __init__(self, html: str):
        super().__init__(convert_charrefs=True)
        self.root = _Node("document")
        self.stack = [self.root]
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        node = _Node(tag, attrs)
        self.stack[-1].children.append(node)
        if tag not in {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"}:
            self.stack.append(node)

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        self.handle_endtag(tag)

    def handle_endtag(self, tag):
        for index in range(len(self.stack) - 1, 0, -1):
            if self.stack[index].tag == tag:
                del self.stack[index:]
                break

    def handle_data(self, data):
        self.stack[-1].children.append(data)


def _text(node: _Node | None) -> str:
    return " ".join(node.text().split()) if node else ""


def _document(html: str, template: str) -> _Node:
    root = _Document(html).root
    element = root.first("html")
    if element is None or element.attrs.get("data-template") != template:
        raise ValueError("XForums returned a browser check, login page, or unrecognized forum page")
    return root


def normalize_xforums_timestamp(value: str | None, *, collected_at_utc: str | None = None) -> str:
    del collected_at_utc
    try:
        parsed = datetime.fromisoformat(str(value or "").strip().replace("Z", "+00:00"))
    except ValueError:
        return ""
    if parsed.tzinfo is not None:
        parsed = parsed.astimezone(timezone.utc)
    return parsed.date().isoformat()


def xforums_page_url(source_url: str, page: int) -> str:
    parsed = urlsplit(source_url)
    path = re.sub(r"/page-\d+/?$", "/", parsed.path).rstrip("/") + "/"
    if page > 1:
        path += f"page-{page}"
    query = [(key, value) for key, value in parse_qsl(parsed.query, keep_blank_values=True) if key.lower() != "page"]
    return urlunsplit((parsed.scheme, parsed.netloc, path, urlencode(query), ""))


def xforums_section(url: str) -> str:
    match = re.search(r"/forums/([^/]+)\.(\d+)(?:/|$)", urlsplit(url).path)
    if not match:
        raise ValueError("XForums seed URL must identify a forum board")
    return match.group(1).replace("-", "_")


def _page_number(url: str) -> int:
    match = re.search(r"/page-(\d+)/?$", urlsplit(url).path)
    return int(match.group(1)) if match else 1


def _pagination(root: _Node, url: str) -> tuple[int, bool]:
    current_nodes = root.find_all(cls="pageNav-page--current")
    current_values = {_text(node) for node in current_nodes}
    page = _page_number(url)
    if current_values and current_values != {str(page)}:
        raise ValueError("XForums pagination did not advance to the requested page")
    if page > 1 and not current_nodes:
        raise ValueError("XForums response has no verifiable current page")
    base = xforums_page_url(url, 1)
    has_more = False
    for nav in root.find_all(cls="pageNav"):
        for link in nav.find_all("a"):
            target = urljoin(url, link.attrs.get("href") or "")
            if xforums_page_url(target, 1) == base and _page_number(target) > page:
                has_more = True
    return page, has_more


def parse_xforums_list(url: str, html: str, max_topics: int = 20) -> dict:
    root = _document(html, "forum_view")
    rows = root.find_all(cls="structItem--thread")
    if not rows and not (
        root.first(cls="structItemContainer") is not None
        and re.search(r"there are no threads|no threads have been posted", _text(root), re.IGNORECASE)
    ):
        raise ValueError("XForums listing has no recognized threads or explicit empty state")
    page, has_more = _pagination(root, url)
    topics = {}
    for row in rows:
        title_node = row.first(cls="structItem-title")
        links = title_node.find_all("a") if title_node else []
        target = ""
        tid = ""
        title = ""
        for link in links:
            candidate = urlsplit(urljoin(url, link.attrs.get("href") or ""))
            match = re.fullmatch(r"/threads/(?:[^/]+\.)?(\d+)/?", candidate.path)
            if candidate.netloc == urlsplit(url).netloc and match:
                tid = match.group(1)
                target = urljoin(url, f"/threads/{tid}/")
                title = _text(link)
                break
        if not tid or not title:
            raise ValueError("XForums thread row has no recognized title or stable identifier")
        row_id = re.search(r"\bjs-threadListItem-(\d+)\b", row.attrs.get("class") or "")
        if row_id and row_id.group(1) != tid:
            raise ValueError("XForums thread row and link identifiers disagree")
        start = row.first(cls="structItem-startDate")
        started = start.first("time") if start else None
        published = started.attrs.get("datetime", "") if started else ""
        latest = row.first("time", "structItem-latestDate")
        counts = {}
        for pair in row.find_all("dl"):
            counts[_text(pair.first("dt")).lower()] = _text(pair.first("dd"))
        topics.setdefault(tid, {
            "tid": tid, "title": title, "full_url": target,
            "relative_url": f"/threads/{tid}/", "author": row.attrs.get("data-author") or "",
            "published_at": published, "last_reply_at": latest.attrs.get("datetime", "") if latest else "",
            "replies": counts.get("replies", ""), "views": counts.get("views", ""),
            "content_hash": content_hash(title, tid, published),
        })
    values = list(topics.values())
    return {
        "site_name": "xforums", "source_url": url, "domain": urlsplit(url).netloc,
        "title": _text(root.first("title")), "collected_at_utc": utc_now_iso(),
        "topics": values[:max(0, max_topics)], "topic_count": min(len(values), max(0, max_topics)),
        "source_count": len(values), "current_page": page, "has_more": has_more,
    }


def parse_xforums_detail(url: str, html: str) -> dict:
    root = _document(html, "thread_view")
    if _pagination(root, url)[0] != 1:
        raise ValueError("XForums detail must contain the original post, not a replies page")
    posts = root.find_all("article", "message--post")
    post = next((item for item in posts if item.has_class("is-first") or item.attrs.get("data-position") == "0"), None)
    if post is None:
        raise ValueError("XForums original post is unavailable or requires login")
    message_body = post.first(cls="message-body")
    body = message_body.first(cls="bbWrapper") if message_body else None
    content = _text(body)
    if not content:
        raise ValueError("XForums original post has no visible text")
    restricted = [
        node for node in body.find_all()
        if any(name.startswith(("bbCodeBlock--hide", "bbCodeBlock--hidden")) for name in (node.attrs.get("class") or "").split())
    ]
    visible = content
    for node in restricted:
        visible = visible.replace(_text(node), "")
    if not visible.strip() or re.fullmatch(
        r"you (?:must|need to|have to) (?:log in|login|register|reply|react).{0,200}",
        visible.strip(), re.IGNORECASE,
    ):
        raise ValueError("XForums post content requires login or an interaction")
    title = _text(root.first("h1", "p-title-value")) or _text(root.first("title")).split(" | ", 1)[0]
    attribution = post.first(cls="message-attribution")
    timestamp_node = attribution.first("time") if attribution else post.first("time")
    timestamp = timestamp_node.attrs.get("datetime", "") if timestamp_node else ""
    author = post.attrs.get("data-author") or _text(post.first(cls="message-name")) or "Unknown"
    attachments = list(dict.fromkeys(
        urljoin(url, link.attrs["href"]) for link in post.find_all("a")
        if re.match(r"/attachments/", urlsplit(urljoin(url, link.attrs.get("href") or "")).path)
        and urlsplit(urljoin(url, link.attrs.get("href") or "")).netloc == urlsplit(url).netloc
    ))
    victims = extract_victims_from_content(content, title)
    return {
        "site_name": "xforums", "source_url": url, "domain": urlsplit(url).netloc,
        "title": title, "collected_at_utc": utc_now_iso(), "content": content,
        "author": author, "timestamp": timestamp, "published_at_utc": normalize_xforums_timestamp(timestamp),
        "content_access": "partial" if restricted else "public",
        "attachments": attachments,
        "victims": [{"name": victim, "industry": determine_industry(victim, f"{title} {content}"), "region": determine_region(victim)} for victim in victims],
        "attackers": extract_attackers_from_content(content),
        "content_hash": content_hash(title, content, author, timestamp, *attachments),
    }
