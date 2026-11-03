from __future__ import annotations

import re
from urllib.parse import urljoin, urlsplit

from darkweb_collector.collection_errors import CollectionFailure, raise_if_error_page
from darkweb_collector.normalize import content_hash
from darkweb_collector.sites.spear import (
    _thread_url,
    _timestamp,
    normalize_spear_timestamp,
    parse_spear_detail,
)
from darkweb_collector.sites.xforums import _Document, _Node, _text
from darkweb_collector.utils import utc_now_iso


FORUM_SECTIONS = {
    name: f"https://leakforum.io/Forum-{slug}?sortby=started&order=desc&datecut=9999"
    for name, slug in (
        ("cloud_logs", "Cloud-Logs"),
        ("source_codes", "Source-codes"),
        ("other_leaks", "Other-Leaks"),
    )
}


def get_leakforum_sections() -> dict[str, str]:
    return dict(FORUM_SECTIONS)


def normalize_leakforum_timestamp(value: str | None, *, collected_at_utc: str | None = None) -> str:
    return normalize_spear_timestamp(value, collected_at_utc=collected_at_utc)


def _author(node: _Node | None, url: str) -> str:
    for link in node.find_all("a") if node else ():
        target = urlsplit(urljoin(url, link.attrs.get("href") or ""))
        if target.scheme in {"http", "https"} and target.netloc == urlsplit(url).netloc and target.path.strip("/"):
            name = _text(link)
            if name:
                return name
    return ""


def parse_leakforum_list(url: str, html: str, max_topics: int = 20) -> dict:
    raise_if_error_page(html)
    root = _Document(html).root
    rows = root.find_all("tr")
    for index, row in enumerate(rows):
        if any(
            isinstance(cell, _Node) and cell.has_class("tcat") and _text(cell) == "Normal Threads"
            for cell in row.children
        ):
            rows = rows[index + 1:]
            break
    collected_at = utc_now_iso()
    topics = {}
    for row in rows:
        if not row.has_class("inline_row"):
            continue
        subject = next((node for node in row.find_all("span") if re.fullmatch(r"tid_\d+", node.attrs.get("id") or "")), None)
        if subject is None:
            continue
        tid = subject.attrs["id"][4:]
        link = subject.first("a")
        title = _text(link)
        target = _thread_url(url, link.attrs.get("href") or "", tid) if link else ""
        if not title or not target:
            continue
        published = _timestamp(row.first(cls="thread-date"))
        stats = row.find_all(cls="stats-count")
        topics.setdefault(tid, {
            "tid": tid, "title": title, "full_url": target,
            "relative_url": link.attrs.get("href") or "",
            "author": _author(row.first(cls="author"), url),
            "replies": _text(stats[0]) if stats else "",
            "views": _text(stats[1]) if len(stats) > 1 else "",
            "published_at": published, "last_reply_at": _timestamp(row.first(cls="lastpost")),
            "content_hash": content_hash(title, tid, normalize_leakforum_timestamp(published, collected_at_utc=collected_at) or published),
        })
    if not topics and not re.search(r"(?:no threads|currently no threads|no topics)", _text(root), re.IGNORECASE):
        raise CollectionFailure("parse", "LeakForum listing has no recognized thread rows")
    values = list(topics.values())[:max(0, max_topics)]
    return {
        "site_name": "leakforum", "source_url": url, "domain": urlsplit(url).netloc,
        "title": _text(root.first("title")), "collected_at_utc": collected_at,
        "topic_count": len(values), "source_count": len(topics), "topics": values,
    }


def parse_leakforum_detail(url: str, html: str) -> dict:
    raise_if_error_page(html)
    root = _Document(html).root
    post = next((node for node in root.find_all() if re.fullmatch(r"post_\d+", node.attrs.get("id") or "")), None)
    if post is None:
        raise CollectionFailure("parse", "LeakForum response has no original post")
    number = post.first(cls="pagnum") or post.first(cls="postbit-number")
    if number is not None and _text(number).lstrip("#").strip() != "1":
        raise CollectionFailure("parse", "LeakForum response starts with a reply instead of the original post")
    try:
        detail = parse_spear_detail(url, html)
    except CollectionFailure as exc:
        raise CollectionFailure(exc.kind, str(exc).replace("Spear", "LeakForum"), scope=exc.scope, retry_after=exc.retry_after) from exc
    detail["site_name"] = "leakforum"
    detail["author"] = _author(post.first(cls="post-username"), url) or "Unknown"
    detail["content_hash"] = content_hash(
        detail["title"], detail["content"], detail["author"], detail["published_at_utc"],
        detail["content_access"], *detail["attachments"],
    )
    return detail
