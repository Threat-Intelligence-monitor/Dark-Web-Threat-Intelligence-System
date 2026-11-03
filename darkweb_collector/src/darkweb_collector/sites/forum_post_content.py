"""Visible original-post text, with quotes kept distinct from author prose."""
from __future__ import annotations

from html.parser import HTMLParser
import re
from urllib.parse import parse_qs, urljoin, urlsplit

from darkweb_collector.collection_errors import CollectionFailure, raise_if_error_page


_VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"}
_IGNORE_TAGS = {"script", "style", "template", "noscript", "nav", "footer", "aside", "form", "button", "input", "select", "textarea"}
_IGNORE_CLASSES = {"signature", "post_signature", "message-signature", "post_controls", "post_meta", "post_actions", "post_toolbar", "quote_expand", "bbCodeBlock-expandLink"}
_RESTRICTED_CLASSES = {"hide-tag", "hide-content", "hidden-content", "bbcode_hidden", "hidebox"}
_QUOTE_TITLES = {"quote_title", "quote-title", "bbCodeBlock-title"}
_PROMPT = re.compile(r"(?:(?:hidden content|this content is hidden)[\s.!:,-]*)?(?:you (?:must|need to|have to) (?:log in|login|register|reply|react|like)|(?:please )?(?:log in|login|register|reply|react|like)|only registered members).{0,300}", re.I)


class _Node:
    def __init__(self, tag, attrs=(), *, parent=None, start=0, end=0):
        self.tag, self.attrs, self.parent = tag, dict(attrs), parent
        self.start, self.end, self.children = start, end, []


class _Document(HTMLParser):
    def __init__(self, source):
        super().__init__(convert_charrefs=True)
        self.source = source
        self.lines = [0] + [m.end() for m in re.finditer("\n", source)]
        self.root = _Node("document", end=len(source))
        self.stack = [self.root]
        self.feed(source)

    def _offset(self):
        line, column = self.getpos()
        return self.lines[line - 1] + column

    def handle_starttag(self, tag, attrs):
        start = self._offset()
        node = _Node(tag, attrs, parent=self.stack[-1], start=start, end=len(self.source))
        self.stack[-1].children.append(node)
        if tag in _VOID:
            node.end = start + len(self.get_starttag_text())
        else:
            if len(self.stack) >= 256:
                raise CollectionFailure("parse", "forum document nesting exceeds the parser limit")
            self.stack.append(node)

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        if tag not in _VOID:
            self.stack.pop().end = self._offset() + len(self.get_starttag_text())

    def handle_endtag(self, tag):
        end = self.source.find(">", self._offset())
        end = end + 1 if end >= 0 else len(self.source)
        for index in range(len(self.stack) - 1, 0, -1):
            if self.stack[index].tag == tag:
                for node in self.stack[index:]:
                    node.end = end
                del self.stack[index:]
                break

    def handle_data(self, data):
        self.stack[-1].children.append(data)


def _nodes(node):
    pending = [node]
    while pending:
        current = pending.pop()
        yield current
        pending.extend(reversed([child for child in current.children if not isinstance(child, str)]))


def _classes(node):
    return set(str(node.attrs.get("class") or "").split())


def _ignored(node):
    return (node.tag in _IGNORE_TAGS or bool(_classes(node) & _IGNORE_CLASSES)
            or "hidden" in node.attrs or str(node.attrs.get("aria-hidden") or "").lower() == "true"
            or bool(re.search(r"display\s*:\s*none|visibility\s*:\s*hidden", str(node.attrs.get("style") or ""), re.I)))


def _restricted(node):
    return bool(_classes(node) & _RESTRICTED_CLASSES) or any(
        name.startswith(("bbCodeBlock--hide", "bbCodeBlock--hidden")) for name in _classes(node))


def _post(node):
    return (node.tag == "div" and re.fullmatch(r"post_\d+", str(node.attrs.get("id") or "")) is not None
            or node.tag == "article" and "message--post" in _classes(node))


def _ancillary(node):
    parent = getattr(node, "parent", None)
    while parent is not None:
        if parent.tag in _IGNORE_TAGS | {"header", "blockquote", "pre", "code"} or _classes(parent) & _IGNORE_CLASSES:
            return True
        parent = getattr(parent, "parent", None)
    return False


def _normal(value):
    return " ".join(value.split())


def is_post_container(node):
    return _post(node) and not _ancillary(node)


def _pagination_url_key(url):
    parsed = urlsplit(url)
    path = re.sub(r"(?:/page[-/]|-page-)\d+(?=(?:\.html)?/?$)", "", parsed.path).rstrip("/")
    xenforo = re.fullmatch(r"/(threads|forums)/(?:[^/]+\.)?(\d+)", path)
    if xenforo:
        path = f"/{xenforo.group(1)}/{xenforo.group(2)}"
    query = parse_qs(parsed.query)
    prefix, _, filename = path.rpartition("/")
    mybb = re.fullmatch(r"thread-(\d+)\.html", filename, re.I)
    if mybb:
        path, filename, query = prefix + "/showthread.php", "showthread.php", {"tid": [mybb.group(1)]}
    keys = {"showthread.php": ("tid",), "forumdisplay.php": ("fid",)}.get(filename, ("tid", "fid"))
    identity = tuple((key, tuple(query.get(key, ()))) for key in keys) if path.endswith(".php") else ()
    return parsed.netloc.lower(), path, identity


def _pagination_context(node):
    group, parent, needs_link = None, node, False
    while parent is not None:
        classes = _classes(parent)
        # Semantic header/footer/nav tags can also contain the real pager.
        if (parent.tag in (_IGNORE_TAGS - {"nav", "footer"}) | {"blockquote", "pre", "code", "iframe", "object"}
                or _post(parent) or _restricted(parent) or classes & (_IGNORE_CLASSES | {
                    "navigation", "pagination_breadcrumb", "breadcrumb", "breadcrumbs", "p-breadcrumbs", "p-nav",
                    "post_body", "post_content", "messageContent", "message-body", "message-userContent",
                })
                or "hidden" in parent.attrs or str(parent.attrs.get("aria-hidden") or "").lower() == "true"
                or re.search(r"display\s*:\s*none|visibility\s*:\s*hidden", str(parent.attrs.get("style") or ""), re.I)):
            return False, None, False
        if group is None and classes & {"pagination", "pageNav"}:
            group = parent
        needs_link = needs_link or parent.tag in {"header", "footer"}
        parent = getattr(parent, "parent", None)
    return True, group, needs_link


def is_current_pagination(node, url: str) -> bool:
    """Ignore navigation/examples and pagers explicitly pointing elsewhere."""
    eligible, group, needs_link = _pagination_context(node)
    if not eligible:
        return False

    def targets(container):
        return [urljoin(url, str(item.attrs["href"])) for item in _nodes(container)
                if item.tag == "a" and item.attrs.get("href")
                and _pagination_context(item)[0]
                and not str(item.attrs["href"]).startswith(("#", "javascript:"))]

    # The current page's own link is stronger evidence than adjacent links.
    links = targets(node) or (targets(group) if group is not None else [])
    return not needs_link if not links else any(_pagination_url_key(link) == _pagination_url_key(url) for link in links)


def pagination_label(node) -> str:
    parts, pending = [], [node]
    while pending:
        current = pending.pop()
        if isinstance(current, str):
            parts.append(current)
        elif not _ignored(current):
            pending.extend(reversed(current.children))
    return _normal(" ".join(parts))


def extract_body_content(body) -> dict:
    if body is None:
        raise CollectionFailure("parse", "forum original post has no recognized body container")
    parent = body
    while parent is not None:
        if _ignored(parent) or _restricted(parent):
            kind = "restricted" if _restricted(parent) else "parse"
            raise CollectionFailure(kind, "forum original post body is not publicly visible")
        parent = getattr(parent, "parent", None)
    attributions = []
    restricted = any(_restricted(node) for node in _nodes(body))

    def render(node, *, quotes=True, in_quote=False):
        if _ignored(node) or _restricted(node) or (_post(node) and not in_quote):
            return ""
        citation = node.tag == "cite" or bool(_classes(node) & _QUOTE_TITLES)
        if in_quote and citation:
            return ""
        if node.tag == "blockquote":
            if not quotes:
                return ""
            quote_text = _normal(" ".join(child if isinstance(child, str) else render(child, in_quote=True) for child in node.children))
            if not quote_text:
                return ""
            # Do not attribute a parent quote to a nested quote's cited author.
            search, attribution = list(node.children), ""
            while search:
                child = search.pop(0)
                if isinstance(child, str) or child.tag == "blockquote" or _ignored(child):
                    continue
                if child.tag == "cite" or _classes(child) & _QUOTE_TITLES:
                    attribution = _normal(render(child, quotes=False))
                    break
                search[0:0] = child.children
            attribution = attribution or _normal(str(node.attrs.get("cite") or ""))
            if attribution and attribution not in attributions:
                attributions.append(attribution)
            return (f"[引用：{attribution}] " if attribution else "[引用] ") + quote_text + " [/引用]"
        return " ".join(child if isinstance(child, str) else render(child, quotes=quotes, in_quote=in_quote) for child in node.children)

    content = _normal(render(body))
    own_content = _normal(render(body, quotes=False))
    if not content:
        if restricted:
            raise CollectionFailure("restricted", "post body only contains an access or interaction prompt")
        media = any(node.tag in {"img", "video", "audio", "iframe", "object", "embed"} and not _ignored(node) for node in _nodes(body))
        raise CollectionFailure("parse", "forum original post contains media without readable text" if media
                                else "forum original post has no visible text")
    if _PROMPT.fullmatch(content):
        raise CollectionFailure("restricted", "post body only contains an access or interaction prompt")
    return {"content": content, "content_access": "partial" if restricted else "public",
            "content_quote_only": not bool(own_content), "quote_attributions": attributions}


def extract_mybb_post(url: str, html: str) -> dict:
    raise_if_error_page(html)
    parsed_url = urlsplit(url)
    pages = parse_qs(parsed_url.query).get("page", [])
    path_page = re.search(r"(?:/|-)page[-/](\d+)(?:\.html)?(?:/|$)", parsed_url.path)
    if any(value.isdigit() and int(value) > 1 for value in pages) or path_page and int(path_page.group(1)) > 1:
        raise CollectionFailure("parse", "forum detail must contain the original post, not a replies page")
    document = _Document(html)
    nodes = list(_nodes(document.root))
    for node in nodes:
        if _classes(node) & {"pagination_current", "pageNav-page--current"} and is_current_pagination(node, url):
            label = pagination_label(node)
            if label.isdigit() and int(label) > 1:
                raise CollectionFailure("parse", "forum response is a replies page")
    posts = [node for node in nodes if is_post_container(node)]
    header = ""
    if posts:
        first = posts[0]
        parent = first
        while parent is not None:
            if _ignored(parent) or _restricted(parent):
                kind = "restricted" if _restricted(parent) else "parse"
                raise CollectionFailure(kind, "forum original post is not publicly visible")
            parent = parent.parent
        end = min(first.end, posts[1].start) if len(posts) > 1 else first.end
        header, scoped = html[:first.start], html[first.start:end]
        document = _Document(scoped)
        nodes = list(_nodes(document.root))
    else:
        scoped = html
    bodies = [node for node in nodes if _classes(node) & {"post_body", "post_content", "messageContent"}
              and not _ancillary(node)]
    preferred = [node for node in bodies if "post_body" in _classes(node)] or bodies
    if not preferred or not posts and len(preferred) != 1:
        raise CollectionFailure("parse", "forum response has no identifiable original post body")
    body = preferred[0]
    result = extract_body_content(body)
    # Metadata keeps its original parsing rules, but must not read quoted authors
    # or dates from the body or a later reply.
    metadata = scoped[:body.start] + " " + scoped[body.end:]
    metadata = re.sub(r"<(script|style)\b[^>]*>.*?</\1>", " ", metadata, flags=re.I | re.S)
    header = re.sub(r"<(script|style)\b[^>]*>.*?</\1>", " ", header, flags=re.I | re.S)
    return {**result, "post_html": scoped, "metadata_html": metadata, "header_html": header}
