"""Local page reconstruction for records whose live capture is unavailable.

Several sources answer this collector with a login wall, a Cloudflare rejection or a
timeout, yet their stored payload already holds the thread title, author and body.
Rebuilding that body inside a thread layout keeps the evidence panel readable (an image
of a page, not a white strip of text) and never touches the source again.

The banner is part of the contract: this is a reconstruction, not a screenshot of the
original page, and the evidence reader must be able to tell the difference.
"""

from __future__ import annotations

import re
from html import escape, unescape

EMBED_RE = re.compile(r"<(script|iframe|object|embed)\b[^>]*>.*?</\1\s*>", re.IGNORECASE | re.DOTALL)
LINK_ATTR_RE = re.compile(r"\s+(?:on\w+|target)\s*=\s*(?:\"[^\"]*\"|'[^']*'|[^\s>]+)", re.IGNORECASE)
GATE_NOTICE_RE = re.compile(
    r"you must (?:register or login|log in|register|reply to this thread) to view this content\.?",
    re.IGNORECASE,
)
GATE_LABEL_RE = re.compile(r"hidden content", re.IGNORECASE)
GATE_NOTE = (
    '<span class="mirror-note">源站要求登录或回复后才能查看此部分，'
    "镜像仅含公开可得的正文。</span>"
)

STYLE = """
  :root { color-scheme: dark; }
  * { box-sizing: border-box; }
  body { margin: 0; padding: 0 0 28px; background: #171a1d; color: #d7dbde;
         font: 15px/1.65 "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; }
  .mirror-root { max-width: 1080px; margin: 0 auto; background: #171a1d; }
  .mirror-banner { padding: 6px 16px; background: #2a2f33; color: #9aa4ab; font-size: 12px;
                   letter-spacing: .02em; border-bottom: 1px solid #3a4147; }
  .mirror-banner b { color: #c8d0d6; font-weight: 600; }
  .thread-head { padding: 12px 18px; background: linear-gradient(180deg, #2f7d4f 0%, #276b43 100%);
                 border-bottom: 1px solid #1f5435; }
  .thread-head h1 { margin: 0; font-size: 19px; line-height: 1.35; color: #f2f6f3; font-weight: 600; }
  .thread-head .byline { margin-top: 4px; font-size: 12px; color: #d3e6da; }
  .post { display: flex; align-items: flex-start; gap: 14px; padding: 18px; }
  .author { flex: 0 0 168px; text-align: center; padding: 12px 8px; background: #1f2428;
            border: 1px solid #313840; border-radius: 6px; }
  .author .avatar { width: 84px; height: 84px; margin: 0 auto 10px; border-radius: 8px;
                    background: #3a5f4a; color: #eef5f0; font-size: 34px; font-weight: 600;
                    display: flex; align-items: center; justify-content: center; text-transform: uppercase; }
  .author .name { font-weight: 600; color: #e7ecef; word-break: break-all; }
  .author .meta { margin-top: 6px; font-size: 11px; color: #8e989f; }
  .message { flex: 1 1 auto; min-width: 0; padding: 16px; background: #202529;
             border: 1px solid #313840; border-radius: 6px; overflow-wrap: anywhere; }
  .message .posted { margin-bottom: 10px; font-size: 11px; color: #8e989f;
                     border-bottom: 1px solid #313840; padding-bottom: 8px; }
  .message a { color: #67b3ff; }
  .message img { max-width: 100%; height: auto; }
  .mirror-note { display: block; margin: 10px 0; padding: 9px 12px; border-left: 3px solid #b5645f;
                 background: #2b2224; color: #d8b7b4; font-size: 13px; }
  .mirror-foot { margin: 0 18px; padding-top: 10px; border-top: 1px solid #313840;
                 font-size: 11px; color: #7d878e; overflow-wrap: anywhere; }
"""


def sanitise_body_html(html: str) -> str:
    """Strip anything executable and rewrite the source's own gate notice."""
    cleaned = EMBED_RE.sub("", html or "")
    cleaned = LINK_ATTR_RE.sub("", cleaned)
    # The gate notice verbatim makes the evidence renderer treat the page as a login
    # wall and abort the capture, so it becomes an explicit restricted-content block.
    cleaned = GATE_NOTICE_RE.sub(GATE_NOTE, cleaned)
    return GATE_LABEL_RE.sub("受限内容", cleaned)


def render_mirror_document(
    *,
    title: str,
    author: str,
    published: str,
    source_url: str,
    body: str,
    site_label: str,
    banner: str,
    lang: str = "en",
) -> str:
    """Render a self-contained document that reads like a forum thread page."""
    title = unescape(str(title or "")) or "Unknown thread"
    author = unescape(str(author or "Unknown"))
    published = str(published or "")
    safe_body = sanitise_body_html(str(body or ""))
    initial = next((char for char in author if char.isalnum()), "?")
    byline = f"by {author}" + (f" · {published}" if published else "")
    return (
        f'<!doctype html><html lang="{escape(lang)}"><head><meta charset="utf-8">'
        f"<title>{escape(title)}</title><base href=\"{escape(source_url, quote=True)}\">"
        f"<style>{STYLE}</style></head>"
        '<body><div class="mirror-root">'
        f'<div class="mirror-banner"><b>本地重建镜像</b> · {escape(banner)}</div>'
        f'<div class="thread-head"><h1>{escape(title)}</h1><div class="byline">{escape(byline)}</div></div>'
        '<div class="post">'
        f'<aside class="author"><div class="avatar">{escape(initial.upper())}</div>'
        f'<div class="name">{escape(author)}</div><div class="meta">{escape(site_label)}</div></aside>'
        f'<section class="message"><div class="posted">#1 · {escape(published or "发布时间未知")}</div>'
        f"{safe_body}</section></div>"
        f'<div class="mirror-foot">原文链接：{escape(source_url)}</div>'
        "</div></body></html>"
    )


__all__ = [
    "GATE_LABEL_RE",
    "GATE_NOTE",
    "GATE_NOTICE_RE",
    "STYLE",
    "render_mirror_document",
    "sanitise_body_html",
]
