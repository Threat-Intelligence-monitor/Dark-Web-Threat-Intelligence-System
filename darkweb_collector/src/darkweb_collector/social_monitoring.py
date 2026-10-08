from __future__ import annotations

from datetime import datetime, timedelta, timezone
from html import unescape
from html.parser import HTMLParser
import json
import logging
import os
from pathlib import Path
import re
from threading import Event, Lock, Thread
from typing import Any, Callable
from urllib.parse import parse_qs, quote, urlsplit
from urllib.request import Request, urlopen
import uuid

from darkweb_collector.db import get_db_connection


logger = logging.getLogger(__name__)
ENGINES = {
    "x": (("social_searcher_x", "3a9b377185eceb40a"), ("awesome_x", "5857bab69c8b8e37e")),
    "facebook": (("awesome_facebook", "95ae46262a5f2958e"),),
}
X_POST = re.compile(r"^/([A-Za-z0-9_]{1,15})/status/(\d+)$")
FB_POST = re.compile(r"^/(?!groups/)[^?#]*/(?:posts|permalink)/[^?#]*?(\d+)$", re.I)
USER_AGENT = "DarkwebThreatIntel-PublicSocialMonitor/1.0 (read-only; no login or captcha bypass)"
LEASE_MINUTES = 15
LEASE_RENEW_SECONDS = 60
_worker_lock = Lock()
_worker_stop = Event()
_worker: Thread | None = None
_schema_lock = Lock()
_schema_ready: set[tuple] = set()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _later(minutes: int) -> str:
    return (datetime.now(timezone.utc) + timedelta(minutes=minutes)).isoformat(timespec="seconds")


def _schema(connection) -> None:
    key = tuple(getattr(connection, "cache_identity", ("connection", id(connection))))
    if key in _schema_ready:
        return
    with _schema_lock:
        if key in _schema_ready:
            return
        connection.execute("""CREATE TABLE IF NOT EXISTS social_watchlists (
            id TEXT PRIMARY KEY, name TEXT NOT NULL, aliases_json TEXT NOT NULL,
            risk_terms_json TEXT NOT NULL, queries_json TEXT NOT NULL,
            interval_minutes INTEGER NOT NULL, max_posts_per_platform INTEGER NOT NULL,
            enabled INTEGER NOT NULL, next_scan_at TEXT NOT NULL, lease_until TEXT NOT NULL DEFAULT '',
            lease_owner TEXT NOT NULL DEFAULT '',
            last_scan_at TEXT NOT NULL DEFAULT '', last_scan_status TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL, updated_at TEXT NOT NULL
        )""")
        columns = connection.execute("SELECT * FROM social_watchlists LIMIT 0").description
        if "lease_owner" not in {column[0] for column in columns}:
            connection.execute("ALTER TABLE social_watchlists ADD COLUMN lease_owner TEXT NOT NULL DEFAULT ''")
        connection.execute("""CREATE TABLE IF NOT EXISTS social_scan_runs (
            id TEXT PRIMARY KEY, watchlist_id TEXT NOT NULL, status TEXT NOT NULL,
            stats_json TEXT NOT NULL, started_at TEXT NOT NULL, finished_at TEXT NOT NULL DEFAULT ''
        )""")
        connection.execute("""CREATE TABLE IF NOT EXISTS social_hits (
            id TEXT PRIMARY KEY, watchlist_id TEXT NOT NULL, platform TEXT NOT NULL,
            post_id TEXT NOT NULL, source_url TEXT NOT NULL, title TEXT NOT NULL,
            excerpt TEXT NOT NULL, author TEXT NOT NULL, source_status TEXT NOT NULL,
            classification TEXT NOT NULL, matched_aliases_json TEXT NOT NULL,
            matched_risks_json TEXT NOT NULL, found_via_json TEXT NOT NULL,
            review_status TEXT NOT NULL DEFAULT 'pending', evidence_url TEXT NOT NULL DEFAULT '',
            review_note TEXT NOT NULL DEFAULT '', reviewer TEXT NOT NULL DEFAULT '',
            first_seen_at TEXT NOT NULL, last_seen_at TEXT NOT NULL, reviewed_at TEXT NOT NULL DEFAULT ''
        )""")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_social_hits_watchlist ON social_hits(watchlist_id, classification, last_seen_at)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_social_runs_watchlist ON social_scan_runs(watchlist_id, started_at)")
        connection.commit()
        _schema_ready.add(key)


def _terms(raw: Any, *, label: str, limit: int) -> list[str]:
    if not isinstance(raw, list):
        raise ValueError(f"{label} must be a list")
    terms = list(dict.fromkeys(" ".join(str(value).split()) for value in raw if str(value).strip()))
    if not terms or len(terms) > limit or any(len(value) > 100 for value in terms):
        raise ValueError(f"{label} must contain 1-{limit} entries of at most 100 characters")
    return terms


def _watchlist_payload(row) -> dict[str, Any]:
    item = dict(row)
    item.pop("lease_owner", None)
    for key in ("aliases", "risk_terms", "queries"):
        item[key] = json.loads(item.pop(f"{key}_json"))
    item["enabled"] = bool(item["enabled"])
    return item


def save_watchlist(payload: dict[str, Any], watchlist_id: str | None = None) -> dict[str, Any]:
    name = " ".join(str(payload.get("name") or "").split())
    if not name or len(name) > 80:
        raise ValueError("name must contain 1-80 characters")
    aliases = _terms(payload.get("aliases"), label="aliases", limit=8)
    risks = _terms(payload.get("risk_terms"), label="risk_terms", limit=12)
    queries = _terms(payload.get("queries"), label="queries", limit=4)
    interval = int(payload.get("interval_minutes", 120))
    maximum = int(payload.get("max_posts_per_platform", 8))
    if not 60 <= interval <= 1440 or not 1 <= maximum <= 30:
        raise ValueError("interval_minutes must be 60-1440 and max_posts_per_platform must be 1-30")
    enabled = bool(payload.get("enabled", True))
    now = _now()
    with get_db_connection() as connection:
        _schema(connection)
        existing = connection.execute("SELECT * FROM social_watchlists WHERE id = ?", (watchlist_id,)).fetchone() if watchlist_id else None
        if watchlist_id and existing is None:
            raise ValueError("watchlist not found")
        selected_id = watchlist_id or uuid.uuid4().hex
        next_scan = now if enabled and (existing is None or not existing["enabled"]) else (
            existing["next_scan_at"] if existing else now
        )
        if existing:
            connection.execute("""UPDATE social_watchlists SET name=?, aliases_json=?, risk_terms_json=?,
                queries_json=?, interval_minutes=?, max_posts_per_platform=?, enabled=?,
                next_scan_at=?, updated_at=? WHERE id=?""", (
                name, json.dumps(aliases, ensure_ascii=False), json.dumps(risks, ensure_ascii=False),
                json.dumps(queries, ensure_ascii=False), interval, maximum, int(enabled), next_scan, now, selected_id,
            ))
        else:
            connection.execute("""INSERT INTO social_watchlists
                (id,name,aliases_json,risk_terms_json,queries_json,interval_minutes,max_posts_per_platform,
                 enabled,next_scan_at,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)""", (
                selected_id, name, json.dumps(aliases, ensure_ascii=False), json.dumps(risks, ensure_ascii=False),
                json.dumps(queries, ensure_ascii=False), interval, maximum, int(enabled), next_scan, now, now,
            ))
        row = connection.execute("SELECT * FROM social_watchlists WHERE id = ?", (selected_id,)).fetchone()
        connection.commit()
    return _watchlist_payload(row)


def list_watchlists() -> list[dict[str, Any]]:
    with get_db_connection() as connection:
        _schema(connection)
        rows = connection.execute("SELECT * FROM social_watchlists ORDER BY created_at DESC").fetchall()
        connection.commit()
    return [_watchlist_payload(row) for row in rows]


def get_watchlist(watchlist_id: str) -> dict[str, Any] | None:
    with get_db_connection() as connection:
        _schema(connection)
        row = connection.execute("SELECT * FROM social_watchlists WHERE id = ?", (watchlist_id,)).fetchone()
        connection.commit()
    return _watchlist_payload(row) if row else None


def canonical_post(value: str) -> tuple[str, str, str] | None:
    parsed = urlsplit(unescape(str(value or "")))
    if parsed.scheme != "https":
        return None
    host = (parsed.hostname or "").lower()
    path = parsed.path.rstrip("/")
    if host in {"x.com", "twitter.com", "mobile.x.com", "mobile.twitter.com"}:
        match = X_POST.fullmatch(path)
        if match:
            author, post_id = match.groups()
            return "x", post_id, f"https://x.com/{author}/status/{post_id}"
    if host in {"facebook.com", "www.facebook.com", "m.facebook.com"}:
        match = FB_POST.fullmatch(path)
        if match:
            return "facebook", match.group(1), f"https://www.facebook.com{path}"
        if path in {"/permalink.php", "/story.php"}:
            post_id = parse_qs(parsed.query).get("story_fbid", [""])[0]
            if post_id.isdigit():
                return "facebook", post_id, f"https://www.facebook.com/story.php?story_fbid={post_id}"
    return None


def _term_present(text: str, term: str) -> bool:
    if term.isascii() and len(term) <= 4 and term.isalpha():
        return re.search(rf"(?<![A-Za-z]){re.escape(term)}(?![A-Za-z])", text, re.I) is not None
    return term.casefold() in text.casefold()


def match_post(text: str, aliases: list[str], risks: list[str]) -> tuple[str, list[str], list[str]]:
    matched_aliases = [term for term in aliases if _term_present(text, term)]
    if not matched_aliases:
        return "not_target", [], []
    matched_risks = [term for term in risks if _term_present(text, term)]
    if not matched_risks:
        return "no_risk", [], []
    return "candidate", matched_aliases, matched_risks


class _Paragraph(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.in_p = False
        self.parts: list[str] = []

    def handle_starttag(self, tag, attrs) -> None:
        if tag == "p" and not self.parts:
            self.in_p = True
        if tag == "br" and self.in_p:
            self.parts.append(" ")

    def handle_endtag(self, tag) -> None:
        if tag == "p":
            self.in_p = False

    def handle_data(self, data) -> None:
        if self.in_p:
            self.parts.append(data)


class _Metadata(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.fields: dict[str, str] = {}

    def handle_starttag(self, tag, attrs) -> None:
        if tag == "meta":
            values = dict(attrs)
            key = str(values.get("property") or values.get("name") or "").lower()
            if key and values.get("content"):
                self.fields[key] = unescape(values["content"])


def _http_get(url: str, max_bytes: int = 1_000_000) -> tuple[bytes, str]:
    request = Request(url, headers={"User-Agent": USER_AGENT, "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8"})
    with urlopen(request, timeout=18) as response:
        body = response.read(max_bytes + 1)
        if len(body) > max_bytes:
            raise ValueError("response too large")
        return body, response.geturl()


def fetch_public_post(platform: str, url: str) -> dict[str, str]:
    try:
        if platform == "x":
            endpoint = "https://publish.twitter.com/oembed?omit_script=1&url=" + quote(url, safe="")
            body, final = _http_get(endpoint)
            if urlsplit(final).hostname not in {"publish.twitter.com", "publish.x.com"}:
                raise ValueError("embed redirected away")
            payload = json.loads(body)
            expected = canonical_post(url)
            actual = canonical_post(str(payload.get("url") or ""))
            if not expected or not actual or expected[:2] != actual[:2]:
                raise ValueError("embed post ID mismatch")
            parser = _Paragraph()
            parser.feed(str(payload.get("html") or ""))
            text = " ".join("".join(parser.parts).split())
            if not text:
                raise ValueError("embed has no post text")
            return {"status": "source_text", "text": text, "author": str(payload.get("author_name") or "")}
        body, final = _http_get(url)
        if urlsplit(final).hostname not in {"facebook.com", "www.facebook.com", "m.facebook.com"}:
            raise ValueError("post redirected away")
        expected, actual = canonical_post(url), canonical_post(final)
        if not expected or not actual or expected[:2] != actual[:2]:
            raise ValueError("public post ID mismatch")
        parser = _Metadata()
        parser.feed(body.decode("utf-8", errors="replace"))
        text = parser.fields.get("og:description") or parser.fields.get("description") or ""
        if not text or "log in to facebook" in text.lower():
            raise ValueError("public post metadata unavailable")
        return {"status": "public_metadata", "text": text, "author": parser.fields.get("og:title", "")}
    except Exception as exc:
        return {"status": "unavailable", "text": "", "error": f"{type(exc).__name__}: {exc}"[:180]}


def discover_cse(context, platform: str, query: str, engine: str) -> list[dict[str, str]]:
    engine_id = next(value for name, value in ENGINES[platform] if name == engine)
    page = context.new_page()
    try:
        page.goto(f"https://cse.google.com/cse?cx={engine_id}", wait_until="domcontentloaded", timeout=20_000)
        field = page.locator("input.gsc-input[name=search]").first
        field.wait_for(timeout=12_000)
        field.fill(query)
        field.press("Enter")
        try:
            page.locator(".gsc-webResult.gsc-result").first.wait_for(timeout=15_000)
        except Exception as exc:
            page_text = page.locator("body").inner_text().lower()
            if "no results" in page_text or "did not match any results" in page_text:
                return []
            raise RuntimeError("search results unavailable or challenge shown") from exc
        hits: list[dict[str, str]] = []
        for row in page.locator(".gsc-webResult.gsc-result").all()[:10]:
            link = row.locator("a.gs-title").first
            if link.count():
                snippet = row.locator(".gs-snippet").first
                hits.append({"url": link.get_attribute("href") or "", "title": link.inner_text(),
                             "snippet": snippet.inner_text() if snippet.count() else ""})
        return hits
    finally:
        page.close()


def _safe_text(value: str, limit: int) -> str:
    value = re.sub(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}", "[email redacted]", str(value or ""))
    value = re.sub(
        r'''(?i)(["']?[\w.-]*(?:password|passwd|pwd|pass2|token|api[_-]?key|secret)[\w.-]*["']?\s*[:=]\s*)("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|[^\s,;}\]]+)''',
        r"\1[redacted]", value,
    )
    value = re.sub(r"\b[A-Za-z0-9_/-]{48,}\b", "[identifier redacted]", value)
    return " ".join(value.split())[:limit]


def _hit_payload(row) -> dict[str, Any]:
    item = dict(row)
    for key in ("matched_aliases", "matched_risks", "found_via"):
        item[key] = json.loads(item.pop(f"{key}_json"))
    return item


def list_hits(watchlist_id: str, *, limit: int = 100) -> list[dict[str, Any]]:
    with get_db_connection() as connection:
        _schema(connection)
        rows = connection.execute("SELECT * FROM social_hits WHERE watchlist_id=? ORDER BY last_seen_at DESC LIMIT ?",
                                  (watchlist_id, max(1, min(limit, 500)))).fetchall()
        connection.commit()
    return [_hit_payload(row) for row in rows]


def get_hit(hit_id: str) -> dict[str, Any] | None:
    with get_db_connection() as connection:
        _schema(connection)
        row = connection.execute("SELECT * FROM social_hits WHERE id=?", (hit_id,)).fetchone()
        connection.commit()
    return _hit_payload(row) if row else None


def public_hit_preview(hit_id: str) -> dict[str, Any]:
    hit = get_hit(hit_id)
    if not hit:
        raise ValueError("hit not found")
    canonical = canonical_post(hit["source_url"])
    if not canonical or canonical[:2] != (hit["platform"], hit["post_id"]):
        return {"source_status": "unavailable", "text": "", "truncated": False}
    source = fetch_public_post(hit["platform"], canonical[2])
    raw = " ".join(str(source.get("text") or "").split())
    sanitized = re.sub(r"https?://\S+", "[link redacted]", raw)
    safe = _safe_text(sanitized, len(sanitized))
    status = str(source.get("status") or "unavailable")
    if status not in {"source_text", "public_metadata"} or not safe:
        return {"source_status": "unavailable", "text": "", "truncated": False}
    return {"source_status": status, "text": safe[:600], "truncated": len(safe) > 600}


def list_scans(watchlist_id: str, *, limit: int = 30) -> list[dict[str, Any]]:
    with get_db_connection() as connection:
        _schema(connection)
        rows = connection.execute("SELECT * FROM social_scan_runs WHERE watchlist_id=? ORDER BY started_at DESC LIMIT ?",
                                  (watchlist_id, max(1, min(limit, 100)))).fetchall()
        connection.commit()
    return [{**dict(row), "stats": json.loads(row["stats_json"])} for row in rows]


def review_hit(hit_id: str, status: str, evidence_url: str, note: str, reviewer: str) -> dict[str, Any]:
    if status not in {"pending", "unconfirmed", "false_positive", "corroborated"}:
        raise ValueError("invalid review status")
    if status == "corroborated":
        host = (urlsplit(evidence_url).hostname or "").lower()
        if urlsplit(evidence_url).scheme != "https" or not host or any(
            host == value or host.endswith("." + value) for value in ("x.com", "twitter.com", "facebook.com")
        ) or not note.strip():
            raise ValueError("corroborated requires an independent HTTPS evidence URL and note")
    with get_db_connection() as connection:
        _schema(connection)
        existing = connection.execute("SELECT id,classification FROM social_hits WHERE id=?", (hit_id,)).fetchone()
        if existing is None:
            raise ValueError("hit not found")
        if status == "corroborated" and existing["classification"] != "candidate":
            raise ValueError("only a source-verified candidate can be marked corroborated")
        connection.execute("""UPDATE social_hits SET review_status=?, evidence_url=?, review_note=?,
            reviewer=?, reviewed_at=? WHERE id=?""", (
            status, evidence_url if status == "corroborated" else "", _safe_text(note, 300),
            _safe_text(reviewer, 80), _now(), hit_id,
        ))
        connection.commit()
    return get_hit(hit_id) or {}


def _claim_scan(watchlist_id: str, *, force: bool) -> tuple[str, dict[str, Any]]:
    now = _now()
    run_id = uuid.uuid4().hex
    with get_db_connection() as connection:
        _schema(connection)
        row = connection.execute("SELECT * FROM social_watchlists WHERE id=?", (watchlist_id,)).fetchone()
        if row is None:
            raise ValueError("watchlist not found")
        condition = "" if force else " AND next_scan_at <= ?"
        params: tuple[Any, ...] = (_later(LEASE_MINUTES), run_id, _later(int(row["interval_minutes"])), watchlist_id, now)
        if not force:
            params += (now,)
        claimed = connection.execute("""UPDATE social_watchlists SET lease_until=?, lease_owner=?, next_scan_at=?
            WHERE id=? AND enabled=1 AND (lease_until='' OR lease_until < ?)""" + condition, params)
        if claimed.rowcount != 1:
            raise RuntimeError("watchlist disabled, not due, or scan already running")
        connection.execute("""UPDATE social_scan_runs SET status='failed', stats_json=?, finished_at=?
            WHERE watchlist_id=? AND status='running'""", (json.dumps({"error": "scan lease expired"}), now, watchlist_id))
        connection.execute("""INSERT INTO social_scan_runs
            (id,watchlist_id,status,stats_json,started_at) VALUES (?,?,?,?,?)""",
            (run_id, watchlist_id, "running", "{}", now))
        connection.commit()
    return run_id, _watchlist_payload(row)


def _renew_scan(run_id: str, watchlist_id: str, connection=None) -> None:
    if connection is None:
        with get_db_connection() as current:
            _schema(current)
            _renew_scan(run_id, watchlist_id, current)
            current.commit()
        return
    renewed = connection.execute("""UPDATE social_watchlists SET lease_until=?
        WHERE id=? AND lease_owner=? AND lease_until >= ?""", (_later(LEASE_MINUTES), watchlist_id, run_id, _now()))
    if renewed.rowcount != 1:
        raise RuntimeError("scan ownership lost")


def _finish_scan(connection, run_id: str, watchlist: dict[str, Any], status: str, stats: dict, now: str) -> None:
    released = connection.execute("""UPDATE social_watchlists SET lease_until='', lease_owner='',
        last_scan_at=?, last_scan_status=?, next_scan_at=? WHERE id=? AND lease_owner=?""", (
        now, status, _later(15) if status == "failed" else _later(watchlist["interval_minutes"]), watchlist["id"], run_id,
    ))
    if released.rowcount != 1:
        status, stats = "failed", {"error": "scan ownership lost"}
    connection.execute("UPDATE social_scan_runs SET status=?, stats_json=?, finished_at=? WHERE id=?",
                       (status, json.dumps(stats, ensure_ascii=False), now, run_id))


def _save_hit(connection, watchlist: dict[str, Any], platform: str, post_id: str, url: str,
              found: dict[str, Any], source: dict[str, str], now: str) -> tuple[bool, str]:
    hit_id = f"{watchlist['id']}:{platform}:{post_id}"
    existing = connection.execute("SELECT * FROM social_hits WHERE id=?", (hit_id,)).fetchone()
    source_status = str(source.get("status") or "unavailable")
    if source_status in {"source_text", "public_metadata"}:
        classification, aliases, risks = match_post(str(source.get("text") or ""), watchlist["aliases"], watchlist["risk_terms"])
    else:
        result, _, _ = match_post(f"{found['title']} {found['snippet']}", watchlist["aliases"], watchlist["risk_terms"])
        classification, aliases, risks = ("unverified_search_hit", [], []) if result == "candidate" else ("unavailable", [], [])
        if existing and existing["classification"] == "candidate":
            classification = "candidate"
            aliases = json.loads(existing["matched_aliases_json"])
            risks = json.loads(existing["matched_risks_json"])
    found_via = sorted(set(json.loads(existing["found_via_json"]) if existing else []) | found["engines"])
    title = _safe_text(found["title"], 220)
    excerpt = ""  # Process post text in memory only; do not retain possible leaked material.
    author = _safe_text(str(source.get("author") or (existing["author"] if existing else "")), 80)
    if existing:
        connection.execute("""UPDATE social_hits SET last_seen_at=?, found_via_json=?, title=?,
            excerpt=?, author=?, source_status=?, classification=?, matched_aliases_json=?,
            matched_risks_json=? WHERE id=?""", (
            now, json.dumps(found_via), title, excerpt, author, source_status, classification,
            json.dumps(aliases, ensure_ascii=False), json.dumps(risks, ensure_ascii=False), hit_id,
        ))
    else:
        connection.execute("""INSERT INTO social_hits (id,watchlist_id,platform,post_id,source_url,title,excerpt,
            author,source_status,classification,matched_aliases_json,matched_risks_json,found_via_json,
            first_seen_at,last_seen_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", (
            hit_id, watchlist["id"], platform, post_id, url, title, excerpt, author, source_status,
            classification, json.dumps(aliases, ensure_ascii=False), json.dumps(risks, ensure_ascii=False),
            json.dumps(found_via), now, now,
        ))
    return existing is None, classification


def _execute_scan(run_id: str, watchlist: dict[str, Any], discoverer: Callable, hydrator: Callable) -> dict[str, Any]:
    found: dict[tuple[str, str], dict[str, Any]] = {}
    errors: list[str] = []
    attempted = 0
    for platform, engines in ENGINES.items():
        for query in watchlist["queries"]:
            for engine, _ in engines:
                _renew_scan(run_id, watchlist["id"])
                attempted += 1
                try:
                    rows = discoverer(platform, query, engine)
                except Exception as exc:
                    errors.append(_safe_text(f"{engine}: {type(exc).__name__}: {exc}", 180))
                    continue
                for row in rows:
                    canonical = canonical_post(str(row.get("url") or ""))
                    if canonical is None or canonical[0] != platform:
                        continue
                    key = canonical[:2]
                    hit = found.setdefault(key, {"url": canonical[2], "title": "", "snippet": "", "engines": set()})
                    hit["engines"].add(engine)
                    hit["title"] = hit["title"] or str(row.get("title") or "")
                    hit["snippet"] = hit["snippet"] or str(row.get("snippet") or "")
    now = _now()
    counts = {"checked": 0, "new_hits": 0, "candidate_count": 0, "unverified_count": 0, "unavailable_count": 0}
    per_platform = {platform: 0 for platform in ENGINES}
    processed = []
    for (platform, post_id), hit in found.items():
        if per_platform[platform] >= watchlist["max_posts_per_platform"]:
            continue
        per_platform[platform] += 1
        counts["checked"] += 1
        _renew_scan(run_id, watchlist["id"])
        try:
            source = hydrator(platform, hit["url"])
        except Exception as exc:
            source = {"status": "unavailable", "text": "", "error": f"{type(exc).__name__}: {exc}"[:180]}
        counts["unavailable_count"] += int(source.get("status") == "unavailable")
        processed.append((platform, post_id, hit, source))
    with get_db_connection() as connection:
        _schema(connection)
        _renew_scan(run_id, watchlist["id"], connection)
        for platform, post_id, hit, source in processed:
            created, classification = _save_hit(connection, watchlist, platform, post_id, hit["url"], hit, source, now)
            counts["new_hits"] += int(created)
            counts["candidate_count"] += int(classification == "candidate")
            counts["unverified_count"] += int(classification == "unverified_search_hit")
        status = "failed" if attempted and len(errors) == attempted else "completed_limited"
        stats = {"discovered_unique": len(found), "skipped_due_limit": len(found) - counts["checked"],
                 **counts, "source_errors": errors, "coverage": "public_search_index_only"}
        _finish_scan(connection, run_id, watchlist, status, stats, now)
        connection.commit()
    return {"run_id": run_id, "status": status, **stats}


def _run_claimed_scan(run_id: str, watchlist: dict[str, Any], discoverer: Callable | None,
                      hydrator: Callable | None) -> dict[str, Any]:
    stop_renewal = Event()

    def renew() -> None:
        while not stop_renewal.wait(LEASE_RENEW_SECONDS):
            try:
                _renew_scan(run_id, watchlist["id"])
            except RuntimeError:
                break
            except Exception as exc:
                logger.warning("social scan lease renewal failed: %s", type(exc).__name__)

    renewal = Thread(target=renew, name=f"social-lease-{run_id[:8]}", daemon=True)
    try:
        renewal.start()
        if discoverer is not None:
            return _execute_scan(run_id, watchlist, discoverer, hydrator or fetch_public_post)
        from playwright.sync_api import sync_playwright

        with sync_playwright() as playwright:
            launch_options = {"headless": True}
            if os.name == "nt" and not Path(playwright.chromium.executable_path).is_file():
                launch_options["channel"] = "chrome"
            browser = playwright.chromium.launch(**launch_options)
            try:
                context = browser.new_context()  # Deliberately no stored account or cookies.
                return _execute_scan(run_id, watchlist,
                                     lambda platform, query, engine: discover_cse(context, platform, query, engine),
                                     hydrator or fetch_public_post)
            finally:
                browser.close()
    except Exception as exc:
        with get_db_connection() as connection:
            _schema(connection)
            now = _now()
            _finish_scan(connection, run_id, watchlist, "failed", {"error": _safe_text(str(exc), 180)}, now)
            connection.commit()
        raise
    finally:
        stop_renewal.set()
        if renewal.ident is not None:
            renewal.join(timeout=2)


def scan_watchlist_once(watchlist_id: str, *, discoverer: Callable | None = None,
                        hydrator: Callable | None = None, force: bool = True) -> dict[str, Any]:
    run_id, watchlist = _claim_scan(watchlist_id, force=force)
    return _run_claimed_scan(run_id, watchlist, discoverer, hydrator)


def start_manual_scan(watchlist_id: str) -> dict[str, str]:
    watchlist = get_watchlist(watchlist_id)
    if not watchlist or not watchlist["enabled"]:
        raise ValueError("watchlist not found or disabled")
    run_id, watchlist = _claim_scan(watchlist_id, force=True)

    def run() -> None:
        try:
            _run_claimed_scan(run_id, watchlist, None, None)
        except Exception:
            logger.exception("manual social scan failed for %s", watchlist_id)

    try:
        Thread(target=run, name=f"social-scan-{watchlist_id[:8]}", daemon=True).start()
    except Exception as exc:
        with get_db_connection() as connection:
            _schema(connection)
            _finish_scan(connection, run_id, watchlist, "failed", {"error": _safe_text(str(exc), 180)}, _now())
            connection.commit()
        raise
    return {"status": "queued", "watchlist_id": watchlist_id, "run_id": run_id}


def due_watchlist_ids() -> list[str]:
    with get_db_connection() as connection:
        _schema(connection)
        now = _now()
        rows = connection.execute("""SELECT id FROM social_watchlists WHERE enabled=1 AND next_scan_at <= ?
            AND (lease_until='' OR lease_until < ?) ORDER BY next_scan_at LIMIT 10""", (now, now)).fetchall()
        connection.commit()
    return [row["id"] for row in rows]


def _worker_loop() -> None:
    while not _worker_stop.is_set():
        try:
            for watchlist_id in due_watchlist_ids():
                if _worker_stop.is_set():
                    break
                try:
                    scan_watchlist_once(watchlist_id, force=False)
                except Exception:
                    logger.exception("scheduled social scan failed for %s", watchlist_id)
        except Exception:
            logger.exception("social monitoring scheduler tick failed")
        _worker_stop.wait(60)


def start_social_worker() -> None:
    global _worker
    with _worker_lock:
        if _worker and _worker.is_alive():
            return
        _worker_stop.clear()
        _worker = Thread(target=_worker_loop, name="social-monitoring-scheduler", daemon=True)
        _worker.start()


def stop_social_worker() -> None:
    _worker_stop.set()
