"""Bounded collector monitoring, independent of the recent-job display page."""
from __future__ import annotations

from datetime import datetime, timezone
from threading import Lock
import time

from darkweb_collector.collection_errors import safe_failure_text as safe_error_message


_cache: dict = {}
_cache_lock = Lock()
_JOB_COLUMNS = "job_id, site_name, job_type, status, queue_name, target, enqueued_at, started_at, finished_at, duration_ms, error_message"
_PENDING = "status IN ('pending','queued','dispatching','legacy_queued') AND (fetched_version = '' OR observed_version <> fetched_version)"


def iso(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp, timezone.utc).isoformat()


def ensure_metrics_schema(connection, *, postgres=False) -> None:
    for statement in (
        "CREATE TABLE IF NOT EXISTS collector_metrics_state (name TEXT PRIMARY KEY, value TEXT NOT NULL)",
        """CREATE TABLE IF NOT EXISTS collector_visible_events (
            event_id TEXT PRIMARY KEY, site_name TEXT NOT NULL, published_at DOUBLE PRECISION)""",
        "CREATE TABLE IF NOT EXISTS collector_visible_groups (group_key TEXT PRIMARY KEY)",
        "CREATE INDEX IF NOT EXISTS idx_collector_visible_time ON collector_visible_events(published_at, site_name)",
        """CREATE TABLE IF NOT EXISTS collector_queue_snapshots (
            sampled_at BIGINT PRIMARY KEY, pending_recent BIGINT NOT NULL, pending_backfill BIGINT NOT NULL)""",
        "CREATE INDEX IF NOT EXISTS idx_crawl_jobs_site_type_id ON crawl_jobs(site_name, job_type, id DESC)",
        "CREATE INDEX IF NOT EXISTS idx_crawl_jobs_site_type_outcome ON crawl_jobs(site_name, job_type, status, finished_at DESC, id DESC)",
        "CREATE INDEX IF NOT EXISTS idx_crawl_jobs_active_status ON crawl_jobs(status, finished_at, site_name)",
    ):
        connection.execute(statement)
    placeholder = "%s" if postgres else "?"
    cursor = connection.execute("INSERT INTO collector_metrics_state(name,value) VALUES ('visible_since', " + placeholder + ") ON CONFLICT(name) DO NOTHING", (str(time.time()),))
    if (cursor or connection).rowcount:
        # Existing intelligence has no trustworthy first-publication timestamp.
        # Baseline identities, but never label an upgrade/rebuild as new output.
        record_visible_rebuild(connection, baseline=True, postgres=postgres)


def record_visible_publication(connection, event_id: str, site_name: str, *, group_key: str, is_new=True, now=None) -> None:
    fresh_group = connection.execute("INSERT INTO collector_visible_groups(group_key) VALUES (?) ON CONFLICT(group_key) DO NOTHING", (group_key,)).rowcount > 0
    connection.execute("""INSERT INTO collector_visible_events(event_id,site_name,published_at)
        VALUES (?,?,?) ON CONFLICT(event_id) DO NOTHING""",
        (event_id, site_name, (time.time() if now is None else now) if is_new and fresh_group else None))


def record_visible_rebuild(connection, *, now=None, baseline=False, postgres=False) -> None:
    """Keep both event and canonical-group identities across rebuilds and renames."""
    from darkweb_collector.incremental_intelligence import _group
    bind = "%s" if postgres else "?"
    after, timestamp = "", time.time() if now is None else now
    while True:
        cursor = connection.execute("SELECT event_id,source_site_name,event_type,title FROM normalized_intelligence_events "
                                    f"WHERE event_id>{bind} ORDER BY event_id LIMIT 200", (after,))
        rows = (cursor or connection).fetchall()
        if not rows:
            break
        entries = [(r[0], r[1], _group(dict(zip(("event_id", "source_site_name", "event_type", "title"), [r[i] for i in range(4)])))) for r in rows]
        marks = ",".join(bind for _ in entries)
        cursor = connection.execute(f"SELECT event_id FROM collector_visible_events WHERE event_id IN ({marks})", tuple(r[0] for r in entries))
        known_ids = {r[0] for r in (cursor or connection).fetchall()}
        cursor = connection.execute(f"SELECT group_key FROM collector_visible_groups WHERE group_key IN ({marks})", tuple(r[2] for r in entries))
        known_groups = {r[0] for r in (cursor or connection).fetchall()}
        groups, events = [], []
        for event_id, site_name, group in entries:
            if event_id not in known_ids:
                events.append((event_id, site_name, None if baseline or group in known_groups else timestamp))
            if group not in known_groups:
                groups.append((group,)); known_groups.add(group)
        if groups:
            connection.executemany(f"INSERT INTO collector_visible_groups(group_key) VALUES ({bind}) ON CONFLICT(group_key) DO NOTHING", groups)
        if events:
            connection.executemany(f"INSERT INTO collector_visible_events(event_id,site_name,published_at) VALUES ({bind},{bind},{bind}) ON CONFLICT(event_id) DO NOTHING", events)
        after = rows[-1][0]


def pending_by_site(connection) -> dict:
    return {r["site_name"]: {"recent": int(r["recent"] or 0), "backfill": int(r["backfill"] or 0)}
        for r in connection.execute(f"""SELECT site_name,
            SUM(CASE WHEN discovery_lane='backfill' THEN 0 ELSE 1 END) AS recent,
            SUM(CASE WHEN discovery_lane='backfill' THEN 1 ELSE 0 END) AS backfill
            FROM crawl_frontier WHERE {_PENDING} GROUP BY site_name""").fetchall()}


def record_queue_snapshot(connection, *, now=None) -> None:
    """Called by the scheduler in its transaction, not by read-only GET requests."""
    from darkweb_collector.config import load_site_configs
    timestamp = time.time() if now is None else float(now)
    minute = int(timestamp // 60) * 60
    if connection.execute("SELECT 1 FROM collector_queue_snapshots WHERE sampled_at=?", (minute,)).fetchone():
        return
    configured = {c.site_name for c in load_site_configs()}
    values = [v for site, v in pending_by_site(connection).items() if site in configured]
    connection.execute("""INSERT INTO collector_queue_snapshots(sampled_at,pending_recent,pending_backfill)
        VALUES (?,?,?) ON CONFLICT(sampled_at) DO NOTHING""",
        (minute, sum(v["recent"] for v in values), sum(v["backfill"] for v in values)))
    connection.execute("DELETE FROM collector_queue_snapshots WHERE sampled_at < ?", (minute - 8 * 86400,))


def site_job_rows(connection, sites: list[str]) -> tuple[list[dict], dict]:
    """A noisy site must never evict another site's latest outcome or active count."""
    rows: dict[str, dict] = {}
    for site in sites:
        selections = [("job_type='seed'", 20), ("job_type='seed' AND status='succeeded'", 1)]
        selections += [(f"job_type='detail' AND status='{status}'", 1)
                       for status in ("succeeded", "partial", "failed", "running", "enqueued", "stale")]
        for clause, limit in selections:
            order = "id DESC" if clause == "job_type='seed'" else "finished_at DESC,id DESC"
            for row in connection.execute(f"SELECT {_JOB_COLUMNS} FROM crawl_jobs WHERE site_name=? AND {clause} ORDER BY {order} LIMIT ?", (site, limit)).fetchall():
                item = dict(row)
                rows[item["job_id"]] = item
    now = time.time()
    counts = {r["site_name"]: dict(r) for r in connection.execute("""SELECT site_name,
        SUM(CASE WHEN status='running' AND (started_at IS NULL OR started_at>=?) THEN 1 ELSE 0 END) AS running,
        SUM(CASE WHEN status='enqueued' AND (started_at IS NOT NULL OR enqueued_at IS NULL OR enqueued_at>=?) THEN 1 ELSE 0 END) AS enqueued,
        SUM(CASE WHEN (status='running' AND started_at<?) OR
            (status='enqueued' AND started_at IS NULL AND enqueued_at<?) THEN 1 ELSE 0 END) AS stale
        FROM crawl_jobs WHERE finished_at IS NULL AND status IN ('running','enqueued') GROUP BY site_name""",
        (iso(now - 1800), iso(now - 600), iso(now - 1800), iso(now - 600))).fetchall()}
    return sorted(rows.values(), key=lambda r: str(r.get("finished_at") or r.get("started_at") or r.get("enqueued_at") or ""), reverse=True), counts


def _bucket(connection, expression: str, step: int, *, text_time=False) -> str:
    postgres = getattr(connection, "backend_name", "") == "postgresql"
    if text_time:
        expression = f"EXTRACT(EPOCH FROM CAST({expression} AS TIMESTAMPTZ))" if postgres else f"CAST(strftime('%s', {expression}) AS INTEGER)"
    return f"CAST(FLOOR(({expression})/{step}) AS BIGINT)*{step}" if postgres else f"CAST(({expression})/{step} AS INTEGER)*{step}"


def _site_scope(names: list[str], column="site_name") -> tuple[str, tuple]:
    return (column + " IN (" + ",".join("?" for _ in names) + ")", tuple(names)) if names else ("1=0", ())


def _overview_data(hours: int) -> dict:
    from darkweb_collector.api_data import build_jobs_payload
    from darkweb_collector.db import get_db_connection
    from darkweb_collector.worker_supervisor import get_worker_capacity
    health = build_jobs_payload(include_auxiliary=False)
    sites = health["site_health"]
    names = [s["site_name"] for s in sites]
    scope, args = _site_scope(names)
    now, step = time.time(), 300 if hours == 1 else 3600
    start = now - hours * 3600
    first, last = int(start // step) * step, int(now // step) * step
    points = {t: {"at": iso(t), "raw_new": None, "visible_new": None, "success": 0,
                  "failed": 0, "partial": 0, "skipped": 0, "pending_recent": None,
                  "pending_backfill": None, "backlog_at": None}
              for t in range(first, last + 1, step)}
    with get_db_connection() as connection:
        tracking = connection.execute("SELECT value FROM collector_metrics_state WHERE name='visible_since'").fetchone()
        visible_since = float(tracking[0]) if tracking else None
        raw_since_row = connection.execute("SELECT MIN(finished_at) FROM crawl_detail_results WHERE " + scope, args).fetchone()
        raw_since = raw_since_row[0] if raw_since_row else None
        for t, point in points.items():
            if visible_since is not None and t + step > visible_since:
                point["visible_new"] = 0
            if raw_since is not None and t + step > raw_since:
                point["raw_new"] = 0
        bucket = _bucket(connection, "finished_at", step, text_time=True)
        for row in connection.execute(f"""SELECT {bucket} AS bucket, status, COUNT(*) AS total
            FROM crawl_jobs WHERE finished_at>=? AND finished_at<=? AND {scope}
            AND status IN ('succeeded','failed','partial','skipped') GROUP BY {bucket},status""", (iso(start), iso(now), *args)).fetchall():
            point = points.get(int(row["bucket"])) if row["bucket"] is not None else None
            if point is not None:
                point[{"succeeded": "success"}.get(row["status"], row["status"])] = int(row["total"])
        bucket = _bucket(connection, "finished_at", step)
        for row in connection.execute(f"""SELECT {bucket} AS bucket, SUM(new_count) AS total
            FROM crawl_detail_results WHERE finished_at>=? AND finished_at<=? AND {scope}
            GROUP BY {bucket}""", (start, now, *args)).fetchall():
            if int(row["bucket"]) in points:
                points[int(row["bucket"])]["raw_new"] = int(row["total"] or 0)
        bucket = _bucket(connection, "published_at", step)
        visible_by_site = {}
        for row in connection.execute(f"""SELECT {bucket} AS bucket, site_name, COUNT(*) AS total
            FROM collector_visible_events WHERE published_at>=? AND published_at<=? AND {scope}
            GROUP BY {bucket},site_name""", (start, now, *args)).fetchall():
            count = int(row["total"])
            visible_by_site[row["site_name"]] = visible_by_site.get(row["site_name"], 0) + count
            if int(row["bucket"]) in points:
                point = points[int(row["bucket"])]
                point["visible_new"] = (point["visible_new"] or 0) + count
        backlog_since_row = connection.execute("SELECT MIN(sampled_at) FROM collector_queue_snapshots").fetchone()
        backlog_since = backlog_since_row[0] if backlog_since_row else None
        bucket = _bucket(connection, "sampled_at", step)
        # One real sample per bucket, never copy today's backlog into missing history.
        for row in connection.execute(f"""SELECT s.* FROM collector_queue_snapshots s JOIN (
            SELECT MAX(sampled_at) AS sampled_at FROM collector_queue_snapshots
            WHERE sampled_at>=? AND sampled_at<=? GROUP BY {bucket}) latest
            ON latest.sampled_at=s.sampled_at""", (start, now)).fetchall():
            t = int(row["sampled_at"] // step) * step
            if t in points:
                points[t].update(pending_recent=int(row["pending_recent"]), pending_backfill=int(row["pending_backfill"]), backlog_at=iso(row["sampled_at"]))
        pending = pending_by_site(connection)
    items = []
    for s in sites:
        waiting = pending.get(s["site_name"], {})
        items.append({"site_name": s["site_name"], "display_name": s["display_name"],
            "enabled": s["enabled"], "state": s["overall_status"], "attention": s.get("needs_attention", False),
            "new_visible": visible_by_site.get(s["site_name"], 0) if visible_since is not None else None,
            "pending_recent": waiting.get("recent", 0), "pending_backfill": waiting.get("backfill", 0),
            "last_success_at": s.get("last_success_at_raw") or None,
            "last_error": safe_error_message(s.get("last_error") or ""), "next_run_at": s.get("next_run_at"),
            "detail_retry_at": s.get("detail_retry_at")})
    return {"updated_at": iso(now), "hours": hours, "interval_seconds": step,
        "scope": {"total_sites": len(sites), "enabled_sites": sum(bool(s["enabled"]) for s in sites)},
        "summary": {"visible_new": sum(visible_by_site.values()) if visible_since is not None else None,
            "raw_new": sum(p["raw_new"] or 0 for p in points.values()) if raw_since is not None else None,
            "pending_recent": sum(s["pending_recent"] for s in items),
            "pending_backfill": sum(s["pending_backfill"] for s in items),
            "running_jobs": health["running_jobs"], "available_slots": get_worker_capacity(),
            "attention_sites": sum(s["attention"] for s in items)},
        "coverage": {"visible_since": iso(visible_since) if visible_since is not None else None,
            "visible_complete": visible_since is not None and visible_since <= start,
            "raw_since": iso(raw_since) if raw_since is not None else None,
            "raw_complete": raw_since is not None and raw_since <= start,
            "backlog_since": iso(backlog_since) if backlog_since is not None else None},
        "series": list(points.values()), "site_items": items}


def build_overview(hours=24, page=1, page_size=10, q="", state="all", attention_first=False) -> dict:
    from darkweb_collector.runtime import configured_database_schema, configured_database_url, default_config_path, default_db_path
    hours = int(hours)
    if hours not in (1, 24, 168):
        raise ValueError("hours must be 1, 24 or 168")
    if state not in ("all", "running", "waiting", "attention", "disabled"):
        raise ValueError("unsupported site state")
    # Bounded per-period cache. Different users/pages share the same global aggregate.
    config_path = default_config_path()
    key = (hours, configured_database_url(), configured_database_schema(), str(default_db_path()), str(config_path),
           config_path.stat().st_mtime_ns if config_path.exists() else 0)
    with _cache_lock:
        cached = _cache.get(key)
        if not cached or time.monotonic() - cached[0] >= 20:
            data = _overview_data(hours)
            if len(_cache) >= 6:
                _cache.clear()
            _cache[key] = (time.monotonic(), data)
        else:
            data = cached[1]
    items = data["site_items"]
    query = str(q).strip().casefold()
    if query:
        items = [s for s in items if query in (s["site_name"] + " " + s["display_name"]).casefold()]
    if state != "all":
        items = [s for s in items if {"running": s["state"] == "执行中", "disabled": not s["enabled"],
            "attention": s["attention"], "waiting": s["enabled"] and s["state"] in ("等待调度", "等待执行", "资源等待", "退避中", "证据待补")}[state]]
    if attention_first:
        items = sorted(items, key=lambda s: (not s["attention"], s["site_name"]))
    page_size = min(100, max(1, int(page_size)))
    page = min(max(1, int(page)), max(1, (len(items) + page_size - 1) // page_size))
    return {**{k: v for k, v in data.items() if k != "site_items"}, "sites": {
        "items": items[(page - 1) * page_size:page * page_size], "total": len(items), "page": page, "page_size": page_size}}


def build_task_history(hours=24, page=1, page_size=20, q="", site="", status="") -> dict:
    from darkweb_collector.config import load_site_configs
    from darkweb_collector.db import get_db_connection
    from darkweb_collector.api_data import site_display_name
    from darkweb_collector.collection_errors import safe_failure_text as safe_source_url
    hours = int(hours)
    if hours not in (1, 24, 168):
        raise ValueError("hours must be 1, 24 or 168")
    if status not in ("", "all", "running", "enqueued", "succeeded", "partial", "failed", "skipped", "stale"):
        raise ValueError("unsupported task status")
    configs = load_site_configs()
    labels = {c.site_name: site_display_name(c) for c in configs}
    scope, scope_args = _site_scope(list(labels), "j.site_name")
    clauses = [f"COALESCE(j.finished_at,j.started_at,j.enqueued_at)>=?", scope]
    args = [iso(time.time() - hours * 3600), *scope_args]
    if site:
        clauses.append("j.site_name=?"); args.append(site)
    if status not in ("", "all"):
        clauses.append("j.status=?"); args.append(status)
    if str(q).strip():
        pattern = "%" + str(q).strip().lower().replace("!", "!!").replace("%", "!%").replace("_", "!_") + "%"
        fields = ("job_id", "site_name", "target", "error_message")
        conditions = [f"LOWER(COALESCE(j.{field},'')) LIKE ? ESCAPE '!'" for field in fields]
        args.extend([pattern] * len(fields))
        matching = [name for name, label in labels.items() if str(q).strip().casefold() in label.casefold()]
        if matching:
            conditions.append("j.site_name IN (" + ",".join("?" for _ in matching) + ")"); args.extend(matching)
        clauses.append("(" + " OR ".join(conditions) + ")")
    where = " AND ".join(clauses)
    with get_db_connection() as connection:
        total = int(connection.execute("SELECT COUNT(*) FROM crawl_jobs j WHERE " + where, tuple(args)).fetchone()[0])
        page_size = min(100, max(1, int(page_size)))
        page = min(max(1, int(page)), max(1, (total + page_size - 1) // page_size))
        rows = connection.execute(f"""SELECT j.*, r.new_count,r.updated_count,r.unchanged_count
            FROM crawl_jobs j LEFT JOIN crawl_detail_results r ON r.job_id=j.job_id WHERE {where}
            ORDER BY COALESCE(j.finished_at,j.started_at,j.enqueued_at) DESC,j.id DESC LIMIT ? OFFSET ?""",
            (*args, page_size, (page - 1) * page_size)).fetchall()
        items = []
        for row in rows:
            item = {key: row[key] for key in ("job_id", "site_name", "job_type", "status", "enqueued_at", "started_at", "finished_at", "duration_ms")}
            item.update(display_name=labels.get(row["site_name"], row["site_name"]),
                        target=safe_source_url(row["target"]), error_message=safe_error_message(row["error_message"] or ""),
                        result={key: row[key] for key in ("new_count", "updated_count", "unchanged_count")})
            items.append(item)
    return {"items": items, "total": total, "page": page, "page_size": page_size, "updated_at": iso(time.time()),
            "sites": [{"site_name": c.site_name, "display_name": labels[c.site_name]} for c in configs]}
